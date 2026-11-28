import CryptoKit
import Darwin
import Foundation

struct DaemonPingResult: Sendable {
    let pid: UInt32
    let port: UInt16
    let version: String?
}

struct DaemonTicketResult: Sendable {
    let port: UInt16
    let url: URL
}

enum DaemonClientError: Error, LocalizedError {
    case socketNotFound(String)
    case connectFailed(String, Int32)
    case ioFailed(String)
    case invalidResponse(String)
    case daemonError(code: String, message: String, hint: String)

    var errorDescription: String? {
        switch self {
        case .socketNotFound(let path):
            return "mynote daemon socket not found at \(path)"
        case .connectFailed(let path, let code):
            return "Failed to connect to \(path): \(String(cString: strerror(code))) (errno \(code))"
        case .ioFailed(let detail):
            return "Daemon IPC I/O failed: \(detail)"
        case .invalidResponse(let detail):
            return "Invalid daemon response: \(detail)"
        case .daemonError(let code, let message, let hint):
            return "\(code): \(message) (\(hint))"
        }
    }
}

private struct UdsErrorPayload: Decodable {
    let code: String
    let message: String
    let hint: String
}

private struct UdsResponsePayload: Decodable {
    let ok: Bool
    let version: String?
    let pid: UInt32?
    let port: UInt16?
    let url: String?
    let error: UdsErrorPayload?
}

/// Pure-POSIX client for `mynote daemon`'s `0600 daemon.sock` NDJSON protocol
/// (mirrors `crates/mynote-cli/src/runner.rs::resolve_data_dir` and `uds.rs::socket_path_for`).
enum DaemonClient {
    static func resolveDataDir(env: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        if let explicit = env["MYNOTE_DATA_DIR"]?.trimmingCharacters(in: .whitespacesAndNewlines),
           !explicit.isEmpty
        {
            return URL(fileURLWithPath: explicit, isDirectory: true)
        }
        if let xdg = env["XDG_DATA_HOME"]?.trimmingCharacters(in: .whitespacesAndNewlines),
           !xdg.isEmpty
        {
            return URL(fileURLWithPath: xdg, isDirectory: true).appendingPathComponent("mynote", isDirectory: true)
        }
        let home = env["HOME"] ?? NSHomeDirectory()
        return URL(fileURLWithPath: home, isDirectory: true)
            .appendingPathComponent(".local", isDirectory: true)
            .appendingPathComponent("share", isDirectory: true)
            .appendingPathComponent("mynote", isDirectory: true)
    }

    static func socketPath(env: [String: String] = ProcessInfo.processInfo.environment) -> String {
        let dataDir = resolveDataDir(env: env)
        let dataPath = dataDir.path
        let tmpPath = NSTemporaryDirectory()
        let isCustom = (env["MYNOTE_DATA_DIR"] != nil)
            || dataPath.hasPrefix("/tmp/")
            || dataPath.contains("/.tmp")
            || dataPath.hasPrefix(tmpPath)

        let candidate: String
        if isCustom {
            candidate = dataDir.appendingPathComponent("daemon.sock").path
        } else {
            candidate = dataDir
                .appendingPathComponent("run", isDirectory: true)
                .appendingPathComponent("daemon.sock").path
        }

        // Mirror `uds.rs`: macOS sockaddr_un.sun_path limit is 104 bytes; hash >= 96 bytes deterministically.
        if candidate.utf8.count >= 96 {
            let digest = SHA256.hash(data: Data(dataPath.utf8))
            let hex = digest.prefix(8).map { String(format: "%02x", $0) }.joined()
            if let xdg = env["XDG_RUNTIME_DIR"]?.trimmingCharacters(in: .whitespacesAndNewlines),
               !xdg.isEmpty, xdg.utf8.count < 64
            {
                return URL(fileURLWithPath: xdg, isDirectory: true)
                    .appendingPathComponent("mn", isDirectory: true)
                    .appendingPathComponent("\(hex).sock").path
            }
            return "/tmp/mn-\(getuid())/\(hex).sock"
        }
        return candidate
    }

    static func ping(timeoutSeconds: Int = 2) throws -> DaemonPingResult {
        let resp = try send(jsonLine: #"{"cmd":"ping"}"#, timeoutSeconds: timeoutSeconds)
        guard let pid = resp.pid, let port = resp.port else {
            throw DaemonClientError.invalidResponse("ping response missing pid or port")
        }
        return DaemonPingResult(pid: pid, port: port, version: resp.version)
    }

    static func openTicket(timeoutSeconds: Int = 2) throws -> DaemonTicketResult {
        let resp = try send(jsonLine: #"{"cmd":"open_ticket"}"#, timeoutSeconds: timeoutSeconds)
        guard let port = resp.port, let rawURL = resp.url, let url = URL(string: rawURL) else {
            throw DaemonClientError.invalidResponse("open_ticket response missing port or valid url")
        }
        guard url.scheme == "http", url.host == "localhost", url.port == Int(port) else {
            throw DaemonClientError.invalidResponse("refusing non-localhost ticket URL: \(rawURL)")
        }
        return DaemonTicketResult(port: port, url: url)
    }

    private static func send(jsonLine: String, timeoutSeconds: Int) throws -> UdsResponsePayload {
        let path = socketPath()
        guard FileManager.default.fileExists(atPath: path) else {
            throw DaemonClientError.socketNotFound(path)
        }

        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw DaemonClientError.ioFailed("socket() failed: errno \(errno)")
        }
        defer { Darwin.close(fd) }

        var noSigPipe: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        var tv = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        let maxPathLen = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < maxPathLen else {
            throw DaemonClientError.ioFailed("socket path exceeds sockaddr_un limit (\(pathBytes.count) >= \(maxPathLen))")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuf in
            rawBuf.initializeMemory(as: UInt8.self, repeating: 0)
            for (i, b) in pathBytes.enumerated() {
                rawBuf[i] = b
            }
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let connectRes = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectRes == 0 else {
            throw DaemonClientError.connectFailed(path, errno)
        }

        let payload = Array((jsonLine + "\n").utf8)
        var written = 0
        while written < payload.count {
            let n = payload.withUnsafeBytes { buf in
                Darwin.write(fd, buf.baseAddress!.advanced(by: written), payload.count - written)
            }
            if n <= 0 {
                throw DaemonClientError.ioFailed("write() failed: errno \(errno)")
            }
            written += n
        }

        var responseData = Data()
        var chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = Darwin.read(fd, &chunk, chunk.count)
            if n < 0 {
                throw DaemonClientError.ioFailed("read() failed: errno \(errno)")
            }
            if n == 0 {
                break
            }
            responseData.append(contentsOf: chunk[0..<n])
            if chunk[0..<n].contains(UInt8(ascii: "\n")) {
                break
            }
        }

        guard let line = String(data: responseData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !line.isEmpty
        else {
            throw DaemonClientError.invalidResponse("empty UDS response")
        }

        let decoded: UdsResponsePayload
        do {
            decoded = try JSONDecoder().decode(UdsResponsePayload.self, from: Data(line.utf8))
        } catch {
            throw DaemonClientError.invalidResponse("JSON decode failed: \(error.localizedDescription)")
        }

        if !decoded.ok {
            if let err = decoded.error {
                throw DaemonClientError.daemonError(code: err.code, message: err.message, hint: err.hint)
            }
            throw DaemonClientError.invalidResponse("daemon returned ok=false without error payload")
        }
        return decoded
    }
}
