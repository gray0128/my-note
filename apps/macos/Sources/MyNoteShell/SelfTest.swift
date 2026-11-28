import AppKit
import Darwin
import Foundation
import WebKit

private struct SelfTestReport: Encodable {
    let ok: Bool
    let socketPath: String
    let daemonPort: UInt16
    let daemonPid: UInt32
    let udsOpenTicketMs: Double
    let webviewAuthLoadMs: Double
    let toggleShowMs: Double
    let hotKeyRegisterStatus: Int32
    let origin: String
    let originMatches: Bool
    let isSecureContext: Bool
    let cookieHttpOnlySafe: Bool
    let bootstrapApiOk: Bool
    let domAppMounted: Bool
    let wsConnected: Bool
    let externalNavBlocked: Bool
    let shellRssBytes: UInt64
    let error: String?
}

private func currentProcessRssBytes() -> UInt64 {
    var info = mach_task_basic_info()
    var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size) / 4
    let kerr = withUnsafeMutablePointer(to: &info) { ptr in
        ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
            task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), intPtr, &count)
        }
    }
    return kerr == KERN_SUCCESS ? UInt64(info.resident_size) : 0
}

@MainActor
final class SelfTestRunner: NSObject, NSApplicationDelegate {
    private var delegate: AppDelegate!
    private var startedAuthAt: CFAbsoluteTime = 0
    private var ticketMs: Double = 0
    private var daemonPort: UInt16 = 0
    private var daemonPid: UInt32 = 0
    private var hotKeyStatus: Int32 = -1
    private var finished = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.prohibited)

        // 1. Verify UDS ping + open_ticket latency
        let t0 = CFAbsoluteTimeGetCurrent()
        let ping: DaemonPingResult
        let ticket: DaemonTicketResult
        do {
            ping = try DaemonClient.ping(timeoutSeconds: 2)
            ticket = try DaemonClient.openTicket(timeoutSeconds: 2)
        } catch {
            emitAndExit(error: "UDS failed: \(error.localizedDescription)")
            return
        }
        ticketMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000.0
        daemonPort = ticket.port
        daemonPid = ping.pid

        // 2. Verify Carbon RegisterEventHotKey without Accessibility permission
        let hk = HotKeyManager(onTrigger: {})
        hotKeyStatus = hk.register(preset: .defaultPreset)
        hk.unregister()

        // 3. Spin up real AppDelegate + WKWebView off-screen and run auth exchange
        delegate = AppDelegate(enableInspector: false)
        delegate.suppressExternalOpenForSelfTest = true
        delegate.applicationDidFinishLaunching(notification)
        // Hide window off-screen during headless verification so we don't disturb desktop focus
        delegate.activeWindow.setFrameOrigin(NSPoint(x: -5000, y: -5000))
        startedAuthAt = CFAbsoluteTimeGetCurrent()

        delegate.onNavigationFinished = { [weak self] url in
            guard let self, !self.finished else { return }
            guard let url, url.host == "localhost", url.path == "/" else { return }
            let loadMs = (CFAbsoluteTimeGetCurrent() - self.startedAuthAt) * 1000.0
            // Give app.ts ~400ms to finish bootstrap & mount DOM
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.45) {
                self.runWebAssertions(loadMs: loadMs)
            }
        }

        // Timeout guard (10s)
        DispatchQueue.main.asyncAfter(deadline: .now() + 10.0) { [weak self] in
            guard let self, !self.finished else { return }
            self.emitAndExit(error: "Timed out waiting for WKWebView auth/load")
        }
    }

    private func runWebAssertions(loadMs: Double) {
        let js = """
        const res = await fetch('/v1/local/bootstrap', { credentials: 'same-origin', redirect: 'manual' });
        const body = await res.json();
        const wsOk = await new Promise((resolve) => {
          try {
            const ws = new WebSocket(`ws://${window.location.host}/v1/local/ws`);
            const timer = setTimeout(() => { try { ws.close(); } catch {} resolve(false); }, 2000);
            ws.onopen = () => { clearTimeout(timer); ws.close(); resolve(true); };
            ws.onerror = () => { clearTimeout(timer); resolve(false); };
          } catch {
            resolve(false);
          }
        });
        return {
          origin: window.location.origin,
          isSecureContext: Boolean(window.isSecureContext),
          cookieLeaksSession: document.cookie.includes('mynote_local_session'),
          bootstrapOk: res.status === 200 && body && body.ok === true,
          domMounted: document.body.children.length > 0 && document.body.innerText.trim().length > 0,
          wsConnected: wsOk
        };
        """
        delegate.activeWebView.callAsyncJavaScript(js, arguments: [:], in: nil, in: .page) { [weak self] result in
            guard let self, !self.finished else { return }
            switch result {
            case .failure(let err):
                self.emitAndExit(error: "JS assertion failed: \(err.localizedDescription)")
            case .success(let value):
                guard let dict = value as? [String: Any] else {
                    self.emitAndExit(error: "Unexpected JS return value: \(String(describing: value))")
                    return
                }
                let origin = (dict["origin"] as? String) ?? ""
                let expectedOrigin = "http://localhost:\(self.daemonPort)"
                let originMatches = (origin == expectedOrigin)
                let isSecureContext = (dict["isSecureContext"] as? Bool) ?? false
                let cookieSafe = !((dict["cookieLeaksSession"] as? Bool) ?? true)
                let bootstrapOk = (dict["bootstrapOk"] as? Bool) ?? false
                let domMounted = (dict["domMounted"] as? Bool) ?? false
                let wsConnected = (dict["wsConnected"] as? Bool) ?? false

                // 4. Test external navigation blocking guard
                var blocked = false
                self.delegate.onExternalNavigationBlocked = { url in
                    if url.host == "example.com" {
                        blocked = true
                    }
                }
                self.delegate.activeWebView.load(URLRequest(url: URL(string: "https://example.com/")!))

                DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
                    // 5. Measure window show/focus toggle latency
                    let tToggle = CFAbsoluteTimeGetCurrent()
                    self.delegate.activeWindow.orderOut(nil)
                    self.delegate.activeWindow.orderFront(nil)
                    self.delegate.activeWindow.makeFirstResponder(self.delegate.activeWebView)
                    let toggleMs = (CFAbsoluteTimeGetCurrent() - tToggle) * 1000.0
                    self.delegate.activeWindow.orderOut(nil)

                    let ok = originMatches
                        && isSecureContext
                        && cookieSafe
                        && bootstrapOk
                        && domMounted
                        && wsConnected
                        && blocked
                        && (self.hotKeyStatus == noErr)

                    let report = SelfTestReport(
                        ok: ok,
                        socketPath: DaemonClient.socketPath(),
                        daemonPort: self.daemonPort,
                        daemonPid: self.daemonPid,
                        udsOpenTicketMs: (self.ticketMs * 100).rounded() / 100,
                        webviewAuthLoadMs: (loadMs * 100).rounded() / 100,
                        toggleShowMs: (toggleMs * 100).rounded() / 100,
                        hotKeyRegisterStatus: self.hotKeyStatus,
                        origin: origin,
                        originMatches: originMatches,
                        isSecureContext: isSecureContext,
                        cookieHttpOnlySafe: cookieSafe,
                        bootstrapApiOk: bootstrapOk,
                        domAppMounted: domMounted,
                        wsConnected: wsConnected,
                        externalNavBlocked: blocked,
                        shellRssBytes: currentProcessRssBytes(),
                        error: ok ? nil : "One or more assertions returned false"
                    )
                    self.finish(with: report)
                }
            }
        }
    }

    private func emitAndExit(error: String) {
        let report = SelfTestReport(
            ok: false,
            socketPath: DaemonClient.socketPath(),
            daemonPort: daemonPort,
            daemonPid: daemonPid,
            udsOpenTicketMs: ticketMs,
            webviewAuthLoadMs: 0,
            toggleShowMs: 0,
            hotKeyRegisterStatus: hotKeyStatus,
            origin: "",
            originMatches: false,
            isSecureContext: false,
            cookieHttpOnlySafe: false,
            bootstrapApiOk: false,
            domAppMounted: false,
            wsConnected: false,
            externalNavBlocked: false,
            shellRssBytes: currentProcessRssBytes(),
            error: error
        )
        finish(with: report)
    }

    private func finish(with report: SelfTestReport) {
        guard !finished else { return }
        finished = true
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(report), let json = String(data: data, encoding: .utf8) {
            print(json)
        }
        fflush(stdout)
        exit(report.ok ? 0 : 1)
    }
}
