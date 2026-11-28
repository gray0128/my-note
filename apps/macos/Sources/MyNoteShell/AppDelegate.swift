import AppKit
import Foundation
import WebKit

private enum PrefKey {
    static let hotKeyPreset = "MyNoteShell.hotKeyPreset"
    static let hideDockIcon = "MyNoteShell.hideDockIcon"
    static let windowAutosave = "MyNoteShell.MainWindow"
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate {
    private let enableInspector: Bool
    private var window: NSWindow!
    private var webView: WKWebView!
    private var statusItem: NSStatusItem!
    private var hotKeyManager: HotKeyManager!

    private var daemonPort: UInt16?
    private var daemonPid: UInt32?
    private var showingErrorPage = false
    private var previousApp: NSRunningApplication?

    // Hooks used only by `--self-test` mode.
    var onNavigationFinished: ((URL?) -> Void)?
    var onExternalNavigationBlocked: ((URL) -> Void)?
    var suppressExternalOpenForSelfTest = false

    init(enableInspector: Bool = false) {
        self.enableInspector = enableInspector
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        applyActivationPolicy(hideDock: UserDefaults.standard.bool(forKey: PrefKey.hideDockIcon))
        setupMainMenu()
        setupWindowAndWebView()
        setupStatusItem()
        setupHotKey()

        // Connect to daemon immediately on launch so first toggle is warm (< 50 ms).
        authenticateAndLoad()
        showWindow()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showWindow()
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        hotKeyManager?.unregister()
    }

    // MARK: - Window & WebView

    private func setupWindowAndWebView() {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .default()
        config.preferences.javaScriptCanOpenWindowsAutomatically = false

        let frame = NSRect(x: 0, y: 0, width: 1040, height: 740)
        window = NSWindow(
            contentRect: frame,
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "my-note"
        window.minSize = NSSize(width: 640, height: 420)
        window.isReleasedWhenClosed = false
        window.collectionBehavior = [.moveToActiveSpace, .fullScreenPrimary]
        window.delegate = self
        window.center()
        window.setFrameAutosaveName(PrefKey.windowAutosave)

        webView = WKWebView(frame: window.contentView!.bounds, configuration: config)
        webView.autoresizingMask = [.width, .height]
        webView.navigationDelegate = self
        webView.uiDelegate = self
        if #available(macOS 13.3, *) {
            webView.isInspectable = enableInspector
        }
        window.contentView?.addSubview(webView)
    }

    func toggleWindow() {
        if window.isVisible && NSApp.isActive && window.isKeyWindow {
            hideWindowAndRestoreFocus()
        } else {
            showWindow()
        }
    }

    func showWindow() {
        let currentFront = NSWorkspace.shared.frontmostApplication
        if let currentFront, currentFront.processIdentifier != ProcessInfo.processInfo.processIdentifier {
            previousApp = currentFront
        }

        if #available(macOS 14.0, *) {
            NSApp.activate()
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(webView)
        refreshSessionIfDaemonRestarted()
    }

    func hideWindowAndRestoreFocus() {
        window.orderOut(nil)
        if let prev = previousApp, !prev.isTerminated {
            prev.activate(options: [])
        }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        // Closing window hides it instead of terminating (keeps hot-key wake instant & preserves state).
        hideWindowAndRestoreFocus()
        return false
    }

    // MARK: - Daemon Auth & Self-Healing

    func authenticateAndLoad() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result: Result<(DaemonPingResult, DaemonTicketResult), Error>
            do {
                let ping = try DaemonClient.ping(timeoutSeconds: 2)
                let ticket = try DaemonClient.openTicket(timeoutSeconds: 2)
                result = .success((ping, ticket))
            } catch {
                result = .failure(error)
            }

            DispatchQueue.main.async {
                guard let self else { return }
                switch result {
                case .success(let (ping, ticket)):
                    self.daemonPid = ping.pid
                    self.daemonPort = ticket.port
                    self.showingErrorPage = false
                    self.webView.load(URLRequest(url: ticket.url))
                case .failure(let err):
                    self.renderDisconnectedPage(error: err)
                }
            }
        }
    }

    private func refreshSessionIfDaemonRestarted() {
        let knownPid = daemonPid
        let wasError = showingErrorPage
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let ping = try? DaemonClient.ping(timeoutSeconds: 1)
            DispatchQueue.main.async {
                guard let self else { return }
                guard let ping else {
                    if !wasError {
                        self.renderDisconnectedPage(error: DaemonClientError.socketNotFound(DaemonClient.socketPath()))
                    }
                    return
                }
                if wasError || knownPid != ping.pid {
                    self.authenticateAndLoad()
                }
            }
        }
    }

    private func renderDisconnectedPage(error: Error) {
        showingErrorPage = true
        let escaped = escapeHTML(error.localizedDescription)
        let sock = escapeHTML(DaemonClient.socketPath())
        let html = """
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8" />
        <meta name="color-scheme" content="light dark" />
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
            margin: 0; height: 100vh; display: flex; align-items: center; justify-content: center;
            background: canvas; color: canvastext;
          }
          .card { max-width: 460px; padding: 28px; border-radius: 12px; border: 1px solid rgba(128,128,128,.25); }
          h1 { font-size: 17px; margin: 0 0 10px; }
          p { font-size: 13px; line-height: 1.5; opacity: .82; margin: 0 0 12px; }
          code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; word-break: break-all; }
          .hint { padding: 10px 12px; border-radius: 8px; background: rgba(128,128,128,.12); margin-bottom: 14px; }
          a.btn {
            display: inline-block; padding: 7px 14px; border-radius: 7px; text-decoration: none;
            background: #2e5a88; color: #fff; font-size: 13px; font-weight: 500;
          }
        </style>
        </head>
        <body>
          <div class="card">
            <h1>mynote daemon is not reachable</h1>
            <p>\(escaped)</p>
            <div class="hint">
              <div>Socket: <code>\(sock)</code></div>
              <div style="margin-top:6px">Start daemon: <code>mynote daemon</code> or check LaunchAgent <code>com.mynote.daemon</code>.</div>
            </div>
            <a class="btn" href="mynote-shell://retry">Retry Connection (⌘R)</a>
          </div>
        </body>
        </html>
        """
        webView.loadHTMLString(html, baseURL: nil)
    }

    private func escapeHTML(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }

    // MARK: - Menus & Status Item

    private func setupMainMenu() {
        let mainMenu = NSMenu()

        // App menu
        let appItem = NSMenuItem()
        let appMenu = NSMenu(title: "my-note")
        appMenu.addItem(withTitle: "Show / Hide Window", action: #selector(menuToggleWindow), keyEquivalent: "")
        appMenu.addItem(withTitle: "Reload & Re-authenticate", action: #selector(menuReloadAuth), keyEquivalent: "r")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide my-note", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let hideOthers = appMenu.addItem(withTitle: "Hide Others", action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(withTitle: "Quit my-note", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        mainMenu.addItem(appItem)

        // Standard Edit menu — REQUIRED so Cmd+C/V/X/Z/A work inside WKWebView!
        // Intentionally omits Cmd+F / Cmd+P / Cmd+L / Cmd+E so web app shortcuts pass straight through.
        let editItem = NSMenuItem()
        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        let redo = editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        redo.keyEquivalentModifierMask = [.command, .shift]
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu
        mainMenu.addItem(editItem)

        // Window menu — Cmd+W hides window without quitting.
        let winItem = NSMenuItem()
        let winMenu = NSMenu(title: "Window")
        winMenu.addItem(withTitle: "Hide Window", action: #selector(menuHideWindow), keyEquivalent: "w")
        winMenu.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        winItem.submenu = winMenu
        mainMenu.addItem(winItem)

        NSApp.mainMenu = mainMenu
    }

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem.button {
            button.image = makeStatusIcon()
            button.toolTip = "my-note"
            button.target = self
            button.action = #selector(statusItemClicked(_:))
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }
    }

    private func makeStatusIcon() -> NSImage {
        let size = NSSize(width: 18, height: 18)
        let img = NSImage(size: size, flipped: false) { _ in
            NSColor.labelColor.setStroke()
            let card = NSBezierPath(roundedRect: NSRect(x: 2.5, y: 2.5, width: 13, height: 13), xRadius: 2.8, yRadius: 2.8)
            card.lineWidth = 1.4
            card.stroke()

            let lines: [(CGFloat, CGFloat)] = [(11.8, 12.2), (9.0, 10.6), (6.2, 8.8)]
            for (y, endX) in lines {
                let p = NSBezierPath()
                p.move(to: NSPoint(x: 5.2, y: y))
                p.line(to: NSPoint(x: endX, y: y))
                p.lineWidth = 1.4
                p.lineCapStyle = .round
                p.stroke()
            }
            return true
        }
        img.isTemplate = true
        return img
    }

    private func buildStatusMenu() -> NSMenu {
        let menu = NSMenu()
        let title = (window.isVisible && NSApp.isActive) ? "Hide Window" : "Show Window"
        let toggleItem = menu.addItem(withTitle: "\(title) (\(hotKeyManager.currentPreset.label))", action: #selector(menuToggleWindow), keyEquivalent: "")
        toggleItem.target = self

        let reloadItem = menu.addItem(withTitle: "Reload & Re-authenticate", action: #selector(menuReloadAuth), keyEquivalent: "")
        reloadItem.target = self

        menu.addItem(.separator())

        let hkMenuItem = NSMenuItem(title: "Global Hotkey", action: nil, keyEquivalent: "")
        let hkSubmenu = NSMenu()
        for preset in HotKeyPreset.all {
            let item = NSMenuItem(title: preset.label, action: #selector(selectHotKeyPreset(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = preset.id
            item.state = (preset == hotKeyManager.currentPreset) ? .on : .off
            hkSubmenu.addItem(item)
        }
        hkMenuItem.submenu = hkSubmenu
        menu.addItem(hkMenuItem)

        let hideDock = UserDefaults.standard.bool(forKey: PrefKey.hideDockIcon)
        let dockItem = menu.addItem(withTitle: "Menu Bar Only (Hide Dock Icon)", action: #selector(toggleHideDockIcon), keyEquivalent: "")
        dockItem.target = self
        dockItem.state = hideDock ? .on : .off

        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit my-note", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        return menu
    }

    private func setupHotKey() {
        hotKeyManager = HotKeyManager { [weak self] in
            self?.toggleWindow()
        }
        let savedID = UserDefaults.standard.string(forKey: PrefKey.hotKeyPreset)
        let preset = HotKeyPreset.byID(savedID)
        _ = hotKeyManager.register(preset: preset)
    }

    private func applyActivationPolicy(hideDock: Bool) {
        NSApp.setActivationPolicy(hideDock ? .accessory : .regular)
    }

    // MARK: - Menu Actions

    @objc private func statusItemClicked(_ sender: NSStatusBarButton) {
        guard let event = NSApp.currentEvent else {
            toggleWindow()
            return
        }
        if event.type == .rightMouseUp || event.modifierFlags.contains(.control) {
            statusItem.menu = buildStatusMenu()
            statusItem.button?.performClick(nil)
            statusItem.menu = nil
        } else {
            toggleWindow()
        }
    }

    @objc private func menuToggleWindow() {
        toggleWindow()
    }

    @objc private func menuHideWindow() {
        hideWindowAndRestoreFocus()
    }

    @objc private func menuReloadAuth() {
        authenticateAndLoad()
    }

    @objc private func selectHotKeyPreset(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String else { return }
        let preset = HotKeyPreset.byID(id)
        let status = hotKeyManager.register(preset: preset)
        if status == noErr {
            UserDefaults.standard.set(preset.id, forKey: PrefKey.hotKeyPreset)
        }
    }

    @objc private func toggleHideDockIcon() {
        let next = !UserDefaults.standard.bool(forKey: PrefKey.hideDockIcon)
        UserDefaults.standard.set(next, forKey: PrefKey.hideDockIcon)
        applyActivationPolicy(hideDock: next)
        if !next {
            showWindow()
        }
    }

    // MARK: - WKNavigationDelegate (Strict Localhost Origin Guard)

    func isAllowedLocalURL(_ url: URL) -> Bool {
        guard let port = daemonPort else { return false }
        return url.scheme == "http" && url.host == "localhost" && url.port == Int(port)
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }
        if url.absoluteString == "about:blank" {
            decisionHandler(.allow)
            return
        }
        if url.scheme == "mynote-shell" && url.host == "retry" {
            decisionHandler(.cancel)
            authenticateAndLoad()
            return
        }
        if isAllowedLocalURL(url) {
            decisionHandler(.allow)
            return
        }
        if url.scheme == "http" || url.scheme == "https" || url.scheme == "mailto" {
            onExternalNavigationBlocked?(url)
            if !suppressExternalOpenForSelfTest {
                NSWorkspace.shared.open(url)
            }
        }
        decisionHandler(.cancel)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        onNavigationFinished?(webView.url)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        let nsErr = error as NSError
        if nsErr.domain == "WebKitErrorDomain" && nsErr.code == 102 {
            // Frame load interrupted by our intentional policy cancel (e.g. external link).
            return
        }
        if nsErr.domain == NSURLErrorDomain && nsErr.code == NSURLErrorCancelled {
            return
        }
        renderDisconnectedPage(error: error)
    }

    // MARK: - WKUIDelegate (target="_blank", window.prompt, <input type="file">)

    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        if let url = navigationAction.request.url {
            if isAllowedLocalURL(url) {
                webView.load(navigationAction.request)
            } else if url.scheme == "http" || url.scheme == "https" || url.scheme == "mailto" {
                onExternalNavigationBlocked?(url)
                if !suppressExternalOpenForSelfTest {
                    NSWorkspace.shared.open(url)
                }
            }
        }
        return nil
    }

    func webView(
        _ webView: WKWebView,
        runJavaScriptAlertPanelWithMessage message: String,
        initiatedByFrame frame: WKFrameInfo,
        completionHandler: @escaping () -> Void
    ) {
        let alert = NSAlert()
        alert.messageText = "my-note"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.beginSheetModal(for: window) { _ in completionHandler() }
    }

    func webView(
        _ webView: WKWebView,
        runJavaScriptConfirmPanelWithMessage message: String,
        initiatedByFrame frame: WKFrameInfo,
        completionHandler: @escaping (Bool) -> Void
    ) {
        let alert = NSAlert()
        alert.messageText = "my-note"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        alert.beginSheetModal(for: window) { resp in
            completionHandler(resp == .alertFirstButtonReturn)
        }
    }

    func webView(
        _ webView: WKWebView,
        runJavaScriptTextInputPanelWithPrompt prompt: String,
        defaultText: String?,
        initiatedByFrame frame: WKFrameInfo,
        completionHandler: @escaping (String?) -> Void
    ) {
        let alert = NSAlert()
        alert.messageText = prompt
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        input.stringValue = defaultText ?? ""
        alert.accessoryView = input
        window.makeFirstResponder(input)
        alert.beginSheetModal(for: window) { resp in
            completionHandler(resp == .alertFirstButtonReturn ? input.stringValue : nil)
        }
    }

    func webView(
        _ webView: WKWebView,
        runOpenPanelWith parameters: WKOpenPanelParameters,
        initiatedByFrame frame: WKFrameInfo,
        completionHandler: @escaping ([URL]?) -> Void
    ) {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = parameters.allowsMultipleSelection
        panel.canChooseDirectories = parameters.allowsDirectories
        panel.canChooseFiles = true
        panel.beginSheetModal(for: window) { resp in
            completionHandler(resp == .OK ? panel.urls : nil)
        }
    }

    // MARK: - Self-Test Accessors

    var activeWebView: WKWebView { webView }
    var activeWindow: NSWindow { window }
    var currentDaemonPort: UInt16? { daemonPort }
}
