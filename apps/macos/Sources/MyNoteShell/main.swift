import AppKit
import Foundation

MainActor.assumeIsolated {
    let args = CommandLine.arguments
    let app = NSApplication.shared

    if args.contains("--self-test") {
        let runner = SelfTestRunner()
        app.delegate = runner
        app.run()
    } else {
        let enableInspector = args.contains("--inspect")
        let delegate = AppDelegate(enableInspector: enableInspector)
        app.delegate = delegate
        app.run()
    }
}
