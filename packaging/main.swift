import AppKit
import Foundation
import WebKit

private struct PanelControl: Decodable {
    let port: Int
    let token: String
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate {
    private var statusItem: NSStatusItem!
    private var window: NSWindow!
    private var rootView: NSView!
    private var webView: WKWebView?
    private var activePort: Int?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        if let iconURL = Bundle.main.url(forResource: "HopHarbor", withExtension: "icns"),
           let icon = NSImage(contentsOf: iconURL) {
            NSApp.applicationIconImage = icon
        }
        buildMenu()
        buildWindow()
        buildApplicationMenu()
        showPanel(nil)
    }

    private func buildMenu() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "network", accessibilityDescription: "HopHarbor")
            button.image?.isTemplate = true
            button.toolTip = "HopHarbor — connections run independently of the panel"
        }
        let menu = NSMenu()
        let show = NSMenuItem(title: "Open HopHarbor", action: #selector(showPanel(_:)), keyEquivalent: "o")
        show.target = self
        menu.addItem(show)
        let reload = NSMenuItem(title: "Reload Panel", action: #selector(reloadPanel(_:)), keyEquivalent: "r")
        reload.target = self
        menu.addItem(reload)
        menu.addItem(.separator())
        let hint = NSMenuItem(title: "Closing this panel keeps connections running", action: nil, keyEquivalent: "")
        hint.isEnabled = false
        menu.addItem(hint)
        let quit = NSMenuItem(title: "Quit Panel", action: #selector(quitPanel(_:)), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        statusItem.menu = menu
    }

    private func buildWindow() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1120, height: 760),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "HopHarbor"
        window.minSize = NSSize(width: 780, height: 560)
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.center()
        rootView = NSView(frame: window.contentLayoutRect)
        rootView.wantsLayer = true
        rootView.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        window.contentView = rootView
    }

    private func buildApplicationMenu() {
        let bar = NSMenu()
        let appMenu = NSMenu(title: "HopHarbor")
        let quit = NSMenuItem(title: "Quit Panel", action: #selector(quitPanel(_:)), keyEquivalent: "q")
        quit.target = self
        appMenu.addItem(quit)
        let appItem = NSMenuItem()
        appItem.submenu = appMenu
        bar.addItem(appItem)

        let editMenu = NSMenu(title: "Edit")
        for (title, action, key) in [
            ("Cut", "cut:", "x"), ("Copy", "copy:", "c"),
            ("Paste", "paste:", "v"), ("Select All", "selectAll:", "a")
        ] {
            editMenu.addItem(NSMenuItem(title: title, action: Selector(action), keyEquivalent: key))
        }
        let editItem = NSMenuItem(title: "Edit", action: nil, keyEquivalent: "")
        editItem.submenu = editMenu
        bar.addItem(editItem)

        let windowMenu = NSMenu(title: "Window")
        windowMenu.addItem(NSMenuItem(title: "Close Panel", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w"))
        let windowItem = NSMenuItem(title: "Window", action: nil, keyEquivalent: "")
        windowItem.submenu = windowMenu
        bar.addItem(windowItem)
        NSApp.mainMenu = bar
        NSApp.windowsMenu = windowMenu
    }

    @objc private func showPanel(_ sender: Any?) {
        if webView == nil { loadPanel() }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func reloadPanel(_ sender: Any?) {
        discardPage()
        loadPanel()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func quitPanel(_ sender: Any?) {
        discardPage()
        NSApp.terminate(nil)
    }

    private func controlURL() -> URL {
        if let location = Bundle.main.infoDictionary?["HopHarborDataDirectory"] as? String,
           location.hasPrefix("/") {
            return URL(fileURLWithPath: location, isDirectory: true)
                .appendingPathComponent("control.json")
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/HopHarbor/control.json")
    }

    private func loadPanel() {
        removeChildren()
        let control: PanelControl
        do {
            let url = controlURL()
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
            let size = (attributes[.size] as? NSNumber)?.intValue ?? 0
            guard permissions & 0o077 == 0, size > 0, size <= 16_384 else {
                showError("The panel access file is not ready.", detail: "Start the background service and try again.")
                return
            }
            control = try JSONDecoder().decode(PanelControl.self, from: Data(contentsOf: url))
            guard (1024...65535).contains(control.port), (16...4096).contains(control.token.utf8.count) else {
                showError("The panel connection settings are invalid.", detail: "Check the background service configuration.")
                return
            }
        } catch {
            showError("The background service is not ready.", detail: "Try again once the background service has started.")
            return
        }

        activePort = control.port
        var components = URLComponents()
        components.scheme = "http"
        components.host = "127.0.0.1"
        components.port = control.port
        components.path = "/"
        var permitted = CharacterSet.urlQueryAllowed
        permitted.remove(charactersIn: "&=+#%")
        guard let encoded = control.token.addingPercentEncoding(withAllowedCharacters: permitted) else { return }
        components.percentEncodedFragment = "token=" + encoded
        guard let url = components.url else { return }

        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = false
        let browser = WKWebView(frame: .zero, configuration: configuration)
        browser.translatesAutoresizingMaskIntoConstraints = false
        browser.navigationDelegate = self
        browser.allowsBackForwardNavigationGestures = false
        browser.underPageBackgroundColor = .windowBackgroundColor
        webView = browser
        rootView.addSubview(browser)
        NSLayoutConstraint.activate([
            browser.leadingAnchor.constraint(equalTo: rootView.leadingAnchor),
            browser.trailingAnchor.constraint(equalTo: rootView.trailingAnchor),
            browser.topAnchor.constraint(equalTo: rootView.topAnchor),
            browser.bottomAnchor.constraint(equalTo: rootView.bottomAnchor)
        ])
        browser.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20))
    }

    private func discardPage() {
        // Destroying the page stops its status polling while the panel is closed.
        webView?.stopLoading()
        webView?.navigationDelegate = nil
        webView?.loadHTMLString("<html></html>", baseURL: nil)
        webView?.removeFromSuperview()
        webView = nil
        activePort = nil
    }

    private func removeChildren() {
        rootView.subviews.forEach { $0.removeFromSuperview() }
    }

    private func showError(_ title: String, detail: String) {
        removeChildren()
        let heading = NSTextField(labelWithString: title)
        heading.font = NSFont.systemFont(ofSize: 21, weight: .semibold)
        heading.alignment = .center
        let description = NSTextField(wrappingLabelWithString: detail)
        description.font = NSFont.systemFont(ofSize: 14)
        description.textColor = .secondaryLabelColor
        description.alignment = .center
        let button = NSButton(title: "Try Again", target: self, action: #selector(reloadPanel(_:)))
        button.bezelStyle = .rounded
        let stack = NSStackView(views: [heading, description, button])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 18
        stack.translatesAutoresizingMaskIntoConstraints = false
        rootView.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: rootView.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: rootView.centerYAnchor),
            stack.widthAnchor.constraint(lessThanOrEqualToConstant: 580),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: rootView.leadingAnchor, constant: 32),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: rootView.trailingAnchor, constant: -32)
        ])
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        discardPage()
        sender.orderOut(nil)
        return false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showPanel(nil)
        return true
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }
        if navigationAction.navigationType == .linkActivated,
           url.absoluteString == "https://github.com/kiyanibehzad/HopHarbor" {
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel)
            return
        }
        let isLocal = url.scheme == "http" && url.host == "127.0.0.1" && url.port == activePort
        decisionHandler(isLocal ? .allow : .cancel)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        if (error as NSError).code == NSURLErrorCancelled { return }
        showError("Unable to connect to the panel.", detail: "Check that the background service is running and try again.")
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        if (error as NSError).code == NSURLErrorCancelled { return }
        showError("The panel could not be loaded.", detail: "Reload the panel and try again.")
    }
}

@main
enum ProxyManagerMain {
    @MainActor
    static func main() {
        let application = NSApplication.shared
        let appDelegate = AppDelegate()
        application.delegate = appDelegate
        withExtendedLifetime(appDelegate) { application.run() }
    }
}
