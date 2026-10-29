import AppKit
import Foundation
import WebKit
import Darwin

private struct SmokeFailure: Error, LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

@MainActor
private final class PanelAuthSmokeDriver {
    let delegate: AppDelegate
    let fixture: URL
    let reportURL: URL
    let session = URLSession(configuration: .ephemeral)
    var checks: [String] = []
    var exitCode: Int32 = 1

    init(delegate: AppDelegate, fixture: URL, reportURL: URL) {
        self.delegate = delegate
        self.fixture = fixture
        self.reportURL = reportURL
    }

    func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw SmokeFailure(message: message) }
    }

    func pause(_ seconds: Double) async throws {
        try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
    }

    func wait(_ name: String, timeout: Double = 15,
              until predicate: @escaping @MainActor () async throws -> Bool) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while ProcessInfo.processInfo.systemUptime < deadline {
            do { if try await predicate() { return } } catch { /* A new document may still be loading. */ }
            try await pause(0.05)
        }
        throw SmokeFailure(message: "Timed out: " + name)
    }

    func evaluate(_ code: String, browser supplied: WKWebView? = nil) async throws -> Any {
        guard let browser = supplied ?? delegate.testingBrowser else {
            throw SmokeFailure(message: "The test panel is absent.")
        }
        guard let text = try await browser.evaluateJavaScript("JSON.stringify((" + code + "))") as? String,
              let data = text.data(using: .utf8) else {
            throw SmokeFailure(message: "The test panel returned an unreadable result.")
        }
        return try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    }

    func fixtureCall(_ action: String, body: [String: Any] = [:]) async throws -> [String: Any] {
        var request = URLRequest(url: fixture.appendingPathComponent("fixture/" + action))
        request.httpMethod = "POST"
        request.timeoutInterval = 5
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SmokeFailure(message: "The private fixture control failed.")
        }
        return object
    }

    func document() async throws -> [String: Any] {
        let expression = "({ready:typeof nativeReadySent==='boolean'&&nativeReadySent,"
            + "authorized:typeof authorized==='boolean'&&authorized,"
            + "loaded:typeof loaded==='boolean'&&loaded,"
            + "locked:!document.getElementById('lockedScreen').hidden,"
            + "fragmentEmpty:location.hash==='',label:document.getElementById('serviceLabel').textContent})"
        guard let result = try await evaluate(expression) as? [String: Any] else {
            throw SmokeFailure(message: "The actual document state is unavailable.")
        }
        return result
    }

    func waitOnline(after generation: Int? = nil) async throws {
        try await wait("authenticated panel") {
            if let generation = generation, self.delegate.testingGeneration <= generation { return false }
            let state = try await self.document()
            return state["ready"] as? Bool == true && state["authorized"] as? Bool == true
                && state["loaded"] as? Bool == true && state["locked"] as? Bool == false
                && state["fragmentEmpty"] as? Bool == true
                && state["label"] as? String == "Local service online"
        }
        // Let the actual ready bridge message arrive before the next recovery.
        try await pause(0.1)
    }

    func save(ok: Bool, error: String? = nil) throws {
        var report: [String: Any] = ["ok": ok, "checks": checks,
            "actual_wkwebview": true, "actual_app_delegate": true,
            "synthetic_loopback_only": true, "real_ssh_started": false,
            "actual_system_sleep": false, "forced_renderer_crash": false]
        if let error = error { report["error"] = error }
        let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: reportURL, options: .atomic)
    }

    func passed(_ name: String) throws {
        checks.append(name)
        try save(ok: false)
        print("PASS: " + name)
        fflush(stdout)
    }

    func run() async {
        do {
            delegate.testingNameWindow()
            try await waitOnline()
            try passed("Actual AppDelegate and WKWebView bootstrap authenticate and remove the token fragment")

            let start = delegate.testingGeneration
            _ = try await evaluate("(()=>{const f=document.createElement('iframe');f.id='fixture-frame';f.hidden=true;f.src=location.origin+'/?fixture=frame';document.body.append(f);return true})()")
            try await wait("actual subframe bridge attempt") {
                try await self.evaluate("document.documentElement.dataset.fixtureFrameDone==='true'") as? Bool == true
            }
            _ = try await evaluate("(()=>{window.webkit.messageHandlers.hopharborPanel.postMessage({action:'reauthenticate',reason:'unknown'});window.webkit.messageHandlers.hopharborPanel.postMessage({action:'reauthenticate',reason:'authentication',destination:'http://attacker.invalid/'});return true})()")
            try await pause(0.5)
            try require(delegate.testingGeneration == start && !delegate.testingRecoveryScheduled,
                        "A subframe or malformed recovery message was accepted.")
            try passed("Real subframe and malformed bridge messages cannot schedule recovery")

            guard let racingBrowser = delegate.testingBrowser else { throw SmokeFailure(message: "Current WebView missing.") }
            delegate.testingPrimeRecoveryCooldown()
            delegate.webViewWebContentProcessDidTerminate(racingBrowser)
            try require(delegate.testingRecoveryScheduled, "The authenticated-ready race fixture did not queue recovery.")
            _ = try await evaluate("(window.webkit.messageHandlers.hopharborPanel.postMessage({action:'ready'}),true)")
            try await wait("authenticated ready cancels queued recovery") { !self.delegate.testingRecoveryScheduled }
            try await pause(2.25)
            try require(delegate.testingGeneration == start && !delegate.testingNeedsReauthentication,
                        "A successful authenticated ready message did not cancel the queued reload.")
            try passed("An authenticated ready message cancels a previously queued recovery without reloading")

            guard let browser = delegate.testingBrowser else { throw SmokeFailure(message: "Initial WebView missing.") }
            let cookieStore = browser.configuration.websiteDataStore.httpCookieStore
            let cookies = await withCheckedContinuation { continuation in
                cookieStore.getAllCookies { continuation.resume(returning: $0) }
            }
            let panelCookies = cookies.filter { $0.name == "pm_session" && $0.domain == "127.0.0.1" }
            try require(panelCookies.count == 1, "Expected one synthetic panel session cookie.")
            let cookieGeneration = delegate.testingGeneration
            for cookie in panelCookies {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    cookieStore.delete(cookie) { continuation.resume() }
                }
            }
            _ = try await evaluate("(refresh(true),true)")
            try await waitOnline(after: cookieGeneration)
            try passed("Deleting the real WebKit session cookie recovers automatically through fresh bootstrap")

            let invalidatedGeneration = delegate.testingGeneration
            _ = try await fixtureCall("invalidate")
            _ = try await evaluate("(refresh(true),true)")
            try await waitOnline(after: invalidatedGeneration)
            try passed("Invalidated server-side sessions recover without restarting the fixture service")

            _ = try await fixtureCall("control-token", body: ["valid": false])
            delegate.testingReload()
            try await wait("invalid bootstrap locked screen") {
                let state = try await self.document()
                return state["locked"] as? Bool == true && state["authorized"] as? Bool == false
            }
            let rejectedGeneration = delegate.testingGeneration
            try await pause(2.25)
            try require(delegate.testingGeneration == rejectedGeneration && !delegate.testingRecoveryScheduled,
                        "A rejected bootstrap started an automatic reload loop.")
            _ = try await fixtureCall("control-token", body: ["valid": true])
            _ = try await evaluate("(document.getElementById('lockedRetry').click(),true)")
            try await waitOnline(after: rejectedGeneration)
            try passed("A rejected bootstrap stays bounded and the real Retry button rereads corrected private control settings")

            let budgetGeneration = delegate.testingGeneration
            let budgetStats = try await fixtureCall("state-mode", body: ["always_unauthorized": true])
            let baseLogins = budgetStats["logins"] as? Int ?? -100
            _ = try await evaluate("(refresh(true),true)")
            try await wait("three automatic recovery attempts", timeout: 16) {
                let stats = try await self.fixtureCall("stats")
                return stats["logins"] as? Int == baseLogins + 3
            }
            try await pause(2.25)
            let bounded = try await fixtureCall("stats")
            try require(bounded["logins"] as? Int == baseLogins + 3,
                        "Perpetual 401 responses exceeded three automatic recovery attempts.")
            try require(delegate.testingGeneration == budgetGeneration + 3 && !delegate.testingRecoveryScheduled,
                        "The native recovery generation did not honor the automatic budget.")
            _ = try await fixtureCall("state-mode", body: ["always_unauthorized": false])
            let manualGeneration = delegate.testingGeneration
            _ = try await evaluate("(document.getElementById('lockedRetry').click(),true)")
            try await waitOnline(after: manualGeneration)
            try passed("Perpetual state 401s stop after three automatic attempts; explicit Retry recovers after correction")

            guard let renderer = delegate.testingBrowser else { throw SmokeFailure(message: "Current WebView missing.") }
            let rendererGeneration = delegate.testingGeneration
            delegate.webViewWebContentProcessDidTerminate(renderer)
            try await waitOnline(after: rendererGeneration)
            let current = delegate.testingBrowser
            delegate.webViewWebContentProcessDidTerminate(renderer)
            delegate.webView(renderer, didFail: nil, withError: NSError(domain: NSURLErrorDomain, code: NSURLErrorCannotConnectToHost))
            try await pause(0.2)
            try require(delegate.testingBrowser === current && !delegate.testingRecoveryScheduled,
                        "A stale renderer callback replaced the current panel.")
            try passed("Controlled renderer-termination callback rebuilds the panel and stale renderer/navigation callbacks are ignored")

            guard let hiddenBrowser = delegate.testingBrowser else { throw SmokeFailure(message: "Current WebView missing.") }
            delegate.webViewWebContentProcessDidTerminate(hiddenBrowser)
            try require(delegate.testingRecoveryScheduled, "The visibility cancellation fixture did not queue recovery.")
            delegate.testingHide()
            let hiddenGeneration = delegate.testingGeneration
            try await pause(2.25)
            try require(delegate.testingBrowser == nil && !delegate.testingRecoveryScheduled
                        && delegate.testingGeneration == hiddenGeneration,
                        "A discarded hidden page restarted itself.")
            delegate.testingShow()
            try await waitOnline(after: hiddenGeneration)
            try passed("Hiding discards the page and cancels queued recovery; reopening authenticates a fresh WebView")

            exitCode = 0
            try save(ok: true)
        } catch {
            try? save(ok: false, error: error.localizedDescription)
            fputs("FAIL: \(error.localizedDescription)\n", stderr)
        }
        delegate.testingQuit()
    }
}

@main
enum PanelAuthSmokeMain {
    @MainActor
    static func main() {
        let environment = ProcessInfo.processInfo.environment
        let nativeTemporary = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .resolvingSymlinksInPath().standardizedFileURL
        let declaredData = Bundle.main.object(forInfoDictionaryKey: "HopHarborDataDirectory") as? String
        let dataURL = declaredData.map { URL(fileURLWithPath: $0, isDirectory: true)
            .resolvingSymlinksInPath().standardizedFileURL }
        guard Bundle.main.bundleIdentifier?.hasPrefix("local.hopharbor.panel-auth-test.") == true,
              let declaredData = declaredData, declaredData == environment["HOPHARBOR_TEST_DATA"],
              let dataURL = dataURL, dataURL.lastPathComponent == "data",
              dataURL.deletingLastPathComponent().lastPathComponent.hasPrefix("hopharbor-mac-panel-test-"),
              dataURL.deletingLastPathComponent().deletingLastPathComponent() == nativeTemporary,
              let address = environment["HOPHARBOR_TEST_FIXTURE"], let fixture = URL(string: address),
              fixture.scheme == "http", fixture.host == "127.0.0.1", fixture.port != nil,
              let report = environment["HOPHARBOR_TEST_REPORT"], report.hasPrefix("/"),
              !FileManager.default.fileExists(atPath: report) else {
            fputs("This test requires its unique isolated bundle and loopback fixture.\n", stderr)
            exit(2)
        }
        let application = NSApplication.shared
        let delegate = AppDelegate()
        let driver = PanelAuthSmokeDriver(delegate: delegate, fixture: fixture,
                                          reportURL: URL(fileURLWithPath: report))
        application.delegate = delegate
        let observer = NotificationCenter.default.addObserver(
            forName: NSApplication.didFinishLaunchingNotification, object: nil, queue: .main
        ) { _ in Task { @MainActor in await driver.run() } }
        withExtendedLifetime((delegate, driver, observer)) { application.run() }
        exit(driver.exitCode)
    }
}
