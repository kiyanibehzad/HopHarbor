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
    var frameChecks: [[String: Any]] = []
    var layoutChecks: [[String: Any]] = []
    var noticeChecks: [String] = []
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
                && state["label"] as? String == "Online"
        }
        // Let the actual ready bridge message arrive before the next recovery.
        try await pause(0.1)
    }

    func save(ok: Bool, error: String? = nil) throws {
        var report: [String: Any] = ["ok": ok, "checks": checks, "frame_checks": frameChecks,
            "actual_wkwebview": true, "actual_app_delegate": true, "layout_checks": layoutChecks, "notice_checks": noticeChecks,
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

    func requireChildNeverExecuted(_ name: String, generation: Int, browser: WKWebView) async throws {
        let stats = try await fixtureCall("stats")
        guard let requests = stats["frame_requests"] as? [String: Int] else {
            throw SmokeFailure(message: "The fixture did not report child request counts.")
        }
        let noScript = try await evaluate(
            "!document.documentElement.dataset.fixtureFrameAttempted&&!document.documentElement.dataset.fixtureFrameDone") as? Bool == true
        try require(requests[name, default: 0] == 0 && noScript,
                    "A child document was fetched or executed: " + name)
        try require(delegate.testingGeneration == generation && delegate.testingBrowser === browser
                    && !delegate.testingRecoveryScheduled && !delegate.testingNeedsReauthentication,
                    "A child or popup caused panel authentication recovery: " + name)
        frameChecks.append(["case": name, "child_requests": requests[name, default: 0],
            "child_script_executed": !noScript, "panel_generation_changed": false])
    }

    func saveLayoutSnapshot(_ label: String) async throws {
        guard let browser=delegate.testingBrowser else { return }
        let image=try await browser.takeSnapshot(configuration:nil)
        if let tiff=image.tiffRepresentation,let bitmap=NSBitmapImageRep(data:tiff),
           let png=bitmap.representation(using:.png,properties:[:]) {
            let name=reportURL.deletingPathExtension().lastPathComponent+"-"+label+"-dark.png"
            try png.write(to:reportURL.deletingLastPathComponent().appendingPathComponent(name))
        }
    }

    func checkUpdatesLayout() async throws {
        guard let window = NSApp.windows.first(where: { $0.title == "HopHarbor — isolated panel test" }) else {
            throw SmokeFailure(message: "Isolated layout window missing.")
        }
        let originalFrame = window.frame, originalMinimum = window.minSize
        defer { window.minSize = originalMinimum; window.setFrame(originalFrame, display: true) }
        window.minSize = NSSize(width: 320, height: 480)
        for width in [1120, 780, 320] {
            window.setContentSize(NSSize(width: width, height: 760))
            try await pause(0.15)
            for mode in ["system", "light", "dark"] {
                _ = try await evaluate("(closeUpdates(),true)")
                _ = try await evaluate("(changeAppearance('" + mode + "'),goView('servers'),true)")
                let closed = try await evaluate("(()=>{const p=document.querySelector('.sidebar-bottom'),b=document.getElementById('updatesToggle'),r=b.getBoundingClientRect();return {height:r.height,hidden:getComputedStyle(document.getElementById('updatesContent')).display==='none',plain:p.innerText.trim()===(innerWidth>820?'Online':''),width:innerWidth}})()") as? [String:Any] ?? [:]
                try require(closed["hidden"] as? Bool == true && closed["plain"] as? Bool == true
                    && (closed["height"] as? Double ?? 99)<=34,"Default status row is cluttered: " + String(describing:closed))
                if mode == "dark", width == 1120 || width == 780 {
                    try await saveLayoutSnapshot(String(width) + "-closed")
                }
                _ = try await evaluate("(()=>{const b=document.getElementById('updatesToggle');if(getComputedStyle(b).display!=='none'&&b.getAttribute('aria-expanded')!=='true')b.click();return true})()")
                let geometry = try await evaluate("(()=>{const b=document.getElementById('appearanceSelect'),s=b.querySelector('svg'),br=b.getBoundingClientRect(),sr=s.getBoundingClientRect(),c=document.getElementById('checkRelease'),cr=c.getBoundingClientRect(),v=document.getElementById('appVersion'),vr=v.getBoundingClientRect(),p=document.getElementById('updatesContent'),pr=p.getBoundingClientRect(),native=window.HopHarborNativeVersion;return {width:innerWidth,mode:document.documentElement.dataset.appearance,dx:(sr.left+sr.width/2)-(br.left+br.width/2),dy:(sr.top+sr.height/2)-(br.top+br.height/2),buttonWidth:br.width,buttonHeight:br.height,svgCount:b.querySelectorAll('svg').length,radius:getComputedStyle(b).borderRadius,sidebar:!!c.closest('.sidebar-bottom')&&!!v.closest('.sidebar-bottom'),unique:document.querySelectorAll('#appVersion').length===1&&document.querySelectorAll('#checkRelease').length===1&&document.querySelectorAll('#releaseStatus').length===1,footerCopies:document.querySelectorAll('.page-foot #appVersion,.page-foot #checkRelease,.page-foot #releaseStatus').length,metadata:v.textContent==='v'+native.version+' · build '+native.build,visible:cr.width>0&&cr.height>0&&vr.width>0,clickable:document.elementFromPoint(cr.left+cr.width/2,cr.top+cr.height/2)?.closest('#checkRelease')===c,inside:pr.left>=0&&pr.right<=innerWidth+1&&pr.top>=0&&pr.bottom<=innerHeight+1,noOverflow:document.documentElement.scrollWidth<=innerWidth+1}})()") as? [String: Any] ?? [:]
                try require(abs(geometry["dx"] as? Double ?? 99) <= 0.25
                    && abs(geometry["dy"] as? Double ?? 99) <= 0.25
                    && geometry["buttonWidth"] as? Double == 34 && geometry["buttonHeight"] as? Double == 34
                    && geometry["svgCount"] as? Int == 1 && geometry["radius"] as? String == "7px",
                    "Appearance SVG is not centered in its 34px frame: " + String(describing: geometry))
                for key in ["sidebar", "unique", "metadata", "visible", "clickable", "inside", "noOverflow"] {
                    try require(geometry[key] as? Bool == true, "Updates layout failed " + key + ": " + String(describing: geometry))
                }
                try require(geometry["footerCopies"] as? Int == 0, "Duplicate version/update controls remain in the footer.")
                layoutChecks.append(geometry)
                if mode == "dark", width == 1120 || width == 780 {
                    if let browser = delegate.testingBrowser {
                        let image = try await browser.takeSnapshot(configuration: nil)
                        if let tiff = image.tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff),
                           let png = bitmap.representation(using: .png, properties: [:]) {
                            let name = reportURL.deletingPathExtension().lastPathComponent + "-" + String(width) + "-dark.png"
                            try png.write(to: reportURL.deletingLastPathComponent().appendingPathComponent(name))
                        }
                    }
                }
            }
            for view in ["dashboard", "tunnels", "servers", "logs"] {
                _ = try await evaluate("(goView('" + view + "'),true)")
                let visible = try await evaluate("(()=>{const b=document.getElementById('checkRelease'),r=b.getBoundingClientRect();return r.width>0&&document.elementFromPoint(r.left+r.width/2,r.top+r.height/2)?.closest('#checkRelease')===b})()") as? Bool
                try require(visible == true, "Updates are inaccessible on " + view + " at width " + String(width))
            }
            do {
                let escaped = try await evaluate("(()=>{document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));return document.getElementById('updatesToggle').getAttribute('aria-expanded')==='false'&&document.activeElement===document.getElementById('updatesToggle')})()") as? Bool
                try require(escaped == true, "Compact updates Escape/focus behavior failed.")
                _ = try await evaluate("(document.getElementById('updatesToggle').click(),true)")
            }
        }
        _ = try await evaluate("(openUpdates(),document.getElementById('checkRelease').click(),true)")
        try await wait("Check for updates from sidebar") {
            try await self.evaluate("document.getElementById('releaseStatus').textContent.includes('9.0.0')&&document.getElementById('releaseLink').href==='https://github.com/kiyanibehzad/HopHarbor/releases/tag/v9.0.0'") as? Bool == true
        }
        let stats = try await fixtureCall("stats")
        try require(stats["release_checks"] as? Int == 1, "Sidebar Check for updates did not reach the synthetic service exactly once.")
        _ = try await evaluate("(closeUpdates(),changeAppearance('system'),goView('dashboard'),true)")
        try passed("Centered appearance SVG and sidebar metadata/updates pass all themes, all tabs, 1120/780/320px widths, native click, safe release link and keyboard focus")
    }

    func releaseFixture(_ status:String,_ version:String) async throws {
        _ = try await fixtureCall("release",body:["status":status,"version":version])
        _ = try await evaluate("(refresh(true),true)")
        try await wait("release fixture refresh") {
            try await self.evaluate("state.service.release.status==='"+status+"'&&state.service.release.latest_version==='"+version+"'") as? Bool == true
        }
    }

    func checkReleaseNotices() async throws {
        _ = try await evaluate("(closeUpdates(),localStorage.removeItem(RELEASE_NOTICE_KEY),releaseNoticeSeen='',true)")
        for (status,version) in [("older","1.3.2"),("current","1.4.0"),("unavailable","1.3.2"),("unchecked","1.3.2"),("available","invalid")] {
            try await releaseFixture(status,version)
            let quiet = try await evaluate("document.getElementById('updatesToggle').getAttribute('aria-expanded')==='false'&&document.getElementById('updateNotice').hidden") as? Bool
            try require(quiet == true,"A non-new release produced an announcement.")
        }
        noticeChecks.append("equal, older, offline, unchecked and invalid results stay silent")
        _ = try await evaluate("(document.getElementById('primaryAction').focus(),openServer(),true)")
        try await releaseFixture("available","1.5.0")
        let deferred = try await evaluate("document.getElementById('serverDialog').open&&document.activeElement===document.getElementById('serverName')&&document.getElementById('updatesToggle').getAttribute('aria-expanded')==='false'") as? Bool
        try require(deferred == true,"Release announcement interrupted a modal editor.")
        _ = try await evaluate("(document.getElementById('serverDialog').close(),true)")
        try await wait("deferred release announcement") {
            try await self.evaluate("document.getElementById('updatesToggle').getAttribute('aria-expanded')==='true'&&localStorage.getItem(RELEASE_NOTICE_KEY)==='1.5.0'") as? Bool == true
        }
        let noFocus = try await evaluate("document.activeElement!==document.getElementById('checkRelease')&&document.activeElement!==document.getElementById('updatesToggle')") as? Bool
        try require(noFocus == true,"Automatic announcement stole focus.")
        noticeChecks.append("new release defers until modal closes and opens without focus theft")
        _ = try await evaluate("(document.getElementById('updatesClose').click(),refresh(true),true)")
        try await pause(0.15)
        let dismissed = try await evaluate("document.getElementById('updatesToggle').getAttribute('aria-expanded')==='false'&&!document.getElementById('updateNotice').hidden") as? Bool
        try require(dismissed == true,"A dismissed release re-opened during render or lost its small badge.")
        let generation=delegate.testingGeneration;delegate.testingReload();try await waitOnline(after:generation)
        let persisted = try await evaluate("document.getElementById('updatesToggle').getAttribute('aria-expanded')==='false'&&releaseNoticeSeen==='1.5.0'") as? Bool
        try require(persisted == true,"Release dismissal did not survive a fresh actual WKWebView.")
        noticeChecks.append("dismissal survives render, refresh and a fresh WKWebView")
        _ = try await evaluate("(document.getElementById('updatesToggle').click(),true)")
        let manual = try await evaluate("document.getElementById('updatesToggle').getAttribute('aria-expanded')==='true'") as? Bool
        try require(manual == true,"Status row cannot manually reopen details.")
        _ = try await evaluate("(document.getElementById('pageTitle').click(),true)")
        let outside = try await evaluate("document.getElementById('updatesToggle').getAttribute('aria-expanded')==='false'") as? Bool
        try require(outside == true,"Outside click did not close details.")
        noticeChecks.append("manual reopening and outside dismissal remain available")
        _ = try await evaluate("(Object.defineProperty(document,'hidden',{configurable:true,value:true}),document.getElementById('primaryAction').focus(),true)")
        try await releaseFixture("available","1.6.0")
        let hidden = try await evaluate("document.getElementById('updatesToggle').getAttribute('aria-expanded')==='false'") as? Bool
        try require(hidden == true,"A hidden document opened an announcement.")
        _ = try await evaluate("(delete document.hidden,document.dispatchEvent(new Event('visibilitychange')),true)")
        try await wait("newer next release on visibility") {
            try await self.evaluate("document.getElementById('updatesToggle').getAttribute('aria-expanded')==='true'&&releaseNoticeSeen==='1.6.0'") as? Bool == true
        }
        let visibleNoFocus = try await evaluate("document.activeElement===document.getElementById('primaryAction')") as? Bool
        try require(visibleNoFocus == true,"Visibility announcement stole focus.")
        noticeChecks.append("a strictly newer next release opens once at the first visible opportunity")
        _ = try await evaluate("(closeUpdates(),true)")
        delegate.testingHide()
        _ = try await fixtureCall("release",body:["status":"available","version":"1.7.0"])
        delegate.testingShow();try await waitOnline()
        try await wait("release after hidden native panel reopen") {
            try await self.evaluate("document.getElementById('updatesToggle').getAttribute('aria-expanded')==='true'&&releaseNoticeSeen==='1.7.0'") as? Bool == true
        }
        _ = try await evaluate("(document.getElementById('updatesClose').click(),true)")
        delegate.testingHide();delegate.testingShow();try await waitOnline()
        let once = try await evaluate("document.getElementById('updatesToggle').getAttribute('aria-expanded')==='false'&&releaseNoticeSeen==='1.7.0'") as? Bool
        try require(once == true,"Native hide/reopen repeated an acknowledged release.")
        noticeChecks.append("native hidden panel waits for reopen; the same release does not reopen again")
        try await releaseFixture("older","1.3.2")
        _ = try await evaluate("(closeUpdates(),true)")
        try passed("Release notices are numeric, quiet by default, modal/visibility-aware, focus-preserving and persistent once per release")
    }

    func run() async {
        do {
            delegate.testingNameWindow()
            try await waitOnline()
            try passed("Actual AppDelegate and WKWebView bootstrap authenticate and remove the token fragment")

            // Exercise the real WKWebView, including the existing preference key.
            _ = try await evaluate("(changeAppearance('system'),true)")
            for (mode, next) in [("system", "Light"), ("light", "Dark"), ("dark", "System")] {
                let appearance = try await evaluate("(()=>{const b=document.getElementById('appearanceSelect'),r=b.getBoundingClientRect();return {mode:document.documentElement.dataset.appearance,label:b.getAttribute('aria-label'),width:r.width,height:r.height,svg:b.querySelectorAll('svg').length,tag:b.tagName}})()") as? [String: Any] ?? [:]
                try require(appearance["mode"] as? String == mode && appearance["tag"] as? String == "BUTTON"
                    && appearance["svg"] as? Int == 1 && appearance["width"] as? Double == 34
                    && appearance["height"] as? Double == 34
                    && (appearance["label"] as? String)?.contains("Switch to " + next) == true,
                    "Compact appearance button has incorrect mode, label or geometry.")
                _ = try await evaluate("(document.getElementById('appearanceSelect').click(),true)")
            }
            _ = try await evaluate("(changeAppearance('dark'),true)")
            let appearanceGeneration = delegate.testingGeneration
            delegate.testingReload()
            try await waitOnline(after: appearanceGeneration)
            let savedAppearance = try await evaluate("document.documentElement.dataset.appearance") as? String
            try require(savedAppearance == "dark",
                        "The existing saved appearance preference did not survive reload.")
            _ = try await evaluate("(changeAppearance('system'),window.HopHarborSystemDark=true,window.dispatchEvent(new Event('hopharbor-system-appearance')),true)")
            let systemDark = try await evaluate("document.documentElement.dataset.theme") as? String
            try require(systemDark == "dark", "System dark change was not applied.")
            _ = try await evaluate("(window.HopHarborSystemDark=false,window.dispatchEvent(new Event('hopharbor-system-appearance')),true)")
            let systemLight = try await evaluate("document.documentElement.dataset.theme") as? String
            try require(systemLight == "light", "System light change was not applied.")
            _ = try await evaluate("(delete window.HopHarborSystemDark,applyAppearance(),true)")
            try passed("Compact 34-point appearance button cycles all modes, persists existing preference and follows live System changes")

            try await checkUpdatesLayout()
            try await checkReleaseNotices()

            let start = delegate.testingGeneration
            for name in ["direct", "parent-native", "parent-wrapper"] {
                guard let browser = delegate.testingBrowser else { throw SmokeFailure(message: "Current WebView missing.") }
                let blocked = delegate.testingBlockedFrameNavigations
                _ = try await evaluate("(()=>{const f=document.createElement('iframe');f.id='fixture-frame';f.hidden=true;f.src=location.origin+'/?fixture=frame&case=" + name + "';document.body.append(f);return true})()")
                try await wait("native child navigation cancellation: " + name) {
                    self.delegate.testingBlockedFrameNavigations > blocked
                }
                try await pause(0.2)
                try await requireChildNeverExecuted(name, generation: start, browser: browser)
                _ = try await evaluate("(document.getElementById('fixture-frame').remove(),true)")
                try passed("Native navigation prevents child execution before its " + name + " bridge call")
            }

            guard let popupBrowser = delegate.testingBrowser else { throw SmokeFailure(message: "Current WebView missing.") }
            _ = try await evaluate("(window.open(location.origin+'/?fixture=frame&case=popup','_blank'),true)")
            try await pause(0.5)
            try await requireChildNeverExecuted("popup", generation: start, browser: popupBrowser)
            try passed("A popup cannot open a child document or initiate panel recovery")

            _ = try await evaluate("(()=>{window.webkit.messageHandlers.hopharborPanel.postMessage({action:'reauthenticate',reason:'unknown'});window.webkit.messageHandlers.hopharborPanel.postMessage({action:'reauthenticate',reason:'authentication',destination:'http://attacker.invalid/'});return true})()")
            try await pause(0.5)
            try require(delegate.testingGeneration == start && !delegate.testingRecoveryScheduled,
                        "A malformed recovery message was accepted.")
            try passed("Malformed main-frame bridge messages cannot schedule recovery")

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
            guard let staleNavigation = delegate.testingMainFrameNavigation else {
                throw SmokeFailure(message: "A real main-frame navigation was not observed.")
            }
            let rendererGeneration = delegate.testingGeneration
            delegate.webViewWebContentProcessDidTerminate(renderer)
            try await waitOnline(after: rendererGeneration)
            let current = delegate.testingBrowser
            delegate.webViewWebContentProcessDidTerminate(renderer)
            delegate.webView(renderer, didFail: nil, withError: NSError(domain: NSURLErrorDomain, code: NSURLErrorCannotConnectToHost))
            var stalePolicy: WKNavigationActionPolicy?
            delegate.webView(renderer, decidePolicyFor: staleNavigation) { stalePolicy = $0 }
            try await pause(0.2)
            try require(stalePolicy == .cancel && delegate.testingBrowser === current && !delegate.testingRecoveryScheduled,
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
