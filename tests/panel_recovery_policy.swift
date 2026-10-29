import Foundation

private struct CheckFailure: Error { let name: String }

@main
enum PanelRecoveryPolicyChecks {
    static func main() {
        do { try run() }
        catch {
            fputs("Policy check failed: \(error)\n", stderr)
            exit(1)
        }
    }

    static func run() throws {
        var checks: [String] = []
        func check(_ name: String, _ condition: @autoclosure () -> Bool) throws {
            guard condition() else { throw CheckFailure(name: name) }
            checks.append(name)
        }

        var policy = PanelRecoveryPolicy()
        try check("first automatic recovery has no artificial delay", policy.delay(manual: false, now: 100) == 0)
        try check("automatic attempts are spaced by two seconds", policy.delay(manual: false, now: 100.25) == 1.75)
        try check("third automatic attempt is admitted", policy.delay(manual: false, now: 104) == 0)
        try check("fourth automatic attempt is refused", policy.delay(manual: false, now: 106) == nil)
        try check("explicit Retry remains possible after the automatic budget", policy.delay(manual: true, now: 106) == 0)
        try check("manual Retry does not clear the automatic budget", policy.delay(manual: false, now: 108) == nil)
        try check("the sixty-second window is not shortened", policy.delay(manual: false, now: 159.999) == nil)
        try check("an expired automatic attempt leaves the rolling window", policy.delay(manual: false, now: 160) == 0)
        policy.authenticated()
        try check("authenticated success restores the budget but keeps the cooldown", policy.delay(manual: false, now: 160.5) == 1.5)

        func trusted(current: Bool = true, main: Bool = true, scheme: String = "http",
                     host: String = "127.0.0.1", port: Int = 21899,
                     url: String? = "http://127.0.0.1:21899/", active: Int? = 21899) -> Bool {
            PanelRecoveryPolicy.trustsMessage(currentView: current, mainFrame: main,
                scheme: scheme, host: host, port: port,
                frameURL: url.flatMap(URL.init(string:)), activePort: active)
        }
        try check("the current local main frame is accepted", trusted())
        try check("the explicit local index path is accepted", trusted(url: "http://127.0.0.1:21899/index.html"))
        let rejected: [(String, Bool)] = [
            ("a stale WebView", trusted(current: false)),
            ("a subframe", trusted(main: false)),
            ("an absent active endpoint", trusted(active: nil)),
            ("a foreign security-origin host", trusted(host: "attacker.invalid")),
            ("a localhost alias", trusted(host: "localhost")),
            ("a different security-origin port", trusted(port: 21900)),
            ("a different security-origin scheme", trusted(scheme: "https")),
            ("an absent frame URL", trusted(url: nil)),
            ("a foreign frame URL", trusted(url: "http://attacker.invalid:21899/")),
            ("a frame URL on a different port", trusted(url: "http://127.0.0.1:21900/")),
            ("a frame URL with a different scheme", trusted(url: "https://127.0.0.1:21899/")),
            ("a URL containing a username", trusted(url: "http://user@127.0.0.1:21899/")),
            ("a URL containing a password", trusted(url: "http://user:password@127.0.0.1:21899/")),
            ("an API document", trusted(url: "http://127.0.0.1:21899/api/state")),
            ("a non-panel resource", trusted(url: "http://127.0.0.1:21899/app.js")),
            ("an encoded lookalike path", trusted(url: "http://127.0.0.1:21899/%69ndex.html")),
            ("a lookalike path", trusted(url: "http://127.0.0.1:21899/index.html/"))
        ]
        for (name, result) in rejected { try check("reject " + name, !result) }
        let report: [String: Any] = ["ok": true, "checks": checks, "count": checks.count]
        let data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
        print(String(decoding: data, as: UTF8.self))
    }
}
