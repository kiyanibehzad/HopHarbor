import Foundation

// Native recovery never receives an access token or a destination from the page.
struct PanelRecoveryPolicy {
    private var automaticAttempts: [TimeInterval] = []
    private var lastScheduled: TimeInterval?
    let window: TimeInterval = 60
    let interval: TimeInterval = 2
    let automaticLimit = 3

    mutating func delay(manual: Bool, now: TimeInterval) -> TimeInterval? {
        automaticAttempts.removeAll { now - $0 >= window }
        if !manual && automaticAttempts.count >= automaticLimit { return nil }
        let delay = max(0, interval - (now - (lastScheduled ?? (now - interval))))
        let scheduled = now + delay
        lastScheduled = scheduled
        if !manual { automaticAttempts.append(scheduled) }
        return delay
    }

    mutating func authenticated() {
        automaticAttempts.removeAll()
    }

    static func trustsMessage(currentView: Bool, mainFrame: Bool, scheme: String,
                              host: String, port: Int, frameURL: URL?, activePort: Int?) -> Bool {
        guard currentView, mainFrame, let activePort = activePort,
              scheme == "http", host == "127.0.0.1", port == activePort,
              let url = frameURL, url.scheme == "http", url.host == "127.0.0.1",
              url.port == activePort, url.user == nil, url.password == nil,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              ["/", "/index.html"].contains(components.percentEncodedPath) else { return false }
        return true
    }
}
