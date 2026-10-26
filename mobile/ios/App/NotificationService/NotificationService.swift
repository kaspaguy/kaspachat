import UserNotifications

// Runs when Kaspaguy's push service wakes the phone (opt-in, PROTOCOL_SPEC §7). The push names only buckets, which
// other people's messages and cover traffic share, so this fetches the new messages in them and shows "New message"
// only if one carries a tag the app expects. Otherwise it shows nothing (Apple's notification-filtering entitlement).
final class NotificationService: UNNotificationServiceExtension {
    private var done: ((UNNotificationContent) -> Void)?
    private var content: UNMutableNotificationContent?

    override func didReceive(_ request: UNNotificationRequest, withContentHandler handler: @escaping (UNNotificationContent) -> Void) {
        done = handler
        content = request.content.mutableCopy() as? UNMutableNotificationContent
        let d = UserDefaults(suiteName: "group.com.kaspaguy.kaspachat")
        guard let d, let kc = request.content.userInfo["kc"] as? [String: Any], let buckets = kc["b"] as? [Int], !buckets.isEmpty,
              let base = d.string(forKey: "indexer"), !base.isEmpty, let want = d.stringArray(forKey: "watchTags"), !want.isEmpty,
              var url = URLComponents(string: base + "/v1/buckets") else { return finish(show: false) }
        let since = Int(Date().timeIntervalSince1970 * 1000) - 600_000
        url.queryItems = [URLQueryItem(name: "b", value: buckets.prefix(64).map(String.init).joined(separator: ",")), URLQueryItem(name: "since", value: String(since))]
        guard let u = url.url else { return finish(show: false) }
        var req = URLRequest(url: u, timeoutInterval: 20)
        if let a = d.string(forKey: "auth"), !a.isEmpty { req.setValue(a, forHTTPHeaderField: "authorization") }
        let expected = Set(want)
        URLSession.shared.dataTask(with: req) { data, _, _ in
            guard let data, let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let msgs = j["messages"] as? [[String: Any]] else {
                return self.finish(show: false)
            }
            // Payload byte 0 is the version, bytes 1-16 the tag (WIRE_FORMAT §4.1).
            // Oldest first, so trimming to 500 forgets the oldest tags (a Set has no order to trim by).
            var told = d.stringArray(forKey: "notified") ?? []
            let seen = Set(told)
            let hits = Array(Set(msgs.compactMap { $0["p"] as? String }.filter { $0.count >= 34 }.map { String($0.dropFirst(2).prefix(32)) }.filter { expected.contains($0) && !seen.contains($0) }))
            if hits.isEmpty { return self.finish(show: false) }
            told.append(contentsOf: hits)
            d.set(Array(told.suffix(500)), forKey: "notified")
            self.content?.title = "KaspaChat"
            self.content?.body = hits.count == 1 ? "New message" : "\(hits.count) new messages"
            self.finish(show: true)
        }.resume()
    }

    override func serviceExtensionTimeWillExpire() {
        finish(show: false)
    }

    private func finish(show: Bool) {
        guard let done else { return }
        self.done = nil
        done(show ? (content ?? UNMutableNotificationContent()) : UNNotificationContent())
    }
}
