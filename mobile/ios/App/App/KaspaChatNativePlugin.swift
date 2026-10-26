import Capacitor
import KaspaChatTor
import Network

// iPhone side of the app's native plugin.
// setWatch hands the notification extension what it needs to recognise this account's messages: the upcoming message
// tags (hex) and where to fetch new messages. Stored in the app group, which only this app and its extension can read.
// torStart/torFetch: the Tor built into the app (tor/, Arti, KaspaChatTor.xcframework), as on Android (PROTOCOL_SPEC §6.3).
@objc(KaspaChatNativePlugin)
public class KaspaChatNativePlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "KaspaChatNativePlugin"
    public let jsName = "KaspaChatNative"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "setWatch", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "torStart", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "torFetch", returnType: CAPPluginReturnPromise),
    ]

    private static let torQueue = DispatchQueue(label: "com.kaspaguy.kaspachat.tor")
    private static var torPort: Int32 = 0
    private static var session: (port: Int, s: URLSession)?
    private static let sessionLock = NSLock()

    @objc func setWatch(_ call: CAPPluginCall) {
        guard let d = UserDefaults(suiteName: "group.com.kaspaguy.kaspachat") else { return call.reject("app group unavailable") }
        d.set(call.getArray("tags", String.self) ?? [], forKey: "watchTags")
        d.set(call.getString("indexer") ?? "", forKey: "indexer")
        d.set(call.getString("auth") ?? "", forKey: "auth")
        call.resolve()
    }

    // Starts Tor once (blocks until it is ready, so off the main thread) and returns the SOCKS port.
    @objc func torStart(_ call: CAPPluginCall) {
        let host = call.getString("host") ?? ""
        Self.torQueue.async {
            if Self.torPort == 0 {
                var dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("tor")
                try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                var v = URLResourceValues()
                v.isExcludedFromBackup = true
                try? dir.setResourceValues(v)
                let p = kc_tor_start(dir.path, host)
                if p <= 0 { return call.reject(String(cString: kc_tor_error())) }
                Self.torPort = p
            }
            call.resolve(["port": Int(Self.torPort)])
        }
    }

    // One request through the SOCKS port. The onion host is resolved by Tor, never by the phone's DNS.
    @objc func torFetch(_ call: CAPPluginCall) {
        guard let s = call.getString("url"), let url = URL(string: s) else { return call.reject("bad url") }
        var req = URLRequest(url: url, timeoutInterval: 60)
        req.httpMethod = call.getString("method") ?? "GET"
        for (k, v) in call.getObject("headers") ?? [:] { if let v = v as? String { req.setValue(v, forHTTPHeaderField: k) } }
        if let b = call.getString("body") { req.httpBody = Data(b.utf8) }
        Self.torSession(port: call.getInt("port") ?? 0).dataTask(with: req) { data, res, err in
            guard let h = res as? HTTPURLResponse else { return call.reject("Tor request failed: \(err?.localizedDescription ?? "no response")") }
            var headers = JSObject()
            for (k, v) in h.allHeaderFields { if let k = k as? String { headers[k.lowercased()] = "\(v)" } }
            call.resolve(["status": h.statusCode, "headers": headers, "body": String(decoding: data ?? Data(), as: UTF8.self)])
        }.resume()
    }

    private static func torSession(port: Int) -> URLSession {
        sessionLock.lock()
        defer { sessionLock.unlock() }
        if let s = session, s.port == port { return s.s }
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForResource = 120
        if #available(iOS 17.0, *) {
            c.proxyConfigurations = [ProxyConfiguration(socksv5Proxy: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: UInt16(port))!))]
        } else {
            c.connectionProxyDictionary = ["SOCKSEnable": 1, "SOCKSProxy": "127.0.0.1", "SOCKSPort": port]
        }
        let s = URLSession(configuration: c)
        session = (port, s)
        return s
    }
}
