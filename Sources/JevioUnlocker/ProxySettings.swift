import Foundation

/// User-facing proxy settings, shared with the Network Extension through the App Group.
/// (The extension reads the same keys to configure `MtProtoProxyServer`.)
struct ProxySettings: Codable, Equatable {
    var port: Int = 1443
    var secretHex: String
    var fakeTlsDomain: String = "www.cloudflare.com"
    var cfDomain: String = ""

    static let appGroup = "group.com.jevio.unlocker"
    private static let key = "jevio.proxy.settings"

    static func load() -> ProxySettings {
        guard let d = UserDefaults(suiteName: appGroup)?.data(forKey: key),
              let s = try? JSONDecoder().decode(ProxySettings.self, from: d) else {
            return ProxySettings(secretHex: SecretGenerator.generate())
        }
        return s
    }

    func save() {
        guard let d = try? JSONEncoder().encode(self) else { return }
        UserDefaults(suiteName: ProxySettings.appGroup)?.set(d, forKey: ProxySettings.key)
    }

    /// The `tg://proxy` deeplink that points Telegram at our local proxy. Fake TLS uses an
    /// `ee` secret = `ee` + hex(secret) + hex(domain); plain uses `dd` + hex(secret).
    var telegramDeeplink: URL? {
        let secretParam: String
        if fakeTlsDomain.isEmpty {
            secretParam = "dd" + secretHex
        } else {
            secretParam = "ee" + secretHex + Data(fakeTlsDomain.utf8).hexString
        }
        return URL(string: "tg://proxy?server=127.0.0.1&port=\(port)&secret=\(secretParam)")
    }
}

extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
