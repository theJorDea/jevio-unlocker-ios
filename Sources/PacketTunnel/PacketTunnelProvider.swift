import NetworkExtension
import JevioCore

/// The Network Extension that hosts the local MTProto proxy in the background.
///
/// On Android the proxy ran inside a foreground Service; on iOS the only way to keep a
/// background network process alive is a Network Extension. We start a minimal packet tunnel
/// (its job is just to keep this process resident) and run `MtProtoProxyServer` on the device
/// loopback so Telegram — configured via the `tg://proxy` deeplink — can reach 127.0.0.1:port.
///
/// NOTE: routing/`NEPacketTunnelNetworkSettings` here is intentionally minimal for the first
/// iteration. See docs/ARCHITECTURE.md "Phase 3" for the routing options (loopback-only vs.
/// routing Telegram DC subnets). Verify on device with a paid Apple Developer account.
class PacketTunnelProvider: NEPacketTunnelProvider {
    private var proxy: MtProtoProxyServer?

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        let cfg = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        let port = (cfg["port"] as? Int).map(UInt16.init) ?? 1443
        let secret = cfg["secretHex"] as? String ?? ""
        let fakeTls = cfg["fakeTlsDomain"] as? String ?? ""
        let cfDomain = cfg["cfDomain"] as? String ?? ""

        let proxyConfig = MtProtoProxyServer.Config(host: "127.0.0.1", port: port,
                                                    secretHex: secret, cfDomain: cfDomain,
                                                    fakeTlsDomain: fakeTls)
        let server = MtProtoProxyServer(config: proxyConfig,
                                        onLog: { NSLog("[Jevio] %@", $0) })
        self.proxy = server

        // Minimal tunnel settings — enough to keep the extension resident. The proxy itself
        // listens on loopback, which is reachable by other apps without routing.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.ipv4Settings = NEIPv4Settings(addresses: ["10.13.37.2"], subnetMasks: ["255.255.255.255"])
        settings.mtu = 1500

        setTunnelNetworkSettings(settings) { error in
            if let error { completionHandler(error); return }
            do {
                try server.start()
                completionHandler(nil)
            } catch {
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        proxy?.stop()
        proxy = nil
        completionHandler()
    }
}
