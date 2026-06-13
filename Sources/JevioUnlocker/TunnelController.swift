import Foundation
import NetworkExtension
import Combine

/// Installs and toggles the Packet Tunnel (our local-proxy host) via NETunnelProviderManager.
/// This is the bridge between the SwiftUI UI and the Network Extension process.
@MainActor
final class TunnelController: ObservableObject {
    @Published var status: NEVPNStatus = .invalid
    @Published var lastError: String?

    private var manager: NETunnelProviderManager?
    private var cancellable: AnyCancellable?

    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let m = managers.first ?? NETunnelProviderManager()
            self.manager = m
            self.status = m.connection.status
            observe(m)
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func observe(_ m: NETunnelProviderManager) {
        cancellable = NotificationCenter.default
            .publisher(for: .NEVPNStatusDidChange, object: m.connection)
            .sink { [weak self] _ in self?.status = m.connection.status }
    }

    /// Create/refresh the VPN profile that runs PacketTunnelProvider.
    private func configure(_ settings: ProxySettings) async throws -> NETunnelProviderManager {
        let m = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.jevio.unlocker.PacketTunnel"
        proto.serverAddress = "127.0.0.1"   // local proxy; shown in Settings as the "server"
        proto.providerConfiguration = [
            "port": settings.port,
            "secretHex": settings.secretHex,
            "fakeTlsDomain": settings.fakeTlsDomain,
            "cfDomain": settings.cfDomain
        ]
        m.protocolConfiguration = proto
        m.localizedDescription = "Jevio Unlocker"
        m.isEnabled = true
        try await m.saveToPreferences()
        try await m.loadFromPreferences()
        self.manager = m
        observe(m)
        return m
    }

    func start(_ settings: ProxySettings) async {
        do {
            let m = try await configure(settings)
            try m.connection.startVPNTunnel()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }
}
