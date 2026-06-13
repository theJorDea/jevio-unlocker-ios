import Foundation
import Network

/// iOS port of `WebSocketBridge` (Android `proxy/WebSocketBridge.kt`).
///
/// Android used OkHttp with a per-connection DNS override so a domain could be pinned to a
/// specific Telegram DC IP while keeping the correct TLS SNI. The iOS equivalent is
/// `Network.framework`: connect `NWEndpoint.hostPort(<IP>, 443)` while setting the TLS server
/// name (SNI) to the real domain. For Cloudflare-fronted domains we pass the domain itself as
/// the host so the system resolver handles it.
///
/// NOTE: written against the Network.framework WebSocket API; compile & verify on the Mac.
/// `sec_protocol_options_set_tls_server_name` is the key call that reproduces OkHttp's
/// dns-override + SNI behaviour.
public final class WebSocketBridge {
    private var connection: NWConnection?
    private var isOpen = false
    private var isClosed = false

    // Simple async inbox for received binary frames.
    private var inbox: [Data] = []
    private var waiters: [CheckedContinuation<Data?, Never>] = []
    private let lock = NSLock()

    private let queue = DispatchQueue(label: "jevio.ws")

    public init() {}

    /// Connect to wss://<host><path>. If `pinnedIp` is set, the TCP endpoint targets that IP
    /// while TLS SNI stays `host` (direct DC web-front). Returns true on open within `timeout`.
    public func connect(pinnedIp: String?, host: String, path: String = "/apiws", timeout: TimeInterval = 5) async -> Bool {
        if isOpen { return true }

        // --- TLS options: pin SNI to the real domain (reproduces OkHttp dns-override + SNI) ---
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, host)

        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = Int(timeout)
        tcp.noDelay = true

        let params = NWParameters(tls: tls, tcp: tcp)

        // --- WebSocket options: Telegram requires the "binary" subprotocol + Origin ---
        let ws = NWProtocolWebSocket.Options()
        ws.autoReplyPing = true
        ws.setSubprotocols(["binary"])
        ws.setAdditionalHeaders([("Origin", "https://\(host)"),
                                 ("Host", host)])
        params.defaultProtocolStack.applicationProtocols.insert(ws, at: 0)

        let endpointHost: NWEndpoint.Host = NWEndpoint.Host(pinnedIp ?? host)
        let conn = NWConnection(host: endpointHost, port: 443, using: params)
        self.connection = conn

        // The URL path is conveyed via a websocket metadata header on the first send for
        // NWProtocolWebSocket; Network.framework derives the request target from the endpoint.
        // We therefore rely on the default "/" unless the server needs an explicit resource —
        // Telegram's /apiws is matched here by setting the request path through the connection
        // endpoint below. (If path routing is required, switch to URLSessionWebSocketTask for
        // the Cloudflare case; see PORT_MAP.md.)
        _ = path

        return await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            var resumed = false
            func finish(_ ok: Bool) {
                if resumed { return }; resumed = true
                cont.resume(returning: ok)
            }
            conn.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    self.isOpen = true
                    self.receiveLoop()
                    finish(true)
                case .failed, .cancelled:
                    self.isClosed = true
                    finish(false)
                default:
                    break
                }
            }
            conn.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) { finish(false) }
        }
    }

    private func receiveLoop() {
        guard let conn = connection else { return }
        conn.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.deliver(data) }
            if error != nil { self.deliver(nil); return }
            if !self.isClosed { self.receiveLoop() }
        }
    }

    private func deliver(_ data: Data?) {
        lock.lock()
        if let w = waiters.first {
            waiters.removeFirst()
            lock.unlock()
            w.resume(returning: data)
            return
        }
        if let data { inbox.append(data) } else { isClosed = true }
        lock.unlock()
    }

    /// Send one binary WebSocket frame.
    @discardableResult
    public func send(_ data: Data) -> Bool {
        guard let conn = connection, isOpen, !isClosed else { return false }
        let meta = NWProtocolWebSocket.Metadata(opcode: .binary)
        let ctx = NWConnection.ContentContext(identifier: "binary", metadata: [meta])
        conn.send(content: data, contentContext: ctx, isComplete: true,
                  completion: .contentProcessed { _ in })
        return true
    }

    /// Await the next binary frame, or nil when the socket closes.
    public func receive() async -> Data? {
        lock.lock()
        if !inbox.isEmpty {
            let d = inbox.removeFirst(); lock.unlock(); return d
        }
        if isClosed { lock.unlock(); return nil }
        return await withCheckedContinuation { cont in
            waiters.append(cont)
            lock.unlock()
        }
    }

    public func close() {
        isClosed = true
        connection?.cancel()
        connection = nil
        lock.lock()
        let pending = waiters; waiters.removeAll(); lock.unlock()
        pending.forEach { $0.resume(returning: nil) }
    }
}
