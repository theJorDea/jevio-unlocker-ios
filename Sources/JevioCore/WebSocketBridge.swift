import Foundation
import Network
import Security

/// iOS port of `WebSocketBridge` (Android `proxy/WebSocketBridge.kt`).
///
/// Android used OkHttp with a per-connection DNS override so a domain could be pinned to a
/// specific Telegram DC IP while keeping the correct TLS SNI. The iOS equivalent is
/// `Network.framework`: connect `NWEndpoint.hostPort(<IP>, 443)` while setting the TLS server
/// name (SNI) to the real domain. For Cloudflare-fronted domains we pass the domain itself as
/// the host so the system resolver handles it.
///
/// Direct pinned-IP candidates use Network.framework for SNI control. Cloudflare candidates
/// use URLSessionWebSocketTask so the `/apiws` resource path is part of the WebSocket handshake.
public final class WebSocketBridge: NSObject, URLSessionWebSocketDelegate {
    private var connection: NWConnection?
    private var urlSession: URLSession?
    private var urlTask: URLSessionWebSocketTask?
    private var isOpen = false
    private var isClosed = false
    private var openContinuation: CheckedContinuation<Bool, Never>?

    // Simple async inbox for received binary frames.
    private var inbox: [Data] = []
    private var waiters: [CheckedContinuation<Data?, Never>] = []
    private let lock = NSLock()

    private let queue = DispatchQueue(label: "jevio.ws")

    public override init() {
        super.init()
    }

    /// Connect to wss://<host><path>. If `pinnedIp` is set, the TCP endpoint targets that IP
    /// while TLS SNI stays `host` (direct DC web-front). Returns true on open within `timeout`.
    public func connect(pinnedIp: String?, host: String, path: String = "/apiws", timeout: TimeInterval = 5) async -> Bool {
        await withTaskCancellationHandler {
            if isOpen { return true }
            if pinnedIp == nil {
                return await connectURLSession(host: host, path: path, timeout: timeout)
            }

            return await connectNetwork(pinnedIp: pinnedIp, host: host, path: path, timeout: timeout)
        } onCancel: {
            close()
        }
    }

    private func connectNetwork(pinnedIp: String?, host: String, path: String, timeout: TimeInterval) async -> Bool {
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

        // Network.framework gives us pinned-IP + SNI, but not an obvious public hook for the
        // WebSocket resource path in this hostPort mode. Keep this path for direct candidates;
        // Cloudflare candidates use URLSessionWebSocketTask, where `/apiws` is explicit.
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

    private func connectURLSession(host: String, path: String, timeout: TimeInterval) async -> Bool {
        guard let url = URL(string: "wss://\(host)\(path)") else { return false }

        var request = URLRequest(url: url)
        request.addValue("binary", forHTTPHeaderField: "Sec-WebSocket-Protocol")
        request.addValue("https://\(host)", forHTTPHeaderField: "Origin")

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout

        let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        let task = session.webSocketTask(with: request)
        self.urlSession = session
        self.urlTask = task

        return await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            lock.lock()
            openContinuation = cont
            lock.unlock()

            task.resume()
            queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
                self?.finishOpen(false)
            }
        }
    }

    private func finishOpen(_ ok: Bool) {
        lock.lock()
        let cont = openContinuation
        openContinuation = nil
        lock.unlock()
        cont?.resume(returning: ok)
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

    private func urlReceiveLoop() {
        guard let task = urlTask else { return }
        task.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(.data(let data)):
                if !data.isEmpty { self.deliver(data) }
            case .success(.string(let text)):
                if let data = text.data(using: .utf8), !data.isEmpty { self.deliver(data) }
            case .failure:
                self.markClosed()
                return
            @unknown default:
                self.markClosed()
                return
            }
            if !self.isClosed { self.urlReceiveLoop() }
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

    private func markClosed() {
        isClosed = true
        deliver(nil)
        finishOpen(false)
    }

    /// Send one binary WebSocket frame.
    @discardableResult
    public func send(_ data: Data) -> Bool {
        if let task = urlTask, isOpen, !isClosed {
            task.send(.data(data)) { [weak self] error in
                if error != nil { self?.markClosed() }
            }
            return true
        }

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
        urlTask?.cancel(with: .normalClosure, reason: nil)
        urlTask = nil
        urlSession?.invalidateAndCancel()
        urlSession = nil
        lock.lock()
        let pending = waiters; waiters.removeAll(); lock.unlock()
        pending.forEach { $0.resume(returning: nil) }
        finishOpen(false)
    }

    public func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,
                           didOpenWithProtocol selectedProtocol: String?) {
        isOpen = true
        urlReceiveLoop()
        finishOpen(true)
    }

    public func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,
                           didCloseWith closeCode: URLSessionWebSocketTask.CloseCode,
                           reason: Data?) {
        markClosed()
    }
}
