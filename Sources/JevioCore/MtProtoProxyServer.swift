import Foundation
import Network

/// iOS port of `MtProtoProxyServer` (Android `proxy/MtProtoProxyServer.kt`).
///
/// Hosts a local MTProto proxy on 127.0.0.1:<port>. Telegram (configured via the
/// `tg://proxy?server=127.0.0.1&port=...&secret=...` deeplink) connects here; each client is
/// relayed to a Telegram DC over a WebSocket (/apiws) tunnel, with a Cloudflare-fronted
/// fallback. On Android this ran inside a foreground Service; on iOS it runs inside the
/// NEPacketTunnelProvider so it survives in the background.
///
/// Faithful structural port. The relay crypto/protocol pieces are shared with the Android
/// build (handshake, FakeTls, MsgSplitter). Compile & field-test on the Mac/iPhone — the
/// TCP fallback and masking-relay paths are stubbed for the first iteration (see TODOs).
public final class MtProtoProxyServer {

    public struct Config {
        public var host: String
        public var port: UInt16
        public var secretHex: String
        public var cfDomain: String
        public var fakeTlsDomain: String
        public init(host: String = "127.0.0.1", port: UInt16 = 1443, secretHex: String,
                    cfDomain: String = "", fakeTlsDomain: String = "") {
            self.host = host; self.port = port; self.secretHex = secretHex
            self.cfDomain = cfDomain; self.fakeTlsDomain = fakeTlsDomain
        }
    }

    private let config: Config
    private let secret: Data
    private let onLog: (String) -> Void
    private let onConnectionChange: (Int) -> Void

    private var listener: NWListener?
    private let queue = DispatchQueue(label: "jevio.proxy", attributes: .concurrent)
    private var running = false

    // Live stats (read by the UI / extension).
    public private(set) var bytesUp: Int64 = 0
    public private(set) var bytesDown: Int64 = 0
    public private(set) var lastRoute = ""
    private var connectionCount = 0
    private let statsLock = NSLock()

    // Web-front IPs that serve kwsN.web.telegram.org /apiws (NOT the raw MTProto IPs).
    private let wsFrontIps: [Int: String] = [
        1: "149.154.174.100", 2: "149.154.167.99", 3: "149.154.174.100",
        4: "149.154.167.99", 5: "149.154.170.100", 203: "149.154.167.99"
    ]
    private let defaultCfDomains = [
        "noskomnadzor.co.uk", "kartoshka.co.uk", "cakeisalie.co.uk", "lovetrue.co.uk",
        "sorokdva.co.uk", "havegreatday.co.uk", "pomogite.co.uk", "pclead.co.uk", "offshor.co.uk"
    ]
    private var cfDomains: [String] {
        let u = config.cfDomain.trimmingCharacters(in: .whitespaces)
        return u.isEmpty ? defaultCfDomains : [u] + defaultCfDomains
    }

    public init(config: Config,
                onLog: @escaping (String) -> Void = { _ in },
                onConnectionChange: @escaping (Int) -> Void = { _ in }) {
        self.config = config
        self.secret = Data(hexString: config.secretHex) ?? Data()
        self.onLog = onLog
        self.onConnectionChange = onConnectionChange
    }

    // MARK: - Lifecycle

    public func start() throws {
        running = true
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(config.host),
                                                 port: NWEndpoint.Port(rawValue: config.port)!)
        let listener = try NWListener(using: params)
        self.listener = listener
        listener.newConnectionHandler = { [weak self] conn in
            self?.accept(conn)
        }
        listener.start(queue: queue)
        onLog("Прокси слушает на \(config.host):\(config.port)")
    }

    public func stop() {
        running = false
        listener?.cancel()
        listener = nil
        onLog("Прокси остановлен")
    }

    private func bumpConnections(_ delta: Int) {
        statsLock.lock(); connectionCount += delta; let c = connectionCount; statsLock.unlock()
        onConnectionChange(c)
    }
    private func addUp(_ n: Int) { statsLock.lock(); bytesUp += Int64(n); statsLock.unlock() }
    private func addDown(_ n: Int) { statsLock.lock(); bytesDown += Int64(n); statsLock.unlock() }

    // MARK: - Per-client handling

    private func accept(_ conn: NWConnection) {
        guard running else { conn.cancel(); return }
        let client = ClientConnection(conn, queue: queue)
        bumpConnections(1)
        Task {
            await self.handleClient(client)
            self.bumpConnections(-1)
        }
    }

    private func handleClient(_ client: ClientConnection) async {
        defer { client.close() }
        do {
            try await client.open()

            let firstByte = try await client.readExactly(1)
            var deframer: FakeTlsDeframer? = nil
            let handshake: Data

            if !config.fakeTlsDomain.isEmpty && Int(firstByte[firstByte.startIndex]) == FakeTls.TLS_RECORD_HANDSHAKE {
                // --- Fake TLS path ---
                let hdrRest = try await client.readExactly(4)
                let recLen = (Int(hdrRest[hdrRest.startIndex + 2]) << 8) | Int(hdrRest[hdrRest.startIndex + 3])
                let body = try await client.readExactly(recLen)
                let clientHello = firstByte + hdrRest + body

                guard let verified = FakeTls.verifyClientHello(clientHello, secret: secret) else {
                    onLog("Fake TLS verify failed → drop")   // TODO: masking relay to real domain
                    return
                }
                let serverHello = FakeTls.buildServerHello(secret: secret,
                                                           clientRandom: verified.clientRandom,
                                                           sessionId: verified.sessionId)
                client.write(serverHello)

                let df = FakeTlsDeframer()
                deframer = df
                handshake = try await client.readDeframed(df, count: MtProtoConstants.HANDSHAKE_LEN)
                onLog("Fake TLS handshake ok")
            } else {
                // --- Raw obfuscated2 path ---
                let rest = try await client.readExactly(MtProtoConstants.HANDSHAKE_LEN - 1)
                handshake = firstByte + rest
            }

            guard let result = MtProtoHandshake.tryHandshake(handshake, secret: secret) else {
                onLog("bad handshake (wrong secret or proto)")
                return
            }

            let protoInt: Int64 = {
                if result.protoTag == MtProtoConstants.PROTO_TAG_ABRIDGED { return MtProtoConstants.PROTO_ABRIDGED_INT }
                if result.protoTag == MtProtoConstants.PROTO_TAG_INTERMEDIATE { return MtProtoConstants.PROTO_INTERMEDIATE_INT }
                return MtProtoConstants.PROTO_PADDED_INTERMEDIATE_INT
            }()

            let dcIdx = result.isMedia ? -result.dcId : result.dcId
            onLog("handshake ok: DC\(result.dcId)\(result.isMedia ? " media" : "") proto=0x\(String(protoInt, radix: 16))")

            let relayInit = MtProtoHandshake.generateRelayInit(protoTag: result.protoTag, dcIdx: dcIdx)
            let ctx = MtProtoHandshake.buildCryptoContext(clientDecPrekeyIv: result.clientDecPrekeyIv,
                                                          secret: secret, relayInit: relayInit)

            guard let bridge = await connectAnyWs(dcId: result.dcId, isMedia: result.isMedia) else {
                onLog("WS connection failed (TCP fallback TODO)")  // TODO: tcpFallback
                return
            }

            bridge.send(relayInit) // first WS frame = relay obfuscation init
            await bridgeData(client: client, deframer: deframer, bridge: bridge,
                             ctx: ctx, relayInit: relayInit, protoInt: protoInt,
                             dc: result.dcId, isMedia: result.isMedia)
        } catch {
            onLog("client error: \(error.localizedDescription)")
        }
    }

    // MARK: - WS transport racing

    private struct WsCandidate { let pinnedIp: String?; let host: String; let kind: String }

    private func connectAnyWs(dcId: Int, isMedia: Bool) async -> WebSocketBridge? {
        var candidates: [WsCandidate] = []
        let wsTargetIp = wsFrontIps[dcId] ?? wsFrontIps[2]!
        for domain in MtProtoHandshake.wsDomains(dc: dcId, isMedia: isMedia) {
            candidates.append(WsCandidate(pinnedIp: wsTargetIp, host: domain, kind: "direct"))
        }
        let cfDc = (dcId == 203) ? 2 : dcId
        for base in cfDomains {
            candidates.append(WsCandidate(pinnedIp: nil, host: "kws\(cfDc).\(base)", kind: "cloudflare"))
        }
        onLog("connecting WS: racing \(candidates.count) endpoints (direct + Cloudflare)")

        // Race: first bridge to open wins, the rest are cancelled.
        return await withTaskGroup(of: WebSocketBridge?.self) { group in
            for c in candidates {
                group.addTask {
                    let b = WebSocketBridge()
                    let ok = await b.connect(pinnedIp: c.pinnedIp, host: c.host)
                    if ok { return b }
                    b.close(); return nil
                }
            }
            var winner: WebSocketBridge?
            for await result in group {
                if let b = result, winner == nil {
                    winner = b
                } else if let b = result {
                    b.close() // a late opener — not needed
                }
            }
            return winner
        }
    }

    // MARK: - Bidirectional relay

    private func bridgeData(client: ClientConnection, deframer: FakeTlsDeframer?, bridge: WebSocketBridge,
                            ctx: CryptoContext, relayInit: Data, protoInt: Int64,
                            dc: Int, isMedia: Bool) async {
        let splitter = MsgSplitter(relayInit: relayInit, protoInt: protoInt)

        await withTaskGroup(of: Void.self) { group in
            // client -> telegram
            group.addTask {
                do {
                    while self.running {
                        let raw = try await client.read(deframer: deframer)
                        if raw.isEmpty { splitter.flush().forEach { bridge.send($0) }; break }
                        self.addUp(raw.count)
                        let plain = ctx.cltDecryptor.update(raw)
                        let reenc = ctx.tgEncryptor.update(plain)
                        for p in splitter.split(reenc) where !bridge.send(p) { return }
                    }
                } catch { /* client closed */ }
            }
            // telegram -> client
            group.addTask {
                while self.running {
                    guard let data = await bridge.receive() else { break }
                    self.addDown(data.count)
                    let plain = ctx.tgDecryptor.update(data)
                    let enc = ctx.cltEncryptor.update(plain)
                    client.writeFramed(enc, deframer: deframer)
                }
            }
            await group.next()
            group.cancelAll()
        }
        bridge.close()
        onLog("DC\(dc)\(isMedia ? "m" : "") session closed")
    }
}

// MARK: - Hex helper

extension Data {
    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count % 2 == 0 else { return nil }
        var d = Data(capacity: chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(chars[i...i+1]), radix: 16) else { return nil }
            d.append(b); i += 2
        }
        self = d
    }
}
