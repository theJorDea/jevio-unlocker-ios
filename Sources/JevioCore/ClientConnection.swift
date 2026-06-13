import Foundation
import Network

/// Async wrapper over an inbound loopback `NWConnection` from Telegram.
///
/// Network.framework delivers TCP as arbitrary-size chunks, so we buffer and expose the
/// byte-exact reads the relay needs (mirroring the Android `readFully` helper). When Fake TLS
/// is active the inner obfuscated2 stream is recovered through a `FakeTlsDeframer`; outgoing
/// bytes are re-framed with `FakeTls.wrapTlsRecord`.
final class ClientConnection {
    private let conn: NWConnection
    private let queue: DispatchQueue
    private var buffer = Data()   // raw bytes already received (pre-deframe)
    private var closed = false

    init(_ conn: NWConnection, queue: DispatchQueue) {
        self.conn = conn
        self.queue = queue
    }

    func open() async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready: cont.resume()
                case .failed(let e): cont.resume(throwing: e)
                case .cancelled: cont.resume(throwing: ConnError.closed)
                default: break
                }
            }
            conn.start(queue: queue)
        }
        conn.stateUpdateHandler = { [weak self] state in
            if case .cancelled = state { self?.closed = true }
            if case .failed = state { self?.closed = true }
        }
    }

    enum ConnError: Error { case closed }

    /// Pull one more chunk of raw bytes from the socket into `buffer`.
    private func fill() async throws {
        let chunk: Data = try await withCheckedThrowingContinuation { cont in
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                if let error { cont.resume(throwing: error); return }
                if let data, !data.isEmpty { cont.resume(returning: data); return }
                if isComplete { cont.resume(throwing: ConnError.closed); return }
                cont.resume(returning: Data())
            }
        }
        if chunk.isEmpty { throw ConnError.closed }
        buffer.append(chunk)
    }

    /// Read exactly `n` raw bytes (used during the pre-deframe handshake).
    func readExactly(_ n: Int) async throws -> Data {
        while buffer.count < n { try await fill() }
        let out = buffer.prefix(n)
        buffer.removeFirst(n)
        return Data(out)
    }

    /// Read exactly `count` *inner* bytes through a Fake-TLS deframer.
    func readDeframed(_ df: FakeTlsDeframer, count: Int) async throws -> Data {
        var inner = Data()
        // First, drain anything already buffered through the deframer.
        if !buffer.isEmpty { inner.append(df.feed(consumeBuffer())) }
        while inner.count < count {
            try await fill()
            inner.append(df.feed(consumeBuffer()))
        }
        // Keep any overflow for the next read by stashing in a small carry buffer.
        if inner.count > count {
            carry = inner.suffix(inner.count - count)
            inner = inner.prefix(count)
        }
        return Data(inner)
    }

    private var carry = Data()
    private func consumeBuffer() -> Data { let b = buffer; buffer.removeAll(keepingCapacity: true); return b }

    /// Read the next batch of *inner* bytes (deframed if Fake TLS is active). Empty = EOF.
    func read(deframer: FakeTlsDeframer?) async throws -> Data {
        if !carry.isEmpty { let c = carry; carry = Data(); return c }
        guard let df = deframer else {
            // Raw path: just hand back whatever arrives next.
            if buffer.isEmpty { try await fill() }
            return consumeBuffer()
        }
        while true {
            if buffer.isEmpty { try await fill() }
            let inner = df.feed(consumeBuffer())
            if !inner.isEmpty { return inner }
            if df.ended { return Data() }
        }
    }

    /// Write raw bytes to the client.
    func write(_ data: Data) {
        conn.send(content: data, completion: .contentProcessed { _ in })
    }

    /// Write bytes to the client, re-framing as TLS app-data when Fake TLS is active.
    func writeFramed(_ data: Data, deframer: FakeTlsDeframer?) {
        let out = deframer == nil ? data : FakeTls.wrapTlsRecord(data)
        write(out)
    }

    func close() {
        closed = true
        conn.cancel()
    }
}
