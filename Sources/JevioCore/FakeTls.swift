import Foundation

/// Direct Swift port of `FakeTls` (Android `proxy/FakeTls.kt`).
/// Fake TLS (`ee...` secrets): makes proxy traffic look like a real HTTPS session.
public enum FakeTls {

    public static let TLS_RECORD_HANDSHAKE = 0x16
    public static let TLS_RECORD_CCS       = 0x14
    public static let TLS_RECORD_APPDATA   = 0x17

    private static let CLIENT_RANDOM_OFFSET = 11
    private static let CLIENT_RANDOM_LEN    = 32
    private static let SESSION_ID_OFFSET    = 44
    private static let SESSION_ID_LEN       = 32
    private static let TIMESTAMP_TOLERANCE  = 120
    private static let TLS_APPDATA_MAX      = 16384

    private static let CCS_FRAME = Data([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])

    // ServerHello skeleton (122-byte record). Offsets: random@11, sessionId@44, pubkey@89.
    private static let SERVER_HELLO_TEMPLATE: Data = {
        var b = Data()
        func add(_ v: UInt8...) { b.append(contentsOf: v) }
        func zeros(_ n: Int) { b.append(Data(count: n)) }
        add(0x16, 0x03, 0x03, 0x00, 0x7a)          // record header
        add(0x02, 0x00, 0x00, 0x76)                // handshake header (ServerHello)
        add(0x03, 0x03)                            // version
        zeros(32)                                  // server random (filled later)
        add(0x20)                                  // session id length
        zeros(32)                                  // session id (filled later)
        add(0x13, 0x01, 0x00)                      // cipher suite + compression
        add(0x00, 0x2e)                            // extensions length
        add(0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20) // key_share header
        zeros(32)                                  // key_share pubkey (filled later)
        add(0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)    // supported_versions TLS1.3
        return b
    }()
    private static let SH_RANDOM_OFF = 11
    private static let SH_SESSID_OFF = 44
    private static let SH_PUBKEY_OFF = 89

    public struct ClientHello {
        public let clientRandom: Data
        public let sessionId: Data
        public let timestamp: Int64
    }

    /// Verify a TLS ClientHello against `secret`; nil = not a valid Fake-TLS hello.
    public static func verifyClientHello(_ data: Data, secret: Data,
                                         now: Int64 = Int64(Date().timeIntervalSince1970)) -> ClientHello? {
        let n = data.count
        if n < 43 { return nil }
        if data.u(0) != TLS_RECORD_HANDSHAKE { return nil }
        if data.u(5) != 0x01 { return nil }

        let clientRandom = data.slice(CLIENT_RANDOM_OFFSET, CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN)

        var zeroed = data
        for i in 0..<CLIENT_RANDOM_LEN { zeroed[zeroed.startIndex + CLIENT_RANDOM_OFFSET + i] = 0 }
        let expected = hmacSha256(key: secret, data: zeroed)

        // First 28 bytes must match exactly.
        for i in 0..<28 where expected[expected.startIndex + i] != clientRandom[clientRandom.startIndex + i] {
            return nil
        }

        // Last 4 bytes: XOR-masked little-endian unix timestamp.
        var ts: UInt32 = 0
        for i in 0..<4 {
            let x = clientRandom[clientRandom.startIndex + 28 + i] ^ expected[expected.startIndex + 28 + i]
            ts |= UInt32(x) << (8 * i)
        }
        let timestamp = Int64(ts)
        if abs(now - timestamp) > Int64(TIMESTAMP_TOLERANCE) { return nil }

        var sessionId = Data(count: SESSION_ID_LEN)
        if n >= SESSION_ID_OFFSET + SESSION_ID_LEN && data.u(43) == 0x20 {
            sessionId = data.slice(SESSION_ID_OFFSET, SESSION_ID_OFFSET + SESSION_ID_LEN)
        }
        return ClientHello(clientRandom: clientRandom, sessionId: sessionId, timestamp: timestamp)
    }

    /// Build the ServerHello (+ CCS + dummy app-data) keyed to the client's hello.
    public static func buildServerHello(secret: Data, clientRandom: Data, sessionId: Data) -> Data {
        var sh = SERVER_HELLO_TEMPLATE
        sh.replaceSubrange((sh.startIndex + SH_SESSID_OFF)..<(sh.startIndex + SH_SESSID_OFF + 32), with: sessionId)
        let pub = secureRandomBytes(32)
        sh.replaceSubrange((sh.startIndex + SH_PUBKEY_OFF)..<(sh.startIndex + SH_PUBKEY_OFF + 32), with: pub)

        let encryptedSize = 1900 + Int.random(in: 0...200) // 1900..2100
        let encryptedData = secureRandomBytes(encryptedSize)
        var appRecord = Data([0x17, 0x03, 0x03])
        appRecord.append(UInt8((encryptedSize >> 8) & 0xFF))
        appRecord.append(UInt8(encryptedSize & 0xFF))
        appRecord.append(encryptedData)

        var response = sh + CCS_FRAME + appRecord
        let serverRandom = hmacSha256(key: secret, data: clientRandom + response)
        response.replaceSubrange((response.startIndex + SH_RANDOM_OFF)..<(response.startIndex + SH_RANDOM_OFF + 32),
                                 with: serverRandom)
        return response
    }

    /// Wrap arbitrary bytes into one or more TLS application-data records.
    public static func wrapTlsRecord(_ data: Data) -> Data {
        var out = Data()
        var offset = 0
        while offset < data.count {
            let end = min(offset + TLS_APPDATA_MAX, data.count)
            let len = end - offset
            out.append(contentsOf: [0x17, 0x03, 0x03, UInt8((len >> 8) & 0xFF), UInt8(len & 0xFF)])
            out.append(data.slice(offset, end))
            offset = end
        }
        return out
    }
}

/// De-frames TLS application-data records from a byte stream. CCS records are skipped.
/// Feed raw incoming bytes; get back the inner obfuscated2 payload. Buffers partial records.
/// Replaces `FakeTlsInputStream` from the Android original (adapted for async NWConnection).
public final class FakeTlsDeframer {
    private var buffer = Data()
    public private(set) var ended = false

    public init() {}

    /// Append new raw bytes, return any fully-decoded inner app-data bytes available now.
    public func feed(_ data: Data) -> Data {
        buffer.append(data)
        var out = Data()
        while true {
            if buffer.count < 5 { break }
            let rtype = Int(buffer[buffer.startIndex])
            let recLen = (Int(buffer[buffer.startIndex + 3]) << 8) | Int(buffer[buffer.startIndex + 4])
            if buffer.count < 5 + recLen { break } // wait for the full record

            let body = buffer.slice(5, 5 + recLen)
            buffer.removeSubrange(buffer.startIndex..<(buffer.startIndex + 5 + recLen))

            if rtype == FakeTls.TLS_RECORD_CCS { continue }      // skip ChangeCipherSpec
            if rtype != FakeTls.TLS_RECORD_APPDATA { ended = true; break } // any other = end
            out.append(body)
        }
        return out
    }
}
