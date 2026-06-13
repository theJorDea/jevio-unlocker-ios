import Foundation

/// Direct Swift port of `MtProtoConstants` (Android `proxy/MtProtoHandshake.kt`).
public enum MtProtoConstants {
    public static let HANDSHAKE_LEN = 64
    public static let SKIP_LEN = 8
    public static let PREKEY_LEN = 32
    public static let KEY_LEN = 32
    public static let IV_LEN = 16
    public static let PROTO_TAG_POS = 56
    public static let DC_IDX_POS = 60

    public static let PROTO_TAG_ABRIDGED     = Data([0xEF, 0xEF, 0xEF, 0xEF])
    public static let PROTO_TAG_INTERMEDIATE = Data([0xEE, 0xEE, 0xEE, 0xEE])
    public static let PROTO_TAG_SECURE       = Data([0xDD, 0xDD, 0xDD, 0xDD])

    // 0xEFEFEFEF etc. — kept as Int64 so the high-bit values stay positive (like Kotlin Long).
    public static let PROTO_ABRIDGED_INT: Int64            = 0xEFEFEFEF
    public static let PROTO_INTERMEDIATE_INT: Int64        = 0xEEEEEEEE
    public static let PROTO_PADDED_INTERMEDIATE_INT: Int64 = 0xDDDDDDDD

    public static let ZERO_64 = Data(count: 64)
}

/// Result of a successful client obfuscated2 handshake.
public struct HandshakeResult: Equatable {
    public let dcId: Int
    public let isMedia: Bool
    public let protoTag: Data
    public let clientDecPrekeyIv: Data
}

/// The four parallel AES-CTR keystreams that drive a relayed session.
public struct CryptoContext {
    public let cltDecryptor: AesCtr  // decrypt data coming FROM the client
    public let cltEncryptor: AesCtr  // encrypt data going TO the client
    public let tgEncryptor: AesCtr   // encrypt data going TO telegram (over WS)
    public let tgDecryptor: AesCtr   // decrypt data coming FROM telegram (over WS)
}

// MARK: - Small Data helpers used throughout the port

extension Data {
    /// Sub-range copy, byte-for-byte equivalent of Kotlin `copyOfRange(from, to)`.
    func slice(_ from: Int, _ to: Int) -> Data {
        subdata(in: (startIndex + from)..<(startIndex + to))
    }

    /// Reversed bytes (Kotlin `reversedArray()`).
    var reversedData: Data { Data(reversed()) }

    /// Unsigned byte at index (Kotlin `b.toInt() and 0xFF`).
    func u(_ i: Int) -> Int { Int(self[startIndex + i]) }
}
