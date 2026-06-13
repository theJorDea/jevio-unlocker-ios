import Foundation

/// Direct Swift port of `MsgSplitter` (Android `proxy/MsgSplitter.kt`).
///
/// Splits the already-relay-encrypted upstream byte stream into individual MTProto transport
/// packets so each is sent as its own WebSocket binary frame (Telegram's /apiws expects the
/// obfuscated2 stream framed that way). Keeps a parallel AES-CTR keystream identical to the
/// relay encryptor so it can recover plaintext lengths and cut the cipher buffer on packet
/// boundaries.
public final class MsgSplitter {
    private let dec: AesCtr
    private let protoInt: Int64

    private var cipherBuf = Data()
    private var plainBuf = Data()
    private var disabled = false

    public init(relayInit: Data, protoInt: Int64) {
        let key = relayInit.slice(MtProtoConstants.SKIP_LEN, MtProtoConstants.SKIP_LEN + MtProtoConstants.PREKEY_LEN)
        let iv  = relayInit.slice(MtProtoConstants.SKIP_LEN + MtProtoConstants.PREKEY_LEN,
                                  MtProtoConstants.SKIP_LEN + MtProtoConstants.PREKEY_LEN + MtProtoConstants.IV_LEN)
        self.dec = AesCtr(key: key, iv: iv)
        self.protoInt = protoInt
        dec.update(MtProtoConstants.ZERO_64) // mirror the relay encryptor's fast-forward
    }

    public func split(_ chunk: Data) -> [Data] {
        if chunk.isEmpty { return [] }
        if disabled { return [chunk] }

        let plain = dec.update(chunk)
        cipherBuf.append(chunk)
        plainBuf.append(plain)

        var parts: [Data] = []
        var offset = 0
        let bufLen = cipherBuf.count
        while offset < bufLen {
            guard let packetLen = nextPacketLen(offset: offset, avail: bufLen - offset) else { break }
            if packetLen <= 0 {
                parts.append(cipherBuf.slice(offset, bufLen))
                offset = bufLen
                disabled = true
                break
            }
            parts.append(cipherBuf.slice(offset, offset + packetLen))
            offset += packetLen
        }

        if offset > 0 {
            cipherBuf = cipherBuf.slice(offset, cipherBuf.count)
            plainBuf  = plainBuf.slice(offset, plainBuf.count)
        }
        return parts
    }

    public func flush() -> [Data] {
        if cipherBuf.isEmpty { return [] }
        let tail = cipherBuf
        cipherBuf = Data()
        plainBuf = Data()
        return [tail]
    }

    private func nextPacketLen(offset: Int, avail: Int) -> Int? {
        if avail <= 0 { return nil }
        switch protoInt {
        case MtProtoConstants.PROTO_ABRIDGED_INT:
            return nextAbridgedLen(offset: offset, avail: avail)
        case MtProtoConstants.PROTO_INTERMEDIATE_INT, MtProtoConstants.PROTO_PADDED_INTERMEDIATE_INT:
            return nextIntermediateLen(offset: offset, avail: avail)
        default:
            return 0
        }
    }

    private func nextAbridgedLen(offset: Int, avail: Int) -> Int? {
        let first = plainBuf.u(offset)
        let payloadLen: Int
        let headerLen: Int
        if first == 0x7F || first == 0xFF {
            if avail < 4 { return nil }
            payloadLen = (plainBuf.u(offset + 1) | (plainBuf.u(offset + 2) << 8) | (plainBuf.u(offset + 3) << 16)) * 4
            headerLen = 4
        } else {
            payloadLen = (first & 0x7F) * 4
            headerLen = 1
        }
        if payloadLen <= 0 { return 0 }
        let packetLen = headerLen + payloadLen
        if avail < packetLen { return nil }
        return packetLen
    }

    private func nextIntermediateLen(offset: Int, avail: Int) -> Int? {
        if avail < 4 { return nil }
        let payloadLen = (plainBuf.u(offset) | (plainBuf.u(offset + 1) << 8) |
                          (plainBuf.u(offset + 2) << 16) | (plainBuf.u(offset + 3) << 24)) & 0x7FFFFFFF
        if payloadLen <= 0 { return 0 }
        let packetLen = 4 + payloadLen
        if avail < packetLen { return nil }
        return packetLen
    }
}
