import Foundation

/// Direct Swift port of `MtProtoHandshake` (Android `proxy/MtProtoHandshake.kt`).
/// Pure, deterministic logic — the safest part to validate with unit tests on the Mac.
public enum MtProtoHandshake {

    /// Verify a client's 64-byte obfuscated2 init against `secret`. Returns nil if the
    /// decoded protocol tag is not one we support (i.e. wrong secret / not MTProto).
    public static func tryHandshake(_ handshake: Data, secret: Data) -> HandshakeResult? {
        precondition(handshake.count == MtProtoConstants.HANDSHAKE_LEN)

        let decPrekeyAndIv = handshake.slice(MtProtoConstants.SKIP_LEN,
                                             MtProtoConstants.SKIP_LEN + MtProtoConstants.PREKEY_LEN + MtProtoConstants.IV_LEN)
        let decPrekey = decPrekeyAndIv.slice(0, MtProtoConstants.PREKEY_LEN)
        let decIv     = decPrekeyAndIv.slice(MtProtoConstants.PREKEY_LEN, MtProtoConstants.PREKEY_LEN + MtProtoConstants.IV_LEN)

        let decKey = sha256(decPrekey + secret)
        let decrypted = AesCtr(key: decKey, iv: decIv).update(handshake)

        let protoTag = decrypted.slice(MtProtoConstants.PROTO_TAG_POS, MtProtoConstants.PROTO_TAG_POS + 4)
        guard protoTag == MtProtoConstants.PROTO_TAG_ABRIDGED ||
              protoTag == MtProtoConstants.PROTO_TAG_INTERMEDIATE ||
              protoTag == MtProtoConstants.PROTO_TAG_SECURE else {
            return nil
        }

        // dc index: signed little-endian Int16 at offset 60.
        let lo = decrypted.u(MtProtoConstants.DC_IDX_POS)
        let hi = decrypted.u(MtProtoConstants.DC_IDX_POS + 1)
        let dcIdx = Int16(bitPattern: UInt16(lo | (hi << 8)))

        let dcId = abs(Int(dcIdx))
        let isMedia = dcIdx < 0
        return HandshakeResult(dcId: dcId, isMedia: isMedia, protoTag: protoTag, clientDecPrekeyIv: decPrekeyAndIv)
    }

    /// Generate the 64-byte obfuscation init we send TO Telegram (the relay side).
    /// Ported from the Android `generateRelayInit`, including the forbidden-prefix filter.
    public static func generateRelayInit(protoTag: Data, dcIdx: Int) -> Data {
        let forbidden4: [Data] = [
            Data([0x48, 0x45, 0x41, 0x44]),  // HEAD
            Data([0x50, 0x4F, 0x53, 0x54]),  // POST
            Data([0x47, 0x45, 0x54, 0x20]),  // "GET "
            MtProtoConstants.PROTO_TAG_INTERMEDIATE,
            MtProtoConstants.PROTO_TAG_SECURE,
            Data([0x16, 0x03, 0x01, 0x02])
        ]

        while true {
            var rnd = secureRandomBytes(MtProtoConstants.HANDSHAKE_LEN)
            if rnd[rnd.startIndex] == 0xEF { continue }
            let first4 = rnd.slice(0, 4)
            if forbidden4.contains(first4) { continue }
            if rnd.slice(4, 8) == Data(count: 4) { continue }

            let encKey = rnd.slice(MtProtoConstants.SKIP_LEN, MtProtoConstants.SKIP_LEN + MtProtoConstants.PREKEY_LEN)
            let encIv  = rnd.slice(MtProtoConstants.SKIP_LEN + MtProtoConstants.PREKEY_LEN,
                                   MtProtoConstants.SKIP_LEN + MtProtoConstants.PREKEY_LEN + MtProtoConstants.IV_LEN)
            let encryptor = AesCtr(key: encKey, iv: encIv)

            // dc index as signed little-endian Int16.
            let dc16 = UInt16(bitPattern: Int16(truncatingIfNeeded: dcIdx))
            let dcBytes = Data([UInt8(dc16 & 0xFF), UInt8(dc16 >> 8)])
            let tailPlain = protoTag + dcBytes + secureRandomBytes(2)   // 8 bytes

            let encryptedFull = encryptor.update(rnd)
            var encryptedTail = Data(count: 8)
            for i in 0..<8 {
                let keystreamByte = encryptedFull[encryptedFull.startIndex + 56 + i] ^ rnd[rnd.startIndex + 56 + i]
                encryptedTail[encryptedTail.startIndex + i] = tailPlain[tailPlain.startIndex + i] ^ keystreamByte
            }

            var result = rnd
            result.replaceSubrange((result.startIndex + MtProtoConstants.PROTO_TAG_POS)..<(result.startIndex + MtProtoConstants.PROTO_TAG_POS + 8),
                                   with: encryptedTail)
            return result
        }
    }

    /// Build the four AES-CTR keystreams for a session. See the Android comments for the
    /// exact key derivation (client side hashes with the user secret; the Telegram side uses
    /// the raw relayInit keys). The ZERO_64 fast-forwards must match exactly.
    public static func buildCryptoContext(clientDecPrekeyIv: Data, secret: Data, relayInit: Data) -> CryptoContext {
        // --- Client side ---
        let cltDecPrekey = clientDecPrekeyIv.slice(0, MtProtoConstants.PREKEY_LEN)
        let cltDecIv     = clientDecPrekeyIv.slice(MtProtoConstants.PREKEY_LEN, MtProtoConstants.PREKEY_LEN + MtProtoConstants.IV_LEN)
        let cltDecKey    = sha256(cltDecPrekey + secret)

        let cltEncPrekeyIv = clientDecPrekeyIv.reversedData
        let cltEncKey      = sha256(cltEncPrekeyIv.slice(0, MtProtoConstants.PREKEY_LEN) + secret)
        let cltEncIv       = cltEncPrekeyIv.slice(MtProtoConstants.PREKEY_LEN, MtProtoConstants.PREKEY_LEN + MtProtoConstants.IV_LEN)

        let cltDecryptor = AesCtr(key: cltDecKey, iv: cltDecIv)
        cltDecryptor.update(MtProtoConstants.ZERO_64)            // skip the consumed init keystream
        let cltEncryptor = AesCtr(key: cltEncKey, iv: cltEncIv)  // NOT fast-forwarded

        // --- Telegram (relay) side ---
        let tgEncKey = relayInit.slice(MtProtoConstants.SKIP_LEN, MtProtoConstants.SKIP_LEN + MtProtoConstants.PREKEY_LEN)
        let tgEncIv  = relayInit.slice(MtProtoConstants.SKIP_LEN + MtProtoConstants.PREKEY_LEN,
                                       MtProtoConstants.SKIP_LEN + MtProtoConstants.PREKEY_LEN + MtProtoConstants.IV_LEN)

        let tgDecPrekeyIv = relayInit.slice(MtProtoConstants.SKIP_LEN,
                                            MtProtoConstants.SKIP_LEN + MtProtoConstants.PREKEY_LEN + MtProtoConstants.IV_LEN).reversedData
        let tgDecKey = tgDecPrekeyIv.slice(0, MtProtoConstants.KEY_LEN)
        let tgDecIv  = tgDecPrekeyIv.slice(MtProtoConstants.KEY_LEN, MtProtoConstants.KEY_LEN + MtProtoConstants.IV_LEN)

        let tgEncryptor = AesCtr(key: tgEncKey, iv: tgEncIv)
        tgEncryptor.update(MtProtoConstants.ZERO_64)            // relayInit's own 64 bytes go raw
        let tgDecryptor = AesCtr(key: tgDecKey, iv: tgDecIv)    // NOT fast-forwarded

        return CryptoContext(cltDecryptor: cltDecryptor, cltEncryptor: cltEncryptor,
                             tgEncryptor: tgEncryptor, tgDecryptor: tgDecryptor)
    }

    /// The kwsN.web.telegram.org WebSocket hostnames for a DC, media-preferred ordering.
    public static func wsDomains(dc: Int, isMedia: Bool) -> [String] {
        let actualDc = (dc == 203) ? 2 : dc
        if isMedia {
            return ["kws\(actualDc)-1.web.telegram.org", "kws\(actualDc).web.telegram.org"]
        } else {
            return ["kws\(actualDc).web.telegram.org", "kws\(actualDc)-1.web.telegram.org"]
        }
    }
}
