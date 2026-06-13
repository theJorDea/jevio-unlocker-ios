import XCTest
@testable import JevioCore

/// Swift port of `MtProtoHandshakeTest.kt`. Validates the deterministic handshake decode.
final class MtProtoHandshakeTests: XCTestCase {

    func testWsDomainsNonMediaOrder() {
        XCTAssertEqual(MtProtoHandshake.wsDomains(dc: 2, isMedia: false),
                       ["kws2.web.telegram.org", "kws2-1.web.telegram.org"])
    }

    func testWsDomainsMediaIsReversed() {
        XCTAssertEqual(MtProtoHandshake.wsDomains(dc: 2, isMedia: true),
                       ["kws2-1.web.telegram.org", "kws2.web.telegram.org"])
    }

    func testWsDomainsMapsDc203ToDc2() {
        XCTAssertEqual(MtProtoHandshake.wsDomains(dc: 203, isMedia: false),
                       ["kws2.web.telegram.org", "kws2-1.web.telegram.org"])
    }

    func testTryHandshakeRejectsUnknownProtoTag() {
        let secret = Data((0..<16).map { UInt8(($0 + 3) & 0xFF) })
        let hs = Data((0..<64).map { UInt8(($0 * 13 + 7) & 0xFF) })
        XCTAssertNil(MtProtoHandshake.tryHandshake(hs, secret: secret))
    }

    func testTryHandshakeDecodesValidHandshake() {
        let secret = Data((0..<16).map { UInt8(($0 + 3) & 0xFF) })
        var hs = Data(count: 64)
        for i in 0..<56 { hs[i] = UInt8((i * 9 + 1) & 0xFF) } // fixes key/iv + keystream

        let decKey = sha256(hs.slice(8, 40) + secret)
        let decIv = hs.slice(40, 56)
        let keystream = AesCtr(key: decKey, iv: decIv).update(Data(count: 64))

        let protoTag = MtProtoConstants.PROTO_TAG_INTERMEDIATE
        // dc index = 2 (little-endian Int16)
        let dcBytes: [UInt8] = [2, 0]
        for i in 0..<4 { hs[56 + i] = protoTag[protoTag.startIndex + i] ^ keystream[keystream.startIndex + 56 + i] }
        for i in 0..<2 { hs[60 + i] = dcBytes[i] ^ keystream[keystream.startIndex + 60 + i] }
        hs[62] = UInt8(5) ^ keystream[keystream.startIndex + 62]
        hs[63] = UInt8(6) ^ keystream[keystream.startIndex + 63]

        let res = MtProtoHandshake.tryHandshake(hs, secret: secret)
        XCTAssertNotNil(res)
        XCTAssertEqual(res?.dcId, 2)
        XCTAssertEqual(res?.isMedia, false)
        XCTAssertEqual(res?.protoTag, protoTag)
        XCTAssertEqual(res?.clientDecPrekeyIv, hs.slice(8, 56))
    }

    /// CTR encrypt/decrypt round-trip across multiple update() calls keeps keystream state.
    func testAesCtrStreamingState() {
        let key = Data((0..<32).map { UInt8($0) })
        let iv = Data((0..<16).map { UInt8(16 - $0) })
        let enc = AesCtr(key: key, iv: iv)
        let dec = AesCtr(key: key, iv: iv)
        let p1 = Data((0..<30).map { UInt8($0) })
        let p2 = Data((0..<50).map { UInt8($0 &* 3) })
        let c1 = enc.update(p1), c2 = enc.update(p2)
        XCTAssertEqual(dec.update(c1), p1)
        XCTAssertEqual(dec.update(c2), p2)
    }
}
