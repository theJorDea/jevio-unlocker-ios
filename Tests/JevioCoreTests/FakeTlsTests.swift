import XCTest
@testable import JevioCore

/// Swift port of `FakeTlsTest.kt`.
final class FakeTlsTests: XCTestCase {

    func testWrapTlsRecordSinglePayload() {
        let data = Data((0..<100).map { UInt8($0) })
        let wrapped = FakeTls.wrapTlsRecord(data)
        XCTAssertEqual(wrapped.count, 5 + 100)
        XCTAssertEqual(wrapped.u(0), 0x17)
        XCTAssertEqual(wrapped.u(1), 0x03)
        XCTAssertEqual(wrapped.u(2), 0x03)
        XCTAssertEqual((wrapped.u(3) << 8) | wrapped.u(4), 100)
        XCTAssertEqual(wrapped.slice(5, wrapped.count), data)
    }

    func testWrapTlsRecordSplitsAt16384() {
        let data = Data((0..<(16384 + 10)).map { UInt8($0 % 256) })
        let wrapped = FakeTls.wrapTlsRecord(data)
        XCTAssertEqual(wrapped.count, 5 + 16384 + 5 + 10)
        XCTAssertEqual((wrapped.u(3) << 8) | wrapped.u(4), 16384)
        let secondHeaderAt = 5 + 16384
        XCTAssertEqual(wrapped.u(secondHeaderAt), 0x17)
        XCTAssertEqual((wrapped.u(secondHeaderAt + 3) << 8) | wrapped.u(secondHeaderAt + 4), 10)
    }

    func testDeframerRoundTripAcrossMultipleRecords() {
        let payload = Data((0..<40000).map { UInt8(($0 &* 3) & 0xFF) })
        let framed = FakeTls.wrapTlsRecord(payload)
        let df = FakeTlsDeframer()
        // Feed in small chunks to exercise the partial-record buffering.
        var out = Data()
        var i = 0
        while i < framed.count {
            let end = min(i + 333, framed.count)
            out.append(df.feed(framed.slice(i, end)))
            i = end
        }
        XCTAssertEqual(out, payload)
    }

    func testDeframerSkipsChangeCipherSpec() {
        let ccs = Data([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
        let app = Data([0x17, 0x03, 0x03, 0x00, 0x02, 0x41, 0x42])
        let df = FakeTlsDeframer()
        let out = df.feed(ccs + app)
        XCTAssertEqual(out, Data([0x41, 0x42]))
    }

    func testVerifyClientHelloRejectsGarbage() {
        let secret = Data((0..<16).map { UInt8($0 + 1) })
        XCTAssertNil(FakeTls.verifyClientHello(Data(count: 10), secret: secret))
        var bad = Data(count: 80); bad[0] = 0x16; bad[5] = 0x01
        XCTAssertNil(FakeTls.verifyClientHello(bad, secret: secret))
    }

    func testVerifyClientHelloAcceptsValidHello() {
        let secret = Data((0..<16).map { UInt8($0 + 1) })
        var buf = Data(count: 76)
        buf[0] = 0x16; buf[5] = 0x01; buf[43] = 0x20
        for i in 0..<32 { buf[44 + i] = UInt8((i * 5) & 0xFF) }

        let now = Int64(Date().timeIntervalSince1970)
        let expected = hmacSha256(key: secret, data: buf)
        let ts = UInt32(truncatingIfNeeded: now)
        var clientRandom = Data(count: 32)
        for i in 0..<28 { clientRandom[i] = expected[expected.startIndex + i] }
        for i in 0..<4 {
            let tsByte = UInt8((ts >> (8 * i)) & 0xFF)
            clientRandom[28 + i] = tsByte ^ expected[expected.startIndex + 28 + i]
        }
        buf.replaceSubrange((buf.startIndex + 11)..<(buf.startIndex + 43), with: clientRandom)

        let res = FakeTls.verifyClientHello(buf, secret: secret, now: now)
        XCTAssertNotNil(res)
        XCTAssertEqual(res?.clientRandom, clientRandom)
        XCTAssertEqual(res?.sessionId, buf.slice(44, 76))
    }
}
