import XCTest
@testable import JevioCore

/// Swift port of `MsgSplitterTest.kt`.
final class MsgSplitterTests: XCTestCase {

    private let relayInit = Data((0..<64).map { UInt8(($0 * 7 + 3) & 0xFF) })

    /// A keystream-aligned encryptor identical to the one MsgSplitter decrypts with.
    private func encryptor() -> AesCtr {
        let key = relayInit.slice(8, 40)
        let iv = relayInit.slice(40, 56)
        let c = AesCtr(key: key, iv: iv)
        c.update(Data(count: 64)) // ZERO_64 fast-forward
        return c
    }

    private func intHeader(_ len: Int) -> Data {
        Data([UInt8(len & 0xFF), UInt8((len >> 8) & 0xFF),
              UInt8((len >> 16) & 0xFF), UInt8((len >> 24) & 0xFF)])
    }

    func testSplitsIntermediatePacketsAtBoundaries() {
        let splitter = MsgSplitter(relayInit: relayInit, protoInt: MtProtoConstants.PROTO_INTERMEDIATE_INT)
        let plain = intHeader(8) + Data(repeating: 1, count: 8) + intHeader(4) + Data(repeating: 2, count: 4)
        let cipher = encryptor().update(plain)
        let parts = splitter.split(cipher)
        XCTAssertEqual(parts.count, 2)
        XCTAssertEqual(parts[0].count, 12)
        XCTAssertEqual(parts[1].count, 8)
        XCTAssertEqual(parts[0] + parts[1], cipher)
    }

    func testHoldsPartialPacketUntilComplete() {
        let splitter = MsgSplitter(relayInit: relayInit, protoInt: MtProtoConstants.PROTO_INTERMEDIATE_INT)
        let plain = intHeader(8) + Data(repeating: 5, count: 8)
        let cipher = encryptor().update(plain)
        XCTAssertTrue(splitter.split(cipher.slice(0, 6)).isEmpty)
        let rest = splitter.split(cipher.slice(6, cipher.count))
        XCTAssertEqual(rest.count, 1)
        XCTAssertEqual(rest[0].count, 12)
        XCTAssertEqual(rest[0], cipher)
    }

    func testSplitsAbridgedShortPacket() {
        let splitter = MsgSplitter(relayInit: relayInit, protoInt: MtProtoConstants.PROTO_ABRIDGED_INT)
        let plain = Data([2]) + Data(repeating: 9, count: 8)
        let cipher = encryptor().update(plain)
        let parts = splitter.split(cipher)
        XCTAssertEqual(parts.count, 1)
        XCTAssertEqual(parts[0].count, 9)
        XCTAssertEqual(parts[0], cipher)
    }

    func testEmptyChunkYieldsNothing() {
        let splitter = MsgSplitter(relayInit: relayInit, protoInt: MtProtoConstants.PROTO_INTERMEDIATE_INT)
        XCTAssertTrue(splitter.split(Data()).isEmpty)
    }
}
