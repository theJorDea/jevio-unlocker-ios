import Foundation
import CommonCrypto

/// Stateful AES-CTR keystream cipher.
///
/// Mirrors `javax.crypto.Cipher.getInstance("AES/CTR/NoPadding")` used in ENCRYPT mode as a
/// streaming XOR cipher in the Android original. The crucial property we need is that
/// `update(_:)` *advances the CTR counter across calls* — the same key/iv produce one
/// continuous keystream over successive `update` calls — exactly like the JCE `Cipher`.
///
/// `CCCryptorCreateWithMode(kCCModeCTR, ... kCCModeOptionCTR_BE)` keeps that state in the
/// `CCCryptorRef`, so each `CCCryptorUpdate` continues the keystream where the last left off.
public final class AesCtr {
    private var cryptor: CCCryptorRef?

    public init(key: Data, iv: Data) {
        precondition(key.count == kCCKeySizeAES256 || key.count == kCCKeySizeAES128,
                     "AES key must be 16 or 32 bytes")
        precondition(iv.count == kCCBlockSizeAES128, "AES-CTR iv must be 16 bytes")
        key.withUnsafeBytes { keyPtr in
            iv.withUnsafeBytes { ivPtr in
                _ = CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivPtr.baseAddress,
                    keyPtr.baseAddress, key.count,
                    nil, 0, 0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &cryptor
                )
            }
        }
    }

    deinit { if let c = cryptor { CCCryptorRelease(c) } }

    /// XOR `data` against the running keystream and return the transformed bytes.
    /// For CTR, encrypt and decrypt are the same operation.
    @discardableResult
    public func update(_ data: Data) -> Data {
        guard let cryptor, !data.isEmpty else { return Data() }
        var out = Data(count: data.count)
        var moved = 0
        _ = out.withUnsafeMutableBytes { outPtr in
            data.withUnsafeBytes { inPtr in
                CCCryptorUpdate(cryptor, inPtr.baseAddress, data.count,
                                outPtr.baseAddress, out.count, &moved)
            }
        }
        if moved < out.count { out.removeSubrange(moved..<out.count) }
        return out
    }
}

// MARK: - Hash helpers (CryptoKit)

import CryptoKit

@inline(__always)
public func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}

@inline(__always)
public func hmacSha256(key: Data, data: Data) -> Data {
    let k = SymmetricKey(data: key)
    return Data(HMAC<SHA256>.authenticationCode(for: data, using: k))
}

// MARK: - Secure random

@inline(__always)
public func secureRandomBytes(_ count: Int) -> Data {
    var d = Data(count: count)
    _ = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
    return d
}
