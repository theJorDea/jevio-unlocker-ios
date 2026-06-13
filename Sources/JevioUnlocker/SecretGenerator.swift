import Foundation

enum SecretGenerator {
    /// 16 random bytes → 32 hex chars, the MTProto proxy secret.
    static func generate() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}
