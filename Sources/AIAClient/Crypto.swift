/**
 * Cryptographic primitives for the AIA Swift SDK.
 *
 * - Ed25519 signing/verification via CryptoKit Curve25519
 * - SHA-256 via CryptoKit
 * - JCS (RFC 8785) deterministic JSON canonicalization
 * - Base64url encoding/decoding (no padding)
 * - Nonce generation (128-bit CSPRNG)
 */
import Foundation
import Crypto

// MARK: - Base64url (RFC 4648, no padding)

public enum Base64URL {
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func decode(_ string: String) throws -> Data {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = s.count % 4
        if remainder > 0 { s += String(repeating: "=", count: 4 - remainder) }
        guard let data = Data(base64Encoded: s) else {
            throw AIAError.cryptoError("Invalid base64url string")
        }
        return data
    }
}

// MARK: - Ed25519 Key Pair

public struct AIAKeyPair {
    public let privateKey: Curve25519.Signing.PrivateKey
    public let publicKey: Curve25519.Signing.PublicKey

    public static func generate() -> AIAKeyPair {
        let pk = Curve25519.Signing.PrivateKey()
        return AIAKeyPair(privateKey: pk, publicKey: pk.publicKey)
    }

    public static func from(privateKeyB64url: String) throws -> AIAKeyPair {
        let data = try Base64URL.decode(privateKeyB64url)
        let pk = try Curve25519.Signing.PrivateKey(rawRepresentation: data)
        return AIAKeyPair(privateKey: pk, publicKey: pk.publicKey)
    }

    public var privateKeyB64url: String { Base64URL.encode(privateKey.rawRepresentation) }
    public var publicKeyB64url: String { Base64URL.encode(publicKey.rawRepresentation) }
}

// MARK: - SHA-256

public func sha256Hex(_ data: Data) -> String {
    let digest = SHA256.hash(data: data)
    return digest.map { String(format: "%02x", $0) }.joined()
}

public func sha256Hex(_ string: String) -> String {
    sha256Hex(Data(string.utf8))
}

public func reasoningHash(_ reasoning: String) -> String {
    "sha256:\(sha256Hex(reasoning))"
}

// MARK: - JCS (RFC 8785) deterministic JSON serialisation

public enum JCS {
    public static func canonicalize(_ value: Any) throws -> Data {
        let json = try jcsValue(value)
        guard let data = json.data(using: .utf8) else {
            throw AIAError.cryptoError("JCS: UTF-8 encoding failed")
        }
        return data
    }

    private static func jcsValue(_ value: Any) throws -> String {
        switch value {
        case is NSNull:
            return "null"
        case let b as Bool:
            return b ? "true" : "false"
        case let i as Int:
            return "\(i)"
        case let d as Double:
            if !d.isFinite { throw AIAError.cryptoError("Non-finite number in JCS") }
            return d.truncatingRemainder(dividingBy: 1) == 0 ? "\(Int(d))" : "\(d)"
        case let s as String:
            let escaped = s
                .replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
                .replacingOccurrences(of: "\n", with: "\\n")
                .replacingOccurrences(of: "\r", with: "\\r")
                .replacingOccurrences(of: "\t", with: "\\t")
            return "\"\(escaped)\""
        case let arr as [Any]:
            let items = try arr.map { try jcsValue($0) }
            return "[\(items.joined(separator: ","))]"
        case let dict as [String: Any]:
            let pairs = try dict.keys.sorted().map { k in
                let v = try jcsValue(dict[k]!)
                return "\"\(k)\":\(v)"
            }
            return "{\(pairs.joined(separator: ","))}"
        default:
            throw AIAError.cryptoError("JCS: unsupported type \(type(of: value))")
        }
    }
}

// MARK: - Nonce (128-bit CSPRNG)

public func generateNonce() -> String {
    var bytes = [UInt8](repeating: 0, count: 16)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    return bytes.map { String(format: "%02x", $0) }.joined()
}
