import XCTest
import Crypto
@testable import AIAClient

final class AIAClientTests: XCTestCase {

    // -------------------------------------------------------------------------
    // Base64url
    // -------------------------------------------------------------------------

    func testBase64URLRoundTrip() throws {
        let original = Data([1, 2, 3, 255, 0, 128])
        let encoded = Base64URL.encode(original)
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
        let decoded = try Base64URL.decode(encoded)
        XCTAssertEqual(decoded, original)
    }

    // -------------------------------------------------------------------------
    // Ed25519 sign/verify
    // -------------------------------------------------------------------------

    func testSignAndVerify() throws {
        let kp = AIAKeyPair.generate()
        let message = Data("hello world".utf8)
        let signature = try kp.privateKey.signature(for: message)
        let valid = kp.publicKey.isValidSignature(signature, for: message)
        XCTAssertTrue(valid)
    }

    func testKeyPairFromPrivateKey() throws {
        let original = AIAKeyPair.generate()
        let recovered = try AIAKeyPair.from(privateKeyB64url: original.privateKeyB64url)
        XCTAssertEqual(recovered.publicKeyB64url, original.publicKeyB64url)
    }

    func testVerifyFailsWithWrongMessage() throws {
        let kp = AIAKeyPair.generate()
        let message = Data("hello".utf8)
        let signature = try kp.privateKey.signature(for: message)
        let wrong = Data("world".utf8)
        let valid = kp.publicKey.isValidSignature(signature, for: wrong)
        XCTAssertFalse(valid)
    }

    // -------------------------------------------------------------------------
    // SHA-256
    // -------------------------------------------------------------------------

    func testSha256HexEmptyString() {
        let result = sha256Hex("")
        XCTAssertEqual(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    func testReasoningHashFormat() {
        let h = reasoningHash("some reasoning text")
        XCTAssertTrue(h.hasPrefix("sha256:"))
        let hashPart = String(h.dropFirst(7))
        XCTAssertEqual(hashPart.count, 64)
        XCTAssertTrue(hashPart.allSatisfy { $0.isHexDigit })
    }

    // -------------------------------------------------------------------------
    // JCS canonicalization
    // -------------------------------------------------------------------------

    func testJCSKeyOrdering() throws {
        let a = try JCS.canonicalize(["z": 1, "a": 2] as [String: Any])
        let b = try JCS.canonicalize(["a": 2, "z": 1] as [String: Any])
        XCTAssertEqual(a, b)
        XCTAssertEqual(String(data: a, encoding: .utf8), "{\"a\":2,\"z\":1}")
    }

    func testJCSNestedObject() throws {
        let obj: [String: Any] = ["b": ["d": 4, "c": 3] as [String: Any], "a": 1]
        let canonical = try JCS.canonicalize(obj)
        XCTAssertEqual(String(data: canonical, encoding: .utf8), "{\"a\":1,\"b\":{\"c\":3,\"d\":4}}")
    }

    func testJCSArray() throws {
        let canonical = try JCS.canonicalize(["items": [3, 1, 2]] as [String: Any])
        XCTAssertEqual(String(data: canonical, encoding: .utf8), "{\"items\":[3,1,2]}")
    }

    // -------------------------------------------------------------------------
    // Nonce
    // -------------------------------------------------------------------------

    func testNonceFormat() {
        let nonce = generateNonce()
        XCTAssertEqual(nonce.count, 32)
        XCTAssertTrue(nonce.allSatisfy { $0.isHexDigit })
    }

    func testNonceUniqueness() {
        let n1 = generateNonce()
        let n2 = generateNonce()
        XCTAssertNotEqual(n1, n2)
    }

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    func testAIAErrorDescription() {
        let err = AIAError.verificationDenied(reason: "policy_deny", verificationId: "abc-123")
        XCTAssertTrue(err.localizedDescription.contains("policy_deny"))
        XCTAssertTrue(err.localizedDescription.contains("abc-123"))
    }
}
