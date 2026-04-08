import Foundation

// MARK: - Agent Registration

public struct AgentRegistration: Codable, Sendable {
    public let agentId: String
    public let agentName: String
    public let orgId: String
    public let certificate: [String: AnyCodable]
    /// Base64url-encoded Ed25519 private key — returned ONCE at registration
    public let privateKey: String
    public let publicKey: String
    public let issuedAt: String
    public let expiresAt: String
    public let warning: String?

    enum CodingKeys: String, CodingKey {
        case agentId = "agent_id"
        case agentName = "agent_name"
        case orgId = "org_id"
        case certificate
        case privateKey = "private_key"
        case publicKey = "public_key"
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case warning
    }
}

// MARK: - Capability Token

public struct CapabilityToken: Codable, Sendable {
    public let capabilityId: String
    public let agentId: String
    public let capabilityName: String
    public let token: String
    public let jwtId: String
    public let issuedAt: String
    public let expiresAt: String

    enum CodingKeys: String, CodingKey {
        case capabilityId = "capability_id"
        case agentId = "agent_id"
        case capabilityName = "capability_name"
        case token
        case jwtId = "jwt_id"
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
    }
}

// MARK: - Signed Intent Envelope (SIE)

public struct SIE: Codable, Sendable {
    public let agentCertificate: [String: AnyCodable]
    public let capabilityToken: String
    public let intent: [String: AnyCodable]
    public let timestamp: String
    public let nonce: String
    public var reasoningHash: String?
    public let signature: String

    enum CodingKeys: String, CodingKey {
        case agentCertificate = "agent_certificate"
        case capabilityToken = "capability_token"
        case intent
        case timestamp
        case nonce
        case reasoningHash = "reasoning_hash"
        case signature
    }
}

// MARK: - Verify Result

public struct VerifyResult: Codable, Sendable {
    public let result: String  // "allow" | "deny"
    public let reason: String?
    public let verificationId: String
    public let latencyMs: Double
    public let riskScore: Double
    public let riskLevel: String

    enum CodingKeys: String, CodingKey {
        case result
        case reason
        case verificationId = "verification_id"
        case latencyMs = "latency_ms"
        case riskScore = "risk_score"
        case riskLevel = "risk_level"
    }
}

// MARK: - Revoke Result

public struct RevokeResult: Codable, Sendable {
    public let agentId: String
    public let revokedAt: String
    public let message: String

    enum CodingKeys: String, CodingKey {
        case agentId = "agent_id"
        case revokedAt = "revoked_at"
        case message
    }
}

// MARK: - Audit Log

public struct AuditRecord: Codable, Sendable {
    public let id: Int
    public let verificationId: String
    public let agentId: String?
    public let result: String
    public let reason: String?
    public let sieHash: String
    public let timestamp: String
    public let previousHash: String
    public let recordHash: String

    enum CodingKeys: String, CodingKey {
        case id
        case verificationId = "verification_id"
        case agentId = "agent_id"
        case result
        case reason
        case sieHash = "sie_hash"
        case timestamp
        case previousHash = "previous_hash"
        case recordHash = "record_hash"
    }
}

public struct AuditLogResult: Codable, Sendable {
    public let records: [AuditRecord]
    public let total: Int
    public let chainIntegrity: Bool

    enum CodingKeys: String, CodingKey {
        case records
        case total
        case chainIntegrity = "chain_integrity"
    }
}

// MARK: - AnyCodable (lightweight type-erased JSON value)

public struct AnyCodable: Codable, Sendable {
    public let value: Any

    public init(_ value: Any) {
        self.value = value
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { value = NSNull(); return }
        if let bool = try? container.decode(Bool.self) { value = bool; return }
        if let int = try? container.decode(Int.self) { value = int; return }
        if let double = try? container.decode(Double.self) { value = double; return }
        if let string = try? container.decode(String.self) { value = string; return }
        if let array = try? container.decode([AnyCodable].self) { value = array.map(\.value); return }
        if let dict = try? container.decode([String: AnyCodable].self) {
            value = dict.mapValues(\.value); return
        }
        throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON value")
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case is NSNull: try container.encodeNil()
        case let b as Bool: try container.encode(b)
        case let i as Int: try container.encode(i)
        case let d as Double: try container.encode(d)
        case let s as String: try container.encode(s)
        case let arr as [Any]:
            try container.encode(arr.map { AnyCodable($0) })
        case let dict as [String: Any]:
            try container.encode(dict.mapValues { AnyCodable($0) })
        default:
            throw EncodingError.invalidValue(value, .init(codingPath: encoder.codingPath, debugDescription: "Unsupported type"))
        }
    }
}
