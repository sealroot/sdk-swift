/**
 * AIAClient — AIA Protocol Platform Swift SDK.
 *
 * Provides the same 6 core methods as the Python and Node.js SDKs:
 *   1. registerAgent       — POST /agents
 *   2. issueCapability      — POST /capabilities
 *   3. generateSIE          — local (no network), signs SIE with agent's Ed25519 key
 *   4. verify               — POST /verify
 *   5. revokeAgent          — DELETE /agents/{id}
 *   6. getAuditLog          — GET /audit
 *
 * Requires iOS 16+ / macOS 13+ (URLSession async/await).
 */
import Foundation
import Crypto

public final class AIAClient: Sendable {
    private let baseURL: URL
    private let apiKey: String
    private let session: URLSession

    public init(baseURL: URL, apiKey: String, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.apiKey = apiKey
        self.session = session
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private func makeRequest(
        method: String,
        path: String,
        body: [String: Any]? = nil,
        authenticated: Bool = true
    ) -> URLRequest {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if authenticated {
            request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        }
        if let body = body {
            request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        }
        return request
    }

    private func perform<T: Decodable>(_ request: URLRequest) async throws -> T {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw AIAError.unknown("Non-HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            var detail = HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            if let err = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let d = err["detail"] as? String {
                detail = d
            }
            if http.statusCode == 404 { throw AIAError.agentNotFound(detail) }
            throw AIAError.httpError(statusCode: http.statusCode, detail: detail)
        }
        if data.isEmpty, let empty = (() -> T? { EmptyResponse() as? T })() {
            return empty
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    // -------------------------------------------------------------------------
    // 1. Register agent
    // -------------------------------------------------------------------------

    public func registerAgent(
        name: String,
        validityHours: Int = 24,
        metadata: [String: Any]? = nil
    ) async throws -> AgentRegistration {
        var body: [String: Any] = [
            "agent_name": name,
            "validity_hours": validityHours,
        ]
        if let meta = metadata { body["metadata"] = meta }
        let request = makeRequest(method: "POST", path: "/agents", body: body)
        return try await perform(request)
    }

    // -------------------------------------------------------------------------
    // 2. Issue capability token
    // -------------------------------------------------------------------------

    public func issueCapability(
        agentId: String,
        capabilityName: String,
        parameters: [String: Any]? = nil,
        validitySeconds: Int = 3600
    ) async throws -> CapabilityToken {
        var body: [String: Any] = [
            "agent_id": agentId,
            "capability_name": capabilityName,
            "validity_seconds": validitySeconds,
        ]
        if let params = parameters { body["parameters"] = params }
        let request = makeRequest(method: "POST", path: "/capabilities", body: body)
        return try await perform(request)
    }

    // -------------------------------------------------------------------------
    // 3. Generate SIE (local — no network call)
    // -------------------------------------------------------------------------

    public func generateSIE(
        registration: AgentRegistration,
        capability: CapabilityToken,
        intent: [String: Any],
        reasoning: String? = nil
    ) throws -> SIE {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let nonce = generateNonce()

        var intentDict: [String: Any] = ["capability": capability.capabilityName]
        for (k, v) in intent { intentDict[k] = v }

        var envelope: [String: Any] = [
            "agent_certificate": registration.certificate.mapValues { $0.value },
            "capability_token": capability.token,
            "intent": intentDict,
            "timestamp": timestamp,
            "nonce": nonce,
        ]

        var reasoningHashValue: String? = nil
        if let r = reasoning {
            reasoningHashValue = reasoningHash(r)
            envelope["reasoning_hash"] = reasoningHashValue!
        }

        // Sign the canonical form (without signature field)
        let canonical = try JCS.canonicalize(envelope)
        let kp = try AIAKeyPair.from(privateKeyB64url: registration.privateKey)
        let signature = try kp.privateKey.signature(for: canonical)
        let signatureB64 = Base64URL.encode(signature)

        // Build SIE model — re-encode certificate back to AnyCodable
        let certCodable = registration.certificate
        let intentCodable = intentDict.mapValues { AnyCodable($0) }

        return SIE(
            agentCertificate: certCodable,
            capabilityToken: capability.token,
            intent: intentCodable,
            timestamp: timestamp,
            nonce: nonce,
            reasoningHash: reasoningHashValue,
            signature: signatureB64
        )
    }

    // -------------------------------------------------------------------------
    // 4. Verify SIE
    // -------------------------------------------------------------------------

    public func verify(sie: SIE) async throws -> VerifyResult {
        let encoder = JSONEncoder()
        guard let sieData = try? encoder.encode(sie),
              let sieDict = try? JSONSerialization.jsonObject(with: sieData) as? [String: Any] else {
            throw AIAError.invalidResponse("Failed to encode SIE")
        }
        let body: [String: Any] = ["sie": sieDict]
        var request = makeRequest(method: "POST", path: "/verify", body: body, authenticated: false)
        let result: VerifyResult = try await perform(request)

        if result.result == "deny" {
            throw AIAError.verificationDenied(
                reason: result.reason ?? "unknown",
                verificationId: result.verificationId
            )
        }
        return result
    }

    // -------------------------------------------------------------------------
    // 5. Revoke agent
    // -------------------------------------------------------------------------

    public func revokeAgent(agentId: String, reason: String? = nil) async throws -> RevokeResult {
        var path = "/agents/\(agentId)"
        if let r = reason, let encoded = r.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) {
            path += "?reason=\(encoded)"
        }
        let request = makeRequest(method: "DELETE", path: path)
        do {
            return try await perform(request)
        } catch let err as AIAError {
            throw AIAError.revocationFailed(err.localizedDescription)
        }
    }

    // -------------------------------------------------------------------------
    // 6. Get audit log
    // -------------------------------------------------------------------------

    public func getAuditLog(
        agentId: String? = nil,
        result: String? = nil,
        limit: Int = 100,
        offset: Int = 0
    ) async throws -> AuditLogResult {
        var components = URLComponents()
        components.queryItems = [
            URLQueryItem(name: "limit", value: "\(limit)"),
            URLQueryItem(name: "offset", value: "\(offset)"),
        ]
        if let aid = agentId { components.queryItems?.append(.init(name: "agent_id", value: aid)) }
        if let r = result { components.queryItems?.append(.init(name: "result", value: r)) }
        let qs = components.percentEncodedQuery.map { "?\($0)" } ?? ""
        let request = makeRequest(method: "GET", path: "/audit\(qs)")
        return try await perform(request)
    }
}

// Empty response helper (for 204 No Content)
private struct EmptyResponse: Codable {}
