import Foundation

public enum AIAError: Error, LocalizedError {
    case httpError(statusCode: Int, detail: String)
    case agentNotFound(String)
    case verificationDenied(reason: String, verificationId: String)
    case revocationFailed(String)
    case cryptoError(String)
    case invalidResponse(String)
    case unknown(String)

    public var errorDescription: String? {
        switch self {
        case .httpError(let code, let detail):
            return "HTTP \(code): \(detail)"
        case .agentNotFound(let id):
            return "Agent not found: \(id)"
        case .verificationDenied(let reason, let vid):
            return "Verification denied: \(reason) (id=\(vid))"
        case .revocationFailed(let msg):
            return "Revocation failed: \(msg)"
        case .cryptoError(let msg):
            return "Crypto error: \(msg)"
        case .invalidResponse(let msg):
            return "Invalid response: \(msg)"
        case .unknown(let msg):
            return msg
        }
    }
}
