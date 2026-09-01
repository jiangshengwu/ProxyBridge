import Foundation
import Security

final class LocalIPCClient {
    static let shared = LocalIPCClient()
    private let baseURL = URL(string: "http://127.0.0.1:58223")!
    private let session: URLSession
    private let tokenLock = NSLock()
    private var authorizationToken: String?
    
    private init() {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 2.0
        config.timeoutIntervalForResource = 2.0
        self.session = URLSession(configuration: config)
    }

    func setAuthorizationToken(_ token: String?) {
        tokenLock.lock()
        authorizationToken = token?.trimmingCharacters(in: .whitespacesAndNewlines)
        tokenLock.unlock()
    }

    @discardableResult
    func rotateAuthorizationToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        let token: String
        if status == errSecSuccess {
            token = Data(bytes).base64EncodedString()
        } else {
            token = UUID().uuidString + UUID().uuidString
        }
        setAuthorizationToken(token)
        return token
    }

    private func authorize(_ request: inout URLRequest) -> Bool {
        tokenLock.lock()
        let token = authorizationToken
        tokenLock.unlock()

        guard let token = token, !token.isEmpty else { return false }
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        return true
    }
    
    func fetchLogs(completion: @escaping ([[String: String]]) -> Void) {
        let url = baseURL.appendingPathComponent("logs")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        guard authorize(&request) else {
            completion([])
            return
        }
        
        session.dataTask(with: request) { data, _, _ in
            guard let data = data,
                  let logs = try? JSONSerialization.jsonObject(with: data) as? [[String: String]] else {
                completion([])
                return
            }
            completion(logs)
        }.resume()
    }
    
    func syncRules(_ rules: [[String: Any]], completion: ((Bool, Int) -> Void)? = nil) {
        let url = baseURL.appendingPathComponent("rules")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: rules)
        guard authorize(&request) else {
            completion?(false, 0)
            return
        }
        
        session.dataTask(with: request) { data, _, error in
            guard error == nil,
                  let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let status = json["status"] as? String, status == "ok" else {
                completion?(false, 0)
                return
            }
            let count = json["count"] as? Int ?? rules.count
            completion?(true, count)
        }.resume()
    }
    
    func syncConfigs(_ configs: [[String: Any]], completion: ((Bool) -> Void)? = nil) {
        let url = baseURL.appendingPathComponent("configs")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: configs)
        guard authorize(&request) else {
            completion?(false)
            return
        }
        
        session.dataTask(with: request) { data, _, error in
            guard error == nil,
                  let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let status = json["status"] as? String, status == "ok" else {
                completion?(false)
                return
            }
            completion?(true)
        }.resume()
    }
    
    func setTrafficLogging(_ enabled: Bool, completion: ((Bool) -> Void)? = nil) {
        let url = baseURL.appendingPathComponent("trafficLogging")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["enabled": enabled])
        guard authorize(&request) else {
            completion?(false)
            return
        }
        
        session.dataTask(with: request) { data, _, error in
            guard error == nil,
                  let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let status = json["status"] as? String, status == "ok" else {
                completion?(false)
                return
            }
            completion?(true)
        }.resume()
    }
}
