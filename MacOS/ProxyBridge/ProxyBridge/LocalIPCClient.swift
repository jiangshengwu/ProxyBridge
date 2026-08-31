import Foundation

final class LocalIPCClient {
    static let shared = LocalIPCClient()
    private let baseURL = URL(string: "http://127.0.0.1:58223")!
    private let session: URLSession
    
    private init() {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 2.0
        config.timeoutIntervalForResource = 2.0
        self.session = URLSession(configuration: config)
    }
    
    func fetchLogs(completion: @escaping ([[String: String]]) -> Void) {
        let url = baseURL.appendingPathComponent("logs")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
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
