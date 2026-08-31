import Foundation

final class SharedConfigStore {
    static let shared = SharedConfigStore()
    
    private let appGroup = "group.com.interceptsuite.ProxyBridge"
    private let configURL: URL?
    private let lock = NSLock()
    private var lastMtime: Date?
    
    private init() {
        configURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appendingPathComponent("shared_config.json")
    }
    
    func save(rules: [[String: Any]], configs: [[String: Any]], trafficLoggingEnabled: Bool) {
        guard let url = configURL else { return }
        lock.lock()
        defer { lock.unlock() }
        
        let payload: [String: Any] = [
            "version": 1,
            "updatedAt": Date().timeIntervalSince1970,
            "trafficLoggingEnabled": trafficLoggingEnabled,
            "configs": configs,
            "rules": rules
        ]
        
        if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted]) {
            try? data.write(to: url, options: .atomic)
        }
    }
    
    func loadIfModified() -> (rules: [[String: Any]], configs: [[String: Any]], trafficLoggingEnabled: Bool)? {
        guard let url = configURL else { return nil }
        lock.lock()
        defer { lock.unlock() }
        
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let mtime = attrs[.modificationDate] as? Date else {
            return nil
        }
        
        if let last = lastMtime, last >= mtime {
            return nil
        }
        
        guard let data = try? Data(contentsOf: url),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        
        lastMtime = mtime
        let rules = json["rules"] as? [[String: Any]] ?? []
        let configs = json["configs"] as? [[String: Any]] ?? []
        let logging = json["trafficLoggingEnabled"] as? Bool ?? true
        
        return (rules, configs, logging)
    }
    
    func loadCurrent() -> (rules: [[String: Any]], configs: [[String: Any]], trafficLoggingEnabled: Bool)? {
        guard let url = configURL,
              let data = try? Data(contentsOf: url),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        let rules = json["rules"] as? [[String: Any]] ?? []
        let configs = json["configs"] as? [[String: Any]] ?? []
        let logging = json["trafficLoggingEnabled"] as? Bool ?? true
        return (rules, configs, logging)
    }
}
