import Foundation

final class SharedConfigStore {
    static let shared = SharedConfigStore()
    
    private let sharedDirectory: URL
    private let configURL: URL
    private let lock = NSLock()
    private var lastMtime: Date?
    
    private init() {
        let dir = URL(fileURLWithPath: "/Users/Shared/ProxyBridge", isDirectory: true)
        self.sharedDirectory = dir
        self.configURL = dir.appendingPathComponent("shared_config.json")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o777])
    }
    
    func save(rules: [[String: Any]], configs: [[String: Any]], trafficLoggingEnabled: Bool) {
        lock.lock()
        defer { lock.unlock() }
        
        try? FileManager.default.createDirectory(at: sharedDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o777])
        
        let payload: [String: Any] = [
            "version": 1,
            "updatedAt": Date().timeIntervalSince1970,
            "trafficLoggingEnabled": trafficLoggingEnabled,
            "configs": configs,
            "rules": rules
        ]
        
        if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted]) {
            try? data.write(to: configURL, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o666], ofItemAtPath: configURL.path)
        }
    }
    
    func loadIfModified() -> (rules: [[String: Any]], configs: [[String: Any]], trafficLoggingEnabled: Bool)? {
        lock.lock()
        defer { lock.unlock() }
        
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: configURL.path),
              let mtime = attrs[.modificationDate] as? Date else {
            return nil
        }
        
        if let last = lastMtime, last >= mtime {
            return nil
        }
        
        guard let data = try? Data(contentsOf: configURL),
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
        guard let data = try? Data(contentsOf: configURL),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        let rules = json["rules"] as? [[String: Any]] ?? []
        let configs = json["configs"] as? [[String: Any]] ?? []
        let logging = json["trafficLoggingEnabled"] as? Bool ?? true
        return (rules, configs, logging)
    }
}
