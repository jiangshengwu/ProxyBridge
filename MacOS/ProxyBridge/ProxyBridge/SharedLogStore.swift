import Foundation

final class SharedLogStore {
    static let shared = SharedLogStore()
    
    private let appGroup = "group.com.interceptsuite.ProxyBridge"
    private let logURL: URL?
    private let lock = NSLock()
    private var readOffset: UInt64 = 0
    private static let maxFileSize: UInt64 = 5 * 1024 * 1024 // 5MB max
    
    private static func resolveContainerURL(appGroup: String) -> URL? {
        if let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup),
           !url.path.hasPrefix("/var/root") {
            return url
        }
        let usersURL = URL(fileURLWithPath: "/Users")
        if let userDirs = try? FileManager.default.contentsOfDirectory(at: usersURL, includingPropertiesForKeys: nil) {
            for userDir in userDirs {
                let candidate = userDir.appendingPathComponent("Library/Group Containers/\(appGroup)")
                if FileManager.default.fileExists(atPath: candidate.path) {
                    return candidate
                }
            }
        }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
    }
    
    private init() {
        logURL = SharedLogStore.resolveContainerURL(appGroup: appGroup)?
            .appendingPathComponent("shared_logs.jsonl")
    }
    
    // Writer side (Extension): append one log entry line
    func append(entryDict: [String: String]) {
        guard let url = logURL else { return }
        lock.lock()
        defer { lock.unlock() }
        
        guard let data = try? JSONSerialization.data(withJSONObject: entryDict) else { return }
        var lineData = data
        lineData.append(0x0A) // '\n'
        
        if FileManager.default.fileExists(atPath: url.path) {
            if let handle = try? FileHandle(forWritingTo: url) {
                defer { try? handle.close() }
                let fileSize = handle.seekToEndOfFile()
                if fileSize > SharedLogStore.maxFileSize {
                    try? handle.truncate(atOffset: 0)
                }
                handle.write(lineData)
            }
        } else {
            try? lineData.write(to: url, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o666], ofItemAtPath: url.path)
        }
    }
    
    // Reader side (App): poll and drain new log lines
    func drainNewEntries() -> [[String: String]] {
        guard let url = logURL else { return [] }
        lock.lock()
        defer { lock.unlock() }
        
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        
        let fileSize = handle.seekToEndOfFile()
        if fileSize < readOffset {
            readOffset = 0
        }
        if fileSize == readOffset {
            return []
        }
        
        handle.seek(toFileOffset: readOffset)
        let newData = handle.readDataToEndOfFile()
        readOffset = fileSize
        
        guard !newData.isEmpty,
              let str = String(data: newData, encoding: .utf8) else {
            return []
        }
        
        var results: [[String: String]] = []
        let lines = str.components(separatedBy: "\n")
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty,
                  let lineData = trimmed.data(using: .utf8),
                  let dict = try? JSONSerialization.jsonObject(with: lineData) as? [String: String] else {
                continue
            }
            results.append(dict)
        }
        return results
    }
    
    func clear() {
        guard let url = logURL else { return }
        lock.lock()
        defer { lock.unlock() }
        readOffset = 0
        try? FileManager.default.removeItem(at: url)
    }
}
