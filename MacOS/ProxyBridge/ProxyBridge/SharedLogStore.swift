import Foundation

final class SharedLogStore {
    static let shared = SharedLogStore()
    
    private let sharedDirectory: URL
    private let logURL: URL
    private let lock = NSLock()
    private var readOffset: UInt64 = 0
    private static let maxFileSize: UInt64 = 5 * 1024 * 1024 // 5MB max
    
    private init() {
        let dir = URL(fileURLWithPath: "/Users/Shared/ProxyBridge", isDirectory: true)
        self.sharedDirectory = dir
        self.logURL = dir.appendingPathComponent("shared_logs.jsonl")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o777])
    }
    
    // Writer side (Extension): append one log entry line
    func append(entryDict: [String: String]) {
        lock.lock()
        defer { lock.unlock() }
        
        try? FileManager.default.createDirectory(at: sharedDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o777])
        
        guard let data = try? JSONSerialization.data(withJSONObject: entryDict) else { return }
        var lineData = data
        lineData.append(0x0A) // '\n'
        
        if FileManager.default.fileExists(atPath: logURL.path) {
            if let handle = try? FileHandle(forWritingTo: logURL) {
                defer { try? handle.close() }
                let fileSize = handle.seekToEndOfFile()
                if fileSize > SharedLogStore.maxFileSize {
                    try? handle.truncate(atOffset: 0)
                }
                handle.write(lineData)
            }
        } else {
            try? lineData.write(to: logURL, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o666], ofItemAtPath: logURL.path)
        }
    }
    
    // Reader side (App): poll and drain new log lines
    func drainNewEntries() -> [[String: String]] {
        lock.lock()
        defer { lock.unlock() }
        
        guard let handle = try? FileHandle(forReadingFrom: logURL) else { return [] }
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
        lock.lock()
        defer { lock.unlock() }
        readOffset = 0
        try? FileManager.default.removeItem(at: logURL)
    }
}
