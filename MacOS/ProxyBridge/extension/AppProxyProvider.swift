import NetworkExtension
import Foundation

enum RuleProtocol: String, Codable {
    case tcp = "TCP"
    case udp = "UDP"
    case both = "BOTH"
}

struct ProxyRule: Codable {
    var ruleId: UInt32
    let name: String
    let processNames: String
    let targetHosts: String
    let targetPorts: String
    let ruleProtocol: RuleProtocol
    let action: String  // "DIRECT", "BLOCK", or a proxy config UUID
    var enabled: Bool

    enum CodingKeys: String, CodingKey {
        case ruleId
        case name
        case processNames
        case targetHosts
        case targetPorts
        case ruleProtocol
        case action = "ruleAction"
        case enabled
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.ruleId = try container.decodeIfPresent(UInt32.self, forKey: .ruleId) ?? 0
        self.name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        self.processNames = try container.decode(String.self, forKey: .processNames)
        self.targetHosts = try container.decode(String.self, forKey: .targetHosts)
        self.targetPorts = try container.decode(String.self, forKey: .targetPorts)
        self.ruleProtocol = try container.decode(RuleProtocol.self, forKey: .ruleProtocol)
        self.action = try container.decode(String.self, forKey: .action)
        self.enabled = try container.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
    }

    init(ruleId: UInt32, name: String = "", processNames: String, targetHosts: String, targetPorts: String, ruleProtocol: RuleProtocol, action: String, enabled: Bool) {
        self.ruleId = ruleId
        self.name = name
        self.processNames = processNames
        self.targetHosts = targetHosts
        self.targetPorts = targetPorts
        self.ruleProtocol = ruleProtocol
        self.action = action
        self.enabled = enabled
    }
    
    func matchProcess(bundleId: String, processName: String?, executablePath: String?) -> ProcessMatch? {
        if processNames.isEmpty || processNames == "*" { return .any }

        let appBundleNames = executablePath.map(Self.appBundleNames) ?? []
        let patterns = processNames.components(separatedBy: CharacterSet(charactersIn: ",;"))

        for rawPattern in patterns {
            let pattern = rawPattern.trimmingCharacters(in: .whitespacesAndNewlines)
            if pattern.lowercased().hasSuffix(".app") {
                // App rules are exact names, not globs. Match any containing
                // app bundle so both the main executable and nested helpers
                // belong to Antigravity.app, for example.
                guard !pattern.contains("*") else { continue }
                if appBundleNames.contains(where: { $0.caseInsensitiveCompare(pattern) == .orderedSame }) {
                    return .app(pattern)
                }
                continue
            }

            if Self.matchProcessPattern(
                pattern,
                processPath: bundleId,
                filename: (bundleId as NSString).lastPathComponent
            ) {
                return pattern.isEmpty || pattern == "*" ? .any : .process(pattern)
            }

            if let processName,
               Self.matchProcessPattern(
                   pattern,
                   processPath: processName,
                   filename: (processName as NSString).lastPathComponent
               ) {
                return pattern.isEmpty || pattern == "*" ? .any : .process(pattern)
            }
        }

        return nil
    }
    
    func matchesIP(_ ipString: String) -> Bool {
        return Self.matchIPList(targetHosts, ipString: ipString)
    }

    // matches targetHosts against the destination ip and any domains that
    // resolved to it (from the dns proxy). a pattern can be an ip/range or a
    // domain like *.github.com
    func matchesHost(ip: String, domains: [String]) -> Bool {
        if targetHosts.isEmpty || targetHosts == "*" { return true }
        for raw in targetHosts.components(separatedBy: ";") {
            let pattern = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if pattern.isEmpty { continue }
            if Self.matchIPPattern(pattern, ipString: ip) { return true }

            let lowered = pattern.lowercased()
            // *.example.com also covers the apex example.com, which is what users expect
            let apex = lowered.hasPrefix("*.") ? String(lowered.dropFirst(2)) : nil
            for domain in domains {
                if Self.globMatch(lowered, domain) { return true }
                if let apex = apex, domain == apex { return true }
            }
        }
        return false
    }


    func matchesPort(_ port: UInt16) -> Bool {
        return Self.matchPortList(targetPorts, port: port)
    }
    
    private static func appBundleNames(_ executablePath: String) -> [String] {
        let pathComponents = (executablePath as NSString).pathComponents
        return pathComponents.dropLast().filter { $0.lowercased().hasSuffix(".app") }
    }
    
    private static func matchProcessPattern(_ pattern: String, processPath: String, filename: String) -> Bool {
        if pattern.isEmpty || pattern == "*" {
            return true
        }

        let isFullPathPattern = pattern.contains("/") || pattern.contains("\\")
        let matchTarget = isFullPathPattern ? processPath : filename
        return globMatch(pattern.lowercased(), matchTarget.lowercased())
    }

    // wildcard match supporting any number of "*", e.g. *chrome*, com.*.browser, curl*
    private static func globMatch(_ pattern: String, _ text: String) -> Bool {
        let p = Array(pattern), t = Array(text)
        var pi = 0, ti = 0, star = -1, mark = 0
        while ti < t.count {
            if pi < p.count, p[pi] == t[ti] {
                pi += 1; ti += 1
            } else if pi < p.count, p[pi] == "*" {
                star = pi; mark = ti; pi += 1
            } else if star != -1 {
                pi = star + 1; mark += 1; ti = mark
            } else {
                return false
            }
        }
        while pi < p.count, p[pi] == "*" { pi += 1 }
        return pi == p.count
    }
    
    private static func matchIPList(_ ipList: String, ipString: String) -> Bool {
        if ipList.isEmpty || ipList == "*" {
            return true
        }
        
        let patterns = ipList.components(separatedBy: ";")
        for pattern in patterns {
            let trimmed = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
            if matchIPPattern(trimmed, ipString: ipString) {
                return true
            }
        }
        return false
    }
    
    // raw bytes of a v4 (4) or v6 (16) address, nil if not an ip literal
    private static func ipToBytes(_ ipString: String) -> [UInt8]? {
        if let v4 = IPv4Address(ipString) { return Array(v4.rawValue) }
        if let v6 = IPv6Address(ipString) { return Array(v6.rawValue) }
        return nil
    }

    private static func compareBytes(_ a: [UInt8], _ b: [UInt8]) -> Int {
        for i in 0..<min(a.count, b.count) where a[i] != b[i] {
            return a[i] < b[i] ? -1 : 1
        }
        return 0
    }

    // full 8 hextet form of a v6 address, e.g. ["2001","db8","0",...]
    private static func expandIPv6(_ ipString: String) -> [String]? {
        guard let v6 = IPv6Address(ipString) else { return nil }
        let bytes = Array(v6.rawValue)
        var groups: [String] = []
        for i in stride(from: 0, to: 16, by: 2) {
            let value = (UInt16(bytes[i]) << 8) | UInt16(bytes[i + 1])
            groups.append(String(format: "%x", value))
        }
        return groups
    }

    private static func matchIPPattern(_ pattern: String, ipString: String) -> Bool {
        if pattern.isEmpty || pattern == "*" {
            return true
        }

        // range, works for v4 and v6, e.g. 10.0.0.1-10.0.0.254 or fe80::1-fe80::ff
        if pattern.contains("-") {
            let parts = pattern.components(separatedBy: "-")
            guard parts.count == 2,
                  let lo = ipToBytes(parts[0].trimmingCharacters(in: .whitespaces)),
                  let hi = ipToBytes(parts[1].trimmingCharacters(in: .whitespaces)),
                  let target = ipToBytes(ipString),
                  lo.count == hi.count, target.count == lo.count else {
                return false
            }
            return compareBytes(target, lo) >= 0 && compareBytes(target, hi) <= 0
        }

        // v6 pattern (contains a colon)
        if pattern.contains(":") {
            return matchIPv6Pattern(pattern, ipString: ipString)
        }

        // v4 wildcard, e.g. 192.168.1.*
        let patternOctets = pattern.components(separatedBy: ".")
        let ipOctets = ipString.components(separatedBy: ".")
        if patternOctets.count != 4 || ipOctets.count != 4 {
            return false
        }
        for i in 0..<4 {
            if patternOctets[i] == "*" { continue }
            if patternOctets[i] != ipOctets[i] { return false }
        }
        return true
    }

    private static func matchIPv6Pattern(_ pattern: String, ipString: String) -> Bool {
        // prefix wildcard on leading hextets, e.g. 2001:db8:* (no :: compression)
        if pattern.hasSuffix("*") {
            guard let target = expandIPv6(ipString) else { return false }
            var groups = pattern.lowercased().dropLast()
                .split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            if groups.last == "" { groups.removeLast() }
            for (i, g) in groups.enumerated() {
                guard i < 8, !g.isEmpty, let value = UInt16(g, radix: 16) else { return false }
                if String(format: "%x", value) != target[i] { return false }
            }
            return true
        }

        // exact match, compared on normalized bytes so ::1 == 0:0:...:1
        guard let p = ipToBytes(pattern), let t = ipToBytes(ipString) else { return false }
        return p == t
    }
    
    private static func matchPortList(_ portList: String, port: UInt16) -> Bool {
        if portList.isEmpty || portList == "*" {
            return true
        }
        
        let patterns = portList.components(separatedBy: CharacterSet(charactersIn: ",;"))
        for pattern in patterns {
            let trimmed = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
            if matchPortPattern(trimmed, port: port) {
                return true
            }
        }
        return false
    }
    
    private static func matchPortPattern(_ pattern: String, port: UInt16) -> Bool {
        if pattern.isEmpty || pattern == "*" {
            return true
        }
        
        if let dashIndex = pattern.firstIndex(of: "-") {
            let startStr = String(pattern[..<dashIndex])
            let endStr = String(pattern[pattern.index(after: dashIndex)...])
            
            if let start = UInt16(startStr), let end = UInt16(endStr) {
                return port >= start && port <= end
            }
            return false
        }
        
        if let patternPort = UInt16(pattern) {
            return port == patternPort
        }
        return false
    }
}

enum ProcessMatch {
    case app(String)
    case process(String)
    case any

    var kind: String {
        switch self {
        case .app: return "APP"
        case .process: return "PROC"
        case .any: return "ANY"
        }
    }

    var value: String {
        switch self {
        case let .app(value), let .process(value): return value
        case .any: return ""
        }
    }
}

struct MatchedRule {
    let rule: ProxyRule
    let processMatch: ProcessMatch
}

@objc(AppProxyProvider)
class AppProxyProvider: NETransparentProxyProvider {

    private struct RuleLogContext {
        let ruleId: String
        let ruleName: String
        let matchType: String
        let matchValue: String

        static let defaultMatch = RuleLogContext(
            ruleId: "",
            ruleName: "",
            matchType: "DEFAULT",
            matchValue: ""
        )

        init(ruleId: String, ruleName: String, matchType: String, matchValue: String) {
            self.ruleId = ruleId
            self.ruleName = ruleName
            self.matchType = matchType
            self.matchValue = matchValue
        }

        init(_ match: MatchedRule) {
            self.init(
                ruleId: String(match.rule.ruleId),
                ruleName: match.rule.name,
                matchType: match.processMatch.kind,
                matchValue: match.processMatch.value
            )
        }
    }
    
    // one log entry, kept as an enum so we don't allocate a dictionary per line,
    // the dict is only built when the gui drains a batch
    private enum LogEntry {
        case connection(proto: String, process: String, destination: String, port: String, proxy: String, status: String, details: String, rule: RuleLogContext)
        case activity(timestamp: String, level: String, message: String)

        func toDict() -> [String: String] {
            switch self {
            case let .connection(proto, process, destination, port, proxy, status, details, rule):
                return ["type": "connection", "protocol": proto, "process": process,
                        "destination": destination, "port": port, "proxy": proxy,
                        "status": status, "details": details, "ruleId": rule.ruleId,
                        "ruleName": rule.ruleName, "matchType": rule.matchType,
                        "matchValue": rule.matchValue]
            case let .activity(timestamp, level, message):
                return ["type": "activity", "timestamp": timestamp, "level": level, "message": message]
            }
        }
    }

    // circular buffer for logs, avoids shifting the whole array on every pop
    private static let logCapacity = 500
    private var logBuffer = [LogEntry?](repeating: nil, count: AppProxyProvider.logCapacity)
    private var logHead = 0
    private var logTail = 0
    private var logCount = 0
    private let logQueueLock = NSLock()
    private let dateFormatter: ISO8601DateFormatter = ISO8601DateFormatter()
    
    // cache the full executable path by pid so app rules can inspect containing
    // .app components without calling proc_pidpath on every connection
    private var processPathCache: [pid_t: String] = [:]
    private let pidCacheLock = NSLock()
    private static let pidCacheMaxSize = 256
    
    private func getProcessPath(from metaData: NEFlowMetaData) -> String? {
        guard let auditTokenData = metaData.sourceAppAuditToken else {
            return nil
        }
        guard auditTokenData.count == MemoryLayout<audit_token_t>.size else {
            return nil
        }
        
        let pid = auditTokenData.withUnsafeBytes { ptr -> pid_t in
            guard let baseAddress = ptr.baseAddress else { return 0 }
            let token = baseAddress.assumingMemoryBound(to: UInt32.self)
            return pid_t(token[5])
        }
        
        guard pid > 0 else { return nil }
        
        pidCacheLock.lock()
        if let cached = processPathCache[pid] {
            pidCacheLock.unlock()
            return cached
        }
        pidCacheLock.unlock()

        var pathBuffer = [Int8](repeating: 0, count: Int(MAXPATHLEN))
        guard proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN)) > 0 else {
            return nil
        }
        
        let fullPath = String(cString: pathBuffer)
        
        // store in cache, evict everything if full - processes rarely hit this
        pidCacheLock.lock()
        if processPathCache.count >= AppProxyProvider.pidCacheMaxSize {
            processPathCache.removeAll(keepingCapacity: true)
        }
        processPathCache[pid] = fullPath
        pidCacheLock.unlock()
        
        return fullPath
    }
    
    // guarded by its own lock, the old OSAtomic compare-and-swap setter could
    // silently no-op if the stored value wasn't the exact expected one
    private var _trafficLoggingEnabled = true
    private let trafficLoggingLock = NSLock()
    private var trafficLoggingEnabled: Bool {
        get { trafficLoggingLock.lock(); defer { trafficLoggingLock.unlock() }; return _trafficLoggingEnabled }
        set { trafficLoggingLock.lock(); _trafficLoggingEnabled = newValue; trafficLoggingLock.unlock() }
    }
    
    private var rules: [ProxyRule] = []
    private let rulesLock = NSLock()
    private var nextRuleId: UInt32 = 1
    
    private struct StoredProxyConfig {
        let type: String
        let host: String
        let port: Int
        let username: String?
        let password: String?
    }
    private var storedProxyConfigs: [String: StoredProxyConfig] = [:]
    private let proxyLock = NSLock()

    private enum ActivityLogScope {
        case system
        case connection
    }
    
    private func log(_ message: String, level: String = "INFO", scope: ActivityLogScope = .connection) {
        // Per-flow events already have a structured representation in the
        // Connections tab. Activity is reserved for control-plane events so the
        // two tabs do not mirror the same traffic in different string formats.
        guard case .system = scope else { return }
        appendLog(.activity(timestamp: dateFormatter.string(from: Date()), level: level, message: message))
    }

    private func appendLog(_ entry: LogEntry) {
        logQueueLock.lock()
        logBuffer[logTail] = entry
        logTail = (logTail + 1) % AppProxyProvider.logCapacity
        if logCount < AppProxyProvider.logCapacity {
            logCount += 1
        } else {
            // buffer full, bump head to drop the oldest entry
            logHead = (logHead + 1) % AppProxyProvider.logCapacity
        }
        logQueueLock.unlock()
    }

    private func applyProxyConfigs(_ configs: [[String: Any]]) {
        proxyLock.lock()
        storedProxyConfigs = [:]
        for configDict in configs {
            guard let id = configDict["id"] as? String,
                  let type = configDict["proxyType"] as? String,
                  let host = configDict["proxyHost"] as? String,
                  let port = configDict["proxyPort"] as? Int else { continue }
            storedProxyConfigs[id] = StoredProxyConfig(
                type: type, host: host, port: port,
                username: configDict["proxyUsername"] as? String,
                password: configDict["proxyPassword"] as? String
            )
        }
        proxyLock.unlock()
        log("Proxy configs loaded: \(storedProxyConfigs.count) config(s)", scope: .system)
    }

    private func applyRules(_ rawRules: [[String: Any]]) {
        rulesLock.lock()
        rules.removeAll()
        nextRuleId = 1
        for ruleDict in rawRules {
            let name = ruleDict["name"] as? String ?? ""
            let processNames = ruleDict["processNames"] as? String ?? ""
            let targetHosts = ruleDict["targetHosts"] as? String ?? ""
            let targetPorts = ruleDict["targetPorts"] as? String ?? ""
            let protoStr = (ruleDict["protocol"] as? String ?? ruleDict["ruleProtocol"] as? String ?? "BOTH").uppercased()
            let proto = RuleProtocol(rawValue: protoStr) ?? .both
            let action = ruleDict["action"] as? String ?? ruleDict["ruleAction"] as? String ?? "DIRECT"
            let enabled = ruleDict["enabled"] as? Bool ?? true
            let rule = ProxyRule(ruleId: nextRuleId, name: name, processNames: processNames, targetHosts: targetHosts, targetPorts: targetPorts, ruleProtocol: proto, action: action, enabled: enabled)
            nextRuleId += 1
            rules.append(rule)
        }
        let count = rules.count
        rulesLock.unlock()
        log("Loaded \(count) rule(s) into extension", scope: .system)
    }

    private func drainLogs() -> [[String: String]] {
        logQueueLock.lock()
        defer { logQueueLock.unlock() }
        guard logCount > 0 else { return [] }
        let batchSize = min(100, logCount)
        var logsToSend: [[String: String]] = []
        logsToSend.reserveCapacity(batchSize)
        for _ in 0..<batchSize {
            if let entry = logBuffer[logHead] {
                logsToSend.append(entry.toDict())
            }
            logBuffer[logHead] = nil
            logHead = (logHead + 1) % AppProxyProvider.logCapacity
            logCount -= 1
        }
        return logsToSend
    }

    override func startProxy(options: [String : Any]?, completionHandler: @escaping (Error?) -> Void) {
        var initialDict = options ?? [:]
        if let protoConfig = (self.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration {
            for (k, v) in protoConfig {
                if initialDict[k] == nil {
                    initialDict[k] = v
                }
            }
        }
        
        if let configs = initialDict["configs"] as? [[String: Any]] {
            self.applyProxyConfigs(configs)
        }
        if let rawRules = initialDict["rules"] as? [[String: Any]] {
            self.applyRules(rawRules)
        }

        LocalIPCServer.shared.onGetLogs = { [weak self] in
            return self?.drainLogs() ?? []
        }
        LocalIPCServer.shared.onGetHealth = { [weak self] in
            guard let self = self else { return [:] }
            self.rulesLock.lock()
            let ruleCount = self.rules.count
            self.rulesLock.unlock()
            self.proxyLock.lock()
            let configCount = self.storedProxyConfigs.count
            self.proxyLock.unlock()
            self.udpLock.lock()
            let udpCount = self.udpAssociations.count
            self.udpLock.unlock()
            return [
                "status": "ok",
                "rulesCount": ruleCount,
                "configsCount": configCount,
                "activeUDPCount": udpCount
            ]
        }
        LocalIPCServer.shared.onSetRules = { [weak self] rawRules in
            self?.applyRules(rawRules)
            return rawRules.count
        }
        LocalIPCServer.shared.onSetConfigs = { [weak self] configs in
            self?.applyProxyConfigs(configs)
        }
        LocalIPCServer.shared.onSetTrafficLogging = { [weak self] enabled in
            self?.trafficLoggingEnabled = enabled
        }
        LocalIPCServer.shared.onClearRules = { [weak self] in
            self?.rulesLock.lock()
            self?.rules.removeAll()
            self?.nextRuleId = 1
            self?.rulesLock.unlock()
        }
        if let ipcAuthToken = initialDict["ipcAuthToken"] as? String {
            LocalIPCServer.shared.start(authorizationToken: ipcAuthToken)
        } else {
            log("Local IPC disabled: missing startup authorization token", level: "ERROR", scope: .system)
        }

        startUDPSweeper()

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        
        let allTrafficRule = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .any,
            direction: .outbound
        )
        
        settings.includedNetworkRules = [allTrafficRule]
        
        self.setTunnelNetworkSettings(settings) { error in
            completionHandler(error)
        }
    }
    
    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stopUDPSweeper()
        LocalIPCServer.shared.stop()
        udpLock.lock()
        let all = Array(udpAssociations.values)
        udpAssociations.removeAll()
        udpLock.unlock()
        for a in all {
            a.controlConnection.cancel()
            a.udpSession.cancel()
        }
        completionHandler()
    }
    
    // one association per udp flow, holds both channels so we tear the whole thing
    // down together when any side goes away
    private final class UDPAssociation {
        let clientFlow: NEAppProxyUDPFlow
        let controlConnection: NWTCPConnection  // socks5 tcp control channel, keeps the association alive
        let udpSession: NWUDPSession            // relay channel to the socks server
        let displayName: String
        let socksHost: String
        let socksPort: Int
        let ruleContext: RuleLogContext
        var loggedDestinations = Set<String>()  // dedupe connection logs, bounded
        var isTornDown = false
        var lastActivity: Date = Date()

        init(clientFlow: NEAppProxyUDPFlow, controlConnection: NWTCPConnection, udpSession: NWUDPSession, displayName: String, socksHost: String, socksPort: Int, ruleContext: RuleLogContext) {
            self.clientFlow = clientFlow
            self.controlConnection = controlConnection
            self.udpSession = udpSession
            self.displayName = displayName
            self.socksHost = socksHost
            self.socksPort = socksPort
            self.ruleContext = ruleContext
        }
    }
    private var udpAssociations: [NEAppProxyUDPFlow: UDPAssociation] = [:]
    private let udpLock = NSLock()
    private var udpSweeperTimer: DispatchSourceTimer?
    private let sweeperQueue = DispatchQueue(label: "com.interceptsuite.ProxyBridge.sweeper")

    private func startUDPSweeper() {
        stopUDPSweeper()
        let timer = DispatchSource.makeTimerSource(queue: sweeperQueue)
        timer.schedule(deadline: .now() + 30.0, repeating: 30.0)
        timer.setEventHandler { [weak self] in
            self?.sweepStaleUDPAssociations()
        }
        udpSweeperTimer = timer
        timer.resume()
    }

    private func stopUDPSweeper() {
        udpSweeperTimer?.cancel()
        udpSweeperTimer = nil
    }

    private func sweepStaleUDPAssociations() {
        let now = Date()
        udpLock.lock()
        // Evict any UDP association with no traffic for > 60 seconds
        let staleFlows = udpAssociations.compactMap { (flow, assoc) -> NEAppProxyUDPFlow? in
            return now.timeIntervalSince(assoc.lastActivity) > 60.0 ? flow : nil
        }
        udpLock.unlock()

        for flow in staleFlows {
            teardownUDP(flow)
        }
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let message = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
              let action = message["action"] as? String else {
            completionHandler?(nil)
            return
        }
        
        switch action {
        case "getLogs":
            logQueueLock.lock()
            if logCount > 0 {
                let batchSize = min(100, logCount)
                var logsToSend: [[String: String]] = []
                logsToSend.reserveCapacity(batchSize)
                for _ in 0..<batchSize {
                    if let entry = logBuffer[logHead] {
                        logsToSend.append(entry.toDict())
                    }
                    logBuffer[logHead] = nil  // release the drained entry
                    logHead = (logHead + 1) % AppProxyProvider.logCapacity
                    logCount -= 1
                }
                logQueueLock.unlock()
                completionHandler?(try? JSONSerialization.data(withJSONObject: logsToSend))
            } else {
                logQueueLock.unlock()
                completionHandler?(nil)
            }
        case "setTrafficLogging":
            if let enabled = message["enabled"] as? Bool {
                trafficLoggingEnabled = enabled
                let response = ["status": "ok"]
                completionHandler?(try? JSONSerialization.data(withJSONObject: response))
            } else {
                completionHandler?(nil)
            }
        case "setProxyConfigs":
            if let configs = message["configs"] as? [[String: Any]] {
                applyProxyConfigs(configs)
            }
            completionHandler?(try? JSONSerialization.data(withJSONObject: ["status": "ok"]))

        case "addRule":
            var decodedRule: ProxyRule? = nil
            if let ruleData = try? JSONSerialization.data(withJSONObject: message),
               let r = try? JSONDecoder().decode(ProxyRule.self, from: ruleData) {
                decodedRule = r
            } else {
                let name = message["name"] as? String ?? ""
                let processNames = message["processNames"] as? String ?? ""
                let targetHosts = message["targetHosts"] as? String ?? ""
                let targetPorts = message["targetPorts"] as? String ?? ""
                let protoStr = (message["protocol"] as? String ?? message["ruleProtocol"] as? String ?? "BOTH").uppercased()
                let proto = RuleProtocol(rawValue: protoStr) ?? .both
                let action = message["action"] as? String ?? message["ruleAction"] as? String ?? "DIRECT"
                let enabled = message["enabled"] as? Bool ?? true
                decodedRule = ProxyRule(ruleId: 0, name: name, processNames: processNames, targetHosts: targetHosts, targetPorts: targetPorts, ruleProtocol: proto, action: action, enabled: enabled)
            }

            if var rule = decodedRule {
                rulesLock.lock()
                rule.ruleId = nextRuleId
                nextRuleId += 1
                rules.append(rule)
                rulesLock.unlock()

                let response: [String: Any] = [
                    "status": "ok",
                    "ruleId": rule.ruleId,
                    "processNames": rule.processNames,
                    "targetHosts": rule.targetHosts,
                    "targetPorts": rule.targetPorts,
                    "protocol": rule.ruleProtocol.rawValue,
                    "action": rule.action,
                    "enabled": rule.enabled
                ]
                completionHandler?(try? JSONSerialization.data(withJSONObject: response))
            } else {
                let response = ["status": "error", "message": "Invalid rule format"]
                completionHandler?(try? JSONSerialization.data(withJSONObject: response))
            }
        
        case "clearRules":
            rulesLock.lock()
            let count = rules.count
            rules.removeAll()
            rulesLock.unlock()
            let response: [String: Any] = ["status": "ok", "cleared": count]
            completionHandler?(try? JSONSerialization.data(withJSONObject: response))
        
        case "clearConfig":
            // drop the stored proxy configs so credentials don't sit in memory after stop
            proxyLock.lock()
            storedProxyConfigs.removeAll()
            proxyLock.unlock()
            completionHandler?(try? JSONSerialization.data(withJSONObject: ["status": "ok"]))
        default:
            completionHandler?(nil)
        }
    }
    
    override func sleep(completionHandler: @escaping () -> Void) {
        log("System going to sleep, cleaning up active UDP flows", scope: .system)
        udpLock.lock()
        let allFlows = Array(udpAssociations.keys)
        udpLock.unlock()
        for flow in allFlows {
            teardownUDP(flow)
        }
        completionHandler()
    }
    
    override func wake() {
        log("System woke from sleep, resetting stale associations and verifying listener", scope: .system)
        udpLock.lock()
        let allFlows = Array(udpAssociations.keys)
        udpLock.unlock()
        for flow in allFlows {
            teardownUDP(flow)
        }
    }
    
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            return handleTCPFlow(tcpFlow)
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            return handleUDPFlow(udpFlow)
        }
        return false
    }
    
    private func handleTCPFlow(_ flow: NEAppProxyTCPFlow) -> Bool {
        let metaData = flow.metaData
        let signingIdentifier = metaData.sourceAppSigningIdentifier
        
        // never proxy our own traffic, it would loop
        if signingIdentifier == "com.interceptsuite.ProxyBridge" || signingIdentifier == "com.interceptsuite.ProxyBridge.extension" {
            return false
        }

        let remoteEndpoint = flow.remoteEndpoint
        var destination = ""
        var portNum: UInt16 = 0
        var portStr = ""
        
        if let remoteHost = remoteEndpoint as? NWHostEndpoint {
            destination = remoteHost.hostname
            portStr = remoteHost.port
            portNum = UInt16(portStr) ?? 0
        } else {
            destination = String(describing: remoteEndpoint)
            portStr = "unknown"
        }
        
        if portNum == LocalIPCServer.port {
            return false
        }
        
        let executablePath = getProcessPath(from: metaData)
        let processName = executablePath.map { ($0 as NSString).lastPathComponent }
        let displayName = processName ?? signingIdentifier
        
        // domains that resolved to this ip (from the dns proxy), used for domain
        // rules and to show the hostname in the log instead of the raw ip
        let domains = DNSMapStore.shared.domains(forIP: destination)
        let logDest = domains.first ?? destination

        proxyLock.lock()
        let hasProxyConfig = !storedProxyConfigs.isEmpty
        proxyLock.unlock()

        if !hasProxyConfig {
            sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: portStr, proxy: "Direct", status: "DIRECT", details: "No proxy configured")
            log("[\(displayName)] [\(logDest):\(portStr)] DIRECT (no proxy configured)")
            return false
        }

        let matchedRule = findMatchingRule(bundleId: signingIdentifier, processName: processName, executablePath: executablePath, destination: destination, port: portNum, connectionProtocol: .tcp, checkIpPort: true, domains: domains)

        if let matchedRule {
            let rule = matchedRule.rule
            let ruleContext = RuleLogContext(matchedRule)
            switch rule.action {
            case "DIRECT":
                sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: portStr, proxy: "Direct", status: "DIRECT", ruleContext: ruleContext)
                log("[\(displayName)] [\(logDest):\(portStr)] DIRECT (matched rule #\(rule.ruleId))")
                return false
            case "BLOCK":
                sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: portStr, proxy: "BLOCK", status: "BLOCKED", ruleContext: ruleContext)
                log("[\(displayName)] [\(logDest):\(portStr)] BLOCKED (matched rule #\(rule.ruleId))", level: "WARN")
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return true
            default:
                proxyLock.lock()
                let config = storedProxyConfigs[rule.action]
                proxyLock.unlock()
                guard let config = config else {
                    // rule points at a proxy that no longer exists, let it go direct
                    sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: portStr, proxy: "Direct", status: "DIRECT", details: "Proxy config not found", ruleContext: ruleContext)
                    log("[\(displayName)] [\(logDest):\(portStr)] DIRECT (proxy config '\(rule.action)' missing)", level: "WARN")
                    return false
                }
                let label = proxyLabel(config)
                sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: portStr, proxy: label, status: "CONNECTING", details: "Handshaking with \(label)", ruleContext: ruleContext)
                log("[\(displayName)] [\(logDest):\(portStr)] [\(label)] Routing via rule #\(rule.ruleId)")
                proxyTCPFlow(flow, displayName: displayName, destination: destination, port: portNum, logDest: logDest, config: config, ruleContext: ruleContext)
                return true
            }
        } else {
            sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: portStr, proxy: "Direct", status: "DIRECT")
            log("[\(displayName)] [\(logDest):\(portStr)] DIRECT (no matching rule)")
            return false
        }
    }

    // human readable label for the connection log, e.g. SOCKS5 127.0.0.1:1080
    private func proxyLabel(_ config: StoredProxyConfig) -> String {
        return "\(config.type.uppercased()) \(config.host):\(config.port)"
    }
    
    private func handleUDPFlow(_ flow: NEAppProxyUDPFlow) -> Bool {
        let metaData = flow.metaData
        let signingIdentifier = metaData.sourceAppSigningIdentifier
        let executablePath = getProcessPath(from: metaData)
        let processName = executablePath.map { ($0 as NSString).lastPathComponent }
        let displayName = processName ?? signingIdentifier
        
        if signingIdentifier == "com.interceptsuite.ProxyBridge" || signingIdentifier == "com.interceptsuite.ProxyBridge.extension" {
            return false
        }
        
        proxyLock.lock()
        let hasAnySocks5 = storedProxyConfigs.values.contains { $0.type.lowercased() == "socks5" }
        proxyLock.unlock()

        if !hasAnySocks5 {
            sendLogToApp(protocol: "UDP", process: displayName, destination: "*", port: "*", proxy: "Direct", status: "DIRECT", details: "No SOCKS5 proxy configured for UDP")
            return false
        }

        let matchedRule = findMatchingRule(bundleId: signingIdentifier, processName: processName, executablePath: executablePath, destination: "", port: 0, connectionProtocol: .udp, checkIpPort: false)

        if let matchedRule {
            let rule = matchedRule.rule
            let ruleContext = RuleLogContext(matchedRule)
            let action = rule.action
            switch action {
            case "DIRECT":
                sendLogToApp(protocol: "UDP", process: displayName, destination: "*", port: "*", proxy: "Direct", status: "DIRECT", ruleContext: ruleContext)
                log("[\(displayName)] [UDP] DIRECT (matched rule #\(rule.ruleId))")
                return false
            case "BLOCK":
                sendLogToApp(protocol: "UDP", process: displayName, destination: "*", port: "*", proxy: "BLOCK", status: "BLOCKED", ruleContext: ruleContext)
                log("[\(displayName)] [UDP] BLOCKED (matched rule #\(rule.ruleId))", level: "WARN")
                return true
            default:
                proxyLock.lock()
                let matched = storedProxyConfigs[action]
                proxyLock.unlock()
                guard let socks5Config = matched, socks5Config.type.lowercased() == "socks5" else {
                    sendLogToApp(protocol: "UDP", process: displayName, destination: "*", port: "*", proxy: "Direct", status: "DIRECT", details: "HTTP proxy cannot relay UDP", ruleContext: ruleContext)
                    log("[\(displayName)] [UDP] DIRECT (configured proxy is HTTP, UDP not supported)")
                    return false
                }
                log("[\(displayName)] [UDP] [SOCKS5 \(socks5Config.host):\(socks5Config.port)] Opening UDP flow (rule #\(rule.ruleId))")
                flow.open(withLocalEndpoint: nil) { [weak self] error in
                    guard let self = self else { return }
                    if let error = error {
                        self.log("[\(displayName)] [UDP] [SOCKS5 \(socks5Config.host):\(socks5Config.port)] Flow open failed: \(error.localizedDescription)", level: "ERROR")
                        self.sendLogToApp(protocol: "UDP", process: displayName, destination: "*", port: "*", proxy: "SOCKS5 \(socks5Config.host):\(socks5Config.port)", status: self.connectionStatus(for: error), details: "Flow open failed: \(error.localizedDescription)", ruleContext: ruleContext)
                        return
                    }
                    self.proxyUDPFlowViaSOCKS5(flow, displayName: displayName, socksHost: socks5Config.host, socksPort: socks5Config.port, username: socks5Config.username, password: socks5Config.password, ruleContext: ruleContext)
                }
                return true
            }
        } else {
            sendLogToApp(protocol: "UDP", process: displayName, destination: "*", port: "*", proxy: "Direct", status: "DIRECT")
            log("[\(displayName)] [UDP] DIRECT (no matching rule)")
            return false
        }
    }
    
    // handshake failed before an association existed, so drop the control
    // connection and close the flow instead of leaking them
    private func failUDPHandshake(_ clientFlow: NEAppProxyUDPFlow, _ tcpConnection: NWTCPConnection, displayName: String, socksEndpoint: String, _ reason: String, status: String = "FAILED", ruleContext: RuleLogContext) {
        log("[\(displayName)] [UDP] [\(socksEndpoint)] \(reason)", level: "ERROR")
        sendLogToApp(protocol: "UDP", process: displayName, destination: "*", port: "*", proxy: "SOCKS5 \(socksEndpoint)", status: status, details: reason, ruleContext: ruleContext)
        tcpConnection.cancel()
        clientFlow.closeReadWithError(nil)
        clientFlow.closeWriteWithError(nil)
    }

    private func proxyUDPFlowViaSOCKS5(_ clientFlow: NEAppProxyUDPFlow, displayName: String, socksHost: String, socksPort: Int, username: String?, password: String?, ruleContext: RuleLogContext) {
        let socksEndpoint = "\(socksHost):\(socksPort)"
        let proxyEndpoint = NWHostEndpoint(hostname: socksHost, port: String(socksPort))
        let tcpConnection = createTCPConnection(to: proxyEndpoint, enableTLS: false, tlsParameters: nil, delegate: nil)

        // offer username/password auth when we have credentials, same as the tcp path
        let useAuth = (username != nil && password != nil)
        let greeting: [UInt8] = useAuth ? [0x05, 0x02, 0x00, 0x02] : [0x05, 0x01, 0x00]

        tcpConnection.write(Data(greeting)) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP greeting failed: \(error.localizedDescription)", status: self.connectionStatus(for: error), ruleContext: ruleContext)
                return
            }

            tcpConnection.readMinimumLength(2, maximumLength: 2) { [weak self] data, error in
                guard let self = self else { return }

                if let error = error {
                    self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP greeting response failed: \(error.localizedDescription)", status: self.connectionStatus(for: error), ruleContext: ruleContext)
                    return
                }

                guard let data = data, data.count == 2, data[0] == 0x05 else {
                    self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP greeting response invalid", ruleContext: ruleContext)
                    return
                }

                switch data[1] {
                case 0x00:
                    self.sendSOCKS5UDPAssociate(clientFlow: clientFlow, tcpConnection: tcpConnection, socksHost: socksHost, socksPort: socksPort, displayName: displayName, ruleContext: ruleContext)
                case 0x02:
                    self.sendSOCKS5UDPAuth(clientFlow: clientFlow, tcpConnection: tcpConnection, socksHost: socksHost, socksPort: socksPort, displayName: displayName, username: username ?? "", password: password ?? "", ruleContext: ruleContext)
                default:
                    self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP no acceptable auth method (method=\(data[1]))", status: "AUTH_FAILED", ruleContext: ruleContext)
                }
            }
        }
    }

    private func sendSOCKS5UDPAuth(clientFlow: NEAppProxyUDPFlow, tcpConnection: NWTCPConnection, socksHost: String, socksPort: Int, displayName: String, username: String, password: String, ruleContext: RuleLogContext) {
        let socksEndpoint = "\(socksHost):\(socksPort)"
        let user = Array(username.utf8), pass = Array(password.utf8)
        guard user.count <= 255, pass.count <= 255 else {
            self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP credentials too long", ruleContext: ruleContext)
            return
        }

        var authData = Data()
        authData.append(0x01)
        authData.append(UInt8(user.count))
        authData.append(contentsOf: user)
        authData.append(UInt8(pass.count))
        authData.append(contentsOf: pass)

        tcpConnection.write(authData) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP auth write failed: \(error.localizedDescription)", status: self.connectionStatus(for: error), ruleContext: ruleContext)
                return
            }

            tcpConnection.readMinimumLength(2, maximumLength: 2) { [weak self] data, error in
                guard let self = self else { return }

                if let error = error {
                    self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP auth response failed: \(error.localizedDescription)", status: self.connectionStatus(for: error), ruleContext: ruleContext)
                    return
                }

                guard let data = data, data.count == 2, data[1] == 0x00 else {
                    self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP auth rejected by proxy", status: "AUTH_FAILED", ruleContext: ruleContext)
                    return
                }

                self.sendSOCKS5UDPAssociate(clientFlow: clientFlow, tcpConnection: tcpConnection, socksHost: socksHost, socksPort: socksPort, displayName: displayName, ruleContext: ruleContext)
            }
        }
    }

    private func sendSOCKS5UDPAssociate(clientFlow: NEAppProxyUDPFlow, tcpConnection: NWTCPConnection, socksHost: String, socksPort: Int, displayName: String, ruleContext: RuleLogContext) {
        let socksEndpoint = "\(socksHost):\(socksPort)"
        var request = Data()
        request.append(0x05)
        request.append(0x03)
        request.append(0x00)
        request.append(0x01)
        request.append(contentsOf: [0, 0, 0, 0])
        request.append(contentsOf: [0, 0])
        
        tcpConnection.write(request) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP ASSOCIATE write failed: \(error.localizedDescription)", status: self.connectionStatus(for: error), ruleContext: ruleContext)
                return
            }

            // read at least VER+REP so we can report the reason even on a short reply
            tcpConnection.readMinimumLength(2, maximumLength: 512) { [weak self] data, error in
                guard let self = self else { return }

                if let error = error {
                    self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP ASSOCIATE response read error: \(error.localizedDescription)", status: self.connectionStatus(for: error), ruleContext: ruleContext)
                    return
                }

                guard let data = data, data.count >= 2, data[0] == 0x05 else {
                    self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP ASSOCIATE invalid reply (\(data?.count ?? 0) bytes)", ruleContext: ruleContext)
                    return
                }

                let rep = data[1]
                guard rep == 0x00 else {
                    let reason = self.socksReplyReason(rep)
                    self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP ASSOCIATE rejected, REP=0x\(String(format: "%02x", rep)) (\(reason))", status: self.socksReplyStatus(rep), ruleContext: ruleContext)
                    return
                }

                guard data.count >= 10 else {
                    self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP ASSOCIATE reply too short (\(data.count) bytes)", ruleContext: ruleContext)
                    return
                }

                let (parsedHost, relayPort) = self.parseSOCKS5Address(from: data, offset: 3)
                // many socks servers reply 0.0.0.0 meaning "reuse the control connection host"
                let relayHost = (parsedHost == "0.0.0.0" || parsedHost == "::" || parsedHost.isEmpty) ? socksHost : parsedHost
                guard relayPort != 0 else {
                    self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP ASSOCIATE returned no relay port", ruleContext: ruleContext)
                    return
                }
                self.log("[\(displayName)] [UDP] SOCKS5 UDP ASSOCIATE established via \(relayHost):\(relayPort)")
                self.relayUDPThroughSOCKS5(clientFlow: clientFlow, relayHost: relayHost, relayPort: relayPort, tcpConnection: tcpConnection, displayName: displayName, socksHost: socksHost, socksPort: socksPort, ruleContext: ruleContext)
            }
        }
    }
    
    // Map failures to statuses only when the error or protocol reply identifies
    // the cause. Unknown failures deliberately remain FAILED.
    private func connectionStatus(for error: Error) -> String {
        var current: NSError? = error as NSError
        var visited = Set<ObjectIdentifier>()

        while let nsError = current, visited.insert(ObjectIdentifier(nsError)).inserted {
            if nsError.domain == NEAppProxyErrorDomain {
                switch nsError.code {
                case 1: return "CLOSED"             // not connected
                case 2: return "RESET"              // peer reset
                case 3: return "UNREACHABLE"
                case 5: return "CANCELLED"          // aborted
                case 6: return "REFUSED"
                case 7: return "TIMEOUT"
                default: break
                }
            }

            if nsError.domain == NSPOSIXErrorDomain {
                switch nsError.code {
                case 32, 57, 58: return "CLOSED"         // EPIPE, ENOTCONN, ESHUTDOWN
                case 54: return "RESET"                  // ECONNRESET
                case 89: return "CANCELLED"              // ECANCELED
                case 60: return "TIMEOUT"                // ETIMEDOUT
                case 61: return "REFUSED"                // ECONNREFUSED
                case 50, 51, 64, 65: return "UNREACHABLE" // ENETDOWN/UNREACH, EHOSTDOWN/UNREACH
                default: break
                }
            }

            if nsError.domain == NSURLErrorDomain {
                switch nsError.code {
                case NSURLErrorCancelled:
                    return "CANCELLED"
                case NSURLErrorNetworkConnectionLost:
                    return "RESET"
                case NSURLErrorTimedOut:
                    return "TIMEOUT"
                case NSURLErrorCannotConnectToHost:
                    return "REFUSED"
                case NSURLErrorCannotFindHost, NSURLErrorDNSLookupFailed, NSURLErrorNotConnectedToInternet:
                    return "UNREACHABLE"
                default: break
                }
            }

            current = nsError.userInfo[NSUnderlyingErrorKey] as? NSError
        }

        return "FAILED"
    }

    private func socksReplyStatus(_ rep: UInt8) -> String {
        switch rep {
        case 0x02: return "REJECTED"
        case 0x03, 0x04: return "UNREACHABLE"
        case 0x05: return "REFUSED"
        case 0x06: return "TIMEOUT"
        default: return "FAILED"
        }
    }

    private func httpConnectFailureStatus(_ firstLine: String) -> String {
        guard let codeToken = firstLine.split(separator: " ").dropFirst().first,
              let code = Int(codeToken) else {
            return "FAILED"
        }

        switch code {
        case 401, 407: return "AUTH_FAILED"
        case 408, 504: return "TIMEOUT"
        case 502, 503: return "UNREACHABLE"
        case 400..<500: return "REJECTED"
        default: return "FAILED"
        }
    }

    // human readable name for a socks5 REP code, from RFC 1928
    private func socksReplyReason(_ rep: UInt8) -> String {
        switch rep {
        case 0x01: return "general failure"
        case 0x02: return "not allowed by ruleset"
        case 0x03: return "network unreachable"
        case 0x04: return "host unreachable"
        case 0x05: return "connection refused"
        case 0x06: return "TTL expired"
        case 0x07: return "command not supported"
        case 0x08: return "address type not supported"
        default: return "unknown"
        }
    }

    private func parseSOCKS5Address(from data: Data, offset: Int) -> (String, UInt16) {
        guard data.count > offset else { return ("0.0.0.0", 0) }
        let atyp = data[offset]

        if atyp == 0x01 {
            guard data.count >= offset + 7 else { return ("0.0.0.0", 0) }
            let ip = "\(data[offset+1]).\(data[offset+2]).\(data[offset+3]).\(data[offset+4])"
            let port = (UInt16(data[offset+5]) << 8) | UInt16(data[offset+6])
            return (ip, port)
        } else if atyp == 0x04 {
            guard data.count >= offset + 19 else { return ("0.0.0.0", 0) }
            var ipv6Parts: [String] = []
            for i in 0..<8 {
                let idx = offset + 1 + (i * 2)
                let part = (UInt16(data[idx]) << 8) | UInt16(data[idx+1])
                ipv6Parts.append(String(format: "%x", part))
            }
            let ip = ipv6Parts.joined(separator: ":")
            let port = (UInt16(data[offset+17]) << 8) | UInt16(data[offset+18])
            return (ip, port)
        } else if atyp == 0x03 {
            guard data.count >= offset + 2 else { return ("0.0.0.0", 0) }
            let len = Int(data[offset+1])
            guard data.count >= offset + 2 + len + 2 else { return ("0.0.0.0", 0) }
            let domain = String(data: data[(offset+2)..<(offset+2+len)], encoding: .utf8) ?? "unknown"
            let port = (UInt16(data[offset+2+len]) << 8) | UInt16(data[offset+2+len+1])
            return (domain, port)
        }

        return ("0.0.0.0", 0)
    }
    
    private func relayUDPThroughSOCKS5(clientFlow: NEAppProxyUDPFlow, relayHost: String, relayPort: UInt16, tcpConnection: NWTCPConnection, displayName: String, socksHost: String, socksPort: Int, ruleContext: RuleLogContext) {
        let relayEndpoint = NWHostEndpoint(hostname: relayHost, port: String(relayPort))
        let udpSession = self.createUDPSession(to: relayEndpoint, from: nil)

        let association = UDPAssociation(clientFlow: clientFlow, controlConnection: tcpConnection, udpSession: udpSession, displayName: displayName, socksHost: socksHost, socksPort: socksPort, ruleContext: ruleContext)

        udpLock.lock()
        let existing = udpAssociations[clientFlow]
        udpAssociations[clientFlow] = association
        udpLock.unlock()
        // if the app reused a flow, drop the stale association first
        existing?.controlConnection.cancel()
        existing?.udpSession.cancel()

        readAndForwardClientUDP(association)
        readAndForwardRelayUDP(association)
        // note: we deliberately don't read the control connection to detect close.
        // holding a strong ref keeps the associate alive, and reading it risks a
        // spurious teardown that would EPIPE the app's udp socket.
    }

    // idempotent, cancels both channels and closes the flow exactly once
    private func teardownUDP(_ flow: NEAppProxyUDPFlow) {
        udpLock.lock()
        guard let assoc = udpAssociations.removeValue(forKey: flow), !assoc.isTornDown else {
            udpLock.unlock()
            return
        }
        assoc.isTornDown = true
        udpLock.unlock()

        log("[\(assoc.displayName)] [UDP] [SOCKS5 \(assoc.socksHost):\(assoc.socksPort)] Teardown UDP flow")
        assoc.controlConnection.cancel()
        assoc.udpSession.cancel()
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
    }

    private func readAndForwardClientUDP(_ association: UDPAssociation) {
        let clientFlow = association.clientFlow
        clientFlow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self = self else { return }

            if let error = error {
                let status = self.connectionStatus(for: error)
                self.log("[\(association.displayName)] [UDP] [SOCKS5 \(association.socksHost):\(association.socksPort)] UDP client read error: \(error.localizedDescription)", level: "ERROR")
                self.sendLogToApp(protocol: "UDP", process: association.displayName, destination: "*", port: "*", proxy: "SOCKS5 \(association.socksHost):\(association.socksPort)", status: status, details: "Client read error: \(error.localizedDescription)", ruleContext: association.ruleContext)
                self.teardownUDP(clientFlow)
                return
            }

            // nil or empty datagrams with no error = flow closed for reading.
            // re-arming on empty spins at 100% cpu because the read completes
            // immediately forever once the flow is closed (issue #89 / pr #90)
            guard let datagrams = datagrams, let endpoints = endpoints, !datagrams.isEmpty else {
                self.teardownUDP(clientFlow)
                return
            }

            association.lastActivity = Date()

            var toSend: [Data] = []
            toSend.reserveCapacity(datagrams.count)

            for i in 0..<min(datagrams.count, endpoints.count) {
                guard let nwHost = endpoints[i] as? NWHostEndpoint else { continue }
                let destHost = nwHost.hostname
                let destPort = UInt16(nwHost.port) ?? 0
                guard destPort != 0 else { continue }

                // log each distinct destination once, cap the set so it can't grow forever
                if !association.loggedDestinations.contains(destHost) {
                    if association.loggedDestinations.count < 64 {
                        association.loggedDestinations.insert(destHost)
                    }
                    self.sendLogToApp(protocol: "UDP", process: association.displayName, destination: destHost, port: nwHost.port, proxy: "SOCKS5 \(association.socksHost):\(association.socksPort)", status: "CONNECTED", details: "Relaying datagrams", ruleContext: association.ruleContext)
                    self.log("[\(association.displayName)] [UDP] [\(destHost):\(nwHost.port)] [SOCKS5 \(association.socksHost):\(association.socksPort)] Relaying datagrams")
                }

                if let encapsulated = self.encapsulateSOCKS5UDP(datagram: datagrams[i], destHost: destHost, destPort: destPort) {
                    toSend.append(encapsulated)
                } else {
                    self.sendLogToApp(protocol: "UDP", process: association.displayName, destination: destHost, port: nwHost.port, proxy: "SOCKS5 \(association.socksHost):\(association.socksPort)", status: "FAILED", details: "Could not encode datagram destination", ruleContext: association.ruleContext)
                }
            }

            if !toSend.isEmpty {
                association.udpSession.writeMultipleDatagrams(toSend) { [weak self] error in
                    if let error = error {
                        self?.log("[\(association.displayName)] [UDP] [SOCKS5 \(association.socksHost):\(association.socksPort)] UDP write to relay error: \(error.localizedDescription)", level: "ERROR")
                        self?.sendLogToApp(protocol: "UDP", process: association.displayName, destination: "*", port: "*", proxy: "SOCKS5 \(association.socksHost):\(association.socksPort)", status: self?.connectionStatus(for: error) ?? "FAILED", details: "Relay write error: \(error.localizedDescription)", ruleContext: association.ruleContext)
                    }
                }
            }

            self.readAndForwardClientUDP(association)
        }
    }

    private func readAndForwardRelayUDP(_ association: UDPAssociation) {
        let clientFlow = association.clientFlow
        association.udpSession.setReadHandler({ [weak self] datagrams, error in
            guard let self = self else { return }

            if let error = error {
                // stop reading the relay but don't close the app's flow, let it
                // time out on its own instead of getting a hard EPIPE
                self.log("[\(association.displayName)] [UDP] [SOCKS5 \(association.socksHost):\(association.socksPort)] UDP relay read error: \(error.localizedDescription)", level: "ERROR")
                self.sendLogToApp(protocol: "UDP", process: association.displayName, destination: "*", port: "*", proxy: "SOCKS5 \(association.socksHost):\(association.socksPort)", status: self.connectionStatus(for: error), details: "Relay read error: \(error.localizedDescription)", ruleContext: association.ruleContext)
                return
            }

            guard let datagrams = datagrams, !datagrams.isEmpty else { return }

            association.lastActivity = Date()

            var payloads: [Data] = []
            var endpoints: [NWEndpoint] = []
            payloads.reserveCapacity(datagrams.count)
            endpoints.reserveCapacity(datagrams.count)

            for datagram in datagrams {
                if let (payload, destHost, destPort) = self.decapsulateSOCKS5UDPWithEndpoint(datagram: datagram) {
                    payloads.append(payload)
                    endpoints.append(NWHostEndpoint(hostname: destHost, port: String(destPort)))
                }
            }

            if !payloads.isEmpty {
                clientFlow.writeDatagrams(payloads, sentBy: endpoints) { [weak self] error in
                    if let error = error {
                        self?.log("[\(association.displayName)] [UDP] [SOCKS5 \(association.socksHost):\(association.socksPort)] UDP client response write error: \(error.localizedDescription)", level: "ERROR")
                        self?.sendLogToApp(protocol: "UDP", process: association.displayName, destination: "*", port: "*", proxy: "SOCKS5 \(association.socksHost):\(association.socksPort)", status: self?.connectionStatus(for: error) ?? "FAILED", details: "Client response write error: \(error.localizedDescription)", ruleContext: association.ruleContext)
                    }
                }
            }
        }, maxDatagrams: 32)
    }
    
    private func encapsulateSOCKS5UDP(datagram: Data, destHost: String, destPort: UInt16) -> Data? {
        // a udp payload can be up to ~65507 bytes, don't drop mtu-sized quic
        // packets, let the network fragment if it must
        if datagram.count > 65507 {
            return nil
        }

        var header = Data()
        header.append(contentsOf: [0, 0])
        header.append(0x00)
        
        if let ipv4 = IPv4Address(destHost) {
            header.append(0x01)
            header.append(contentsOf: ipv4.rawValue)
        } else if let ipv6 = IPv6Address(destHost) {
            header.append(0x04)
            header.append(contentsOf: ipv6.rawValue)
        } else {
            // length prefix must be the utf8 byte count, not the character count
            let hostBytes = Array(destHost.utf8)
            guard hostBytes.count <= 255 else {
                self.log("Domain name too long: \(hostBytes.count) bytes", level: "ERROR")
                return nil
            }
            header.append(0x03)
            header.append(UInt8(hostBytes.count))
            header.append(contentsOf: hostBytes)
        }
        
        header.append(UInt8(destPort >> 8))
        header.append(UInt8(destPort & 0xFF))
        
        var result = header
        result.append(datagram)
        return result
    }
    
    private func decapsulateSOCKS5UDPWithEndpoint(datagram: Data) -> (Data, String, UInt16)? {
        guard datagram.count > 10 else { return nil }

        // byte 2 is FRAG, we don't reassemble so drop any fragmented datagram
        guard datagram[2] == 0x00 else { return nil }

        let atyp = datagram[3]
        var headerLen = 4
        var destHost = ""
        var destPort: UInt16 = 0

        if atyp == 0x01 {
            // ipv4 is 4 bytes + 2 port, already covered by count > 10
            destHost = "\(datagram[4]).\(datagram[5]).\(datagram[6]).\(datagram[7])"
            destPort = (UInt16(datagram[8]) << 8) | UInt16(datagram[9])
            headerLen += 6
        } else if atyp == 0x04 {
            // ipv6 needs 16 bytes + 2 port
            guard datagram.count >= 22 else { return nil }
            var ipv6Parts: [String] = []
            for i in 0..<8 {
                let idx = 4 + (i * 2)
                let part = (UInt16(datagram[idx]) << 8) | UInt16(datagram[idx+1])
                ipv6Parts.append(String(format: "%x", part))
            }
            destHost = ipv6Parts.joined(separator: ":")
            destPort = (UInt16(datagram[20]) << 8) | UInt16(datagram[21])
            headerLen += 18
        } else if atyp == 0x03 {
            // byte 4 is the domain length, then the domain, then 2 port bytes
            guard datagram.count >= 6 else { return nil }
            let domainLen = Int(datagram[4])
            guard datagram.count >= 5 + domainLen + 2 else { return nil }
            destHost = String(data: datagram[5..<(5+domainLen)], encoding: .utf8) ?? "unknown"
            destPort = (UInt16(datagram[5+domainLen]) << 8) | UInt16(datagram[5+domainLen+1])
            headerLen += 1 + domainLen + 2
        } else {
            return nil
        }

        guard datagram.count > headerLen else { return nil }

        let payload = datagram[headerLen...]
        return (Data(payload), destHost, destPort)
    }
    
    private func proxyTCPFlow(_ flow: NEAppProxyTCPFlow, displayName: String, destination: String, port: UInt16, logDest: String, config: StoredProxyConfig, ruleContext: RuleLogContext) {
        let label = proxyLabel(config)
        let proxyEndpoint = NWHostEndpoint(hostname: config.host, port: String(config.port))
        let proxyConnection = createTCPConnection(to: proxyEndpoint, enableTLS: false, tlsParameters: nil, delegate: nil)

        switch config.type.lowercased() {
        case "socks5":
            handleSOCKS5Proxy(clientFlow: flow, proxyConnection: proxyConnection, displayName: displayName, destination: destination, port: port, logDest: logDest, config: config, ruleContext: ruleContext)
        case "http":
            handleHTTPProxy(clientFlow: flow, proxyConnection: proxyConnection, displayName: displayName, destination: destination, port: port, logDest: logDest, config: config, ruleContext: ruleContext)
        default:
            log("[\(displayName)] [\(logDest):\(port)] [\(label)] Unsupported proxy type: \(config.type)", level: "ERROR")
            sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "FAILED", details: "Unsupported proxy type: \(config.type)", ruleContext: ruleContext)
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            proxyConnection.cancel()
        }
    }
    
    private func handleSOCKS5Proxy(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection, displayName: String, destination: String, port: UInt16, logDest: String, config: StoredProxyConfig, ruleContext: RuleLogContext) {
        let label = proxyLabel(config)
        var greeting: [UInt8]
        if config.username != nil && config.password != nil {
            greeting = [0x05, 0x02, 0x00, 0x02]
        } else {
            greeting = [0x05, 0x01, 0x00]
        }
        
        let greetingData = Data(greeting)
        proxyConnection.write(greetingData) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 greeting write failed: \(error.localizedDescription)", level: "ERROR")
                self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Greeting write failed: \(error.localizedDescription)", ruleContext: ruleContext)
                clientFlow.closeReadWithError(error)
                clientFlow.closeWriteWithError(error)
                proxyConnection.cancel()
                return
            }
            
            proxyConnection.readMinimumLength(2, maximumLength: 2) { [weak self] data, error in
                guard let self = self else { return }
                
                if let error = error {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 greeting response failed: \(error.localizedDescription)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Greeting read failed: \(error.localizedDescription)", ruleContext: ruleContext)
                    clientFlow.closeReadWithError(error)
                    clientFlow.closeWriteWithError(error)
                    proxyConnection.cancel()
                    return
                }
                
                guard let data = data, data.count == 2 else {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 invalid greeting response (\(data?.count ?? 0) bytes)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "FAILED", details: "Invalid greeting response", ruleContext: ruleContext)
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                    return
                }
                
                let version = data[0]
                let method = data[1]
                
                if version != 0x05 {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 invalid version: 0x\(String(format: "%02x", version))", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "FAILED", details: "Invalid version 0x\(String(format: "%02x", version))", ruleContext: ruleContext)
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                    return
                }
                
                if method == 0x00 {
                    self.sendSOCKS5ConnectRequest(clientFlow: clientFlow, proxyConnection: proxyConnection, displayName: displayName, destination: destination, port: port, logDest: logDest, label: label, ruleContext: ruleContext)
                } else if method == 0x02 {
                    self.sendSOCKS5Auth(clientFlow: clientFlow, proxyConnection: proxyConnection, displayName: displayName, destination: destination, port: port, logDest: logDest, label: label, username: config.username ?? "", password: config.password ?? "", ruleContext: ruleContext)
                } else {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 no acceptable auth method (method=0x\(String(format: "%02x", method)))", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "AUTH_FAILED", details: "No acceptable auth (0x\(String(format: "%02x", method)))", ruleContext: ruleContext)
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                }
            }
        }
    }
    
    private func sendSOCKS5Auth(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection, displayName: String, destination: String, port: UInt16, logDest: String, label: String, username: String, password: String, ruleContext: RuleLogContext) {
        var authData = Data()
        authData.append(0x01)
        authData.append(UInt8(username.count))
        authData.append(username.data(using: .utf8) ?? Data())
        authData.append(UInt8(password.count))
        authData.append(password.data(using: .utf8) ?? Data())
        
        proxyConnection.write(authData) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 auth write failed: \(error.localizedDescription)", level: "ERROR")
                self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Auth write failed: \(error.localizedDescription)", ruleContext: ruleContext)
                clientFlow.closeReadWithError(error)
                clientFlow.closeWriteWithError(error)
                proxyConnection.cancel()
                return
            }
            
            proxyConnection.readMinimumLength(2, maximumLength: 2) { [weak self] data, error in
                guard let self = self else { return }
                
                if let error = error {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 auth response read failed: \(error.localizedDescription)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Auth read error: \(error.localizedDescription)", ruleContext: ruleContext)
                    clientFlow.closeReadWithError(error)
                    clientFlow.closeWriteWithError(error)
                    proxyConnection.cancel()
                    return
                }
                
                guard let data = data, data.count == 2, data[1] == 0x00 else {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 auth rejected by proxy", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "AUTH_FAILED", details: "Auth rejected", ruleContext: ruleContext)
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                    return
                }
                
                self.sendSOCKS5ConnectRequest(clientFlow: clientFlow, proxyConnection: proxyConnection, displayName: displayName, destination: destination, port: port, logDest: logDest, label: label, ruleContext: ruleContext)
            }
        }
    }
    
    private func sendSOCKS5ConnectRequest(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection, displayName: String, destination: String, port: UInt16, logDest: String, label: String, ruleContext: RuleLogContext) {
        var request = Data()
        request.append(0x05)
        request.append(0x01)
        request.append(0x00)
        
        if let ipAddr = IPv4Address(destination) {
            request.append(0x01)
            request.append(contentsOf: ipAddr.rawValue)
        } else if let ipAddr = IPv6Address(destination) {
            request.append(0x04)
            request.append(contentsOf: ipAddr.rawValue)
        } else {
            request.append(0x03)
            request.append(UInt8(destination.count))
            request.append(destination.data(using: .utf8) ?? Data())
        }
        
        request.append(UInt8(port >> 8))
        request.append(UInt8(port & 0xFF))
        
        proxyConnection.write(request) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 connect write failed: \(error.localizedDescription)", level: "ERROR")
                self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Connect write failed: \(error.localizedDescription)", ruleContext: ruleContext)
                clientFlow.closeReadWithError(error)
                clientFlow.closeWriteWithError(error)
                proxyConnection.cancel()
                return
            }
            
            proxyConnection.readMinimumLength(10, maximumLength: 512) { [weak self] data, error in
                guard let self = self else { return }
                
                if let error = error {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 connect response read failed: \(error.localizedDescription)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Connect read error: \(error.localizedDescription)", ruleContext: ruleContext)
                    clientFlow.closeReadWithError(error)
                    clientFlow.closeWriteWithError(error)
                    proxyConnection.cancel()
                    return
                }
                
                guard let data = data, data.count >= 2, data[0] == 0x05 else {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 connect invalid reply (\(data?.count ?? 0) bytes)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "FAILED", details: "Invalid connect reply", ruleContext: ruleContext)
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                    return
                }
                
                let rep = data[1]
                guard rep == 0x00, data.count >= 10 else {
                    let reason = self.socksReplyReason(rep)
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 connect rejected: 0x\(String(format: "%02x", rep)) (\(reason))", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.socksReplyStatus(rep), details: "REP=0x\(String(format: "%02x", rep)) (\(reason))", ruleContext: ruleContext)
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                    return
                }
                
                self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 tunnel established")
                self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "CONNECTED", details: "Tunnel established", ruleContext: ruleContext)
                self.relayData(clientFlow: clientFlow, proxyConnection: proxyConnection, displayName: displayName, destination: logDest, port: port, proxyLabel: label, ruleContext: ruleContext)
            }
        }
    }
    
    private func handleHTTPProxy(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection, displayName: String, destination: String, port: UInt16, logDest: String, config: StoredProxyConfig, ruleContext: RuleLogContext) {
        let label = proxyLabel(config)
        let host = IPv6Address(destination) != nil ? "[\(destination)]" : destination
        var request = "CONNECT \(host):\(port) HTTP/1.1\r\n"
        request += "Host: \(host):\(port)\r\n"
        
        if let username = config.username, let password = config.password {
            let credentials = "\(username):\(password)"
            if let credData = credentials.data(using: .utf8) {
                let base64Creds = credData.base64EncodedString()
                request += "Proxy-Authorization: Basic \(base64Creds)\r\n"
            }
        }
        
        request += "\r\n"
        
        guard let requestData = request.data(using: .utf8) else {
            log("[\(displayName)] [\(logDest):\(port)] [\(label)] HTTP CONNECT request encoding failed", level: "ERROR")
            sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "FAILED", details: "Encoding failed", ruleContext: ruleContext)
            clientFlow.closeReadWithError(nil)
            clientFlow.closeWriteWithError(nil)
            proxyConnection.cancel()
            return
        }
        
        proxyConnection.write(requestData) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] HTTP CONNECT write failed: \(error.localizedDescription)", level: "ERROR")
                self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Write failed: \(error.localizedDescription)", ruleContext: ruleContext)
                clientFlow.closeReadWithError(error)
                clientFlow.closeWriteWithError(error)
                proxyConnection.cancel()
                return
            }
            
            proxyConnection.readMinimumLength(1, maximumLength: 8192) { [weak self] data, error in
                guard let self = self else { return }
                
                if let error = error {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] HTTP CONNECT response read failed: \(error.localizedDescription)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Read response failed: \(error.localizedDescription)", ruleContext: ruleContext)
                    clientFlow.closeReadWithError(error)
                    clientFlow.closeWriteWithError(error)
                    proxyConnection.cancel()
                    return
                }
                
                guard let data = data,
                      let response = String(data: data, encoding: .utf8) else {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] HTTP CONNECT invalid response", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "FAILED", details: "Invalid proxy response", ruleContext: ruleContext)
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                    return
                }
                
                let firstLine = response.components(separatedBy: "\r\n").first ?? response
                if response.contains("200") {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] HTTP tunnel established (200 OK)")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "CONNECTED", details: "Tunnel established (200 OK)", ruleContext: ruleContext)
                    self.relayData(clientFlow: clientFlow, proxyConnection: proxyConnection, displayName: displayName, destination: logDest, port: port, proxyLabel: label, ruleContext: ruleContext)
                } else {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] HTTP CONNECT rejected: \(firstLine)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.httpConnectFailureStatus(firstLine), details: firstLine, ruleContext: ruleContext)
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                }
            }
        }
    }
    
    private final class TCPRelayContext {
        let clientFlow: NEAppProxyTCPFlow
        let proxyConnection: NWTCPConnection
        private var isClosed = false
        private let lock = NSLock()
        private var timeoutItem: DispatchWorkItem?

        init(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection) {
            self.clientFlow = clientFlow
            self.proxyConnection = proxyConnection
        }

        func close() {
            lock.lock()
            defer { lock.unlock() }
            guard !isClosed else { return }
            isClosed = true
            timeoutItem?.cancel()
            timeoutItem = nil
            clientFlow.closeReadWithError(nil)
            clientFlow.closeWriteWithError(nil)
            proxyConnection.cancel()
        }

        func onClientEOF() {
            clientFlow.closeReadWithError(nil)
            lock.lock()
            guard !isClosed else { lock.unlock(); return }
            // If proxy doesn't complete the response within 45s, cleanly close both sides
            let item = DispatchWorkItem { [weak self] in
                self?.close()
            }
            timeoutItem = item
            lock.unlock()
            DispatchQueue.global().asyncAfter(deadline: .now() + 45.0, execute: item)
        }
    }

    private func relayData(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection, displayName: String, destination: String, port: UInt16, proxyLabel: String, ruleContext: RuleLogContext) {
        clientFlow.open(withLocalEndpoint: nil) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.log("[\(displayName)] [\(destination):\(port)] Failed to open client flow: \(error.localizedDescription)", level: "ERROR")
                self.sendLogToApp(protocol: "TCP", process: displayName, destination: destination, port: String(port), proxy: proxyLabel, status: self.connectionStatus(for: error), details: "Flow open error: \(error.localizedDescription)", ruleContext: ruleContext)
                clientFlow.closeReadWithError(error)
                clientFlow.closeWriteWithError(error)
                proxyConnection.cancel()
                return
            }
            
            let context = TCPRelayContext(clientFlow: clientFlow, proxyConnection: proxyConnection)
            self.relayClientToProxy(context: context, displayName: displayName, destination: destination, port: port, proxyLabel: proxyLabel, ruleContext: ruleContext)
            self.relayProxyToClient(context: context, displayName: displayName, destination: destination, port: port, proxyLabel: proxyLabel, ruleContext: ruleContext)
        }
    }
    
    private func relayClientToProxy(context: TCPRelayContext, displayName: String, destination: String, port: UInt16, proxyLabel: String, ruleContext: RuleLogContext) {
        context.clientFlow.readData { [weak self] data, error in
            guard let self = self else { return }
            if let error = error {
                let code = (error as NSError).code
                if code != 57 && code != 54 && code != 89 {
                    self.log("[\(displayName)] [\(destination):\(port)] [\(proxyLabel)] Client read error: \(error.localizedDescription)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: destination, port: String(port), proxy: proxyLabel, status: self.connectionStatus(for: error), details: "Client read error: \(error.localizedDescription)", ruleContext: ruleContext)
                }
                context.close()
                return
            }
            
            guard let data = data, !data.isEmpty else {
                // Client reached EOF (finished sending request), allow proxy to finish response up to 45s
                context.onClientEOF()
                return
            }
            
            context.proxyConnection.write(data) { [weak self] error in
                guard let self = self else { return }
                if let error = error {
                    self.log("[\(displayName)] [\(destination):\(port)] [\(proxyLabel)] Proxy write error: \(error.localizedDescription)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: destination, port: String(port), proxy: proxyLabel, status: self.connectionStatus(for: error), details: "Proxy write error: \(error.localizedDescription)", ruleContext: ruleContext)
                    context.close()
                } else {
                    self.relayClientToProxy(context: context, displayName: displayName, destination: destination, port: port, proxyLabel: proxyLabel, ruleContext: ruleContext)
                }
            }
        }
    }
    
    private func relayProxyToClient(context: TCPRelayContext, displayName: String, destination: String, port: UInt16, proxyLabel: String, ruleContext: RuleLogContext) {
        context.proxyConnection.readMinimumLength(1, maximumLength: 65536) { [weak self] data, error in
            guard let self = self else { return }
            if let error = error {
                let code = (error as NSError).code
                if code != 57 && code != 54 && code != 89 {
                    self.log("[\(displayName)] [\(destination):\(port)] [\(proxyLabel)] Proxy read error: \(error.localizedDescription)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: destination, port: String(port), proxy: proxyLabel, status: self.connectionStatus(for: error), details: "Proxy read error: \(error.localizedDescription)", ruleContext: ruleContext)
                }
                context.close()
                return
            }
            
            guard let data = data, !data.isEmpty else {
                context.close()
                return
            }
            
            context.clientFlow.write(data) { [weak self] error in
                guard let self = self else { return }
                if let error = error {
                    let status = self.connectionStatus(for: error)
                    let isExpectedClose = status == "CLOSED" || status == "CANCELLED"
                    let summary = status == "CANCELLED" ? "Client flow cancelled" : (status == "CLOSED" ? "Client flow closed" : "Client write error")
                    self.log("[\(displayName)] [\(destination):\(port)] [\(proxyLabel)] \(summary): \(error.localizedDescription)", level: isExpectedClose ? "INFO" : "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: destination, port: String(port), proxy: proxyLabel, status: status, details: "\(summary): \(error.localizedDescription)", ruleContext: ruleContext)
                    context.close()
                } else {
                    self.relayProxyToClient(context: context, displayName: displayName, destination: destination, port: port, proxyLabel: proxyLabel, ruleContext: ruleContext)
                }
            }
        }
    }
    
    private func findMatchingRule(bundleId: String, processName: String?, executablePath: String?, destination: String, port: UInt16, connectionProtocol: RuleProtocol, checkIpPort: Bool, domains: [String] = []) -> MatchedRule? {
        rulesLock.lock()
        let currentRules = rules
        rulesLock.unlock()

        for rule in currentRules {
            guard rule.enabled else { continue }

            if rule.ruleProtocol != .both && rule.ruleProtocol != connectionProtocol {
                continue
            }

            let isWildcardProcess = (rule.processNames == "*" || rule.processNames.isEmpty)

            if isWildcardProcess {
                let hasIpFilter = (rule.targetHosts != "*" && !rule.targetHosts.isEmpty)
                let hasPortFilter = (rule.targetPorts != "*" && !rule.targetPorts.isEmpty)

                if checkIpPort {
                    if rule.matchesHost(ip: destination, domains: domains), rule.matchesPort(port) {
                        return MatchedRule(rule: rule, processMatch: .any)
                    }
                } else if !hasIpFilter && !hasPortFilter {
                    // UDP has no destination here. Only a pure wildcard can
                    // match; filtered wildcard rules remain TCP-only.
                    return MatchedRule(rule: rule, processMatch: .any)
                }
                continue
            }

            if let processMatch = rule.matchProcess(bundleId: bundleId, processName: processName, executablePath: executablePath) {
                if checkIpPort {
                    if rule.matchesHost(ip: destination, domains: domains) && rule.matchesPort(port) {
                        return MatchedRule(rule: rule, processMatch: processMatch)
                    }
                } else {
                    // udp matches on process alone
                    return MatchedRule(rule: rule, processMatch: processMatch)
                }
            }
        }

        return nil
    }
    
    private func sendLogToApp(protocol: String, process: String, destination: String, port: String, proxy: String, status: String = "", details: String = "", ruleContext: RuleLogContext = .defaultMatch) {
        guard trafficLoggingEnabled else { return }
        appendLog(.connection(proto: `protocol`, process: process, destination: destination, port: port, proxy: proxy, status: status, details: details, rule: ruleContext))
    }
}
