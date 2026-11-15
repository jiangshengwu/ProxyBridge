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
            if pattern.isEmpty { continue }
            if pattern.lowercased().hasSuffix(".app") && !pattern.contains("/") {
                // App rules are exact names, not globs. Match any containing
                // app bundle so both the main executable and nested helpers
                // belong to Antigravity.app, for example.
                guard !pattern.contains("*") else { continue }
                if appBundleNames.contains(where: { $0.caseInsensitiveCompare(pattern) == .orderedSame }) {
                    return .app(pattern)
                }
                continue
            }

            if let executablePath, Self.matchProcessPattern(pattern, processPath: executablePath, filename: (executablePath as NSString).lastPathComponent) {
                return pattern == "*" ? .any : .process(pattern)
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
        return globMatch(Array(pattern), Array(text))
    }

    fileprivate static func globMatch(_ p: [Character], _ t: [Character]) -> Bool {
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

    fileprivate static func matchIPPattern(_ pattern: String, ipString: String) -> Bool {
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

// Pre-parsed form of a rule. Rules are matched on every new flow, so the string
// splitting, lowercasing and number parsing happens once when the rule is added
// instead of once per rule per connection.
extension ProxyRule {
    // lowercased forms of the flow's process, built once per flow
    struct FlowProcess {
        let candidates: [(path: [Character], file: [Character])]

        // the names a rule can match: the bundle identifier, and the program itself. when the full path of
        // the program is known a rule written with a path (/opt/tool/bin/worker, /Applications/Foo.app/*)
        // is compared with it, and a rule written with a file name with its last part. without the path
        // only the file name is known and a rule with a path cannot match (issue #288).
        init(bundleId: String, processName: String?, executablePath: String? = nil) {
            var list = [bundleId]
            if let executablePath = executablePath {
                list.append(executablePath)
            } else if let processName = processName {
                list.append(processName)
            }
            candidates = list.map {
                (Array($0.lowercased()), Array((($0 as NSString).lastPathComponent).lowercased()))
            }
        }
    }

    struct Matcher {
        let processAll: Bool
        let processPatterns: [(chars: [Character], fullPath: Bool)]
        let hostAll: Bool
        let hostPatterns: [(raw: String, glob: [Character], apex: String?)]
        let portAll: Bool
        let portRanges: [ClosedRange<UInt16>]

        init(_ rule: ProxyRule) {
            func isAll(_ s: String) -> Bool { s.isEmpty || s == "*" }

            // empty segments are skipped, "Safari;" used to match every process
            // because the empty pattern after the ; counted as a wildcard
            var all = isAll(rule.processNames)
            var procs: [(chars: [Character], fullPath: Bool)] = []
            if !all {
                for raw in rule.processNames.components(separatedBy: CharacterSet(charactersIn: ",;")) {
                    let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                    if t.isEmpty { continue }
                    if t == "*" { all = true; break }
                    procs.append((Array(t.lowercased()), t.contains("/") || t.contains("\\")))
                }
            }
            processAll = all
            processPatterns = procs

            var hostsAll = isAll(rule.targetHosts)
            var hosts: [(raw: String, glob: [Character], apex: String?)] = []
            if !hostsAll {
                for raw in rule.targetHosts.components(separatedBy: ";") {
                    let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                    if t.isEmpty { continue }
                    if t == "*" { hostsAll = true; break }
                    let lowered = t.lowercased()
                    let apex = lowered.hasPrefix("*.") ? String(lowered.dropFirst(2)) : nil
                    hosts.append((t, Array(lowered), apex))
                }
            }
            hostAll = hostsAll
            hostPatterns = hosts

            var portsAll = isAll(rule.targetPorts)
            var ranges: [ClosedRange<UInt16>] = []
            if !portsAll {
                for raw in rule.targetPorts.components(separatedBy: CharacterSet(charactersIn: ",;")) {
                    let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                    if t.isEmpty { continue }
                    if t == "*" { portsAll = true; break }
                    if let dash = t.firstIndex(of: "-") {
                        if let lo = UInt16(t[..<dash]), let hi = UInt16(t[t.index(after: dash)...]), lo <= hi {
                            ranges.append(lo...hi)
                        }
                    } else if let p = UInt16(t) {
                        ranges.append(p...p)
                    }
                }
            }
            portAll = portsAll
            portRanges = ranges
        }

        var hasHostFilter: Bool { !hostAll }
        var hasPortFilter: Bool { !portAll }

        func matchesProcess(_ flow: FlowProcess) -> Bool {
            if processAll { return true }
            for cand in flow.candidates {
                for p in processPatterns {
                    if ProxyRule.globMatch(p.chars, p.fullPath ? cand.path : cand.file) { return true }
                }
            }
            return false
        }

        func matchesHost(ip: String, domains: [(name: String, chars: [Character])]) -> Bool {
            if hostAll { return true }
            for p in hostPatterns {
                if ProxyRule.matchIPPattern(p.raw, ipString: ip) { return true }
                for d in domains {
                    if ProxyRule.globMatch(p.glob, d.chars) { return true }
                    if let apex = p.apex, d.name == apex { return true }
                }
            }
            return false
        }

        func matchesPort(_ port: UInt16) -> Bool {
            if portAll { return true }
            for r in portRanges where r.contains(port) { return true }
            return false
        }
    }
}

extension ProxyRule {
    static func firstMatch(in currentRules: [(rule: ProxyRule, matcher: Matcher)], bundleId: String, processName: String?, executablePath: String?, destination: String, port: UInt16, connectionProtocol: RuleProtocol, checkIpPort: Bool, domains: [String] = []) -> MatchedRule? {
        if currentRules.isEmpty { return nil }

        let domainChars = domains.map { (name: $0, chars: Array($0)) }

        for (rule, m) in currentRules {
            guard rule.enabled else { continue }

            if rule.ruleProtocol != .both && rule.ruleProtocol != connectionProtocol {
                continue
            }

            let isWildcardProcess = m.processAll

            if isWildcardProcess {
                let hasIpFilter = m.hasHostFilter
                let hasPortFilter = m.hasPortFilter

                if checkIpPort {
                    if m.matchesHost(ip: destination, domains: domainChars), m.matchesPort(port) {
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
                    if m.matchesHost(ip: destination, domains: domainChars) && m.matchesPort(port) {
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

    // cache by pid + pid version so we don't call proc_pidpath on every
    // connection. the version changes when a pid is reused, so a new process
    // never inherits the previous owner's name
    private struct ProcessIdentity {
        let name: String   // file name of the executable, what the logs show
        let path: String   // full path of the executable, what a rule with a path is compared with
    }
    private var pidCache: [UInt64: ProcessIdentity] = [:]
    private let pidCacheLock = NSLock()
    private static let pidCacheMaxSize = 256

    private func getProcessIdentity(from metaData: NEFlowMetaData) -> ProcessIdentity? {
        guard let auditTokenData = metaData.sourceAppAuditToken else {
            return nil
        }
        guard auditTokenData.count == MemoryLayout<audit_token_t>.size else {
            return nil
        }

        let (pid, pidVersion) = auditTokenData.withUnsafeBytes { ptr -> (pid_t, UInt32) in
            guard let baseAddress = ptr.baseAddress else { return (0, 0) }
            let token = baseAddress.assumingMemoryBound(to: UInt32.self)
            return (pid_t(token[5]), token[7])
        }

        guard pid > 0 else { return nil }
        let key = (UInt64(UInt32(pid)) << 32) | UInt64(pidVersion)

        pidCacheLock.lock()
        if let cached = pidCache[key] {
            pidCacheLock.unlock()
            return cached
        }
        pidCacheLock.unlock()

        var pathBuffer = [Int8](repeating: 0, count: Int(MAXPATHLEN))
        guard proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN)) > 0 else {
            return nil
        }

        let fullPath = String(cString: pathBuffer)
        let identity = ProcessIdentity(name: (fullPath as NSString).lastPathComponent, path: fullPath)

        // store in cache, evict everything if full - processes rarely hit this
        pidCacheLock.lock()
        if pidCache.count >= AppProxyProvider.pidCacheMaxSize {
            pidCache.removeAll(keepingCapacity: true)
        }
        pidCache[key] = identity
        pidCacheLock.unlock()

        return identity
    }

    private func getProcessPath(from metaData: NEFlowMetaData) -> String? {
        getProcessIdentity(from: metaData)?.path
    }

    // guarded by its own lock, the old OSAtomic compare-and-swap setter could
    // silently no-op if the stored value wasn't the exact expected one
    private var _trafficLoggingEnabled = true
    private let trafficLoggingLock = NSLock()
    private var trafficLoggingEnabled: Bool {
        get { trafficLoggingLock.lock(); defer { trafficLoggingLock.unlock() }; return _trafficLoggingEnabled }
        set { trafficLoggingLock.lock(); _trafficLoggingEnabled = newValue; trafficLoggingLock.unlock() }
    }

    private typealias CompiledRule = (rule: ProxyRule, matcher: ProxyRule.Matcher)
    private var rules: [CompiledRule] = []
    private let rulesLock = NSLock()
    private var nextRuleId: UInt32 = 1

    private struct StoredProxyConfig {
        let type: String
        let host: String
        let port: Int
        let username: String?
        let password: String?
        let sendDomain: Bool   // hand the proxy the host name instead of the ip when it is known
    }
    private var storedProxyConfigs: [String: StoredProxyConfig] = [:]
    private let proxyLock = NSLock()
    // problems that would repeat on every connection are reported once per proxy list
    private var warnedKeys = Set<String>()

    private func warnOnce(_ key: String, _ message: String) {
        proxyLock.lock()
        let isNew = warnedKeys.insert(key).inserted
        proxyLock.unlock()
        if isNew { log(message, level: "ERROR") }
    }

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

    // the extension's own life cycle: to the unified log, which survives the extension, and to the
    // activity log, which the app shows while it is connected
    private func diag(_ message: String, level: String = "INFO") {
        ProviderDiagnostics.note(message, error: level == "ERROR")
        log(message, level: level, scope: .system)
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
                password: configDict["proxyPassword"] as? String,
                sendDomain: configDict["sendDomainToProxy"] as? Bool ?? false
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
            rules.append((rule, ProxyRule.Matcher(rule)))
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
            guard let self else { return }
            self.rulesLock.lock()
            self.rules.removeAll()
            self.nextRuleId = 1
            self.rulesLock.unlock()
        }
        if let ipcAuthToken = initialDict["ipcAuthToken"] as? String {
            LocalIPCServer.shared.start(authorizationToken: ipcAuthToken)
        } else {
            log("Local IPC disabled: missing startup authorization token", level: "ERROR", scope: .system)
        }


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

        startUDPSweepTimer()
        diag("Tunnel starting")

        self.setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                self?.diag("Could not apply the tunnel network settings: \(error.localizedDescription)", level: "ERROR")
            } else {
                self?.diag("Tunnel started")
            }
            completionHandler(error)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        diag("Tunnel stopping: \(ProviderDiagnostics.text(for: reason))")
        udpSweepTimer?.cancel()
        udpSweepTimer = nil
        sweepHandshakes(all: true)
        LocalIPCServer.shared.stop()
        udpLock.lock()
        let all = Array(udpAssociations.values)
        udpAssociations.removeAll()
        udpLock.unlock()
        for a in all {
            a.release()
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
        private var lastActivity = Date()
        private let activityLock = NSLock()

        // per-packet work is the hot path for quic/video, so the socks5 header for
        // a destination and the endpoint for a relay source are built once and
        // reused. both are capped so they can't grow forever.
        struct HostPort: Hashable { let host: String; let port: UInt16 }
        var headerCache: [HostPort: Data] = [:]
        var endpointCache: [UInt64: (host: String, port: UInt16)] = [:]
        static let cacheLimit = 64

        func touch() {
            activityLock.lock(); lastActivity = Date(); activityLock.unlock()
        }

        func idleTime() -> TimeInterval {
            activityLock.lock(); defer { activityLock.unlock() }
            return Date().timeIntervalSince(lastActivity)
        }

        // NWUDPSession keeps its read handler after cancel(), and that handler
        // refers back to this association, so the whole graph (association,
        // session, tcp control connection, flow) used to stay alive after every
        // udp flow. swap the handler out first, then cancel.
        func release() {
            udpSession.setReadHandler({ _, _ in }, maxDatagrams: 1)
            controlConnection.cancel()
            udpSession.cancel()
        }

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

    // udp has no close signal we can rely on (quic flows come and go), so idle
    // associations are reaped here, otherwise each one pins a flow, a tcp
    // control connection and a udp session for the life of the extension
    private static let udpIdleTimeout: TimeInterval = 120
    private var udpSweepTimer: DispatchSourceTimer?

    private func startUDPSweepTimer() {
        udpSweepTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 5, repeating: 5, leeway: .seconds(1))
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            self.sweepHandshakes()
            self.udpLock.lock()
            let stale = self.udpAssociations.filter { $0.value.idleTime() > AppProxyProvider.udpIdleTimeout }.map { $0.key }
            self.udpLock.unlock()
            for flow in stale { self.teardownUDP(flow) }
        }
        timer.resume()
        udpSweepTimer = timer
    }

    // tcp and udp proxy handshakes have no timeout of their own, so a proxy that
    // accepts the connection and then goes quiet would pin the flow forever.
    // entries are checked by the shared sweep timer, no per-flow timer is
    // scheduled (a timer closure would hold the flow for its full delay even
    // after the handshake succeeded, which adds up with quic churn)
    private struct HandshakeLog {
        let proto: String, process: String, destination: String, port: String, proxy: String
        let rule: RuleLogContext
    }
    private var pendingHandshakes: [ObjectIdentifier: (deadline: Date, flow: NEAppProxyFlow, connection: NWTCPConnection, log: HandshakeLog?)] = [:]
    private let handshakeLock = NSLock()
    private static let handshakeTimeout: TimeInterval = 20
    // grace between a client FIN and tearing the relay down, lets the upstream FIN flush
    private static let halfCloseTimeout: TimeInterval = 3

    private func armHandshakeTimeout(flow: NEAppProxyFlow, connection: NWTCPConnection, log: HandshakeLog? = nil) {
        let deadline = Date().addingTimeInterval(AppProxyProvider.handshakeTimeout)
        handshakeLock.lock()
        pendingHandshakes[ObjectIdentifier(connection)] = (deadline, flow, connection, log)
        handshakeLock.unlock()
    }

    // false means the sweep already timed it out and tore everything down
    private func completeHandshake(_ connection: NWTCPConnection) -> Bool {
        handshakeLock.lock()
        defer { handshakeLock.unlock() }
        return pendingHandshakes.removeValue(forKey: ObjectIdentifier(connection)) != nil
    }

    private func sweepHandshakes(now: Date = Date(), all: Bool = false) {
        handshakeLock.lock()
        let expired = pendingHandshakes.filter { all || $0.value.deadline <= now }
        for key in expired.keys { pendingHandshakes.removeValue(forKey: key) }
        handshakeLock.unlock()
        for (_, entry) in expired {
            if let info = entry.log {
                sendLogToApp(protocol: info.proto, process: info.process, destination: info.destination, port: info.port, proxy: info.proxy, status: all ? "CANCELLED" : "TIMEOUT", details: all ? "Tunnel stopped" : "Proxy handshake timed out", ruleContext: info.rule)
            }
            entry.connection.cancel()
            // a tcp flow must fail its connect (see FlowFailure), udp flows keep the clean close
            let reason: Error? = entry.flow is NEAppProxyTCPFlow ? FlowFailure.timedOut : nil
            entry.flow.closeReadWithError(reason)
            entry.flow.closeWriteWithError(reason)
        }
    }

    private func closeRelay(_ flow: NEAppProxyTCPFlow, _ connection: NWTCPConnection, error: Error? = nil) {
        _ = completeHandshake(connection)
        connection.cancel()
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
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
                rules.append((rule, ProxyRule.Matcher(rule)))
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

        case "setRules":
            // replace the whole rule list in one step. the old way was clearRules
            // followed by one addRule per rule, and any connection that arrived
            // in between was matched against a half-built list (so it went direct)
            guard let raw = message["rules"] as? [[String: Any]] else {
                completionHandler?(try? JSONSerialization.data(withJSONObject: ["status": "error", "message": "Invalid rules payload"]))
                return
            }
            var built: [CompiledRule] = []
            built.reserveCapacity(raw.count)
            for dict in raw {
                guard let ruleData = try? JSONSerialization.data(withJSONObject: dict),
                      let rule = try? JSONDecoder().decode(ProxyRule.self, from: ruleData) else { continue }
                built.append((rule, ProxyRule.Matcher(rule)))
            }
            rulesLock.lock()
            rules = built.map { item in
                var rule = item.rule
                rule.ruleId = nextRuleId
                nextRuleId += 1
                return (rule, item.matcher)
            }
            rulesLock.unlock()
            let response: [String: Any] = ["status": "ok", "count": built.count, "skipped": raw.count - built.count]
            completionHandler?(try? JSONSerialization.data(withJSONObject: response))

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
            warnedKeys.removeAll()
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

        if LocalIPCServer.isListenerEndpoint(host: destination, port: portNum) {
            return false
        }

        let executablePath = getProcessPath(from: metaData)
        let processName = executablePath.map { ($0 as NSString).lastPathComponent }
        let displayName = processName ?? signingIdentifier

        // domains that resolved to this ip (from the dns proxy), used for domain
        // rules and to show the hostname in the log instead of the raw ip
        let domains = DNSMapStore.shared.domains(forIP: destination)
        let logDest = domains.first ?? destination

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

        // rules first: udp BLOCK and DIRECT need no proxy at all. only a rule that
        // sends udp through a proxy needs a socks5 one (http proxies can't carry udp)
        proxyLock.lock()
        let hasAnySocks5 = storedProxyConfigs.values.contains { $0.type.lowercased() == "socks5" }
        proxyLock.unlock()

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
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
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
    private func failUDPHandshake(_ clientFlow: NEAppProxyUDPFlow, _ tcpConnection: NWTCPConnection, displayName: String, socksEndpoint: String, _ reason: String, status: String = "FAILED", ruleContext: RuleLogContext = .defaultMatch) {
        log("[\(displayName)] [UDP] [\(socksEndpoint)] \(reason)", level: "ERROR")
        sendLogToApp(protocol: "UDP", process: displayName, destination: "*", port: "*", proxy: "SOCKS5 \(socksEndpoint)", status: status, details: reason, ruleContext: ruleContext)
        _ = completeHandshake(tcpConnection)
        tcpConnection.cancel()
        clientFlow.closeReadWithError(nil)
        clientFlow.closeWriteWithError(nil)
    }

    private func proxyUDPFlowViaSOCKS5(_ clientFlow: NEAppProxyUDPFlow, displayName: String, socksHost: String, socksPort: Int, username: String?, password: String?, ruleContext: RuleLogContext) {
        let socksEndpoint = "\(socksHost):\(socksPort)"
        let proxyEndpoint = NWHostEndpoint(hostname: socksHost, port: String(socksPort))
        let tcpConnection = createTCPConnection(to: proxyEndpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
        armHandshakeTimeout(flow: clientFlow, connection: tcpConnection, log: HandshakeLog(proto: "UDP", process: displayName, destination: "*", port: "*", proxy: "SOCKS5 \(socksEndpoint)", rule: ruleContext))

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

            self.readSOCKS5Reply(tcpConnection) { [weak self] reply in
                guard let self = self else { return }

                switch reply {
                case .failed(let reason):
                    self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP ASSOCIATE failed: \(reason)", ruleContext: ruleContext)
                case .rejected(let rep):
                    self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP ASSOCIATE rejected, REP=0x\(String(format: "%02x", rep)) (\(self.socksReplyReason(rep)))", ruleContext: ruleContext)
                case .success(let data):
                    let (parsedHost, relayPort) = self.parseSOCKS5Address(from: data, offset: 3)
                    // many socks servers reply 0.0.0.0 meaning "reuse the control connection host"
                    let relayHost = (parsedHost == "0.0.0.0" || parsedHost == "::" || parsedHost.isEmpty) ? socksHost : parsedHost
                    guard relayPort != 0 else {
                        self.failUDPHandshake(clientFlow, tcpConnection, displayName: displayName, socksEndpoint: socksEndpoint, "SOCKS5 UDP ASSOCIATE returned no relay port", ruleContext: ruleContext)
                        return
                    }
                    self.relayUDPThroughSOCKS5(clientFlow: clientFlow, relayHost: relayHost, relayPort: relayPort, tcpConnection: tcpConnection, displayName: displayName, socksHost: socksHost, socksPort: socksPort, ruleContext: ruleContext)
                }
            }
        }
    }

    private enum SOCKS5Reply {
        case success(Data)       // the whole reply, VER REP RSV ATYP BND.ADDR BND.PORT
        case rejected(UInt8)     // REP != 0
        case failed(String)
    }

    // reads exactly n bytes, never more, so nothing the server sends after what we
    // asked for (a banner from a server-first protocol) is consumed here
    private func readExact(_ connection: NWTCPConnection, _ n: Int, completion: @escaping (Data?, Error?) -> Void) {
        connection.readMinimumLength(n, maximumLength: n) { data, error in
            if let error = error { completion(nil, error); return }
            guard let data = data, data.count == n else { completion(nil, nil); return }
            completion(data, nil)
        }
    }

    // reads one SOCKS5 reply. the length depends on the address type (10 bytes for
    // ipv4, 22 for ipv6, variable for a domain), reading a fixed 10 used to leave
    // part of an ipv6/domain reply in the client's data and could swallow the
    // first bytes the real server sent
    private func readSOCKS5Reply(_ connection: NWTCPConnection, completion: @escaping (SOCKS5Reply) -> Void) {
        readExact(connection, 4) { [weak self] header, error in
            guard let self = self else { return }
            if let error = error { completion(.failed(error.localizedDescription)); return }
            guard let header = header, header[0] == 0x05 else { completion(.failed("invalid reply")); return }
            guard header[1] == 0x00 else { completion(.rejected(header[1])); return }

            func finish(_ rest: Data?, _ error: Error?, prefix: Data) {
                if let error = error { completion(.failed(error.localizedDescription)); return }
                guard let rest = rest else { completion(.failed("short reply")); return }
                completion(.success(prefix + rest))
            }

            switch header[3] {
            case 0x01:
                self.readExact(connection, 6) { rest, error in finish(rest, error, prefix: header) }
            case 0x04:
                self.readExact(connection, 18) { rest, error in finish(rest, error, prefix: header) }
            case 0x03:
                self.readExact(connection, 1) { lenByte, error in
                    guard let lenByte = lenByte else { completion(.failed(error?.localizedDescription ?? "short reply")); return }
                    self.readExact(connection, Int(lenByte[0]) + 2) { rest, error in
                        finish(rest, error, prefix: header + lenByte)
                    }
                }
            default:
                completion(.failed("unsupported address type 0x\(String(format: "%02x", header[3]))"))
            }
        }
    }

    // reads an http proxy's reply up to the end of its headers. returns the status
    // code and whatever the server already sent after the headers, which belongs to
    // the tunnel and has to reach the client first
    private func readHTTPConnectResponse(_ connection: NWTCPConnection, buffer: Data = Data(), completion: @escaping (Int?, Data, String) -> Void) {
        connection.readMinimumLength(1, maximumLength: 8192) { [weak self] data, error in
            guard let self = self else { return }
            if let error = error { completion(nil, Data(), error.localizedDescription); return }
            var buffer = buffer
            if let data = data { buffer.append(data) }

            if let end = buffer.range(of: Data([0x0d, 0x0a, 0x0d, 0x0a])) {
                let head = String(decoding: buffer[buffer.startIndex..<end.lowerBound], as: UTF8.self)
                let statusLine = head.components(separatedBy: "\r\n").first ?? ""
                let parts = statusLine.split(separator: " ", omittingEmptySubsequences: true)
                guard parts.count >= 2, parts[0].hasPrefix("HTTP/1."), let status = Int(parts[1]) else {
                    completion(nil, Data(), "invalid status line: \(statusLine.prefix(80))")
                    return
                }
                completion(status, Data(buffer[end.upperBound...]), statusLine)
            } else if buffer.count >= 16384 || data == nil || data!.isEmpty {
                completion(nil, Data(), "response headers incomplete or too large")
            } else {
                self.readHTTPConnectResponse(connection, buffer: buffer, completion: completion)
            }
        }
    }

    // human readable name for a socks5 REP code, from RFC 1928
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
        guard completeHandshake(tcpConnection) else { return }
        let relayEndpoint = NWHostEndpoint(hostname: relayHost, port: String(relayPort))
        let udpSession = self.createUDPSession(to: relayEndpoint, from: nil)

        let association = UDPAssociation(clientFlow: clientFlow, controlConnection: tcpConnection, udpSession: udpSession, displayName: displayName, socksHost: socksHost, socksPort: socksPort, ruleContext: ruleContext)

        udpLock.lock()
        let existing = udpAssociations[clientFlow]
        udpAssociations[clientFlow] = association
        udpLock.unlock()
        // if the app reused a flow, drop the stale association first
        existing?.release()

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
        assoc.release()
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

            association.touch()
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

                let key = UDPAssociation.HostPort(host: destHost, port: destPort)
                var header = association.headerCache[key]
                if header == nil, let built = self.socks5UDPHeader(destHost: destHost, destPort: destPort) {
                    if association.headerCache.count < UDPAssociation.cacheLimit { association.headerCache[key] = built }
                    header = built
                }
                // a udp payload can be up to ~65507 bytes, don't drop mtu-sized quic packets
                if let header = header, datagrams[i].count <= 65507 {
                    var packet = Data(capacity: header.count + datagrams[i].count)
                    packet.append(header)
                    packet.append(datagrams[i])
                    toSend.append(packet)
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
        association.udpSession.setReadHandler({ [weak self, weak association] datagrams, error in
            guard let self = self, let association = association else { return }

            if let error = error {
                // stop reading the relay but don't close the app's flow, let it
                // time out on its own instead of getting a hard EPIPE
                self.log("[\(association.displayName)] [UDP] [SOCKS5 \(association.socksHost):\(association.socksPort)] UDP relay read error: \(error.localizedDescription)", level: "ERROR")
                self.sendLogToApp(protocol: "UDP", process: association.displayName, destination: "*", port: "*", proxy: "SOCKS5 \(association.socksHost):\(association.socksPort)", status: self.connectionStatus(for: error), details: "Relay read error: \(error.localizedDescription)", ruleContext: association.ruleContext)
                return
            }

            guard let datagrams = datagrams, !datagrams.isEmpty else { return }
            association.touch()

            var payloads: [Data] = []
            var endpoints: [NWEndpoint] = []
            payloads.reserveCapacity(datagrams.count)
            endpoints.reserveCapacity(datagrams.count)

            for datagram in datagrams {
                if let (payload, destHost, destPort) = self.decapsulateSOCKS5UDPWithEndpoint(datagram: datagram, association: association) {
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

    // the socks5 udp request header for one destination, the payload follows it
    private func socks5UDPHeader(destHost: String, destPort: UInt16) -> Data? {
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
        return header
    }

    private func decapsulateSOCKS5UDPWithEndpoint(datagram: Data, association: UDPAssociation) -> (Data, String, UInt16)? {
        guard datagram.count > 10 else { return nil }

        // byte 2 is FRAG, we don't reassemble so drop any fragmented datagram
        guard datagram[2] == 0x00 else { return nil }

        let atyp = datagram[3]
        var headerLen = 4
        var destHost = ""
        var destPort: UInt16 = 0

        if atyp == 0x01 {
            // ipv4 is 4 bytes + 2 port, already covered by count > 10. the dotted
            // string is cached by the raw 6 bytes, a flow talks to few peers
            let raw = (UInt64(datagram[4]) << 40) | (UInt64(datagram[5]) << 32) | (UInt64(datagram[6]) << 24)
                | (UInt64(datagram[7]) << 16) | (UInt64(datagram[8]) << 8) | UInt64(datagram[9])
            if let hit = association.endpointCache[raw] {
                destHost = hit.host
                destPort = hit.port
            } else {
                destHost = "\(datagram[4]).\(datagram[5]).\(datagram[6]).\(datagram[7])"
                destPort = (UInt16(datagram[8]) << 8) | UInt16(datagram[9])
                if association.endpointCache.count < UDPAssociation.cacheLimit {
                    association.endpointCache[raw] = (destHost, destPort)
                }
            }
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

    private static let dnsNameMaxAge: TimeInterval = 300

    private func proxyTCPFlow(_ flow: NEAppProxyTCPFlow, displayName: String, destination: String, port: UInt16, logDest: String, config: StoredProxyConfig, ruleContext: RuleLogContext) {
        let label = proxyLabel(config)
        // "let proxy resolve DNS", per proxy like the windows app: when the app
        // resolved this address through our DNS proxy, ask the proxy for the name
        // (socks5 domain address / CONNECT host:port) and fall back to the ip
        let destinationIP = destination
        var destination = destinationIP
        if config.sendDomain,
           IPv4Address(destinationIP) != nil || IPv6Address(destinationIP) != nil,
           let name = DNSMapStore.shared.latestDomain(forIP: destinationIP, maxAge: AppProxyProvider.dnsNameMaxAge) {
            destination = name
        }
        let proxyEndpoint = NWHostEndpoint(hostname: config.host, port: String(config.port))
        let proxyConnection = createTCPConnection(to: proxyEndpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
        armHandshakeTimeout(flow: flow, connection: proxyConnection, log: HandshakeLog(proto: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, rule: ruleContext))

        switch config.type.lowercased() {
        case "socks5":
            handleSOCKS5Proxy(clientFlow: flow, proxyConnection: proxyConnection, displayName: displayName, destination: destination, port: port, logDest: logDest, config: config, ruleContext: ruleContext)
        case "http":
            handleHTTPProxy(clientFlow: flow, proxyConnection: proxyConnection, displayName: displayName, destination: destination, port: port, logDest: logDest, config: config, ruleContext: ruleContext)
        default:
            log("[\(displayName)] [\(logDest):\(port)] [\(label)] Unsupported proxy type: \(config.type)", level: "ERROR")
            sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "FAILED", details: "Unsupported proxy type: \(config.type)", ruleContext: ruleContext)
            flow.closeReadWithError(FlowFailure.refused)
            flow.closeWriteWithError(FlowFailure.refused)
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
                self.closeRelay(clientFlow, proxyConnection, error: error)
                return
            }

            proxyConnection.readMinimumLength(2, maximumLength: 2) { [weak self] data, error in
                guard let self = self else { return }

                if let error = error {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 greeting response failed: \(error.localizedDescription)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Greeting read failed: \(error.localizedDescription)", ruleContext: ruleContext)
                    self.closeRelay(clientFlow, proxyConnection, error: error)
                    return
                }

                guard let data = data, data.count == 2 else {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 invalid greeting response (\(data?.count ?? 0) bytes)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "FAILED", details: "Invalid greeting response", ruleContext: ruleContext)
                    self.closeRelay(clientFlow, proxyConnection, error: FlowFailure.refused)
                    return
                }

                let version = data[0]
                let method = data[1]

                if version != 0x05 {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 invalid version: 0x\(String(format: "%02x", version))", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "FAILED", details: "Invalid version 0x\(String(format: "%02x", version))", ruleContext: ruleContext)
                    self.closeRelay(clientFlow, proxyConnection, error: FlowFailure.refused)
                    return
                }

                if method == 0x00 {
                    self.sendSOCKS5ConnectRequest(clientFlow: clientFlow, proxyConnection: proxyConnection, displayName: displayName, destination: destination, port: port, logDest: logDest, label: label, ruleContext: ruleContext)
                } else if method == 0x02 {
                    self.sendSOCKS5Auth(clientFlow: clientFlow, proxyConnection: proxyConnection, displayName: displayName, destination: destination, port: port, logDest: logDest, label: label, username: config.username ?? "", password: config.password ?? "", ruleContext: ruleContext)
                } else {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 no acceptable auth method (method=0x\(String(format: "%02x", method)))", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "AUTH_FAILED", details: "No acceptable auth (0x\(String(format: "%02x", method)))", ruleContext: ruleContext)
                    self.closeRelay(clientFlow, proxyConnection, error: FlowFailure.refused)
                }
            }
        }
    }

    private func sendSOCKS5Auth(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection, displayName: String, destination: String, port: UInt16, logDest: String, label: String, username: String, password: String, ruleContext: RuleLogContext) {
        let user = Array(username.utf8), pass = Array(password.utf8)
        guard user.count <= 255, pass.count <= 255 else {
            log("SOCKS5 credentials too long", level: "ERROR")
            closeRelay(clientFlow, proxyConnection, error: FlowFailure.refused)
            return
        }
        var authData = Data()
        authData.append(0x01)
        authData.append(UInt8(user.count))
        authData.append(contentsOf: user)
        authData.append(UInt8(pass.count))
        authData.append(contentsOf: pass)

        proxyConnection.write(authData) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 auth write failed: \(error.localizedDescription)", level: "ERROR")
                self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Auth write failed: \(error.localizedDescription)", ruleContext: ruleContext)
                self.closeRelay(clientFlow, proxyConnection, error: error)
                return
            }

            proxyConnection.readMinimumLength(2, maximumLength: 2) { [weak self] data, error in
                guard let self = self else { return }

                if let error = error {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 auth response read failed: \(error.localizedDescription)", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Auth read error: \(error.localizedDescription)", ruleContext: ruleContext)
                    self.closeRelay(clientFlow, proxyConnection, error: error)
                    return
                }

                guard let data = data, data.count == 2, data[1] == 0x00 else {
                    self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 auth rejected by proxy", level: "ERROR")
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "AUTH_FAILED", details: "Auth rejected", ruleContext: ruleContext)
                    self.closeRelay(clientFlow, proxyConnection, error: FlowFailure.refused)
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
            let hostBytes = Array(destination.utf8)
            guard hostBytes.count <= 255 else {
                log("SOCKS5 destination name too long", level: "ERROR")
                closeRelay(clientFlow, proxyConnection, error: FlowFailure.refused)
                return
            }
            request.append(0x03)
            request.append(UInt8(hostBytes.count))
            request.append(contentsOf: hostBytes)
        }

        request.append(UInt8(port >> 8))
        request.append(UInt8(port & 0xFF))

        proxyConnection.write(request) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] SOCKS5 connect write failed: \(error.localizedDescription)", level: "ERROR")
                self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Connect write failed: \(error.localizedDescription)", ruleContext: ruleContext)
                self.closeRelay(clientFlow, proxyConnection, error: error)
                return
            }

            self.readSOCKS5Reply(proxyConnection) { [weak self] reply in
                guard let self = self else { return }
                switch reply {
                case .success:
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "CONNECTED", ruleContext: ruleContext)
                    self.relayData(clientFlow: clientFlow, proxyConnection: proxyConnection, displayName: displayName, destination: logDest, port: port, proxyLabel: label, ruleContext: ruleContext)
                case .rejected(let rep):
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.socksReplyStatus(rep), ruleContext: ruleContext)
                    self.log("SOCKS5 connect rejected, REP=0x\(String(format: "%02x", rep)) (\(self.socksReplyReason(rep)))", level: "ERROR")
                    self.closeRelay(clientFlow, proxyConnection, error: FlowFailure.socks(rep))
                case .failed(let reason):
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "FAILED", details: reason, ruleContext: ruleContext)
                    self.log("SOCKS5 connect failed: \(reason)", level: "ERROR")
                    self.closeRelay(clientFlow, proxyConnection, error: FlowFailure.proxyUnreachable)
                }
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
            self.closeRelay(clientFlow, proxyConnection, error: FlowFailure.refused)
            return
        }

        proxyConnection.write(requestData) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.log("[\(displayName)] [\(logDest):\(port)] [\(label)] HTTP CONNECT write failed: \(error.localizedDescription)", level: "ERROR")
                self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.connectionStatus(for: error), details: "Write failed: \(error.localizedDescription)", ruleContext: ruleContext)
                self.closeRelay(clientFlow, proxyConnection, error: error)
                return
            }

            self.readHTTPConnectResponse(proxyConnection) { [weak self] status, leftover, detail in
                guard let self = self else { return }
                // any 2xx opens the tunnel, a "200" somewhere else in the reply
                // (407 with Content-Length: 200) used to count as success
                if let status = status, (200...299).contains(status) {
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: "CONNECTED", ruleContext: ruleContext)
                    self.relayData(clientFlow: clientFlow, proxyConnection: proxyConnection, displayName: displayName, destination: logDest, port: port, proxyLabel: label, ruleContext: ruleContext, initialData: leftover)
                } else {
                    self.sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: String(port), proxy: label, status: self.httpConnectFailureStatus(detail), details: detail, ruleContext: ruleContext)
                    self.log("HTTP CONNECT failed: \(detail)", level: "ERROR")
                    self.closeRelay(clientFlow, proxyConnection, error: FlowFailure.http(status))
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
            guard !isClosed else { lock.unlock(); return }
            isClosed = true
            let timeout = timeoutItem
            timeoutItem = nil
            lock.unlock()
            timeout?.cancel()
            clientFlow.closeReadWithError(nil)
            clientFlow.closeWriteWithError(nil)
            proxyConnection.cancel()
        }

        func onClientEOF() {
            clientFlow.closeReadWithError(nil)
            proxyConnection.writeClose()
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

    private func relayData(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection, displayName: String, destination: String, port: UInt16, proxyLabel: String, ruleContext: RuleLogContext, initialData: Data? = nil) {
        guard completeHandshake(proxyConnection) else { return }
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
            if let initialData, !initialData.isEmpty {
                clientFlow.write(initialData) { [weak self] error in
                    guard let self else { context.close(); return }
                    if let error {
                        self.sendLogToApp(protocol: "TCP", process: displayName, destination: destination, port: String(port), proxy: proxyLabel, status: self.connectionStatus(for: error), details: error.localizedDescription, ruleContext: ruleContext)
                        context.close()
                    } else {
                        self.relayProxyToClient(context: context, displayName: displayName, destination: destination, port: port, proxyLabel: proxyLabel, ruleContext: ruleContext)
                    }
                }
            } else {
                self.relayProxyToClient(context: context, displayName: displayName, destination: destination, port: port, proxyLabel: proxyLabel, ruleContext: ruleContext)
            }
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
        return ProxyRule.firstMatch(in: currentRules, bundleId: bundleId, processName: processName, executablePath: executablePath, destination: destination, port: port, connectionProtocol: connectionProtocol, checkIpPort: checkIpPort, domains: domains)
    }

    private func sendLogToApp(protocol: String, process: String, destination: String, port: String, proxy: String, status: String = "", details: String = "", ruleContext: RuleLogContext = .defaultMatch) {
        guard trafficLoggingEnabled else { return }
        appendLog(.connection(proto: `protocol`, process: process, destination: destination, port: port, proxy: proxy, status: status, details: details, rule: ruleContext))
    }
}
