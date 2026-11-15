// Rule matching (ProxyRule.Matcher in AppProxyProvider.swift). Compiled as main.swift by run.sh.
import Foundation

func matcher(_ p: String, _ h: String, _ pt: String) -> ProxyRule.Matcher {
    ProxyRule.Matcher(ProxyRule(ruleId: 1, processNames: p, targetHosts: h, targetPorts: pt, ruleProtocol: .both, action: "DIRECT", enabled: true))
}
var fails = 0
func t(_ name: String, _ got: Bool, _ expected: Bool) { if got != expected { fails += 1; print("FAIL", name) } }

let chrome = ProxyRule.FlowProcess(bundleId: "com.google.Chrome", processName: "Google Chrome")
let curl = ProxyRule.FlowProcess(bundleId: "curl-abc", processName: "curl")

// process patterns
t("star", matcher("*", "*", "*").matchesProcess(chrome), true)
t("prefix glob must match the start only", matcher("chrome*", "*", "*").matchesProcess(chrome), false)
t("contains glob", matcher("*chrome*", "*", "*").matchesProcess(chrome), true)
t("exact name", matcher("curl", "*", "*").matchesProcess(curl), true)
t("list with spaces", matcher("safari; curl", "*", "*").matchesProcess(curl), true)
t("comma list", matcher("safari,curl", "*", "*").matchesProcess(curl), true)
t("trailing separator is not a wildcard", matcher("safari;", "*", "*").matchesProcess(curl), false)
t("leading separator is not a wildcard", matcher(";safari", "*", "*").matchesProcess(curl), false)
t("bundle id glob", matcher("com.google.*", "*", "*").matchesProcess(chrome), true)
t("case insensitive", matcher("CURL", "*", "*").matchesProcess(curl), true)
t("no match", matcher("firefox", "*", "*").matchesProcess(curl), false)

// full executable paths (issue #288): a rule written with a path is compared with the program's path
let workerA = ProxyRule.FlowProcess(bundleId: "-", processName: "worker", executablePath: "/opt/example-app-a/bin/worker")
let workerB = ProxyRule.FlowProcess(bundleId: "-", processName: "worker", executablePath: "/opt/example-app-b/bin/worker")
let nameOnly = ProxyRule.FlowProcess(bundleId: "-", processName: "worker")
let chromeHelper = ProxyRule.FlowProcess(bundleId: "com.google.Chrome.helper", processName: "Google Chrome Helper",
    executablePath: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper")
t("a path rule matches that program", matcher("/opt/example-app-a/bin/worker", "*", "*").matchesProcess(workerA), true)
t("a path rule does not match a same-named program elsewhere", matcher("/opt/example-app-a/bin/worker", "*", "*").matchesProcess(workerB), false)
t("a file name rule matches both programs", matcher("worker", "*", "*").matchesProcess(workerA) && matcher("worker", "*", "*").matchesProcess(workerB), true)
t("a path with a folder wildcard", matcher("/opt/example-app-a/*", "*", "*").matchesProcess(workerA), true)
t("a path with a folder wildcard leaves the other folder out", matcher("/opt/example-app-a/*", "*", "*").matchesProcess(workerB), false)
t("a wildcard in the middle of a path", matcher("/opt/*/bin/worker", "*", "*").matchesProcess(workerA) && matcher("/opt/*/bin/worker", "*", "*").matchesProcess(workerB), true)
t("a path rule is not case sensitive", matcher("/OPT/Example-App-A/BIN/Worker", "*", "*").matchesProcess(workerA), true)
t("a path rule for a whole app bundle, with spaces in the path", matcher("/Applications/Google Chrome.app/*", "*", "*").matchesProcess(chromeHelper), true)
t("a path rule for another app does not match", matcher("/Applications/Firefox.app/*", "*", "*").matchesProcess(chromeHelper), false)
t("a path rule cannot match when only the name is known", matcher("/opt/example-app-a/bin/worker", "*", "*").matchesProcess(nameOnly), false)
t("a path pattern is not compared with the bundle id", matcher("/com.google.Chrome.helper", "*", "*").matchesProcess(chromeHelper), false)
t("a bundle id rule still matches when the path is known", matcher("com.google.Chrome.*", "*", "*").matchesProcess(chromeHelper), true)
t("a name rule with a wildcard still matches when the path is known", matcher("*chrome helper*", "*", "*").matchesProcess(chromeHelper), true)
t("a list can mix a path and a name", matcher("/opt/example-app-a/bin/worker; curl", "*", "*").matchesProcess(workerA), true)
t("a list can mix a path and a name, other entry", matcher("/opt/example-app-a/bin/worker; curl", "*", "*").matchesProcess(curl), true)
t("a path is not cut at a folder name that looks like the file name", matcher("/opt/example-app-a/bin", "*", "*").matchesProcess(workerA), false)

// ports
t("the IPC listener bypasses TCP rules", LocalIPCServer.isListenerEndpoint(host: "127.0.0.1", port: 58223), true)
t("another local port still uses TCP rules", LocalIPCServer.isListenerEndpoint(host: "127.0.0.1", port: 443), false)
for host in ["192.0.2.1", "2001:db8::1", "example.org", "127.0.0.1.example.org"] {
    t("remote IPC port still uses TCP rules: \(host)", LocalIPCServer.isListenerEndpoint(host: host, port: 58223), false)
}
t("port in list", matcher("*", "*", "80,443,8000-8100").matchesPort(8050), true)
t("port exact", matcher("*", "*", "80,443").matchesPort(443), true)
t("port miss", matcher("*", "*", "80,443").matchesPort(81), false)
t("port range edge low", matcher("*", "*", "8000-8100").matchesPort(8000), true)
t("port range edge high", matcher("*", "*", "8000-8100").matchesPort(8100), true)
t("port range just out", matcher("*", "*", "8000-8100").matchesPort(8101), false)
t("all ports", matcher("*", "*", "*").matchesPort(1), true)
t("garbage port never matches", matcher("*", "*", "abc").matchesPort(1), false)
t("trailing separator in ports is not a wildcard", matcher("*", "*", "80;").matchesPort(443), false)
t("reversed range never matches", matcher("*", "*", "9000-8000").matchesPort(8500), false)

// hosts: ips, ranges, v6, domains
func dom(_ names: String...) -> [(name: String, chars: [Character])] { names.map { (name: $0, chars: Array($0)) } }
t("ip exact", matcher("*", "10.0.0.5", "*").matchesHost(ip: "10.0.0.5", domains: []), true)
t("ip wildcard octet", matcher("*", "192.168.1.*", "*").matchesHost(ip: "192.168.1.9", domains: []), true)
t("ip range", matcher("*", "10.0.0.1-10.0.0.9", "*").matchesHost(ip: "10.0.0.5", domains: []), true)
t("ip miss", matcher("*", "10.0.0.5", "*").matchesHost(ip: "10.0.0.6", domains: []), false)
t("ipv6 exact", matcher("*", "::1", "*").matchesHost(ip: "::1", domains: []), true)
t("ipv6 prefix wildcard", matcher("*", "2001:db8:*", "*").matchesHost(ip: "2001:db8::5", domains: []), true)
t("domain glob", matcher("*", "*.github.com", "*").matchesHost(ip: "1.1.1.1", domains: dom("api.github.com")), true)
t("domain glob covers the apex", matcher("*", "*.github.com", "*").matchesHost(ip: "1.1.1.1", domains: dom("github.com")), true)
t("domain miss", matcher("*", "*.gitlab.com", "*").matchesHost(ip: "1.1.1.1", domains: dom("api.github.com")), false)
t("domain exact", matcher("*", "example.com", "*").matchesHost(ip: "1.1.1.1", domains: dom("example.com")), true)
t("list of ip and domain", matcher("*", "1.2.3.4;*.github.com", "*").matchesHost(ip: "9.9.9.9", domains: dom("api.github.com")), true)
t("domain rule without any known name", matcher("*", "*.github.com", "*").matchesHost(ip: "9.9.9.9", domains: []), false)
t("all hosts", matcher("*", "*", "*").matchesHost(ip: "9.9.9.9", domains: []), true)

// Migration: app-bundle provenance, full paths, empty list segments and first-match ordering.
let helperPath = "/Applications/Browser.app/Contents/Frameworks/Helper.app/Contents/MacOS/worker"
let bundleRule = ProxyRule(ruleId: 10, name: "Browser bundle", processNames: "Browser.app", targetHosts: "*", targetPorts: "*", ruleProtocol: .both, action: "DIRECT", enabled: true)
t("containing app covers helpers", bundleRule.matchProcess(bundleId: "helper.id", processName: "worker", executablePath: helperPath)?.kind == "APP", true)
let pathRule = ProxyRule(ruleId: 11, processNames: "/Applications/Browser.app/*", targetHosts: "*", targetPorts: "*", ruleProtocol: .both, action: "DIRECT", enabled: true)
t("full executable path and provenance", pathRule.matchProcess(bundleId: "helper.id", processName: "worker", executablePath: helperPath)?.kind == "PROC", true)
let emptySegment = ProxyRule(ruleId: 12, processNames: "safari;", targetHosts: "*", targetPorts: "*", ruleProtocol: .both, action: "DIRECT", enabled: true)
t("empty segment does not match worker", emptySegment.matchProcess(bundleId: "helper.id", processName: "worker", executablePath: helperPath) != nil, false)
let catchAll = ProxyRule(ruleId: 13, name: "Catch all", processNames: "*", targetHosts: "*", targetPorts: "*", ruleProtocol: .both, action: "BLOCK", enabled: true)
func first(_ rules: [ProxyRule], destination: String = "1.2.3.4", proto: RuleProtocol = .tcp) -> MatchedRule? {
    ProxyRule.firstMatch(in: rules.map { ($0, ProxyRule.Matcher($0)) }, bundleId: "helper.id", processName: "worker", executablePath: helperPath, destination: destination, port: 443, connectionProtocol: proto, checkIpPort: true)
}
t("catch-all first wins IPv4", first([catchAll, bundleRule])?.rule.ruleId == 13, true)
t("catch-all first wins IPv6", first([catchAll, bundleRule], destination: "2001:db8::1")?.rule.ruleId == 13, true)
t("reordered app rule wins", first([bundleRule, catchAll])?.rule.ruleId == 10, true)
t("rule provenance is preserved", first([bundleRule, catchAll])?.processMatch.kind == "APP", true)
var disabled = catchAll; disabled.enabled = false
t("disabled catch-all is skipped", first([disabled, bundleRule])?.rule.ruleId == 10, true)
t("UDP ordering", first([catchAll, bundleRule], proto: .udp)?.rule.ruleId == 13, true)

print(fails == 0 ? "matcher tests: ALL PASS" : "matcher tests: \(fails) FAILED")
exit(fails == 0 ? 0 : 1)
