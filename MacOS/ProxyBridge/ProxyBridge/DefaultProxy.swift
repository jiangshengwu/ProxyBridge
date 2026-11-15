import Foundation

// The default proxy (issue #274). A rule whose action is "DEFAULT" follows whichever proxy is the
// profile's default, so a whole rule set can move to another proxy by changing one setting.
//
// The extension never sees "DEFAULT". Just before the rules are sent, the app replaces it with the
// real proxy id (or DIRECT when there is no proxy), and sends the rules again when the default changes.
nonisolated enum DefaultProxy {
    // the action a rule has when it follows the default proxy
    static let action = "DEFAULT"

    // actions that are never a proxy id, so a proxy cannot be given one of these as its id
    static let reservedActions: Set<String> = ["DEFAULT", "DIRECT", "BLOCK"]

    // what "Default" means right now: the proxy marked as default when it still exists, otherwise the
    // first proxy, otherwise DIRECT (no proxy at all)
    static func effectiveAction(defaultId: String?, proxyIds: [String]) -> String {
        if let id = defaultId, proxyIds.contains(id) { return id }
        return proxyIds.first ?? "DIRECT"
    }

    // the proxy id the default stands for, nil when there is no proxy
    static func effectiveId(defaultId: String?, proxyIds: [String]) -> String? {
        let a = effectiveAction(defaultId: defaultId, proxyIds: proxyIds)
        return proxyIds.contains(a) ? a : nil
    }

    static func resetReferences(to removedProxyId: String, in rules: inout [[String: Any]]) -> Int {
        var count = 0
        for i in rules.indices where rules[i]["action"] as? String == removedProxyId {
            rules[i]["action"] = "DIRECT"
            count += 1
        }
        return count
    }

    // Only resolved rules can be sent over IPC. Saved rules retain DEFAULT for future changes.
    struct ResolvedRules {
        let rules: [[String: Any]]

        init(_ saved: [[String: Any]], defaultAction: String) {
            rules = saved.map { rule in
                guard (rule["action"] as? String) == DefaultProxy.action else { return rule }
                var copy = rule
                copy["action"] = defaultAction
                return copy
            }
        }
    }

    static func usesDefault(_ rules: [[String: Any]]) -> Bool {
        rules.contains { ($0["action"] as? String) == action }
    }
}
