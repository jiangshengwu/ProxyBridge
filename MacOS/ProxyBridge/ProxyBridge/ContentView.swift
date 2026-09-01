import SwiftUI
import AppKit

enum RoutingFilter: String, CaseIterable, Identifiable {
    case proxied = "PROXIED"
    case direct = "DIRECT"
    case reject = "REJECT"

    var id: String { rawValue }
}

enum ProtocolFilter: String, CaseIterable, Identifiable {
    case tcp = "TCP"
    case udp = "UDP"

    var id: String { rawValue }
}

extension ProxyBridgeViewModel.ConnectionLog {
    var isProxied: Bool {
        let p = proxy.lowercased()
        let s = status.uppercased()
        return p != "direct" && p != "block" && s != "BLOCKED" && s != "REJECTED" && s != "DIRECT"
    }
    
    var isDirect: Bool {
        let p = proxy.lowercased()
        let s = status.uppercased()
        return p == "direct" || s == "DIRECT"
    }
    
    var isRejected: Bool {
        let p = proxy.lowercased()
        let s = status.uppercased()
        return p == "block" || s == "BLOCKED" || s == "REJECTED" || s == "FAILED" || s == "ERROR"
    }
}

struct ContentView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    @State private var selectedTab = 0
    @State private var connectionSearchText = ""
    @State private var activitySearchText = ""
    @State private var selectedRoutingFilter: RoutingFilter? = nil
    @State private var selectedProtocolFilter: ProtocolFilter? = nil
    @State private var selectedActivitySource: ProxyBridgeViewModel.ActivitySource? = nil
    
    var body: some View {
        VStack(spacing: 0) {
            headerView
            Divider()
            tabSelector
            Divider()
            contentView
        }
        .frame(minWidth: 800, minHeight: 600)
    }
    
    private var headerView: some View {
        HStack(spacing: 12) {
            HStack(spacing: 8) {
                Circle()
                    .fill(viewModel.isProxyActive ? Color.green : Color.gray.opacity(0.6))
                    .frame(width: 9, height: 9)
                Text("ProxyBridge")
                    .font(.headline)
                Text(viewModel.isProxyActive ? "Active" : "Stopped")
                    .font(.caption)
                    .foregroundColor(viewModel.isProxyActive ? .green : .secondary)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(viewModel.isProxyActive ? Color.green.opacity(0.12) : Color.gray.opacity(0.12))
                    .cornerRadius(4)
            }
            .padding(.leading, 16)
            
            Spacer()
            
            // Start / Stop Toggle Button
            Button(action: {
                if viewModel.isProxyActive {
                    viewModel.stopProxy()
                } else {
                    viewModel.startProxy()
                }
            }) {
                HStack(spacing: 6) {
                    Image(systemName: viewModel.isProxyActive ? "stop.fill" : "play.fill")
                        .font(.system(size: 10, weight: .bold))
                    Text(viewModel.isProxyActive ? "Stop Proxy" : "Start Proxy")
                        .font(.system(size: 12, weight: .semibold))
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 5)
                .background(viewModel.isProxyActive ? Color.red.opacity(0.85) : Color.green.opacity(0.85))
                .foregroundColor(.white)
                .cornerRadius(6)
            }
            .buttonStyle(.plain)
            
            // Rules Button
            Button(action: openRules) {
                HStack(spacing: 5) {
                    Image(systemName: "list.bullet.rectangle")
                        .font(.system(size: 11))
                    Text("Rules")
                        .font(.system(size: 12))
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(Color(NSColor.controlColor))
                .cornerRadius(6)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                )
            }
            .buttonStyle(.plain)
            
            // Settings Button
            Button(action: openSettings) {
                HStack(spacing: 5) {
                    Image(systemName: "gearshape")
                        .font(.system(size: 11))
                    Text("Settings")
                        .font(.system(size: 12))
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(Color(NSColor.controlColor))
                .cornerRadius(6)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                )
            }
            .buttonStyle(.plain)
            .padding(.trailing, 16)
        }
        .frame(height: 46)
        .background(Color(NSColor.windowBackgroundColor))
    }
    
    private func openSettings() {
        if let delegate = AppDelegate.shared {
            delegate.openProxySettings()
        } else {
            NSApp.sendAction(#selector(AppDelegate.openProxySettings), to: nil, from: nil)
        }
    }
    
    private func openRules() {
        if let delegate = AppDelegate.shared {
            delegate.openProxyRules()
        } else {
            NSApp.sendAction(#selector(AppDelegate.openProxyRules), to: nil, from: nil)
        }
    }
    
    private var tabSelector: some View {
        HStack(spacing: 0) {
            TabButton(title: "Connections", isSelected: selectedTab == 0) {
                selectedTab = 0
            }
            TabButton(title: "System Activity", isSelected: selectedTab == 1) {
                selectedTab = 1
            }
            Spacer()
        }
        .frame(height: 40)
        .background(Color(NSColor.controlBackgroundColor))
    }
    
    private var contentView: some View {
        Group {
            if selectedTab == 0 {
                ConnectionsView(
                    connections: filteredConnections,
                    allConnections: viewModel.connections,
                    searchText: $connectionSearchText,
                    selectedRoutingFilter: $selectedRoutingFilter,
                    selectedProtocolFilter: $selectedProtocolFilter,
                    onClear: viewModel.clearConnections
                )
            } else {
                ActivityLogsView(
                    logs: filteredActivityLogs,
                    allLogs: viewModel.activityLogs,
                    searchText: $activitySearchText,
                    selectedSource: $selectedActivitySource,
                    onClear: viewModel.clearActivityLogs
                )
            }
        }
    }
    
    private var filteredConnections: [ProxyBridgeViewModel.ConnectionLog] {
        let q = connectionSearchText
        return viewModel.connections.filter { c in
            if let routing = selectedRoutingFilter {
                switch routing {
                case .proxied:
                    if !c.isProxied { return false }
                case .direct:
                    if !c.isDirect { return false }
                case .reject:
                    if !c.isRejected { return false }
                }
            }
            
            if let proto = selectedProtocolFilter {
                switch proto {
                case .tcp:
                    if c.connectionProtocol.uppercased() != "TCP" { return false }
                case .udp:
                    if c.connectionProtocol.uppercased() != "UDP" { return false }
                }
            }
            
            if q.isEmpty { return true }
            return c.timestamp.localizedCaseInsensitiveContains(q) ||
                c.connectionProtocol.localizedCaseInsensitiveContains(q) ||
                c.process.localizedCaseInsensitiveContains(q) ||
                c.destination.localizedCaseInsensitiveContains(q) ||
                c.port.localizedCaseInsensitiveContains(q) ||
                c.proxy.localizedCaseInsensitiveContains(q) ||
                c.status.localizedCaseInsensitiveContains(q) ||
                c.details.localizedCaseInsensitiveContains(q) ||
                c.ruleId.localizedCaseInsensitiveContains(q) ||
                c.ruleName.localizedCaseInsensitiveContains(q) ||
                c.matchType.localizedCaseInsensitiveContains(q) ||
                c.matchValue.localizedCaseInsensitiveContains(q)
        }
    }

    private var filteredActivityLogs: [ProxyBridgeViewModel.ActivityLog] {
        let q = activitySearchText
        return viewModel.activityLogs.filter {
            if let source = selectedActivitySource, $0.source != source {
                return false
            }

            if q.isEmpty { return true }
            return $0.timestamp.localizedCaseInsensitiveContains(q) ||
                $0.source.rawValue.localizedCaseInsensitiveContains(q) ||
                $0.level.localizedCaseInsensitiveContains(q) ||
                $0.message.localizedCaseInsensitiveContains(q)
        }
    }
}

struct TabButton: View {
    let title: String
    let isSelected: Bool
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            Text(title)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(isSelected ? Color.blue.opacity(0.2) : Color.clear)
                .cornerRadius(6)
        }
        .buttonStyle(.plain)
    }
}

struct FilterChipButton: View {
    let title: String
    let isSelected: Bool
    let count: Int
    let badgeColor: Color?
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Text(title)
                    .font(.system(size: 11, weight: isSelected ? .bold : .medium))
                
                Text("\(count)")
                    .font(.system(size: 10, weight: .semibold))
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(badgeBackground)
                    .foregroundColor(badgeForeground)
                    .clipShape(Capsule())
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(isSelected ? Color.accentColor : Color(NSColor.controlColor).opacity(0.8))
            .foregroundColor(isSelected ? .white : .primary)
            .cornerRadius(6)
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .stroke(isSelected ? Color.accentColor : Color.gray.opacity(0.25), lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }
    
    private var badgeBackground: Color {
        if isSelected {
            return Color.white.opacity(0.25)
        }
        if let badgeColor = badgeColor {
            return badgeColor.opacity(0.15)
        }
        return Color.gray.opacity(0.2)
    }
    
    private var badgeForeground: Color {
        if isSelected {
            return .white
        }
        if let badgeColor = badgeColor {
            return badgeColor
        }
        return .secondary
    }
}

struct ConnectionsView: View {
    let connections: [ProxyBridgeViewModel.ConnectionLog]
    let allConnections: [ProxyBridgeViewModel.ConnectionLog]
    @Binding var searchText: String
    @Binding var selectedRoutingFilter: RoutingFilter?
    @Binding var selectedProtocolFilter: ProtocolFilter?
    let onClear: () -> Void
    
    var isAllSelected: Bool {
        selectedRoutingFilter == nil && selectedProtocolFilter == nil
    }
    
    var body: some View {
        VStack(spacing: 0) {
            searchBar
            Divider()
            LogTextView(text: connectionsText)
        }
    }

    private var allCount: Int { allConnections.count }
    private var proxiedCount: Int { allConnections.filter { $0.isProxied }.count }
    private var directCount: Int { allConnections.filter { $0.isDirect }.count }
    private var rejectCount: Int { allConnections.filter { $0.isRejected }.count }
    private var tcpCount: Int { allConnections.filter { $0.connectionProtocol.uppercased() == "TCP" }.count }
    private var udpCount: Int { allConnections.filter { $0.connectionProtocol.uppercased() == "UDP" }.count }

    private var searchBar: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.gray)
                TextField("Search connections...", text: $searchText)
                    .textFieldStyle(.plain)
                
                if !searchText.isEmpty {
                    Button(action: { searchText = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.gray)
                    }
                    .buttonStyle(.plain)
                }
                
                Spacer()
                Button("Clear", action: onClear)
            }
            
            HStack(spacing: 6) {
                Text("Filter:")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                // ALL (mutually exclusive with all other filters)
                FilterChipButton(
                    title: "ALL",
                    isSelected: isAllSelected,
                    count: allCount,
                    badgeColor: nil
                ) {
                    selectedRoutingFilter = nil
                    selectedProtocolFilter = nil
                }
                
                Divider()
                    .frame(height: 14)
                    .padding(.horizontal, 2)
                
                // PROXIED / DIRECT / REJECT (mutually exclusive with each other, togglable)
                FilterChipButton(
                    title: "PROXIED",
                    isSelected: selectedRoutingFilter == .proxied,
                    count: proxiedCount,
                    badgeColor: .purple
                ) {
                    if selectedRoutingFilter == .proxied {
                        selectedRoutingFilter = nil
                    } else {
                        selectedRoutingFilter = .proxied
                    }
                }
                
                FilterChipButton(
                    title: "DIRECT",
                    isSelected: selectedRoutingFilter == .direct,
                    count: directCount,
                    badgeColor: .blue
                ) {
                    if selectedRoutingFilter == .direct {
                        selectedRoutingFilter = nil
                    } else {
                        selectedRoutingFilter = .direct
                    }
                }
                
                FilterChipButton(
                    title: "REJECT",
                    isSelected: selectedRoutingFilter == .reject,
                    count: rejectCount,
                    badgeColor: .red
                ) {
                    if selectedRoutingFilter == .reject {
                        selectedRoutingFilter = nil
                    } else {
                        selectedRoutingFilter = .reject
                    }
                }
                
                Divider()
                    .frame(height: 14)
                    .padding(.horizontal, 2)
                
                // TCP / UDP (mutually exclusive with each other, togglable)
                FilterChipButton(
                    title: "TCP",
                    isSelected: selectedProtocolFilter == .tcp,
                    count: tcpCount,
                    badgeColor: .teal
                ) {
                    if selectedProtocolFilter == .tcp {
                        selectedProtocolFilter = nil
                    } else {
                        selectedProtocolFilter = .tcp
                    }
                }
                
                FilterChipButton(
                    title: "UDP",
                    isSelected: selectedProtocolFilter == .udp,
                    count: udpCount,
                    badgeColor: .orange
                ) {
                    if selectedProtocolFilter == .udp {
                        selectedProtocolFilter = nil
                    } else {
                        selectedProtocolFilter = .udp
                    }
                }
                
                Spacer()
            }
        }
        .padding(10)
        .background(Color(NSColor.controlBackgroundColor))
    }

    private var connectionsText: NSAttributedString {
        let out = NSMutableAttributedString()
        for c in connections {
            out.append(LogText.seg("[\(c.timestamp)] ", .secondaryLabelColor))
            out.append(LogText.seg("[\(c.connectionProtocol)] ", .systemBlue))
            out.append(LogText.seg(c.process, .systemGreen))
            out.append(LogText.seg(" → ", .secondaryLabelColor))
            out.append(LogText.seg("\(c.destination):\(c.port)", .systemOrange))
            out.append(LogText.seg(" → ", .secondaryLabelColor))
            out.append(LogText.seg(c.proxy, c.proxy == "Direct" ? .secondaryLabelColor : (c.proxy == "BLOCK" ? .systemRed : .systemPurple)))
            
            if !c.status.isEmpty {
                let statusColor: NSColor
                switch c.status.uppercased() {
                case "CONNECTED", "SUCCESS", "OPEN":
                    statusColor = .systemGreen
                case "FAILED", "ERROR", "REJECTED":
                    statusColor = .systemRed
                case "CONNECTING":
                    statusColor = .systemYellow
                case "BLOCKED":
                    statusColor = .systemRed
                case "DIRECT":
                    statusColor = .secondaryLabelColor
                default:
                    statusColor = .secondaryLabelColor
                }
                out.append(LogText.seg(" [\(c.status)]", statusColor))
            }
            let ruleColor: NSColor = c.matchType.uppercased() == "DEFAULT" ? .secondaryLabelColor : .systemTeal
            out.append(LogText.seg(" [\(c.ruleMatchLabel)]", ruleColor))
            if !c.details.isEmpty {
                out.append(LogText.seg(" (\(c.details))", .secondaryLabelColor))
            }
            out.append(LogText.seg("\n", .labelColor))
        }
        return out
    }
}

struct ActivityLogsView: View {
    let logs: [ProxyBridgeViewModel.ActivityLog]
    let allLogs: [ProxyBridgeViewModel.ActivityLog]
    @Binding var searchText: String
    @Binding var selectedSource: ProxyBridgeViewModel.ActivitySource?
    let onClear: () -> Void
    
    var body: some View {
        VStack(spacing: 0) {
            searchBar
            Divider()
            LogTextView(text: logsText)
        }
    }

    private var allCount: Int { allLogs.count }
    private var appCount: Int { allLogs.filter { $0.source == .app }.count }
    private var extensionCount: Int { allLogs.filter { $0.source == .systemExtension }.count }

    private var searchBar: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.gray)
                TextField("Search system activity...", text: $searchText)
                    .textFieldStyle(.plain)

                if !searchText.isEmpty {
                    Button(action: { searchText = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.gray)
                    }
                    .buttonStyle(.plain)
                }

                Spacer()
                Button("Clear", action: onClear)
            }

            HStack(spacing: 6) {
                Text("Filter:")
                    .font(.caption)
                    .foregroundColor(.secondary)

                FilterChipButton(
                    title: "ALL",
                    isSelected: selectedSource == nil,
                    count: allCount,
                    badgeColor: nil
                ) {
                    selectedSource = nil
                }

                Divider()
                    .frame(height: 14)
                    .padding(.horizontal, 2)

                FilterChipButton(
                    title: "APP",
                    isSelected: selectedSource == .app,
                    count: appCount,
                    badgeColor: .green
                ) {
                    selectedSource = selectedSource == .app ? nil : .app
                }

                FilterChipButton(
                    title: "EXTENSION",
                    isSelected: selectedSource == .systemExtension,
                    count: extensionCount,
                    badgeColor: .purple
                ) {
                    selectedSource = selectedSource == .systemExtension ? nil : .systemExtension
                }

                Spacer()
            }
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
    }

    private var logsText: NSAttributedString {
        let out = NSMutableAttributedString()
        for log in logs {
            out.append(LogText.seg("[\(log.timestamp)] ", .secondaryLabelColor))
            let sourceColor: NSColor = log.source == .app ? .systemGreen : .systemPurple
            out.append(LogText.seg("[\(log.source.rawValue)] ", sourceColor))
            let levelColor: NSColor
            switch log.level.uppercased() {
            case "ERROR":
                levelColor = .systemRed
            case "WARN", "WARNING":
                levelColor = .systemYellow
            default:
                levelColor = .systemBlue
            }
            out.append(LogText.seg("[\(log.level)] ", levelColor))
            out.append(LogText.seg(log.message, .labelColor))
            out.append(LogText.seg("\n", .labelColor))
        }
        return out
    }
}

// builds the colored, monospaced segments shared by both log views
enum LogText {
    static let font = NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)

    static func seg(_ string: String, _ color: NSColor) -> NSAttributedString {
        NSAttributedString(string: string, attributes: [.foregroundColor: color, .font: font])
    }
}

// read-only NSTextView so the whole log behaves like a text area, multi-row
// drag select, select all and copy all work like any text box
struct LogTextView: NSViewRepresentable {
    let text: NSAttributedString

    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSTextView.scrollableTextView()
        scrollView.hasVerticalScroller = true
        scrollView.drawsBackground = false

        if let textView = scrollView.documentView as? NSTextView {
            textView.isEditable = false
            textView.isSelectable = true
            textView.drawsBackground = false
            textView.textContainerInset = NSSize(width: 8, height: 8)
            textView.font = LogText.font
        }
        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        guard let textView = scrollView.documentView as? NSTextView,
              let storage = textView.textStorage else { return }

        // nothing changed, leave the current selection and scroll position alone
        if storage.string == text.string { return }

        // keep the user's selection if it still fits (holds while not trimming),
        // otherwise stick to the bottom so new lines stay in view
        let previousSelection = textView.selectedRanges
        let wasAtBottom = isScrolledToBottom(scrollView)

        storage.setAttributedString(text)

        let length = (text.string as NSString).length
        let validSelection = previousSelection.filter { value in
            let r = value.rangeValue
            return r.location + r.length <= length
        }

        if let sel = validSelection.first, sel.rangeValue.length > 0 {
            textView.selectedRanges = validSelection
        } else if wasAtBottom {
            textView.scrollToEndOfDocument(nil)
        }
    }

    private func isScrolledToBottom(_ scrollView: NSScrollView) -> Bool {
        let docHeight = scrollView.documentView?.bounds.height ?? 0
        let visible = scrollView.contentView.bounds
        return visible.maxY >= docHeight - 24
    }
}
