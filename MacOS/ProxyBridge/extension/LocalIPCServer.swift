import Foundation
import Network

final class LocalIPCServer {
    static let shared = LocalIPCServer()
    static let port: UInt16 = 58223
    
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "com.interceptsuite.ProxyBridge.ipcServer")
    
    var onGetLogs: (() -> [[String: String]])?
    var onSetRules: (([[String: Any]]) -> Int)?
    var onSetConfigs: (([[String: Any]]) -> Void)?
    var onSetTrafficLogging: ((Bool) -> Void)?
    var onClearRules: (() -> Void)?
    
    func start() {
        guard listener == nil else { return }
        do {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            let port = NWEndpoint.Port(rawValue: LocalIPCServer.port)!
            listener = try NWListener(using: params, on: port)
            
            listener?.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    NSLog("[ProxyBridge IPC] Server ready on 127.0.0.1:\(LocalIPCServer.port)")
                case .failed(let error):
                    NSLog("[ProxyBridge IPC] Server failed: \(error)")
                default:
                    break
                }
            }
            
            listener?.newConnectionHandler = { [weak self] connection in
                self?.handleConnection(connection)
            }
            
            listener?.start(queue: queue)
        } catch {
            NSLog("[ProxyBridge IPC] Failed to start NWListener: \(error)")
        }
    }
    
    func stop() {
        listener?.cancel()
        listener = nil
    }
    
    private func handleConnection(_ connection: NWConnection) {
        connection.start(queue: queue)
        readHTTPRequest(connection: connection, accumulatedData: Data())
    }
    
    private func readHTTPRequest(connection: NWConnection, accumulatedData: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, error in
            guard let self = self, error == nil, let chunk = content, !chunk.isEmpty else {
                connection.cancel()
                return
            }
            
            var data = accumulatedData
            data.append(chunk)
            
            guard let requestStr = String(data: data, encoding: .utf8) else {
                if data.count < 1048576 && !isComplete {
                    self.readHTTPRequest(connection: connection, accumulatedData: data)
                } else {
                    connection.cancel()
                }
                return
            }
            
            if let headerEndRange = requestStr.range(of: "\r\n\r\n") {
                let headersStr = String(requestStr[..<headerEndRange.lowerBound])
                var expectedContentLength = 0
                for line in headersStr.components(separatedBy: "\r\n") {
                    let lower = line.lowercased()
                    if lower.hasPrefix("content-length:") {
                        let valStr = line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)
                        expectedContentLength = Int(valStr) ?? 0
                    }
                }
                
                let bodyOffset = headerEndRange.upperBound
                let currentBodyStr = String(requestStr[bodyOffset...])
                let currentBodyBytesCount = currentBodyStr.utf8.count
                
                if currentBodyBytesCount < expectedContentLength && !isComplete {
                    self.readHTTPRequest(connection: connection, accumulatedData: data)
                    return
                }
                
                let bodyData = currentBodyStr.data(using: .utf8)
                let responseData = self.processRequest(headersStr: headersStr, bodyData: bodyData)
                let httpHeader = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(responseData.count)\r\nConnection: close\r\n\r\n"
                var fullResponse = httpHeader.data(using: .utf8)!
                fullResponse.append(responseData)
                
                connection.send(content: fullResponse, completion: .contentProcessed({ _ in
                    connection.cancel()
                }))
            } else {
                if !isComplete {
                    self.readHTTPRequest(connection: connection, accumulatedData: data)
                } else {
                    connection.cancel()
                }
            }
        }
    }
    
    private func processRequest(headersStr: String, bodyData: Data?) -> Data {
        let lines = headersStr.components(separatedBy: "\r\n")
        guard let firstLine = lines.first else {
            return "{\"status\":\"error\",\"message\":\"Empty request\"}".data(using: .utf8)!
        }
        
        let parts = firstLine.components(separatedBy: " ")
        guard parts.count >= 2 else {
            return "{\"status\":\"error\",\"message\":\"Invalid HTTP\"}".data(using: .utf8)!
        }
        
        let method = parts[0]
        let path = parts[1]
        
        switch (method, path) {
        case ("GET", "/logs"):
            let logs = onGetLogs?() ?? []
            if let json = try? JSONSerialization.data(withJSONObject: logs) {
                return json
            }
            return "[]".data(using: .utf8)!
            
        case ("POST", "/rules"):
            if let data = bodyData,
               let raw = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
                let count = onSetRules?(raw) ?? 0
                return "{\"status\":\"ok\",\"count\":\(count)}".data(using: .utf8)!
            }
            return "{\"status\":\"error\",\"message\":\"Invalid rules JSON\"}".data(using: .utf8)!
            
        case ("POST", "/configs"):
            if let data = bodyData,
               let raw = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
                onSetConfigs?(raw)
                return "{\"status\":\"ok\"}".data(using: .utf8)!
            }
            return "{\"status\":\"error\",\"message\":\"Invalid configs JSON\"}".data(using: .utf8)!
            
        case ("POST", "/trafficLogging"):
            if let data = bodyData,
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let enabled = json["enabled"] as? Bool {
                onSetTrafficLogging?(enabled)
                return "{\"status\":\"ok\"}".data(using: .utf8)!
            }
            return "{\"status\":\"error\",\"message\":\"Invalid logging JSON\"}".data(using: .utf8)!
            
        case ("POST", "/clearRules"):
            onClearRules?()
            return "{\"status\":\"ok\"}".data(using: .utf8)!
            
        default:
            return "{\"status\":\"error\",\"message\":\"Not found\"}".data(using: .utf8)!
        }
    }
}
