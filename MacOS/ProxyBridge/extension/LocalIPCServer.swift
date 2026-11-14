import Foundation
import Network

final class LocalIPCServer {
    static let shared = LocalIPCServer()
    static let port: UInt16 = 58223

    private static let maxHeaderBytes = 16 * 1024
    private static let maxBodyBytes = 1024 * 1024
    private static let headerTerminator = Data("\r\n\r\n".utf8)
    private static let maxRequestBytes = maxHeaderBytes + headerTerminator.count + maxBodyBytes

    private struct HTTPResponse {
        let statusCode: Int
        let reason: String
        let body: Data
    }

    private var listener: NWListener?
    private let queue = DispatchQueue(label: "com.interceptsuite.ProxyBridge.ipcServer")
    private let tokenLock = NSLock()
    private var token = ""

    var authorizationToken: String {
        tokenLock.lock()
        defer { tokenLock.unlock() }
        return token
    }

    var onGetLogs: (() -> [[String: String]])?
    var onGetHealth: (() -> [String: Any])?
    var onSetRules: (([[String: Any]]) -> Int)?
    var onSetConfigs: (([[String: Any]]) -> Void)?
    var onSetTrafficLogging: ((Bool) -> Void)?
    var onClearRules: (() -> Void)?

    func start(authorizationToken: String) {
        guard listener == nil else { return }
        guard authorizationToken.utf8.count >= 32 else {
            NSLog("[ProxyBridge IPC] Refusing to start without a strong authorization token")
            return
        }
        setAuthorizationToken(authorizationToken)

        do {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            let port = NWEndpoint.Port(rawValue: LocalIPCServer.port)!
            params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: port)
            listener = try NWListener(using: params)

            listener?.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    NSLog("[ProxyBridge IPC] Server ready on 127.0.0.1:\(LocalIPCServer.port)")
                case .failed(let error):
                    self?.listener?.cancel()
                    self?.listener = nil
                    self?.clearAuthorizationToken()
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
            clearAuthorizationToken()
            NSLog("[ProxyBridge IPC] Failed to start NWListener: \(error)")
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        clearAuthorizationToken()
    }

    private func setAuthorizationToken(_ newToken: String) {
        tokenLock.lock()
        token = newToken
        tokenLock.unlock()
    }

    private func clearAuthorizationToken() {
        tokenLock.lock()
        token = ""
        tokenLock.unlock()
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

            if data.count > Self.maxRequestBytes {
                self.sendResponse(
                    self.errorResponse(statusCode: 413, reason: "Payload Too Large", message: "Request is too large"),
                    over: connection
                )
                return
            }

            guard let headerRange = data.range(of: Self.headerTerminator) else {
                if data.count > Self.maxHeaderBytes {
                    self.sendResponse(
                        self.errorResponse(statusCode: 431, reason: "Request Header Fields Too Large", message: "Headers are too large"),
                        over: connection
                    )
                } else if isComplete {
                    self.sendResponse(
                        self.errorResponse(statusCode: 400, reason: "Bad Request", message: "Incomplete HTTP headers"),
                        over: connection
                    )
                } else {
                    self.readHTTPRequest(connection: connection, accumulatedData: data)
                }
                return
            }

            let headerData = data.subdata(in: data.startIndex..<headerRange.lowerBound)
            guard headerData.count <= Self.maxHeaderBytes else {
                self.sendResponse(
                    self.errorResponse(statusCode: 431, reason: "Request Header Fields Too Large", message: "Headers are too large"),
                    over: connection
                )
                return
            }
            guard let headers = String(data: headerData, encoding: .utf8) else {
                self.sendResponse(
                    self.errorResponse(statusCode: 400, reason: "Bad Request", message: "Headers must be UTF-8"),
                    over: connection
                )
                return
            }
            guard let contentLength = self.contentLength(in: headers) else {
                self.sendResponse(
                    self.errorResponse(statusCode: 400, reason: "Bad Request", message: "Invalid Content-Length"),
                    over: connection
                )
                return
            }
            guard contentLength <= Self.maxBodyBytes else {
                self.sendResponse(
                    self.errorResponse(statusCode: 413, reason: "Payload Too Large", message: "Request body is too large"),
                    over: connection
                )
                return
            }

            let bodyStart = headerRange.upperBound
            let availableBodyBytes = data.distance(from: bodyStart, to: data.endIndex)
            guard availableBodyBytes >= contentLength else {
                if isComplete {
                    self.sendResponse(
                        self.errorResponse(statusCode: 400, reason: "Bad Request", message: "Incomplete request body"),
                        over: connection
                    )
                } else {
                    self.readHTTPRequest(connection: connection, accumulatedData: data)
                }
                return
            }

            let bodyEnd = data.index(bodyStart, offsetBy: contentLength)
            let bodyData = contentLength == 0 ? nil : data.subdata(in: bodyStart..<bodyEnd)
            self.sendResponse(self.processRequest(headers: headers, bodyData: bodyData), over: connection)
        }
    }

    private func contentLength(in headers: String) -> Int? {
        var parsedLength: Int?
        for line in headers.components(separatedBy: "\r\n").dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces)
            guard name.caseInsensitiveCompare("Content-Length") == .orderedSame else { continue }
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard let length = Int(value), length >= 0 else { return nil }
            if let existing = parsedLength, existing != length { return nil }
            parsedLength = length
        }
        return parsedLength ?? 0
    }

    private func processRequest(headers: String, bodyData: Data?) -> HTTPResponse {
        let lines = headers.components(separatedBy: "\r\n")
        guard let firstLine = lines.first else {
            return errorResponse(statusCode: 400, reason: "Bad Request", message: "Empty request")
        }
        guard isAuthorized(lines: lines) else {
            return errorResponse(statusCode: 401, reason: "Unauthorized", message: "Missing or invalid authorization")
        }

        let parts = firstLine.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count == 3 else {
            return errorResponse(statusCode: 400, reason: "Bad Request", message: "Invalid HTTP request line")
        }

        let method = String(parts[0])
        let path = String(parts[1])

        switch (method, path) {
        case ("GET", "/logs"):
            let logs = onGetLogs?() ?? []
            return jsonResponse(statusCode: 200, reason: "OK", object: logs)

        case ("GET", "/health"):
            let health = onGetHealth?() ?? ["status": "ok"]
            return jsonResponse(statusCode: 200, reason: "OK", object: health)

        case ("POST", "/rules"):
            if let data = bodyData,
               let raw = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
                let count = onSetRules?(raw) ?? 0
                return jsonResponse(statusCode: 200, reason: "OK", object: ["status": "ok", "count": count])
            }
            return errorResponse(statusCode: 400, reason: "Bad Request", message: "Invalid rules JSON")

        case ("POST", "/configs"):
            if let data = bodyData,
               let raw = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
                onSetConfigs?(raw)
                return jsonResponse(statusCode: 200, reason: "OK", object: ["status": "ok"])
            }
            return errorResponse(statusCode: 400, reason: "Bad Request", message: "Invalid configs JSON")

        case ("POST", "/trafficLogging"):
            if let data = bodyData,
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let enabled = json["enabled"] as? Bool {
                onSetTrafficLogging?(enabled)
                return jsonResponse(statusCode: 200, reason: "OK", object: ["status": "ok"])
            }
            return errorResponse(statusCode: 400, reason: "Bad Request", message: "Invalid logging JSON")

        case ("POST", "/clearRules"):
            onClearRules?()
            return jsonResponse(statusCode: 200, reason: "OK", object: ["status": "ok"])

        default:
            return errorResponse(statusCode: 404, reason: "Not Found", message: "Not found")
        }
    }

    private func isAuthorized(lines: [String]) -> Bool {
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces)
            guard name.caseInsensitiveCompare("Authorization") == .orderedSame else { continue }
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            let parts = value.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
            guard parts.count == 2,
                  parts[0].caseInsensitiveCompare("Bearer") == .orderedSame else {
                return false
            }
            return constantTimeEqual(String(parts[1]), authorizationToken)
        }
        return false
    }

    private func constantTimeEqual(_ lhs: String, _ rhs: String) -> Bool {
        let left = Array(lhs.utf8)
        let right = Array(rhs.utf8)
        guard !left.isEmpty, left.count == right.count else { return false }
        var difference: UInt8 = 0
        for index in left.indices {
            difference |= left[index] ^ right[index]
        }
        return difference == 0
    }

    private func jsonResponse(statusCode: Int, reason: String, object: Any) -> HTTPResponse {
        let body = (try? JSONSerialization.data(withJSONObject: object)) ?? Data("{\"status\":\"error\"}".utf8)
        return HTTPResponse(statusCode: statusCode, reason: reason, body: body)
    }

    private func errorResponse(statusCode: Int, reason: String, message: String) -> HTTPResponse {
        jsonResponse(
            statusCode: statusCode,
            reason: reason,
            object: ["status": "error", "message": message]
        )
    }

    private func sendResponse(_ response: HTTPResponse, over connection: NWConnection) {
        var headers = "HTTP/1.1 \(response.statusCode) \(response.reason)\r\n"
        headers += "Content-Type: application/json\r\n"
        headers += "Content-Length: \(response.body.count)\r\n"
        headers += "Cache-Control: no-store\r\n"
        if response.statusCode == 401 {
            headers += "WWW-Authenticate: Bearer\r\n"
        }
        headers += "Connection: close\r\n\r\n"

        var data = Data(headers.utf8)
        data.append(response.body)
        connection.send(content: data, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }
}
