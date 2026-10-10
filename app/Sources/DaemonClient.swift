import Darwin
import Foundation

/// daemon 回報的狀態，欄位對應 src/control.c 的 status_json()。
struct DaemonStatus: Decodable, Equatable {
    struct Config: Decodable, Equatable {
        var enabled: Bool
        var primary: Bool
        var wifiOff: Bool?  // 0.3.5 起才有
        var dnsMode: String
        var dnsServers: [String]
    }

    var ok: Bool
    var version: String?
    var state: String?
    var device: String?
    var error: String?
    var since: Double?
    var interface: String?
    var ip: String?
    var gateway: String?
    var netmask: String?
    var dns: [String]?
    var dnsFallback: Bool?
    var rxBytes: UInt64?
    var txBytes: UInt64?
    var config: Config?
}

enum DaemonError: Error {
    case unreachable
    case badReply
}

/// 透過 Unix socket 跟 droidtetherd 講話：送一行指令，收一行 JSON。
enum DaemonClient {
    static let socketPath = "/var/run/droidtetherd.sock"

    static func status() throws -> DaemonStatus {
        try decode(send("status"))
    }

    @discardableResult
    static func command(_ line: String) throws -> DaemonStatus {
        try decode(send(line))
    }

    private static func decode(_ data: Data) throws -> DaemonStatus {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        guard let s = try? decoder.decode(DaemonStatus.self, from: data) else { throw DaemonError.badReply }
        return s
    }

    private static func send(_ command: String) throws -> Data {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw DaemonError.unreachable }
        defer { close(fd) }

        var tv = timeval(tv_sec: 3, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let path = Array(socketPath.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: path.prefix(raw.count - 1))
        }
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { throw DaemonError.unreachable }

        let line = Array((command + "\n").utf8)
        guard write(fd, line, line.count) == line.count else { throw DaemonError.unreachable }

        var data = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = read(fd, &buf, buf.count)
            if n <= 0 { break }
            data.append(buf, count: n)
            if buf[..<n].contains(UInt8(ascii: "\n")) { break }
        }
        guard !data.isEmpty else { throw DaemonError.badReply }
        return data
    }
}
