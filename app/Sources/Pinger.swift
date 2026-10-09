import Foundation

/// 用系統的 /sbin/ping 量延遲。-b 綁定 tether 介面，就算它不是主要連線，量到的也是手機那條路。
enum Pinger {
    /// 回傳毫秒；逾時或失敗回傳 nil。
    static func ping(_ host: String, interface: String?) -> Double? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/sbin/ping")
        var args = ["-n", "-q", "-c", "1", "-t", "2"]
        if let interface { args += ["-b", interface] }
        p.arguments = args + [host]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
        } catch {
            return nil
        }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0, let text = String(data: data, encoding: .utf8) else { return nil }
        // round-trip min/avg/max/stddev = 15.102/15.102/15.102/0.000 ms
        guard let line = text.split(separator: "\n").first(where: { $0.contains("min/avg/max") }),
              let values = line.split(separator: "=").last?.trimmingCharacters(in: .whitespaces),
              let avg = values.split(separator: "/").dropFirst().first
        else { return nil }
        return Double(avg)
    }
}
