import Foundation

/// daemon 連不上又起不來時（例如換簽章後 launchd 擋下），把它關掉的 Wi-Fi 開回來。
/// daemon 關 Wi-Fi 前會寫標記檔，記下介面名稱；只有標記檔在、Wi-Fi 真的關著時才動手。
/// 標記檔是 root 的，這裡不刪：daemon 回來後讀到它，看到 Wi-Fi 開著，就當成使用者自己開的，不會再關。
enum WifiGuard {
    static let markerPath = "/Library/Application Support/DroidTether/config.wifi-off"
    static let networksetup = "/usr/sbin/networksetup"

    /// 有開回來就回傳介面名稱。
    static func restoreIfDaemonTurnedItOff(markerPath: String = WifiGuard.markerPath) -> String? {
        guard let text = try? String(contentsOfFile: markerPath, encoding: .utf8) else { return nil }
        let ifname = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !ifname.isEmpty, ifname.count < 16, ifname.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) else {
            return nil
        }
        guard power(ifname) == false else { return nil }
        _ = run(["-setairportpower", ifname, "on"])
        return power(ifname) == true ? ifname : nil
    }

    /// true 開、false 關、nil 讀不到。
    static func power(_ ifname: String) -> Bool? {
        guard let out = run(["-getairportpower", ifname]) else { return nil }
        if out.hasSuffix(" On") { return true }
        if out.hasSuffix(" Off") { return false }
        return nil
    }

    private static func run(_ args: [String]) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: networksetup)
        p.arguments = args
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
        return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
