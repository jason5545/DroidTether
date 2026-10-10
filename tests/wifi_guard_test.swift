// WifiGuard 實機測試：daemon 連不上時，App 只在「標記檔在、Wi-Fi 被關著」時把 Wi-Fi 開回來。
// 用臨時標記檔，不碰 daemon 的標記檔，也不停掉 daemon。會開關 Wi-Fi 幾次，結束時還原成開始的狀態。
//
//   swiftc -O -parse-as-library app/Sources/WifiGuard.swift tests/wifi_guard_test.swift -o build/wifi_guard_test && build/wifi_guard_test

import Foundation

var passed = 0, failed = 0
func check(_ name: String, _ ok: Bool, _ detail: String = "") {
    if ok { passed += 1 } else { failed += 1 }
    print("  \(ok ? "PASS" : "FAIL")  \(name)" + (detail.isEmpty ? "" : "  (\(detail))"))
}

func setPower(_ ifname: String, _ on: Bool) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: WifiGuard.networksetup)
    p.arguments = ["-setairportpower", ifname, on ? "on" : "off"]
    try? p.run()
    p.waitUntilExit()
    for _ in 0..<30 where WifiGuard.power(ifname) != on { usleep(100_000) }
}

@main
struct WifiGuardTest {
    static func main() throws {
        exit(try run())
    }

    static func run() throws -> Int32 {
        let wifi = "en0"
        guard let original = WifiGuard.power(wifi) else {
            print("cannot read Wi-Fi power for \(wifi)")
            return 2
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("wifi-guard-\(getpid())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let marker = dir.appendingPathComponent("config.wifi-off").path
        defer {
            setPower(wifi, original)
            try? FileManager.default.removeItem(at: dir)
        }

        print("== Wi-Fi off, no marker: leave it alone")
        setPower(wifi, false)
        check("returns nil", WifiGuard.restoreIfDaemonTurnedItOff(markerPath: marker) == nil)
        check("Wi-Fi still off", WifiGuard.power(wifi) == false)

        print("== Wi-Fi off, marker with a bad name: leave it alone")
        try "en0; rm -rf /\n".write(toFile: marker, atomically: true, encoding: .utf8)
        check("returns nil", WifiGuard.restoreIfDaemonTurnedItOff(markerPath: marker) == nil)
        check("Wi-Fi still off", WifiGuard.power(wifi) == false)

        print("== Wi-Fi off, marker names \(wifi): turn it back on")
        try "\(wifi)\n".write(toFile: marker, atomically: true, encoding: .utf8)
        let r = WifiGuard.restoreIfDaemonTurnedItOff(markerPath: marker)
        check("returns \(wifi)", r == wifi, "got \(r ?? "nil")")
        check("Wi-Fi on", WifiGuard.power(wifi) == true)
        check("marker left in place for the daemon", FileManager.default.fileExists(atPath: marker))

        print("== Wi-Fi already on: nothing to do")
        check("returns nil", WifiGuard.restoreIfDaemonTurnedItOff(markerPath: marker) == nil)
        check("Wi-Fi still on", WifiGuard.power(wifi) == true)

        print("\n\(passed) passed, \(failed) failed")
        return failed == 0 ? 0 : 1
    }
}
