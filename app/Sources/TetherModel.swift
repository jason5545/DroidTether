import AppKit
import Foundation
import ServiceManagement

/// 一筆流量取樣（每秒一筆）。
struct TrafficSample: Identifiable {
    let id: Int
    let date: Date
    let down: Double  // bytes/s
    let up: Double
}

/// 選單列 App 的狀態來源：每秒向 daemon 要一次狀態、記流量歷史、量延遲，並負責註冊背景服務。
@MainActor
final class TetherModel: ObservableObject {
    static let shared = TetherModel()
    static let daemonPlist = "io.github.jason5545.droidtether.plist"
    static let logPath = "/Library/Logs/DroidTether.log"
    static let historySeconds = 120
    static let internetPingHost = "1.1.1.1"

    enum ServiceState {
        case enabled, requiresApproval, notRegistered, failed
    }

    @Published private(set) var status: DaemonStatus?
    @Published private(set) var serviceState: ServiceState = .notRegistered
    @Published private(set) var rxRate: Double = 0
    @Published private(set) var txRate: Double = 0
    @Published private(set) var launchAtLogin = SMAppService.mainApp.status == .enabled
    @Published private(set) var history: [TrafficSample] = []
    @Published private(set) var phonePing: Double?
    @Published private(set) var internetPing: Double?

    private let service = SMAppService.daemon(plistName: TetherModel.daemonPlist)
    private var timer: Timer?
    private var lastSample: (date: Date, rx: UInt64, tx: UInt64)?
    private var restartedStaleDaemon = false
    private var sampleID = 0
    private var pingInFlight = false
    private var tick = 0

    let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"

    init() {
        registerDaemon()
        refresh()
        let t = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        RunLoop.main.add(t, forMode: .common)  // 面板打開時也要繼續更新
        timer = t
    }

    // MARK: - 狀態

    var state: String { status?.state ?? "unreachable" }
    var isConnected: Bool { state == "connected" }
    var isEnabled: Bool { status?.config?.enabled ?? true }

    func refresh() {
        tick += 1
        if tick % 5 == 0 { updateServiceState() }  // 背景服務狀態不常變，不用每秒查
        Task.detached {
            let s = try? DaemonClient.status()
            await MainActor.run { self.apply(s) }
        }
    }

    private func apply(_ s: DaemonStatus?) {
        if let s, let rx = s.rxBytes, let tx = s.txBytes, s.state == "connected" {
            let now = Date()
            if let last = lastSample, rx >= last.rx, tx >= last.tx {
                let dt = now.timeIntervalSince(last.date)
                if dt > 0.5 {
                    rxRate = Double(rx - last.rx) / dt
                    txRate = Double(tx - last.tx) / dt
                    record(now)
                }
            } else if lastSample != nil {
                history.removeAll()  // 計數歸零代表換了一次連線
            }
            lastSample = (now, rx, tx)
            if tick % 2 == 0 { measurePing(interface: s.interface, gateway: s.gateway) }
        } else {
            lastSample = nil
            rxRate = 0
            txRate = 0
            phonePing = nil
            internetPing = nil
            if !history.isEmpty { history.removeAll() }
        }
        if status != s { status = s }
        restartDaemonIfStale(s)
    }

    private func record(_ date: Date) {
        sampleID += 1
        history.append(TrafficSample(id: sampleID, date: date, down: rxRate, up: txRate))
        if history.count > Self.historySeconds { history.removeFirst(history.count - Self.historySeconds) }
    }

    private func measurePing(interface: String?, gateway: String?) {
        guard !pingInFlight, let gateway else { return }
        pingInFlight = true
        Task.detached {
            async let phone = Pinger.ping(gateway, interface: interface)
            async let internet = Pinger.ping(TetherModel.internetPingHost, interface: interface)
            let (p, i) = await (phone, internet)
            await MainActor.run {
                self.phonePing = p
                self.internetPing = i
                self.pingInFlight = false
            }
        }
    }

    /// App 更新後，舊版 daemon 還在跑；請它結束，launchd 會用 App 裡的新版重新啟動。
    private func restartDaemonIfStale(_ s: DaemonStatus?) {
        guard !restartedStaleDaemon, serviceState == .enabled, let v = s?.version, v != "dev", v != appVersion else { return }
        restartedStaleDaemon = true
        Task.detached { try? DaemonClient.command("quit") }
    }

    // MARK: - 背景服務

    private func updateServiceState() {
        switch service.status {
        case .enabled: serviceState = .enabled
        case .requiresApproval: serviceState = .requiresApproval
        case .notRegistered, .notFound: if serviceState != .failed { serviceState = .notRegistered }
        @unknown default: serviceState = .notRegistered
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    func registerDaemon() {
        guard service.status != .enabled else {
            updateServiceState()
            return
        }
        do {
            try service.register()
        } catch {
            NSLog("DroidTether: daemon register failed: \(error)")
        }
        updateServiceState()
        if service.status == .notRegistered || service.status == .notFound { serviceState = .failed }
    }

    func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    func setLaunchAtLogin(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            NSLog("DroidTether: login item change failed: \(error)")
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    // MARK: - 指令

    private func send(_ line: String) {
        Task.detached {
            let s = try? DaemonClient.command(line)
            await MainActor.run {
                if let s, s.state != nil { self.apply(s) } else { self.refresh() }
            }
        }
    }

    func setEnabled(_ on: Bool) { send("set enabled \(on ? 1 : 0)") }
    func setPrimary(_ on: Bool) { send("set primary \(on ? 1 : 0)") }
    func reconnect() { send("reconnect") }
    func useCustomDNS(_ servers: [String]) { send("set dns " + servers.joined(separator: ",")) }
    func usePhoneDNS() { send("set dns phone") }

    func openLog() {
        NSWorkspace.shared.open(URL(fileURLWithPath: TetherModel.logPath))
    }
}
