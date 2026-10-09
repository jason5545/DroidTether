import AppKit
import SwiftUI

@main
struct DroidTetherApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = TetherModel.shared

    init() {
        // 除錯用：DroidTether --snapshot <路徑前綴> [秒數]，等資料累積後輸出面板的淺色、深色截圖就結束。
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--snapshot"), i + 1 < args.count {
            let prefix = args[i + 1]
            let wait = i + 2 < args.count ? Double(args[i + 2]) ?? 15 : 15
            Task { @MainActor in
                let m = TetherModel()
                try? await Task.sleep(for: .seconds(wait))
                for (scheme, name, bg) in [(ColorScheme.light, "light", Color(white: 0.95)), (.dark, "dark", Color(white: 0.17))] {
                    let renderer = ImageRenderer(content: PanelView(model: m).background(bg).environment(\.colorScheme, scheme))
                    renderer.scale = 2
                    if let tiff = renderer.nsImage?.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
                       let png = rep.representation(using: .png, properties: [:]) {
                        try? png.write(to: URL(fileURLWithPath: "\(prefix)-\(name).png"))
                    }
                }
                // 選單列圖示四種狀態，放大 4 倍輸出
                for (style, name) in [(MenuBarIcon.Style.on, "on"), (.connecting, "connecting"), (.off, "off"), (.inactive, "inactive")] {
                    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 72, pixelsHigh: 72, bitsPerSample: 8,
                                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                                               bytesPerRow: 0, bitsPerPixel: 0)!
                    NSGraphicsContext.saveGraphicsState()
                    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
                    NSColor.white.setFill()
                    NSRect(x: 0, y: 0, width: 72, height: 72).fill()
                    MenuBarIcon.image(style).draw(in: NSRect(x: 0, y: 0, width: 72, height: 72))
                    NSGraphicsContext.restoreGraphicsState()
                    try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: "\(prefix)-icon-\(name).png"))
                }
                exit(0)
            }
        }
    }

    var body: some Scene {
        MenuBarExtra {
            PanelView(model: model)
        } label: {
            Image(nsImage: menuBarImage)
        }
        .menuBarExtraStyle(.window)
    }

    private var menuBarImage: NSImage {
        switch model.state {
        case "connected": return MenuBarIcon.image(.on)
        case "connecting": return MenuBarIcon.image(.connecting)
        case "disabled", "unreachable": return MenuBarIcon.image(.inactive)
        default: return MenuBarIcon.image(.off)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    /// 使用者從 Finder / Spotlight 再打開已經在跑的 App，就直接給設定視窗。
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        SettingsWindow.show()
        return false
    }
}

/// 設定視窗由 AppKit 直接管理，選單列面板和重新打開 App 都走這裡。
@MainActor
enum SettingsWindow {
    private static var window: NSWindow?

    static func show() {
        if window == nil {
            let w = NSWindow(contentViewController: NSHostingController(rootView: SettingsView(model: .shared)))
            w.title = NSLocalizedString("DroidTether Settings", comment: "")
            w.styleMask = [.titled, .closable]
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
}

/// 點選單列圖示後彈出的面板。
struct PanelView: View {
    @ObservedObject var model: TetherModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header

            if model.serviceState == .requiresApproval {
                notice(NSLocalizedString("Allow DroidTether in System Settings to start the background service.", comment: ""),
                       action: NSLocalizedString("Open System Settings", comment: "")) { model.openLoginItemsSettings() }
            } else if model.serviceState == .failed {
                notice(NSLocalizedString("The background service could not be installed.", comment: ""),
                       action: NSLocalizedString("Retry", comment: "")) { model.registerDaemon() }
            }

            if model.isConnected {
                traffic
                ping
            }

            Divider()
            actions
        }
        .padding(14)
        .frame(width: 320)
    }

    // MARK: - 狀態

    private var header: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: statusSymbol.name)
                .font(.system(size: 22))
                .foregroundStyle(statusSymbol.color)
                .frame(width: 26)
            VStack(alignment: .leading, spacing: 3) {
                Text(statusTitle).font(.headline)
                ForEach(statusDetails, id: \.self) { line in
                    Text(line).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            Spacer(minLength: 0)
            // 用純 SwiftUI 畫，不用 Button：外觀一樣，截圖（ImageRenderer）也畫得出來。
            Image(systemName: "gearshape")
                .font(.system(size: 14))
                .foregroundStyle(.secondary)
                .frame(width: 22, height: 22)
                .contentShape(Rectangle())
                .onTapGesture { SettingsWindow.show() }
                .help(Text("Settings…"))
                .accessibilityLabel(Text("Settings…"))
                .accessibilityAddTraits(.isButton)
        }
    }

    private var statusSymbol: (name: String, color: Color) {
        switch model.state {
        case "connected": return ("checkmark.circle.fill", .green)
        case "connecting": return ("arrow.triangle.2.circlepath.circle.fill", .orange)
        case "phone_no_tether", "busy": return ("exclamationmark.circle.fill", .orange)
        case "disabled": return ("pause.circle.fill", .secondary)
        case "waiting", "starting": return ("cable.connector", .secondary)
        default: return ("xmark.circle.fill", .red)
        }
    }

    private var statusTitle: String {
        let device = model.status?.device ?? ""
        switch model.state {
        case "connected": return String(format: NSLocalizedString("Connected to %@", comment: ""), device)
        case "connecting": return String(format: NSLocalizedString("Connecting to %@…", comment: ""), device)
        case "phone_no_tether": return String(format: NSLocalizedString("%@ is connected", comment: ""), device)
        case "busy": return String(format: NSLocalizedString("%@ is in use by another app", comment: ""), device)
        case "waiting", "starting": return NSLocalizedString("Waiting for an Android phone", comment: "")
        case "disabled": return NSLocalizedString("USB tethering paused", comment: "")
        default: return NSLocalizedString("Background service not running", comment: "")
        }
    }

    private var statusDetails: [String] {
        let s = model.status
        switch model.state {
        case "connected":
            var lines: [String] = []
            if let ip = s?.ip { lines.append("IP \(ip)") }
            if let dns = s?.dns, !dns.isEmpty { lines.append("DNS " + dns.joined(separator: ", ")) }
            if s?.config?.primary == false { lines.append(NSLocalizedString("Not used as the main connection", comment: "")) }
            return lines
        case "connecting":
            if let err = s?.error, !err.isEmpty { return [Self.errorText(err)] }
            return []
        case "phone_no_tether": return [NSLocalizedString("Turn on USB tethering on the phone", comment: "")]
        case "busy": return [NSLocalizedString("Quit other tethering apps (e.g. MacTethering)", comment: "")]
        default: return []
        }
    }

    private func notice(_ text: String, action: String, perform: @escaping () -> Void) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(text).font(.callout)
            Button(action, action: perform)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - 流量與延遲

    private var traffic: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 14) {
                legend(color: TrafficColor.down, label: NSLocalizedString("Download", comment: ""), value: model.rxRate)
                legend(color: TrafficColor.up, label: NSLocalizedString("Upload", comment: ""), value: model.txRate)
                Spacer(minLength: 0)
            }
            TrafficChart(samples: model.history)
                .frame(height: 90)
            Text("Last 2 minutes").font(.caption2).foregroundStyle(.tertiary)
        }
    }

    private func legend(color: Color, label: String, value: Double) -> some View {
        HStack(spacing: 5) {
            RoundedRectangle(cornerRadius: 2).fill(color).frame(width: 10, height: 3)
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(Rate.text(value)).font(.caption.monospacedDigit())
        }
    }

    private var ping: some View {
        HStack(spacing: 14) {
            Label("Ping", systemImage: "stopwatch").font(.caption).foregroundStyle(.secondary)
            pingValue(NSLocalizedString("Phone", comment: ""), model.phonePing)
            pingValue(NSLocalizedString("Internet", comment: ""), model.internetPing)
            Spacer(minLength: 0)
        }
        .help(Text("Phone: latency over the USB cable. Internet: latency to 1.1.1.1 through the phone."))
    }

    private func pingValue(_ label: String, _ ms: Double?) -> some View {
        HStack(spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(ms.map { $0 < 1 ? "<1 ms" : String(format: "%.0f ms", $0) } ?? "—").font(.caption.monospacedDigit())
        }
    }

    // MARK: - 操作

    private var actions: some View {
        HStack {
            if model.status != nil {
                Button(model.isEnabled ? NSLocalizedString("Pause", comment: "") : NSLocalizedString("Resume", comment: "")) {
                    model.setEnabled(!model.isEnabled)
                }
                Button("Reconnect") { model.reconnect() }
                    .disabled(!model.isEnabled)
            }
            Spacer()
            Button("Quit") { NSApp.terminate(nil) }
        }
        .controlSize(.small)
    }

    static func errorText(_ code: String) -> String {
        switch code {
        case "dhcp_failed": return NSLocalizedString("The phone did not assign an address; check that USB tethering is on", comment: "")
        case "rndis_failed": return NSLocalizedString("Could not talk to the phone over USB", comment: "")
        case "interface_failed": return NSLocalizedString("Could not create the network interface", comment: "")
        case "netcfg_failed": return NSLocalizedString("Could not apply network settings", comment: "")
        default: return code
        }
    }
}
