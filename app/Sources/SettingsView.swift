import Darwin
import SwiftUI

struct SettingsView: View {
    @ObservedObject var model: TetherModel
    @State private var customDNS = ""
    @State private var dnsError = false

    private var config: DaemonStatus.Config? { model.status?.config }

    var body: some View {
        Form {
            Section {
                Toggle("Open DroidTether at login", isOn: Binding(
                    get: { model.launchAtLogin },
                    set: { model.setLaunchAtLogin($0) }))
            }

            Section {
                Toggle(isOn: Binding(
                    get: { config?.primary ?? true },
                    set: { model.setPrimary($0) })) {
                    Text("Use as the main connection")
                    Text("All traffic and DNS go through the phone. Turn off to keep Wi-Fi as the main connection.")
                }

                Picker("DNS", selection: Binding(
                    get: { config?.dnsMode ?? "phone" },
                    set: { mode in
                        if mode == "phone" {
                            model.usePhoneDNS()
                        } else if let servers = parsedDNS(), !servers.isEmpty {
                            model.useCustomDNS(servers)
                        } else {
                            customDNS = customDNS.isEmpty ? "1.1.1.1, 8.8.8.8" : customDNS
                            if let servers = parsedDNS() { model.useCustomDNS(servers) }
                        }
                    })) {
                    Text("Provided by the phone").tag("phone")
                    Text("Custom").tag("custom")
                }
                .pickerStyle(.radioGroup)

                if config?.dnsMode == "phone", model.status?.dnsFallback == true {
                    Text("The phone does not answer DNS queries, so 8.8.8.8 and 8.8.4.4 are used. DroidTether switches back once the phone answers.")
                        .foregroundStyle(.secondary)
                }

                if config?.dnsMode == "custom" {
                    HStack {
                        TextField("1.1.1.1, 8.8.8.8", text: $customDNS)
                            .onSubmit(applyCustomDNS)
                        Button("Apply", action: applyCustomDNS)
                    }
                    if dnsError {
                        Text("Enter up to four IPv4 addresses separated by commas.")
                            .foregroundStyle(.red)
                    }
                }
            } header: {
                Text("Network")
            } footer: {
                Text("Changing these settings reconnects USB tethering for a moment.")
                    .foregroundStyle(.secondary)
            }

            Section {
                Toggle(isOn: Binding(
                    get: { config?.wifiOff ?? false },
                    set: { model.setWifiOff($0) })) {
                    Text("Turn off Wi-Fi while connected")
                    Text("Wi-Fi comes back on when you unplug the phone or pause. Only when the phone is the main connection.")
                }
                .disabled(config?.wifiOff == nil || !(config?.primary ?? true))
            }

            Section {
                LabeledContent("App", value: model.appVersion)
                LabeledContent("Background service", value: model.status?.version ?? "—")
                Button("Open Log") { model.openLog() }
            } header: {
                Text("About")
            }
        }
        .formStyle(.grouped)
        .frame(width: 440)
        .fixedSize(horizontal: false, vertical: true)
        .onAppear { customDNS = config?.dnsServers.joined(separator: ", ") ?? "" }
        .onChange(of: config?.dnsServers ?? []) { _, servers in
            if !servers.isEmpty { customDNS = servers.joined(separator: ", ") }
        }
    }

    private func parsedDNS() -> [String]? {
        let parts = customDNS.split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init)
        guard !parts.isEmpty, parts.count <= 4 else { return nil }
        for p in parts {
            var addr = in_addr()
            guard inet_pton(AF_INET, p, &addr) == 1 else { return nil }
        }
        return parts
    }

    private func applyCustomDNS() {
        guard let servers = parsedDNS() else {
            dnsError = true
            return
        }
        dnsError = false
        model.useCustomDNS(servers)
    }
}
