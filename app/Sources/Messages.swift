import AppKit
import SwiftUI
import UserNotifications

// 簡訊視窗：左邊是對話列表，右邊是對話內容和輸入框。收發都交給 daemon（src/control.c 的 sms 指令）。

/// 字數與分段，規則跟 src/sms.c 一樣：GSM 7-bit 一則 160 個（分段 153），有中文就用 UCS-2，一則 70 個（分段 67），最多 10 段。
enum SMSCounter {
    static let maxParts = 10

    private static let gsm: Set<UInt32> = {
        var s: Set<UInt32> = [0x40, 0xA3, 0x24, 0xA5, 0xE8, 0xE9, 0xF9, 0xEC, 0xF2, 0xC7, 0x0A, 0xD8, 0xF8, 0x0D, 0xC5, 0xE5,
                              0x394, 0x5F, 0x3A6, 0x393, 0x39B, 0x3A9, 0x3A0, 0x3A8, 0x3A3, 0x398, 0x39E, 0xC6, 0xE6, 0xDF,
                              0xC9, 0x20, 0x21, 0x22, 0x23, 0xA4, 0xA1, 0xC4, 0xD6, 0xD1, 0xDC, 0xA7, 0xBF, 0xE4, 0xF6, 0xF1,
                              0xFC, 0xE0]
        s.formUnion(0x25...0x3F)
        s.formUnion(0x41...0x5A)
        s.formUnion(0x61...0x7A)
        return s
    }()
    private static let gsmExtension: Set<UInt32> = [0x0C, 0x5E, 0x7B, 0x7D, 0x5C, 0x5B, 0x7E, 0x5D, 0x7C, 0x20AC]

    struct Count {
        var parts: Int
        var ucs2: Bool
        var left: Int  // 這一段還放得下幾個（GSM 的擴充字元算兩個）
    }

    static func count(_ text: String) -> Count {
        var septets: [Bool] = []  // true 是擴充字元前面的 escape
        for u in text.unicodeScalars {
            if gsm.contains(u.value) {
                septets.append(false)
            } else if gsmExtension.contains(u.value) {
                septets.append(true)
                septets.append(false)
            } else {
                let units = Array(text.utf16)
                return split(units.count, single: 70, per: 67, ucs2: true) { (0xD800..<0xDC00).contains(units[$0 - 1]) }
            }
        }
        return split(septets.count, single: 160, per: 153, ucs2: false) { septets[$0 - 1] }
    }

    /// splitsBadly(end)：在 end 前面切會拆開 escape 或 surrogate pair。
    private static func split(_ n: Int, single: Int, per: Int, ucs2: Bool, splitsBadly: (Int) -> Bool) -> Count {
        if n <= single { return Count(parts: n == 0 ? 0 : 1, ucs2: ucs2, left: single - n) }
        var parts = 0, start = 0, last = 0
        while start < n {
            var end = min(start + per, n)
            if end < n && splitsBadly(end) { end -= 1 }
            parts += 1
            last = end - start
            start = end
        }
        return Count(parts: parts, ucs2: ucs2, left: per - last)
    }

    /// 去掉空白、連字號、括號；剩下的要是 3～20 位數字，前面可以有 +。
    static func normalizedNumber(_ s: String) -> String? {
        let n = s.filter { !" -().\u{00A0}".contains($0) }
        let digits = n.hasPrefix("+") ? n.dropFirst() : Substring(n)
        guard (3...20).contains(digits.count), digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return n
    }
}

/// 同一個人的號碼可能是 +886912345678 也可能是 0912345678：數字有 9 位以上就比最後 9 位。
enum SMSThreads {
    static func key(_ number: String) -> String {
        let digits = number.filter { $0.isASCII && $0.isNumber }
        guard !digits.isEmpty, digits.count == number.filter({ $0 != "+" }).count else { return number }  // 英數字寄件者
        return digits.count >= 9 ? String(digits.suffix(9)) : digits
    }
}

struct SMSThread: Identifiable, Equatable {
    var id: String
    var number: String  // 顯示用：最近一則的號碼
    var messages: [SMSMessage]
    var unreadIDs: [Int]
    var last: SMSMessage { messages[messages.count - 1] }
}

extension TetherModel {
    var smsThreads: [SMSThread] {
        var byKey: [String: [SMSMessage]] = [:]
        for m in smsMessages { byKey[SMSThreads.key(m.number), default: []].append(m) }
        return byKey.map { key, msgs in
            let sorted = msgs.sorted { ($0.time, $0.id) < ($1.time, $1.id) }
            return SMSThread(id: key, number: sorted.last!.number, messages: sorted,
                             unreadIDs: sorted.filter { !$0.isOutgoing && !$0.read }.map(\.id))
        }
        .sorted { ($0.last.time, $0.last.id) > ($1.last.time, $1.last.id) }
    }
}

enum SMSText {
    static func time(_ d: Date) -> String {
        Calendar.current.isDateInToday(d) ? d.formatted(date: .omitted, time: .shortened)
                                          : d.formatted(date: .abbreviated, time: .shortened)
    }

    static func body(_ m: SMSMessage) -> String {
        m.text.isEmpty ? NSLocalizedString("(data message that cannot be shown)", comment: "") : m.text
    }

    /// 寄出的簡訊狀態。
    static func state(_ m: SMSMessage) -> String? {
        guard m.isOutgoing else { return nil }
        switch m.state {
        case "queued": return NSLocalizedString("Waiting for the modem…", comment: "")
        case "sending": return NSLocalizedString("Sending…", comment: "")
        case "sent": return NSLocalizedString("Sent", comment: "")
        default: return String(format: NSLocalizedString("Failed: %@", comment: ""), failure(m.error ?? ""))
        }
    }

    static func failure(_ code: String) -> String {
        switch code {
        case "no_modem": return NSLocalizedString("no modem was connected", comment: "")
        case "interrupted": return NSLocalizedString("the background service restarted; it may not have gone out", comment: "")
        case "rejected": return NSLocalizedString("the modem or mobile network refused it", comment: "")
        case "no_answer": return NSLocalizedString("the modem did not answer; it may have gone out", comment: "")
        case "partial": return NSLocalizedString("only part of it went out", comment: "")
        default: return NSLocalizedString("it could not be encoded", comment: "")
        }
    }

    /// sms send 被 daemon 拒絕的原因。
    static func sendError(_ code: String) -> String {
        switch code {
        case "invalid_number": return NSLocalizedString("Enter a phone number: digits, optionally starting with +.", comment: "")
        case "invalid_text": return NSLocalizedString("The message is empty.", comment: "")
        case "too_long": return NSLocalizedString("Too long: at most 10 SMS (about 670 Chinese characters).", comment: "")
        case "no_modem": return NSLocalizedString("No modem is connected.", comment: "")
        default: return NSLocalizedString("The background service did not take the message.", comment: "")
        }
    }
}

// MARK: - 通知

@MainActor
enum Notifier {
    private static var asked = false

    static func requestAuthorizationOnce() {
        guard !asked else { return }
        asked = true
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    static func newMessage(_ m: SMSMessage) {
        let c = UNMutableNotificationContent()
        c.title = m.number
        c.body = SMSText.body(m)
        c.sound = .default
        c.threadIdentifier = SMSThreads.key(m.number)
        c.userInfo = ["number": m.number]
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "sms-\(m.id)", content: c, trigger: nil))
    }
}

// MARK: - 視窗

@MainActor
final class MessagesNavigation: ObservableObject {
    static let newMessage = "\u{0}new"
    @Published var selection: String?
}

/// 簡訊視窗由 AppKit 直接管理（跟設定視窗一樣），面板和通知都走這裡。
@MainActor
enum MessagesWindow {
    private static var window: NSWindow?
    static let navigation = MessagesNavigation()

    static func show(number: String? = nil) {
        if let number { navigation.selection = SMSThreads.key(number) }
        if window == nil {
            let w = NSWindow(contentViewController: NSHostingController(rootView: MessagesView(model: .shared, nav: navigation)))
            w.title = NSLocalizedString("Messages", comment: "")
            w.styleMask = [.titled, .closable, .miniaturizable, .resizable]
            w.isReleasedWhenClosed = false
            w.setContentSize(NSSize(width: 760, height: 520))
            w.center()
            w.setFrameAutosaveName("TetherlineMessages")
            window = w
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
}

struct MessagesView: View {
    @ObservedObject var model: TetherModel
    @ObservedObject var nav: MessagesNavigation

    var body: some View {
        let threads = model.smsThreads
        HStack(spacing: 0) {
            sidebar(threads)
                .frame(width: 240)
            Divider()
            Group {
                if nav.selection == MessagesNavigation.newMessage {
                    NewMessageView(model: model, nav: nav)
                } else if let t = threads.first(where: { $0.id == nav.selection }) {
                    ThreadView(model: model, thread: t)
                        .id(t.id)
                } else {
                    Text(threads.isEmpty ? "No messages" : "Select a conversation")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .frame(minWidth: 380, maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(minWidth: 640, minHeight: 400)
    }

    private func sidebar(_ threads: [SMSThread]) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                Button {
                    nav.selection = MessagesNavigation.newMessage
                } label: {
                    Label("New Message", systemImage: "square.and.pencil")
                }
                .disabled(!model.smsReady)
                if !model.smsReady {
                    Text("Connect the modem to send and receive messages.")
                        .font(.caption).foregroundStyle(.secondary)
                } else if model.status?.smsFull == true {
                    Text("The modem's message storage is full; new messages cannot arrive.")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            .padding(10)
            Divider()
            List(selection: $nav.selection) {
                ForEach(threads) { t in
                    ThreadRow(thread: t)
                        .tag(t.id)
                        .contextMenu {
                            Button("Delete Conversation", role: .destructive) { model.deleteSMS(t.messages.map(\.id)) }
                        }
                }
            }
            .listStyle(.sidebar)
        }
    }
}

struct ThreadRow: View {
    let thread: SMSThread

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(thread.number)
                    .fontWeight(thread.unreadIDs.isEmpty ? .regular : .bold)
                    .lineLimit(1)
                Spacer(minLength: 4)
                Text(SMSText.time(thread.last.date)).font(.caption).foregroundStyle(.secondary)
            }
            HStack(spacing: 4) {
                if !thread.unreadIDs.isEmpty {
                    Circle().fill(Color.accentColor).frame(width: 7, height: 7)
                }
                Text(SMSText.body(thread.last))
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
        .padding(.vertical, 3)
    }
}

struct ThreadView: View {
    @ObservedObject var model: TetherModel
    let thread: SMSThread
    @State private var confirmDelete = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(thread.number).font(.headline).textSelection(.enabled)
                Spacer()
                Button(role: .destructive) {
                    confirmDelete = true
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .help(Text("Delete Conversation"))
                .accessibilityLabel(Text("Delete Conversation"))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            Divider()
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 10) {
                        ForEach(thread.messages) { m in
                            Bubble(message: m)
                                .id(m.id)
                                .contextMenu {
                                    Button("Copy") {
                                        NSPasteboard.general.clearContents()
                                        NSPasteboard.general.setString(m.text, forType: .string)
                                    }
                                    Button("Delete", role: .destructive) { model.deleteSMS([m.id]) }
                                }
                        }
                    }
                    .padding(14)
                }
                .onAppear { proxy.scrollTo(thread.last.id, anchor: .bottom) }
                .onChange(of: thread.messages.count) { proxy.scrollTo(thread.last.id, anchor: .bottom) }
            }
            Divider()
            if model.smsReady && !thread.id.contains(where: { $0.isLetter }) {
                ComposeBar(model: model, number: replyNumber)
            }
        }
        .onAppear { model.markSMSRead(thread.unreadIDs) }
        .onChange(of: thread.unreadIDs) { model.markSMSRead(thread.unreadIDs) }
        .confirmationDialog(Text("Delete this conversation?"), isPresented: $confirmDelete) {
            Button("Delete", role: .destructive) { model.deleteSMS(thread.messages.map(\.id)) }
        } message: {
            Text("The messages are removed from this Mac. The modem keeps no copy.")
        }
    }

    /// 回覆用收到的號碼（國際格式也照樣回），沒有收到過就用寄出時打的號碼。
    private var replyNumber: String {
        thread.messages.last(where: { !$0.isOutgoing })?.number ?? thread.number
    }
}

struct Bubble: View {
    let message: SMSMessage

    var body: some View {
        let out = message.isOutgoing
        HStack {
            if out { Spacer(minLength: 60) }
            VStack(alignment: out ? .trailing : .leading, spacing: 3) {
                Text(SMSText.body(message))
                    .textSelection(.enabled)
                    .padding(.horizontal, 11)
                    .padding(.vertical, 7)
                    .foregroundStyle(out ? Color.white : Color.primary)
                    .background(out ? Color.accentColor : Color.secondary.opacity(0.16), in: RoundedRectangle(cornerRadius: 14))
                HStack(spacing: 6) {
                    Text(SMSText.time(message.date))
                    if let state = SMSText.state(message) { Text(state) }
                }
                .font(.caption2)
                .foregroundStyle(message.state == "failed" ? Color.red : Color.secondary)
            }
            if !out { Spacer(minLength: 60) }
        }
    }
}

/// 輸入框：Return 送出，Option-Return 換行。
struct ComposeBar: View {
    @ObservedObject var model: TetherModel
    let number: String
    var autofocus = true
    var onSent: (() -> Void)? = nil
    @State private var draft = ""
    @State private var error: String?
    @State private var sending = false
    @FocusState private var focused: Bool

    var body: some View {
        let count = SMSCounter.count(draft)
        VStack(alignment: .leading, spacing: 4) {
            if let error {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            HStack(alignment: .bottom, spacing: 8) {
                TextField("Text Message", text: $draft, axis: .vertical)
                    .lineLimit(1...8)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused)
                    .onSubmit(send)
                VStack(alignment: .trailing, spacing: 3) {
                    if count.parts > 0 {
                        Text(String(format: NSLocalizedString("%1$d left · %2$d SMS", comment: ""), count.left, count.parts))
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(count.parts > SMSCounter.maxParts ? Color.red : Color.secondary)
                    }
                    Button("Send", action: send)
                        .keyboardShortcut(.return, modifiers: .command)
                        .disabled(!canSend(count))
                }
            }
        }
        .padding(12)
        .onAppear { focused = autofocus }
    }

    private func canSend(_ c: SMSCounter.Count) -> Bool {
        !sending && c.parts > 0 && c.parts <= SMSCounter.maxParts && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func send() {
        guard canSend(SMSCounter.count(draft)) else { return }
        guard let to = SMSCounter.normalizedNumber(number) else {
            error = SMSText.sendError("invalid_number")
            return
        }
        sending = true
        let text = draft
        Task {
            let err = await model.sendSMS(to: to, text: text)
            sending = false
            if let err {
                error = SMSText.sendError(err)
            } else {
                error = nil
                draft = ""
                onSent?()
            }
        }
    }
}

struct NewMessageView: View {
    @ObservedObject var model: TetherModel
    @ObservedObject var nav: MessagesNavigation
    @State private var number = ""
    @FocusState private var numberFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("To:").foregroundStyle(.secondary)
                TextField("Phone number", text: $number)
                    .textFieldStyle(.plain)
                    .focused($numberFocused)
                    .onAppear { numberFocused = true }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            Divider()
            Spacer()
            Divider()
            ComposeBar(model: model, number: number, autofocus: false) {
                nav.selection = SMSThreads.key(SMSCounter.normalizedNumber(number) ?? number)
            }
        }
    }
}
