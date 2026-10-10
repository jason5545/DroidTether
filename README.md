<p align="center"><img src="docs/logo.png" width="128" alt="Tetherline icon"></p>

<h1 align="center">Tetherline</h1>

<p align="center">
USB tethering for macOS, from Android phones and 4G/5G USB modems: a menu bar app plus a small user-space driver.<br>
No kernel extension, no DriverKit, no SIP changes, and DNS that actually follows the phone.
</p>

<p align="center"><sub>Formerly DroidTether. The bundle identifier, the background service, its settings and its log keep the old name, so updating from DroidTether 0.3.x needs no new approval and no restart (tested going from 0.3.7 to 0.4.0).</sub></p>

<p align="center"><a href="#繁體中文">繁體中文</a></p>

<p align="center"><img src="docs/panel-en.png" width="320" alt="Tetherline menu bar panel"></p>

## Why another one?

macOS has no RNDIS driver, HoRNDIS no longer loads on Apple Silicon without lowering security, and the user-space tools I tried kept breaking DNS. Two things were wrong:

1. **DNS was never applied.** The tool wrote only `State:/Network/Service/<id>/DNS` to the SystemConfiguration dynamic store. `configd` ignores a service that has DNS but no `IPv4` entity, so the Mac kept resolving over Wi-Fi, or not at all once Wi-Fi was off.
2. **`utun` confuses Tailscale.** Network.framework reports `utun` interfaces as type `other`. Tailscale filters those out and decides the network is down, so the tailnet (and MagicDNS) drops while tethering.

Tetherline fixes both:

- The tether is registered as a complete network service, with `IPv4`, `DNS` and `OverridePrimary`. `configd` then moves the default route and the resolver to the phone itself. Wi-Fi can stay on.
- A full-tunnel VPN still wins. With a Tailscale exit node on, `configd` keeps the VPN's default route even though the tether asks for `OverridePrimary`, and Tetherline adds no routes of its own to override that, so the VPN's traffic stays inside the tunnel. `tests/vpn_logic_test.py` checks this from both orders: exit node first, or tether first.
- The service is written with `SCDynamicStoreAddTemporaryValue`, so `configd` removes it when the daemon exits, even on `kill -9`. Wi-Fi takes over again within a few seconds.
- The Mac side is a `feth` pair (macOS's built-in fake Ethernet), which Network.framework reports as `wiredEthernet`. Tailscale and other `NWPathMonitor` users keep working.
- DNS defaults to the server the phone hands out over DHCP. A custom list is optional. Some tethering tools say Android's USB link does not proxy DNS and always use public servers. On a POCO F8 Ultra with HyperOS the phone's own DNS does answer over the USB link: a direct query to it with Wi-Fi off came back in under 100 ms, and the live test asks it directly on every run. Other phones may differ, so Tetherline asks the phone first and falls back to 8.8.8.8 and 8.8.4.4 only if it gets no answer. It then asks the phone again every minute and switches back once it answers.

### 4G/5G USB modems (MBIM)

USB modems are the other half. Many can switch to ECM, which macOS supports, but then the modem's own router does the dialing and NAT. On the author's plan the carrier counts that as hotspot sharing; in MBIM mode, where the computer itself dials as Windows and Linux do, it does not. macOS has no MBIM driver.

Tetherline speaks MBIM itself: it opens the modem's control channel, waits for the SIM and network registration, dials with an APN (default `internet`), reads the address the network assigns, and carries IP packets in NTB16 blocks. The Mac side is the same `feth` pair, with the Ethernet headers and ARP replies made up by the daemon, so DNS, the VPN behaviour, Wi-Fi handling and the panel all work the same way. When a modem says it is connected but nothing comes back (some firmware does this every few hours), the daemon notices from unanswered pings while idle and resets the modem over USB.

The panel shows the carrier, the network type and the signal as bars. IPv6 works alongside IPv4 when the network offers it (Taiwan Mobile does): the daemon answers neighbor discovery for the modem's side of the link and registers the IPv6 address, router and DNS with `configd`. If the SIM needs its PIN, the panel asks for it once. The daemon keeps it in a file only root can read and enters it on later plug-ins, and it never tries a PIN the SIM has rejected, so a stored PIN cannot use up the attempts and lock the SIM into PUK.

Text messages go through the modem's MBIM SMS service in PDU format: GSM 7-bit and UCS-2 (Chinese and emoji included), with multipart messages joined on arrival and split when sending (up to 10 parts). Each received message is saved to a file only root can read, next to the settings, and only then deleted from the modem, whose storage is small (40 messages on the IK512) and takes no new messages once full. A multipart message is deleted only after all its parts are in and saved. Messages opens from the panel, and each new message brings a notification. Message text and phone numbers never go into the log.

The IK512 itself cannot do SMS. Its firmware advertises SMS, but sending fails at once (MBIM status `failure`), and messages sent to it never arrive. Over Qualcomm's QMI, which the modem exposes through MBIM, the messaging service answers `DeviceUnsupported` and IMS is not running, even though the Taiwan Mobile carrier profile is the one selected; the same SIM handles SMS in a phone. When a modem refuses to send, the daemon remembers it by USB vendor and product ID and the app hides Messages until that modem sends or receives a message. So the SMS encoding has been checked against libmbim and against real messages from ModemManager's tests, not yet on a live network.

Tested with a TCL LINKKEY IK512 (Qualcomm SDX62) on Taiwan Mobile, on macOS 26: plugged in, the Mac is online about 3 seconds later, with the carrier's DNS, and the live DNS test (14/14) and VPN test (26/26) pass over the modem. IPv6 gets a global address from the carrier, and `ping6` and HTTPS over IPv6 work. Every request the daemon builds also matches libmbim byte for byte. This modem ignores the MBIM open request until the host has set its NTB input size, which Linux always does while binding, so the daemon does it too.

## Features

- Enable USB tethering on the phone and the Mac is online about a second later. Unplug and Wi-Fi comes back.
- 4G/5G USB modems in MBIM mode: plug in and the Mac dials with the configured APN, over IPv4 and IPv6, with the carrier, network type and signal bars in the panel, and SIM PIN entry when needed.
- SMS on modems that support it: an inbox grouped by conversation, writing and replying, and a notification for each new message.
- Menu bar panel: status, IP and DNS, a two-minute traffic graph, and ping to the phone (the USB link) and to 1.1.1.1 (through the phone).
- Pause, resume and reconnect.
- Settings: use the phone as the main connection or not, DNS (from the phone or custom), turn Wi-Fi off while connected, open at login.
- Tells you when a phone is plugged in but USB tethering is off, or when another app is holding the device.
- English and Traditional Chinese, following the system language.
- The background service is registered with `SMAppService`: one switch in System Settings, no installer and no password.

Menu bar icon, left to right: connected, connecting, not connected, paused.

<img src="docs/menubar-icons.png" width="360" alt="Menu bar icon states">

## How it works

```
Android phone (RNDIS)              4G/5G USB modem (MBIM)
   │  USB: control + bulk endpoints, via libusb
droidtetherd  (root, started by launchd through SMAppService)
   │  RNDIS ⇄ Ethernet frames · DHCP client with lease renewal
   │  MBIM: control channel, APN dial-up, NTB16 ⇄ IP packets, ARP answered by the daemon
   │  BPF on feth7701
feth7701 ⇄ feth7700   macOS fake-Ethernet pair; feth7700 holds the IP, the kernel does ARP
   │
configd  ← State:/Network/Service/DroidTether/{IPv4,DNS}   (OverridePrimary, temporary values)
   │
default route and DNS → the phone

Tetherline.app (menu bar) ⇄ /var/run/droidtetherd.sock ⇄ droidtetherd
```

- `src/` is the daemon, in C (about 5,300 lines): USB discovery, RNDIS, DHCP, MBIM, SMS, `feth`/BPF, SystemConfiguration and the control socket.
- `app/` is the menu bar app, in SwiftUI. It talks to the daemon over a Unix socket, one command per line and one JSON reply.
- Only the RNDIS or MBIM control and data interfaces are claimed. ADB, and a modem's AT and diagnostic ports, stay free.

## Requirements

- macOS 26 or later on Apple Silicon. That is what it is built for and tested on (deployment target 26.0, arm64).
- An Android phone that tethers over RNDIS (USB interface class `EF/04/01`, `E0/01/03` or `02/02/FF`). Tested with a POCO F8 Ultra on HyperOS.
- Or a USB modem in MBIM mode (interface class `02/0E/00`). Tested with a TCL LINKKEY IK512.
- To build: the Xcode command line tools (Swift 6), `libusb` from Homebrew, and an Apple Development code-signing identity. I have only tested the `SMAppService` background service with a properly signed app.

## Download

Signed with Developer ID and notarized by Apple: get the DMG from the [latest release](https://github.com/jason5545/Tetherline/releases/latest), drag Tetherline into Applications and open it. Then allow the background item as described below.

## Build and install

```bash
brew install libusb
git clone https://github.com/jason5545/Tetherline.git
cd Tetherline
make test
make install
open /Applications/Tetherline.app
```

`make install` builds the daemon and the app, signs both with your `Apple Development` identity, and copies the app to `/Applications`. If your keychain has more than one, pick it with `SIGN_ID="Apple Development: Your Name (TEAMID)"`.

On first launch, macOS asks you to allow the background item. Turn on **Tetherline** under **System Settings → General → Login Items & Extensions**; the panel has a button that opens that page. After an update, the app notices that the running daemon is older and restarts it from the new bundle.

## Using it

- Turn on USB tethering on the phone. If your ROM keeps the AOSP developer option **Default USB configuration**, setting it to *USB tethering* skips this step every time you plug in.
- Click the menu bar icon for the panel. The gear opens Settings. Opening Tetherline again from Applications or Spotlight also brings up Settings.
- **Modems** dial with the APN `internet` unless told otherwise; it is what the Taiwanese carriers use. Settings → 4G/5G modem has the APN, an IPv6 switch (on by default; if the network refuses IPv4v6 the daemon falls back to IPv4 by itself) and, once a PIN has been entered, a button to forget it.
- **Use as the main connection** (on by default) sends all traffic and DNS through the phone. Turn it off to keep Wi-Fi primary and leave the tether available as a secondary interface.
- **Turn off Wi-Fi while connected** (off by default) switches Wi-Fi off once the tether is up, and back on when you unplug the phone, turn tethering off on the phone, pause, or quit. Only Wi-Fi that Tetherline switched off comes back on: if it was already off when you plugged in, or you turn it back on yourself while connected, Tetherline leaves it alone. It works only while the phone is the main connection. Wi-Fi usually rejoins within a couple of seconds after you unplug; until then the Mac has no connection. If the background service stops and launchd cannot start it again (for example after switching between differently signed copies, see Troubleshooting), the menu bar app turns that Wi-Fi back on after 10 seconds.
- **With Tailscale's "Use Tailscale DNS" on**, Tailscale can handle DNS first. On the test machine (tailnet global nameservers 8.8.8.8 and 8.8.4.4), macOS sent ordinary names to 100.100.100.100 rather than to the phone, even with Tetherline as the main connection. Tetherline's DNS setting then only matters for queries that reach the system resolvers; traffic, including Tailscale's own DNS forwarding, still goes through the phone. In `scutil --dns` this shows up as a Tailscale resolver with no `domain` and a lower `order` than Tetherline's.

## Troubleshooting

| What you see | What to check |
|---|---|
| "Turn on USB tethering on the phone" | The phone is plugged in but exposes no RNDIS interface yet. |
| "… is in use by another app" | Quit any other tethering tool that might hold the device. |
| Connected, but names don't resolve | `scutil --dns` should list the phone's DNS as the default resolver, and `printf 'show State:/Network/Global/IPv4\n' \| scutil` should show `PrimaryService : DroidTether` (the service keeps the old name). A Tailscale resolver with no domain and a lower `order` means Tailscale answers names first (see Using it). `dig @<DNS from the panel> example.com` asks the phone directly, bypassing both. |
| Modem: "No SIM card", "needs its PUK", "could not register" | The modem reports this itself. Check the SIM in a phone first. A SIM that wants its PUK has to be unlocked in a phone. |
| Modem: "The SIM card rejected the PIN" | The saved PIN was wrong and has been deleted, so it is not tried again. The panel shows how many attempts are left; enter the right PIN there. |
| Modem: "refused the data connection; check the APN" | The network rejected the APN. Set the one your carrier publishes in Settings; the daemon tries again every 10 seconds, and the log shows the MBIM status. |
| Modem connected, but no Messages in the panel | The modem refused to send an SMS (the log says so), as the TCL IK512 does. Messages comes back by itself once that modem receives a message. To clear it by hand, delete `/Library/Application Support/DroidTether/config.sms-unsupported` as root. |
| Ping works, websites hang | Some carriers drop large packets. Try a smaller MTU with the development build below (`--mtu 1380`). |
| Background service never starts after switching between a self-built copy and a downloaded one | `launchctl print system/io.github.jason5545.droidtether` shows `spawn failed` and `needs LWCR update`. launchd still holds the code requirement of the first copy that registered the service. Restarting the Mac clears it. Avoid keeping several copies of Tetherline.app (or an older DroidTether.app) around: macOS may resolve the bundled daemon from the wrong one. |

The daemon logs to `/Library/Logs/DroidTether.log`. To query it from a terminal:

```bash
echo status | nc -U /var/run/droidtetherd.sock
```

## Development

```bash
make            # daemon only: build/droidtetherd
make test       # packet tests, no device needed (uses tcpdump to double-check checksums if present)
make app        # build/Tetherline.app
python3 tests/dns_logic_test.py --quick   # live DNS/routing invariants with the phone connected, no disruption
python3 tests/dns_logic_test.py           # plus reconnect, pause, DNS and primary switches, Wi-Fi off while
                                          # connected, configd losing our entries, and a daemon crash
                                          # (the connection drops briefly)
build/test_mbim                           # part of make test: MBIM messages against bytes a TCL IK512 sent,
                                          # SMS PDUs against real messages and expected output from ModemManager's tests
build/test_sms_store                      # part of make test: the SMS inbox file (save, reload, duplicates)
build/test_mbim --dump > mbim.dump        # on a Linux host with libmbim: python3 tests/mbim_oracle.py mbim.dump
                                          # checks every request against libmbim, byte for byte (SMS included)
python3 tests/vpn_logic_test.py           # a Tailscale exit node layered on the tether keeps the default route
                                          # (switches to an exit node and back; needs Tailscale online)
swiftc -O -parse-as-library app/Sources/WifiGuard.swift tests/wifi_guard_test.swift -o build/wifi_guard_test
build/wifi_guard_test                     # when the app turns Wi-Fi back on (toggles Wi-Fi, restores it)
```

The live test also reproduces the DNS-only write that broke the tools this project replaces, and checks that `configd` ignores it while Tetherline's entry is the one in use.

`tests/mbim_probe.c` runs the same MBIM code against a real modem on a Linux host, with no interface and no routes: it dials, pings and queries DNS by itself. AGENTS.md has the steps used on the author's Proxmox host.

To run the daemon by hand, first turn Tetherline off under Login Items so the installed copy releases the phone (only one instance can run). Then:

```bash
sudo build/droidtetherd -v --no-primary --pcap /tmp/tether.pcap -c /tmp/droidtether.conf
```

`--no-primary` leaves Wi-Fi as the main connection, so you can test through the tether with `curl --interface feth7700` without cutting yourself off. `--pcap` records the first 128 bytes of every frame that crosses USB.

Control socket commands (`/var/run/droidtetherd.sock`, owned by `root:staff`, mode 0660):

| Command | Effect |
|---|---|
| `status` | JSON with state, device, addresses, byte counters and settings |
| `set enabled 0\|1` | Pause or resume |
| `set primary 0\|1` | Use as the main connection or not |
| `set dns phone` / `set dns 1.1.1.1,8.8.8.8` | DNS source |
| `set wifi_off 0\|1` | Turn Wi-Fi off while connected (applies without reconnecting) |
| `reconnect` | Drop and re-establish the connection |
| `quit` | Exit; launchd starts it again (used after updates) |

`Tetherline.app/Contents/MacOS/Tetherline --snapshot <prefix> [seconds]` renders the panel and the menu bar icons to PNG files. The screenshots in this README were made that way.

## Uninstall

1. Turn Tetherline off under **System Settings → General → Login Items & Extensions**, then choose **Quit** in the panel.
2. Delete `/Applications/Tetherline.app` (`DroidTether.app` for versions before 0.4).
3. Remove the settings and logs (they keep the old name):

```bash
sudo rm -rf "/Library/Application Support/DroidTether" /Library/Logs/DroidTether.log*
```

## Related projects

Several projects tackle the same problem, most of them started in 2026:

- [jwise/HoRNDIS](https://github.com/jwise/HoRNDIS), the original kernel extension.
- [XiaoMiku01/TetherKit](https://github.com/XiaoMiku01/TetherKit): libusb, `feth` and BPF in C++, with asynchronous USB transfers. The closest relative of this project.
- [noahhhi/HoRNDIS-Userspace](https://github.com/noahhhi/HoRNDIS-Userspace): IOUSBHost and `feth`, with careful privilege separation.
- [jost-s/macos-usb-tether-android](https://github.com/jost-s/macos-usb-tether-android) (muta): Rust, nusb and `utun`, with no `OverridePrimary` and no split routes so that a VPN on top keeps its traffic. Reading it is what led to the VPN test in this repository.
- [s4wbvnny/BetterTether](https://github.com/s4wbvnny/BetterTether) and [francescoterrito/android-rndis-macos](https://github.com/francescoterrito/android-rndis-macos): libusb with `utun`.
- [prostec-labs/TetherKit](https://github.com/prostec-labs/TetherKit): a DriverKit port, which needs entitlements approved by Apple.

Tetherline shares no code with any of them.

## License

[MIT](LICENSE)

---

## 繁體中文

Tetherline 讓 Mac 透過 USB 使用 Android 手機或 4G/5G USB 數據機的網路。它由選單列 App 和一個使用者空間的小驅動組成，不用 kext、不用 DriverKit，也不用關 SIP。

舊名 DroidTether。bundle ID、背景服務、設定檔和記錄檔沿用舊名，從 DroidTether 0.3.x 更新不用重新允許背景項目，也不用重開機（0.3.7 換 0.4.0 實測）。

<p align="center"><img src="docs/panel-zh-dark.png" width="320" alt="Tetherline 選單列面板"></p>

### 為什麼要再寫一個

我原本用的工具每次開分享，DNS 都會出問題。查下去有兩個原因：

- 它只寫了 DNS，沒有寫 IPv4。`configd` 會直接忽略這種服務，所以 DNS 其實一直走 Wi-Fi，Wi-Fi 一關就沒有 DNS。
- 它用 `utun` 介面。Network.framework 把 `utun` 歸類成 `other`，Tailscale 會把它濾掉，然後判定網路斷線。

Tetherline 的做法：

- 把手機註冊成完整的網路服務（IPv4、DNS 加 `OverridePrimary`），由系統自己把預設路由和 DNS 切到手機。Wi-Fi 開著也沒關係。
- 開全通道 VPN 時讓 VPN 優先。實測開 Tailscale exit node 時，就算手機要求 `OverridePrimary`，系統還是把預設路由留給 VPN；Tetherline 也不自己加路由去蓋過它，VPN 的流量不會從手機明文出去。
- 用暫存值寫入，程式異常結束時系統會自動清掉，幾秒內就回到 Wi-Fi。
- Mac 這端用 `feth` 虛擬乙太網卡，Network.framework 認得它是有線網路，Tailscale 照常運作。
- DNS 預設用手機提供的，也可以自訂。有些工具說 Android 的 USB 網路共用不轉發 DNS，一律改用公共 DNS。在 POCO F8 Ultra（HyperOS）上實測，手機自己的 DNS 透過 USB 可以正常回應：關掉 Wi-Fi 直接問手機，不到 100 ms 就有答案，即時測試每次也會直接問一次。其他手機不一定一樣，所以 Tetherline 會先問手機，沒回應才改用 8.8.8.8、8.8.4.4，之後每分鐘再問一次手機，有回應就切回來。

開著 Tailscale 的「Use Tailscale DNS」時，DNS 可能先交給 Tailscale。測試機的 tailnet 設了全域 DNS（8.8.8.8、8.8.4.4），即使 Tetherline 是主要連線，macOS 一般網址也是先問 100.100.100.100，不會問手機。這時 Tetherline 的 DNS 設定只影響真正交到系統 DNS 的查詢；流量本身（包括 Tailscale 轉出去的 DNS 查詢）還是走手機。在 `scutil --dns` 裡看得到一筆沒有 `domain`、`order` 比 Tetherline 小的 Tailscale 項目。

### 4G/5G USB 數據機（MBIM）

很多數據機可以切成 macOS 支援的 ECM 模式，但那是數據機內建的路由器在撥號、做 NAT。作者的方案下，電信商把這種流量算成熱點分享；改用 MBIM、由電腦自己撥號（Windows、Linux 就是這樣），就不算。macOS 沒有 MBIM 驅動。

Tetherline 自己處理 MBIM：開控制通道、等 SIM 和註冊、用 APN 撥號（預設 `internet`，臺灣的電信商都用這個）、讀網路配的位址，資料用 NTB16 收送。Mac 這端一樣是 `feth`，乙太網路標頭和 ARP 由 daemon 補，所以 DNS、VPN、Wi-Fi 和面板的行為都跟手機一樣。數據機有時會「顯示連著但不通」，閒置時 ping 不回來，daemon 會透過 USB 把它重置。

面板會顯示電信商、網路制式和訊號格數。網路有給 IPv6 時（台灣大哥大有），IPv4、IPv6 都能用。SIM 卡要 PIN 時，面板會請你輸入一次；daemon 把它存在只有 root 讀得到的檔案，之後插上自動輸入。被拒絕過的 PIN 會立刻刪掉、絕不再試，所以存著的 PIN 不會把次數用完、把 SIM 鎖成要 PUK。

簡訊走數據機的 MBIM SMS 服務，PDU 格式：GSM 7-bit 和 UCS-2（中文、emoji 都可以），收到的多段簡訊會接成一則，寄出時太長就分段（最多 10 段）。收到的簡訊先存進設定檔旁邊、只有 root 能讀的檔案，存好才從數據機刪掉：數據機的空間很小（IK512 只有 40 則），滿了就收不到新簡訊。多段簡訊要等每一段都到齊、合併存好才刪。面板可以打開簡訊視窗，有新簡訊會跳通知。內容和號碼不會寫進記錄檔。

IK512 本身不能收發簡訊。韌體宣稱支援，但一送就回 MBIM `failure`，傳給它的簡訊也收不到。透過 MBIM 裡的高通 QMI 查，簡訊服務回 `DeviceUnsupported`、IMS 沒在運作，而選用的電信商設定檔確實是台灣大哥大；同一張 SIM 在手機上收發簡訊都正常。數據機送簡訊被拒時，daemon 會按 USB 的 VID:PID 記住它，App 就不顯示簡訊入口，等這支數據機收到或送出任何一則才再出現。所以簡訊的編解碼只跟 libmbim、ModemManager 測試裡的真實簡訊對照過，還沒在實際網路上收發過。

實測：TCL LINKKEY IK512（高通 SDX62）、台灣大哥大、macOS 26。插上後大約 3 秒連上，DNS 用電信商的，透過數據機跑即時 DNS 測試 14/14、VPN 測試 26/26。IPv6 拿得到電信商配的全域位址，`ping6` 和走 IPv6 的 HTTPS 都正常。daemon 組出來的每種請求也都跟 libmbim 逐位元組相同。這張網卡要主機先設定 NTB 接收大小才肯回 MBIM 的 OPEN；Linux 綁定驅動時一定會送，所以 daemon 也照做。

### 功能

- 手機打開 USB 網路共用，大約一秒就連上；拔線自動回到 Wi-Fi。
- MBIM 模式的 4G/5G USB 數據機：插上就用設定的 APN 撥號，IPv4、IPv6 都有，面板顯示電信商、網路制式和訊號格數，SIM 卡要 PIN 時可以直接輸入。APN 和 IPv6 開關在「設定 → 4G/5G 數據機」。
- 支援簡訊的數據機可以收發簡訊：依對話分組的收件匣、寫簡訊和回覆，新簡訊跳通知。
- 選單列面板：連線狀態、IP 與 DNS、最近 2 分鐘的流量圖，以及兩種 Ping：「手機」是 USB 線路本身的延遲，「網路」是經過手機連到 1.1.1.1 的延遲。
- 暫停、恢復、重新連線。
- 設定：是否設為主要連線、DNS 來源、連線時關閉 Wi-Fi、登入時開啟。
- 連線時關閉 Wi-Fi（預設關閉）：連上手機後關掉 Wi-Fi，拔線、手機關掉分享、暫停或結束時再打開。只會打開 Tetherline 自己關掉的 Wi-Fi：接上前就是關的、或連線中你自己打開的，都不會去動。背景服務停掉又起不來時，選單列 App 等 10 秒後會把這個 Wi-Fi 打開。
- 手機接上但沒開分享、或被其他程式占用時，會直接提示。
- 介面有繁體中文和英文，跟著系統語言切換。
- 背景服務用 `SMAppService` 註冊，在系統設定開一個開關就好，不用跑安裝程式，也不用輸入密碼。

### 安裝

直接下載：到 [最新 release](https://github.com/jason5545/Tetherline/releases/latest) 下載 DMG（已用 Developer ID 簽章並通過 Apple 公證），把 Tetherline 拖進「應用程式」再打開。

自己編譯：需要 macOS 26 以上、Apple Silicon、Homebrew 的 `libusb`，以及 Apple Development 簽章憑證。

```bash
brew install libusb
git clone https://github.com/jason5545/Tetherline.git
cd Tetherline
make test
make install
open /Applications/Tetherline.app
```

第一次打開時，到「系統設定 → 一般 → 登入項目與延伸功能」允許 Tetherline 在背景執行。面板上有按鈕可以直接開那一頁。

記錄檔在 `/Library/Logs/DroidTether.log`。疑難排解、開發和移除方式請看上面英文段落的 Troubleshooting、Development、Uninstall。
