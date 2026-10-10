# Tetherline（舊名 DroidTether）協作規則

App 顯示名稱和 repo 在 0.4 改成 Tetherline。bundle ID（`io.github.jason5545.DroidTether`）、背景服務 label（`io.github.jason5545.droidtether`）、`droidtetherd`、設定檔、記錄檔、socket、configd 的服務 ID `DroidTether` 都刻意沿用舊名：改了系統會當成另一個 App，背景項目要重新允許，還可能卡 LWCR 要重開機。2026/10/10 從 `/Applications/DroidTether.app`（0.3.7）換成 `/Applications/Tetherline.app`（0.4.0），背景服務 1 秒內用新 bundle 重啟，不用重新允許、不用重開機。

## 本機部署：一律用公證版

- 裝到這台 Mac 的 `/Applications/Tetherline.app`（0.4 以前是 `DroidTether.app`，安裝時一併移除），只能用 `scripts/release.sh <版本>` 產出的 Developer ID 簽章、Apple 公證版。
- 不准用 `make install`，也不准把 `make app` 的產物複製進 `/Applications`。那是 Apple Development 簽章，給沒有 Developer ID 的外部開發者用。
- release.sh 結束時會刪掉中間產物，公證版從 `build/dist/Tetherline-<版本>.zip` 解出來：先 `codesign --verify --deep --strict`、`spctl -a -vv -t exec` 確認是 Notarized Developer ID，再取代 `/Applications/Tetherline.app`（同時刪掉舊的 `DroidTether.app`），解壓的副本用 `lsregister -u` 取消登記後刪掉。
- 改版本時同步改 `Makefile` 的 `VERSION`，App 打開後會請舊版 daemon 結束，launchd 用新版重啟。

### 為什麼

SMAppService 登記背景服務時，會把當時的簽章身分記成啟動限制（LWCR）。換成另一種簽章後，launchd 拒絕啟動 daemon（`OS_REASON_CODESIGNING | Launch Constraint Violation`），只有重開機才會重新評估。

2026/10/10 用 `make install` 換掉公證版，接著 daemon 停掉後起不來。舊版殘留的 `feth7700` 和 `0/1`、`128/1` 路由把所有對外流量吃掉，切 Wi-Fi、關 Tailscale 都沒用，重開機才恢復。從公證版換回來，又重開了一次。

## daemon 是網路來源

連線時 daemon 會關掉 Wi-Fi，手機是唯一的網路。任何會讓 daemon 停掉的動作（`debug abort`、安裝、`quit`），先確認它能被 launchd 拉回來；`tests/dns_logic_test.py` 的完整測試會模擬當機。

## 測試

- `make test`：封包單元測試，不需要手機。包含 `build/test_mbim`：MBIM 訊息用 TCL IK512 實際收發的位元組對照，簡訊 PDU 用 ModemManager 測試裡的真實簡訊與期待值對照；`build/test_sms_store`：收件匣檔案。
- `tests/mbim_probe.c`：在 Linux 主機上用真的 MBIM 數據機跑 `src/mbim.c`（開 session、撥號、自己組 ping 與 DNS 經數據機收發），不建介面、不改路由。PVE 沒有編譯器，在 LXC 112（gki-build）裡用 Mac 帶過去的 `libusb.h` 編，直接連結 `/usr/lib/x86_64-linux-gnu/libusb-1.0.so.0`。跑之前停掉 `failover-watchdog.timer` 與 `ModemManager`，跑完 `systemctl start ModemManager`、`systemctl restart ik512-always-on`、`systemctl start failover-watchdog.timer`；包成 `systemd-run` 執行，SSH 斷了也會還原。2026/10/10 實測全過，5G 備援停了約 80 秒，主線路沒受影響。
- `build/test_mbim --dump` 加 `tests/mbim_oracle.py`：在裝了 libmbim 的 Linux 主機（PVE）上，跟 libmbim 逐位元組對照撥號、附著等送不出去的指令。不需要數據機。
- `python3 tests/dns_logic_test.py`：DNS 與路由的實機邏輯測試，需要手機連線。
- `python3 tests/vpn_logic_test.py`：Tailscale exit node 疊在 tether 上時，VPN 必須拿到預設路由。
- `swiftc -O -parse-as-library app/Sources/WifiGuard.swift tests/wifi_guard_test.swift -o build/wifi_guard_test && build/wifi_guard_test`：daemon 連不上時，App 把 daemon 關掉的 Wi-Fi 開回來的條件。

## 簡訊

- 收到的簡訊存在 `/Library/Application Support/DroidTether/config.sms`（只有 root 能讀寫），存好才從數據機刪（Jason 2026/10/10 決定）。內容和號碼不准寫進 log。
- 每一則實際送出的測試簡訊都要先問 Jason，寫明收件號碼和內容。
- TCL IK512 不能收發簡訊：MBIM SEND 一秒就回 failure，傳給它的也收不到。2026/10/10 透過 QMI over MBIM（服務 `d1a30bc2-f97a-6e43-bf65-c7e24fb0f0d3`，CID 1，要先用 DEVICE_SERVICE_SUBSCRIBE_LIST 訂閱才收得到 QMI indication）查：NAS 在 LTE 上 CS、PS 都附著了；WMS Raw Send 回 DeviceUnsupported、傳輸註冊回 DeviceNotReady；IMSA 回 InvalidOperation；PDC 選用的是 `TaiwanMobile_Commercial`。可能要改 NV／EFS 打開 IMS，沒試，Jason 決定先不碰。daemon 把送簡訊被拒的數據機記在 `config.sms-unsupported`，App 就不顯示簡訊入口。
- 在 Mac 上直接用數據機跑 probe：`echo "set enabled 0" | nc -U /var/run/droidtetherd.sock` 暫停 daemon，以一般使用者身分跑（macOS 存取 USB 不需要 root），跑完 `set enabled 1`。暫停期間 Mac 改走 Wi-Fi，恢復後約 5 秒重新連上。
