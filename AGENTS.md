# DroidTether 協作規則

## 本機部署：一律用公證版

- 裝到這台 Mac 的 `/Applications/DroidTether.app`，只能用 `scripts/release.sh <版本>` 產出的 Developer ID 簽章、Apple 公證版。
- 不准用 `make install`，也不准把 `make app` 的產物複製進 `/Applications`。那是 Apple Development 簽章，給沒有 Developer ID 的外部開發者用。
- release.sh 結束時會刪掉中間產物，公證版從 `build/dist/DroidTether-<版本>.zip` 解出來：先 `codesign --verify --deep --strict`、`spctl -a -vv -t exec` 確認是 Notarized Developer ID，再取代 `/Applications/DroidTether.app`，解壓的副本用 `lsregister -u` 取消登記後刪掉。
- 改版本時同步改 `Makefile` 的 `VERSION`，App 打開後會請舊版 daemon 結束，launchd 用新版重啟。

### 為什麼

SMAppService 登記背景服務時，會把當時的簽章身分記成啟動限制（LWCR）。換成另一種簽章後，launchd 拒絕啟動 daemon（`OS_REASON_CODESIGNING | Launch Constraint Violation`），只有重開機才會重新評估。

2026/10/10 用 `make install` 換掉公證版，接著 daemon 停掉後起不來。舊版殘留的 `feth7700` 和 `0/1`、`128/1` 路由把所有對外流量吃掉，切 Wi-Fi、關 Tailscale 都沒用，重開機才恢復。從公證版換回來，又重開了一次。

## daemon 是網路來源

連線時 daemon 會關掉 Wi-Fi，手機是唯一的網路。任何會讓 daemon 停掉的動作（`debug abort`、安裝、`quit`），先確認它能被 launchd 拉回來；`tests/dns_logic_test.py` 的完整測試會模擬當機。

## 測試

- `make test`：封包單元測試，不需要手機。包含 `build/test_mbim`：MBIM 訊息用 TCL IK512 實際收發的位元組對照。
- `tests/mbim_probe.c`：在 Linux 主機上用真的 MBIM 數據機跑 `src/mbim.c`（開 session、撥號、自己組 ping 與 DNS 經數據機收發），不建介面、不改路由。PVE 沒有編譯器，在 LXC 112（gki-build）裡用 Mac 帶過去的 `libusb.h` 編，直接連結 `/usr/lib/x86_64-linux-gnu/libusb-1.0.so.0`。跑之前停掉 `failover-watchdog.timer` 與 `ModemManager`，跑完 `systemctl start ModemManager`、`systemctl restart ik512-always-on`、`systemctl start failover-watchdog.timer`；包成 `systemd-run` 執行，SSH 斷了也會還原。2026/10/10 實測全過，5G 備援停了約 80 秒，主線路沒受影響。
- `build/test_mbim --dump` 加 `tests/mbim_oracle.py`：在裝了 libmbim 的 Linux 主機（PVE）上，跟 libmbim 逐位元組對照撥號、附著等送不出去的指令。不需要數據機。
- `python3 tests/dns_logic_test.py`：DNS 與路由的實機邏輯測試，需要手機連線。
- `python3 tests/vpn_logic_test.py`：Tailscale exit node 疊在 tether 上時，VPN 必須拿到預設路由。
- `swiftc -O -parse-as-library app/Sources/WifiGuard.swift tests/wifi_guard_test.swift -o build/wifi_guard_test && build/wifi_guard_test`：daemon 連不上時，App 把 daemon 關掉的 Wi-Fi 開回來的條件。
