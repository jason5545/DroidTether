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

- `make test`：封包單元測試，不需要手機。
- `python3 tests/dns_logic_test.py`：DNS 與路由的實機邏輯測試，需要手機連線。
- `python3 tests/vpn_logic_test.py`：Tailscale exit node 疊在 tether 上時，VPN 必須拿到預設路由。
- `swiftc -O -parse-as-library app/Sources/WifiGuard.swift tests/wifi_guard_test.swift -o build/wifi_guard_test && build/wifi_guard_test`：daemon 連不上時，App 把 daemon 關掉的 Wi-Fi 開回來的條件。
