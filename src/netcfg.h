#pragma once

#include "common.h"

// 把 tether 註冊成系統的網路服務（IPv4 + DNS），讓 configd 把它當 primary、
// 設預設路由、把 DNS 交給 mDNSResponder。用暫存值寫入，行程結束時由 configd 自動移除。
int netcfg_publish(const char *ifname, uint32_t ip, uint32_t mask, uint32_t router, const uint32_t *dns, int ndns,
                   bool primary);
void netcfg_withdraw(void);

// 清掉上次異常結束可能留下的鍵。
void netcfg_remove_stale(void);

// 我們註冊的 IPv4 / DNS 還在不在（configd 重啟或別的程式刪掉時會消失）。
bool netcfg_present(void);
// 用上次 netcfg_publish 的參數再註冊一次。
int netcfg_republish(void);

// 測試用（控制 socket 的 debug 指令），用獨立的 SCDynamicStore session，不碰主流程的狀態。
// 照 MacTethering 的寫法只寫 DNS、不寫 IPv4，用來對照 configd 會不會採用。
int netcfg_debug_legacy_dns(uint32_t dns);
void netcfg_debug_legacy_dns_clear(void);
// 模擬 configd 把我們的鍵弄丟。
void netcfg_debug_drop(void);
