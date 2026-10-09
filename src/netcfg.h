#pragma once

#include "common.h"

// 把 tether 註冊成系統的網路服務（IPv4 + DNS），讓 configd 把它當 primary、
// 設預設路由、把 DNS 交給 mDNSResponder。用暫存值寫入，行程結束時由 configd 自動移除。
int netcfg_publish(const char *ifname, uint32_t ip, uint32_t mask, uint32_t router, const uint32_t *dns, int ndns,
                   bool primary);
void netcfg_withdraw(void);

// 清掉上次異常結束可能留下的鍵。
void netcfg_remove_stale(void);
