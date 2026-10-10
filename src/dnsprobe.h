#pragma once

#include "common.h"

// 有些手機的 USB 網路分享不轉發 DNS（MacTethering 就是這樣假設，一律用 8.8.8.8）。
// 連上時直接問手機一次，沒回應才改用備用 DNS。

#define DNSPROBE_NAME "captive.apple.com"  // macOS 每次換網路本來就會查

// 組一個 A 查詢，回傳長度；buf 太小回傳 -1。
int dnsprobe_build(uint8_t *buf, int cap, uint16_t id);

// 回覆是否代表「這台 DNS 有在幫我們查」：id 相符、是回覆、RCODE 是 NOERROR 或 NXDOMAIN。
// SERVFAIL、REFUSED 都算沒轉發。
bool dnsprobe_reply_ok(const uint8_t *buf, int len, uint16_t id);

// 從 ifname 直接問 server（network order）。綁在介面上，不會被別的路由（Tailscale、Wi-Fi）帶走。
bool dnsprobe_server(const char *ifname, uint32_t server, int timeout_ms);
