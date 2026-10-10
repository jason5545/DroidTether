#pragma once

// RNDIS（main.c）與 MBIM（mbim_session.c）兩種連線共用的部分。

#include <time.h>

#include "state.h"
#include "usb.h"

#define MAX_MTU 1500
#define DNS_REPROBE_S 60

time_t mono_now(void);
void pcap_frame(const uint8_t *f, int len);

// configd 收到 OverridePrimary 後會自己改預設路由，這裡只等它、記一筆。
void wait_default_route(const char *ifname);

// 逐一直接問 DNS，回傳有回應的幾台（放進 out）。
int probe_phone_dns(const char *ifname, const uint32_t *phone, int n, uint32_t *out);
int fallback_dns(uint32_t *out);
void dns_list(char *buf, size_t cap, const uint32_t *dns, int n);
bool wifi_wanted(void);

// 回傳 true 表示還沒連上就失敗了。
bool run_mbim_session(usbdev_t *u, const dt_config *opt);
