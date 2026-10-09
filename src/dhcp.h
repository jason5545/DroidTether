#pragma once

#include "common.h"

#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_ACK 5
#define DHCP_NAK 6
#define DHCP_RELEASE 7

// 位址一律用 network byte order。
typedef struct {
    uint8_t msg_type;
    uint32_t yiaddr;
    uint32_t server_id;
    uint32_t mask;
    uint32_t router;
    uint32_t dns[4];
    int ndns;
    uint32_t lease;  // 秒
    uint32_t t1;     // 秒，0 表示伺服器沒給
    uint16_t mtu;    // 0 表示伺服器沒給
} dhcp_reply_t;

typedef struct {
    uint8_t type;       // DHCP_DISCOVER / DHCP_REQUEST / DHCP_RELEASE
    uint32_t xid;
    const uint8_t *mac;
    uint32_t ciaddr;     // 續約、釋放時填自己的 IP
    uint32_t requested;  // option 50，選擇階段用
    uint32_t server_id;  // option 54，選擇階段、釋放用
    // Ethernet / IP 目的地：廣播時 dst_mac 全 FF、dst_ip 255.255.255.255
    const uint8_t *dst_mac;
    uint32_t src_ip;
    uint32_t dst_ip;
} dhcp_send_t;

// 在 frame 寫入完整 Ethernet + IPv4 + UDP + DHCP，回傳 frame 長度。
int dhcp_build(uint8_t *frame, int cap, const dhcp_send_t *s);

// 解析 UDP payload（BOOTP 起頭）。符合 xid 與 chaddr 才回傳 0。
int dhcp_parse(const uint8_t *p, int len, uint32_t xid, const uint8_t *mac, dhcp_reply_t *out);

uint16_t ip_checksum(const void *data, int len, uint32_t initial);
