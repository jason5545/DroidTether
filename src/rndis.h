#pragma once

#include "usb.h"

#define RNDIS_MSG_PACKET 0x00000001u
#define RNDIS_MSG_INIT 0x00000002u
#define RNDIS_MSG_HALT 0x00000003u
#define RNDIS_MSG_QUERY 0x00000004u
#define RNDIS_MSG_SET 0x00000005u
#define RNDIS_MSG_RESET 0x00000006u
#define RNDIS_MSG_INDICATE 0x00000007u
#define RNDIS_MSG_KEEPALIVE 0x00000008u
#define RNDIS_MSG_COMPLETION 0x80000000u

#define RNDIS_PACKET_HDR 44

typedef struct {
    usbdev_t *u;
    uint32_t req_id;
    uint32_t dev_max_transfer;  // 裝置一次能收的最大長度
    uint32_t dev_max_packets;
    uint32_t max_frame;  // 不含 Ethernet header 的最大 payload
    uint8_t mac[6];      // 裝置指定給主機端使用的 MAC
} rndis_t;

int rndis_init(rndis_t *r, usbdev_t *u);
void rndis_halt(rndis_t *r);

// 把一個 Ethernet frame 包成 RNDIS_PACKET_MSG，回傳總長度。buf 前面要留 RNDIS_PACKET_HDR。
int rndis_wrap(uint8_t *buf, int frame_len);

typedef void (*rndis_frame_cb)(void *ctx, const uint8_t *frame, int len);

// 解析一次 bulk IN 收到的資料，可能包含多個 RNDIS_PACKET_MSG。回傳解出的 frame 數。
int rndis_unwrap(const uint8_t *buf, int len, rndis_frame_cb cb, void *ctx);
