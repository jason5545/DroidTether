#pragma once

#include <net/if.h>

#include "common.h"

// 用一對 feth（macOS 內建的虛擬乙太網卡）當系統這端的網卡：
// host 那張拿 IP、給系統用；peer 那張由我們用 BPF 讀寫，等於網路線的另一頭。
// 不用 utun 的原因：utun 在 Network framework 裡是 "other" 類型，
// Tailscale 這類排除 other 的程式會因此判定網路斷線。
typedef struct {
    char host[IFNAMSIZ];
    char peer[IFNAMSIZ];
    int bpf;
    uint32_t blen;
    uint8_t *rbuf;
} feth_t;

// 移除上次異常結束留下的介面。
void feth_destroy_stale(void);

int feth_create(feth_t *f, const uint8_t mac[6], int mtu);
int feth_set_ipv4(feth_t *f, uint32_t ip, uint32_t mask);
// 加一個 IPv6 位址（link-local 由系統自己產生）。
int feth_set_ipv6(feth_t *f, const uint8_t addr[16], int prefix);
void feth_destroy(feth_t *f);

// 把一個 frame 送進系統（從 peer 送出，host 會收到）。
int feth_inject(feth_t *f, const uint8_t *frame, int len);

typedef void (*feth_frame_cb)(void *ctx, const uint8_t *frame, int len);

// 等系統送出的 frame，最多 timeout_ms；每個 frame 呼叫一次 cb。回傳 -1 表示 BPF 壞了。
int feth_read(feth_t *f, int timeout_ms, feth_frame_cb cb, void *ctx);
