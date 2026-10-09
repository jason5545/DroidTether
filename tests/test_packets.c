// 不需要裝置的封包測試：DHCP 封包組裝與解析、RNDIS 包裝與拆解。
// 用法：build/test_packets [輸出.pcap]  —— 給了路徑就把組出來的 DHCP 封包寫成 pcap，可用 tcpdump -vvv 檢查 checksum。

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "../src/dhcp.h"
#include "../src/rndis.h"

int g_verbose;
atomic_bool g_stop;
atomic_bool g_reset;
void log_msg(const char *level, const char *fmt, ...) {
    (void)level;
    (void)fmt;
}
const char *ip_str(uint32_t ip_be, char buf[16]) {
    struct in_addr a = {.s_addr = ip_be};
    return inet_ntop(AF_INET, &a, buf, 16);
}

static int failures;
#define CHECK(cond)                                                \
    do {                                                           \
        if (!(cond)) {                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                            \
        }                                                          \
    } while (0)

static FILE *g_pcap;
static void pcap_rec(const uint8_t *d, int n) {
    if (!g_pcap) return;
    uint32_t h[4] = {0, 0, (uint32_t)n, (uint32_t)n};
    fwrite(h, 4, 4, g_pcap);
    fwrite(d, 1, (size_t)n, g_pcap);
}

static int frames_seen, last_len;
static void cb(void *ctx, const uint8_t *f, int len) {
    (void)ctx;
    (void)f;
    frames_seen++;
    last_len = len;
}

// 驗證 IPv4 標頭與 UDP checksum（含 pseudo header）算出來是 0。
static void check_checksums(const uint8_t *frame, int len) {
    const uint8_t *ip = frame + 14;
    CHECK(ip_checksum(ip, 20, 0) == 0);
    int udp_len = get_be16(ip + 24);
    CHECK(14 + 20 + udp_len == len);
    uint32_t pseudo = (uint32_t)((ip[12] << 8) | ip[13]) + (uint32_t)((ip[14] << 8) | ip[15]) +
                      (uint32_t)((ip[16] << 8) | ip[17]) + (uint32_t)((ip[18] << 8) | ip[19]) + 17 + (uint32_t)udp_len;
    CHECK(ip_checksum(ip + 20, udp_len, pseudo) == 0);
}

int main(int argc, char **argv) {
    static const uint8_t mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t gw_mac[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    static const uint8_t bc[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (argc > 1) {
        g_pcap = fopen(argv[1], "wb");
        uint32_t gh[6] = {0xa1b2c3d4, 0x00040002, 0, 0, 65535, 1};
        fwrite(gh, 4, 6, g_pcap);
    }

    uint8_t fr[1600];
    uint32_t ip, gw;
    inet_pton(AF_INET, "192.168.42.10", &ip);
    inet_pton(AF_INET, "192.168.42.129", &gw);

    // DISCOVER：廣播、broadcast flag、checksum 正確
    dhcp_send_t d = {.type = DHCP_DISCOVER, .xid = 0x12345678, .mac = mac, .dst_mac = bc, .dst_ip = INADDR_BROADCAST};
    int n = dhcp_build(fr, sizeof fr, &d);
    CHECK(n == 14 + 20 + 8 + 300);
    CHECK(memcmp(fr, bc, 6) == 0 && memcmp(fr + 6, mac, 6) == 0);
    CHECK(get_be16(fr + 14 + 20 + 8 + 10) == 0x8000);
    check_checksums(fr, n);
    pcap_rec(fr, n);

    // REQUEST（選擇階段）：帶 option 50 / 54
    d.type = DHCP_REQUEST;
    d.requested = ip;
    d.server_id = gw;
    n = dhcp_build(fr, sizeof fr, &d);
    check_checksums(fr, n);
    pcap_rec(fr, n);

    // REQUEST（續約）：單播、ciaddr、沒有 broadcast flag
    dhcp_send_t r = {.type = DHCP_REQUEST, .xid = 0x9abcdef0, .mac = mac, .ciaddr = ip,
                     .dst_mac = gw_mac, .src_ip = ip, .dst_ip = gw};
    n = dhcp_build(fr, sizeof fr, &r);
    check_checksums(fr, n);
    CHECK(get_be16(fr + 14 + 20 + 8 + 10) == 0);
    CHECK(memcmp(fr + 14 + 20 + 8 + 12, &ip, 4) == 0);
    pcap_rec(fr, n);
    if (g_pcap) fclose(g_pcap);

    // 把續約 REQUEST 改成伺服器回的 ACK，測解析
    uint8_t *b = fr + 14 + 20 + 8;
    int blen = n - 42;
    b[0] = 2;
    memcpy(b + 16, &ip, 4);
    uint8_t opts[] = {53, 1, 5, 54, 4, 0, 0, 0, 0, 1, 4, 255, 255, 255, 0, 3, 4, 0, 0, 0, 0,
                      6, 8, 0, 0, 0, 0, 8, 8, 8, 8, 51, 4, 0, 0, 0x0e, 0x10, 26, 2, 0x05, 0xdc, 255};
    memcpy(opts + 5, &gw, 4);
    memcpy(opts + 17, &gw, 4);
    memcpy(opts + 23, &gw, 4);
    memcpy(b + 240, opts, sizeof opts);
    dhcp_reply_t rep;
    CHECK(dhcp_parse(b, blen, 0x9abcdef0, mac, &rep) == 0);
    CHECK(rep.msg_type == DHCP_ACK);
    CHECK(rep.yiaddr == ip && rep.router == gw && rep.server_id == gw);
    CHECK(rep.mask == htonl(0xFFFFFF00u));
    CHECK(rep.ndns == 2 && rep.dns[0] == gw && rep.dns[1] == htonl(0x08080808u));
    CHECK(rep.lease == 3600 && rep.mtu == 1500);
    CHECK(dhcp_parse(b, blen, 1, mac, &rep) != 0);     // xid 不符
    CHECK(dhcp_parse(b, blen, 0x9abcdef0, gw_mac, &rep) != 0);  // chaddr 不符

    // RNDIS：兩個封包黏在同一次傳輸，尾端多一個補位位元組
    uint8_t buf[4096];
    memset(buf, 0, sizeof buf);
    int t1 = rndis_wrap(buf, 60);
    int t2 = rndis_wrap(buf + t1, 1514);
    CHECK(t1 == RNDIS_PACKET_HDR + 60 && t2 == RNDIS_PACKET_HDR + 1514);
    CHECK(rndis_unwrap(buf, t1 + t2 + 1, cb, NULL) == 2 && frames_seen == 2 && last_len == 1514);
    // 第二個封包被截斷：只解出第一個
    frames_seen = 0;
    CHECK(rndis_unwrap(buf, t1 + 100, cb, NULL) == 1);
    // 長度欄位亂掉不能越界
    put_le32(buf + 4, 0xFFFFFFF0u);
    CHECK(rndis_unwrap(buf, t1 + t2, cb, NULL) == 0);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("all packet tests passed\n");
    return 0;
}
