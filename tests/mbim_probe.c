// 在 Linux 主機上用真的 MBIM 數據機跑一次 droidtetherd 的 MBIM 程式碼：開 session、撥號、拿 IP，
// 再自己組 ping 和 DNS 查詢，直接經數據機收發。不建網路介面、不改路由，主機原本的網路不受影響。
// 跑的是 src/mbim.c 與 src/usb_match.c 本身；macOS 端只差 feth 與 configd，那部分跟 RNDIS 共用。
//
// 用法（root）：先停掉會搶數據機的 ModemManager，然後
//   mbim_probe [apn]
// 結束時會掛斷、關 session、放開介面，核心驅動（cdc_mbim）自動接回去。

#include <arpa/inet.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/dhcp.h"
#include "../src/dnsprobe.h"
#include "../src/mbim.h"

int g_verbose = 1;
atomic_bool g_stop;
atomic_bool g_reset;

void log_msg(const char *level, const char *fmt, ...) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    fprintf(stderr, "%ld.%03ld %s ", (long)t.tv_sec % 1000, t.tv_nsec / 1000000, level);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void sleep_ms_interruptible(int ms) {
    while (ms > 0 && !stopping()) {
        int step = ms < 100 ? ms : 100;
        usleep((useconds_t)step * 1000);
        ms -= step;
    }
}

const char *ip_str(uint32_t ip_be, char buf[16]) {
    struct in_addr a = {.s_addr = ip_be};
    return inet_ntop(AF_INET, &a, buf, 16);
}

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

#define PROBE_ID 0x4454
#define MAX_SEQ 256

static usbdev_t U;
static ntb_params_t NP;
static uint32_t MY_IP;
static pthread_mutex_t tx_lock = PTHREAD_MUTEX_INITIALIZER;
static uint16_t ntb_seq;
static double sent_at[MAX_SEQ], rtt[MAX_SEQ];
static uint16_t dns_ids[4];
static bool dns_ok[4];
static atomic_int rx_ntbs, rx_dgrams, rx_bad_ntbs, tx_errs;

static int send_ip(const uint8_t *ip, int len) {
    static uint8_t buf[65536];
    pthread_mutex_lock(&tx_lock);
    int total = ntb16_build(buf, sizeof buf, ntb_seq++, &NP, ip, len);
    int rc = -1, sent = 0;
    if (total > 0) {
        rc = libusb_bulk_transfer(U.h, U.ep_out, buf, total, &sent, 2000);
        if (rc == 0 && U.out_maxpkt > 0 && total % U.out_maxpkt == 0) libusb_bulk_transfer(U.h, U.ep_out, buf, 0, &sent, 2000);
    }
    pthread_mutex_unlock(&tx_lock);
    if (rc != 0) tx_errs++;
    return rc;
}

// ICMP echo，payload 大小可調（測滿載的 NTB）。
static int echo(uint8_t *b, uint32_t dst, uint16_t seq, int payload) {
    int len = 28 + payload;
    memset(b, 0, (size_t)len);
    b[0] = 0x45;
    put_be16(b + 2, (uint16_t)len);
    put_be16(b + 4, seq);
    put_be16(b + 6, 0x4000);
    b[8] = 64;
    b[9] = 1;
    memcpy(b + 12, &MY_IP, 4);
    memcpy(b + 16, &dst, 4);
    put_be16(b + 10, ip_checksum(b, 20, 0));
    b[20] = 8;
    put_be16(b + 24, PROBE_ID);
    put_be16(b + 26, seq);
    for (int i = 0; i < payload; i++) b[28 + i] = (uint8_t)i;
    put_be16(b + 22, ip_checksum(b + 20, 8 + payload, 0));
    return len;
}

static int dns_query(uint8_t *b, uint32_t dst, uint16_t id, uint16_t sport) {
    uint8_t q[64];
    int ql = dnsprobe_build(q, sizeof q, id);
    int len = 28 + ql;
    memset(b, 0, 28);
    b[0] = 0x45;
    put_be16(b + 2, (uint16_t)len);
    put_be16(b + 4, id);
    b[8] = 64;
    b[9] = 17;
    memcpy(b + 12, &MY_IP, 4);
    memcpy(b + 16, &dst, 4);
    put_be16(b + 10, ip_checksum(b, 20, 0));
    put_be16(b + 20, sport);
    put_be16(b + 22, 53);
    put_be16(b + 24, (uint16_t)(8 + ql));  // UDP checksum 留 0（IPv4 允許）
    memcpy(b + 28, q, (size_t)ql);
    return len;
}

static void on_dgram(void *ctx, const uint8_t *ip, int len) {
    (void)ctx;
    rx_dgrams++;
    if (icmp_is_echo_reply(ip, len, MY_IP, PROBE_ID)) {
        int ihl = (ip[0] & 15) * 4;
        int seq = get_be16(ip + ihl + 6);
        if (seq < MAX_SEQ && sent_at[seq] > 0 && rtt[seq] == 0) rtt[seq] = now_ms() - sent_at[seq];
        return;
    }
    if (len >= 28 && ip[9] == 17 && get_be16(ip + 20) == 53) {
        for (int i = 0; i < 4; i++)
            if (dns_ids[i] && dnsprobe_reply_ok(ip + 28, len - 28, dns_ids[i])) dns_ok[i] = true;
    }
}

static void *rx_thread(void *arg) {
    (void)arg;
    int cap = NP.in_max > 16384 ? (int)NP.in_max : 16384;
    cap = (cap + 1023) & ~1023;
    uint8_t *buf = malloc((size_t)cap);
    while (!g_stop) {
        int got = 0;
        int rc = libusb_bulk_transfer(U.h, U.ep_in, buf, cap, &got, 500);
        if (got > 0) {
            rx_ntbs++;
            if (ntb16_parse(buf, got, on_dgram, NULL) < 0) rx_bad_ntbs++;
        }
        if (rc == LIBUSB_ERROR_NO_DEVICE) break;
    }
    free(buf);
    return NULL;
}

static int failures;
static void result(bool ok, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("%s  ", ok ? "PASS" : "FAIL");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
    if (!ok) failures++;
}

// 送 n 個 ping（間隔 gap_ms），等 wait_ms，回傳收到幾個；平均延遲寫進 *avg。
static int ping_round(uint32_t dst, int first_seq, int n, int payload, int gap_ms, int wait_ms, double *avg) {
    uint8_t pkt[1600];
    for (int i = 0; i < n; i++) {
        int seq = first_seq + i;
        int len = echo(pkt, dst, (uint16_t)seq, payload);
        sent_at[seq] = now_ms();
        send_ip(pkt, len);
        if (gap_ms) usleep((useconds_t)gap_ms * 1000);
    }
    usleep((useconds_t)wait_ms * 1000);
    int got = 0;
    double sum = 0;
    for (int i = 0; i < n; i++)
        if (rtt[first_seq + i] > 0) {
            got++;
            sum += rtt[first_seq + i];
        }
    *avg = got ? sum / got : 0;
    return got;
}

static void on_signal(int sig) {
    (void)sig;
    g_stop = true;
}

int main(int argc, char **argv) {
    const char *apn = argc > 1 ? argv[1] : "internet";
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    libusb_context *ctx = NULL;
    if (libusb_init(&ctx) != 0) return 2;

    libusb_device **list = NULL;
    ssize_t n = libusb_get_device_list(ctx, &list);
    libusb_device *dev = NULL;
    for (ssize_t i = 0; i < n && !dev; i++) {
        struct libusb_config_descriptor *cfg = NULL;
        if (libusb_get_active_config_descriptor(list[i], &cfg) != 0) continue;
        usbdev_t cand;
        memset(&cand, 0, sizeof cand);
        if (usb_match_config(cfg, &cand) && cand.kind == DEV_MBIM) {
            U = cand;
            dev = list[i];
        }
        libusb_free_config_descriptor(cfg);
    }
    result(dev != NULL, "found an MBIM device (comm if %d, data if %d alt %d, max control %u)", U.comm_if, U.data_if,
           U.data_alt, U.mbim_max_ctrl);
    if (!dev) return 1;
    struct libusb_device_descriptor dd;
    libusb_get_device_descriptor(dev, &dd);
    U.vid = dd.idVendor;
    U.pid = dd.idProduct;
    if (libusb_open(dev, &U.h) != 0) {
        result(false, "open device");
        return 1;
    }
    libusb_free_device_list(list, 1);
    libusb_set_auto_detach_kernel_driver(U.h, 1);
    int rc1 = libusb_claim_interface(U.h, U.comm_if);
    int rc2 = rc1 == 0 ? libusb_claim_interface(U.h, U.data_if) : -1;
    result(rc1 == 0 && rc2 == 0, "claimed interfaces %d and %d (kernel driver detached)", U.comm_if, U.data_if);
    if (rc1 || rc2) return 1;
    U.ctx = ctx;
    pthread_mutex_init(&U.tx_lock, NULL);

    mbim_dev_t m;
    pthread_t rx = 0;
    bool connected = false;
    double t0 = now_ms();
    int ok = mbim_dev_start(&m, &U, NULL, NULL) == 0;
    result(ok, "notification thread started (interrupt endpoint %02x)", U.ep_int);
    ok = ok && mbim_data_start(&U, &NP) == 0;
    result(ok, "NTB parameters: formats %u, in max %u, out max %u, out divisor %u align %u", NP.formats, NP.in_max,
           NP.out_max, NP.out_divisor, NP.out_align);
    ok = ok && mbim_dev_open(&m) == 0;
    result(ok, "MBIM session opened (%.0f ms)", now_ms() - t0);
    if (!ok) goto out;

    mbim_ipv4_t ipc;
    mbim_ipv6_t ip6;
    mbim_connect_opts_t co = {.apn = apn, .ipv6 = true, .pin = ""};
    t0 = now_ms();
    const char *err = mbim_connect(&m, &co, &ipc, &ip6);
    char a[16], g[16], d0[16], d1[16];
    result(err == NULL, "connected with apn %s in %.1f s: %s", apn, (now_ms() - t0) / 1000, err ? err : "ok");
    if (err) goto out;
    connected = true;
    MY_IP = ipc.ip;
    result(ipc.ip && ipc.gw, "address %s/%d, gateway %s, dns %s %s, mtu %u", ip_str(ipc.ip, a), ipc.prefix,
           ip_str(ipc.gw, g), ipc.ndns > 0 ? ip_str(ipc.dns[0], d0) : "-", ipc.ndns > 1 ? ip_str(ipc.dns[1], d1) : "-",
           ipc.mtu);

    if (ip6.prefix) {
        char a6[64], g6[64];
        inet_ntop(AF_INET6, ip6.addr, a6, sizeof a6);
        inet_ntop(AF_INET6, ip6.gw, g6, sizeof g6);
        printf("INFO  IPv6 %s/%d, gateway %s, %d DNS, mtu %u\n", a6, ip6.prefix, ip6.has_gw ? g6 : "-", ip6.ndns, ip6.mtu);
    } else {
        printf("INFO  no IPv6 from the network\n");
    }
    {
        uint8_t out[256];
        uint32_t st = 0, type = 0, state = 0, att = 0;
        int n = mbim_dev_command(&m, MBIM_UUID_BASIC_CONNECT, MBIM_CID_PIN, false, NULL, 0, out, sizeof out, &st, 5000);
        result(n >= 0 && st == 0 && mbim_parse_pin_info(out, (uint32_t)n, &type, &state, &att) == 0,
               "SIM PIN state: type %u, state %u, %u attempts left", type, state, att);
    }
    mbim_link_t link;
    result(mbim_query_link(&m, &link) == 0, "link: signal %d/4 (rssi %d, %d dBm), provider '%s', %s (data class 0x%x)", link.bars,
           link.rssi, link.rssi >= 0 ? -113 + 2 * link.rssi : 0, link.provider, mbim_data_class_name(link.data_class),
           link.data_class);

    pthread_create(&rx, NULL, rx_thread, NULL);
    double avg;
    int got = ping_round(htonl(0x08080808u), 1, 5, 16, 200, 3000, &avg);
    result(got >= 4, "ping 8.8.8.8: %d/5 replies, avg %.1f ms", got, avg);
    got = ping_round(htonl(0x01010101u), 11, 5, 16, 200, 3000, &avg);
    result(got >= 4, "ping 1.1.1.1: %d/5 replies, avg %.1f ms", got, avg);
    // 1400 bytes payload：IP 封包 1428，接近 MTU，測大一點的 NTB
    got = ping_round(htonl(0x08080808u), 21, 5, 1400, 200, 3000, &avg);
    result(got >= 4, "ping 8.8.8.8 with 1428-byte packets: %d/5 replies, avg %.1f ms", got, avg);
    // 連發 50 個不等：送出路徑與接收時一個 NTB 裝多個封包
    got = ping_round(htonl(0x08080808u), 41, 50, 56, 0, 4000, &avg);
    result(got >= 45, "burst of 50 pings to 8.8.8.8: %d/50 replies", got);

    for (int i = 0; i < ipc.ndns && i < 4; i++) {
        uint8_t pkt[128];
        dns_ids[i] = (uint16_t)(0x5000 + i);
        int len = dns_query(pkt, ipc.dns[i], dns_ids[i], (uint16_t)(40000 + i));
        send_ip(pkt, len);
    }
    usleep(3000000);
    for (int i = 0; i < ipc.ndns && i < 4; i++) result(dns_ok[i], "DNS %s answers (A %s)", ip_str(ipc.dns[i], a), DNSPROBE_NAME);
    result(tx_errs == 0, "no USB transmit errors (%d)", (int)tx_errs);
    result(rx_bad_ntbs == 0, "received %d NTBs with %d packets, %d malformed", (int)rx_ntbs, (int)rx_dgrams,
           (int)rx_bad_ntbs);

out:
    g_stop = true;
    if (rx) pthread_join(rx, NULL);
    g_stop = false;  // 讓收尾的指令送得出去
    if (connected) mbim_disconnect(&m);
    mbim_dev_close(&m);
    g_stop = true;
    mbim_dev_stop(&m);
    libusb_set_interface_alt_setting(U.h, U.data_if, 0);
    libusb_release_interface(U.h, U.data_if);
    libusb_release_interface(U.h, U.comm_if);
    libusb_close(U.h);
    libusb_exit(ctx);
    printf("\n%s (%d failed)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
