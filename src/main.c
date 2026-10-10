// droidtetherd：Android USB 網路分享（RNDIS）與 4G/5G USB 數據機（MBIM）的使用者空間驅動。
// RNDIS 流程：找裝置 → RNDIS 初始化 → DHCP → 建 feth 網卡 → 向 configd 註冊網路服務 → 轉送乙太網路 frame。
// MBIM 的流程在 mbim_session.c。
// 拔線或出錯就整段拆掉，回到找裝置。

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/param.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "dhcp.h"
#include "dnsprobe.h"
#include "feth.h"
#include "netcfg.h"
#include "rndis.h"
#include "session.h"
#include "state.h"
#include "usb.h"
#include "wifi.h"

extern char **environ;

int g_verbose;
atomic_bool g_stop;
atomic_bool g_reset;

#define RX_BUF_SIZE 65536
#define MAX_FRAME (14 + 4 + MAX_MTU)  // 含 VLAN tag

// ---------- 除錯用：把進出 USB 的 frame 錄成 pcap ----------

static FILE *g_pcap;
#define PCAP_SNAPLEN 128  // 只留標頭，長時間錄也不會太大
static pthread_mutex_t g_pcap_lock = PTHREAD_MUTEX_INITIALIZER;

static int pcap_open(const char *path) {
    g_pcap = fopen(path, "wb");
    if (!g_pcap) return -1;
    chmod(path, 0644);
    uint32_t gh[6] = {0xa1b2c3d4, 0x00040002, 0, 0, PCAP_SNAPLEN, 1};
    fwrite(gh, 4, 6, g_pcap);
    fflush(g_pcap);
    return 0;
}

void pcap_frame(const uint8_t *f, int len) {
    if (!g_pcap) return;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int cap = len < PCAP_SNAPLEN ? len : PCAP_SNAPLEN;
    uint32_t h[4] = {(uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec, (uint32_t)cap, (uint32_t)len};
    pthread_mutex_lock(&g_pcap_lock);
    fwrite(h, 4, 4, g_pcap);
    fwrite(f, 1, (size_t)cap, g_pcap);
    fflush(g_pcap);
    pthread_mutex_unlock(&g_pcap_lock);
}

static const uint8_t BCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

typedef struct {
    usbdev_t *u;
    rndis_t rndis;
    uint8_t mac[6];
    uint8_t gw_mac[6];  // DHCP 伺服器（手機）的 MAC，續約時單播用
    bool gw_mac_known;
    uint32_t ip;  // network order；拿到租約前是 0
    uint32_t gw;
    feth_t net;
    atomic_bool net_ready;
    atomic_bool dead;

    pthread_mutex_t mb_lock;
    pthread_cond_t mb_cond;
    uint8_t mb_buf[1600];
    int mb_len;
    uint8_t mb_src[6];
    bool mb_full;

    atomic_ulong rx_pkts, tx_pkts, rx_bytes, tx_bytes, tx_errs, inject_errs;
} session_t;

// ---------- 共用工具 ----------

void log_msg(const char *level, const char *fmt, ...) {
    char ts[32];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(stderr, "%s %s ", ts, level);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

int run_cmd(const char *const argv[]) {
    pid_t pid;
    int rc = posix_spawn(&pid, argv[0], NULL, NULL, (char *const *)argv, environ);
    if (rc != 0) {
        LOGE("spawn %s: %s", argv[0], strerror(rc));
        return -1;
    }
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
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
    inet_ntop(AF_INET, &a, buf, 16);
    return buf;
}

time_t mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

// ---------- 送出 ----------

// frame 要放在 buf + RNDIS_PACKET_HDR。
static int send_frame(session_t *s, uint8_t *buf, int buf_cap, int frame_len) {
    int total = rndis_wrap(buf, frame_len);
    int rc = usb_send(s->u, buf, total, buf_cap);
    if (rc == LIBUSB_ERROR_NO_DEVICE) s->dead = true;
    if (rc != 0) s->tx_errs++;
    return rc;
}

static void send_dhcp(session_t *s, const dhcp_send_t *d) {
    uint8_t buf[RNDIS_PACKET_HDR + 700];
    int n = dhcp_build(buf + RNDIS_PACKET_HDR, sizeof buf - RNDIS_PACKET_HDR, d);
    if (n > 0) send_frame(s, buf, sizeof buf, n);
}

// ---------- 接收 ----------

// DHCP 回覆留給我們自己處理，其餘 frame 原封不動交給系統。
static bool take_dhcp_reply(session_t *s, const uint8_t *f, int len) {
    if (len < 14 + 20 + 8 || get_be16(f + 12) != 0x0800) return false;
    const uint8_t *ip = f + 14;
    int ihl = (ip[0] & 0x0F) * 4;
    int total = get_be16(ip + 2);
    if ((ip[0] >> 4) != 4 || ihl < 20 || ip[9] != 17 || total < ihl + 8 || total > len - 14) return false;
    const uint8_t *udp = ip + ihl;
    if (get_be16(udp + 2) != 68) return false;

    int plen = get_be16(udp + 4) - 8;
    if (plen > 0 && plen <= total - ihl - 8 && plen <= (int)sizeof s->mb_buf) {
        pthread_mutex_lock(&s->mb_lock);
        memcpy(s->mb_buf, udp + 8, (size_t)plen);
        s->mb_len = plen;
        memcpy(s->mb_src, f + 6, 6);
        s->mb_full = true;
        pthread_cond_signal(&s->mb_cond);
        pthread_mutex_unlock(&s->mb_lock);
    }
    return true;
}

static void on_frame(void *ctx, const uint8_t *f, int len) {
    session_t *s = ctx;
    pcap_frame(f, len);
    if (take_dhcp_reply(s, f, len)) return;
    if (!s->net_ready) return;
    if (feth_inject(&s->net, f, len) == 0) {
        s->rx_pkts++;
        s->rx_bytes += (unsigned long)len;
        g_rx_bytes += (unsigned long)len;
    } else {
        s->inject_errs++;
    }
}

static void *rx_thread(void *arg) {
    session_t *s = arg;
    uint8_t *buf = malloc(RX_BUF_SIZE);
    int errs = 0;
    while (!stopping() && !s->dead) {
        int got = 0;
        int rc = libusb_bulk_transfer(s->u->h, s->u->ep_in, buf, RX_BUF_SIZE, &got, 1000);
        if (rc == 0 || (rc == LIBUSB_ERROR_TIMEOUT && got > 0)) {
            errs = 0;
            rndis_unwrap(buf, got, on_frame, s);
            continue;
        }
        if (rc == LIBUSB_ERROR_TIMEOUT) continue;
        if (rc == LIBUSB_ERROR_NO_DEVICE) {
            LOGW("device disconnected");
            break;
        }
        if (rc == LIBUSB_ERROR_PIPE) libusb_clear_halt(s->u->h, s->u->ep_in);
        if (++errs >= 10) {
            LOGW("USB read keeps failing (%s), resetting session", libusb_error_name(rc));
            break;
        }
        usleep(100000);
    }
    s->dead = true;
    free(buf);
    return NULL;
}

typedef struct {
    session_t *s;
    uint8_t buf[RNDIS_PACKET_HDR + MAX_FRAME + 16];
} tx_ctx_t;

static void on_host_frame(void *ctx, const uint8_t *f, int len) {
    tx_ctx_t *t = ctx;
    pcap_frame(f, len);
    if (len > MAX_FRAME) {
        LOGW("dropping oversized frame from host (%d bytes)", len);
        return;
    }
    memcpy(t->buf + RNDIS_PACKET_HDR, f, (size_t)len);
    if (send_frame(t->s, t->buf, sizeof t->buf, len) == 0) {
        t->s->tx_pkts++;
        t->s->tx_bytes += (unsigned long)len;
        g_tx_bytes += (unsigned long)len;
    }
}

static void *tx_thread(void *arg) {
    tx_ctx_t *t = calloc(1, sizeof *t);
    t->s = arg;
    while (!stopping() && !t->s->dead) {
        if (feth_read(&t->s->net, 500, on_host_frame, t) < 0) {
            LOGE("BPF read failed: %s", strerror(errno));
            break;
        }
    }
    t->s->dead = true;
    free(t);
    return NULL;
}

// ---------- DHCP ----------

// 等一個 xid 相符的回覆。timeout_ms 內沒有就回傳 -1。
static int dhcp_wait(session_t *s, uint32_t xid, int timeout_ms, dhcp_reply_t *r, uint8_t *src_mac) {
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    pthread_mutex_lock(&s->mb_lock);
    for (;;) {
        if (s->mb_full) {
            uint8_t buf[sizeof s->mb_buf], src[6];
            int len = s->mb_len;
            memcpy(buf, s->mb_buf, (size_t)len);
            memcpy(src, s->mb_src, 6);
            s->mb_full = false;
            pthread_mutex_unlock(&s->mb_lock);
            if (dhcp_parse(buf, len, xid, s->mac, r) == 0) {
                if (src_mac) memcpy(src_mac, src, 6);
                return 0;
            }
            pthread_mutex_lock(&s->mb_lock);
            continue;
        }
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed >= timeout_ms || stopping() || s->dead) break;
        long wait = timeout_ms - elapsed;
        if (wait > 200) wait = 200;
        struct timespec rel = {.tv_sec = 0, .tv_nsec = wait * 1000000};
        pthread_cond_timedwait_relative_np(&s->mb_cond, &s->mb_lock, &rel);
    }
    pthread_mutex_unlock(&s->mb_lock);
    return -1;
}

static int dhcp_acquire(session_t *s, dhcp_reply_t *lease) {
    for (int attempt = 0; attempt < 5 && !stopping() && !s->dead; attempt++) {
        uint32_t xid = arc4random();
        dhcp_send_t d = {
            .type = DHCP_DISCOVER, .xid = xid, .mac = s->mac, .dst_mac = BCAST_MAC, .dst_ip = INADDR_BROADCAST};
        send_dhcp(s, &d);
        LOGD("DHCP DISCOVER xid=%08x", xid);

        dhcp_reply_t offer;
        bool got_offer = false;
        for (int t = 0; t < 4 && !got_offer; t++) {
            if (dhcp_wait(s, xid, 1000, &offer, NULL) == 0 && offer.msg_type == DHCP_OFFER) got_offer = true;
        }
        if (!got_offer) continue;

        d.type = DHCP_REQUEST;
        d.requested = offer.yiaddr;
        d.server_id = offer.server_id;
        send_dhcp(s, &d);
        LOGD("DHCP REQUEST xid=%08x", xid);

        dhcp_reply_t ack;
        uint8_t src[6];
        for (int t = 0; t < 4; t++) {
            if (dhcp_wait(s, xid, 1000, &ack, src) != 0) continue;
            if (ack.msg_type == DHCP_NAK) break;
            if (ack.msg_type != DHCP_ACK) continue;
            if (!ack.server_id) ack.server_id = offer.server_id;
            if (!ack.router) ack.router = offer.router ? offer.router : ack.server_id;
            if (!ack.mask) ack.mask = offer.mask;
            if (!ack.ndns && offer.ndns) {
                memcpy(ack.dns, offer.dns, sizeof ack.dns);
                ack.ndns = offer.ndns;
            }
            // Android 的閘道和 DHCP 伺服器是同一台（手機本身）。
            memcpy(s->gw_mac, src, 6);
            s->gw_mac_known = true;
            *lease = ack;
            return 0;
        }
    }
    return -1;
}

// ---------- 路由 ----------

// 預設路由目前走的介面（查 1.1.1.1），查不到時 out 為空字串。
static void default_route_iface(char *out, size_t n) {
    out[0] = '\0';
    FILE *p = popen("/sbin/route -n get -inet 1.1.1.1 2>/dev/null", "r");
    if (!p) return;
    char line[256];
    while (fgets(line, sizeof line, p)) {
        char *k = strstr(line, "interface:");
        if (!k) continue;
        k += strlen("interface:");
        while (*k == ' ') k++;
        k[strcspn(k, "\r\n")] = '\0';
        strlcpy(out, k, n);
    }
    pclose(p);
}

// configd 收到 OverridePrimary 後會自己改預設路由，這裡只等它、記一筆。
// 等不到不自己補 0/1、128/1：那是 VPN（例如 Tailscale exit node）排在前面，
// 補上去會蓋過 VPN 的預設路由，流量變成從手機明文出去（10/10 實測重現）。
void wait_default_route(const char *ifname) {
    char cur[IFNAMSIZ];
    for (int i = 0; i < 30; i++) {
        default_route_iface(cur, sizeof cur);
        if (strcmp(cur, ifname) == 0) {
            LOGI("default route now via %s (set by configd)", ifname);
            return;
        }
        sleep_ms_interruptible(100);
    }
    LOGI("default route stays on %s (a higher-ranked service such as a VPN); leaving it alone", cur[0] ? cur : "?");
}

// ---------- DNS ----------

#define DNS_PROBE_MS 1500

// 手機給的 DNS 逐一直接問，回傳有回應的幾台（放進 out）。
int probe_phone_dns(const char *ifname, const uint32_t *phone, int n, uint32_t *out) {
    if (g_dns_probe_fail) return 0;
    int k = 0;
    for (int i = 0; i < n; i++)
        if (dnsprobe_server(ifname, phone[i], DNS_PROBE_MS)) out[k++] = phone[i];
    return k;
}

// 手機不轉發 DNS 時改用的，跟 MacTethering 的預設一樣。
int fallback_dns(uint32_t *out) {
    out[0] = htonl(0x08080808u);
    out[1] = htonl(0x08080404u);
    return 2;
}

void dns_list(char *buf, size_t cap, const uint32_t *dns, int n) {
    buf[0] = '\0';
    for (int i = 0; i < n; i++) {
        char t[16];
        if (i) strlcat(buf, ",", cap);
        strlcat(buf, ip_str(dns[i], t), cap);
    }
}

// ---------- 一次連線 ----------

bool wifi_wanted(void) {
    pthread_mutex_lock(&g_state_lock);
    bool w = g_cfg.wifi_off && g_cfg.primary;
    pthread_mutex_unlock(&g_state_lock);
    return w;
}

// 回傳 true 表示還沒連上就失敗了。
static bool run_session(usbdev_t *u, const dt_config *opt) {
    session_t *s = calloc(1, sizeof *s);
    s->u = u;
    s->net.bpf = -1;
    pthread_mutex_init(&s->mb_lock, NULL);
    pthread_cond_init(&s->mb_cond, NULL);
    pthread_t rx = 0, tx = 0;
    char b1[16], b2[16];
    bool published = false;

    LOGI("found %s (%04x:%04x)", u->name, u->vid, u->pid);
    g_rx_bytes = 0;
    g_tx_bytes = 0;
    status_set(ST_CONNECTING, u->name, "");
    const char *err = NULL;
    if (rndis_init(&s->rndis, u) != 0) {
        err = "rndis_failed";
        goto out;
    }
    memcpy(s->mac, s->rndis.mac, 6);

    pthread_create(&rx, NULL, rx_thread, s);

    dhcp_reply_t lease;
    if (dhcp_acquire(s, &lease) != 0) {
        if (!stopping()) {
            LOGE("DHCP failed; is USB tethering enabled on the phone?");
            err = "dhcp_failed";
        }
        goto out;
    }
    s->gw = lease.router;
    s->ip = lease.yiaddr;

    uint32_t dns[4];
    int ndns = 0;
    if (opt->dns_from_phone) {
        ndns = lease.ndns;
        memcpy(dns, lease.dns, sizeof dns);
        if (!ndns) dns[ndns++] = lease.router;
    } else {
        ndns = opt->ndns;
        memcpy(dns, opt->dns, sizeof dns);
    }

    int mtu = opt->mtu;
    if (!mtu) {
        mtu = (int)s->rndis.max_frame;
        if (lease.mtu && lease.mtu < mtu) mtu = lease.mtu;
    }
    if (mtu > MAX_MTU) mtu = MAX_MTU;
    if (mtu < 576) mtu = 576;

    uint32_t mask = lease.mask ? lease.mask : htonl(0xFFFFFF00u);
    if (feth_create(&s->net, s->mac, mtu) != 0) {
        err = "interface_failed";
        goto out;
    }
    s->net_ready = true;
    pthread_create(&tx, NULL, tx_thread, s);
    if (feth_set_ipv4(&s->net, s->ip, mask) != 0) {
        err = "interface_failed";
        goto out;
    }

    // 有些手機的 USB 網路分享不轉發 DNS。交給系統之前先直接問一次，沒回應就改用備用 DNS，之後定期再問手機。
    uint32_t phone_dns[4];
    int nphone = 0;
    bool fallback = false;
    if (opt->dns_from_phone) {
        memcpy(phone_dns, dns, sizeof phone_dns);
        nphone = ndns;
        ndns = probe_phone_dns(s->net.host, phone_dns, nphone, dns);
        if (!ndns) {
            char pl[80], fl[80];
            dns_list(pl, sizeof pl, phone_dns, nphone);
            ndns = fallback_dns(dns);
            dns_list(fl, sizeof fl, dns, ndns);
            LOGW("phone did not answer DNS at %s; using %s and asking the phone again every %ds", pl, fl,
                 DNS_REPROBE_S);
            fallback = true;
        }
    }

    if (netcfg_publish(s->net.host, s->ip, mask, s->gw, dns, ndns, opt->primary) != 0) {
        err = "netcfg_failed";
        goto out;
    }
    published = true;
    if (opt->primary) wait_default_route(s->net.host);

    pthread_mutex_lock(&g_state_lock);
    strlcpy(g_st.ifname, s->net.host, sizeof g_st.ifname);
    g_st.ip = s->ip;
    g_st.gw = s->gw;
    g_st.mask = mask;
    memcpy(g_st.dns, dns, sizeof g_st.dns);
    g_st.ndns = ndns;
    g_st.dns_fallback = fallback;
    pthread_mutex_unlock(&g_state_lock);
    status_set(ST_CONNECTED, NULL, "");
    wifi_tether_up(wifi_wanted());

    {
        char dl[80];
        dns_list(dl, sizeof dl, dns, ndns);
        LOGI("tether up on %s: %s -> %s, dns %s, mtu %d, lease %us", s->net.host, ip_str(s->ip, b1), ip_str(s->gw, b2), dl,
             mtu, lease.lease);
    }

    // 租約維持：T1 到了就單播續約，失敗每 10 秒重送，租約到期就重來。
    uint32_t lease_s = lease.lease ? lease.lease : 3600;
    time_t start = mono_now();
    time_t renew_at = start + (lease.t1 ? lease.t1 : lease_s / 2);
    time_t expire_at = start + lease_s;
    uint32_t renew_xid = 0;
    time_t last_req = 0;
    time_t last_stats = start;
    time_t last_check = start;
    time_t last_probe = start;
    unsigned long prev[4] = {0};
    while (!stopping() && !s->dead) {
        time_t now = mono_now();
        if (g_verbose && now - last_stats >= 10) {
            unsigned long cur[4] = {s->rx_pkts, s->rx_bytes, s->tx_pkts, s->tx_bytes};
            LOGD("10s: rx %lu frames / %lu B, tx %lu frames / %lu B, usb tx errors %lu, inject errors %lu",
                 cur[0] - prev[0], cur[1] - prev[1], cur[2] - prev[2], cur[3] - prev[3], (unsigned long)s->tx_errs,
                 (unsigned long)s->inject_errs);
            memcpy(prev, cur, sizeof prev);
            last_stats = now;
        }
        // configd 重啟或有人刪掉我們的鍵時，DNS 會悄悄回到 Wi-Fi（原版的毛病）。每 5 秒確認一次，不見就補回。
        if (now - last_check >= 5) {
            last_check = now;
            if (!netcfg_present()) {
                LOGW("network service entry disappeared from configd, registering it again");
                if (netcfg_republish() == 0 && opt->primary) wait_default_route(s->net.host);
            }
            wifi_tether_up(wifi_wanted());
        }
        if (fallback && now - last_probe >= DNS_REPROBE_S) {
            last_probe = now;
            uint32_t ok_dns[4];
            int n = probe_phone_dns(s->net.host, phone_dns, nphone, ok_dns);
            if (n && netcfg_publish(s->net.host, s->ip, mask, s->gw, ok_dns, n, opt->primary) == 0) {
                char dl[80];
                dns_list(dl, sizeof dl, ok_dns, n);
                LOGI("phone answers DNS now; switched to %s", dl);
                fallback = false;
                pthread_mutex_lock(&g_state_lock);
                memcpy(g_st.dns, ok_dns, sizeof g_st.dns);
                g_st.ndns = n;
                g_st.dns_fallback = false;
                pthread_mutex_unlock(&g_state_lock);
                if (opt->primary) wait_default_route(s->net.host);
            }
        }
        if (now >= expire_at) {
            LOGW("DHCP lease expired");
            break;
        }
        if (now < renew_at) {
            sleep_ms_interruptible(500);
            continue;
        }
        if (!renew_xid || now - last_req >= 10) {
            if (!renew_xid) renew_xid = arc4random();
            dhcp_send_t d = {.type = DHCP_REQUEST,
                             .xid = renew_xid,
                             .mac = s->mac,
                             .ciaddr = s->ip,
                             .dst_mac = s->gw_mac,
                             .src_ip = s->ip,
                             .dst_ip = lease.server_id};
            send_dhcp(s, &d);
            last_req = now;
        }
        dhcp_reply_t r;
        if (dhcp_wait(s, renew_xid, 500, &r, NULL) != 0) continue;
        if (r.msg_type == DHCP_NAK) {
            LOGW("DHCP renewal refused");
            break;
        }
        if (r.msg_type != DHCP_ACK) continue;
        if (r.yiaddr != s->ip) {
            LOGW("DHCP renewal changed address, reconnecting");
            break;
        }
        lease_s = r.lease ? r.lease : lease_s;
        start = mono_now();
        renew_at = start + (r.t1 ? r.t1 : lease_s / 2);
        expire_at = start + lease_s;
        renew_xid = 0;
        LOGI("DHCP lease renewed (%us)", lease_s);
    }

out:
    if (err) status_set(ST_CONNECTING, NULL, err);
    s->dead = true;
    if (tx) pthread_join(tx, NULL);
    if (rx) pthread_join(rx, NULL);
    s->net_ready = false;
    if (published) netcfg_withdraw();
    if (s->net.host[0]) feth_destroy(&s->net);  // 介面與綁在上面的路由會一起消失

    if (s->ip && u->h) {
        // 主動釋放租約；裝置已拔掉時送不出去也沒關係。
        dhcp_send_t d = {.type = DHCP_RELEASE,
                         .xid = arc4random(),
                         .mac = s->mac,
                         .ciaddr = s->ip,
                         .server_id = s->gw,
                         .dst_mac = s->gw_mac_known ? s->gw_mac : BCAST_MAC,
                         .src_ip = s->ip,
                         .dst_ip = s->gw};
        s->dead = false;
        send_dhcp(s, &d);
    }
    rndis_halt(&s->rndis);

    if (s->ip)
        LOGI("tether down: rx %lu frames / %lu B, tx %lu frames / %lu B, usb tx errors %lu, inject errors %lu",
             (unsigned long)s->rx_pkts, (unsigned long)s->rx_bytes, (unsigned long)s->tx_pkts,
             (unsigned long)s->tx_bytes, (unsigned long)s->tx_errs, (unsigned long)s->inject_errs);
    pthread_mutex_destroy(&s->mb_lock);
    pthread_cond_destroy(&s->mb_cond);
    free(s);
    return err != NULL;
}

// ---------- 進入點 ----------

static void on_signal(int sig) {
    (void)sig;
    g_stop = true;
}

// launchd 把 stderr 接到 log 檔；超過 2 MB 就在啟動時換一份新的。
static void rotate_log(void) {
    struct stat st;
    if (fstat(STDERR_FILENO, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 2 * 1024 * 1024) return;
    char path[MAXPATHLEN];
    if (fcntl(STDERR_FILENO, F_GETPATH, path) != 0) return;
    char old[MAXPATHLEN + 4];
    snprintf(old, sizeof old, "%s.1", path);
    rename(path, old);
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        dup2(fd, STDERR_FILENO);
        close(fd);
    }
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: sudo %s [options]\n"
            "  -d, --dns LIST     'phone' (use the phone's DNS) or comma-separated IPv4 servers\n"
            "  -m, --mtu N        override MTU (default: from device / DHCP)\n"
            "      --no-primary   do not take over the default route and DNS\n"
            "  -c, --config FILE  settings file (default: " DT_CONFIG_PATH ")\n"
            "  -v, --verbose      debug logging\n"
            "      --pcap FILE    record every frame crossing USB (debugging)\n",
            argv0);
}

int main(int argc, char **argv) {
    const char *pcap_path = NULL;
    const char *config_path = DT_CONFIG_PATH;
    dt_config cli = {0};
    bool cli_dns = false, cli_no_primary = false;
    static const struct option longopts[] = {{"dns", required_argument, NULL, 'd'},
                                             {"mtu", required_argument, NULL, 'm'},
                                             {"no-primary", no_argument, NULL, 'P'},
                                             {"verbose", no_argument, NULL, 'v'},
                                             {"pcap", required_argument, NULL, 'p'},
                                             {"config", required_argument, NULL, 'c'},
                                             {"help", no_argument, NULL, 'h'},
                                             {NULL, 0, NULL, 0}};
    int c;
    while ((c = getopt_long(argc, argv, "d:m:c:vh", longopts, NULL)) != -1) {
        switch (c) {
            case 'd':
                if (config_parse_dns(optarg, &cli) != 0) {
                    fprintf(stderr, "invalid --dns: %s\n", optarg);
                    return 2;
                }
                cli_dns = true;
                break;
            case 'm':
                cli.mtu = atoi(optarg);
                break;
            case 'P':
                cli_no_primary = true;
                break;
            case 'c':
                config_path = optarg;
                break;
            case 'v':
                g_verbose = 1;
                break;
            case 'p':
                pcap_path = optarg;
                break;
            default:
                usage(argv[0]);
                return c == 'h' ? 0 : 2;
        }
    }
    if (geteuid() != 0) {
        fprintf(stderr, "droidtetherd needs root (network interfaces and configuration).\n");
        return 1;
    }

    setvbuf(stderr, NULL, _IOLBF, 0);
    rotate_log();
    // 同時只能有一份在跑，不然兩份會搶同一支手機、建同名介面。
    int lock_fd = open("/var/run/droidtetherd.lock", O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        fprintf(stderr, "another droidtetherd is already running\n");
        return 1;
    }
    if (pcap_path && pcap_open(pcap_path) != 0) {
        fprintf(stderr, "cannot open %s\n", pcap_path);
        return 1;
    }
    struct sigaction sa = {.sa_handler = on_signal};
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    libusb_context *ctx = NULL;
    int rc = libusb_init_context(&ctx, NULL, 0);
    if (rc != 0) {
        LOGE("libusb init: %s", libusb_error_name(rc));
        return 1;
    }

    // 命令列參數只影響這次執行，不寫回設定檔。
    config_load(config_path);
    pthread_mutex_lock(&g_state_lock);
    if (cli_dns) {
        g_cfg.dns_from_phone = cli.dns_from_phone;
        memcpy(g_cfg.dns, cli.dns, sizeof g_cfg.dns);
        g_cfg.ndns = cli.ndns;
    }
    if (cli_no_primary) g_cfg.primary = false;
    g_cfg.mtu = cli.mtu;
    pthread_mutex_unlock(&g_state_lock);

    netcfg_remove_stale();
    feth_destroy_stale();
    wifi_init(config_path);
    if (control_start(config_path) != 0) LOGW("control socket unavailable; menu bar app cannot talk to the daemon");
    LOGI("droidtetherd %s started", DT_VERSION);

    usb_find_result last = USB_ERROR;
    bool was_disabled = false;
    while (!g_stop) {
        g_reset = false;
        pthread_mutex_lock(&g_state_lock);
        dt_config cfg = g_cfg;
        pthread_mutex_unlock(&g_state_lock);

        if (!cfg.enabled) {
            if (!was_disabled) LOGI("paused");
            was_disabled = true;
            // 先把 Wi-Fi 開回來再回報暫停：App 或使用者看到「已暫停」時，Wi-Fi 已經是最後的狀態
            wifi_tether_gone("paused");
            status_set(ST_DISABLED, "", "");
            last = USB_ERROR;
            sleep_ms_interruptible(1000);
            continue;
        }
        was_disabled = false;

        usbdev_t u;
        memset(&u, 0, sizeof u);
        char hint[128];
        usb_find_result r = usb_find_open(ctx, &u, hint, sizeof hint);
        if (r == USB_FOUND) {
            bool failed = u.kind == DEV_MBIM ? run_mbim_session(&u, &cfg) : run_session(&u, &cfg);
            if (failed) wifi_tether_gone("connection failed");
            usb_close(&u);
            last = USB_FOUND;
            sleep_ms_interruptible(1000);
            continue;
        }
        wifi_tether_gone(r == USB_NOT_FOUND           ? "phone unplugged"
                         : r == USB_PHONE_NO_TETHER ? "USB tethering is off"
                         : r == USB_BUSY            ? "device busy"
                                                    : "USB error");
        if (r == USB_BUSY) status_set(ST_BUSY, hint, "");
        else if (r == USB_PHONE_NO_TETHER) status_set(ST_PHONE_NO_TETHER, hint, "");
        else if (r == USB_NOT_FOUND) status_set(ST_WAITING, "", "");
        if (r != last) {
            if (r == USB_BUSY) LOGW("RNDIS device %s found but busy (another tethering app holding it?)", hint);
            if (r == USB_PHONE_NO_TETHER) LOGI("%s connected, USB tethering is off", hint);
            if (r == USB_NOT_FOUND) LOGI("waiting for device");
            last = r;
        }
        sleep_ms_interruptible(2000);
    }

    wifi_tether_gone("daemon stopping");
    LOGI("droidtetherd stopping");
    libusb_exit(ctx);
    return 0;
}
