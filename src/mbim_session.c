// MBIM 數據機（4G/5G USB 網卡）的一次連線。
// 流程：開 MBIM session → 等 SIM、註冊、附著 → 用 APN 撥號 → 查 IP → 建 feth → 向 configd 註冊 → 轉送封包。
// 跟 RNDIS 的差別：沒有 DHCP，IP 從 IP_CONFIGURATION 來；資料是純 IP 封包，
// 系統這端的 feth 要自己補乙太網路標頭、回 ARP。

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "feth.h"
#include "mbim.h"
#include "netcfg.h"
#include "session.h"
#include "wifi.h"

// 本機管理的 MAC（第一個 byte 0x02）：host 給 feth，閘道是假的，只存在 ARP 回覆裡。
static const uint8_t HOST_MAC[6] = {0x02, 0x44, 0x54, 0x4d, 0x00, 0x01};
static const uint8_t GW_MAC[6] = {0x02, 0x44, 0x54, 0x4d, 0x00, 0x02};

#define RX_MIN 16384
#define MAX_FRAME (14 + MAX_MTU)

// 數據機偶爾「連著但不通」（韌體的 zombie bearer）。閒置太久就自己 ping，連續沒回就重置 USB 重來。
#define IDLE_PROBE_S 30
#define PROBE_EVERY_S 10
#define PROBE_FAILS 3
#define PROBE_ID 0x4454

typedef struct {
    usbdev_t *u;
    mbim_dev_t m;
    ntb_params_t np;
    feth_t net;
    uint32_t ip, gw;  // network order
    atomic_bool net_ready, dead, deactivated;
    atomic_long last_rx;
    pthread_mutex_t tx_lock;
    uint16_t seq;
    uint8_t *txbuf;
    int txcap;
    atomic_ulong rx_pkts, tx_pkts, rx_bytes, tx_bytes, tx_errs, inject_errs;
} msess_t;

// ---------- 控制 ----------

static void on_indicate(void *ctx, const mbim_msg_t *m) {
    msess_t *s = ctx;
    if (memcmp(m->uuid, MBIM_UUID_BASIC_CONNECT, 16) != 0) return;
    if (m->cid == MBIM_CID_CONNECT) {
        mbim_connect_info_t c;
        if (mbim_parse_connect(m->info, m->info_len, &c) == 0 && c.session == 0 && c.activation == MBIM_ACT_DEACTIVATED) {
            LOGW("network ended the data connection (nw error %u)", c.nw_error);
            s->deactivated = true;
        }
    } else if (m->cid == MBIM_CID_REGISTER_STATE) {
        uint32_t err, st;
        if (mbim_parse_register_state(m->info, m->info_len, &err, &st) == 0) LOGD("register state %u (nw error %u)", st, err);
    }
}

// ---------- 資料 ----------

static int send_ip(msess_t *s, const uint8_t *ip, int len) {
    pthread_mutex_lock(&s->tx_lock);
    int total = ntb16_build(s->txbuf, s->txcap, s->seq++, &s->np, ip, len);
    int rc = LIBUSB_ERROR_OVERFLOW;
    if (total > 0) {
        int sent = 0;
        rc = libusb_bulk_transfer(s->u->h, s->u->ep_out, s->txbuf, total, &sent, 2000);
        if (rc == 0 && sent != total) rc = LIBUSB_ERROR_IO;
        // 長度剛好是 max packet size 的倍數時補一個零長度封包，裝置才知道這個 NTB 結束了（Linux cdc_mbim 也這樣）
        if (rc == 0 && s->u->out_maxpkt > 0 && total % s->u->out_maxpkt == 0)
            libusb_bulk_transfer(s->u->h, s->u->ep_out, s->txbuf, 0, &sent, 2000);
    }
    pthread_mutex_unlock(&s->tx_lock);
    if (rc == LIBUSB_ERROR_NO_DEVICE) s->dead = true;
    if (rc != 0) s->tx_errs++;
    return rc;
}

static void on_datagram(void *ctx, const uint8_t *ip, int len) {
    msess_t *s = ctx;
    s->last_rx = mono_now();
    if (icmp_is_echo_reply(ip, len, s->ip, PROBE_ID)) return;  // 自己的探測，不交給系統
    if (!s->net_ready) return;
    uint8_t frame[14 + 65536];
    int fl = l2_to_host(frame, sizeof frame, ip, len, HOST_MAC, GW_MAC);
    if (fl <= 0) return;
    pcap_frame(frame, fl);
    if (feth_inject(&s->net, frame, fl) == 0) {
        s->rx_pkts++;
        s->rx_bytes += (unsigned long)len;
        g_rx_bytes += (unsigned long)len;
    } else {
        s->inject_errs++;
    }
}

static void *rx_thread(void *arg) {
    msess_t *s = arg;
    int cap = s->np.in_max > RX_MIN ? (int)s->np.in_max : RX_MIN;
    cap = (cap + 1023) & ~1023;  // bulk IN 的緩衝區要是 max packet size 的倍數，否則會 overflow
    uint8_t *buf = malloc((size_t)cap);
    int errs = 0;
    while (!stopping() && !s->dead) {
        int got = 0;
        int rc = libusb_bulk_transfer(s->u->h, s->u->ep_in, buf, cap, &got, 1000);
        if (rc == 0 || (rc == LIBUSB_ERROR_TIMEOUT && got > 0)) {
            errs = 0;
            if (got && ntb16_parse(buf, got, on_datagram, s) < 0) LOGD("dropped malformed NTB (%d bytes)", got);
            continue;
        }
        if (rc == LIBUSB_ERROR_TIMEOUT) continue;
        if (rc == LIBUSB_ERROR_NO_DEVICE) {
            LOGW("modem disconnected");
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

static void on_host_frame(void *ctx, const uint8_t *f, int len) {
    msess_t *s = ctx;
    uint8_t reply[64];
    int rlen = 0;
    const uint8_t *ip = NULL;
    int ilen = 0;
    switch (l2_from_host(f, len, s->ip, GW_MAC, reply, &rlen, &ip, &ilen)) {
        case 1:
            feth_inject(&s->net, reply, rlen);
            break;
        case 2:
            pcap_frame(f, len);
            if (send_ip(s, ip, ilen) == 0) {
                s->tx_pkts++;
                s->tx_bytes += (unsigned long)ilen;
                g_tx_bytes += (unsigned long)ilen;
            }
            break;
        default:
            break;  // IPv6 等：這條連線只有 IPv4
    }
}

static void *tx_thread(void *arg) {
    msess_t *s = arg;
    while (!stopping() && !s->dead) {
        if (feth_read(&s->net, 500, on_host_frame, s) < 0) {
            LOGE("BPF read failed: %s", strerror(errno));
            break;
        }
    }
    s->dead = true;
    return NULL;
}

// ---------- 一次連線 ----------

bool run_mbim_session(usbdev_t *u, const dt_config *opt) {
    msess_t *s = calloc(1, sizeof *s);
    s->u = u;
    s->net.bpf = -1;
    pthread_mutex_init(&s->tx_lock, NULL);
    pthread_t rx = 0, tx = 0;
    char b1[16], b2[16];
    bool published = false, reset_usb = false, connected = false;
    const char *err = NULL;

    LOGI("found %s (%04x:%04x, MBIM)", u->name, u->vid, u->pid);
    g_rx_bytes = 0;
    g_tx_bytes = 0;
    status_set(ST_CONNECTING, u->name, "");

    if (mbim_dev_start(&s->m, u, on_indicate, s) != 0 || mbim_data_start(u, &s->np) != 0) {
        err = "mbim_failed";
        goto out;
    }
    if (mbim_dev_open(&s->m) != 0) {
        err = "mbim_failed";
        reset_usb = !s->m.dead;  // 卡在 NotOpened 之類的狀態，PVE 上也要 USB rebind 才會好
        goto out;
    }
    mbim_ipv4_t ipc;
    err = mbim_connect(&s->m, opt->apn, &ipc);
    if (err) {
        if (stopping()) err = NULL;
        goto out;
    }
    connected = true;
    s->ip = ipc.ip;
    s->gw = ipc.gw ? ipc.gw : ipc.ip;
    uint32_t mask = mbim_netmask(s->ip, s->gw, ipc.prefix);

    uint32_t dns[4];
    int ndns = 0;
    if (opt->dns_from_phone) {
        ndns = ipc.ndns;
        memcpy(dns, ipc.dns, sizeof dns);
    } else {
        ndns = opt->ndns;
        memcpy(dns, opt->dns, sizeof dns);
    }
    int mtu = opt->mtu ? opt->mtu : (ipc.mtu ? (int)ipc.mtu : MAX_MTU);
    if (mtu > MAX_MTU) mtu = MAX_MTU;
    if (mtu < 576) mtu = 576;

    s->txcap = (int)(s->np.out_max < 65535 ? s->np.out_max : 65535);
    s->txbuf = malloc((size_t)s->txcap);
    s->last_rx = mono_now();
    pthread_create(&rx, NULL, rx_thread, s);

    if (feth_create(&s->net, HOST_MAC, mtu) != 0) {
        err = "interface_failed";
        goto out;
    }
    s->net_ready = true;
    pthread_create(&tx, NULL, tx_thread, s);
    if (feth_set_ipv4(&s->net, s->ip, mask) != 0) {
        err = "interface_failed";
        goto out;
    }

    // 數據機給的 DNS（電信商的）一樣先直接問一次，沒回應就改用備用 DNS
    uint32_t phone_dns[4];
    int nphone = 0;
    bool fallback = false;
    if (opt->dns_from_phone) {
        memcpy(phone_dns, dns, sizeof phone_dns);
        nphone = ndns;
        ndns = nphone ? probe_phone_dns(s->net.host, phone_dns, nphone, dns) : 0;
        if (!ndns) {
            char fl[80];
            ndns = fallback_dns(dns);
            dns_list(fl, sizeof fl, dns, ndns);
            LOGW("network DNS did not answer; using %s and asking again every %ds", fl, DNS_REPROBE_S);
            fallback = nphone > 0;
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
        LOGI("modem up on %s: %s/%d -> %s, dns %s, mtu %d", s->net.host, ip_str(s->ip, b1), ipc.prefix,
             ip_str(s->gw, b2), dl, mtu);
    }

    time_t start = mono_now();
    time_t last_check = start, last_probe = start, last_ping = 0;
    int unanswered = 0;
    long rx_at_ping = 0;
    uint16_t ping_seq = 0;
    uint32_t probe_dst = htonl(0x08080808u);
    while (!stopping() && !s->dead && !s->m.dead) {
        time_t now = mono_now();
        if (s->deactivated) break;
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
                LOGI("network DNS answers now; switched to %s", dl);
                fallback = false;
                pthread_mutex_lock(&g_state_lock);
                memcpy(g_st.dns, ok_dns, sizeof g_st.dns);
                g_st.ndns = n;
                g_st.dns_fallback = false;
                pthread_mutex_unlock(&g_state_lock);
                if (opt->primary) wait_default_route(s->net.host);
            }
        }
        // 有收到東西就代表通的；閒置超過 IDLE_PROBE_S 才 ping
        if (s->last_rx > rx_at_ping) unanswered = 0;
        if (now - s->last_rx >= IDLE_PROBE_S && now - last_ping >= PROBE_EVERY_S) {
            if (last_ping && s->last_rx <= rx_at_ping) unanswered++;
            if (unanswered >= PROBE_FAILS) {
                LOGW("modem reports connected but nothing comes back (%d pings to 8.8.8.8 unanswered); resetting it",
                     unanswered);
                reset_usb = true;
                break;
            }
            uint8_t pkt[64];
            int pl = icmp_echo_build(pkt, sizeof pkt, s->ip, probe_dst, PROBE_ID, ++ping_seq);
            rx_at_ping = s->last_rx;
            last_ping = now;
            if (pl > 0) send_ip(s, pkt, pl);
        }
        sleep_ms_interruptible(500);
    }

out:
    if (err) status_set(ST_CONNECTING, NULL, err);
    if (err) LOGE("modem connection failed: %s", err);
    s->dead = true;
    if (tx) pthread_join(tx, NULL);
    if (rx) pthread_join(rx, NULL);
    s->net_ready = false;
    if (published) netcfg_withdraw();
    if (s->net.host[0]) feth_destroy(&s->net);

    if (!s->m.dead && u->h) {
        if (connected) {
            // 主動掛斷，數據機下次才不會卡著舊的連線
            mbim_disconnect(&s->m);
        }
        mbim_dev_close(&s->m);
        libusb_set_interface_alt_setting(u->h, u->data_if, 0);
    }
    mbim_dev_stop(&s->m);
    if (reset_usb && u->h && !stopping()) {
        int rc = libusb_reset_device(u->h);
        LOGI("USB reset of the modem: %s", rc == 0 ? "done" : libusb_error_name(rc));
    }

    if (connected)
        LOGI("modem down: rx %lu packets / %lu B, tx %lu packets / %lu B, usb tx errors %lu, inject errors %lu",
             (unsigned long)s->rx_pkts, (unsigned long)s->rx_bytes, (unsigned long)s->tx_pkts,
             (unsigned long)s->tx_bytes, (unsigned long)s->tx_errs, (unsigned long)s->inject_errs);
    free(s->txbuf);
    pthread_mutex_destroy(&s->tx_lock);
    free(s);
    return err != NULL;
}
