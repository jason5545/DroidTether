// MBIM 數據機（4G/5G USB 網卡）的一次連線。
// 流程：開 MBIM session → 等 SIM、註冊、附著 → 用 APN 撥號 → 查 IP → 建 feth → 向 configd 註冊 → 轉送封包。
// 跟 RNDIS 的差別：沒有 DHCP，IP 從 IP_CONFIGURATION 來；資料是純 IP 封包，
// 系統這端的 feth 要自己補乙太網路標頭、回 ARP。

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "feth.h"
#include "mbim.h"
#include "netcfg.h"
#include "session.h"
#include "sms.h"
#include "sms_store.h"
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

#define LINK_EVERY_S 15  // 訊號、電信商、網路制式多久查一次
#define SIM_RETRY_S 10   // SIM、APN、註冊的錯誤等多久再重開一次

#define SMS_POLL_S 30            // 數據機沒通知也每 30 秒讀一次簡訊儲存區
#define SMS_PARTIAL_S 1800       // 多段簡訊缺段等 30 分鐘，還不齊就先存收到的部分
#define SMS_MAX_RECORDS 64       // IK512 的儲存區是 40 則
#define SMS_RESP_BUF 16384
#define SMS_CMD_TIMEOUT_MS 20000
#define SMS_SEND_TIMEOUT_MS 60000

// 多段簡訊還沒收齊的那幾組（只記在這次連線裡）
typedef struct {
    char addr[48];
    uint16_t ref;
    uint8_t total;
    time_t first_seen;
} sms_partial_t;

typedef struct {
    usbdev_t *u;
    mbim_dev_t m;
    ntb_params_t np;
    feth_t net;
    uint32_t ip, gw;  // network order
    uint8_t ip6[16];
    bool has_ip6;
    atomic_bool net_ready, dead, deactivated;
    atomic_long last_rx;
    pthread_mutex_t tx_lock;
    uint16_t seq;
    uint8_t *txbuf;
    int txcap;
    atomic_ulong rx_pkts, tx_pkts, rx_bytes, tx_bytes, tx_errs, inject_errs;
    // 簡訊
    bool sms_ready;          // 儲存區準備好了
    atomic_bool sms_kick;    // 數據機通知有新簡訊或儲存區滿了：主迴圈馬上去讀
    pthread_mutex_t flash_lock;
    uint8_t flash[4096];     // class 0 簡訊：PDU 直接在 indication 裡，不進儲存區
    uint32_t flash_len;
    sms_partial_t partial[8];
} msess_t;

// ---------- 控制 ----------

static void on_sms_indicate(msess_t *s, const mbim_msg_t *m) {
    if (m->cid == MBIM_CID_SMS_MESSAGE_STORE_STATUS) {
        uint32_t flag, index;
        if (mbim_parse_sms_store_status(m->info, m->info_len, &flag, &index) != 0) return;
        LOGD("SMS store status 0x%x", flag);
        if (flag & (MBIM_SMS_STORE_NEW_MESSAGE | MBIM_SMS_STORE_FULL)) s->sms_kick = true;
    } else if (m->cid == MBIM_CID_SMS_READ) {
        pthread_mutex_lock(&s->flash_lock);
        if (!s->flash_len && m->info_len <= sizeof s->flash) {
            memcpy(s->flash, m->info, m->info_len);
            s->flash_len = m->info_len;
        }
        pthread_mutex_unlock(&s->flash_lock);
        s->sms_kick = true;
    }
}

static void on_indicate(void *ctx, const mbim_msg_t *m) {
    msess_t *s = ctx;
    if (memcmp(m->uuid, MBIM_UUID_SMS, 16) == 0) {
        on_sms_indicate(s, m);
        return;
    }
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

static void update_link(msess_t *s, const char *custom) {
    mbim_link_t l;
    if (mbim_query_link(&s->m, &l) != 0) return;
    status_set_link(l.bars, l.rssi >= 0 ? -113 + 2 * l.rssi : 0, l.provider, mbim_tech_name(l.data_class, custom));
}

// ---------- 簡訊 ----------
// 數據機裡的簡訊讀出來、寫進收件匣檔案（fsync 完）之後就從數據機刪掉（Jason 2026/10/10 決定）：
// IK512 只放得下 40 則，滿了新簡訊就收不進來。多段簡訊等全部到齊、合併存好才刪。
// 號碼和內容不寫進 log。

static bool sms_delete(msess_t *s, uint32_t index) {
    uint8_t info[8], out[64];
    uint32_t st = 0;
    int il = mbim_info_sms_delete(info, MBIM_SMS_FLAG_INDEX, index);
    int n = mbim_dev_command(&s->m, MBIM_UUID_SMS, MBIM_CID_SMS_DELETE, true, info, il, out, sizeof out, &st,
                             SMS_CMD_TIMEOUT_MS);
    if (n < 0 || st != 0) {
        LOGW("SMS: could not remove slot %u from the modem (%s)", index, n < 0 ? "no answer" : mbim_status_name(st));
        return false;
    }
    return true;
}

// 收到或送出一則：這支數據機能用簡訊。送簡訊被拒（MBIM failure，一段都沒送出）：記下來，App 不顯示簡訊入口。
static void sms_mark_usable(msess_t *s, bool usable) {
    pthread_mutex_lock(&g_state_lock);
    bool was = g_st.sms_unsupported;
    g_st.sms_unsupported = !usable;
    pthread_mutex_unlock(&g_state_lock);
    if (was == !usable) return;
    sms_modem_set_unsupported(s->u->vid, s->u->pid, !usable);
    if (usable) LOGI("SMS: the modem handles SMS after all; showing Messages again");
    else LOGW("SMS: the modem refused to send; hiding Messages for %04x:%04x until it sends or receives one", s->u->vid, s->u->pid);
}

// 這組多段簡訊第一次看到是多久以前（秒）。第一次看到就記下來，回傳 0。
static time_t partial_age(msess_t *s, const sms_pdu_t *p) {
    time_t now = mono_now();
    int oldest = 0;
    for (int i = 0; i < (int)(sizeof s->partial / sizeof s->partial[0]); i++) {
        sms_partial_t *e = &s->partial[i];
        if (e->total == p->total && e->ref == p->ref && strcmp(e->addr, p->addr) == 0) return now - e->first_seen;
        if (e->first_seen < s->partial[oldest].first_seen) oldest = i;
    }
    sms_partial_t *e = &s->partial[oldest];
    strlcpy(e->addr, p->addr, sizeof e->addr);
    e->ref = p->ref;
    e->total = p->total;
    e->first_seen = now;
    return 0;
}

static void partial_forget(msess_t *s, const sms_pdu_t *p) {
    for (int i = 0; i < (int)(sizeof s->partial / sizeof s->partial[0]); i++) {
        sms_partial_t *e = &s->partial[i];
        if (e->total == p->total && e->ref == p->ref && strcmp(e->addr, p->addr) == 0) memset(e, 0, sizeof *e);
    }
}

// 處理讀到的簡訊。stored 表示在數據機的儲存區裡（存好要刪）；false 是 indication 直接帶來的 class 0 簡訊。
static void sms_take(msess_t *s, const mbim_sms_record_t *r, int cnt, bool stored) {
    sms_pdu_t *p = calloc((size_t)cnt, sizeof *p);
    uint8_t *mark = calloc((size_t)cnt, 1);  // 0 待處理、1 不是收到的簡訊（不動）、2 處理完（要刪）、3 這次先不處理
    if (!p || !mark) goto out;
    for (int i = 0; i < cnt; i++) {
        if (sms_decode(r[i].pdu, (int)r[i].len, &p[i]) != 0 || p[i].submit) {
            LOGD("SMS: slot %u is not a received message; leaving it", r[i].index);
            mark[i] = 1;
        } else if (p[i].pid == 0x40 || p[i].port) {
            LOGI("SMS: discarded a %s message", p[i].pid == 0x40 ? "silent (type 0)" : "port-addressed (WAP push, MMS notice)");
            mark[i] = 2;
        }
    }
    for (int i = 0; i < cnt; i++) {
        if (mark[i]) continue;
        if (p[i].total <= 1) {
            uint64_t uid = sms_hash(SMS_HASH_INIT, r[i].pdu, r[i].len);
            bool dup = sms_store_has(uid);
            if (sms_store_add_received(uid, p[i].addr, p[i].time, p[i].text, 1)) {
                mark[i] = 2;
                if (!dup) {
                    LOGI("SMS: received a message");
                    sms_mark_usable(s, true);
                }
            }
            continue;
        }
        if (!stored) {
            mark[i] = 3;  // 多段的 class 0 很少見；只處理儲存區裡的多段簡訊
            continue;
        }
        // 多段：同一個寄件者、reference、段數的湊成一組，每段取第一個
        int at[256], present = 0;
        for (int k = 0; k <= p[i].total; k++) at[k] = -1;
        for (int j = i; j < cnt; j++) {
            if (mark[j] || p[j].total != p[i].total || p[j].ref != p[i].ref || strcmp(p[j].addr, p[i].addr) != 0) continue;
            if (at[p[j].seq] < 0) {
                at[p[j].seq] = j;
                present++;
            }
        }
        bool complete = present == p[i].total;
        if (!complete && partial_age(s, &p[i]) < SMS_PARTIAL_S) {
            LOGD("SMS: waiting for %d more parts", p[i].total - present);
            for (int k = 1; k <= p[i].total; k++)
                if (at[k] >= 0) mark[at[k]] = 3;
            continue;
        }
        char *text = malloc((size_t)present * SMS_TEXT_MAX + (size_t)p[i].total * 4 + 1);
        if (!text) break;
        text[0] = '\0';
        uint64_t uid = SMS_HASH_INIT;
        time_t t = 0;
        for (int k = 1; k <= p[i].total; k++) {
            if (at[k] < 0) {
                strcat(text, "…");  // 沒收到的那一段
                continue;
            }
            const sms_pdu_t *q = &p[at[k]];
            strcat(text, q->text);
            uid = sms_hash(uid, r[at[k]].pdu, r[at[k]].len);
            if (!t) t = q->time;
        }
        bool dup = sms_store_has(uid);
        if (sms_store_add_received(uid, p[i].addr, t, text, present)) {
            if (!dup) {
                LOGI("SMS: received a message (%d parts%s)", p[i].total, complete ? "" : ", some never arrived");
                sms_mark_usable(s, true);
            }
            partial_forget(s, &p[i]);
            // 同一組的都刪（包括重複收到的段）
            for (int j = i; j < cnt; j++)
                if (!mark[j] && p[j].total == p[i].total && p[j].ref == p[i].ref && strcmp(p[j].addr, p[i].addr) == 0)
                    mark[j] = 2;
        }
        free(text);
    }
    if (stored) {
        int removed = 0;
        for (int i = 0; i < cnt; i++)
            if (mark[i] == 2 && sms_delete(s, r[i].index)) removed++;
        if (removed) LOGD("SMS: removed %d slots from the modem", removed);
    }
out:
    free(p);
    free(mark);
}

// 儲存區準備好了沒、滿了沒、讀新簡訊、處理 class 0 簡訊。
static void sms_service(msess_t *s) {
    uint8_t *out = malloc(SMS_RESP_BUF), info[16];
    uint32_t st = 0;
    int n;
    if (!out) return;
    if (!s->sms_ready) {
        mbim_sms_config_t c;
        n = mbim_dev_command(&s->m, MBIM_UUID_SMS, MBIM_CID_SMS_CONFIGURATION, false, NULL, 0, out, SMS_RESP_BUF, &st,
                             SMS_CMD_TIMEOUT_MS);
        if (n >= 0 && st == 0 && mbim_parse_sms_config(out, (uint32_t)n, &c) == 0 && c.storage_state == 1 && c.format == 0) {
            s->sms_ready = true;
            bool unsupported = sms_modem_unsupported(s->u->vid, s->u->pid);
            pthread_mutex_lock(&g_state_lock);
            g_st.sms_unsupported = unsupported;
            pthread_mutex_unlock(&g_state_lock);
            LOGI("SMS: modem storage ready (%u slots)%s", c.max_messages,
                 unsupported ? "; this modem refused to send before, Messages stays hidden" : "");
        } else {
            LOGD("SMS: storage not ready (%s)", n < 0 ? "no answer" : mbim_status_name(st));
        }
    }
    if (s->sms_ready) {
        uint32_t flag = 0, index = 0;
        n = mbim_dev_command(&s->m, MBIM_UUID_SMS, MBIM_CID_SMS_MESSAGE_STORE_STATUS, false, NULL, 0, out, SMS_RESP_BUF,
                             &st, SMS_CMD_TIMEOUT_MS);
        bool full = n >= 0 && st == 0 && mbim_parse_sms_store_status(out, (uint32_t)n, &flag, &index) == 0 &&
                    (flag & MBIM_SMS_STORE_FULL);
        int il = mbim_info_sms_read(info, MBIM_SMS_FLAG_ALL, 0);
        n = mbim_dev_command(&s->m, MBIM_UUID_SMS, MBIM_CID_SMS_READ, false, info, il, out, SMS_RESP_BUF, &st,
                             SMS_CMD_TIMEOUT_MS);
        if (n >= 0 && st == 0) {
            mbim_sms_record_t rec[SMS_MAX_RECORDS];
            int cnt = mbim_parse_sms_read(out, (uint32_t)n, rec, SMS_MAX_RECORDS);
            if (cnt > 0) sms_take(s, rec, cnt, true);
        } else {
            LOGD("SMS: reading the modem storage failed (%s)", n < 0 ? "no answer" : mbim_status_name(st));
        }
        pthread_mutex_lock(&g_state_lock);
        if (full && !g_st.sms_full) LOGW("SMS: the modem's message storage is full");
        g_st.sms_ready = true;
        g_st.sms_full = full;
        pthread_mutex_unlock(&g_state_lock);
    }
    pthread_mutex_lock(&s->flash_lock);
    uint32_t fl = s->flash_len;
    if (fl) memcpy(out, s->flash, fl);
    s->flash_len = 0;
    pthread_mutex_unlock(&s->flash_lock);
    if (fl) {
        mbim_sms_record_t rec[8];
        int cnt = mbim_parse_sms_read(out, fl, rec, 8);
        if (cnt > 0) sms_take(s, rec, cnt, false);
    }
    free(out);
}

// 寄件佇列裡的簡訊一則一則送。送到一半失敗不重試（已經送出去的那幾段收不回來，重送會重複收費）。
static void sms_send_queued(msess_t *s) {
    static uint8_t ref;
    if (!ref) ref = (uint8_t)(arc4random() | 1);
    uint32_t id;
    char number[48], *text;
    while (!stopping() && !s->dead && !s->m.dead && sms_store_next_queued(&id, number, sizeof number, &text)) {
        uint8_t(*pdu)[SMS_PDU_MAX] = malloc(SMS_MAX_PARTS * sizeof *pdu);
        int len[SMS_MAX_PARTS];
        int parts = pdu ? sms_encode_submit(number, text, ref++, -1, pdu, len, SMS_MAX_PARTS) : -1;
        free(text);
        const char *err = parts < 0 ? "invalid" : NULL;
        int sent = 0;
        uint32_t st = 0;
        for (int k = 0; k < parts && !err; k++) {
            uint8_t info[12 + SMS_PDU_MAX + 4], out[64];
            int il = mbim_info_sms_send(info, sizeof info, pdu[k], len[k]);
            int n = il > 0 ? mbim_dev_command(&s->m, MBIM_UUID_SMS, MBIM_CID_SMS_SEND, true, info, il, out, sizeof out, &st,
                                              SMS_SEND_TIMEOUT_MS)
                           : -1;
            if (n < 0 || st != 0) err = sent ? "partial" : n < 0 ? "no_answer" : "rejected";
            else sent++;
        }
        free(pdu);
        sms_store_finish(id, err);
        if (!err) sms_mark_usable(s, true);
        else if (!sent && st == 2) sms_mark_usable(s, false);  // MBIM_STATUS_FAILURE
        if (err)
            LOGW("SMS: sending failed after %d of %d parts (%s%s%s)", sent, parts, err, st ? ", " : "",
                 st ? mbim_status_name(st) : "");
        else
            LOGI("SMS: sent a message (%d part%s)", parts, parts == 1 ? "" : "s");
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
    uint8_t reply[128];
    int rlen = 0;
    const uint8_t *ip = NULL;
    int ilen = 0;
    switch (l2_from_host(f, len, s->ip, s->has_ip6 ? s->ip6 : NULL, GW_MAC, reply, &rlen, &ip, &ilen)) {
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
            break;  // link-local、多播，或沒有 IPv6 時的 IPv6
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
    pthread_mutex_init(&s->flash_lock, NULL);
    pthread_t rx = 0, tx = 0;
    char b1[16], b2[16];
    bool published = false, reset_usb = false, connected = false;
    const char *err = NULL;

    LOGI("found %s (%04x:%04x, MBIM)", u->name, u->vid, u->pid);
    g_rx_bytes = 0;
    g_tx_bytes = 0;
    // 錯誤訊息留著，連上了才清：每次重試都清掉的話，App 上只會閃一下
    status_set(ST_CONNECTING, u->name, NULL);
    pthread_mutex_lock(&g_state_lock);
    g_st.modem = true;
    pthread_mutex_unlock(&g_state_lock);
    char pin[16];
    sim_pin_load(pin, sizeof pin);

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
    mbim_ipv6_t ip6;
    mbim_connect_opts_t co = {.apn = opt->apn, .ipv6 = opt->ipv6, .pin = pin};
    err = mbim_connect(&s->m, &co, &ipc, &ip6);
    memset(pin, 0, sizeof pin);
    if (co.pin_rejected) {
        LOGW("forgetting the saved SIM PIN so it is not tried again");
        sim_pin_forget();
    }
    pthread_mutex_lock(&g_state_lock);
    g_st.pin_attempts = co.pin_attempts;
    pthread_mutex_unlock(&g_state_lock);
    if (err) {
        if (stopping()) err = NULL;
        goto out;
    }
    char custom[32];
    mbim_query_custom_class(&s->m, custom, sizeof custom);
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
    char ip6str[64] = "";
    if (opt->ipv6 && ip6.prefix) {
        if (feth_set_ipv6(&s->net, ip6.addr, ip6.prefix) == 0) {
            memcpy(s->ip6, ip6.addr, 16);
            s->has_ip6 = true;
            netcfg_set_ipv6(ip6.addr, ip6.prefix, ip6.has_gw ? ip6.gw : NULL, (const uint8_t(*)[16])ip6.dns, ip6.ndns);
            char a6[48];
            inet_ntop(AF_INET6, ip6.addr, a6, sizeof a6);
            snprintf(ip6str, sizeof ip6str, "%s/%d", a6, ip6.prefix);
        } else {
            LOGW("could not add the IPv6 address; continuing with IPv4 only");
        }
    }

    // 電信商的 DNS 不在數據機給的子網路裡（手機的 DNS 就是閘道，不一樣），configd 裝好這個服務的路由之前問不到。
    // 所以先用它註冊，路由好了再直接問一次，沒回應才改用備用 DNS。2026/10/10 實測：先問再註冊，每次都會白白退回一分鐘。
    uint32_t phone_dns[4];
    int nphone = 0;
    bool fallback = false;
    if (opt->dns_from_phone && !ndns) {
        ndns = fallback_dns(dns);  // 網路沒給 DNS
        LOGW("network gave no DNS; using public DNS");
    }
    if (netcfg_publish(s->net.host, s->ip, mask, s->gw, dns, ndns, opt->primary) != 0) {
        err = "netcfg_failed";
        goto out;
    }
    published = true;
    if (opt->primary) wait_default_route(s->net.host);
    else sleep_ms_interruptible(500);  // 不當主要連線時 configd 只裝這個介面專用的路由，給它一點時間
    if (opt->dns_from_phone && ipc.ndns) {
        memcpy(phone_dns, dns, sizeof phone_dns);
        nphone = ndns;
        uint32_t ok_dns[4];
        int n = probe_phone_dns(s->net.host, phone_dns, nphone, ok_dns);
        if (!n) {
            char fl[80];
            ndns = fallback_dns(dns);
            dns_list(fl, sizeof fl, dns, ndns);
            LOGW("network DNS did not answer; using %s and asking again every %ds", fl, DNS_REPROBE_S);
            fallback = true;
        } else {
            ndns = n;
            memcpy(dns, ok_dns, sizeof dns);
        }
        if ((!n || n != nphone) && netcfg_publish(s->net.host, s->ip, mask, s->gw, dns, ndns, opt->primary) != 0) {
            err = "netcfg_failed";
            goto out;
        }
    }

    pthread_mutex_lock(&g_state_lock);
    strlcpy(g_st.ifname, s->net.host, sizeof g_st.ifname);
    g_st.ip = s->ip;
    g_st.gw = s->gw;
    g_st.mask = mask;
    memcpy(g_st.dns, dns, sizeof g_st.dns);
    g_st.ndns = ndns;
    g_st.dns_fallback = fallback;
    strlcpy(g_st.ipv6, ip6str, sizeof g_st.ipv6);
    g_st.ndns6 = 0;
    for (int i = 0; s->has_ip6 && i < ip6.ndns && i < 2; i++)
        inet_ntop(AF_INET6, ip6.dns[i], g_st.dns6[g_st.ndns6++], sizeof g_st.dns6[0]);
    pthread_mutex_unlock(&g_state_lock);
    status_set(ST_CONNECTED, NULL, "");
    update_link(s, custom);
    wifi_tether_up(wifi_wanted());
    {
        char dl[80];
        dns_list(dl, sizeof dl, dns, ndns);
        LOGI("modem up on %s: %s/%d -> %s, dns %s, mtu %d%s%s", s->net.host, ip_str(s->ip, b1), ipc.prefix,
             ip_str(s->gw, b2), dl, mtu, ip6str[0] ? ", IPv6 " : "", ip6str);
    }

    time_t start = mono_now();
    time_t last_check = start, last_probe = start, last_ping = 0, last_link = start, last_sms = 0;
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
        if (now - last_link >= LINK_EVERY_S) {
            last_link = now;
            update_link(s, custom);
        }
        if (s->sms_kick || now - last_sms >= SMS_POLL_S) {
            s->sms_kick = false;
            last_sms = now;
            sms_service(s);
        }
        if (s->sms_ready) sms_send_queued(s);
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
    pthread_mutex_lock(&g_state_lock);
    g_st.sms_ready = false;
    g_st.sms_full = false;
    g_st.sms_unsupported = false;
    pthread_mutex_unlock(&g_state_lock);
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

    // 要 PIN、APN 錯了、註冊不上，這些不會馬上好；別每秒重開一次 MBIM、重撥一次（電信商也不喜歡），
    // 等一下再試。App 送 PIN、改 APN 會觸發重連，打斷這段等待。
    if (err && (strncmp(err, "sim_", 4) == 0 || strcmp(err, "connect_failed") == 0 || strcmp(err, "not_registered") == 0))
        sleep_ms_interruptible(SIM_RETRY_S * 1000);

    if (connected)
        LOGI("modem down: rx %lu packets / %lu B, tx %lu packets / %lu B, usb tx errors %lu, inject errors %lu",
             (unsigned long)s->rx_pkts, (unsigned long)s->rx_bytes, (unsigned long)s->tx_pkts,
             (unsigned long)s->tx_bytes, (unsigned long)s->tx_errs, (unsigned long)s->inject_errs);
    free(s->txbuf);
    pthread_mutex_destroy(&s->tx_lock);
    pthread_mutex_destroy(&s->flash_lock);
    free(s);
    return err != NULL;
}
