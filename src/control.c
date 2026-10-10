// 給選單列 App 用的控制介面：Unix socket，一行一個指令，回一行 JSON。
//   status                     目前狀態
//   set enabled 0|1            暫停 / 恢復
//   set primary 0|1            要不要當主要連線
//   set dns phone|IP[,IP...]   DNS 來源
//   set wifi_off 0|1           連線時關掉 Wi-Fi（不用重連）
//   set apn NAME               MBIM 數據機撥號用的 APN
//   set ipv6 0|1               MBIM 數據機要不要 IPv6
//   sim pin NNNN               存下 SIM PIN 並重新連線（只會試一次，被拒就刪掉）
//   sim forget-pin             刪掉存著的 SIM PIN
//   sms list                   收件匣與寄件（時間由舊到新）
//   sms send NUMBER TEXT       排進寄件佇列（TEXT 用 \n、\t、\\ 跳脫），連著數據機就馬上送
//   sms delete ID[,ID...]      從收件匣刪掉（數據機裡的早就刪了）
//   sms read ID[,ID...]|all    標成已讀
//   reconnect                  斷開重連
//   quit                       結束行程（launchd 會重新啟動，用在 App 更新後換新版 daemon）

#include <errno.h>
#include <grp.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <arpa/inet.h>

#include "dnsprobe.h"
#include "netcfg.h"
#include "sms.h"
#include "sms_store.h"
#include "state.h"

static const char *g_config_path;

typedef struct {
    char *p;
    size_t len, cap;
} sbuf;

// 不夠放就長大（簡訊清單可能很長）
static void sb_add(sbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_add(sbuf *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (b->len + (size_t)n >= b->cap) {
        size_t nc = (b->len + (size_t)n + 1) * 2;
        char *q = realloc(b->p, nc);
        if (!q) return;
        b->p = q;
        b->cap = nc;
        va_start(ap, fmt);
        vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
        va_end(ap);
    }
    b->len += (size_t)n;
}

static void sb_str(sbuf *b, const char *s) {
    sb_add(b, "\"");
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') sb_add(b, "\\%c", c);
        else if (c < 0x20) sb_add(b, "\\u%04x", c);
        else sb_add(b, "%c", c);
    }
    sb_add(b, "\"");
}

static void sb_ips(sbuf *b, const uint32_t *ips, int n) {
    sb_add(b, "[");
    for (int i = 0; i < n; i++) {
        char t[16];
        sb_add(b, "%s\"%s\"", i ? "," : "", ip_str(ips[i], t));
    }
    sb_add(b, "]");
}

static void status_json(sbuf *b) {
    char t[16];
    pthread_mutex_lock(&g_state_lock);
    sb_add(b, "{\"ok\":true,\"version\":\"%s\",\"state\":\"%s\",\"device\":", DT_VERSION, state_name(g_st.state));
    sb_str(b, g_st.device);
    sb_add(b, ",\"error\":");
    sb_str(b, g_st.error);
    sb_add(b, ",\"since\":%ld", (long)g_st.since);
    if (g_st.state == ST_CONNECTED) {
        sb_add(b, ",\"interface\":\"%s\",\"ip\":\"%s\"", g_st.ifname, ip_str(g_st.ip, t));
        sb_add(b, ",\"gateway\":\"%s\"", ip_str(g_st.gw, t));
        sb_add(b, ",\"netmask\":\"%s\",\"dns\":", ip_str(g_st.mask, t));
        sb_ips(b, g_st.dns, g_st.ndns);
        sb_add(b, ",\"dns_fallback\":%s", g_st.dns_fallback ? "true" : "false");
        if (g_st.ipv6[0]) {
            sb_add(b, ",\"ipv6\":");
            sb_str(b, g_st.ipv6);
            sb_add(b, ",\"dns6\":[");
            for (int i = 0; i < g_st.ndns6; i++) {
                if (i) sb_add(b, ",");
                sb_str(b, g_st.dns6[i]);
            }
            sb_add(b, "]");
        }
    }
    sb_add(b, ",\"kind\":\"%s\"", g_st.modem ? "modem" : "phone");
    if (g_st.modem) {
        if (g_st.signal_bars >= 0) sb_add(b, ",\"signal_bars\":%d,\"signal_dbm\":%d", g_st.signal_bars, g_st.signal_dbm);
        if (g_st.carrier[0]) {
            sb_add(b, ",\"carrier\":");
            sb_str(b, g_st.carrier);
        }
        if (g_st.tech[0]) {
            sb_add(b, ",\"tech\":");
            sb_str(b, g_st.tech);
        }
        if (g_st.pin_attempts >= 0) sb_add(b, ",\"pin_attempts\":%d", g_st.pin_attempts);
    }
    sb_add(b, ",\"sim_pin_saved\":%s", sim_pin_saved() ? "true" : "false");
    sb_add(b, ",\"sms_ready\":%s,\"sms_full\":%s,\"sms_unsupported\":%s,\"sms_unread\":%d,\"sms_rev\":%u",
           g_st.sms_ready ? "true" : "false", g_st.sms_full ? "true" : "false", g_st.sms_unsupported ? "true" : "false",
           sms_store_unread(), sms_store_rev());
    sb_add(b, ",\"rx_bytes\":%lu,\"tx_bytes\":%lu", (unsigned long)g_rx_bytes, (unsigned long)g_tx_bytes);
    sb_add(b, ",\"config\":{\"enabled\":%s,\"primary\":%s,\"wifi_off\":%s,\"dns_mode\":\"%s\",\"dns_servers\":",
           g_cfg.enabled ? "true" : "false", g_cfg.primary ? "true" : "false", g_cfg.wifi_off ? "true" : "false",
           g_cfg.dns_from_phone ? "phone" : "custom");
    sb_ips(b, g_cfg.dns, g_cfg.dns_from_phone ? 0 : g_cfg.ndns);
    sb_add(b, ",\"apn\":");
    sb_str(b, g_cfg.apn);
    sb_add(b, ",\"ipv6\":%s}}", g_cfg.ipv6 ? "true" : "false");
    pthread_mutex_unlock(&g_state_lock);
}

static const char *SMS_STATES[] = {"received", "queued", "sending", "sent", "failed"};

static void sms_list_json(sbuf *b) {
    sms_msg_t *m = NULL;
    int n = sms_store_snapshot(&m);
    if (n < 0) {
        sb_add(b, "{\"ok\":false,\"error\":\"no_memory\"}");
        return;
    }
    sb_add(b, "{\"ok\":true,\"rev\":%u,\"messages\":[", sms_store_rev());
    for (int i = 0; i < n; i++) {
        sb_add(b, "%s{\"id\":%u,\"dir\":\"%s\",\"state\":\"%s\",\"time\":%ld,\"read\":%s,\"parts\":%d,\"number\":",
               i ? "," : "", m[i].id, m[i].out ? "out" : "in", SMS_STATES[m[i].state], (long)m[i].time,
               m[i].read ? "true" : "false", m[i].parts);
        sb_str(b, m[i].number);
        if (m[i].error[0]) {
            sb_add(b, ",\"error\":");
            sb_str(b, m[i].error);
        }
        sb_add(b, ",\"text\":");
        sb_str(b, m[i].text);
        sb_add(b, "}");
    }
    sb_add(b, "]}");
    sms_store_free(m, n);
}

// 號碼和內容不寫進 log。
static void handle_sms(const char *key, char *val, sbuf *out) {
    if (strcmp(key, "list") == 0) {
        sms_list_json(out);
        return;
    }
    if (strcmp(key, "send") == 0 && val) {
        char *text = strchr(val, ' ');
        if (!text) {
            sb_add(out, "{\"ok\":false,\"error\":\"invalid_value\"}");
            return;
        }
        *text++ = '\0';
        size_t cap = strlen(text) + 1;
        char *plain = malloc(cap);
        bool ucs2;
        int parts = plain && sms_unescape(text, plain, cap) >= 0 ? sms_count_parts(plain, &ucs2) : -1;
        pthread_mutex_lock(&g_state_lock);
        bool modem = g_st.modem;
        pthread_mutex_unlock(&g_state_lock);
        const char *err = !sms_valid_number(val) ? "invalid_number"
                          : parts < 0            ? "invalid_text"
                          : parts > SMS_MAX_PARTS ? "too_long"
                          : !modem               ? "no_modem"
                                                 : NULL;
        uint32_t id = err ? 0 : sms_store_queue(val, plain, parts);
        if (!err && !id) err = "save_failed";
        free(plain);
        if (err) {
            sb_add(out, "{\"ok\":false,\"error\":\"%s\"}", err);
        } else {
            LOGI("control: SMS queued (%d part%s)", parts, parts == 1 ? "" : "s");
            sb_add(out, "{\"ok\":true,\"id\":%u,\"parts\":%d}", id, parts);
        }
        return;
    }
    if (strcmp(key, "delete") == 0 && val) {
        int n = 0, bad = 0;
        char *save = NULL;
        for (char *t = strtok_r(val, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
            if (sms_store_delete((uint32_t)strtoul(t, NULL, 10)) == 0) n++;
            else bad++;
        }
        if (n) LOGI("control: deleted %d SMS", n);
        sb_add(out, "{\"ok\":%s,\"deleted\":%d}", bad ? "false" : "true", n);
        return;
    }
    if (strcmp(key, "read") == 0 && val) {
        if (strcmp(val, "all") == 0) {
            sms_store_mark_read(0);
        } else {
            char *save = NULL;
            for (char *t = strtok_r(val, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
                uint32_t id = (uint32_t)strtoul(t, NULL, 10);
                if (id) sms_store_mark_read(id);
            }
        }
        sb_add(out, "{\"ok\":true}");
        return;
    }
    sb_add(out, "{\"ok\":false,\"error\":\"invalid_value\"}");
}

static void apply_change(void) {
    config_save(g_config_path);
    g_reset = true;  // 斷開目前連線，主迴圈用新設定重來
}

static void handle(char *line, sbuf *out) {
    line[strcspn(line, "\r\n")] = '\0';
    char *save = NULL;
    char *cmd = strtok_r(line, " ", &save);
    char *key = cmd ? strtok_r(NULL, " ", &save) : NULL;
    char *val = key ? strtok_r(NULL, "", &save) : NULL;

    if (!cmd || strcmp(cmd, "status") == 0) {
        status_json(out);
        return;
    }
    if (strcmp(cmd, "reconnect") == 0) {
        LOGI("control: reconnect");
        g_reset = true;
        sb_add(out, "{\"ok\":true}");
        return;
    }
    if (strcmp(cmd, "sim") == 0 && key) {
        // PIN 不寫進 log
        if (strcmp(key, "pin") == 0 && val && sim_pin_valid(val) && sim_pin_save(val) == 0) {
            LOGI("control: SIM PIN saved; reconnecting to use it");
            g_reset = true;
            status_json(out);
        } else if (strcmp(key, "forget-pin") == 0) {
            LOGI("control: SIM PIN forgotten");
            sim_pin_forget();
            status_json(out);
        } else {
            sb_add(out, "{\"ok\":false,\"error\":\"invalid_value\"}");
        }
        return;
    }
    if (strcmp(cmd, "sms") == 0 && key) {
        handle_sms(key, val, out);
        return;
    }
    if (strcmp(cmd, "quit") == 0) {
        LOGI("control: quit");
        g_stop = true;
        sb_add(out, "{\"ok\":true}");
        return;
    }
    // 測試用，見 tests/dns_logic_test.py
    if (strcmp(cmd, "debug") == 0 && key) {
        if (strcmp(key, "legacy-dns") == 0 && val) {
            struct in_addr a;
            bool ok = inet_pton(AF_INET, val, &a) == 1 && netcfg_debug_legacy_dns(a.s_addr) == 0;
            sb_add(out, "{\"ok\":%s}", ok ? "true" : "false");
        } else if (strcmp(key, "legacy-dns-clear") == 0) {
            netcfg_debug_legacy_dns_clear();
            sb_add(out, "{\"ok\":true}");
        } else if (strcmp(key, "drop-netcfg") == 0) {
            LOGW("control: debug drop-netcfg");
            netcfg_debug_drop();
            sb_add(out, "{\"ok\":true}");
        } else if (strcmp(key, "dns-probe") == 0 && val) {
            struct in_addr a;
            char ifn[16];
            pthread_mutex_lock(&g_state_lock);
            strlcpy(ifn, g_st.ifname, sizeof ifn);
            pthread_mutex_unlock(&g_state_lock);
            if (!ifn[0] || inet_pton(AF_INET, val, &a) != 1) {
                sb_add(out, "{\"ok\":false}");
            } else {
                bool answered = dnsprobe_server(ifn, a.s_addr, 1500);
                sb_add(out, "{\"ok\":true,\"answered\":%s}", answered ? "true" : "false");
            }
        } else if (strcmp(key, "dns-probe-fail") == 0 && val) {
            g_dns_probe_fail = strcmp(val, "0") != 0;
            LOGW("control: debug dns-probe-fail %d", (int)g_dns_probe_fail);
            sb_add(out, "{\"ok\":true}");
        } else if (strcmp(key, "abort") == 0) {
            LOGW("control: debug abort (simulated crash)");
            abort();
        } else {
            sb_add(out, "{\"ok\":false,\"error\":\"unknown_debug_command\"}");
        }
        return;
    }
    if (strcmp(cmd, "set") == 0 && key && val) {
        bool ok = true;
        pthread_mutex_lock(&g_state_lock);
        if (strcmp(key, "enabled") == 0) g_cfg.enabled = strcmp(val, "0") != 0;
        else if (strcmp(key, "primary") == 0) g_cfg.primary = strcmp(val, "0") != 0;
        else if (strcmp(key, "wifi_off") == 0) g_cfg.wifi_off = strcmp(val, "0") != 0;
        else if (strcmp(key, "dns") == 0) ok = config_parse_dns(val, &g_cfg) == 0;
        else if (strcmp(key, "apn") == 0) ok = config_valid_apn(val) && strlcpy(g_cfg.apn, val, sizeof g_cfg.apn);
        else if (strcmp(key, "ipv6") == 0) g_cfg.ipv6 = strcmp(val, "0") != 0;
        else ok = false;
        pthread_mutex_unlock(&g_state_lock);
        if (ok) {
            LOGI("control: set %s %s", key, val);
            // Wi-Fi 設定由連線中的定期檢查套用，不用斷線重連
            if (strcmp(key, "wifi_off") == 0) config_save(g_config_path);
            else apply_change();
            status_json(out);
        } else {
            sb_add(out, "{\"ok\":false,\"error\":\"invalid_value\"}");
        }
        return;
    }
    sb_add(out, "{\"ok\":false,\"error\":\"unknown_command\"}");
}

// 一行最長 16 KB：簡訊內容（10 段中文約 2 KB，跳脫後更長）
#define LINE_MAX_BYTES 16384

static void serve_client(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    static char line[LINE_MAX_BYTES];
    size_t n = 0;
    while (n < sizeof line - 1) {
        if (poll(&p, 1, 2000) <= 0) break;
        ssize_t r = read(fd, line + n, sizeof line - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
        if (memchr(line, '\n', n)) break;
    }
    line[n] = '\0';

    sbuf out = {malloc(4096), 0, 4096};
    if (!out.p) return;
    out.p[0] = '\0';
    handle(line, &out);
    sb_add(&out, "\n");
    for (size_t w = 0; w < out.len;) {
        ssize_t r = write(fd, out.p + w, out.len - w);
        if (r <= 0) break;
        w += (size_t)r;
    }
    free(out.p);
}

static void *control_thread(void *arg) {
    int srv = (int)(intptr_t)arg;
    struct pollfd p = {.fd = srv, .events = POLLIN};
    int ticks = 0;
    while (!g_stop) {
        // 排隊 5 分鐘還沒送出（沒有數據機）的簡訊改成失敗，免得之後突然送出去
        if (++ticks % 20 == 0) sms_store_fail_stale(300);
        if (poll(&p, 1, 500) <= 0) continue;
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) continue;
        serve_client(fd);
        close(fd);
    }
    close(srv);
    unlink(DT_SOCKET_PATH);
    return NULL;
}

int control_start(const char *config_path) {
    g_config_path = config_path;
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) return -1;
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    strlcpy(a.sun_path, DT_SOCKET_PATH, sizeof a.sun_path);
    unlink(DT_SOCKET_PATH);
    if (bind(srv, (struct sockaddr *)&a, sizeof a) < 0 || listen(srv, 8) < 0) {
        LOGE("control socket: %s", strerror(errno));
        close(srv);
        return -1;
    }
    // 只開放給 staff 群組（一般使用者帳號都在裡面）。
    struct group *g = getgrnam("staff");
    if (g) chown(DT_SOCKET_PATH, 0, g->gr_gid);
    chmod(DT_SOCKET_PATH, 0660);

    pthread_t t;
    pthread_create(&t, NULL, control_thread, (void *)(intptr_t)srv);
    pthread_detach(t);
    return 0;
}
