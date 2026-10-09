// 給選單列 App 用的控制介面：Unix socket，一行一個指令，回一行 JSON。
//   status                     目前狀態
//   set enabled 0|1            暫停 / 恢復
//   set primary 0|1            要不要當主要連線
//   set dns phone|IP[,IP...]   DNS 來源
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

#include "netcfg.h"
#include "state.h"

static const char *g_config_path;

typedef struct {
    char *p;
    size_t len, cap;
} sbuf;

static void sb_add(sbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_add(sbuf *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    if (n > 0) b->len = b->len + (size_t)n < b->cap ? b->len + (size_t)n : b->cap - 1;
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
    }
    sb_add(b, ",\"rx_bytes\":%lu,\"tx_bytes\":%lu", (unsigned long)g_rx_bytes, (unsigned long)g_tx_bytes);
    sb_add(b, ",\"config\":{\"enabled\":%s,\"primary\":%s,\"dns_mode\":\"%s\",\"dns_servers\":",
           g_cfg.enabled ? "true" : "false", g_cfg.primary ? "true" : "false", g_cfg.dns_from_phone ? "phone" : "custom");
    sb_ips(b, g_cfg.dns, g_cfg.dns_from_phone ? 0 : g_cfg.ndns);
    sb_add(b, "}}");
    pthread_mutex_unlock(&g_state_lock);
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
        else if (strcmp(key, "dns") == 0) ok = config_parse_dns(val, &g_cfg) == 0;
        else ok = false;
        pthread_mutex_unlock(&g_state_lock);
        if (ok) {
            LOGI("control: set %s %s", key, val);
            apply_change();
            status_json(out);
        } else {
            sb_add(out, "{\"ok\":false,\"error\":\"invalid_value\"}");
        }
        return;
    }
    sb_add(out, "{\"ok\":false,\"error\":\"unknown_command\"}");
}

static void serve_client(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    char line[512];
    size_t n = 0;
    while (n < sizeof line - 1) {
        if (poll(&p, 1, 2000) <= 0) break;
        ssize_t r = read(fd, line + n, sizeof line - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
        if (memchr(line, '\n', n)) break;
    }
    line[n] = '\0';

    char buf[2048];
    sbuf out = {buf, 0, sizeof buf};
    buf[0] = '\0';
    handle(line, &out);
    sb_add(&out, "\n");
    (void)!write(fd, buf, out.len);
}

static void *control_thread(void *arg) {
    int srv = (int)(intptr_t)arg;
    struct pollfd p = {.fd = srv, .events = POLLIN};
    while (!g_stop) {
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
