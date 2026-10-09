#include "state.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

pthread_mutex_t g_state_lock = PTHREAD_MUTEX_INITIALIZER;
dt_config g_cfg = {.enabled = true, .primary = true, .dns_from_phone = true};
dt_status g_st = {.state = ST_STARTING};
atomic_ulong g_rx_bytes, g_tx_bytes;

const char *state_name(dt_state st) {
    switch (st) {
        case ST_STARTING: return "starting";
        case ST_DISABLED: return "disabled";
        case ST_WAITING: return "waiting";
        case ST_PHONE_NO_TETHER: return "phone_no_tether";
        case ST_BUSY: return "busy";
        case ST_CONNECTING: return "connecting";
        case ST_CONNECTED: return "connected";
    }
    return "unknown";
}

void status_set(dt_state st, const char *device, const char *error) {
    pthread_mutex_lock(&g_state_lock);
    if (g_st.state != st) {
        g_st.since = time(NULL);
        if (st != ST_CONNECTED) {
            g_st.ifname[0] = '\0';
            g_st.ip = g_st.gw = g_st.mask = 0;
            g_st.ndns = 0;
        }
    }
    g_st.state = st;
    if (device) strlcpy(g_st.device, device, sizeof g_st.device);
    if (error) strlcpy(g_st.error, error, sizeof g_st.error);
    pthread_mutex_unlock(&g_state_lock);
}

int config_parse_dns(const char *arg, dt_config *c) {
    if (strcmp(arg, "phone") == 0 || strcmp(arg, "dhcp") == 0) {
        c->dns_from_phone = true;
        return 0;
    }
    dt_config tmpc = *c;
    tmpc.dns_from_phone = false;
    tmpc.ndns = 0;
    char tmp[256];
    strlcpy(tmp, arg, sizeof tmp);
    for (char *save = NULL, *tok = strtok_r(tmp, ", ", &save); tok; tok = strtok_r(NULL, ", ", &save)) {
        struct in_addr a;
        if (inet_pton(AF_INET, tok, &a) != 1 || tmpc.ndns >= 4) return -1;
        tmpc.dns[tmpc.ndns++] = a.s_addr;
    }
    if (!tmpc.ndns) return -1;
    *c = tmpc;
    return 0;
}

// 設定檔是很單純的 key=value，一行一個。
void config_load(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
    pthread_mutex_lock(&g_state_lock);
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *k = line, *v = eq + 1;
        if (strcmp(k, "enabled") == 0) g_cfg.enabled = strcmp(v, "0") != 0;
        else if (strcmp(k, "primary") == 0) g_cfg.primary = strcmp(v, "0") != 0;
        else if (strcmp(k, "dns") == 0 && config_parse_dns(v, &g_cfg) != 0) LOGW("config: bad dns '%s'", v);
    }
    pthread_mutex_unlock(&g_state_lock);
    fclose(f);
}

int config_save(const char *path) {
    char dir[256];
    strlcpy(dir, path, sizeof dir);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        mkdir(dir, 0755);
    }
    char tmp[300];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        LOGE("config save %s: %s", tmp, strerror(errno));
        return -1;
    }
    pthread_mutex_lock(&g_state_lock);
    fprintf(f, "enabled=%d\nprimary=%d\ndns=", g_cfg.enabled, g_cfg.primary);
    if (g_cfg.dns_from_phone) {
        fputs("phone", f);
    } else {
        for (int i = 0; i < g_cfg.ndns; i++) {
            char b[16];
            fprintf(f, "%s%s", i ? "," : "", ip_str(g_cfg.dns[i], b));
        }
    }
    fputc('\n', f);
    pthread_mutex_unlock(&g_state_lock);
    fclose(f);
    return rename(tmp, path);
}
