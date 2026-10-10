#include "state.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

pthread_mutex_t g_state_lock = PTHREAD_MUTEX_INITIALIZER;
dt_config g_cfg = {.enabled = true, .primary = true, .dns_from_phone = true, .apn = "internet", .ipv6 = true};
dt_status g_st = {.state = ST_STARTING, .signal_bars = -1, .pin_attempts = -1};
char g_pin_path[300];
atomic_ulong g_rx_bytes, g_tx_bytes;
atomic_bool g_dns_probe_fail;

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
            g_st.dns_fallback = false;
            g_st.signal_bars = -1;
            g_st.signal_dbm = 0;
            g_st.carrier[0] = g_st.tech[0] = g_st.ipv6[0] = '\0';
            g_st.ndns6 = 0;
        }
        if (st != ST_CONNECTING) g_st.pin_attempts = -1;
    }
    g_st.state = st;
    if (device) strlcpy(g_st.device, device, sizeof g_st.device);
    if (error) strlcpy(g_st.error, error, sizeof g_st.error);
    pthread_mutex_unlock(&g_state_lock);
}

void status_set_link(int bars, int dbm, const char *carrier, const char *tech) {
    pthread_mutex_lock(&g_state_lock);
    g_st.signal_bars = bars;
    g_st.signal_dbm = dbm;
    strlcpy(g_st.carrier, carrier, sizeof g_st.carrier);
    strlcpy(g_st.tech, tech, sizeof g_st.tech);
    pthread_mutex_unlock(&g_state_lock);
}

bool sim_pin_valid(const char *pin) {
    size_t n = strlen(pin);
    if (n < 4 || n > 8) return false;
    for (size_t i = 0; i < n; i++)
        if (pin[i] < '0' || pin[i] > '9') return false;
    return true;
}

bool sim_pin_load(char *out, size_t cap) {
    out[0] = '\0';
    if (!g_pin_path[0]) return false;
    int fd = open(g_pin_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[16] = {0};
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return false;
    buf[strcspn(buf, "\r\n")] = '\0';
    if (!sim_pin_valid(buf)) return false;
    strlcpy(out, buf, cap);
    return true;
}

int sim_pin_save(const char *pin) {
    if (!g_pin_path[0] || !sim_pin_valid(pin)) return -1;
    unlink(g_pin_path);
    int fd = open(g_pin_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    bool ok = write(fd, pin, strlen(pin)) == (ssize_t)strlen(pin);
    close(fd);
    return ok ? 0 : -1;
}

void sim_pin_forget(void) {
    if (g_pin_path[0]) unlink(g_pin_path);
}

bool sim_pin_saved(void) {
    struct stat st;
    return g_pin_path[0] && stat(g_pin_path, &st) == 0;
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

bool config_valid_apn(const char *apn) {
    size_t n = strlen(apn);
    if (n == 0 || n >= sizeof g_cfg.apn) return false;
    for (size_t i = 0; i < n; i++)
        if (apn[i] <= 0x20 || apn[i] > 0x7e) return false;
    return true;
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
        else if (strcmp(k, "wifi_off") == 0) g_cfg.wifi_off = strcmp(v, "0") != 0;
        else if (strcmp(k, "dns") == 0 && config_parse_dns(v, &g_cfg) != 0) LOGW("config: bad dns '%s'", v);
        else if (strcmp(k, "ipv6") == 0) g_cfg.ipv6 = strcmp(v, "0") != 0;
        else if (strcmp(k, "apn") == 0) {
            if (config_valid_apn(v)) strlcpy(g_cfg.apn, v, sizeof g_cfg.apn);
            else LOGW("config: bad apn '%s'", v);
        }
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
    fprintf(f, "enabled=%d\nprimary=%d\nwifi_off=%d\ndns=", g_cfg.enabled, g_cfg.primary, g_cfg.wifi_off);
    if (g_cfg.dns_from_phone) {
        fputs("phone", f);
    } else {
        for (int i = 0; i < g_cfg.ndns; i++) {
            char b[16];
            fprintf(f, "%s%s", i ? "," : "", ip_str(g_cfg.dns[i], b));
        }
    }
    fprintf(f, "\napn=%s\nipv6=%d\n", g_cfg.apn, g_cfg.ipv6);
    pthread_mutex_unlock(&g_state_lock);
    fclose(f);
    return rename(tmp, path);
}
