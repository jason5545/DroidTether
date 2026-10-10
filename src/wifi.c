#include "wifi.h"

#include <SystemConfiguration/SystemConfiguration.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_marker[300];
static bool g_owned;    // Wi-Fi 是我們關的，還沒開回來
static bool g_decided;  // 這次接上已經決定過要不要關
static bool g_last_want;
static char g_ifname[16];

static bool valid_ifname(const char *s) {
    if (!*s) return false;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s)) return false;
    return true;
}

static bool find_wifi(char ifname[16]) {
    CFArrayRef all = SCNetworkInterfaceCopyAll();
    if (!all) return false;
    bool found = false;
    for (CFIndex i = 0; i < CFArrayGetCount(all) && !found; i++) {
        SCNetworkInterfaceRef ni = CFArrayGetValueAtIndex(all, i);
        CFStringRef type = SCNetworkInterfaceGetInterfaceType(ni);
        CFStringRef bsd = SCNetworkInterfaceGetBSDName(ni);
        if (type && bsd && CFEqual(type, kSCNetworkInterfaceTypeIEEE80211))
            found = CFStringGetCString(bsd, ifname, 16, kCFStringEncodingASCII) && valid_ifname(ifname);
    }
    CFRelease(all);
    return found;
}

// 1 開、0 關、-1 讀不到。
// 不用 SCDynamicStore 的 State:/Network/Interface/en0/AirPort "Power Status"：
// 實測從 daemon 關掉 Wi-Fi 後，它有一次將近一分鐘還是 TRUE（networksetup 已經是 Off，Wi-Fi 也真的斷了）。
static int power(const char *ifname) {
    char cmd[80];
    snprintf(cmd, sizeof cmd, "/usr/sbin/networksetup -getairportpower %s 2>/dev/null", ifname);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    char line[128] = "";
    int r = -1;
    if (fgets(line, sizeof line, p)) {
        line[strcspn(line, "\r\n")] = '\0';
        const char *v = strrchr(line, ' ');
        if (v && strcmp(v, " On") == 0) r = 1;
        else if (v && strcmp(v, " Off") == 0) r = 0;
    }
    pclose(p);
    return r;
}

// networksetup 失敗時結束碼不一定是非 0，以實際狀態為準。
static bool set_power(const char *ifname, bool on) {
    const char *argv[] = {"/usr/sbin/networksetup", "-setairportpower", ifname, on ? "on" : "off", NULL};
    run_cmd(argv);
    for (int i = 0; i < 30; i++) {
        if (power(ifname) == (on ? 1 : 0)) return true;
        usleep(100000);
    }
    return false;
}

static bool marker_write(const char *ifname) {
    char dir[300];
    strlcpy(dir, g_marker, sizeof dir);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        mkdir(dir, 0755);
    }
    FILE *f = fopen(g_marker, "w");
    if (!f) return false;
    fprintf(f, "%s\n", ifname);
    return fclose(f) == 0;
}

void wifi_init(const char *config_path) {
    snprintf(g_marker, sizeof g_marker, "%s.wifi-off", config_path);
    FILE *f = fopen(g_marker, "r");
    if (!f) return;
    char line[32] = "";
    if (fgets(line, sizeof line, f)) line[strcspn(line, "\r\n")] = '\0';
    fclose(f);
    if (valid_ifname(line) && strlen(line) < sizeof g_ifname) {
        strlcpy(g_ifname, line, sizeof g_ifname);
        g_owned = true;
        LOGI("Wi-Fi (%s) was turned off by an earlier run; it comes back on when the phone is gone", g_ifname);
    } else {
        unlink(g_marker);
    }
}

static void restore(const char *why) {
    if (!g_owned) return;
    if (set_power(g_ifname, true)) LOGI("Wi-Fi (%s) turned back on: %s", g_ifname, why);
    else LOGE("could not turn Wi-Fi (%s) back on", g_ifname);
    // 失敗也不重試：每兩秒重來一次只會洗版，使用者自己開就好。
    g_owned = false;
    unlink(g_marker);
}

void wifi_tether_up(bool want) {
    if (want != g_last_want) {
        g_last_want = want;
        g_decided = false;  // 設定剛打開，重新決定一次
    }
    if (!want) {
        restore("setting turned off");
        return;
    }
    if (g_decided) return;
    g_decided = true;
    char ifn[16];
    if (!find_wifi(ifn)) return;
    if (power(ifn) != 1) return;  // 本來就關著，不是我們的事
    if (g_owned && strcmp(ifn, g_ifname) == 0) {
        // 標記檔說是我們關的，但現在是開的：使用者自己打開了，不再關
        return;
    }
    // 先寫標記再關：中間當掉的話，下次啟動還會開回來
    if (!marker_write(ifn)) {
        LOGW("cannot write %s; leaving Wi-Fi on", g_marker);
        return;
    }
    // 沒確認到關掉也當成我們的：拔線時多開一次已經開著的 Wi-Fi 沒事，漏開才會斷網
    bool off = set_power(ifn, false);
    if (!off && power(ifn) == 1) {
        LOGW("could not turn Wi-Fi (%s) off", ifn);
        unlink(g_marker);
        return;
    }
    strlcpy(g_ifname, ifn, sizeof g_ifname);
    g_owned = true;
    if (off) LOGI("Wi-Fi (%s) turned off while tethered", ifn);
    else LOGW("Wi-Fi (%s) off command sent but not confirmed; will still turn it back on later", ifn);
}

void wifi_tether_gone(const char *why) {
    g_decided = false;
    restore(why);
}
