#include "netcfg.h"

#include <SystemConfiguration/SystemConfiguration.h>
#include <string.h>

#define SERVICE_ID CFSTR("DroidTether")

static SCDynamicStoreRef g_store;

// 上次註冊的參數，自我修復時用
static struct {
    char ifname[16];
    uint32_t ip, mask, router;
    uint32_t dns[4];
    int ndns;
    bool primary;
    bool valid;
} g_last;

static CFStringRef key_for(CFStringRef entity) {
    return SCDynamicStoreKeyCreateNetworkServiceEntity(NULL, kSCDynamicStoreDomainState, SERVICE_ID, entity);
}

static CFStringRef cfstr_ip(uint32_t ip) {
    char buf[16];
    return CFStringCreateWithCString(NULL, ip_str(ip, buf), kCFStringEncodingASCII);
}

static CFArrayRef cfarr_ips(const uint32_t *ips, int n) {
    CFMutableArrayRef a = CFArrayCreateMutable(NULL, n, &kCFTypeArrayCallBacks);
    for (int i = 0; i < n; i++) {
        CFStringRef s = cfstr_ip(ips[i]);
        CFArrayAppendValue(a, s);
        CFRelease(s);
    }
    return a;
}

static bool ensure_store(void) {
    if (g_store) return true;
    g_store = SCDynamicStoreCreate(NULL, CFSTR("droidtetherd"), NULL, NULL);
    if (!g_store) LOGE("SCDynamicStoreCreate: %s", SCErrorString(SCError()));
    return g_store != NULL;
}

void netcfg_remove_stale(void) {
    if (!ensure_store()) return;
    CFStringRef k4 = key_for(kSCEntNetIPv4), kd = key_for(kSCEntNetDNS);
    SCDynamicStoreRemoveValue(g_store, kd);
    SCDynamicStoreRemoveValue(g_store, k4);
    CFRelease(k4);
    CFRelease(kd);
}

// 暫存值只能新增不存在的鍵；先移除再新增，確保它跟著這個 session 消失。
static bool put_temp(CFStringRef key, CFDictionaryRef value) {
    SCDynamicStoreRemoveValue(g_store, key);
    if (SCDynamicStoreAddTemporaryValue(g_store, key, value)) return true;
    LOGW("AddTemporaryValue failed (%s), falling back to SetValue", SCErrorString(SCError()));
    return SCDynamicStoreSetValue(g_store, key, value);
}

int netcfg_publish(const char *ifname, uint32_t ip, uint32_t mask, uint32_t router, const uint32_t *dns, int ndns,
                   bool primary) {
    if (!ensure_store()) return -1;
    strlcpy(g_last.ifname, ifname, sizeof g_last.ifname);
    g_last.ip = ip;
    g_last.mask = mask;
    g_last.router = router;
    g_last.ndns = ndns < 4 ? ndns : 4;
    memcpy(g_last.dns, dns, sizeof(uint32_t) * (size_t)g_last.ndns);
    g_last.primary = primary;
    g_last.valid = true;

    // DNS 先寫：IPv4 一出現 configd 就會重算 primary，那時 DNS 要已經在。
    CFMutableDictionaryRef d =
        CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFArrayRef servers = cfarr_ips(dns, ndns);
    CFDictionarySetValue(d, kSCPropNetDNSServerAddresses, servers);
    CFRelease(servers);

    CFMutableDictionaryRef v4 =
        CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFArrayRef addrs = cfarr_ips(&ip, 1);
    CFArrayRef masks = cfarr_ips(&mask, 1);
    CFStringRef rtr = cfstr_ip(router);
    CFStringRef ifn = CFStringCreateWithCString(NULL, ifname, kCFStringEncodingASCII);
    CFDictionarySetValue(v4, kSCPropNetIPv4Addresses, addrs);
    CFDictionarySetValue(v4, kSCPropNetIPv4SubnetMasks, masks);
    CFDictionarySetValue(v4, kSCPropNetIPv4Router, rtr);
    CFDictionarySetValue(v4, kSCPropInterfaceName, ifn);
    if (primary) {
        int one = 1;
        CFNumberRef n = CFNumberCreate(NULL, kCFNumberIntType, &one);
        CFDictionarySetValue(v4, CFSTR("OverridePrimary"), n);
        CFRelease(n);
    }
    CFRelease(addrs);
    CFRelease(masks);
    CFRelease(rtr);
    CFRelease(ifn);

    CFStringRef kd = key_for(kSCEntNetDNS), k4 = key_for(kSCEntNetIPv4);
    bool ok = put_temp(kd, d) && put_temp(k4, v4);
    CFRelease(kd);
    CFRelease(k4);
    CFRelease(d);
    CFRelease(v4);
    if (!ok) {
        LOGE("publish network service: %s", SCErrorString(SCError()));
        return -1;
    }
    return 0;
}

void netcfg_withdraw(void) {
    g_last.valid = false;
    if (!g_store) return;
    netcfg_remove_stale();
    CFRelease(g_store);
    g_store = NULL;
}

bool netcfg_present(void) {
    if (!g_store) return false;
    bool ok = true;
    CFStringRef keys[2] = {key_for(kSCEntNetIPv4), key_for(kSCEntNetDNS)};
    for (int i = 0; i < 2; i++) {
        CFPropertyListRef v = SCDynamicStoreCopyValue(g_store, keys[i]);
        if (v) CFRelease(v);
        else ok = false;
        CFRelease(keys[i]);
    }
    return ok;
}

int netcfg_republish(void) {
    if (!g_last.valid) return -1;
    // 先複製一份：netcfg_publish 會改寫 g_last，直接傳 g_last 的欄位進去會變成自己複製到自己（strlcpy 重疊會被中止）。
    __typeof__(g_last) p = g_last;
    return netcfg_publish(p.ifname, p.ip, p.mask, p.router, p.dns, p.ndns, p.primary);
}

// ---------- 測試用 ----------

static SCDynamicStoreRef g_debug_store;
#define LEGACY_KEY CFSTR("State:/Network/Service/DroidTetherLegacyTest/DNS")

static SCDynamicStoreRef debug_store(void) {
    if (!g_debug_store) g_debug_store = SCDynamicStoreCreate(NULL, CFSTR("droidtetherd-debug"), NULL, NULL);
    return g_debug_store;
}

int netcfg_debug_legacy_dns(uint32_t dns) {
    SCDynamicStoreRef st = debug_store();
    if (!st) return -1;
    CFMutableDictionaryRef d =
        CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFArrayRef servers = cfarr_ips(&dns, 1);
    CFDictionarySetValue(d, kSCPropNetDNSServerAddresses, servers);
    CFRelease(servers);
    SCDynamicStoreRemoveValue(st, LEGACY_KEY);
    bool ok = SCDynamicStoreAddTemporaryValue(st, LEGACY_KEY, d);
    CFRelease(d);
    return ok ? 0 : -1;
}

void netcfg_debug_legacy_dns_clear(void) {
    SCDynamicStoreRef st = debug_store();
    if (st) SCDynamicStoreRemoveValue(st, LEGACY_KEY);
}

void netcfg_debug_drop(void) {
    SCDynamicStoreRef st = debug_store();
    if (!st) return;
    CFStringRef k4 = key_for(kSCEntNetIPv4), kd = key_for(kSCEntNetDNS);
    SCDynamicStoreRemoveValue(st, k4);
    SCDynamicStoreRemoveValue(st, kd);
    CFRelease(k4);
    CFRelease(kd);
}
