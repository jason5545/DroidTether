#include "netcfg.h"

#include <SystemConfiguration/SystemConfiguration.h>

#define SERVICE_ID CFSTR("DroidTether")

static SCDynamicStoreRef g_store;

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
    if (!g_store) return;
    netcfg_remove_stale();
    CFRelease(g_store);
    g_store = NULL;
}
