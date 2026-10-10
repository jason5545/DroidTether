// 不需要裝置的 MBIM 測試：訊息組裝與解析、分段重組、NTB16、feth 端的 ARP 與乙太網路標頭、ICMP 探測。
// REAL_* 是 TCL IK512（高通 SDX62）實際收發的位元組，2026/10/10 從 Linux 主機上的 mbimcli --verbose-full 取得。
// 撥號、附著這些不能真的送出去的指令，用 tests/mbim_oracle.py 跟 libmbim 逐位元組對照：
//   build/test_mbim           跑測試
//   build/test_mbim --dump    印出要給 mbim_oracle.py 對照的訊息

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "../src/dhcp.h"
#include "../src/mbim.h"

int g_verbose;
atomic_bool g_stop;
atomic_bool g_reset;
void log_msg(const char *level, const char *fmt, ...) {
    (void)level;
    (void)fmt;
}
void sleep_ms_interruptible(int ms) {
    (void)ms;
}

static int failures, checks;
#define CHECK(cond)                                                         \
    do {                                                                    \
        checks++;                                                           \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                     \
        }                                                                   \
    } while (0)

// ---------- IK512 實際的位元組 ----------

static const uint8_t REAL_OPEN[16] = {
    0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
};
static const uint8_t REAL_OPEN_DONE[16] = {
    0x01, 0x00, 0x00, 0x80, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t REAL_IPCFG_QUERY[108] = {
    0x03, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xa2, 0x89, 0xcc, 0x33, 0xbc, 0xbb, 0x8b, 0x4f, 0xb6, 0xb0, 0x13, 0x3e,
    0xc2, 0xaa, 0xe6, 0xdf, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t REAL_IPCFG_DONE[128] = {
    0x03, 0x00, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xa2, 0x89, 0xcc, 0x33, 0xbc, 0xbb, 0x8b, 0x4f, 0xb6, 0xb0, 0x13, 0x3e,
    0xc2, 0xaa, 0xe6, 0xdf, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xdc, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00,
    0x64, 0x62, 0xf0, 0x64, 0x64, 0x62, 0xf0, 0x65, 0x3d, 0x1f, 0x01, 0x01, 0x3d, 0x1f, 0xe9, 0x01,
};
static const uint8_t REAL_CLOSE[12] = {
    0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
};
static const uint8_t REAL_CLOSE_DONE[16] = {
    0x02, 0x00, 0x00, 0x80, 0x10, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t REAL_RADIO_QUERY[48] = {
    0x03, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xa2, 0x89, 0xcc, 0x33, 0xbc, 0xbb, 0x8b, 0x4f, 0xb6, 0xb0, 0x13, 0x3e,
    0xc2, 0xaa, 0xe6, 0xdf, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t REAL_RADIO_DONE[56] = {
    0x03, 0x00, 0x00, 0x80, 0x38, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xa2, 0x89, 0xcc, 0x33, 0xbc, 0xbb, 0x8b, 0x4f, 0xb6, 0xb0, 0x13, 0x3e,
    0xc2, 0xaa, 0xe6, 0xdf, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
};

// ---------- 自己組的回應（版面由 mbim_oracle.py 交給 libmbim 解讀確認） ----------

static int done_msg(uint8_t *b, uint32_t type, uint32_t tid, uint32_t cid, uint32_t status, const uint8_t *info,
                    int n) {
    bool ind = type == MBIM_INDICATE_STATUS;
    int hdr = ind ? 44 : 48;
    put_le32(b, type);
    put_le32(b + 4, (uint32_t)(hdr + n));
    put_le32(b + 8, tid);
    put_le32(b + 12, 1);
    put_le32(b + 16, 0);
    memcpy(b + 20, MBIM_UUID_BASIC_CONNECT, 16);
    put_le32(b + 36, cid);
    if (ind) {
        put_le32(b + 40, (uint32_t)n);
    } else {
        put_le32(b + 40, status);
        put_le32(b + 44, (uint32_t)n);
    }
    memcpy(b + hdr, info, (size_t)n);
    return hdr + n;
}

static int connect_info(uint8_t *p, uint32_t activation, uint32_t nw_error) {
    memset(p, 0, 36);
    put_le32(p + 4, activation);
    put_le32(p + 12, MBIM_IP_TYPE_IPV4);
    memcpy(p + 16, MBIM_CONTEXT_INTERNET, 16);
    put_le32(p + 32, nw_error);
    return 36;
}

static int fx_connect_done(uint8_t *b) {
    uint8_t i[36];
    return done_msg(b, MBIM_COMMAND_DONE, 10, MBIM_CID_CONNECT, 0, i, connect_info(i, MBIM_ACT_ACTIVATED, 0));
}

static int fx_connect_indication(uint8_t *b) {
    uint8_t i[36];
    return done_msg(b, MBIM_INDICATE_STATUS, 0, MBIM_CID_CONNECT, 0, i, connect_info(i, MBIM_ACT_DEACTIVATED, 36));
}

// MBIM_REGISTRATION_STATE_INFO：NwError, RegisterState, RegisterMode, AvailableDataClasses, CurrentCellularClass,
// ProviderId, ProviderName, RoamingText（字串 offset/size，空的都填 0）, RegistrationFlag
static int fx_register_done(uint8_t *b) {
    uint8_t i[48] = {0};
    put_le32(i + 4, MBIM_REG_HOME);
    put_le32(i + 8, 1);       // automatic
    put_le32(i + 12, 0x20);   // LTE
    put_le32(i + 16, 1);      // GSM
    return done_msg(b, MBIM_COMMAND_DONE, 6, MBIM_CID_REGISTER_STATE, 0, i, sizeof i);
}

// MBIM_PACKET_SERVICE_INFO：NwError, PacketServiceState, HighestAvailableDataClass, UplinkSpeed(8), DownlinkSpeed(8)
static int fx_packet_done(uint8_t *b) {
    uint8_t i[28] = {0};
    put_le32(i + 4, MBIM_PS_ATTACHED);
    put_le32(i + 8, 0x20);
    put_le32(i + 12, 50000000);
    put_le32(i + 20, 100000000);
    return done_msg(b, MBIM_COMMAND_DONE, 7, MBIM_CID_PACKET_SERVICE, 0, i, sizeof i);
}

// MBIM_SUBSCRIBER_READY_INFO：ReadyState, SubscriberId, SimIccId（空字串）, ReadyInfo, ElementCount
static int fx_subscriber_done(uint8_t *b) {
    uint8_t i[28] = {0};
    put_le32(i, MBIM_SIM_INITIALIZED);
    return done_msg(b, MBIM_COMMAND_DONE, 3, MBIM_CID_SUBSCRIBER_READY, 0, i, sizeof i);
}

// ---------- 給 mbim_oracle.py 的請求 ----------

static int req_connect(uint8_t *b, uint32_t tid, bool activate, const char *apn) {
    uint8_t info[256];
    int il = mbim_info_connect_set(info, sizeof info, 0, activate, apn, MBIM_IP_TYPE_IPV4);
    return mbim_build_command(b, 4096, tid, MBIM_UUID_BASIC_CONNECT, MBIM_CID_CONNECT, true, info, il);
}

static void hex(const char *kind, const char *name, const uint8_t *b, int n) {
    printf("%s %s ", kind, name);
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static int dump(void) {
    uint8_t b[4096], info[256];
    int il;
    hex("req", "open", b, mbim_build_open(b, sizeof b, 1, 4096));
    hex("req", "close", b, mbim_build_close(b, sizeof b, 2));
    hex("req", "subscriber_ready_query", b,
        mbim_build_command(b, sizeof b, 3, MBIM_UUID_BASIC_CONNECT, MBIM_CID_SUBSCRIBER_READY, false, NULL, 0));
    hex("req", "radio_query", b,
        mbim_build_command(b, sizeof b, 4, MBIM_UUID_BASIC_CONNECT, MBIM_CID_RADIO_STATE, false, NULL, 0));
    il = mbim_info_radio_set(info, true);
    hex("req", "radio_set_on", b,
        mbim_build_command(b, sizeof b, 5, MBIM_UUID_BASIC_CONNECT, MBIM_CID_RADIO_STATE, true, info, il));
    hex("req", "register_query", b,
        mbim_build_command(b, sizeof b, 6, MBIM_UUID_BASIC_CONNECT, MBIM_CID_REGISTER_STATE, false, NULL, 0));
    hex("req", "packet_service_query", b,
        mbim_build_command(b, sizeof b, 7, MBIM_UUID_BASIC_CONNECT, MBIM_CID_PACKET_SERVICE, false, NULL, 0));
    il = mbim_info_packet_service_set(info, true);
    hex("req", "packet_service_attach", b,
        mbim_build_command(b, sizeof b, 8, MBIM_UUID_BASIC_CONNECT, MBIM_CID_PACKET_SERVICE, true, info, il));
    il = mbim_info_connect_query(info, sizeof info, 0);
    hex("req", "connect_query", b,
        mbim_build_command(b, sizeof b, 9, MBIM_UUID_BASIC_CONNECT, MBIM_CID_CONNECT, false, info, il));
    hex("req", "connect_activate_internet", b, req_connect(b, 10, true, "internet"));
    hex("req", "connect_deactivate", b, req_connect(b, 11, false, ""));
    hex("req", "connect_activate_a", b, req_connect(b, 12, true, "a"));
    hex("req", "connect_activate_fet", b, req_connect(b, 13, true, "fet"));

    hex("resp", "real_ipcfg_done", REAL_IPCFG_DONE, sizeof REAL_IPCFG_DONE);
    hex("resp", "real_radio_done", REAL_RADIO_DONE, sizeof REAL_RADIO_DONE);
    hex("resp", "connect_done", b, fx_connect_done(b));
    hex("resp", "connect_indication_deactivated", b, fx_connect_indication(b));
    hex("resp", "register_done_home", b, fx_register_done(b));
    hex("resp", "packet_service_done_attached", b, fx_packet_done(b));
    hex("resp", "subscriber_ready_done", b, fx_subscriber_done(b));
    return 0;
}

// ---------- 測試 ----------

static uint32_t ip4(int a, int b, int c, int d) {
    return htonl((uint32_t)((a << 24) | (b << 16) | (c << 8) | d));
}

static void test_requests_match_device(void) {
    uint8_t b[4096], info[128];
    CHECK(mbim_build_open(b, sizeof b, 2, 4096) == 16 && memcmp(b, REAL_OPEN, 16) == 0);
    CHECK(mbim_build_close(b, sizeof b, 4) == 12 && memcmp(b, REAL_CLOSE, 12) == 0);
    int il = mbim_info_ip_config_query(info, sizeof info, 0);
    int n = mbim_build_command(b, sizeof b, 3, MBIM_UUID_BASIC_CONNECT, MBIM_CID_IP_CONFIGURATION, false, info, il);
    CHECK(n == (int)sizeof REAL_IPCFG_QUERY && memcmp(b, REAL_IPCFG_QUERY, (size_t)n) == 0);
    n = mbim_build_command(b, sizeof b, 3, MBIM_UUID_BASIC_CONNECT, MBIM_CID_RADIO_STATE, false, NULL, 0);
    CHECK(n == (int)sizeof REAL_RADIO_QUERY && memcmp(b, REAL_RADIO_QUERY, (size_t)n) == 0);
    CHECK(mbim_build_open(b, 15, 1, 4096) < 0);
}

static void test_device_responses(void) {
    mbim_msg_t m;
    CHECK(mbim_parse(REAL_OPEN_DONE, sizeof REAL_OPEN_DONE, &m) == 0);
    CHECK(m.type == MBIM_OPEN_DONE && m.tid == 2 && m.status == 0);
    CHECK(mbim_parse(REAL_CLOSE_DONE, sizeof REAL_CLOSE_DONE, &m) == 0);
    CHECK(m.type == MBIM_CLOSE_DONE && m.tid == 4 && m.status == 0);

    CHECK(mbim_parse(REAL_IPCFG_DONE, sizeof REAL_IPCFG_DONE, &m) == 0);
    CHECK(m.type == MBIM_COMMAND_DONE && m.cid == MBIM_CID_IP_CONFIGURATION && m.status == 0 && m.info_len == 80);
    CHECK(memcmp(m.uuid, MBIM_UUID_BASIC_CONNECT, 16) == 0);
    mbim_ipv4_t ip;
    CHECK(mbim_parse_ip_config(m.info, m.info_len, &ip) == 0);
    CHECK(ip.ip == ip4(100, 98, 240, 100) && ip.prefix == 29 && ip.gw == ip4(100, 98, 240, 101));
    CHECK(ip.ndns == 2 && ip.dns[0] == ip4(61, 31, 1, 1) && ip.dns[1] == ip4(61, 31, 233, 1));
    CHECK(ip.mtu == 1500);
    CHECK(mbim_netmask(ip.ip, ip.gw, ip.prefix) == ip4(255, 255, 255, 248));

    CHECK(mbim_parse(REAL_RADIO_DONE, sizeof REAL_RADIO_DONE, &m) == 0);
    uint32_t hw = 0, sw = 0;
    CHECK(m.cid == MBIM_CID_RADIO_STATE && mbim_parse_radio_state(m.info, m.info_len, &hw, &sw) == 0 && hw == 1 && sw == 1);
}

static void test_crafted_responses(void) {
    uint8_t b[256];
    mbim_msg_t m;
    mbim_connect_info_t c;
    int n = fx_connect_done(b);
    CHECK(mbim_parse(b, n, &m) == 0 && m.type == MBIM_COMMAND_DONE && m.cid == MBIM_CID_CONNECT);
    CHECK(mbim_parse_connect(m.info, m.info_len, &c) == 0 && c.activation == MBIM_ACT_ACTIVATED && c.session == 0);
    CHECK(c.ip_type == MBIM_IP_TYPE_IPV4 && memcmp(c.context, MBIM_CONTEXT_INTERNET, 16) == 0);
    n = fx_connect_indication(b);
    CHECK(mbim_parse(b, n, &m) == 0 && m.type == MBIM_INDICATE_STATUS && m.cid == MBIM_CID_CONNECT);
    CHECK(mbim_parse_connect(m.info, m.info_len, &c) == 0 && c.activation == MBIM_ACT_DEACTIVATED && c.nw_error == 36);
    uint32_t e = 9, st = 0;
    n = fx_register_done(b);
    CHECK(mbim_parse(b, n, &m) == 0 && mbim_parse_register_state(m.info, m.info_len, &e, &st) == 0);
    CHECK(e == 0 && st == MBIM_REG_HOME);
    n = fx_packet_done(b);
    CHECK(mbim_parse(b, n, &m) == 0 && mbim_parse_packet_service(m.info, m.info_len, &e, &st) == 0);
    CHECK(st == MBIM_PS_ATTACHED);
    n = fx_subscriber_done(b);
    CHECK(mbim_parse(b, n, &m) == 0 && mbim_parse_subscriber_ready(m.info, m.info_len, &st) == 0);
    CHECK(st == MBIM_SIM_INITIALIZED);
}

static void test_bad_messages(void) {
    mbim_msg_t m;
    uint8_t b[128];
    memcpy(b, REAL_IPCFG_DONE, 128);
    CHECK(mbim_parse(b, 100, &m) < 0);  // 宣告的長度比收到的長
    put_le32(b + 44, 200);              // InformationBufferLength 超出訊息
    CHECK(mbim_parse(b, 128, &m) < 0);
    CHECK(mbim_parse(b, 8, &m) < 0);
    mbim_ipv4_t ip;
    memcpy(b, REAL_IPCFG_DONE, 128);
    put_le32(b + 48 + 16, 200);  // IPv4AddressOffset 指到外面
    CHECK(mbim_parse_ip_config(b + 48, 80, &ip) < 0);
    memcpy(b, REAL_IPCFG_DONE, 128);
    put_le32(b + 48 + 36, 1000000);  // DNS 數量灌爆
    CHECK(mbim_parse_ip_config(b + 48, 80, &ip) < 0);
    CHECK(mbim_parse_ip_config(REAL_IPCFG_DONE + 48, 59, &ip) < 0);
}

static void test_reassembly(void) {
    // 把 IK512 的 IP configuration 回應切成兩段：第一段帶 60 bytes 資料，第二段帶剩下的 48 bytes
    const uint8_t *src = REAL_IPCFG_DONE;
    uint8_t f0[80], f1[68], out[512];
    memcpy(f0, src, 80);
    put_le32(f0 + 4, 80);
    put_le32(f0 + 12, 2);
    memcpy(f1, src, 20);
    put_le32(f1 + 4, 68);
    put_le32(f1 + 12, 2);
    put_le32(f1 + 16, 1);
    memcpy(f1 + 20, src + 80, 48);
    mbim_reasm_t r = {.buf = out, .cap = sizeof out};
    CHECK(mbim_reasm_feed(&r, f0, sizeof f0) == 0);
    CHECK(mbim_reasm_feed(&r, f1, sizeof f1) == 1);
    CHECK(r.len == 128 && memcmp(out, src, 128) == 0);
    // 順序錯了就丟掉
    CHECK(mbim_reasm_feed(&r, f1, sizeof f1) < 0);
    // 不分段的訊息直接交出
    CHECK(mbim_reasm_feed(&r, REAL_OPEN_DONE, 16) == 1 && r.len == 16);
    // 太大的訊息不收
    mbim_reasm_t small = {.buf = out, .cap = 64};
    CHECK(mbim_reasm_feed(&small, src, 128) < 0);
}

static void test_connect_set_layout(void) {
    uint8_t p[256];
    int n = mbim_info_connect_set(p, sizeof p, 0, true, "internet", MBIM_IP_TYPE_IPV4);
    CHECK(n == 76);
    CHECK(get_le32(p + 4) == 1 && get_le32(p + 8) == 60 && get_le32(p + 12) == 16);
    CHECK(get_le32(p + 16) == 0 && get_le32(p + 20) == 0 && get_le32(p + 24) == 0 && get_le32(p + 28) == 0);
    CHECK(get_le32(p + 40) == MBIM_IP_TYPE_IPV4 && memcmp(p + 44, MBIM_CONTEXT_INTERNET, 16) == 0);
    CHECK(memcmp(p + 60, "i\0n\0t\0e\0r\0n\0e\0t\0", 16) == 0);
    CHECK(mbim_info_connect_set(p, sizeof p, 0, true, "a", 1) == 64);  // 2 bytes 補到 4
    CHECK(mbim_info_connect_set(p, sizeof p, 0, false, "", 1) == 60 && get_le32(p + 8) == 0);
    CHECK(mbim_info_connect_set(p, sizeof p, 0, true, "bad apn\x01", 1) < 0);
    CHECK(mbim_info_connect_set(p, 70, 0, true, "internet", 1) < 0);
}

static int seen;
static uint8_t seen_buf[2][2048];
static int seen_len[2];
static void ntb_cb(void *ctx, const uint8_t *d, int len) {
    (void)ctx;
    if (seen < 2) {
        memcpy(seen_buf[seen], d, (size_t)len);
        seen_len[seen] = len;
    }
    seen++;
}

static void test_ntb16(void) {
    // GET_NTB_PARAMETERS，數值是 IK512 的（Linux cdc_ncm 的 sysfs 讀到的）：只有 NTB16、in 31744、out 16384、
    // divisor 4、remainder 0、align 4、一次最多 16 個
    uint8_t pp[28] = {28, 0, 1, 0, 0, 0x7c, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 0x40, 0, 0, 4, 0, 0, 0, 4, 0, 16, 0};
    ntb_params_t np;
    CHECK(ntb_parse_params(pp, sizeof pp, &np) == 0);
    CHECK(np.formats == 1 && np.in_max == 31744 && np.out_max == 16384);
    CHECK(np.out_divisor == 4 && np.out_remainder == 0 && np.out_align == 4 && np.out_max_datagrams == 16);
    pp[2] = 2;  // 只支援 NTB32 的裝置不收
    CHECK(ntb_parse_params(pp, sizeof pp, &np) < 0);
    pp[2] = 1;
    ntb_parse_params(pp, sizeof pp, &np);

    // MTU 1500 的封包：28 + 1500，在 out 上限內
    static uint8_t big[1500], bigbuf[4096];
    big[0] = 0x45;
    CHECK(ntb16_build(bigbuf, sizeof bigbuf, 1, &np, big, 1500) == 1528);

    uint8_t pkt[100], buf[4096];
    for (int i = 0; i < 100; i++) pkt[i] = (uint8_t)i;
    pkt[0] = 0x45;
    int n = ntb16_build(buf, sizeof buf, 7, &np, pkt, 100);
    CHECK(n == 128);
    CHECK(memcmp(buf, "NCMH", 4) == 0 && get_le32(buf + 4) == (12u | (7u << 16)));
    CHECK((buf[8] | buf[9] << 8) == 128 && (buf[10] | buf[11] << 8) == 12);
    CHECK(memcmp(buf + 12, "IPS\0", 4) == 0 && (buf[16] | buf[17] << 8) == 16);
    CHECK((buf[20] | buf[21] << 8) == 28 && (buf[22] | buf[23] << 8) == 100);
    CHECK(get_le32(buf + 24) == 0);  // 結尾的 (0,0)
    seen = 0;
    CHECK(ntb16_parse(buf, n, ntb_cb, NULL) == 1 && seen_len[0] == 100 && memcmp(seen_buf[0], pkt, 100) == 0);

    // divisor 32、remainder 2、align 8：NDP 在 16，封包在 34（34 % 32 == 2）
    ntb_params_t odd = np;
    odd.out_divisor = 32;
    odd.out_remainder = 2;
    odd.out_align = 8;
    n = ntb16_build(buf, sizeof buf, 0, &odd, pkt, 100);
    CHECK((buf[10] | buf[11] << 8) == 16 && (buf[24] | buf[25] << 8) == 34 && n == 134);
    seen = 0;
    CHECK(ntb16_parse(buf, n, ntb_cb, NULL) == 1 && memcmp(seen_buf[0], pkt, 100) == 0);

    // 超過 out_max 不送
    odd.out_max = 120;
    CHECK(ntb16_build(buf, sizeof buf, 0, &odd, pkt, 100) < 0);

    // 裝置送來的：一個 DSS 的 NDP 串到 session 0 的 NDP，裡面兩個封包
    memset(buf, 0, sizeof buf);
    memcpy(buf, "NCMH", 4);
    buf[4] = 12;
    buf[8] = 0;
    buf[9] = 1;   // block 256
    buf[10] = 12;  // 第一個 NDP 在 12
    memcpy(buf + 12, "DSS\0", 4);
    buf[16] = 16;
    buf[18] = 48;  // 下一個 NDP 在 48
    buf[20] = 200;
    buf[22] = 4;   // DSS 的資料，要略過
    memcpy(buf + 48, "IPS\0", 4);
    buf[52] = 20;
    buf[56] = 96;
    buf[58] = 40;
    buf[60] = 136;
    buf[62] = 60;
    memset(buf + 96, 0x45, 40);
    memset(buf + 136, 0x46, 60);
    seen = 0;
    CHECK(ntb16_parse(buf, 256, ntb_cb, NULL) == 2 && seen_len[0] == 40 && seen_len[1] == 60);
    CHECK(seen_buf[0][0] == 0x45 && seen_buf[1][0] == 0x46);

    // 封包指到 block 外面就略過，簽章錯就整個不要
    buf[62] = 200;
    seen = 0;
    CHECK(ntb16_parse(buf, 256, ntb_cb, NULL) == 1);
    buf[0] = 'X';
    CHECK(ntb16_parse(buf, 256, ntb_cb, NULL) < 0);
    CHECK(ntb16_parse(buf, 8, ntb_cb, NULL) < 0);
}

static const uint8_t HOST[6] = {0x02, 0x44, 0x54, 0x4d, 0x00, 0x01};
static const uint8_t GW[6] = {0x02, 0x44, 0x54, 0x4d, 0x00, 0x02};

static int arp_request(uint8_t *f, uint32_t spa, uint32_t tpa) {
    memset(f, 0xff, 6);
    memcpy(f + 6, HOST, 6);
    put_be16(f + 12, 0x0806);
    uint8_t *a = f + 14;
    put_be16(a, 1);
    put_be16(a + 2, 0x0800);
    a[4] = 6;
    a[5] = 4;
    put_be16(a + 6, 1);
    memcpy(a + 8, HOST, 6);
    memcpy(a + 14, &spa, 4);
    memset(a + 18, 0, 6);
    memcpy(a + 24, &tpa, 4);
    memset(f + 42, 0, 18);  // 補到 60
    return 60;
}

static void test_l2(void) {
    uint32_t me = ip4(100, 98, 240, 100), gw = ip4(100, 98, 240, 101);
    uint8_t f[128], reply[64];
    int rl = 0, il = 0;
    const uint8_t *ip = NULL;
    int n = arp_request(f, me, gw);
    CHECK(l2_from_host(f, n, me, GW, reply, &rl, &ip, &il) == 1 && rl == 42);
    CHECK(memcmp(reply, HOST, 6) == 0 && memcmp(reply + 6, GW, 6) == 0 && get_be16(reply + 12) == 0x0806);
    CHECK(get_be16(reply + 20) == 2 && memcmp(reply + 22, GW, 6) == 0 && memcmp(reply + 28, &gw, 4) == 0);
    CHECK(memcmp(reply + 32, HOST, 6) == 0 && memcmp(reply + 38, &me, 4) == 0);
    // 其他鄰居也回（這條線上只有數據機）
    n = arp_request(f, me, ip4(100, 98, 240, 97));
    CHECK(l2_from_host(f, n, me, GW, reply, &rl, &ip, &il) == 1);
    // 系統自己的重複位址檢查、宣告、問自己的 IP：都不能回
    n = arp_request(f, 0, me);
    CHECK(l2_from_host(f, n, me, GW, reply, &rl, &ip, &il) == 0);
    n = arp_request(f, me, me);
    CHECK(l2_from_host(f, n, me, GW, reply, &rl, &ip, &il) == 0);
    n = arp_request(f, gw, me);
    CHECK(l2_from_host(f, n, me, GW, reply, &rl, &ip, &il) == 0);

    // IPv4：去掉乙太網路標頭和最短長度補的 0
    uint8_t pkt[64];
    int pl = icmp_echo_build(pkt, sizeof pkt, me, ip4(8, 8, 8, 8), 0x4454, 1);
    CHECK(pl == 44);
    memset(f, 0, sizeof f);
    memcpy(f, GW, 6);
    memcpy(f + 6, HOST, 6);
    put_be16(f + 12, 0x0800);
    memcpy(f + 14, pkt, (size_t)pl);
    CHECK(l2_from_host(f, 64, me, GW, reply, &rl, &ip, &il) == 2 && il == 44 && ip == f + 14);
    put_be16(f + 12, 0x86dd);
    CHECK(l2_from_host(f, 64, me, GW, reply, &rl, &ip, &il) == 0);

    uint8_t frame[128];
    CHECK(l2_to_host(frame, sizeof frame, pkt, pl, HOST, GW) == 58);
    CHECK(memcmp(frame, HOST, 6) == 0 && memcmp(frame + 6, GW, 6) == 0 && get_be16(frame + 12) == 0x0800);
    CHECK(memcmp(frame + 14, pkt, (size_t)pl) == 0);
    pkt[0] = 0x60;
    CHECK(l2_to_host(frame, sizeof frame, pkt, pl, HOST, GW) == 0);
}

static void test_icmp_probe(void) {
    uint32_t me = ip4(100, 98, 240, 100), dst = ip4(8, 8, 8, 8);
    uint8_t p[64];
    int n = icmp_echo_build(p, sizeof p, me, dst, 0x4454, 3);
    CHECK(n == 44 && ip_checksum(p, 20, 0) == 0 && ip_checksum(p + 20, 24, 0) == 0);
    CHECK(p[9] == 1 && p[20] == 8 && get_be16(p + 24) == 0x4454 && get_be16(p + 26) == 3);
    // 對方的回覆：位址對調、type 0
    uint8_t r[64];
    memcpy(r, p, (size_t)n);
    memcpy(r + 12, &dst, 4);
    memcpy(r + 16, &me, 4);
    r[20] = 0;
    CHECK(icmp_is_echo_reply(r, n, me, 0x4454));
    CHECK(!icmp_is_echo_reply(r, n, me, 0x1111));
    CHECK(!icmp_is_echo_reply(p, n, me, 0x4454));  // 自己送出的 request 不算
    CHECK(!icmp_is_echo_reply(r, 20, me, 0x4454));
}

static void test_netmask(void) {
    // /32 加上子網路外的閘道（有些數據機這樣給）：放寬到包得住閘道
    CHECK(mbim_netmask(ip4(10, 1, 2, 3), ip4(10, 1, 2, 4), 32) == ip4(255, 255, 255, 248));
    CHECK(mbim_netmask(ip4(10, 1, 2, 3), ip4(10, 1, 2, 1), 30) == ip4(255, 255, 255, 252));
    CHECK(mbim_netmask(ip4(10, 1, 2, 3), 0, 24) == ip4(255, 255, 255, 0));
    CHECK(mbim_netmask(ip4(10, 1, 2, 3), ip4(10, 1, 2, 4), 0) == ip4(255, 255, 255, 248));
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--dump") == 0) return dump();
    test_requests_match_device();
    test_device_responses();
    test_crafted_responses();
    test_bad_messages();
    test_reassembly();
    test_connect_set_layout();
    test_ntb16();
    test_l2();
    test_icmp_probe();
    test_netmask();
    printf("mbim: %d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
