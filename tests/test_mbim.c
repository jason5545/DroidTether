// 不需要裝置的 MBIM 測試：訊息組裝與解析、分段重組、NTB16、feth 端的 ARP 與乙太網路標頭、ICMP 探測、
// 簡訊（SMS 服務的訊息與 3GPP TS 23.040 的 PDU 編解碼，PDU 對照 ModemManager 測試裡的真實簡訊與期待值）。
// REAL_* 是 TCL IK512（高通 SDX62）實際收發的位元組，2026/10/10 從 Linux 主機上的 mbimcli --verbose-full 取得。
// 撥號、附著這些不能真的送出去的指令，用 tests/mbim_oracle.py 跟 libmbim 逐位元組對照：
//   build/test_mbim           跑測試
//   build/test_mbim --dump    印出要給 mbim_oracle.py 對照的訊息

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "../src/dhcp.h"
#include "../src/mbim.h"
#include "../src/sms.h"

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

static int svc_msg(uint8_t *b, const uint8_t uuid[16], uint32_t type, uint32_t tid, uint32_t cid, uint32_t status,
                   const uint8_t *info, int n) {
    bool ind = type == MBIM_INDICATE_STATUS;
    int hdr = ind ? 44 : 48;
    put_le32(b, type);
    put_le32(b + 4, (uint32_t)(hdr + n));
    put_le32(b + 8, tid);
    put_le32(b + 12, 1);
    put_le32(b + 16, 0);
    memcpy(b + 20, uuid, 16);
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

static int done_msg(uint8_t *b, uint32_t type, uint32_t tid, uint32_t cid, uint32_t status, const uint8_t *info,
                    int n) {
    return svc_msg(b, MBIM_UUID_BASIC_CONNECT, type, tid, cid, status, info, n);
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

static int put_utf16(uint8_t *p, const char *ascii) {
    int n = 0;
    for (; ascii[n]; n++) {
        p[2 * n] = (uint8_t)ascii[n];
        p[2 * n + 1] = 0;
    }
    return 2 * n;
}

// MBIM_PIN_INFO：PinType, PinState, RemainingAttempts
static int fx_pin_done(uint8_t *b) {
    uint8_t i[12];
    put_le32(i, MBIM_PIN_TYPE_PIN1);
    put_le32(i + 4, MBIM_PIN_STATE_LOCKED);
    put_le32(i + 8, 3);
    return done_msg(b, MBIM_COMMAND_DONE, 20, MBIM_CID_PIN, 0, i, sizeof i);
}

// MBIM_SIGNAL_STATE_INFO：Rssi, ErrorRate, SignalStrengthInterval, RssiThreshold, ErrorRateThreshold（IK512 在 Mac 上讀到 RSSI 14）
static int fx_signal_done(uint8_t *b) {
    uint8_t i[20] = {0};
    put_le32(i, 14);
    put_le32(i + 4, 99);
    return done_msg(b, MBIM_COMMAND_DONE, 21, MBIM_CID_SIGNAL_STATE, 0, i, sizeof i);
}

// 有電信商名稱的 REGISTRATION_STATE：ProviderId "46697"、ProviderName "TW Mobile"
static int fx_register_named(uint8_t *b) {
    uint8_t i[80] = {0};
    put_le32(i + 4, MBIM_REG_HOME);
    put_le32(i + 8, 1);
    put_le32(i + 12, 0x80000020);
    put_le32(i + 16, 1);
    int n1 = put_utf16(i + 48, "46697");
    put_le32(i + 20, 48);
    put_le32(i + 24, (uint32_t)n1);
    int n2 = put_utf16(i + 60, "TW Mobile");
    put_le32(i + 28, 60);
    put_le32(i + 32, (uint32_t)n2);
    return done_msg(b, MBIM_COMMAND_DONE, 22, MBIM_CID_REGISTER_STATE, 0, i, 80);
}

// IPv4 + IPv6 的 IP_CONFIGURATION：位址、閘道照 IK512 在 Mac 上撥 IPv4v6 拿到的，IPv6 DNS 用 Google 的當範例
static const uint8_t V6_ADDR[16] = {0x24, 0x02, 0x75, 0x00, 0x04, 0xf6, 0x9a, 0x73,
                                    0x8c, 0x45, 0x3f, 0x2d, 0x7a, 0x2f, 0x0e, 0xd8};
static const uint8_t V6_GW[16] = {0x24, 0x02, 0x75, 0x00, 0x04, 0xf6, 0x9a, 0x73,
                                  0xe9, 0x65, 0x6c, 0xe9, 0x6e, 0xbc, 0xbf, 0x6d};
static const uint8_t V6_DNS1[16] = {0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88};
static const uint8_t V6_DNS2[16] = {0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x44};
static int fx_ipcfg6_done(uint8_t *b) {
    uint8_t i[148] = {0};
    put_le32(i + 4, 0x0F);
    put_le32(i + 8, 0x0F);
    put_le32(i + 12, 1);
    put_le32(i + 16, 60);
    put_le32(i + 20, 1);
    put_le32(i + 24, 68);
    put_le32(i + 28, 88);
    put_le32(i + 32, 92);
    put_le32(i + 36, 2);
    put_le32(i + 40, 108);
    put_le32(i + 44, 2);
    put_le32(i + 48, 116);
    put_le32(i + 52, 1500);
    put_le32(i + 56, 1500);
    put_le32(i + 60, 30);
    memcpy(i + 64, (uint8_t[]){10, 21, 162, 178}, 4);
    put_le32(i + 68, 64);
    memcpy(i + 72, V6_ADDR, 16);
    memcpy(i + 88, (uint8_t[]){10, 21, 162, 177}, 4);
    memcpy(i + 92, V6_GW, 16);
    memcpy(i + 108, (uint8_t[]){61, 31, 1, 1, 61, 31, 233, 1}, 8);
    memcpy(i + 116, V6_DNS1, 16);
    memcpy(i + 132, V6_DNS2, 16);
    return done_msg(b, MBIM_COMMAND_DONE, 23, MBIM_CID_IP_CONFIGURATION, 0, i, sizeof i);
}

// MBIM_DEVICE_CAPS_INFO，CustomDataClass "5G/TDS"（IK512 的值），DeviceId 等留空
static int fx_device_caps_done(uint8_t *b) {
    uint8_t i[76] = {0};
    put_le32(i, 2);
    put_le32(i + 4, 1);
    put_le32(i + 8, 1);
    put_le32(i + 12, 2);
    put_le32(i + 16, 0x80000020);
    put_le32(i + 20, 3);
    put_le32(i + 24, 1);
    put_le32(i + 28, 15);
    int n = put_utf16(i + 64, "5G/TDS");
    put_le32(i + 32, 64);
    put_le32(i + 36, (uint32_t)n);
    return done_msg(b, MBIM_COMMAND_DONE, 24, MBIM_CID_DEVICE_CAPS, 0, i, sizeof i);
}

// ---------- 簡訊 ----------

// ModemManager 的 src/tests/test-sms-part-3gpp.c 裡的 PDU（真實收到的簡訊），期待值照它的 assert。
// 收到的是 SMS-DELIVER，開頭都帶 SMSC 欄位，MBIM 讀出來的就是這個格式。
static const uint8_t MM_PDU1[] = {  // GSM 7-bit，有擴充表的字元
    0x07, 0x91, 0x21, 0x04, 0x44, 0x29, 0x61, 0xf4, 0x04, 0x0b, 0x91, 0x61, 0x71, 0x95, 0x72, 0x91, 0xf8, 0x00, 0x00,
    0x11, 0x20, 0x82, 0x11, 0x05, 0x05, 0x0a, 0x6a, 0xc8, 0xb2, 0xbc, 0x7c, 0x9a, 0x83, 0xc2, 0x20, 0xf6, 0xdb, 0x7d,
    0x2e, 0xcb, 0x41, 0xed, 0xf2, 0x7c, 0x1e, 0x3e, 0x97, 0x41, 0x1b, 0xde, 0x06, 0x75, 0x4f, 0xd3, 0xd1, 0xa0, 0xf9,
    0xbb, 0x5d, 0x06, 0x95, 0xf1, 0xf4, 0xb2, 0x9b, 0x5c, 0x26, 0x83, 0xc6, 0xe8, 0xb0, 0x3c, 0x3c, 0xa6, 0x97, 0xe5,
    0xf3, 0x4d, 0x6a, 0xe3, 0x03, 0xd1, 0xd1, 0xf2, 0xf7, 0xdd, 0x0d, 0x4a, 0xbb, 0x59, 0xa0, 0x79, 0x7d, 0x8c, 0x06,
    0x85, 0xe7, 0xa0, 0x00, 0x28, 0xec, 0x26, 0x83, 0x2a, 0x96, 0x0b, 0x28, 0xec, 0x26, 0x83, 0xbe, 0x60, 0x50, 0x78,
    0x0e, 0xba, 0x97, 0xd9, 0x6c, 0x17};
static const uint8_t MM_PDU2[] = {  // 英數字寄件者、UCS-2
    0x07, 0x91, 0x97, 0x30, 0x07, 0x11, 0x11, 0xf1, 0x04, 0x14, 0xd0, 0x49, 0x37, 0xbd, 0x2c, 0x77, 0x97, 0xe9, 0xd3,
    0xe6, 0x14, 0x00, 0x08, 0x11, 0x30, 0x92, 0x91, 0x02, 0x40, 0x61, 0x08, 0x04, 0x42, 0x04, 0x35, 0x04, 0x41, 0x04,
    0x42};
static const uint8_t MM_PDU3[] = {
    0x07, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0xf1, 0x04, 0x0b, 0x91, 0x81, 0x00, 0x55, 0x15, 0x12,
    0xf2, 0x00, 0x00, 0x11, 0x10, 0x10, 0x21, 0x43, 0x65, 0x00, 0x0a, 0xe8, 0x32, 0x9b, 0xfd, 0x46,
    0x97, 0xd9, 0xec, 0x37};
static const uint8_t MM_DCSF1[] = {  // TP-DCS 0xF1（class 1，GSM 7-bit），法文
    0x07, 0x91, 0x33, 0x06, 0x09, 0x10, 0x93, 0xF0, 0x04, 0x04, 0x85, 0x81, 0x00, 0x00, 0xF1, 0x11, 0x60, 0x42,
    0x31, 0x80, 0x51, 0x80, 0xA0, 0x49, 0xB7, 0xF9, 0x0D, 0x9A, 0x1A, 0xA5, 0xA0, 0x16, 0x68, 0xF8, 0x76, 0x9B,
    0xD3, 0xE4, 0xB2, 0x9B, 0x9E, 0x2E, 0xB3, 0x59, 0xA0, 0x3F, 0xC8, 0x5D, 0x06, 0xA9, 0xC3, 0xED, 0x70, 0x7A,
    0x0E, 0xA2, 0xCB, 0xC3, 0xEE, 0x79, 0xBB, 0x4C, 0xA7, 0xCB, 0xCB, 0xA0, 0x56, 0x43, 0x61, 0x7D, 0xA7, 0xC7,
    0x69, 0x90, 0xFD, 0x4D, 0x97, 0x97, 0x41, 0xEE, 0x77, 0xDD, 0x5E, 0x0E, 0xD7, 0x41, 0xED, 0x37, 0x1D, 0x44,
    0x2E, 0x83, 0xE0, 0xE1, 0xF9, 0xBC, 0x0C, 0xD2, 0x81, 0xE6, 0x77, 0xD9, 0xB8, 0x4C, 0x06, 0xC1, 0xDF, 0x75,
    0x39, 0xE8, 0x5C, 0x90, 0x97, 0xE5, 0x20, 0xFB, 0x9B, 0x2E, 0x2F, 0x83, 0xC6, 0xEF, 0x36, 0x9C, 0x5E, 0x06,
    0x4D, 0x8D, 0x52, 0xD0, 0xBC, 0x2E, 0x07, 0xDD, 0xEF, 0x77, 0xD7, 0xDC, 0x2C, 0x77, 0x99, 0xE5, 0xA0, 0x77,
    0x1D, 0x04, 0x0F, 0xCB, 0x41, 0xF4, 0x02, 0xBB, 0x00, 0x47, 0xBF, 0xDD, 0x65, 0x50, 0xB8, 0x0E, 0xCA, 0xD9,
    0x66};
// KPN 的歡迎簡訊：16-bit reference 的多段簡訊（UDH 7 octets，GSM 7-bit 剛好沒有補位）
static const char *MM_UDHI =
    "07911356131313F64004850120390011609232239180A006080400100201D7327BFD6EB340E232"
    "1BF46E83EA7790F59D1E97DBE1341B442F83C465763D3DA797E56537C81D0ECB41AB59CC1693C1"
    "6031D96C064241E5656838AF03A96230982A269BCD462917C8FA4E8FCBED709A0D7ABBE9F6B0FB"
    "5C7683D27350984D4FABC9A0B33C4C4FCF5D20EBFB2D079DCB62793DBD06D9C36E50FB2D4E97D9"
    "A0B49B5E96BBCB";
// 8-bit reference 的兩段簡訊（UDH 6 octets，GSM 7-bit 要補 1 個位元）
static const char *MM_MULTI1 =
    "07912160130320F5440B916171056429F5000021405291650569A00500034C0201A9E8F41C949E"
    "83C2207B599E07B1DFEE33885E9ED341E4F23C7D7697C920FA1B54C697E5E3F4BC0C6AD7D9F434"
    "081E96D341E3303C2C4EB3D3F4BC0B94A483E6E8779D4D06CDD1EF3BA80E0785E7A0B7BB0C6A97"
    "E7F3F0B9CC02B9DF7450780EA2DFDF2C50780EA2A3CBA0BA9B5C96B3F369F71954768FDFE4B4FB"
    "0C9297E1F2F2BCECA6CF41";
static const char *MM_MULTI2 =
    "07912160130320F6440B916171056429F5000021405291651569320500034C0202E9E8301D4447"
    "9741F0B09C3E0785E56590BCCC0ED3CB6410FD0D7ABBCBA0B0FB4D4797E52E10";
static const char *MM_MULTI_TEXT1 =
    "This is a very long test designed to exercise multi part capability. It should "
    "show up as one message, not as two, as the underlying encoding represents ";
static const char *MM_MULTI_TEXT2 = "that the parts are related to one another. ";
static const char *MM_STORED_SUBMIT =  // 存在數據機裡的 SMS-SUBMIT，中文
    "002100098136397339F70008224F60597D4F60597D4F60597D4F60597D4F60597D4F60597D4F60597D4F60597D4F60";
static const char *MM_STATUS_REPORT = "07914356060013F1065A098136397339F7219011700463802190117004638030";

// 自己組的台灣簡訊：0912345678 傳來「測試😀」（UCS-2，emoji 是 surrogate pair），2026-10-10 12:34:56 +08
static const uint8_t TW_PDU[] = {0x00, 0x04, 0x0A, 0x81, 0x90, 0x21, 0x43, 0x65, 0x87, 0x00, 0x08, 0x62, 0x01, 0x01,
                                 0x21, 0x43, 0x65, 0x23, 0x08, 0x6E, 0x2C, 0x8A, 0x66, 0xD8, 0x3D, 0xDE, 0x00};

static int unhex(const char *h, uint8_t *out) {
    int n = 0;
    for (; h[0] && h[1]; h += 2) {
        unsigned v;
        sscanf(h, "%2x", &v);
        out[n++] = (uint8_t)v;
    }
    return n;
}

// SMS_CONFIGURATION 回應，數值是 IK512 在 Mac 上實際回的（2026/10/10）：儲存區就緒、PDU、40 則、台灣大哥大的簡訊中心
static int fx_sms_config_done(uint8_t *b) {
    uint8_t i[52] = {0};
    put_le32(i, 1);
    put_le32(i + 8, 40);
    int n = put_utf16(i + 24, "+886935874443");
    put_le32(i + 16, 24);
    put_le32(i + 20, (uint32_t)n);
    return svc_msg(b, MBIM_UUID_SMS, MBIM_COMMAND_DONE, 30, MBIM_CID_SMS_CONFIGURATION, 0, i, sizeof i);
}

// 有新簡訊：MESSAGE_STORE_STATUS 的 indication，Flag new-message、位置 3
static int fx_sms_store_indication(uint8_t *b) {
    uint8_t i[8];
    put_le32(i, MBIM_SMS_STORE_NEW_MESSAGE);
    put_le32(i + 4, 3);
    return svc_msg(b, MBIM_UUID_SMS, MBIM_INDICATE_STATUS, 0, MBIM_CID_SMS_MESSAGE_STORE_STATUS, 0, i, sizeof i);
}

// SMS_READ 回應：兩筆，位置 3（新的，MM_PDU3）與位置 4（讀過的，TW_PDU，27 bytes 要補到 28）
static int fx_sms_read_done(uint8_t *b) {
    uint8_t i[160] = {0};
    int r1 = 24, l1 = 16 + (int)sizeof MM_PDU3, r2 = r1 + l1, l2 = 16 + (int)sizeof TW_PDU;
    put_le32(i + 4, 2);
    put_le32(i + 8, (uint32_t)r1);
    put_le32(i + 12, (uint32_t)l1);
    put_le32(i + 16, (uint32_t)r2);
    put_le32(i + 20, (uint32_t)l2);
    put_le32(i + r1, 3);
    put_le32(i + r1 + 4, MBIM_SMS_STATUS_NEW);
    put_le32(i + r1 + 8, 16);
    put_le32(i + r1 + 12, sizeof MM_PDU3);
    memcpy(i + r1 + 16, MM_PDU3, sizeof MM_PDU3);
    put_le32(i + r2, 4);
    put_le32(i + r2 + 4, MBIM_SMS_STATUS_OLD);
    put_le32(i + r2 + 8, 16);
    put_le32(i + r2 + 12, sizeof TW_PDU);
    memcpy(i + r2 + 16, TW_PDU, sizeof TW_PDU);
    int n = (r2 + l2 + 3) & ~3;
    return svc_msg(b, MBIM_UUID_SMS, MBIM_COMMAND_DONE, 32, MBIM_CID_SMS_READ, 0, i, n);
}

static int fx_sms_send_done(uint8_t *b) {
    uint8_t i[4];
    put_le32(i, 7);
    return svc_msg(b, MBIM_UUID_SMS, MBIM_COMMAND_DONE, 37, MBIM_CID_SMS_SEND, 0, i, sizeof i);
}

// ModemManager 測試裡編好的 SMS-SUBMIT（PDU creator 的期待值）
static const uint8_t MM_SUBMIT_GSM_NO_VP[] = {  // "+15556661234"、"This is really cool ΔΔΔΔΔ"、不帶有效期
    0x00, 0x01, 0x00, 0x0B, 0x91, 0x51, 0x55, 0x66, 0x16, 0x32, 0xF4, 0x00, 0x00, 0x19, 0x54, 0x74, 0x7A, 0x0E,
    0x4A, 0xCF, 0x41, 0xF2, 0x72, 0x98, 0xCD, 0xCE, 0x83, 0xC6, 0xEF, 0x37, 0x1B, 0x04, 0x81, 0x40, 0x20, 0x10};
static const uint8_t MM_SUBMIT_GSM3[] = {  // 同上，有效期 5 分鐘（TP-VP 0）：最後一個 septet 自己占一個 octet
    0x00, 0x11, 0x00, 0x0B, 0x91, 0x51, 0x55, 0x66, 0x16, 0x32, 0xF4, 0x00, 0x00, 0x00, 0x19, 0x54, 0x74, 0x7A, 0x0E,
    0x4A, 0xCF, 0x41, 0xF2, 0x72, 0x98, 0xCD, 0xCE, 0x83, 0xC6, 0xEF, 0x37, 0x1B, 0x04, 0x81, 0x40, 0x20, 0x10};
static const uint8_t MM_SUBMIT_GSM[] = {  // "+15555551234"，有效期 5 分鐘
    0x00, 0x11, 0x00, 0x0B, 0x91, 0x51, 0x55, 0x55, 0x15, 0x32, 0xF4, 0x00, 0x00, 0x00, 0x36, 0xC8, 0x34, 0x88,
    0x8E, 0x2E, 0xCB, 0xCB, 0x2E, 0x97, 0x8B, 0x5A, 0x2F, 0x83, 0x62, 0x37, 0x3A, 0x1A, 0xA4, 0x0C, 0xBB, 0x41,
    0x32, 0x58, 0x4C, 0x06, 0x82, 0xD5, 0x74, 0x33, 0x98, 0x2B, 0x86, 0x03, 0xC1, 0xDB, 0x20, 0xD4, 0xB1, 0x49,
    0x5D, 0xC5, 0x52, 0x20, 0x08, 0x04, 0x02, 0x81, 0x00};
static const uint8_t MM_SUBMIT_UCS2[] = {  // "+15555551234"，俄文，有效期 5 分鐘
    0x00, 0x11, 0x00, 0x0B, 0x91, 0x51, 0x55, 0x55, 0x15, 0x32, 0xF4, 0x00, 0x08, 0x00, 0x3A, 0x04, 0x14, 0x04,
    0x30, 0x00, 0x20, 0x04, 0x37, 0x04, 0x34, 0x04, 0x40, 0x04, 0x30, 0x04, 0x32, 0x04, 0x41, 0x04, 0x42, 0x04,
    0x32, 0x04, 0x43, 0x04, 0x35, 0x04, 0x42, 0x00, 0x20, 0x04, 0x3A, 0x04, 0x3E, 0x04, 0x40, 0x04, 0x3E, 0x04,
    0x3B, 0x04, 0x4C, 0x00, 0x2C, 0x00, 0x20, 0x04, 0x34, 0x04, 0x35, 0x04, 0x42, 0x04, 0x3A, 0x04, 0x30, 0x00,
    0x21};

// ---------- 給 mbim_oracle.py 的請求 ----------

static int req_connect_type(uint8_t *b, uint32_t tid, bool activate, const char *apn, uint32_t type) {
    uint8_t info[256];
    int il = mbim_info_connect_set(info, sizeof info, 0, activate, apn, type);
    return mbim_build_command(b, 4096, tid, MBIM_UUID_BASIC_CONNECT, MBIM_CID_CONNECT, true, info, il);
}

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
    hex("req", "connect_activate_internet_v4v6", b, req_connect_type(b, 14, true, "internet", MBIM_IP_TYPE_IPV4V6));
    hex("req", "pin_query", b, mbim_build_command(b, sizeof b, 15, MBIM_UUID_BASIC_CONNECT, MBIM_CID_PIN, false, NULL, 0));
    il = mbim_info_pin_enter(info, sizeof info, "1234");
    hex("req", "pin_enter_1234", b, mbim_build_command(b, sizeof b, 16, MBIM_UUID_BASIC_CONNECT, MBIM_CID_PIN, true, info, il));
    il = mbim_info_pin_enter(info, sizeof info, "12345");
    hex("req", "pin_enter_12345", b, mbim_build_command(b, sizeof b, 17, MBIM_UUID_BASIC_CONNECT, MBIM_CID_PIN, true, info, il));
    hex("req", "signal_query", b,
        mbim_build_command(b, sizeof b, 18, MBIM_UUID_BASIC_CONNECT, MBIM_CID_SIGNAL_STATE, false, NULL, 0));
    hex("req", "device_caps_query", b,
        mbim_build_command(b, sizeof b, 19, MBIM_UUID_BASIC_CONNECT, MBIM_CID_DEVICE_CAPS, false, NULL, 0));

    hex("resp", "real_ipcfg_done", REAL_IPCFG_DONE, sizeof REAL_IPCFG_DONE);
    hex("resp", "real_radio_done", REAL_RADIO_DONE, sizeof REAL_RADIO_DONE);
    hex("resp", "connect_done", b, fx_connect_done(b));
    hex("resp", "connect_indication_deactivated", b, fx_connect_indication(b));
    hex("resp", "register_done_home", b, fx_register_done(b));
    hex("resp", "packet_service_done_attached", b, fx_packet_done(b));
    hex("resp", "subscriber_ready_done", b, fx_subscriber_done(b));
    hex("resp", "pin_done_locked", b, fx_pin_done(b));
    hex("resp", "signal_done", b, fx_signal_done(b));
    hex("resp", "register_done_named", b, fx_register_named(b));
    hex("resp", "ipcfg6_done", b, fx_ipcfg6_done(b));
    hex("resp", "device_caps_done", b, fx_device_caps_done(b));

    hex("req", "sms_config_query", b,
        mbim_build_command(b, sizeof b, 30, MBIM_UUID_SMS, MBIM_CID_SMS_CONFIGURATION, false, NULL, 0));
    hex("req", "sms_store_status_query", b,
        mbim_build_command(b, sizeof b, 31, MBIM_UUID_SMS, MBIM_CID_SMS_MESSAGE_STORE_STATUS, false, NULL, 0));
    il = mbim_info_sms_read(info, MBIM_SMS_FLAG_ALL, 0);
    hex("req", "sms_read_all", b, mbim_build_command(b, sizeof b, 32, MBIM_UUID_SMS, MBIM_CID_SMS_READ, false, info, il));
    il = mbim_info_sms_read(info, MBIM_SMS_FLAG_INDEX, 3);
    hex("req", "sms_read_index_3", b, mbim_build_command(b, sizeof b, 33, MBIM_UUID_SMS, MBIM_CID_SMS_READ, false, info, il));
    il = mbim_info_sms_read(info, MBIM_SMS_FLAG_NEW, 0);
    hex("req", "sms_read_new", b, mbim_build_command(b, sizeof b, 34, MBIM_UUID_SMS, MBIM_CID_SMS_READ, false, info, il));
    il = mbim_info_sms_delete(info, MBIM_SMS_FLAG_INDEX, 3);
    hex("req", "sms_delete_index_3", b, mbim_build_command(b, sizeof b, 35, MBIM_UUID_SMS, MBIM_CID_SMS_DELETE, true, info, il));
    il = mbim_info_sms_delete(info, MBIM_SMS_FLAG_ALL, 0);
    hex("req", "sms_delete_all", b, mbim_build_command(b, sizeof b, 36, MBIM_UUID_SMS, MBIM_CID_SMS_DELETE, true, info, il));
    // 送出去的 PDU 用 ModemManager 的期待值：73 bytes（補 3）與 37 bytes（補 3）、36 bytes（不用補）
    il = mbim_info_sms_send(info, sizeof info, MM_SUBMIT_UCS2, sizeof MM_SUBMIT_UCS2);
    hex("req", "sms_send_ucs2", b, mbim_build_command(b, sizeof b, 37, MBIM_UUID_SMS, MBIM_CID_SMS_SEND, true, info, il));
    il = mbim_info_sms_send(info, sizeof info, MM_SUBMIT_GSM3, sizeof MM_SUBMIT_GSM3);
    hex("req", "sms_send_gsm", b, mbim_build_command(b, sizeof b, 38, MBIM_UUID_SMS, MBIM_CID_SMS_SEND, true, info, il));
    il = mbim_info_sms_send(info, sizeof info, MM_SUBMIT_GSM_NO_VP, sizeof MM_SUBMIT_GSM_NO_VP);
    hex("req", "sms_send_gsm_no_vp", b, mbim_build_command(b, sizeof b, 39, MBIM_UUID_SMS, MBIM_CID_SMS_SEND, true, info, il));

    hex("resp", "sms_config_done", b, fx_sms_config_done(b));
    hex("resp", "sms_store_indication", b, fx_sms_store_indication(b));
    hex("resp", "sms_read_done", b, fx_sms_read_done(b));
    hex("resp", "sms_send_done", b, fx_sms_send_done(b));
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
    CHECK(l2_from_host(f, n, me, NULL, GW, reply, &rl, &ip, &il) == 1 && rl == 42);
    CHECK(memcmp(reply, HOST, 6) == 0 && memcmp(reply + 6, GW, 6) == 0 && get_be16(reply + 12) == 0x0806);
    CHECK(get_be16(reply + 20) == 2 && memcmp(reply + 22, GW, 6) == 0 && memcmp(reply + 28, &gw, 4) == 0);
    CHECK(memcmp(reply + 32, HOST, 6) == 0 && memcmp(reply + 38, &me, 4) == 0);
    // 其他鄰居也回（這條線上只有數據機）
    n = arp_request(f, me, ip4(100, 98, 240, 97));
    CHECK(l2_from_host(f, n, me, NULL, GW, reply, &rl, &ip, &il) == 1);
    // 系統自己的重複位址檢查、宣告、問自己的 IP：都不能回
    n = arp_request(f, 0, me);
    CHECK(l2_from_host(f, n, me, NULL, GW, reply, &rl, &ip, &il) == 0);
    n = arp_request(f, me, me);
    CHECK(l2_from_host(f, n, me, NULL, GW, reply, &rl, &ip, &il) == 0);
    n = arp_request(f, gw, me);
    CHECK(l2_from_host(f, n, me, NULL, GW, reply, &rl, &ip, &il) == 0);

    // IPv4：去掉乙太網路標頭和最短長度補的 0
    uint8_t pkt[64];
    int pl = icmp_echo_build(pkt, sizeof pkt, me, ip4(8, 8, 8, 8), 0x4454, 1);
    CHECK(pl == 44);
    memset(f, 0, sizeof f);
    memcpy(f, GW, 6);
    memcpy(f + 6, HOST, 6);
    put_be16(f + 12, 0x0800);
    memcpy(f + 14, pkt, (size_t)pl);
    CHECK(l2_from_host(f, 64, me, NULL, GW, reply, &rl, &ip, &il) == 2 && il == 44 && ip == f + 14);
    put_be16(f + 12, 0x86dd);
    CHECK(l2_from_host(f, 64, me, NULL, GW, reply, &rl, &ip, &il) == 0);

    uint8_t frame[128];
    CHECK(l2_to_host(frame, sizeof frame, pkt, pl, HOST, GW) == 58);
    CHECK(memcmp(frame, HOST, 6) == 0 && memcmp(frame + 6, GW, 6) == 0 && get_be16(frame + 12) == 0x0800);
    CHECK(memcmp(frame + 14, pkt, (size_t)pl) == 0);
    pkt[0] = 0x50;  // 不是 IPv4 也不是 IPv6
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

static void test_pin(void) {
    uint8_t p[64];
    int n = mbim_info_pin_enter(p, sizeof p, "1234");
    CHECK(n == 32 && get_le32(p) == MBIM_PIN_TYPE_PIN1 && get_le32(p + 4) == 0);
    CHECK(get_le32(p + 8) == 24 && get_le32(p + 12) == 8 && get_le32(p + 16) == 0 && get_le32(p + 20) == 0);
    CHECK(memcmp(p + 24, "1\0002\0003\0004\0", 8) == 0);
    CHECK(mbim_info_pin_enter(p, sizeof p, "12345") == 36);  // 10 bytes 補到 12
    CHECK(mbim_info_pin_enter(p, sizeof p, "123") < 0);
    CHECK(mbim_info_pin_enter(p, sizeof p, "123456789") < 0);
    CHECK(mbim_info_pin_enter(p, sizeof p, "12a4") < 0);
    CHECK(mbim_info_pin_enter(p, sizeof p, "") < 0);
    uint8_t b[256];
    mbim_msg_t m;
    uint32_t t = 0, s = 0, a = 0;
    CHECK(mbim_parse(b, fx_pin_done(b), &m) == 0 && mbim_parse_pin_info(m.info, m.info_len, &t, &s, &a) == 0);
    CHECK(t == MBIM_PIN_TYPE_PIN1 && s == MBIM_PIN_STATE_LOCKED && a == 3);
    CHECK(mbim_parse_pin_info(m.info, 8, &t, &s, &a) < 0);
}

static void test_signal_and_names(void) {
    uint8_t b[512];
    mbim_msg_t m;
    uint32_t rssi = 0, er = 0;
    CHECK(mbim_parse(b, fx_signal_done(b), &m) == 0 && mbim_parse_signal(m.info, m.info_len, &rssi, &er) == 0);
    CHECK(rssi == 14 && er == 99 && mbim_signal_bars(rssi) == 2);
    CHECK(mbim_signal_bars(99) == -1 && mbim_signal_bars(31) == 4 && mbim_signal_bars(20) == 4 && mbim_signal_bars(19) == 3);
    CHECK(mbim_signal_bars(10) == 2 && mbim_signal_bars(5) == 1 && mbim_signal_bars(4) == 0 && mbim_signal_bars(0) == 0);

    char name[64];
    CHECK(mbim_parse(b, fx_register_named(b), &m) == 0 && mbim_parse_provider_name(m.info, m.info_len, name, sizeof name) == 0);
    CHECK(strcmp(name, "TW Mobile") == 0);
    // 中文名稱（UTF-16 → UTF-8）
    uint8_t r[80];
    memcpy(r, m.info, 48);
    const uint16_t cht[] = {0x4E2D, 0x83EF, 0x96FB, 0x4FE1};  // 中華電信
    for (int i = 0; i < 4; i++) {
        r[48 + 2 * i] = (uint8_t)cht[i];
        r[49 + 2 * i] = (uint8_t)(cht[i] >> 8);
    }
    put_le32(r + 28, 48);
    put_le32(r + 32, 8);
    CHECK(mbim_parse_provider_name(r, 56, name, sizeof name) == 0 && strcmp(name, "中華電信") == 0);
    put_le32(r + 32, 200);  // 超出範圍
    CHECK(mbim_parse_provider_name(r, 56, name, sizeof name) < 0);
    // 太小的輸出緩衝區不會寫超過
    put_le32(r + 32, 8);
    char tiny[5];
    CHECK(mbim_parse_provider_name(r, 56, tiny, sizeof tiny) == 0 && strcmp(tiny, "中") == 0);

    uint32_t cls = 0;
    CHECK(mbim_parse(b, fx_packet_done(b), &m) == 0 && mbim_parse_data_class(m.info, m.info_len, &cls) == 0 && cls == 0x20);
    CHECK(strcmp(mbim_tech_name(0x80000000u, "5G/TDS"), "5G") == 0);
    CHECK(strcmp(mbim_tech_name(0x80000000u, "TDS"), "") == 0);
    CHECK(strcmp(mbim_tech_name(0x20, ""), "LTE") == 0 && strcmp(mbim_tech_name(0x60, ""), "5G") == 0);
    CHECK(strcmp(mbim_tech_name(0x08, ""), "3G") == 0 && strcmp(mbim_tech_name(0, ""), "") == 0);

    // DEVICE_CAPS 的 CustomDataClass 在固定欄位的 32/36（mbim_query_custom_class 讀同一個位置）
    CHECK(mbim_parse(b, fx_device_caps_done(b), &m) == 0 && m.cid == MBIM_CID_DEVICE_CAPS);
    CHECK(get_le32(m.info + 32) == 64 && get_le32(m.info + 36) == 12 && memcmp(m.info + 64, "5\0G\0/\0T\0D\0S\0", 12) == 0);
}

static void test_ip6_config(void) {
    uint8_t b[256];
    mbim_msg_t m;
    CHECK(mbim_parse(b, fx_ipcfg6_done(b), &m) == 0);
    mbim_ipv4_t v4;
    mbim_ipv6_t v6;
    CHECK(mbim_parse_ip_config(m.info, m.info_len, &v4) == 0 && v4.ip == ip4(10, 21, 162, 178) && v4.prefix == 30);
    CHECK(v4.gw == ip4(10, 21, 162, 177) && v4.ndns == 2 && v4.mtu == 1500);
    CHECK(mbim_parse_ip6_config(m.info, m.info_len, &v6) == 0);
    CHECK(memcmp(v6.addr, V6_ADDR, 16) == 0 && v6.prefix == 64 && v6.has_gw && memcmp(v6.gw, V6_GW, 16) == 0);
    CHECK(v6.ndns == 2 && memcmp(v6.dns[0], V6_DNS1, 16) == 0 && memcmp(v6.dns[1], V6_DNS2, 16) == 0 && v6.mtu == 1500);
    // IK512 只給 IPv4 時（PVE 上的真實回應）沒有 IPv6
    CHECK(mbim_parse_ip6_config(REAL_IPCFG_DONE + 48, 80, &v6) < 0 && v6.prefix == 0);
    // 位址 offset 指到外面
    uint8_t bad[148];
    memcpy(bad, m.info, 148);
    put_le32(bad + 24, 140);
    CHECK(mbim_parse_ip6_config(bad, 148, &v6) < 0);
}

// IPv6 frame：乙太網路 + IPv6 + payload
static int frame6(uint8_t *f, const uint8_t src[16], const uint8_t dst[16], uint8_t next, const uint8_t *pl, int pl_len) {
    memcpy(f, GW, 6);
    memcpy(f + 6, HOST, 6);
    put_be16(f + 12, 0x86dd);
    uint8_t *h = f + 14;
    memset(h, 0, 40);
    h[0] = 0x60;
    put_be16(h + 4, (uint16_t)pl_len);
    h[6] = next;
    h[7] = 255;
    memcpy(h + 8, src, 16);
    memcpy(h + 24, dst, 16);
    memcpy(h + 40, pl, (size_t)pl_len);
    return 14 + 40 + pl_len;
}

static uint16_t icmp6_sum(const uint8_t *h, const uint8_t *msg, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < 16; i += 2) sum += (uint32_t)get_be16(h + 8 + i) + get_be16(h + 24 + i);
    sum += (uint32_t)len + 58;
    return ip_checksum(msg, len, sum);
}

static void test_nd(void) {
    static const uint8_t LL[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x10, 0xe7, 0xe4, 0xff, 0xfe, 0xed, 0x32, 0xff};
    static const uint8_t ANY[16] = {0};
    uint8_t snm[16] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xbc, 0xbf, 0x6d};  // 閘道的 solicited-node
    uint8_t ns[32] = {135, 0};
    memcpy(ns + 8, V6_GW, 16);
    ns[24] = 1;  // Source Link-Layer Address
    ns[25] = 1;
    memcpy(ns + 26, HOST, 6);
    uint8_t f[256], reply[128];
    int rl = 0, il = 0;
    const uint8_t *ip = NULL;

    // 系統用 link-local 問閘道：回 NA
    int n = frame6(f, LL, snm, 58, ns, 32);
    CHECK(l2_from_host(f, n, 0, V6_ADDR, GW, reply, &rl, &ip, &il) == 1 && rl == 86);
    const uint8_t *h = reply + 14, *na = reply + 54;
    CHECK(memcmp(reply, HOST, 6) == 0 && memcmp(reply + 6, GW, 6) == 0 && get_be16(reply + 12) == 0x86dd);
    CHECK(h[0] == 0x60 && get_be16(h + 4) == 32 && h[6] == 58 && h[7] == 255);
    CHECK(memcmp(h + 8, V6_GW, 16) == 0 && memcmp(h + 24, LL, 16) == 0);
    CHECK(na[0] == 136 && na[4] == 0x60 && memcmp(na + 8, V6_GW, 16) == 0);
    CHECK(na[24] == 2 && na[25] == 1 && memcmp(na + 26, GW, 6) == 0);
    CHECK(icmp6_sum(h, na, 32) == 0);
    // 用全域位址做 NUD 也回
    n = frame6(f, V6_ADDR, V6_GW, 58, ns, 32);
    CHECK(l2_from_host(f, n, 0, V6_ADDR, GW, reply, &rl, &ip, &il) == 1);
    // 重複位址偵測（來源 ::）、問自己的位址：不回
    n = frame6(f, ANY, snm, 58, ns, 32);
    CHECK(l2_from_host(f, n, 0, V6_ADDR, GW, reply, &rl, &ip, &il) == 0);
    uint8_t ns_self[32];
    memcpy(ns_self, ns, 32);
    memcpy(ns_self + 8, V6_ADDR, 16);
    n = frame6(f, LL, snm, 58, ns_self, 32);
    CHECK(l2_from_host(f, n, 0, V6_ADDR, GW, reply, &rl, &ip, &il) == 0);
    // 沒有 IPv6 就全部不理
    n = frame6(f, LL, snm, 58, ns, 32);
    CHECK(l2_from_host(f, n, 0, NULL, GW, reply, &rl, &ip, &il) == 0);

    // 一般 IPv6 封包：送進行動網路
    uint8_t udp[12] = {0x12, 0x34, 0, 53, 0, 12, 0, 0, 'd', 't', '6', '!'};
    n = frame6(f, V6_ADDR, V6_DNS1, 17, udp, sizeof udp);
    CHECK(l2_from_host(f, n + 6, 0, V6_ADDR, GW, reply, &rl, &ip, &il) == 2 && ip == f + 14 && il == 52);
    // link-local 來源、多播目的地：不送
    n = frame6(f, LL, V6_DNS1, 17, udp, sizeof udp);
    CHECK(l2_from_host(f, n, 0, V6_ADDR, GW, reply, &rl, &ip, &il) == 0);
    n = frame6(f, V6_ADDR, snm, 17, udp, sizeof udp);
    CHECK(l2_from_host(f, n, 0, V6_ADDR, GW, reply, &rl, &ip, &il) == 0);
    // 長度欄位比實際長：丟掉
    n = frame6(f, V6_ADDR, V6_DNS1, 17, udp, sizeof udp);
    put_be16(f + 18, 500);
    CHECK(l2_from_host(f, n, 0, V6_ADDR, GW, reply, &rl, &ip, &il) == 0);

    // 收到的 IPv6 補上 0x86dd 的標頭
    uint8_t frame[128];
    n = frame6(f, V6_DNS1, V6_ADDR, 17, udp, sizeof udp);
    CHECK(l2_to_host(frame, sizeof frame, f + 14, 52, HOST, GW) == 66 && get_be16(frame + 12) == 0x86dd);
    CHECK(memcmp(frame, HOST, 6) == 0 && memcmp(frame + 14, f + 14, 52) == 0);
    CHECK(l2_to_host(frame, sizeof frame, f + 14, 30, HOST, GW) == 0);
}

static void test_sms_decode(void) {
    sms_pdu_t s;
    uint8_t b[256];
    int n;
    CHECK(sms_decode(MM_PDU1, sizeof MM_PDU1, &s) == 0);
    CHECK(!s.submit && strcmp(s.addr, "+16175927198") == 0 && s.time == 1298911850 && s.tz_min == -300);
    CHECK(s.dcs == SMS_DCS_GSM7 && s.total == 0 && !s.port && s.pid == 0);
    CHECK(strcmp(s.text, "Here's a longer message [{with some extended characters}] thrown in, such as £ and ΩΠΨ and §¿ "
                         "as well.") == 0);

    CHECK(sms_decode(MM_PDU2, sizeof MM_PDU2, &s) == 0);
    CHECK(strcmp(s.addr, "InternetSMS") == 0 && s.dcs == SMS_DCS_UCS2 && strcmp(s.text, "тест") == 0);
    CHECK(s.time == 1301412004 && s.tz_min == 240);

    CHECK(sms_decode(MM_PDU3, sizeof MM_PDU3, &s) == 0);
    CHECK(strcmp(s.addr, "+18005551212") == 0 && strcmp(s.text, "hellohello") == 0 && s.time == 1293885296 && s.tz_min == 0);
    memcpy(b, MM_PDU3, sizeof MM_PDU3);
    b[10] = 0x81;  // 國內號碼：沒有 +
    CHECK(sms_decode(b, sizeof MM_PDU3, &s) == 0 && strcmp(s.addr, "18005551212") == 0);
    b[10] = 0x91;
    b[18] = 0x04;  // 8-bit 資料（ModemManager 的 pdu3-8bit：10 octets，多一個 0xde）：沒有文字
    b[sizeof MM_PDU3] = 0xde;
    CHECK(sms_decode(b, sizeof MM_PDU3 + 1, &s) == 0 && s.dcs == SMS_DCS_8BIT && s.text[0] == 0);
    CHECK(sms_decode(b, sizeof MM_PDU3, &s) < 0);
    b[18] = 0xF4;
    CHECK(sms_decode(b, sizeof MM_PDU3 + 1, &s) == 0 && s.dcs == SMS_DCS_8BIT);
    b[18] = 0x00;
    b[17] = 0x40;  // silent SMS（type 0）
    CHECK(sms_decode(b, sizeof MM_PDU3, &s) == 0 && s.pid == 0x40);

    CHECK(sms_decode(MM_DCSF1, sizeof MM_DCSF1, &s) == 0);
    CHECK(strcmp(s.addr, "1800") == 0 && s.time == 1308913695 && s.tz_min == 120);
    CHECK(strcmp(s.text, "Info SFR - Confidentiel, à ne jamais transmettre -\r\nVoici votre nouveau mot de passe : sw2ced "
                         "pour gérer votre compte SFR sur www.sfr.fr ou par téléphone au 963") == 0);

    n = unhex(MM_UDHI, b);
    CHECK(sms_decode(b, n, &s) == 0 && strcmp(s.addr, "1002") == 0 && s.time == 1309383139);
    CHECK(s.ref == 0x0010 && s.total == 2 && s.seq == 1);
    CHECK(strcmp(s.text, "Welkom, bel om uw Voicemail te beluisteren naar +31612001233 (PrePay: *100*1233#). Voicemail "
                         "ontvangen is altijd gratis. Voor gebruik van mobiel interne") == 0);

    n = unhex(MM_MULTI1, b);
    CHECK(sms_decode(b, n, &s) == 0 && strcmp(s.addr, "+16175046925") == 0 && s.time == 1335398210 && s.tz_min == -240);
    CHECK(s.ref == 0x4C && s.total == 2 && s.seq == 1 && strcmp(s.text, MM_MULTI_TEXT1) == 0);
    b[32] = 0;  // seq 0 不合理：當單則
    CHECK(sms_decode(b, n, &s) == 0 && s.total == 0 && strcmp(s.text, MM_MULTI_TEXT1) == 0);
    b[27] = 200;  // UDHL 超出 user data
    CHECK(sms_decode(b, n, &s) < 0);
    n = unhex(MM_MULTI2, b);
    CHECK(sms_decode(b, n, &s) == 0 && s.ref == 0x4C && s.total == 2 && s.seq == 2 && s.time == 1335398211);
    CHECK(strcmp(s.text, MM_MULTI_TEXT2) == 0);

    n = unhex(MM_STORED_SUBMIT, b);
    CHECK(sms_decode(b, n, &s) == 0 && s.submit && strcmp(s.addr, "639337937") == 0 && s.time == 0);
    CHECK(strcmp(s.text, "你好你好你好你好你好你好你好你好你") == 0);
    n = unhex(MM_STATUS_REPORT, b);
    CHECK(sms_decode(b, n, &s) < 0);  // 狀態回報不處理

    CHECK(sms_decode(TW_PDU, sizeof TW_PDU, &s) == 0);
    CHECK(strcmp(s.addr, "0912345678") == 0 && s.time == 1791606896 && s.tz_min == 480 && s.dcs == SMS_DCS_UCS2);
    CHECK(strcmp(s.text, "測試😀") == 0);
    CHECK(sms_decode(TW_PDU, sizeof TW_PDU - 1, &s) < 0);  // user data 不夠長

    // ModemManager 的壞 PDU
    static const uint8_t bad1[] = {0x07, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0xf1, 0x04, 0x0b, 0x91, 0x81,
                                   0x00, 0x55, 0x15, 0x12, 0xf2, 0x00, 0x00, 0x11, 0x10, 0x10, 0x21, 0x43,
                                   0x65, 0x00, 0x0b, 0xe8, 0x32, 0x9b, 0xfd, 0x46, 0x97, 0xd9, 0xec, 0x37};
    static const uint8_t bad2[] = {0x00, 0x0A, 0xBF, 0x00};
    static const uint8_t bad3[] = {0x00, 0x1C, 0x01, 0x1C};
    static const uint8_t bad4[] = {0x00, 0x41, 0x00, 0x01, 0x01, 0x00, 0x01, 0x4B, 0x00, 0x00, 0x2E};
    static const uint8_t bad5[] = {0x00, 0xF1, 0x01, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00};
    CHECK(sms_decode(bad1, sizeof bad1, &s) < 0);
    CHECK(sms_decode(bad2, sizeof bad2, &s) < 0);
    CHECK(sms_decode(bad3, sizeof bad3, &s) < 0);
    CHECK(sms_decode(bad4, sizeof bad4, &s) < 0);
    CHECK(sms_decode(bad5, sizeof bad5, &s) < 0);
    CHECK(sms_decode(TW_PDU, 0, &s) < 0);
    b[0] = 0x0C;  // SMSC 長度超出
    CHECK(sms_decode(b, 5, &s) < 0);
}

static char *repeat(char *out, const char *unit, int times) {
    out[0] = 0;
    for (int i = 0; i < times; i++) strcat(out, unit);
    return out;
}

static void test_sms_encode(void) {
    uint8_t pdu[SMS_MAX_PARTS][SMS_PDU_MAX], b[256];
    int len[SMS_MAX_PARTS];
    static char t[4096], t2[4096];
    sms_pdu_t s;

    // ModemManager 的 PDU creator 期待值
    CHECK(sms_encode_submit("+15556661234", "This is really cool ΔΔΔΔΔ", 0, -1, pdu, len, 1) == 1);
    CHECK(len[0] == (int)sizeof MM_SUBMIT_GSM_NO_VP && memcmp(pdu[0], MM_SUBMIT_GSM_NO_VP, (size_t)len[0]) == 0);
    CHECK(sms_encode_submit("+15556661234", "This is really cool ΔΔΔΔΔ", 0, 0, pdu, len, 1) == 1);
    CHECK(len[0] == (int)sizeof MM_SUBMIT_GSM3 && memcmp(pdu[0], MM_SUBMIT_GSM3, (size_t)len[0]) == 0);
    CHECK(sms_encode_submit("+15555551234", "Hi there...Tue 17th Jan 2012 05:30.18 pm (GMT+1) ΔΔΔΔΔ", 0, 0, pdu, len, 1) == 1);
    CHECK(len[0] == (int)sizeof MM_SUBMIT_GSM && memcmp(pdu[0], MM_SUBMIT_GSM, (size_t)len[0]) == 0);
    CHECK(sms_encode_submit("+15555551234", "Да здравствует король, детка!", 0, 0, pdu, len, 1) == 1);
    CHECK(len[0] == (int)sizeof MM_SUBMIT_UCS2 && memcmp(pdu[0], MM_SUBMIT_UCS2, (size_t)len[0]) == 0);

    // 分段：兩段文字接起來用同一個 reference 編，user data（UDH + 補位 + 7-bit）要跟真實收到的那兩段一樣。
    // 唯一的差別是 UDH 後面補到 septet 邊界的那個位元：收方不看，那支手機填 1，我們填 0。
    snprintf(t, sizeof t, "%s%s", MM_MULTI_TEXT1, MM_MULTI_TEXT2);
    CHECK(sms_encode_submit("+16175046925", t, 0x4C, -1, pdu, len, SMS_MAX_PARTS) == 2);
    int n = unhex(MM_MULTI1, b);
    CHECK(pdu[0][1] == 0x41 && pdu[0][13] == 160 && len[0] == 14 + 140 && n == 27 + 140);
    CHECK(memcmp(pdu[0] + 14, b + 27, 6) == 0 && (pdu[0][20] | 1) == b[33] && memcmp(pdu[0] + 21, b + 34, 133) == 0);
    n = unhex(MM_MULTI2, b);
    CHECK(pdu[1][13] == 50 && len[1] == 14 + 44 && n == 27 + 44);
    CHECK(memcmp(pdu[1] + 14, b + 27, 6) == 0 && (pdu[1][20] | 1) == b[33] && memcmp(pdu[1] + 21, b + 34, 37) == 0);

    // 國內號碼
    CHECK(sms_encode_submit("0912345678", "hi", 0, -1, pdu, len, 1) == 1);
    CHECK(memcmp(pdu[0] + 3, (const uint8_t[]){0x0A, 0x81, 0x90, 0x21, 0x43, 0x65, 0x87}, 7) == 0);

    // 中文分段：100 字 → 67 + 33，解回來接起來一樣
    repeat(t, "中", 100);
    CHECK(sms_encode_submit("+886912345678", t, 7, -1, pdu, len, SMS_MAX_PARTS) == 2);
    CHECK(sms_decode(pdu[0], len[0], &s) == 0 && s.submit && s.dcs == SMS_DCS_UCS2 && s.ref == 7 && s.total == 2 &&
          s.seq == 1);
    CHECK(strcmp(s.addr, "+886912345678") == 0 && strcmp(s.text, repeat(t2, "中", 67)) == 0 && pdu[0][13] == 140);
    CHECK(sms_decode(pdu[1], len[1], &s) == 0 && s.seq == 2 && strcmp(s.text, repeat(t2, "中", 33)) == 0);

    // emoji 剛好跨在分段點：surrogate pair 不拆開，整個移到下一段
    repeat(t, "中", 66);
    strcat(t, "😀");
    strcat(t, repeat(t2, "中", 10));
    CHECK(sms_encode_submit("+886912345678", t, 8, -1, pdu, len, SMS_MAX_PARTS) == 2);
    CHECK(sms_decode(pdu[0], len[0], &s) == 0 && strcmp(s.text, repeat(t2, "中", 66)) == 0);
    CHECK(sms_decode(pdu[1], len[1], &s) == 0 && strncmp(s.text, "😀", 4) == 0);

    // GSM 擴充字元（兩個 septet）剛好跨在分段點：escape 跟後面那個字一起移到下一段
    repeat(t, "a", 152);
    strcat(t, "€");
    strcat(t, repeat(t2, "b", 20));
    CHECK(sms_encode_submit("0912345678", t, 9, -1, pdu, len, SMS_MAX_PARTS) == 2);
    CHECK(sms_decode(pdu[0], len[0], &s) == 0 && s.dcs == SMS_DCS_GSM7 && strcmp(s.text, repeat(t2, "a", 152)) == 0);
    CHECK(sms_decode(pdu[1], len[1], &s) == 0 && strncmp(s.text, "€bbb", 6) == 0 && strlen(s.text) == 3 + 20);

    bool ucs2;
    CHECK(sms_count_parts("hello", &ucs2) == 1 && !ucs2);
    CHECK(sms_count_parts(repeat(t, "a", 160), &ucs2) == 1 && !ucs2);
    CHECK(sms_count_parts(repeat(t, "a", 161), &ucs2) == 2);
    CHECK(sms_count_parts(repeat(t, "a", 306), &ucs2) == 2);
    CHECK(sms_count_parts(repeat(t, "a", 307), &ucs2) == 3);
    CHECK(sms_count_parts(repeat(t, "€", 80), &ucs2) == 1 && !ucs2);
    CHECK(sms_count_parts(repeat(t, "€", 81), &ucs2) == 2);
    CHECK(sms_count_parts(repeat(t, "中", 70), &ucs2) == 1 && ucs2);
    CHECK(sms_count_parts(repeat(t, "中", 71), &ucs2) == 2 && ucs2);
    CHECK(sms_count_parts("`", &ucs2) == 1 && ucs2);  // 反引號不在 GSM 字母表
    CHECK(sms_count_parts("", &ucs2) < 0);
    CHECK(sms_count_parts("\xff", &ucs2) < 0);
    CHECK(sms_count_parts("\xed\xa0\x80", &ucs2) < 0);  // UTF-8 編出來的 surrogate

    CHECK(sms_encode_submit("+886912345678", repeat(t, "中", 670), 1, -1, pdu, len, SMS_MAX_PARTS) == 10);
    CHECK(sms_encode_submit("+886912345678", repeat(t, "中", 671), 1, -1, pdu, len, SMS_MAX_PARTS) < 0);
    CHECK(sms_encode_submit("+886912345678", repeat(t, "中", 71), 1, -1, pdu, len, 1) < 0);
    CHECK(sms_encode_submit("12", "hi", 0, -1, pdu, len, 1) < 0);
    CHECK(sms_encode_submit("09-1234-5678", "hi", 0, -1, pdu, len, 1) < 0);
    CHECK(sms_encode_submit("+", "hi", 0, -1, pdu, len, 1) < 0);
    CHECK(sms_encode_submit("0912345678", "", 0, -1, pdu, len, 1) < 0);
    CHECK(sms_valid_number("0912345678") && sms_valid_number("+886912345678") && sms_valid_number("1922"));
    CHECK(!sms_valid_number("") && !sms_valid_number("+12") && !sms_valid_number("123456789012345678901"));
}

static void test_sms_mbim(void) {
    uint8_t p[256], b[512];
    mbim_msg_t m;
    CHECK(mbim_info_sms_read(p, MBIM_SMS_FLAG_INDEX, 3) == 12 && get_le32(p) == 0 && get_le32(p + 4) == 1 &&
          get_le32(p + 8) == 3);
    CHECK(mbim_info_sms_delete(p, MBIM_SMS_FLAG_INDEX, 3) == 8 && get_le32(p) == 1 && get_le32(p + 4) == 3);
    memset(p, 0xEE, sizeof p);
    CHECK(mbim_info_sms_send(p, sizeof p, TW_PDU, sizeof TW_PDU) == 12 + 28);
    CHECK(get_le32(p) == 0 && get_le32(p + 4) == 8 && get_le32(p + 8) == sizeof TW_PDU);
    CHECK(memcmp(p + 12, TW_PDU, sizeof TW_PDU) == 0 && p[39] == 0);
    CHECK(mbim_info_sms_send(p, 39, TW_PDU, sizeof TW_PDU) < 0);

    mbim_sms_config_t c;
    int n = fx_sms_config_done(b);
    CHECK(mbim_parse(b, n, &m) == 0 && m.type == MBIM_COMMAND_DONE && m.cid == MBIM_CID_SMS_CONFIGURATION);
    CHECK(memcmp(m.uuid, MBIM_UUID_SMS, 16) == 0 && m.info_len == 52);
    CHECK(mbim_parse_sms_config(m.info, m.info_len, &c) == 0 && c.storage_state == 1 && c.format == 0);
    CHECK(c.max_messages == 40 && strcmp(c.smsc, "+886935874443") == 0);

    uint32_t flag = 0, idx = 0;
    n = fx_sms_store_indication(b);
    CHECK(mbim_parse(b, n, &m) == 0 && m.type == MBIM_INDICATE_STATUS && m.cid == MBIM_CID_SMS_MESSAGE_STORE_STATUS);
    CHECK(mbim_parse_sms_store_status(m.info, m.info_len, &flag, &idx) == 0 && flag == MBIM_SMS_STORE_NEW_MESSAGE &&
          idx == 3);

    mbim_sms_record_t r[4];
    sms_pdu_t s;
    n = fx_sms_read_done(b);
    CHECK(mbim_parse(b, n, &m) == 0 && m.cid == MBIM_CID_SMS_READ);
    CHECK(mbim_parse_sms_read(m.info, m.info_len, r, 4) == 2);
    CHECK(r[0].index == 3 && r[0].status == MBIM_SMS_STATUS_NEW && r[0].len == sizeof MM_PDU3);
    CHECK(sms_decode(r[0].pdu, (int)r[0].len, &s) == 0 && strcmp(s.text, "hellohello") == 0);
    CHECK(r[1].index == 4 && r[1].status == MBIM_SMS_STATUS_OLD && r[1].len == sizeof TW_PDU);
    CHECK(sms_decode(r[1].pdu, (int)r[1].len, &s) == 0 && strcmp(s.text, "測試😀") == 0);
    CHECK(mbim_parse_sms_read(m.info, m.info_len, r, 1) == 1);
    uint8_t info[160];
    memcpy(info, m.info, m.info_len);
    put_le32(info + 16, 150);  // 第二筆的 offset 指到外面：跳過，第一筆照收
    CHECK(mbim_parse_sms_read(info, m.info_len, r, 4) == 1 && r[0].index == 3);
    memcpy(info, m.info, m.info_len);
    put_le32(info + 24 + 12, 200);  // 第一筆的 PDU 超出紀錄
    CHECK(mbim_parse_sms_read(info, m.info_len, r, 4) == 1 && r[0].index == 4);
    memcpy(info, m.info, m.info_len);
    put_le32(info + 4, 1000000);  // 筆數灌爆
    CHECK(mbim_parse_sms_read(info, m.info_len, r, 4) < 0);
    put_le32(info, 1);  // CDMA 格式不收
    put_le32(info + 4, 2);
    CHECK(mbim_parse_sms_read(info, m.info_len, r, 4) < 0);
    CHECK(mbim_parse_sms_read(info, 7, r, 4) < 0);

    uint32_t ref = 0;
    n = fx_sms_send_done(b);
    CHECK(mbim_parse(b, n, &m) == 0 && m.cid == MBIM_CID_SMS_SEND && mbim_parse_sms_send(m.info, m.info_len, &ref) == 0 &&
          ref == 7);
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
    test_pin();
    test_signal_and_names();
    test_ip6_config();
    test_nd();
    test_sms_decode();
    test_sms_encode();
    test_sms_mbim();
    printf("mbim: %d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
