#include "mbim.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dhcp.h"

// UUID 在線上的位元組順序就是字面上的順序。
const uint8_t MBIM_UUID_BASIC_CONNECT[16] = {0xa2, 0x89, 0xcc, 0x33, 0xbc, 0xbb, 0x8b, 0x4f,
                                             0xb6, 0xb0, 0x13, 0x3e, 0xc2, 0xaa, 0xe6, 0xdf};
const uint8_t MBIM_CONTEXT_INTERNET[16] = {0x7e, 0x5e, 0x2a, 0x7e, 0x4e, 0x6f, 0x72, 0x72,
                                           0x73, 0x6b, 0x65, 0x6e, 0x7e, 0x5e, 0x2a, 0x7e};

static uint16_t get_le16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static void put_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

// ---------- 訊息組裝 ----------

static void put_header(uint8_t *p, uint32_t type, uint32_t len, uint32_t tid) {
    put_le32(p, type);
    put_le32(p + 4, len);
    put_le32(p + 8, tid);
}

int mbim_build_open(uint8_t *buf, int cap, uint32_t tid, uint32_t max_ctrl) {
    if (cap < 16) return -1;
    put_header(buf, MBIM_OPEN_MSG, 16, tid);
    put_le32(buf + 12, max_ctrl);
    return 16;
}

int mbim_build_close(uint8_t *buf, int cap, uint32_t tid) {
    if (cap < 12) return -1;
    put_header(buf, MBIM_CLOSE_MSG, 12, tid);
    return 12;
}

int mbim_build_command(uint8_t *buf, int cap, uint32_t tid, const uint8_t uuid[16], uint32_t cid, bool set,
                       const uint8_t *info, int info_len) {
    int len = 48 + info_len;
    if (info_len < 0 || len > cap) return -1;
    put_header(buf, MBIM_COMMAND_MSG, (uint32_t)len, tid);
    put_le32(buf + 12, 1);  // TotalFragments
    put_le32(buf + 16, 0);  // CurrentFragment
    memcpy(buf + 20, uuid, 16);
    put_le32(buf + 36, cid);
    put_le32(buf + 40, set ? 1 : 0);
    put_le32(buf + 44, (uint32_t)info_len);
    if (info_len) memcpy(buf + 48, info, (size_t)info_len);
    return len;
}

int mbim_info_radio_set(uint8_t *p, bool on) {
    put_le32(p, on ? 1 : 0);
    return 4;
}

int mbim_info_packet_service_set(uint8_t *p, bool attach) {
    put_le32(p, attach ? 0 : 1);  // 0 attach、1 detach
    return 4;
}

// MBIM_SET_CONNECT：固定欄位 60 bytes，後面接 UTF-16LE 字串，每個字串補到 4 的倍數。
// 空字串的 offset 與 size 都是 0。
int mbim_info_connect_set(uint8_t *p, int cap, uint32_t session, bool activate, const char *apn, uint32_t ip_type) {
    size_t n = apn ? strlen(apn) : 0;
    int len = 60 + (int)((n * 2 + 3) & ~(size_t)3);
    if (len > cap) return -1;
    memset(p, 0, (size_t)len);
    put_le32(p, session);
    put_le32(p + 4, activate ? 1 : 0);
    if (n) {
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)apn[i];
            if (c < 0x20 || c > 0x7e) return -1;  // APN 只會是 ASCII
            p[60 + 2 * i] = c;
        }
        put_le32(p + 8, 60);
        put_le32(p + 12, (uint32_t)(n * 2));
    }
    // UserName、Password 留空；Compression 0、AuthProtocol 0（none）
    put_le32(p + 40, ip_type);
    memcpy(p + 44, MBIM_CONTEXT_INTERNET, 16);
    return len;
}

// 查詢時照 libmbim 的做法帶完整的 MBIM_CONNECT_INFO，只有 SessionId 有意義。
int mbim_info_connect_query(uint8_t *p, int cap, uint32_t session) {
    if (cap < 36) return -1;
    memset(p, 0, 36);
    put_le32(p, session);
    memcpy(p + 16, MBIM_CONTEXT_INTERNET, 16);
    return 36;
}

int mbim_info_ip_config_query(uint8_t *p, int cap, uint32_t session) {
    if (cap < 60) return -1;
    memset(p, 0, 60);
    put_le32(p, session);
    return 60;
}

// MBIM_SET_PIN：PinType, PinOperation, Pin(offset,size), NewPin(offset,size)，後面接 UTF-16LE 的 PIN。
int mbim_info_pin_enter(uint8_t *p, int cap, const char *pin) {
    size_t n = pin ? strlen(pin) : 0;
    if (n < 4 || n > 8) return -1;
    for (size_t i = 0; i < n; i++)
        if (pin[i] < '0' || pin[i] > '9') return -1;
    int len = 24 + (int)((n * 2 + 3) & ~(size_t)3);
    if (len > cap) return -1;
    memset(p, 0, (size_t)len);
    put_le32(p, MBIM_PIN_TYPE_PIN1);
    put_le32(p + 4, 0);  // enter
    put_le32(p + 8, 24);
    put_le32(p + 12, (uint32_t)(n * 2));
    for (size_t i = 0; i < n; i++) p[24 + 2 * i] = (uint8_t)pin[i];
    return len;
}

// ---------- 訊息解析 ----------

int mbim_parse(const uint8_t *buf, int len, mbim_msg_t *m) {
    memset(m, 0, sizeof *m);
    if (len < 12) return -1;
    m->type = get_le32(buf);
    uint32_t mlen = get_le32(buf + 4);
    m->tid = get_le32(buf + 8);
    if (mlen < 12 || mlen > (uint32_t)len) return -1;
    switch (m->type) {
        case MBIM_OPEN_DONE:
        case MBIM_CLOSE_DONE:
        case MBIM_FUNCTION_ERROR:
            if (mlen < 16) return -1;
            m->status = get_le32(buf + 12);
            return 0;
        case MBIM_COMMAND_DONE:
            if (mlen < 48) return -1;
            memcpy(m->uuid, buf + 20, 16);
            m->cid = get_le32(buf + 36);
            m->status = get_le32(buf + 40);
            m->info_len = get_le32(buf + 44);
            if (m->info_len > mlen - 48) return -1;
            m->info = buf + 48;
            return 0;
        case MBIM_INDICATE_STATUS:
            if (mlen < 44) return -1;
            memcpy(m->uuid, buf + 20, 16);
            m->cid = get_le32(buf + 36);
            m->info_len = get_le32(buf + 40);
            if (m->info_len > mlen - 44) return -1;
            m->info = buf + 44;
            return 0;
        default:
            return 0;
    }
}

static bool has_fragments(uint32_t type) {
    return type == MBIM_COMMAND_MSG || type == MBIM_COMMAND_DONE || type == MBIM_INDICATE_STATUS;
}

int mbim_reasm_feed(mbim_reasm_t *r, const uint8_t *f, int len) {
    if (len < 12) return -1;
    uint32_t type = get_le32(f), flen = get_le32(f + 4), tid = get_le32(f + 8);
    if (flen < 12 || flen > (uint32_t)len || (int)flen > r->cap) return -1;
    if (!has_fragments(type)) {
        memcpy(r->buf, f, flen);
        r->len = (int)flen;
        r->total = 0;
        return 1;
    }
    if (flen < 20) return -1;
    uint32_t total = get_le32(f + 12), cur = get_le32(f + 16);
    if (total == 0 || cur >= total) return -1;
    if (cur == 0) {
        memcpy(r->buf, f, flen);
        r->len = (int)flen;
        r->tid = tid;
        r->type = type;
        r->total = total;
        r->next = 1;
    } else {
        // 後續片段只有標頭加上接續的資料
        if (r->total != total || r->next != cur || r->tid != tid || r->type != type || r->len + (int)flen - 20 > r->cap) {
            r->total = 0;
            return -1;
        }
        memcpy(r->buf + r->len, f + 20, flen - 20);
        r->len += (int)flen - 20;
        r->next++;
    }
    if (r->next < r->total) return 0;
    put_le32(r->buf + 4, (uint32_t)r->len);
    put_le32(r->buf + 12, 1);
    put_le32(r->buf + 16, 0);
    r->total = 0;
    return 1;
}

int mbim_parse_subscriber_ready(const uint8_t *p, uint32_t n, uint32_t *ready_state) {
    if (n < 4) return -1;
    *ready_state = get_le32(p);
    return 0;
}

int mbim_parse_radio_state(const uint8_t *p, uint32_t n, uint32_t *hw, uint32_t *sw) {
    if (n < 8) return -1;
    *hw = get_le32(p);
    *sw = get_le32(p + 4);
    return 0;
}

int mbim_parse_register_state(const uint8_t *p, uint32_t n, uint32_t *nw_error, uint32_t *state) {
    if (n < 8) return -1;
    *nw_error = get_le32(p);
    *state = get_le32(p + 4);
    return 0;
}

int mbim_parse_packet_service(const uint8_t *p, uint32_t n, uint32_t *nw_error, uint32_t *state) {
    if (n < 8) return -1;
    *nw_error = get_le32(p);
    *state = get_le32(p + 4);
    return 0;
}

int mbim_parse_connect(const uint8_t *p, uint32_t n, mbim_connect_info_t *c) {
    if (n < 36) return -1;
    c->session = get_le32(p);
    c->activation = get_le32(p + 4);
    c->voice = get_le32(p + 8);
    c->ip_type = get_le32(p + 12);
    memcpy(c->context, p + 16, 16);
    c->nw_error = get_le32(p + 32);
    return 0;
}

// MBIM_IP_CONFIGURATION_INFO：固定欄位 60 bytes，位址、閘道、DNS 用 offset 指到後面的資料區。
int mbim_parse_ip_config(const uint8_t *p, uint32_t n, mbim_ipv4_t *out) {
    memset(out, 0, sizeof *out);
    if (n < 60) return -1;
    uint32_t avail = get_le32(p + 4);
    uint32_t naddr = get_le32(p + 12), addr_off = get_le32(p + 16);
    uint32_t gw_off = get_le32(p + 28);
    uint32_t ndns = get_le32(p + 36), dns_off = get_le32(p + 40);
    uint32_t mtu = get_le32(p + 52);
    if ((avail & 1) && naddr) {
        // 每筆是 OnLinkPrefixLength(4) + IPv4Address(4)，用第一筆
        if (addr_off < 60 || addr_off > n || n - addr_off < 8) return -1;
        out->prefix = (int)get_le32(p + addr_off);
        memcpy(&out->ip, p + addr_off + 4, 4);
    }
    if (avail & 2) {
        if (gw_off < 60 || gw_off > n || n - gw_off < 4) return -1;
        memcpy(&out->gw, p + gw_off, 4);
    }
    if ((avail & 4) && ndns) {
        if (dns_off < 60 || dns_off > n || (n - dns_off) / 4 < ndns) return -1;
        for (uint32_t i = 0; i < ndns && out->ndns < 4; i++) memcpy(&out->dns[out->ndns++], p + dns_off + 4 * i, 4);
    }
    if (avail & 8) out->mtu = mtu;
    return out->ip ? 0 : -1;
}

int mbim_parse_ip6_config(const uint8_t *p, uint32_t n, mbim_ipv6_t *out) {
    memset(out, 0, sizeof *out);
    if (n < 60) return -1;
    uint32_t avail = get_le32(p + 8);
    uint32_t naddr = get_le32(p + 20), addr_off = get_le32(p + 24);
    uint32_t gw_off = get_le32(p + 32);
    uint32_t ndns = get_le32(p + 44), dns_off = get_le32(p + 48);
    if (!(avail & 1) || !naddr) return -1;
    // 每筆是 OnLinkPrefixLength(4) + IPv6Address(16)，用第一筆
    if (addr_off < 60 || addr_off > n || n - addr_off < 20) return -1;
    out->prefix = (int)get_le32(p + addr_off);
    memcpy(out->addr, p + addr_off + 4, 16);
    if (avail & 2) {
        if (gw_off < 60 || gw_off > n || n - gw_off < 16) return -1;
        memcpy(out->gw, p + gw_off, 16);
        out->has_gw = true;
    }
    if ((avail & 4) && ndns) {
        if (dns_off < 60 || dns_off > n || (n - dns_off) / 16 < ndns) return -1;
        for (uint32_t i = 0; i < ndns && out->ndns < 2; i++) memcpy(out->dns[out->ndns++], p + dns_off + 16 * i, 16);
    }
    if (avail & 8) out->mtu = get_le32(p + 56);
    if (out->prefix <= 0 || out->prefix > 128) out->prefix = 64;
    return 0;
}

int mbim_parse_pin_info(const uint8_t *p, uint32_t n, uint32_t *type, uint32_t *state, uint32_t *attempts) {
    if (n < 12) return -1;
    *type = get_le32(p);
    *state = get_le32(p + 4);
    *attempts = get_le32(p + 8);
    return 0;
}

int mbim_parse_signal(const uint8_t *p, uint32_t n, uint32_t *rssi, uint32_t *error_rate) {
    if (n < 8) return -1;
    *rssi = get_le32(p);
    *error_rate = get_le32(p + 4);
    return 0;
}

int mbim_signal_bars(uint32_t rssi) {
    if (rssi > 31) return -1;
    if (rssi >= 20) return 4;  // -73 dBm 以上
    if (rssi >= 15) return 3;  // -83
    if (rssi >= 10) return 2;  // -93
    if (rssi >= 5) return 1;   // -103
    return 0;
}

// UTF-16LE 字串（offset、size 指向 p 裡面）轉 UTF-8。
static int utf16_to_utf8(const uint8_t *p, uint32_t n, uint32_t off, uint32_t size, char *out, int cap) {
    if (cap < 1) return -1;
    out[0] = '\0';
    if (!size) return 0;
    if (off > n || size > n - off || (size & 1)) return -1;
    int o = 0;
    for (uint32_t i = 0; i + 1 < size; i += 2) {
        uint32_t c = get_le16(p + off + i);
        if (c >= 0xD800 && c < 0xDC00 && i + 3 < size) {
            uint32_t lo = get_le16(p + off + i + 2);
            if (lo >= 0xDC00 && lo < 0xE000) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            }
        }
        if (!c) break;
        uint8_t b[4];
        int k = c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
        if (k == 1) {
            b[0] = (uint8_t)c;
        } else {
            static const uint8_t lead[5] = {0, 0, 0xC0, 0xE0, 0xF0};
            for (int j = k - 1; j > 0; j--) {
                b[j] = (uint8_t)(0x80 | (c & 0x3F));
                c >>= 6;
            }
            b[0] = (uint8_t)(lead[k] | c);
        }
        if (o + k >= cap) break;
        memcpy(out + o, b, (size_t)k);
        o += k;
    }
    out[o] = '\0';
    return o;
}

// MBIM_REGISTRATION_STATE_INFO：..., ProviderId(20/24), ProviderName(28/32), RoamingText(36/40), RegistrationFlag(44)
int mbim_parse_provider_name(const uint8_t *p, uint32_t n, char *out, int cap) {
    if (n < 48) return -1;
    return utf16_to_utf8(p, n, get_le32(p + 28), get_le32(p + 32), out, cap) < 0 ? -1 : 0;
}

int mbim_parse_data_class(const uint8_t *p, uint32_t n, uint32_t *cls) {
    if (n < 12) return -1;
    *cls = get_le32(p + 8);
    return 0;
}

// 0x40、0x80 是 Microsoft 擴充定義的 5G NSA、5G SA
const char *mbim_data_class_name(uint32_t cls) {
    if (cls & 0x80) return "5G SA";
    if (cls & 0x40) return "5G";
    if (cls & 0x20) return "LTE";
    if (cls & 0x1C) return "3G";
    if (cls & 0x03) return "2G";
    return "";
}

uint32_t mbim_netmask(uint32_t ip, uint32_t gw, int prefix) {
    if (prefix <= 0 || prefix > 32) prefix = 32;
    uint32_t a = ntohl(ip), b = ntohl(gw);
    if (b && b != a) {
        while (prefix > 0 && ((a ^ b) >> (32 - prefix))) prefix--;
        if (prefix > 30) prefix = 30;  // 至少要留得下自己和閘道兩個位址
    }
    return htonl(prefix ? 0xFFFFFFFFu << (32 - prefix) : 0);
}

const char *mbim_status_name(uint32_t status) {
    static const char *names[] = {"success", "busy", "failure", "sim-not-inserted", "bad-sim", "pin-required",
                                  "pin-disabled", "not-registered", "providers-not-found", "no-device-support",
                                  "provider-not-visible", "data-class-not-available", "packet-service-detached",
                                  "max-activated-contexts", "not-initialized", "voice-call-in-progress",
                                  "context-not-activated", "service-not-activated", "invalid-access-string",
                                  "invalid-user-name-pwd", "radio-power-off"};
    return status < sizeof names / sizeof names[0] ? names[status] : "other";
}

// ---------- NTB16 ----------

#define NTH16_SIG 0x484D434Eu  // "NCMH"
#define NDP16_IPS 0x00535049u  // "IPS" + session 0

int ntb_parse_params(const uint8_t *p, int len, ntb_params_t *o) {
    if (len < 28) return -1;
    o->formats = get_le16(p + 2);
    o->in_max = get_le32(p + 4);
    o->out_max = get_le32(p + 16);
    o->out_divisor = get_le16(p + 20);
    o->out_remainder = get_le16(p + 22);
    o->out_align = get_le16(p + 24);
    o->out_max_datagrams = get_le16(p + 26);
    if (!(o->formats & 1) || o->out_max < 12 + 16 + 20) return -1;
    if (!o->out_divisor) o->out_divisor = 4;
    if (!o->out_align) o->out_align = 4;
    return 0;
}

static int align_up(int v, int a) {
    return a > 1 ? (v + a - 1) / a * a : v;
}

// 一個 NTB 放一個封包：NTH16(12) → NDP16(16，對齊 wNdpOutAlignment) → 封包（offset 符合 divisor/remainder）。
int ntb16_build(uint8_t *buf, int cap, uint16_t seq, const ntb_params_t *np, const uint8_t *dgram, int dlen) {
    int ndp = align_up(12, np->out_align);
    int off = ndp + 16;
    int div = np->out_divisor, rem = np->out_remainder % (div ? div : 1);
    if (div > 1) off = align_up(off - rem, div) + rem;
    int total = off + dlen;
    if (dlen <= 0 || total > cap || (uint32_t)total > np->out_max || total > 0xFFFF) return -1;
    memset(buf, 0, (size_t)off);
    put_le32(buf, NTH16_SIG);
    put_le16(buf + 4, 12);
    put_le16(buf + 6, seq);
    put_le16(buf + 8, (uint16_t)total);
    put_le16(buf + 10, (uint16_t)ndp);
    put_le32(buf + ndp, NDP16_IPS);
    put_le16(buf + ndp + 4, 16);  // 8 + 一筆 + 結尾的 (0,0)
    put_le16(buf + ndp + 6, 0);
    put_le16(buf + ndp + 8, (uint16_t)off);
    put_le16(buf + ndp + 10, (uint16_t)dlen);
    memcpy(buf + off, dgram, (size_t)dlen);
    return total;
}

int ntb16_parse(const uint8_t *buf, int len, ntb_dgram_cb cb, void *ctx) {
    if (len < 12 || get_le32(buf) != NTH16_SIG || get_le16(buf + 4) != 12) return -1;
    int block = get_le16(buf + 8);
    if (block == 0 || block > len) block = len;
    int ndp = get_le16(buf + 10);
    int count = 0;
    for (int hops = 0; ndp && hops < 32; hops++) {
        if (ndp < 12 || ndp + 16 > block || (ndp & 3)) return count ? count : -1;
        uint32_t sig = get_le32(buf + ndp);
        int ndp_len = get_le16(buf + ndp + 4);
        if (ndp_len < 16 || ndp + ndp_len > block) return count ? count : -1;
        if (sig == NDP16_IPS) {
            for (int e = ndp + 8; e + 4 <= ndp + ndp_len; e += 4) {
                int idx = get_le16(buf + e), dl = get_le16(buf + e + 2);
                if (!idx || !dl) break;
                if (idx < 12 || idx + dl > block) continue;
                cb(ctx, buf + idx, dl);
                count++;
            }
        }
        // 其他 session 或 DSS 的 NDP 略過
        ndp = get_le16(buf + ndp + 6);
    }
    return count;
}

// ---------- 系統端的乙太網路 ----------

// ICMPv6 checksum：IPv6 pseudo header（來源、目的、長度、next header 58）加上整個 ICMPv6 訊息。
static uint16_t icmp6_checksum(const uint8_t src[16], const uint8_t dst[16], const uint8_t *msg, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < 16; i += 2) sum += (uint32_t)get_be16(src + i) + get_be16(dst + i);
    sum += (uint32_t)len + 58;
    return ip_checksum(msg, len, sum);
}

static bool ip6_unspecified(const uint8_t a[16]) {
    static const uint8_t zero[16];
    return memcmp(a, zero, 16) == 0;
}

// IPv6：替這條線上的鄰居（閘道和子網路裡其他位址）回 Neighbor Advertisement，其他要送出去的交給呼叫的人。
static int l2_from_host6(const uint8_t *f, int len, const uint8_t *host_ip6, const uint8_t gw_mac[6], uint8_t *reply,
                         int *reply_len, const uint8_t **ip, int *ip_len) {
    if (!host_ip6 || len < 14 + 40) return 0;
    const uint8_t *h = f + 14;
    if ((h[0] >> 4) != 6) return 0;
    int plen = get_be16(h + 4);
    if (plen > len - 14 - 40) return 0;
    const uint8_t *src = h + 8, *dst = h + 24;
    const uint8_t *icmp = h + 40;
    if (h[6] == 58 && plen >= 24 && icmp[0] == 135) {
        const uint8_t *target = icmp + 8;
        // 系統自己的重複位址偵測（來源是 ::）、問自己的位址：不能回，否則會被當成位址衝突
        if (ip6_unspecified(src) || memcmp(target, host_ip6, 16) == 0) return 0;
        uint8_t *e = reply, *r = reply + 14, *na = reply + 14 + 40;
        memcpy(e, f + 6, 6);  // 回給發問的人
        memcpy(e + 6, gw_mac, 6);
        put_be16(e + 12, 0x86DD);
        memset(r, 0, 40);
        r[0] = 0x60;
        put_be16(r + 4, 32);
        r[6] = 58;
        r[7] = 255;
        memcpy(r + 8, target, 16);
        memcpy(r + 24, src, 16);
        memset(na, 0, 32);
        na[0] = 136;
        na[4] = 0x60;  // Solicited + Override（這條線上只有我們，路由器旗標交給 configd 的設定）
        memcpy(na + 8, target, 16);
        na[24] = 2;  // Target Link-Layer Address
        na[25] = 1;
        memcpy(na + 26, gw_mac, 6);
        put_be16(na + 2, icmp6_checksum(r + 8, r + 24, na, 32));
        *reply_len = 14 + 40 + 32;
        return 1;
    }
    // link-local 來源、多播目的地（ND、MLD、mDNS）只屬於這條線，不送進行動網路
    if ((src[0] == 0xfe && (src[1] & 0xc0) == 0x80) || dst[0] == 0xff || ip6_unspecified(src)) return 0;
    *ip = h;
    *ip_len = 40 + plen;
    return 2;
}

int l2_from_host(const uint8_t *f, int len, uint32_t host_ip, const uint8_t *host_ip6, const uint8_t gw_mac[6],
                 uint8_t *reply, int *reply_len, const uint8_t **ip, int *ip_len) {
    if (len < 14) return 0;
    uint16_t type = get_be16(f + 12);
    if (type == 0x86DD) return l2_from_host6(f, len, host_ip6, gw_mac, reply, reply_len, ip, ip_len);
    if (type == 0x0800) {
        if (len < 14 + 20) return 0;
        int total = get_be16(f + 16);
        if (total < 20 || total > len - 14) return 0;
        *ip = f + 14;
        *ip_len = total;  // 去掉乙太網路最短長度補的 0
        return 2;
    }
    if (type != 0x0806 || len < 14 + 28) return 0;
    const uint8_t *a = f + 14;
    if (get_be16(a) != 1 || get_be16(a + 2) != 0x0800 || a[4] != 6 || a[5] != 4 || get_be16(a + 6) != 1) return 0;
    uint32_t spa, tpa;
    memcpy(&spa, a + 14, 4);
    memcpy(&tpa, a + 24, 4);
    // 系統自己檢查 IP 重複（sender 0.0.0.0）或宣告自己（sender = target）時不能回，否則會被當成位址衝突
    if (!spa || spa == tpa || tpa == host_ip) return 0;
    // 這條線上只有數據機：問誰都回同一個假的閘道 MAC
    memcpy(reply, a + 8, 6);  // 目的地：發問的人
    memcpy(reply + 6, gw_mac, 6);
    put_be16(reply + 12, 0x0806);
    uint8_t *r = reply + 14;
    put_be16(r, 1);
    put_be16(r + 2, 0x0800);
    r[4] = 6;
    r[5] = 4;
    put_be16(r + 6, 2);
    memcpy(r + 8, gw_mac, 6);
    memcpy(r + 14, &tpa, 4);
    memcpy(r + 18, a + 8, 6);
    memcpy(r + 24, &spa, 4);
    *reply_len = 14 + 28;
    return 1;
}

int l2_to_host(uint8_t *frame, int cap, const uint8_t *ip, int len, const uint8_t host_mac[6], const uint8_t gw_mac[6]) {
    int v = len >= 1 ? ip[0] >> 4 : 0;
    if ((v == 4 && len < 20) || (v == 6 && len < 40) || (v != 4 && v != 6) || len + 14 > cap) return 0;
    memcpy(frame, host_mac, 6);
    memcpy(frame + 6, gw_mac, 6);
    put_be16(frame + 12, v == 6 ? 0x86DD : 0x0800);
    memcpy(frame + 14, ip, (size_t)len);
    return len + 14;
}

#define ICMP_PAYLOAD 16

int icmp_echo_build(uint8_t *b, int cap, uint32_t src, uint32_t dst, uint16_t id, uint16_t seq) {
    int len = 20 + 8 + ICMP_PAYLOAD;
    if (cap < len) return -1;
    memset(b, 0, (size_t)len);
    b[0] = 0x45;
    put_be16(b + 2, (uint16_t)len);
    put_be16(b + 4, seq);
    put_be16(b + 6, 0x4000);  // DF
    b[8] = 64;
    b[9] = 1;
    memcpy(b + 12, &src, 4);
    memcpy(b + 16, &dst, 4);
    put_be16(b + 10, ip_checksum(b, 20, 0));
    uint8_t *ic = b + 20;
    ic[0] = 8;
    put_be16(ic + 4, id);
    put_be16(ic + 6, seq);
    memcpy(ic + 8, "droidtether-mbim", ICMP_PAYLOAD);
    put_be16(ic + 2, ip_checksum(ic, 8 + ICMP_PAYLOAD, 0));
    return len;
}

bool icmp_is_echo_reply(const uint8_t *ip, int len, uint32_t to, uint16_t id) {
    if (len < 28 || (ip[0] >> 4) != 4 || ip[9] != 1) return false;
    int ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl + 8) return false;
    uint32_t dst;
    memcpy(&dst, ip + 16, 4);
    return dst == to && ip[ihl] == 0 && get_be16(ip + ihl + 4) == id;
}

// ---------- 控制通道 ----------

#define CDC_SEND_ENCAPSULATED_COMMAND 0x00
#define CDC_GET_ENCAPSULATED_RESPONSE 0x01
#define CDC_GET_NTB_PARAMETERS 0x80
#define CDC_SET_NTB_INPUT_SIZE 0x86
#define NTB_INPUT_SIZE 16384  // 跟 Linux cdc_ncm 的預設 rx_max 一樣
#define CDC_NOTIFY_RESPONSE_AVAILABLE 0x01
#define RESP_BUF 16384

static void dispatch(mbim_dev_t *d, const uint8_t *buf, int len) {
    mbim_msg_t m;
    if (mbim_parse(buf, len, &m) != 0) {
        LOGD("MBIM: unparsable message (%d bytes)", len);
        return;
    }
    if (m.type == MBIM_INDICATE_STATUS) {
        if (d->on_indicate) d->on_indicate(d->ind_ctx, &m);
        return;
    }
    pthread_mutex_lock(&d->lock);
    // FUNCTION_ERROR 的 tid 可能對不上，有人在等就交給他
    if (d->wait_tid && (m.tid == d->wait_tid || m.type == MBIM_FUNCTION_ERROR) && d->resp && len <= d->resp_cap) {
        memcpy(d->resp, buf, (size_t)len);
        d->resp_len = len;
        d->wait_tid = 0;
        pthread_cond_broadcast(&d->cond);
    } else {
        LOGD("MBIM: unexpected message type %08x tid %u", m.type, m.tid);
    }
    pthread_mutex_unlock(&d->lock);
}

// 向裝置要一則回應（呼叫前要拿 ctrl_lock）。回傳收到的長度，沒有東西回傳 0。
static int fetch_response(mbim_dev_t *d) {
    uint8_t *buf = malloc(d->max_ctrl);
    int n = libusb_control_transfer(d->u->h, 0xA1, CDC_GET_ENCAPSULATED_RESPONSE, 0, (uint16_t)d->u->comm_if, buf,
                                    (uint16_t)d->max_ctrl, 2000);
    if (n == LIBUSB_ERROR_NO_DEVICE) d->dead = true;
    if (n != LIBUSB_ERROR_PIPE) LOGD("MBIM: GET_ENCAPSULATED_RESPONSE -> %d %s", n, n < 0 ? libusb_error_name(n) : "");
    if (n > 0) {
        int r = mbim_reasm_feed(&d->reasm, buf, n);
        if (r == 1) dispatch(d, d->reasm.buf, d->reasm.len);
        else if (r < 0) LOGD("MBIM: dropped fragment (%d bytes)", n);
    }
    free(buf);
    return n > 0 ? n : 0;
}

static void *notify_thread(void *arg) {
    mbim_dev_t *d = arg;
    uint8_t buf[64];
    while (d->run && !d->dead) {
        int got = 0;
        int rc = libusb_interrupt_transfer(d->u->h, d->u->ep_int, buf, sizeof buf, &got, 500);
        if (rc == LIBUSB_ERROR_TIMEOUT) continue;
        if (rc == LIBUSB_ERROR_NO_DEVICE) {
            d->dead = true;
            break;
        }
        LOGD("MBIM: notification rc %d, %d bytes, %02x %02x", rc, got, got > 0 ? buf[0] : 0, got > 1 ? buf[1] : 0);
        if (rc != 0) {
            if (rc == LIBUSB_ERROR_PIPE) libusb_clear_halt(d->u->h, d->u->ep_int);
            usleep(100000);
            continue;
        }
        if (got >= 8 && buf[0] == 0xA1 && buf[1] == CDC_NOTIFY_RESPONSE_AVAILABLE) {
            pthread_mutex_lock(&d->ctrl_lock);
            fetch_response(d);
            pthread_mutex_unlock(&d->ctrl_lock);
        }
    }
    return NULL;
}

int mbim_dev_start(mbim_dev_t *d, usbdev_t *u, mbim_indicate_cb cb, void *ctx) {
    memset(d, 0, sizeof *d);
    d->u = u;
    d->max_ctrl = u->mbim_max_ctrl >= 64 ? u->mbim_max_ctrl : 4096;
    if (d->max_ctrl > 4096) d->max_ctrl = 4096;
    d->on_indicate = cb;
    d->ind_ctx = ctx;
    d->reasm.cap = RESP_BUF;
    d->reasm.buf = malloc(RESP_BUF);
    pthread_mutex_init(&d->ctrl_lock, NULL);
    pthread_mutex_init(&d->lock, NULL);
    pthread_cond_init(&d->cond, NULL);
    if (!u->ep_int) {
        LOGE("MBIM device has no notification endpoint");
        return -1;
    }
    d->run = true;
    if (pthread_create(&d->thr, NULL, notify_thread, d) != 0) return -1;
    d->thr_started = true;
    return 0;
}

void mbim_dev_stop(mbim_dev_t *d) {
    d->run = false;
    if (d->thr_started) pthread_join(d->thr, NULL);
    d->thr_started = false;
    free(d->reasm.buf);
    d->reasm.buf = NULL;
    pthread_mutex_destroy(&d->ctrl_lock);
    pthread_mutex_destroy(&d->lock);
    pthread_cond_destroy(&d->cond);
}

static void cond_wait_ms(pthread_cond_t *c, pthread_mutex_t *mu, long ms) {
#ifdef __APPLE__
    struct timespec rel = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    pthread_cond_timedwait_relative_np(c, mu, &rel);
#else
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_nsec += (ms % 1000) * 1000000L;
    t.tv_sec += ms / 1000 + t.tv_nsec / 1000000000L;
    t.tv_nsec %= 1000000000L;
    pthread_cond_timedwait(c, mu, &t);
#endif
}

// 送出一則訊息、等 tid 相同的回應（完整訊息複製到 out）。回傳回應長度，失敗回傳 -1。
static int transact(mbim_dev_t *d, uint8_t *msg, int len, uint8_t *out, int cap, int timeout_ms) {
    if (d->dead || len > (int)d->max_ctrl) return -1;
    uint32_t tid = get_le32(msg + 8);
    pthread_mutex_lock(&d->lock);
    d->wait_tid = tid;
    d->resp = out;
    d->resp_cap = cap;
    d->resp_len = -1;
    pthread_mutex_unlock(&d->lock);

    pthread_mutex_lock(&d->ctrl_lock);
    int rc = libusb_control_transfer(d->u->h, 0x21, CDC_SEND_ENCAPSULATED_COMMAND, 0, (uint16_t)d->u->comm_if, msg,
                                     (uint16_t)len, 2000);
    pthread_mutex_unlock(&d->ctrl_lock);
    if (rc == LIBUSB_ERROR_NO_DEVICE) d->dead = true;
    LOGD("MBIM: sent type %08x tid %u (%d bytes) -> %d", get_le32(msg), tid, len, rc);
    if (rc != len) {
        LOGD("MBIM: send failed (%s)", rc < 0 ? libusb_error_name(rc) : "short");
        pthread_mutex_lock(&d->lock);
        d->wait_tid = 0;
        d->resp = NULL;
        pthread_mutex_unlock(&d->lock);
        return -1;
    }

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    long next_poll = 1000;
    pthread_mutex_lock(&d->lock);
    while (d->resp_len < 0 && !d->dead && !g_stop) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long el = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
        if (el >= timeout_ms) break;
        if (el >= next_poll) {
            // 通知可能漏掉：自己去要一次
            next_poll += 1000;
            pthread_mutex_unlock(&d->lock);
            pthread_mutex_lock(&d->ctrl_lock);
            fetch_response(d);
            pthread_mutex_unlock(&d->ctrl_lock);
            pthread_mutex_lock(&d->lock);
            continue;
        }
        cond_wait_ms(&d->cond, &d->lock, 200);
    }
    int got = d->resp_len;
    d->wait_tid = 0;
    d->resp = NULL;
    pthread_mutex_unlock(&d->lock);
    return got;
}

int mbim_dev_open(mbim_dev_t *d) {
    uint8_t msg[16], resp[64];
    mbim_build_close(msg, sizeof msg, ++d->next_tid);
    transact(d, msg, 12, resp, sizeof resp, 2000);  // 沒開過會回錯誤，不管

    int len = mbim_build_open(msg, sizeof msg, ++d->next_tid, d->max_ctrl);
    int n = transact(d, msg, len, resp, sizeof resp, 10000);
    mbim_msg_t m;
    if (n <= 0 || mbim_parse(resp, n, &m) != 0) {
        LOGE("MBIM open: no answer");
        return -1;
    }
    if (m.type != MBIM_OPEN_DONE || m.status != 0) {
        LOGE("MBIM open: %s (type %08x)", mbim_status_name(m.status), m.type);
        return -1;
    }
    return 0;
}

void mbim_dev_close(mbim_dev_t *d) {
    uint8_t msg[12], resp[64];
    mbim_build_close(msg, sizeof msg, ++d->next_tid);
    transact(d, msg, 12, resp, sizeof resp, 2000);
}

int mbim_dev_command(mbim_dev_t *d, uint32_t cid, bool set, const uint8_t *info, int info_len, uint8_t *out, int cap,
                     uint32_t *status, int timeout_ms) {
    uint8_t *msg = malloc(d->max_ctrl);
    uint8_t *resp = malloc(RESP_BUF);
    int ret = -1;
    int len = mbim_build_command(msg, (int)d->max_ctrl, ++d->next_tid, MBIM_UUID_BASIC_CONNECT, cid, set, info, info_len);
    int n = len > 0 ? transact(d, msg, len, resp, RESP_BUF, timeout_ms) : -1;
    mbim_msg_t m;
    if (n > 0 && mbim_parse(resp, n, &m) == 0) {
        if (m.type == MBIM_FUNCTION_ERROR) {
            LOGW("MBIM cid %u: function error %u", cid, m.status);
        } else if (m.type == MBIM_COMMAND_DONE && m.cid == cid && memcmp(m.uuid, MBIM_UUID_BASIC_CONNECT, 16) == 0) {
            *status = m.status;
            ret = (int)m.info_len < cap ? (int)m.info_len : cap;
            memcpy(out, m.info, (size_t)ret);
        }
    } else if (!d->dead) {
        LOGW("MBIM cid %u: no answer", cid);
    }
    free(msg);
    free(resp);
    return ret;
}

#define CMD_TIMEOUT_MS 10000
#define CONNECT_TIMEOUT_MS 60000

static void sleep_s(int s) {
    sleep_ms_interruptible(s * 1000);
}

static int bc(mbim_dev_t *s, uint32_t cid, bool set, const uint8_t *info, int ilen, uint8_t *out, int cap, uint32_t *st,
              int timeout_ms) {
    if (stopping() || s->dead) return -1;
    return mbim_dev_command(s, cid, set, info, ilen, out, cap, st, timeout_ms);
}

// SIM 鎖著：有存 PIN 而且這次還沒試過才試一次，被拒就回報，絕不重試（錯三次會鎖成要 PUK）。
static const char *unlock_sim(mbim_dev_t *s, mbim_connect_opts_t *o) {
    uint8_t out[512], info[64];
    uint32_t st = 0, type = 0, state = 0, att = 0xFFFFFFFFu;
    int n = bc(s, MBIM_CID_PIN, false, NULL, 0, out, sizeof out, &st, CMD_TIMEOUT_MS);
    if (n < 0 || mbim_parse_pin_info(out, (uint32_t)n, &type, &state, &att) != 0) return "sim_locked";
    o->pin_attempts = att > 99 ? -1 : (int)att;
    if (type == MBIM_PIN_TYPE_PUK1) return "sim_puk";
    if (type != MBIM_PIN_TYPE_PIN1 || state != MBIM_PIN_STATE_LOCKED) return "sim_locked";
    if (!o->pin || !o->pin[0] || o->pin_used) return "sim_pin_required";
    int il = mbim_info_pin_enter(info, sizeof info, o->pin);
    if (il < 0) {
        o->pin_rejected = true;  // 格式就不對，不送
        return "sim_pin_wrong";
    }
    o->pin_used = true;
    LOGI("entering the SIM PIN (%d attempts left)", o->pin_attempts);
    n = bc(s, MBIM_CID_PIN, true, info, il, out, sizeof out, &st, CMD_TIMEOUT_MS);
    if (n >= 0 && mbim_parse_pin_info(out, (uint32_t)n, &type, &state, &att) == 0) o->pin_attempts = att > 99 ? -1 : (int)att;
    if (n < 0 || st != 0) {
        o->pin_rejected = true;
        LOGE("SIM PIN rejected (%s, %d attempts left); it will not be tried again", mbim_status_name(st), o->pin_attempts);
        return "sim_pin_wrong";
    }
    LOGI("SIM unlocked");
    return NULL;
}

static const char *dial(mbim_dev_t *s, const char *apn, uint32_t ip_type, uint32_t *st_out) {
    uint8_t out[512], info[256];
    uint32_t st = 0;
    mbim_connect_info_t c;
    int il = mbim_info_connect_set(info, sizeof info, 0, true, apn, ip_type);
    if (il < 0) return "connect_failed";
    LOGI("connecting (apn %s, %s)", apn, ip_type == MBIM_IP_TYPE_IPV4V6 ? "IPv4v6" : "IPv4");
    int n = bc(s, MBIM_CID_CONNECT, true, info, il, out, sizeof out, &st, CONNECT_TIMEOUT_MS);
    *st_out = st;
    if (n < 0) return "mbim_failed";
    bool parsed = mbim_parse_connect(out, (uint32_t)n, &c) == 0;
    if (st != 0 || !parsed || c.activation != MBIM_ACT_ACTIVATED) {
        if (parsed && st == 0)
            LOGE("connect failed: activation state %u, network error %u", c.activation, c.nw_error);
        else
            LOGE("connect failed: %s (status %u)", mbim_status_name(st), st);
        return "connect_failed";
    }
    return NULL;
}

const char *mbim_connect(mbim_dev_t *s, mbim_connect_opts_t *o, mbim_ipv4_t *ipc, mbim_ipv6_t *ip6) {
    uint8_t out[4096], info[256];
    uint32_t st = 0;
    int n;
    o->pin_attempts = -1;
    memset(ip6, 0, sizeof *ip6);
    bool unlocked = false;  // PIN 剛輸入成功，SIM 可能還要一下子才就緒，不要再試一次

    for (int i = 0;; i++) {
        uint32_t ready = 0;
        n = bc(s, MBIM_CID_SUBSCRIBER_READY, false, NULL, 0, out, sizeof out, &st, CMD_TIMEOUT_MS);
        if (n < 0) return "mbim_failed";
        if (mbim_parse_subscriber_ready(out, (uint32_t)n, &ready) == 0) {
            if (ready == MBIM_SIM_INITIALIZED) break;
            if (ready == MBIM_SIM_NOT_INSERTED) return "sim_missing";
            if (ready == MBIM_SIM_LOCKED && !unlocked) {
                const char *e = unlock_sim(s, o);
                if (e) return e;
                unlocked = true;
            }
            if (ready == MBIM_SIM_BAD || ready == MBIM_SIM_FAILURE || ready == MBIM_SIM_NOT_ACTIVATED) return "sim_failed";
        } else if (st == 3) {
            return "sim_missing";  // MBIM_STATUS_SIM_NOT_INSERTED
        } else if (st == 5 && !unlocked) {  // MBIM_STATUS_PIN_REQUIRED
            const char *e = unlock_sim(s, o);
            if (e) return e;
            unlocked = true;
        }
        if (i >= 30) return "sim_failed";
        sleep_s(1);
    }

    uint32_t hw = 1, sw = 1;
    n = bc(s, MBIM_CID_RADIO_STATE, false, NULL, 0, out, sizeof out, &st, CMD_TIMEOUT_MS);
    if (n >= 0 && mbim_parse_radio_state(out, (uint32_t)n, &hw, &sw) == 0 && !sw) {
        LOGI("turning the modem's radio on");
        int il = mbim_info_radio_set(info, true);
        bc(s, MBIM_CID_RADIO_STATE, true, info, il, out, sizeof out, &st, CMD_TIMEOUT_MS);
    }
    if (!hw) return "radio_off";

    for (int i = 0;; i++) {
        uint32_t err = 0, reg = 0;
        n = bc(s, MBIM_CID_REGISTER_STATE, false, NULL, 0, out, sizeof out, &st, CMD_TIMEOUT_MS);
        if (n < 0) return "mbim_failed";
        if (mbim_parse_register_state(out, (uint32_t)n, &err, &reg) == 0) {
            if (reg == MBIM_REG_HOME || reg == MBIM_REG_ROAMING || reg == MBIM_REG_PARTNER) break;
            if (reg == MBIM_REG_DENIED) {
                LOGE("registration denied (nw error %u)", err);
                return "not_registered";
            }
        }
        if (i >= 90) return "not_registered";
        if (i == 0) LOGI("waiting for the modem to register with the network");
        sleep_s(1);
    }

    for (int i = 0;; i++) {
        uint32_t err = 0, ps = 0;
        n = bc(s, MBIM_CID_PACKET_SERVICE, false, NULL, 0, out, sizeof out, &st, CMD_TIMEOUT_MS);
        if (n < 0) return "mbim_failed";
        if (mbim_parse_packet_service(out, (uint32_t)n, &err, &ps) == 0 && ps == MBIM_PS_ATTACHED) break;
        if (i >= 60) return "not_registered";
        if (i == 0) {
            int il = mbim_info_packet_service_set(info, true);
            bc(s, MBIM_CID_PACKET_SERVICE, true, info, il, out, sizeof out, &st, CONNECT_TIMEOUT_MS);
        }
        sleep_s(1);
    }

    // 上一個主機（或上一次連線）留下的連線先斷掉，拿一條新的（同 PVE 上 zombie 的處理）
    int il = mbim_info_connect_query(info, sizeof info, 0);
    n = bc(s, MBIM_CID_CONNECT, false, info, il, out, sizeof out, &st, CMD_TIMEOUT_MS);
    mbim_connect_info_t c;
    if (n >= 0 && mbim_parse_connect(out, (uint32_t)n, &c) == 0 && c.activation == MBIM_ACT_ACTIVATED) {
        LOGI("modem already has a data connection; starting a fresh one");
        il = mbim_info_connect_set(info, sizeof info, 0, false, "", MBIM_IP_TYPE_IPV4);
        bc(s, MBIM_CID_CONNECT, true, info, il, out, sizeof out, &st, CONNECT_TIMEOUT_MS);
        sleep_s(1);
    }

    const char *e = dial(s, o->apn, o->ipv6 ? MBIM_IP_TYPE_IPV4V6 : MBIM_IP_TYPE_IPV4, &st);
    if (e && o->ipv6 && strcmp(e, "connect_failed") == 0) {
        LOGW("IPv4v6 refused; trying IPv4 only");
        e = dial(s, o->apn, MBIM_IP_TYPE_IPV4, &st);
    }
    if (e) return e;

    il = mbim_info_ip_config_query(info, sizeof info, 0);
    n = bc(s, MBIM_CID_IP_CONFIGURATION, false, info, il, out, sizeof out, &st, CMD_TIMEOUT_MS);
    if (n < 0 || st != 0 || mbim_parse_ip_config(out, (uint32_t)n, ipc) != 0) {
        LOGE("modem did not report an IPv4 address");
        return "connect_failed";
    }
    mbim_parse_ip6_config(out, (uint32_t)n, ip6);
    return NULL;
}

int mbim_query_custom_class(mbim_dev_t *s, char *out, int cap) {
    uint8_t buf[2048];
    uint32_t st = 0;
    out[0] = '\0';
    int n = bc(s, MBIM_CID_DEVICE_CAPS, false, NULL, 0, buf, sizeof buf, &st, CMD_TIMEOUT_MS);
    // MBIM_DEVICE_CAPS_INFO：..., CustomDataClass(offset 32, size 36), DeviceId, ...（DeviceId 是 IMEI，不讀）
    if (n < 64 || st != 0) return -1;
    return utf16_to_utf8(buf, (uint32_t)n, get_le32(buf + 32), get_le32(buf + 36), out, cap) < 0 ? -1 : 0;
}

const char *mbim_tech_name(uint32_t data_class, const char *custom) {
    const char *t = mbim_data_class_name(data_class);
    if (!*t && (data_class & 0x80000000u) && custom && strncmp(custom, "5G", 2) == 0) return "5G";
    return t;
}

int mbim_query_link(mbim_dev_t *s, mbim_link_t *l) {
    uint8_t out[1024];
    uint32_t st = 0, a = 0, b = 0;
    int ok = 0, n;
    l->rssi = l->bars = -1;
    l->provider[0] = '\0';
    l->data_class = 0;
    n = bc(s, MBIM_CID_SIGNAL_STATE, false, NULL, 0, out, sizeof out, &st, CMD_TIMEOUT_MS);
    if (n >= 0 && st == 0 && mbim_parse_signal(out, (uint32_t)n, &a, &b) == 0) {
        l->bars = mbim_signal_bars(a);
        l->rssi = l->bars < 0 ? -1 : (int)a;
        ok++;
    }
    n = bc(s, MBIM_CID_REGISTER_STATE, false, NULL, 0, out, sizeof out, &st, CMD_TIMEOUT_MS);
    if (n >= 0 && st == 0 && mbim_parse_provider_name(out, (uint32_t)n, l->provider, sizeof l->provider) == 0) ok++;
    n = bc(s, MBIM_CID_PACKET_SERVICE, false, NULL, 0, out, sizeof out, &st, CMD_TIMEOUT_MS);
    if (n >= 0 && st == 0 && mbim_parse_data_class(out, (uint32_t)n, &l->data_class) == 0) ok++;
    return ok ? 0 : -1;
}

void mbim_disconnect(mbim_dev_t *d) {
    uint8_t info[128], out[256];
    uint32_t st;
    int il = mbim_info_connect_set(info, sizeof info, 0, false, "", MBIM_IP_TYPE_IPV4);
    mbim_dev_command(d, MBIM_CID_CONNECT, true, info, il, out, sizeof out, &st, 5000);
}

int mbim_data_start(usbdev_t *u, ntb_params_t *np) {
    // 先切回 alternate setting 0 讓資料通道重置（同 Linux cdc_ncm），讀完參數再切到有端點的那一組
    libusb_set_interface_alt_setting(u->h, u->data_if, 0);
    uint8_t p[28];
    int n = libusb_control_transfer(u->h, 0xA1, CDC_GET_NTB_PARAMETERS, 0, (uint16_t)u->comm_if, p, sizeof p, 2000);
    if (n < 28 || ntb_parse_params(p, n, np) != 0) {
        LOGE("MBIM: cannot read NTB parameters (%s)", n < 0 ? libusb_error_name(n) : "short or unsupported");
        return -1;
    }
    // IK512（高通 SDX62）沒收到這個請求就不回 MBIM OPEN；Linux 的 cdc_ncm 在綁定時一定會送，
    // 所以在 Linux 上看不出來。2026/10/10 在 macOS 上實測：少了它 OPEN 等 60 秒都沒回，加上後 0.4 秒回。
    uint8_t sz[4];
    put_le32(sz, NTB_INPUT_SIZE);
    int rc = libusb_control_transfer(u->h, 0x21, CDC_SET_NTB_INPUT_SIZE, 0, (uint16_t)u->comm_if, sz, sizeof sz, 2000);
    if (rc == (int)sizeof sz && np->in_max > NTB_INPUT_SIZE) np->in_max = NTB_INPUT_SIZE;
    else if (rc != (int)sizeof sz) LOGW("MBIM: SET_NTB_INPUT_SIZE failed (%s)", rc < 0 ? libusb_error_name(rc) : "short");
    rc = libusb_set_interface_alt_setting(u->h, u->data_if, u->data_alt);
    if (rc != 0) {
        LOGE("MBIM: cannot enable data interface: %s", libusb_error_name(rc));
        return -1;
    }
    LOGD("NTB: in max %u, out max %u, out divisor %u remainder %u align %u", np->in_max, np->out_max, np->out_divisor,
         np->out_remainder, np->out_align);
    return 0;
}
