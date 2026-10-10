#include "sms.h"

#include <string.h>

// ---------- 字元集 ----------

// TS 23.038 6.2.1 的 GSM 7-bit 預設字母表 → Unicode。0x1B 是跳到擴充表的 escape，不對應任何字元。
static const uint16_t GSM7[128] = {
    0x0040, 0x00A3, 0x0024, 0x00A5, 0x00E8, 0x00E9, 0x00F9, 0x00EC, 0x00F2, 0x00C7, 0x000A, 0x00D8, 0x00F8, 0x000D, 0x00C5, 0x00E5,
    0x0394, 0x005F, 0x03A6, 0x0393, 0x039B, 0x03A9, 0x03A0, 0x03A8, 0x03A3, 0x0398, 0x039E, 0xFFFF, 0x00C6, 0x00E6, 0x00DF, 0x00C9,
    0x0020, 0x0021, 0x0022, 0x0023, 0x00A4, 0x0025, 0x0026, 0x0027, 0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F,
    0x00A1, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047, 0x0048, 0x0049, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058, 0x0059, 0x005A, 0x00C4, 0x00D6, 0x00D1, 0x00DC, 0x00A7,
    0x00BF, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078, 0x0079, 0x007A, 0x00E4, 0x00F6, 0x00F1, 0x00FC, 0x00E0,
};

#define GSM7_ESC 0x1B

// 擴充表（escape 後面那個 septet）
static const struct {
    uint8_t code;
    uint16_t uc;
} GSM7_EXT[] = {
    {0x0A, 0x000C}, {0x14, 0x005E}, {0x28, 0x007B}, {0x29, 0x007D}, {0x2F, 0x005C},
    {0x3C, 0x005B}, {0x3D, 0x007E}, {0x3E, 0x005D}, {0x40, 0x007C}, {0x65, 0x20AC},
};

// 讀一個 UTF-8 字元，回傳用掉幾個 byte；不合法（含 surrogate、overlong）回傳 -1。
static int utf8_next(const char *s, uint32_t *cp) {
    const uint8_t *p = (const uint8_t *)s;
    uint32_t c = p[0];
    int n;
    if (c < 0x80) {
        *cp = c;
        return 1;
    }
    if (c >= 0xC2 && c <= 0xDF) {
        n = 2;
        c &= 0x1F;
    } else if (c >= 0xE0 && c <= 0xEF) {
        n = 3;
        c &= 0x0F;
    } else if (c >= 0xF0 && c <= 0xF4) {
        n = 4;
        c &= 0x07;
    } else {
        return -1;
    }
    for (int i = 1; i < n; i++) {
        if ((p[i] & 0xC0) != 0x80) return -1;
        c = (c << 6) | (p[i] & 0x3F);
    }
    if ((n == 3 && c < 0x800) || (n == 4 && (c < 0x10000 || c > 0x10FFFF)) || (c >= 0xD800 && c < 0xE000)) return -1;
    *cp = c;
    return n;
}

// 在 out 後面接一個字元（UTF-8），放不下回傳 false。out 一直保持以 NUL 結尾。
static bool put_cp(char *out, int *o, int cap, uint32_t c) {
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
    if (*o + k >= cap) return false;
    memcpy(out + *o, b, (size_t)k);
    *o += k;
    out[*o] = '\0';
    return true;
}

static void gsm7_to_utf8(const uint8_t *sept, int n, char *out, int cap) {
    int o = 0;
    out[0] = '\0';
    for (int k = 0; k < n; k++) {
        uint32_t c;
        if (sept[k] == GSM7_ESC) {
            if (k + 1 >= n) break;  // 結尾落單的 escape
            uint8_t e = sept[++k];
            c = e == GSM7_ESC ? 0x20 : GSM7[e];  // 不認得的擴充字元照規格顯示預設表的字
            for (size_t i = 0; i < sizeof GSM7_EXT / sizeof GSM7_EXT[0]; i++)
                if (GSM7_EXT[i].code == e) c = GSM7_EXT[i].uc;
        } else {
            c = GSM7[sept[k]];
        }
        if (!put_cp(out, &o, cap, c)) break;
    }
}

// 一個字元換成 GSM 7-bit：回傳 1（*a）、2（escape + *a），不在字母表回傳 0。
static int gsm7_from_cp(uint32_t c, uint8_t *a) {
    for (int i = 0; i < 128; i++)
        if (GSM7[i] == c && i != GSM7_ESC) {
            *a = (uint8_t)i;
            return 1;
        }
    for (size_t i = 0; i < sizeof GSM7_EXT / sizeof GSM7_EXT[0]; i++)
        if (GSM7_EXT[i].uc == c) {
            *a = GSM7_EXT[i].code;
            return 2;
        }
    return 0;
}

// UCS-2（大端序，照 UTF-16 解 surrogate pair）→ UTF-8。落單的 surrogate 換成 U+FFFD。
static void ucs2_to_utf8(const uint8_t *u, int n, char *out, int cap) {
    int o = 0;
    out[0] = '\0';
    for (int i = 0; i + 1 < n; i += 2) {
        uint32_t c = (uint32_t)(u[i] << 8 | u[i + 1]);
        if (c >= 0xD800 && c < 0xDC00 && i + 3 < n) {
            uint32_t lo = (uint32_t)(u[i + 2] << 8 | u[i + 3]);
            if (lo >= 0xDC00 && lo < 0xE000) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            }
        }
        if (c >= 0xD800 && c < 0xE000) c = 0xFFFD;
        if (c && !put_cp(out, &o, cap, c)) break;
    }
}

// ---------- 7-bit 打包 ----------

// 第 k 個 septet 從 start_bit + 7k 開始，低位元在前。
static int unpack7(const uint8_t *in, int in_len, int start_bit, int n, uint8_t *sept) {
    for (int k = 0; k < n; k++) {
        int pos = start_bit + 7 * k, b = pos / 8, sh = pos % 8;
        if (b >= in_len) return -1;
        int v = in[b] >> sh;
        if (sh > 1) {
            if (b + 1 >= in_len) return -1;
            v |= in[b + 1] << (8 - sh);
        }
        sept[k] = (uint8_t)(v & 0x7F);
    }
    return 0;
}

// 回傳用掉的 octet 數（從 out 開頭算，含 start_bit 前面的部分）。
static int pack7(const uint8_t *sept, int n, int start_bit, uint8_t *out) {
    int bytes = (start_bit + 7 * n + 7) / 8;
    memset(out + start_bit / 8, 0, (size_t)(bytes - start_bit / 8));
    for (int k = 0; k < n; k++) {
        int pos = start_bit + 7 * k, b = pos / 8, sh = pos % 8;
        out[b] |= (uint8_t)(sept[k] << sh);
        if (sh > 1) out[b + 1] |= (uint8_t)(sept[k] >> (8 - sh));
    }
    return bytes;
}

// ---------- 解碼 ----------

// TS 23.038 第 4 節：從 TP-DCS 判斷字元集。壓縮過的當成 8-bit（解不了）。
static int dcs_alphabet(uint8_t dcs) {
    if ((dcs & 0x80) == 0) {  // 00xx（一般）、01xx（讀完自動刪）
        if (dcs & 0x20) return SMS_DCS_8BIT;
        int a = (dcs >> 2) & 3;
        return a == 1 ? SMS_DCS_8BIT : a == 2 ? SMS_DCS_UCS2 : SMS_DCS_GSM7;
    }
    if ((dcs & 0xF0) == 0xF0) return (dcs & 0x04) ? SMS_DCS_8BIT : SMS_DCS_GSM7;
    if ((dcs & 0xF0) == 0xE0) return SMS_DCS_UCS2;  // 留言通知，UCS-2
    return SMS_DCS_GSM7;                            // 留言通知（GSM）、保留值
}

static int bcd2(uint8_t b) {
    int lo = b & 0x0F, hi = b >> 4;
    return lo > 9 || hi > 9 ? -1 : lo * 10 + hi;
}

// 公曆日期換成 1970-01-01 起的天數（Howard Hinnant 的 days_from_civil），不靠 timegm。
static long days_from_civil(int y, int m, int d) {
    y -= m <= 2;
    int era = (y >= 0 ? y : y - 399) / 400;
    int yoe = y - era * 400;
    int doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (long)era * 146097 + doe - 719468;
}

// TP-SCTS：年月日時分秒各一個反過來的 BCD，最後一個是以 15 分鐘為單位的時區（bit 3 是負號）。
static time_t scts_decode(const uint8_t *s, int *tz_min) {
    int v[6];
    *tz_min = 0;
    for (int k = 0; k < 6; k++)
        if ((v[k] = bcd2(s[k])) < 0) return 0;
    if (v[1] < 1 || v[1] > 12 || v[2] < 1 || v[2] > 31 || v[3] > 23 || v[4] > 59 || v[5] > 59) return 0;
    int hi = s[6] >> 4, q = (s[6] & 0x07) * 10 + hi;
    if (hi <= 9) *tz_min = (s[6] & 0x08 ? -q : q) * 15;
    long days = days_from_civil(2000 + v[0], v[1], v[2]);
    return (time_t)(days * 86400 + v[3] * 3600 + v[4] * 60 + v[5]) - *tz_min * 60;
}

static void set_concat(sms_pdu_t *o, int ref, int total, int seq) {
    if (total < 2 || seq < 1 || seq > total) return;  // 不合理就當單則
    o->ref = (uint16_t)ref;
    o->total = (uint8_t)total;
    o->seq = (uint8_t)seq;
}

// User Data Header 的 information element：0x00 / 0x08 是 8 / 16-bit reference 的多段簡訊，0x04 / 0x05 是應用程式埠。
static int parse_udh(const uint8_t *h, int n, sms_pdu_t *o) {
    for (int i = 0; i < n;) {
        if (i + 2 > n) return -1;
        int iei = h[i], iel = h[i + 1];
        const uint8_t *d = h + i + 2;
        if (i + 2 + iel > n) return -1;
        if (iei == 0x00 && iel == 3) set_concat(o, d[0], d[1], d[2]);
        else if (iei == 0x08 && iel == 4) set_concat(o, d[0] << 8 | d[1], d[2], d[3]);
        else if (iei == 0x04 || iei == 0x05) o->port = true;
        i += 2 + iel;
    }
    return 0;
}

int sms_decode(const uint8_t *p, int len, sms_pdu_t *o) {
    memset(o, 0, sizeof *o);
    if (len < 1) return -1;
    int i = 1 + p[0];  // 跳過 SMSC
    if (i >= len) return -1;
    uint8_t fo = p[i++];
    int mti = fo & 3;
    if (mti > 1) return -1;  // 狀態回報、保留值
    o->submit = mti == 1;
    if (o->submit) i++;  // TP-MR

    // 位址：位數（英數字時是用到的 semi-octet 數）、type of address、BCD
    if (i + 2 > len) return -1;
    int digits = p[i], toa = p[i + 1], alen = (digits + 1) / 2;
    if (digits > 20 || i + 2 + alen > len) return -1;
    const uint8_t *a = p + i + 2;
    if ((toa & 0x70) == 0x50) {
        uint8_t sept[12];
        int n = digits * 4 / 7;
        if (unpack7(a, alen, 0, n, sept) != 0) return -1;
        gsm7_to_utf8(sept, n, o->addr, sizeof o->addr);
    } else {
        int k = 0;
        if ((toa & 0x70) == 0x10 && digits) o->addr[k++] = '+';
        for (int d = 0; d < digits; d++) {
            int v = (a[d / 2] >> (d % 2 ? 4 : 0)) & 0x0F;
            if (v == 0x0F) break;
            o->addr[k++] = "0123456789*#abc"[v];
        }
        o->addr[k] = '\0';
    }
    i += 2 + alen;

    if (i + 2 > len) return -1;
    o->pid = p[i++];
    o->dcs = dcs_alphabet(p[i++]);
    if (o->submit) {
        int vpf = (fo >> 3) & 3;  // 0 沒有、2 relative（1 octet）、1 enhanced、3 absolute（7 octets）
        i += vpf == 2 ? 1 : vpf ? 7 : 0;
    } else {
        if (i + 7 > len) return -1;
        o->time = scts_decode(p + i, &o->tz_min);
        i += 7;
    }
    if (i >= len) return -1;

    int udl = p[i++];  // GSM 7-bit 是 septet 數，其他是 octet 數
    const uint8_t *ud = p + i;
    bool gsm = o->dcs == SMS_DCS_GSM7;
    int ud_octets = gsm ? (udl * 7 + 7) / 8 : udl;
    if (ud_octets > len - i || udl > (gsm ? 160 : 140)) return -1;
    int hdr = 0;  // UDH 占的 octet，含開頭的 UDHL
    if (fo & 0x40) {
        if (ud_octets < 1 || ud[0] + 1 > ud_octets) return -1;
        hdr = ud[0] + 1;
        if (parse_udh(ud + 1, ud[0], o) != 0) return -1;
    }
    if (gsm) {
        int skip = (hdr * 8 + 6) / 7;  // 標頭占的 septet（含補到 septet 邊界的位元）
        int n = udl - skip;
        uint8_t sept[160];
        if (n < 0 || unpack7(ud, ud_octets, skip * 7, n, sept) != 0) return -1;
        gsm7_to_utf8(sept, n, o->text, sizeof o->text);
    } else if (o->dcs == SMS_DCS_UCS2) {
        ucs2_to_utf8(ud + hdr, udl - hdr, o->text, sizeof o->text);
    }
    return 0;
}

// ---------- 編碼 ----------

#define TEXT_MAX 4096                // 一次最多處理的 UTF-8
#define GSM_SINGLE 160               // septet
#define GSM_PART 153                 // 扣掉 UDH 的 7 個 septet
#define UCS2_SINGLE 70               // UTF-16 單位
#define UCS2_PART 67                 // 扣掉 UDH 的 6 個 octet

bool sms_valid_number(const char *to) {
    const char *d = to[0] == '+' ? to + 1 : to;
    size_t n = strlen(d);
    if (n < 3 || n > 20) return false;
    for (size_t i = 0; i < n; i++)
        if (d[i] < '0' || d[i] > '9') return false;
    return true;
}

// 文字轉成 GSM septet（*n 個）或 UTF-16（*n 個單位）。有字不在 GSM 字母表時 *ucs2 = true。
static int prepare(const char *s, uint8_t *sept, uint16_t *u, int *n, bool *ucs2) {
    size_t len = strlen(s);
    if (!len || len > TEXT_MAX) return -1;
    *ucs2 = false;
    int k = 0;
    for (const char *q = s; *q;) {
        uint32_t c;
        int used = utf8_next(q, &c);
        if (used < 0) return -1;
        q += used;
        uint8_t g;
        int w = gsm7_from_cp(c, &g);
        if (!w) {
            *ucs2 = true;
            break;
        }
        if (w == 2) sept[k++] = GSM7_ESC;
        sept[k++] = g;
    }
    if (!*ucs2) {
        *n = k;
        return 0;
    }
    k = 0;
    for (const char *q = s; *q;) {
        uint32_t c;
        q += utf8_next(q, &c);
        if (c >= 0x10000) {
            c -= 0x10000;
            u[k++] = (uint16_t)(0xD800 + (c >> 10));
            u[k++] = (uint16_t)(0xDC00 + (c & 0x3FF));
        } else {
            u[k++] = (uint16_t)c;
        }
    }
    *n = k;
    return 0;
}

// 每段的起點寫進 cut（多一個結尾）。escape 不跟擴充字元分開，surrogate pair 不拆開。
static int split(const uint8_t *sept, const uint16_t *u, int n, bool ucs2, int *cut, int max) {
    int single = ucs2 ? UCS2_SINGLE : GSM_SINGLE, per = ucs2 ? UCS2_PART : GSM_PART;
    int parts = 0, start = 0;
    cut[0] = 0;
    if (n <= single) {
        cut[1] = n;
        return 1;
    }
    while (start < n) {
        int end = start + per < n ? start + per : n;
        if (end < n && (ucs2 ? (u[end - 1] >= 0xD800 && u[end - 1] < 0xDC00) : sept[end - 1] == GSM7_ESC)) end--;
        if (parts >= max) return parts + 1;  // 超過了，回傳一個大於 max 的數
        cut[++parts] = end;
        start = end;
    }
    return parts;
}

int sms_count_parts(const char *utf8, bool *ucs2) {
    static _Thread_local uint8_t sept[2 * TEXT_MAX];
    static _Thread_local uint16_t u[TEXT_MAX];
    int n, cut[256];
    if (prepare(utf8, sept, u, &n, ucs2) != 0) return -1;
    return split(sept, u, n, *ucs2, cut, 254);
}

static int encode_addr(const char *to, uint8_t *out) {
    bool intl = to[0] == '+';
    const char *d = intl ? to + 1 : to;
    int n = (int)strlen(d);
    out[0] = (uint8_t)n;
    out[1] = intl ? 0x91 : 0x81;  // 國際號碼 / 未知（國內號碼照撥號的樣子）
    for (int k = 0; k < n; k++) {
        int v = d[k] - '0';
        if (k % 2 == 0) out[2 + k / 2] = (uint8_t)(0xF0 | v);
        else out[2 + k / 2] = (uint8_t)((out[2 + k / 2] & 0x0F) | v << 4);
    }
    return 2 + (n + 1) / 2;
}

int sms_encode_submit(const char *to, const char *utf8, uint8_t ref, int vp, uint8_t pdu[][SMS_PDU_MAX], int len[],
                      int max_parts) {
    static _Thread_local uint8_t sept[2 * TEXT_MAX];
    static _Thread_local uint16_t u[TEXT_MAX];
    int n, cut[SMS_MAX_PARTS + 2];
    bool ucs2;
    if (!sms_valid_number(to) || max_parts < 1 || max_parts > SMS_MAX_PARTS) return -1;
    if (prepare(utf8, sept, u, &n, &ucs2) != 0) return -1;
    int parts = split(sept, u, n, ucs2, cut, max_parts);
    if (parts > max_parts) return -1;
    uint8_t da[12];
    int dal = encode_addr(to, da);
    for (int k = 0; k < parts; k++) {
        uint8_t *p = pdu[k];
        int i = 0;
        bool concat = parts > 1;
        p[i++] = 0x00;  // SMSC：用 SIM 裡的
        p[i++] = (uint8_t)(0x01 | (vp >= 0 ? 0x10 : 0) | (concat ? 0x40 : 0));  // SMS-SUBMIT、VPF、UDHI
        p[i++] = 0x00;  // TP-MR，數據機會自己填
        memcpy(p + i, da, (size_t)dal);
        i += dal;
        p[i++] = 0x00;                   // TP-PID
        p[i++] = ucs2 ? 0x08 : 0x00;     // TP-DCS
        if (vp >= 0) p[i++] = (uint8_t)vp;
        int udl_at = i++;
        uint8_t *ud = p + i;
        int h = 0;
        if (concat) {
            const uint8_t udh[6] = {5, 0x00, 3, ref, (uint8_t)parts, (uint8_t)(k + 1)};
            memcpy(ud, udh, 6);
            h = 6;
        }
        int a = cut[k], m = cut[k + 1] - cut[k];
        if (ucs2) {
            for (int j = 0; j < m; j++) {
                ud[h + 2 * j] = (uint8_t)(u[a + j] >> 8);
                ud[h + 2 * j + 1] = (uint8_t)u[a + j];
            }
            p[udl_at] = (uint8_t)(h + 2 * m);
            i += h + 2 * m;
        } else {
            int hs = (h * 8 + 6) / 7;  // 標頭占的 septet
            p[udl_at] = (uint8_t)(hs + m);
            i += pack7(sept + a, m, hs * 7, ud);
        }
        len[k] = i;
    }
    return parts;
}
