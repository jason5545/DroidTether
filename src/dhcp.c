#include "dhcp.h"

#include <arpa/inet.h>
#include <string.h>

#define BOOTP_LEN 236
#define DHCP_MAGIC 0x63825363u

uint16_t ip_checksum(const void *data, int len, uint32_t sum) {
    const uint8_t *p = data;
    while (len > 1) {
        sum += (uint32_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len) sum += (uint32_t)(p[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint8_t *opt_add(uint8_t *o, uint8_t code, const void *data, uint8_t len) {
    o[0] = code;
    o[1] = len;
    memcpy(o + 2, data, len);
    return o + 2 + len;
}

int dhcp_build(uint8_t *frame, int cap, const dhcp_send_t *s) {
    const int eth = 14, ip = 20, udp = 8;
    if (cap < eth + ip + udp + 548) return -1;
    memset(frame, 0, eth + ip + udp + 548);

    // Ethernet
    memcpy(frame, s->dst_mac, 6);
    memcpy(frame + 6, s->mac, 6);
    put_be16(frame + 12, 0x0800);

    // BOOTP
    uint8_t *b = frame + eth + ip + udp;
    b[0] = 1;  // BOOTREQUEST
    b[1] = 1;  // Ethernet
    b[2] = 6;
    memcpy(b + 4, &(uint32_t){htonl(s->xid)}, 4);
    if (s->ciaddr == 0) put_be16(b + 10, 0x8000);  // 還沒有 IP 時請伺服器用廣播回覆
    memcpy(b + 12, &s->ciaddr, 4);
    memcpy(b + 28, s->mac, 6);
    memcpy(b + BOOTP_LEN, &(uint32_t){htonl(DHCP_MAGIC)}, 4);

    uint8_t *o = b + BOOTP_LEN + 4;
    o = opt_add(o, 53, &s->type, 1);
    uint8_t cid[7] = {1};
    memcpy(cid + 1, s->mac, 6);
    o = opt_add(o, 61, cid, sizeof cid);
    if (s->requested) o = opt_add(o, 50, &s->requested, 4);
    if (s->server_id) o = opt_add(o, 54, &s->server_id, 4);
    if (s->type != DHCP_RELEASE) {
        static const uint8_t prl[] = {1, 3, 6, 15, 26, 51, 58, 59};
        o = opt_add(o, 55, prl, sizeof prl);
        uint8_t maxsz[2];
        put_be16(maxsz, 1500);
        o = opt_add(o, 57, maxsz, 2);
    }
    *o++ = 255;

    int dhcp_len = (int)(o - b);
    if (dhcp_len < 300) dhcp_len = 300;  // BOOTP 最小長度，部分伺服器會檢查

    // UDP
    uint8_t *u = frame + eth + ip;
    int udp_len = udp + dhcp_len;
    put_be16(u, 68);
    put_be16(u + 2, 67);
    put_be16(u + 4, (uint16_t)udp_len);

    // IPv4
    uint8_t *h = frame + eth;
    h[0] = 0x45;
    put_be16(h + 2, (uint16_t)(ip + udp_len));
    put_be16(h + 4, (uint16_t)(s->xid & 0xFFFF));
    h[8] = 64;
    h[9] = 17;
    memcpy(h + 12, &s->src_ip, 4);
    memcpy(h + 16, &s->dst_ip, 4);
    put_be16(h + 10, ip_checksum(h, ip, 0));

    // UDP checksum（含 pseudo header）
    uint32_t pseudo = 0;
    const uint8_t *sa = h + 12, *da = h + 16;
    pseudo += (uint32_t)((sa[0] << 8) | sa[1]) + (uint32_t)((sa[2] << 8) | sa[3]);
    pseudo += (uint32_t)((da[0] << 8) | da[1]) + (uint32_t)((da[2] << 8) | da[3]);
    pseudo += 17 + (uint32_t)udp_len;
    uint16_t c = ip_checksum(u, udp_len, pseudo);
    put_be16(u + 6, c ? c : 0xFFFF);

    return eth + ip + udp_len;
}

int dhcp_parse(const uint8_t *p, int len, uint32_t xid, const uint8_t *mac, dhcp_reply_t *out) {
    if (len < BOOTP_LEN + 4) return -1;
    if (p[0] != 2) return -1;  // BOOTREPLY
    uint32_t rx;
    memcpy(&rx, p + 4, 4);
    if (ntohl(rx) != xid) return -1;
    if (memcmp(p + 28, mac, 6) != 0) return -1;
    uint32_t magic;
    memcpy(&magic, p + BOOTP_LEN, 4);
    if (ntohl(magic) != DHCP_MAGIC) return -1;

    memset(out, 0, sizeof *out);
    memcpy(&out->yiaddr, p + 16, 4);

    int i = BOOTP_LEN + 4;
    while (i < len) {
        uint8_t code = p[i++];
        if (code == 0) continue;
        if (code == 255) break;
        if (i >= len) break;
        uint8_t olen = p[i++];
        if (i + olen > len) break;
        const uint8_t *v = p + i;
        switch (code) {
            case 53:
                if (olen >= 1) out->msg_type = v[0];
                break;
            case 54:
                if (olen >= 4) memcpy(&out->server_id, v, 4);
                break;
            case 1:
                if (olen >= 4) memcpy(&out->mask, v, 4);
                break;
            case 3:
                if (olen >= 4) memcpy(&out->router, v, 4);
                break;
            case 6:
                for (int k = 0; k + 4 <= olen && out->ndns < 4; k += 4) memcpy(&out->dns[out->ndns++], v + k, 4);
                break;
            case 51:
                if (olen >= 4) out->lease = (uint32_t)v[0] << 24 | (uint32_t)v[1] << 16 | (uint32_t)v[2] << 8 | v[3];
                break;
            case 58:
                if (olen >= 4) out->t1 = (uint32_t)v[0] << 24 | (uint32_t)v[1] << 16 | (uint32_t)v[2] << 8 | v[3];
                break;
            case 26:
                if (olen >= 2) out->mtu = get_be16(v);
                break;
        }
        i += olen;
    }
    return out->msg_type ? 0 : -1;
}
