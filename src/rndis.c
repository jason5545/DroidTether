#include "rndis.h"

#include <string.h>
#include <unistd.h>

#define OID_GEN_MAXIMUM_FRAME_SIZE 0x00010106u
#define OID_GEN_CURRENT_PACKET_FILTER 0x0001010Eu
#define OID_802_3_PERMANENT_ADDRESS 0x01010101u

// DIRECTED | ALL_MULTICAST | BROADCAST | PROMISCUOUS，與 Linux rndis_host 相同。
#define RNDIS_DEFAULT_FILTER 0x0000002Du

#define CONTROL_BUF 1025
#define HOST_MAX_TRANSFER 16384u

static int send_encapsulated(rndis_t *r, uint8_t *msg, uint16_t len) {
    int rc = libusb_control_transfer(r->u->h, 0x21, 0x00, 0, (uint16_t)r->u->comm_if, msg, len, 5000);
    return rc == len ? 0 : (rc < 0 ? rc : LIBUSB_ERROR_IO);
}

// 送出控制訊息並等對應的 completion。回傳 completion 長度，失敗回傳 -1。
static int rndis_command(rndis_t *r, uint8_t *msg, uint16_t len, uint8_t *resp) {
    uint32_t type = get_le32(msg);
    uint32_t id = get_le32(msg + 8);

    int rc = send_encapsulated(r, msg, len);
    if (rc != 0) {
        LOGE("RNDIS send 0x%08x: %s", type, libusb_error_name(rc));
        return -1;
    }

    for (int attempt = 0; attempt < 20; attempt++) {
        if (r->u->ep_int) {
            // RESPONSE_AVAILABLE 通知；讀不到也沒關係，下面直接輪詢。
            uint8_t note[16];
            int got = 0;
            libusb_interrupt_transfer(r->u->h, r->u->ep_int, note, sizeof note, &got, 100);
        }
        rc = libusb_control_transfer(r->u->h, 0xA1, 0x01, 0, (uint16_t)r->u->comm_if, resp, CONTROL_BUF, 2000);
        if (rc == LIBUSB_ERROR_NO_DEVICE) return -1;
        if (rc < 16) {
            usleep(20000);
            continue;
        }
        uint32_t rtype = get_le32(resp);
        if (rtype == RNDIS_MSG_KEEPALIVE) {
            uint8_t ka[16];
            put_le32(ka, RNDIS_MSG_KEEPALIVE | RNDIS_MSG_COMPLETION);
            put_le32(ka + 4, 16);
            memcpy(ka + 8, resp + 8, 4);
            put_le32(ka + 12, 0);
            send_encapsulated(r, ka, sizeof ka);
            continue;
        }
        if (rtype != (type | RNDIS_MSG_COMPLETION) || get_le32(resp + 8) != id) {
            LOGD("RNDIS skip msg 0x%08x id=%u", rtype, get_le32(resp + 8));
            continue;
        }
        uint32_t status = get_le32(resp + 12);
        if (status != 0) {
            LOGE("RNDIS 0x%08x status 0x%08x", type, status);
            return -1;
        }
        return rc;
    }
    LOGE("RNDIS 0x%08x: no completion", type);
    return -1;
}

static int rndis_query(rndis_t *r, uint32_t oid, uint8_t *out, uint32_t out_cap) {
    // Linux 會附上一段清零的輸入緩衝區，部分裝置需要它。
    uint8_t msg[28 + 48];
    uint32_t in_len = out_cap <= 48 ? out_cap : 48;
    memset(msg, 0, sizeof msg);
    put_le32(msg, RNDIS_MSG_QUERY);
    put_le32(msg + 4, 28 + in_len);
    put_le32(msg + 8, ++r->req_id);
    put_le32(msg + 12, oid);
    put_le32(msg + 16, in_len);
    put_le32(msg + 20, 20);
    put_le32(msg + 24, 0);

    uint8_t resp[CONTROL_BUF];
    int n = rndis_command(r, msg, (uint16_t)(28 + in_len), resp);
    if (n < 24) return -1;
    uint32_t ilen = get_le32(resp + 16);
    uint32_t ioff = get_le32(resp + 20);
    if ((uint64_t)8 + ioff + ilen > (uint64_t)n) return -1;
    memcpy(out, resp + 8 + ioff, ilen < out_cap ? ilen : out_cap);
    return (int)ilen;
}

static int rndis_set(rndis_t *r, uint32_t oid, const uint8_t *data, uint32_t len) {
    uint8_t msg[28 + 16];
    if (len > 16) return -1;
    memset(msg, 0, sizeof msg);
    put_le32(msg, RNDIS_MSG_SET);
    put_le32(msg + 4, 28 + len);
    put_le32(msg + 8, ++r->req_id);
    put_le32(msg + 12, oid);
    put_le32(msg + 16, len);
    put_le32(msg + 20, 20);
    put_le32(msg + 24, 0);
    memcpy(msg + 28, data, len);

    uint8_t resp[CONTROL_BUF];
    return rndis_command(r, msg, (uint16_t)(28 + len), resp) < 0 ? -1 : 0;
}

int rndis_init(rndis_t *r, usbdev_t *u) {
    memset(r, 0, sizeof *r);
    r->u = u;

    uint8_t msg[24];
    put_le32(msg, RNDIS_MSG_INIT);
    put_le32(msg + 4, sizeof msg);
    put_le32(msg + 8, ++r->req_id);
    put_le32(msg + 12, 1);  // major
    put_le32(msg + 16, 0);  // minor
    put_le32(msg + 20, HOST_MAX_TRANSFER);

    uint8_t resp[CONTROL_BUF];
    int n = rndis_command(r, msg, sizeof msg, resp);
    if (n < 52) {
        LOGE("RNDIS INIT failed");
        return -1;
    }
    r->dev_max_packets = get_le32(resp + 32);
    r->dev_max_transfer = get_le32(resp + 36);
    LOGD("RNDIS INIT ok: version %u.%u, max_packets=%u, max_transfer=%u", get_le32(resp + 16), get_le32(resp + 20),
         r->dev_max_packets, r->dev_max_transfer);

    uint8_t buf[48];
    if (rndis_query(r, OID_802_3_PERMANENT_ADDRESS, buf, sizeof buf) < 6) {
        LOGE("RNDIS query MAC failed");
        return -1;
    }
    memcpy(r->mac, buf, 6);

    r->max_frame = 1500;
    if (rndis_query(r, OID_GEN_MAXIMUM_FRAME_SIZE, buf, 4) >= 4) {
        uint32_t f = get_le32(buf);
        if (f >= 576 && f <= 9000) r->max_frame = f;
    }

    uint8_t filter[4];
    put_le32(filter, RNDIS_DEFAULT_FILTER);
    if (rndis_set(r, OID_GEN_CURRENT_PACKET_FILTER, filter, 4) != 0) {
        LOGE("RNDIS set packet filter failed");
        return -1;
    }
    return 0;
}

void rndis_halt(rndis_t *r) {
    if (!r->u || !r->u->h) return;
    uint8_t msg[12];
    put_le32(msg, RNDIS_MSG_HALT);
    put_le32(msg + 4, sizeof msg);
    put_le32(msg + 8, ++r->req_id);
    send_encapsulated(r, msg, sizeof msg);  // HALT 沒有 completion
}

int rndis_wrap(uint8_t *buf, int frame_len) {
    int total = RNDIS_PACKET_HDR + frame_len;
    memset(buf, 0, RNDIS_PACKET_HDR);
    put_le32(buf, RNDIS_MSG_PACKET);
    put_le32(buf + 4, (uint32_t)total);
    put_le32(buf + 8, RNDIS_PACKET_HDR - 8);  // DataOffset 從第 8 位元組起算
    put_le32(buf + 12, (uint32_t)frame_len);
    return total;
}

int rndis_unwrap(const uint8_t *buf, int len, rndis_frame_cb cb, void *ctx) {
    int off = 0, frames = 0;
    while (off + 8 <= len) {
        uint32_t type = get_le32(buf + off);
        uint32_t mlen = get_le32(buf + off + 4);
        if (mlen < 8 || (uint64_t)off + mlen > (uint64_t)len) break;
        if (type == RNDIS_MSG_PACKET && mlen >= RNDIS_PACKET_HDR) {
            uint32_t doff = get_le32(buf + off + 8);
            uint32_t dlen = get_le32(buf + off + 12);
            if ((uint64_t)8 + doff + dlen <= mlen && dlen >= 14) {
                cb(ctx, buf + off + 8 + doff, (int)dlen);
                frames++;
            }
        } else {
            LOGD("RNDIS data channel: skip msg 0x%08x", type);
        }
        off += (int)mlen;
    }
    return frames;
}
