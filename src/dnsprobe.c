#include "dnsprobe.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int dnsprobe_build(uint8_t *buf, int cap, uint16_t id) {
    const char *name = DNSPROBE_NAME;
    int need = 12 + (int)strlen(name) + 2 + 4;
    if (cap < need) return -1;
    memset(buf, 0, 12);
    put_be16(buf, id);
    put_be16(buf + 2, 0x0100);  // 標準查詢，要求遞迴
    put_be16(buf + 4, 1);       // QDCOUNT
    int n = 12;
    for (const char *p = name; *p;) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        buf[n++] = (uint8_t)len;
        memcpy(buf + n, p, (size_t)len);
        n += len;
        p += len + (dot ? 1 : 0);
    }
    buf[n++] = 0;
    put_be16(buf + n, 1);  // A
    put_be16(buf + n + 2, 1);  // IN
    return n + 4;
}

bool dnsprobe_reply_ok(const uint8_t *buf, int len, uint16_t id) {
    if (len < 12 || get_be16(buf) != id) return false;
    uint16_t flags = get_be16(buf + 2);
    if (!(flags & 0x8000)) return false;  // 不是回覆
    int rcode = flags & 0x000F;
    return rcode == 0 || rcode == 3;
}

static long ms_since(const struct timespec *t0) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - t0->tv_sec) * 1000 + (now.tv_nsec - t0->tv_nsec) / 1000000;
}

bool dnsprobe_server(const char *ifname, uint32_t server, int timeout_ms) {
    unsigned idx = if_nametoindex(ifname);
    if (!idx) return false;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    bool ok = false;
    struct sockaddr_in to = {.sin_len = sizeof to, .sin_family = AF_INET, .sin_port = htons(53)};
    to.sin_addr.s_addr = server;
    if (setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof idx) != 0 ||
        connect(fd, (struct sockaddr *)&to, sizeof to) != 0)
        goto out;

    uint8_t q[64], r[1500];
    uint16_t id = (uint16_t)arc4random();
    int qlen = dnsprobe_build(q, sizeof q, id);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    // 送兩次：第一次可能卡在 ARP
    for (int attempt = 0; attempt < 2 && !ok; attempt++) {
        (void)!send(fd, q, (size_t)qlen, 0);
        long until = attempt == 0 ? timeout_ms / 2 : timeout_ms;
        for (long left; !ok && (left = until - ms_since(&t0)) > 0;) {
            struct pollfd p = {.fd = fd, .events = POLLIN};
            if (poll(&p, 1, (int)left) <= 0) break;
            ssize_t n = recv(fd, r, sizeof r, 0);
            if (n > 0) ok = dnsprobe_reply_ok(r, (int)n, id);
            else if (n < 0) break;  // 例如 ICMP port unreachable
        }
    }
out:
    close(fd);
    return ok;
}
