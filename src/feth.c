#include "feth.h"

#include <errno.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define HOST_IF "feth7700"
#define PEER_IF "feth7701"

static bool if_exists(const char *name) {
    return if_nametoindex(name) != 0;
}

static int ifconfig(const char *const argv[]) {
    int rc = run_cmd(argv);
    if (rc != 0) {
        char line[256] = "";
        for (int i = 0; argv[i]; i++) {
            if (i) strlcat(line, " ", sizeof line);
            strlcat(line, argv[i], sizeof line);
        }
        LOGE("'%s' exited %d", line, rc);
    }
    return rc;
}

void feth_destroy_stale(void) {
    const char *names[] = {HOST_IF, PEER_IF};
    for (int i = 0; i < 2; i++) {
        if (!if_exists(names[i])) continue;
        LOGI("removing stale %s", names[i]);
        const char *argv[] = {"/sbin/ifconfig", names[i], "destroy", NULL};
        ifconfig(argv);
    }
}

static int open_bpf(void) {
    for (int i = 0; i < 256; i++) {
        char path[32];
        snprintf(path, sizeof path, "/dev/bpf%d", i);
        int fd = open(path, O_RDWR);
        if (fd >= 0) return fd;
        if (errno != EBUSY) break;
    }
    LOGE("open /dev/bpf: %s", strerror(errno));
    return -1;
}

static int setup_bpf(feth_t *f) {
    int fd = open_bpf();
    if (fd < 0) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    u_int blen = 512 * 1024;
    ioctl(fd, BIOCSBLEN, &blen);  // 系統上限內盡量大；失敗就用預設

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strlcpy(ifr.ifr_name, f->peer, sizeof ifr.ifr_name);
    u_int one = 1, zero = 0;
    if (ioctl(fd, BIOCSETIF, &ifr) < 0 || ioctl(fd, BIOCIMMEDIATE, &one) < 0 || ioctl(fd, BIOCSHDRCMPLT, &one) < 0 ||
        ioctl(fd, BIOCSSEESENT, &zero) < 0) {
        LOGE("BPF setup on %s: %s", f->peer, strerror(errno));
        close(fd);
        return -1;
    }
    ioctl(fd, BIOCPROMISC, NULL);  // frame 的目的地是手機的 MAC，不是 peer 自己的

    if (ioctl(fd, BIOCGBLEN, &blen) < 0) {
        close(fd);
        return -1;
    }
    f->bpf = fd;
    f->blen = blen;
    f->rbuf = malloc(blen);
    return 0;
}

int feth_create(feth_t *f, const uint8_t mac[6], int mtu) {
    memset(f, 0, sizeof *f);
    f->bpf = -1;
    strlcpy(f->host, HOST_IF, sizeof f->host);
    strlcpy(f->peer, PEER_IF, sizeof f->peer);

    char lladdr[18], m[12];
    snprintf(lladdr, sizeof lladdr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    snprintf(m, sizeof m, "%d", mtu);

    const char *c1[] = {"/sbin/ifconfig", f->host, "create", NULL};
    const char *c2[] = {"/sbin/ifconfig", f->peer, "create", NULL};
    const char *c3[] = {"/sbin/ifconfig", f->host, "lladdr", lladdr, NULL};
    const char *c4[] = {"/sbin/ifconfig", f->host, "peer", f->peer, NULL};
    const char *c5[] = {"/sbin/ifconfig", f->peer, "mtu", m, "up", NULL};
    const char *c6[] = {"/sbin/ifconfig", f->host, "mtu", m, "up", NULL};
    const char *const *steps[] = {c1, c2, c3, c4, c5, c6};
    for (size_t i = 0; i < sizeof steps / sizeof steps[0]; i++) {
        if (ifconfig(steps[i]) != 0) {
            feth_destroy(f);
            return -1;
        }
    }
    if (setup_bpf(f) != 0) {
        feth_destroy(f);
        return -1;
    }
    return 0;
}

int feth_set_ipv4(feth_t *f, uint32_t ip, uint32_t mask) {
    char a[16], b[16];
    const char *argv[] = {"/sbin/ifconfig", f->host, "inet", ip_str(ip, a), "netmask", ip_str(mask, b), NULL};
    return ifconfig(argv);
}

void feth_destroy(feth_t *f) {
    if (f->bpf >= 0) close(f->bpf);
    f->bpf = -1;
    free(f->rbuf);
    f->rbuf = NULL;
    const char *names[] = {f->host, f->peer};
    for (int i = 0; i < 2; i++) {
        if (!names[i][0] || !if_exists(names[i])) continue;
        const char *argv[] = {"/sbin/ifconfig", names[i], "destroy", NULL};
        ifconfig(argv);
    }
}

int feth_inject(feth_t *f, const uint8_t *frame, int len) {
    ssize_t n = write(f->bpf, frame, (size_t)len);
    return n == len ? 0 : -1;
}

int feth_read(feth_t *f, int timeout_ms, feth_frame_cb cb, void *ctx) {
    struct pollfd pfd = {.fd = f->bpf, .events = POLLIN};
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr == 0) return 0;
    if (pr < 0) return errno == EINTR ? 0 : -1;
    if (pfd.revents & (POLLERR | POLLNVAL)) return -1;

    ssize_t n = read(f->bpf, f->rbuf, f->blen);
    if (n < 0) return (errno == EINTR || errno == EAGAIN) ? 0 : -1;

    int frames = 0;
    uint8_t *p = f->rbuf, *end = f->rbuf + n;
    while (p + sizeof(struct bpf_hdr) <= end) {
        struct bpf_hdr *h = (struct bpf_hdr *)p;
        if (p + h->bh_hdrlen + h->bh_caplen > end) break;
        if (h->bh_caplen == h->bh_datalen && h->bh_caplen >= 14) {
            cb(ctx, p + h->bh_hdrlen, (int)h->bh_caplen);
            frames++;
        }
        p += BPF_WORDALIGN(h->bh_hdrlen + h->bh_caplen);
    }
    return frames;
}
