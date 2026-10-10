#include "sms_store.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"

// 檔案格式：第一行是註解，之後一行一則，欄位用 tab 分開：
//   id  in|out  狀態  錯誤代碼（沒有是 -）  時間  已讀  uid（16 位十六進位）  段數  號碼  內容（跳脫過）
// 每次變動整份重寫：先寫 .tmp、fsync，再 rename 蓋過去。

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static char path[320], unsupported_path[340];
static sms_msg_t *msgs;
static int nmsgs, capmsgs;
static uint32_t next_id = 1, rev = 1;

static const char *STATE_NAMES[] = {"received", "queued", "sending", "sent", "failed"};

uint64_t sms_hash(uint64_t h, const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

int sms_escape(const char *s, char *d, size_t cap) {
    size_t o = 0;
    for (; *s; s++) {
        char e = *s == '\\' ? '\\' : *s == '\n' ? 'n' : *s == '\t' ? 't' : *s == '\r' ? 'r' : 0;
        if (o + (e ? 2 : 1) >= cap) return -1;
        if (e) {
            d[o++] = '\\';
            d[o++] = e;
        } else {
            d[o++] = *s;
        }
    }
    d[o] = '\0';
    return (int)o;
}

int sms_unescape(const char *s, char *d, size_t cap) {
    size_t o = 0;
    for (; *s; s++) {
        char c = *s;
        if (c == '\\' && s[1]) {
            s++;
            c = *s == 'n' ? '\n' : *s == 't' ? '\t' : *s == 'r' ? '\r' : *s;
        }
        if (o + 1 >= cap) return -1;
        d[o++] = c;
    }
    d[o] = '\0';
    return (int)o;
}

static sms_msg_t *find(uint32_t id) {
    for (int i = 0; i < nmsgs; i++)
        if (msgs[i].id == id) return &msgs[i];
    return NULL;
}

static bool append(const sms_msg_t *m) {
    if (nmsgs == capmsgs) {
        int nc = capmsgs ? capmsgs * 2 : 64;
        sms_msg_t *p = realloc(msgs, (size_t)nc * sizeof *p);
        if (!p) return false;
        msgs = p;
        capmsgs = nc;
    }
    msgs[nmsgs++] = *m;
    return true;
}

static void fsync_dir(const char *file) {
    char tmp[sizeof path];
    strlcpy(tmp, file, sizeof tmp);
    int fd = open(dirname(tmp), O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }
}

static bool save_locked(void) {
    if (!path[0]) return false;
    char tmp[sizeof path + 8];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        LOGE("SMS: cannot write the inbox file: %s", strerror(errno));
        return false;
    }
    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(tmp);
        return false;
    }
    bool ok = fprintf(f, "# Tetherline SMS inbox v1 (id dir state error time read uid parts number text)\n") > 0;
    for (int i = 0; i < nmsgs && ok; i++) {
        const sms_msg_t *m = &msgs[i];
        size_t cap = strlen(m->text) * 2 + 1;
        char *esc = malloc(cap);
        if (!esc || sms_escape(m->text, esc, cap) < 0) {
            free(esc);
            ok = false;
            break;
        }
        ok = fprintf(f, "%u\t%s\t%s\t%s\t%ld\t%d\t%016llx\t%d\t%s\t%s\n", m->id, m->out ? "out" : "in",
                     STATE_NAMES[m->state], m->error[0] ? m->error : "-", (long)m->time, m->read ? 1 : 0,
                     (unsigned long long)m->uid, m->parts, m->number, esc) > 0;
        free(esc);
    }
    ok = fflush(f) == 0 && fsync(fd) == 0 && ok;
    ok = fclose(f) == 0 && ok;
    if (ok && rename(tmp, path) != 0) ok = false;
    if (!ok) {
        LOGE("SMS: saving the inbox failed: %s", strerror(errno));
        unlink(tmp);
        return false;
    }
    fsync_dir(path);
    return true;
}

void sms_store_init(const char *config_path) {
    pthread_mutex_lock(&lock);
    snprintf(path, sizeof path, "%s.sms", config_path);
    snprintf(unsupported_path, sizeof unsupported_path, "%s.sms-unsupported", config_path);
    FILE *f = fopen(path, "r");
    bool interrupted = false;
    if (f) {
        char *line = NULL;
        size_t lcap = 0;
        while (getline(&line, &lcap, f) > 0) {
            if (line[0] == '#') continue;
            line[strcspn(line, "\n")] = '\0';
            char *fld[10], *p = line;
            int k = 0;
            for (; k < 10; k++) {
                fld[k] = p;
                if (k == 9) break;
                char *t = strchr(p, '\t');
                if (!t) break;
                *t = '\0';
                p = t + 1;
            }
            if (k != 9) continue;
            sms_msg_t m = {0};
            m.id = (uint32_t)strtoul(fld[0], NULL, 10);
            m.out = strcmp(fld[1], "out") == 0;
            m.state = SMS_FAILED;
            for (int s = 0; s < 5; s++)
                if (strcmp(fld[2], STATE_NAMES[s]) == 0) m.state = (sms_state)s;
            if (strcmp(fld[3], "-") != 0) strlcpy(m.error, fld[3], sizeof m.error);
            m.time = (time_t)strtol(fld[4], NULL, 10);
            m.read = strcmp(fld[5], "1") == 0;
            m.uid = strtoull(fld[6], NULL, 16);
            m.parts = atoi(fld[7]);
            strlcpy(m.number, fld[8], sizeof m.number);
            size_t tl = strlen(fld[9]) + 1;
            m.text = malloc(tl);
            if (!m.id || !m.text || sms_unescape(fld[9], m.text, tl) < 0) {
                free(m.text);
                continue;
            }
            if (m.state == SMS_QUEUED || m.state == SMS_SENDING) {
                m.state = SMS_FAILED;  // 不知道送出去了沒，不自動重送（會重複收費）
                strlcpy(m.error, "interrupted", sizeof m.error);
                interrupted = true;
            }
            if (!append(&m)) {
                free(m.text);
                break;
            }
            if (m.id >= next_id) next_id = m.id + 1;
        }
        free(line);
        fclose(f);
    }
    if (interrupted) save_locked();
    int n = nmsgs;
    pthread_mutex_unlock(&lock);
    if (n) LOGI("SMS: %d messages in the inbox", n);
}

static sms_msg_t *find_uid(uint64_t uid) {
    for (int i = 0; i < nmsgs; i++)
        if (!msgs[i].out && msgs[i].uid == uid) return &msgs[i];
    return NULL;
}

bool sms_store_has(uint64_t uid) {
    pthread_mutex_lock(&lock);
    bool has = find_uid(uid) != NULL;
    pthread_mutex_unlock(&lock);
    return has;
}

bool sms_store_add_received(uint64_t uid, const char *number, time_t t, const char *text, int parts) {
    bool ok = true;
    pthread_mutex_lock(&lock);
    if (!find_uid(uid)) {
        sms_msg_t m = {.id = next_id, .state = SMS_RECEIVED, .time = t ? t : time(NULL), .uid = uid, .parts = parts};
        strlcpy(m.number, number, sizeof m.number);
        m.text = strdup(text);
        if (!m.text || !append(&m)) {
            free(m.text);
            ok = false;
        } else if (!save_locked()) {
            nmsgs--;
            free(m.text);
            ok = false;
        } else {
            next_id++;
            rev++;
        }
    }
    pthread_mutex_unlock(&lock);
    return ok;
}

uint32_t sms_store_queue(const char *number, const char *text, int parts) {
    uint32_t id = 0;
    pthread_mutex_lock(&lock);
    sms_msg_t m = {.id = next_id, .out = true, .state = SMS_QUEUED, .time = time(NULL), .read = true, .parts = parts};
    strlcpy(m.number, number, sizeof m.number);
    m.text = strdup(text);
    if (!m.text || !append(&m)) {
        free(m.text);
    } else if (!save_locked()) {
        nmsgs--;
        free(m.text);
    } else {
        id = next_id++;
        rev++;
    }
    pthread_mutex_unlock(&lock);
    return id;
}

bool sms_store_next_queued(uint32_t *id, char *number, size_t cap, char **text) {
    bool got = false;
    pthread_mutex_lock(&lock);
    for (int i = 0; i < nmsgs; i++) {
        sms_msg_t *m = &msgs[i];
        if (m->state != SMS_QUEUED) continue;
        *text = strdup(m->text);
        if (!*text) break;
        m->state = SMS_SENDING;
        *id = m->id;
        strlcpy(number, m->number, cap);
        save_locked();
        rev++;
        got = true;
        break;
    }
    pthread_mutex_unlock(&lock);
    return got;
}

void sms_store_finish(uint32_t id, const char *error) {
    pthread_mutex_lock(&lock);
    sms_msg_t *m = find(id);
    if (m) {
        m->state = error ? SMS_FAILED : SMS_SENT;
        strlcpy(m->error, error ? error : "", sizeof m->error);
        save_locked();
        rev++;
    }
    pthread_mutex_unlock(&lock);
}

void sms_store_fail_stale(int max_age) {
    time_t now = time(NULL);
    bool changed = false;
    pthread_mutex_lock(&lock);
    for (int i = 0; i < nmsgs; i++) {
        sms_msg_t *m = &msgs[i];
        if (m->state == SMS_QUEUED && now - m->time > max_age) {
            m->state = SMS_FAILED;
            strlcpy(m->error, "no_modem", sizeof m->error);
            changed = true;
        }
    }
    if (changed) {
        save_locked();
        rev++;
    }
    pthread_mutex_unlock(&lock);
}

int sms_store_delete(uint32_t id) {
    int rc = -1;
    pthread_mutex_lock(&lock);
    for (int i = 0; i < nmsgs; i++) {
        if (msgs[i].id != id) continue;
        if (msgs[i].state == SMS_SENDING) break;  // 送到一半不能刪
        free(msgs[i].text);
        memmove(&msgs[i], &msgs[i + 1], (size_t)(nmsgs - i - 1) * sizeof *msgs);
        nmsgs--;
        save_locked();
        rev++;
        rc = 0;
        break;
    }
    pthread_mutex_unlock(&lock);
    return rc;
}

void sms_store_mark_read(uint32_t id) {
    bool changed = false;
    pthread_mutex_lock(&lock);
    for (int i = 0; i < nmsgs; i++) {
        sms_msg_t *m = &msgs[i];
        if (!m->out && !m->read && (id == 0 || m->id == id)) {
            m->read = true;
            changed = true;
        }
    }
    if (changed) {
        save_locked();
        rev++;
    }
    pthread_mutex_unlock(&lock);
}

int sms_store_snapshot(sms_msg_t **out) {
    pthread_mutex_lock(&lock);
    int n = nmsgs;
    sms_msg_t *c = calloc((size_t)(n ? n : 1), sizeof *c);
    for (int i = 0; c && i < n; i++) {
        c[i] = msgs[i];
        c[i].text = strdup(msgs[i].text);
        if (!c[i].text) {
            sms_store_free(c, i);
            c = NULL;
        }
    }
    pthread_mutex_unlock(&lock);
    *out = c;
    return c ? n : -1;
}

void sms_store_free(sms_msg_t *m, int n) {
    for (int i = 0; m && i < n; i++) free(m[i].text);
    free(m);
}

uint32_t sms_store_rev(void) {
    pthread_mutex_lock(&lock);
    uint32_t r = rev;
    pthread_mutex_unlock(&lock);
    return r;
}

int sms_store_unread(void) {
    int n = 0;
    pthread_mutex_lock(&lock);
    for (int i = 0; i < nmsgs; i++)
        if (!msgs[i].out && !msgs[i].read) n++;
    pthread_mutex_unlock(&lock);
    return n;
}

bool sms_modem_unsupported(uint16_t vid, uint16_t pid) {
    char want[16], line[64];
    bool found = false;
    snprintf(want, sizeof want, "%04x:%04x", vid, pid);
    pthread_mutex_lock(&lock);
    FILE *f = unsupported_path[0] ? fopen(unsupported_path, "r") : NULL;
    while (f && fgets(line, sizeof line, f))
        if (strncmp(line, want, 9) == 0) found = true;
    if (f) fclose(f);
    pthread_mutex_unlock(&lock);
    return found;
}

void sms_modem_set_unsupported(uint16_t vid, uint16_t pid, bool unsupported) {
    char want[16], line[64], keep[1024] = "";
    bool found = false;
    snprintf(want, sizeof want, "%04x:%04x", vid, pid);
    pthread_mutex_lock(&lock);
    FILE *f = unsupported_path[0] ? fopen(unsupported_path, "r") : NULL;
    while (f && fgets(line, sizeof line, f)) {
        if (strncmp(line, want, 9) == 0) found = true;
        else if (strlen(keep) + strlen(line) < sizeof keep) strcat(keep, line);
    }
    if (f) fclose(f);
    if (unsupported != found && unsupported_path[0]) {
        if (unsupported) {
            size_t n = strlen(keep);
            snprintf(keep + n, sizeof keep - n, "%s\n", want);
        }
        if (!keep[0]) {
            unlink(unsupported_path);
        } else {
            int fd = open(unsupported_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            if (fd >= 0) {
                (void)!write(fd, keep, strlen(keep));
                close(fd);
            }
        }
    }
    pthread_mutex_unlock(&lock);
}
