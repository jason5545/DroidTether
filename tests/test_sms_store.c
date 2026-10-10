// 收件匣檔案（src/sms_store.c）：寫進去、重新讀回來、同一則不存兩次、中斷的寄件改成失敗、內容跳脫。
// 在暫存資料夾裡跑，不碰 /Library/Application Support。

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/common.h"
#include "../src/sms_store.h"

int g_verbose;
atomic_bool g_stop;
atomic_bool g_reset;
void log_msg(const char *level, const char *fmt, ...) {
    (void)level;
    (void)fmt;
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

// sms_store 是全域狀態：重新讀檔要開一個新的行程（自己帶 --reload 再跑一次）。
static int child_reload(const char *self, const char *config) {
    pid_t pid = fork();
    if (pid == 0) {
        execl(self, self, "--reload", config, (char *)NULL);
        _exit(98);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
}

static int check_reloaded(void) {
    sms_msg_t *m;
    int n = sms_store_snapshot(&m);
    int bad = 0;
    if (n != 3) return 1;
    // 收到的：號碼、時間、內容（含換行、tab、反斜線）都要一樣，已讀狀態保留
    if (m[0].out || m[0].state != SMS_RECEIVED || strcmp(m[0].number, "0912345678") != 0 || m[0].time != 1791606896 ||
        strcmp(m[0].text, "第一行\n第二行\t\\結尾") != 0 || !m[0].read || m[0].uid != 0x1122334455667788ull)
        bad |= 2;
    // 寄出的：送完的照舊，送到一半的改成失敗（interrupted），不會自動重送
    if (!m[1].out || m[1].state != SMS_SENT || m[1].parts != 2) bad |= 4;
    if (!m[2].out || m[2].state != SMS_FAILED || strcmp(m[2].error, "interrupted") != 0) bad |= 8;
    if (!sms_store_has(0x1122334455667788ull)) bad |= 16;
    // id 接著用，不會跟舊的重複
    uint32_t id = sms_store_queue("+886912345678", "next", 1);
    if (id <= m[2].id) bad |= 32;
    sms_store_free(m, n);
    return bad;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--reload") == 0) {
        sms_store_init(argv[2]);
        return check_reloaded();
    }
    char dir[] = "/tmp/tetherline-sms-test.XXXXXX";
    if (!mkdtemp(dir)) return 2;
    char config[300], file[320];
    snprintf(config, sizeof config, "%s/config", dir);
    snprintf(file, sizeof file, "%s.sms", config);

    char esc[64], back[64];
    CHECK(sms_escape("a\\b\nc\td\re", esc, sizeof esc) > 0 && strcmp(esc, "a\\\\b\\nc\\td\\re") == 0);
    CHECK(sms_unescape(esc, back, sizeof back) > 0 && strcmp(back, "a\\b\nc\td\re") == 0);
    CHECK(sms_escape("\n\n\n", esc, 6) < 0);  // 放不下

    sms_store_init(config);  // 還沒有檔案
    sms_msg_t *m;
    CHECK(sms_store_snapshot(&m) == 0);
    sms_store_free(m, 0);
    uint32_t rev = sms_store_rev();

    CHECK(sms_store_add_received(0x1122334455667788ull, "0912345678", 1791606896, "第一行\n第二行\t\\結尾", 1));
    CHECK(sms_store_rev() != rev && sms_store_unread() == 1);
    rev = sms_store_rev();
    // 同一則（uid 一樣）再存一次：成功但不會多一筆
    CHECK(sms_store_add_received(0x1122334455667788ull, "0912345678", 1791606896, "第一行\n第二行\t\\結尾", 1));
    CHECK(sms_store_rev() == rev && sms_store_snapshot(&m) == 1);
    sms_store_free(m, 1);

    struct stat st;
    CHECK(stat(file, &st) == 0 && (st.st_mode & 0777) == 0600);  // 只有擁有者（root）能讀寫

    uint32_t a = sms_store_queue("+886912345678", "已送出", 2);
    uint32_t b = sms_store_queue("+886912345678", "送到一半", 1);
    CHECK(a && b && b > a);
    uint32_t id;
    char num[48], *text;
    CHECK(sms_store_next_queued(&id, num, sizeof num, &text) && id == a && strcmp(text, "已送出") == 0);
    free(text);
    sms_store_finish(a, NULL);
    CHECK(sms_store_next_queued(&id, num, sizeof num, &text) && id == b);
    free(text);
    CHECK(sms_store_delete(b) < 0);  // 傳送中不能刪
    CHECK(!sms_store_next_queued(&id, num, sizeof num, &text));
    sms_store_mark_read(0);
    CHECK(sms_store_unread() == 0);

    // 另一個行程重新讀檔（像 daemon 重新啟動）
    CHECK(child_reload(argv[0], config) == 0);

    // 排太久的改成失敗
    uint32_t c = sms_store_queue("0912345678", "沒有數據機", 1);
    CHECK(c);
    sms_store_fail_stale(-1);
    CHECK(sms_store_snapshot(&m) == 4 && m[3].state == SMS_FAILED && strcmp(m[3].error, "no_modem") == 0);
    sms_store_free(m, 4);
    CHECK(sms_store_delete(c) == 0 && sms_store_delete(c) < 0);

    // 送簡訊被拒的數據機：按 VID:PID 記下來，別的數據機不受影響，收到或送出一則就清掉
    CHECK(!sms_modem_unsupported(0x1bbb, 0x0530));
    sms_modem_set_unsupported(0x1bbb, 0x0530, true);
    sms_modem_set_unsupported(0x2c7c, 0x0620, true);
    CHECK(sms_modem_unsupported(0x1bbb, 0x0530) && sms_modem_unsupported(0x2c7c, 0x0620));
    CHECK(!sms_modem_unsupported(0x1bbb, 0x0531));
    sms_modem_set_unsupported(0x1bbb, 0x0530, false);
    CHECK(!sms_modem_unsupported(0x1bbb, 0x0530) && sms_modem_unsupported(0x2c7c, 0x0620));
    sms_modem_set_unsupported(0x2c7c, 0x0620, false);
    char flag[340];
    snprintf(flag, sizeof flag, "%s.sms-unsupported", config);
    CHECK(access(flag, F_OK) != 0);  // 都清掉就沒有檔案

    // 檔案寫不進去（資料夾不見了）：收到的不算存好，數據機裡的就不會被刪
    unlink(file);
    rmdir(dir);
    CHECK(!sms_store_add_received(0x99, "0911", 0, "x", 1));
    CHECK(!sms_store_has(0x99));
    CHECK(sms_store_queue("0912345678", "x", 1) == 0);

    printf("sms store: %d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
