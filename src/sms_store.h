#pragma once

// 簡訊收件匣與寄件佇列：存在設定檔旁邊（<設定檔>.sms，只有 root 能讀寫），App 透過控制 socket 讀寫。
// 收到的簡訊寫進檔案（fsync 完）才算存好，存好之後 mbim_session.c 才從數據機刪掉。
// 寄出的簡訊先排進佇列，連著數據機的那條連線拿去送，送完把結果寫回來。
// 號碼和內容不寫進 log。

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef enum {
    SMS_RECEIVED,
    SMS_QUEUED,   // 等數據機
    SMS_SENDING,
    SMS_SENT,
    SMS_FAILED,   // error 是原因代碼（App 端翻譯）
} sms_state;

typedef struct {
    uint32_t id;
    bool out;        // 寄出的
    sms_state state;
    char error[24];  // no_modem、interrupted、rejected、no_answer、partial、invalid
    time_t time;     // 收到的：簡訊中心收到的時間；寄出的：按下傳送的時間
    bool read;
    uint64_t uid;    // 收到的：PDU 的雜湊，同一則不會存兩次
    int parts;
    char number[48];
    char *text;
} sms_msg_t;

// 讀進設定檔旁邊的簡訊檔。中斷的寄件（daemon 重新啟動時還在佇列或傳送中）改成失敗，不自動重送。
void sms_store_init(const char *config_path);

// 收到的簡訊。uid 已經存過就直接回傳 true（數據機裡那份可以刪了）；寫檔失敗回傳 false。
bool sms_store_add_received(uint64_t uid, const char *number, time_t t, const char *text, int parts);
bool sms_store_has(uint64_t uid);

// 排進寄件佇列，回傳 id；寫檔失敗回傳 0。號碼與文字由呼叫的人先檢查。
uint32_t sms_store_queue(const char *number, const char *text, int parts);
// 拿下一則要寄的（改成傳送中）。text 由呼叫的人 free。
bool sms_store_next_queued(uint32_t *id, char *number, size_t cap, char **text);
void sms_store_finish(uint32_t id, const char *error);  // error 是 NULL 表示寄出了
// 排隊超過 max_age 秒還沒送出（沒有數據機）就改成失敗。
void sms_store_fail_stale(int max_age);

int sms_store_delete(uint32_t id);  // 找不到回傳 -1
void sms_store_mark_read(uint32_t id);  // 0 表示全部

// 複製一份目前的清單（時間由舊到新），用 sms_store_free 釋放。
int sms_store_snapshot(sms_msg_t **out);
void sms_store_free(sms_msg_t *m, int n);
// 每次有變動就加一，App 看到變了才重新要清單。
uint32_t sms_store_rev(void);
int sms_store_unread(void);

// 送簡訊被數據機拒絕（MBIM failure，一段都沒送出）的數據機記在設定檔旁邊（<設定檔>.sms-unsupported，一行一個 VID:PID），
// App 就不顯示簡訊入口。這支數據機之後收到或送出任何一則就清掉。
// 2026/10/10 TCL IK512 就是這樣：韌體的 IMS 與簡訊傳輸層沒開，SEND 一秒就回 failure，網路也不會把簡訊送進來。
bool sms_modem_unsupported(uint16_t vid, uint16_t pid);
void sms_modem_set_unsupported(uint16_t vid, uint16_t pid, bool unsupported);

// FNV-1a，算 uid 用。
uint64_t sms_hash(uint64_t h, const uint8_t *p, size_t n);
#define SMS_HASH_INIT 0xcbf29ce484222325ull

// 檔案裡的文字跳脫（\\ \n \t \r），控制 socket 也用同一套傳簡訊內容。回傳 dst 長度，放不下回傳 -1。
int sms_escape(const char *src, char *dst, size_t cap);
int sms_unescape(const char *src, char *dst, size_t cap);
