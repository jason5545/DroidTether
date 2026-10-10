#pragma once

// 3GPP TS 23.040 的簡訊 PDU：收到的 SMS-DELIVER 解碼、要送的 SMS-SUBMIT 編碼。
// 字元集是 TS 23.038 的 GSM 7-bit 預設字母表（含擴充表）與 UCS-2（照 UTF-16 處理，emoji 才收得到、送得出去）。
// 跟 MBIM 無關：數據機只負責把 PDU 原封不動搬進搬出（src/mbim.c 的 SMS 服務）。
// PDU 一律以 SMSC 欄位開頭，MBIM 讀出來、送進去都是這個格式。

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define SMS_PDU_MAX 176   // SMSC(12) + SMS-SUBMIT 標頭(最多 21) + user data(140)
#define SMS_TEXT_MAX 512  // 一段解出來的 UTF-8 上限：160 個 GSM 字元，每個最多 3 bytes
#define SMS_MAX_PARTS 10  // 寫簡訊最多分幾段（中文約 670 字）

enum { SMS_DCS_GSM7, SMS_DCS_8BIT, SMS_DCS_UCS2 };

typedef struct {
    bool submit;     // SMS-SUBMIT（自己存的草稿或寄件備份）；false 是收到的 SMS-DELIVER
    char addr[48];   // 寄件者（DELIVER）或收件者（SUBMIT）："+886912345678"、"0912345678"，或英數字名稱（UTF-8）
    time_t time;     // 簡訊中心收到的時間（SCTS），UTC；SUBMIT 或解不出來是 0
    int tz_min;      // SCTS 帶的時區（分鐘）
    int pid;         // TP-PID；0x40 是不給人看的 silent SMS
    int dcs;         // SMS_DCS_*
    bool port;       // UDH 有應用程式埠（WAP push、MMS 通知），不是給人看的
    uint16_t ref;    // 多段簡訊的 reference；total <= 1 表示單則
    uint8_t total, seq;
    char text[SMS_TEXT_MAX];  // UTF-8；8-bit 資料是空字串
} sms_pdu_t;

// 解一則 SMS-DELIVER 或 SMS-SUBMIT。格式錯誤或是其他種類（狀態回報）回傳 -1。
int sms_decode(const uint8_t *pdu, int len, sms_pdu_t *out);

// 號碼只收數字，國際碼前面可加 +，3～20 位。
bool sms_valid_number(const char *to);

// 這段文字要用哪種編碼（*ucs2）、要分幾段。不是合法 UTF-8 或是空字串回傳 -1。
int sms_count_parts(const char *utf8, bool *ucs2);

// 編 SMS-SUBMIT：一段放得下就單則，放不下用 8-bit reference ref 分段（每段一個 PDU）。
// SMSC 欄位是 0（用 SIM 裡的簡訊中心）。vp 是 TP-VP（relative 格式），-1 表示不帶。
// 回傳段數；號碼不合法、文字不合法、超過 max_parts 段回傳 -1。
int sms_encode_submit(const char *to, const char *utf8, uint8_t ref, int vp, uint8_t pdu[][SMS_PDU_MAX], int len[],
                      int max_parts);
