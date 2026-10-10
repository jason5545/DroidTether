#pragma once

#include <pthread.h>
#include <time.h>

#include "common.h"

#define DT_CONFIG_PATH "/Library/Application Support/DroidTether/config"
#define DT_SOCKET_PATH "/var/run/droidtetherd.sock"

typedef enum {
    ST_STARTING,
    ST_DISABLED,         // 使用者暫停
    ST_WAITING,          // 沒有接手機
    ST_PHONE_NO_TETHER,  // 接著 Android 手機，但沒開 USB 網路共用
    ST_BUSY,             // 有 RNDIS 裝置，但被別的程式占用
    ST_CONNECTING,
    ST_CONNECTED,
} dt_state;

typedef struct {
    bool enabled;
    bool primary;
    bool dns_from_phone;
    bool wifi_off;  // 連線時關掉 Wi-Fi，手機不在了再打開
    uint32_t dns[4];
    int ndns;
    int mtu;  // 只能從命令列指定，0 表示自動
    char apn[64];  // MBIM 數據機撥號用
    bool ipv6;     // MBIM 數據機要求 IPv4v6
} dt_config;

typedef struct {
    dt_state state;
    char device[128];
    char error[48];  // 錯誤代碼，App 端負責翻譯；空字串表示沒有錯誤
    char ifname[16];
    uint32_t ip, gw, mask;
    uint32_t dns[4];
    int ndns;
    bool dns_fallback;  // 手機沒回 DNS，暫時用備用 DNS
    time_t since;
    // MBIM 數據機才有
    bool modem;
    int signal_bars;  // 0～4，-1 表示不知道
    int signal_dbm;   // 0 表示不知道
    char carrier[64];
    char tech[16];
    char ipv6[64];     // "位址/prefix"，空字串表示沒有
    char dns6[2][48];  // 數據機給的 IPv6 DNS（configd 會排在 IPv4 前面）
    int ndns6;
    int pin_attempts;  // SIM 要 PIN 時剩幾次，-1 表示不知道
    bool sms_ready;    // 數據機的簡訊儲存區可以用（連線中才有）
    bool sms_full;     // 數據機的簡訊儲存區滿了
    bool sms_unsupported;  // 這支數據機送簡訊被拒過（見 sms_store.h），App 不顯示簡訊入口
} dt_status;

extern pthread_mutex_t g_state_lock;
extern dt_config g_cfg;
extern dt_status g_st;
extern atomic_ulong g_rx_bytes, g_tx_bytes;
extern atomic_bool g_dns_probe_fail;  // 測試用：當作手機不回 DNS

void config_load(const char *path);
int config_save(const char *path);
int config_parse_dns(const char *arg, dt_config *c);
// APN 只收可列印的 ASCII、不含空白，長度 1～63。
bool config_valid_apn(const char *apn);

// 換狀態；device 或 error 傳 NULL 表示不變。
void status_set(dt_state st, const char *device, const char *error);
void status_set_link(int bars, int dbm, const char *carrier, const char *tech);

// SIM PIN 存在設定檔旁邊（<設定檔>.sim-pin，只有 root 能讀寫）。被拒就立刻刪掉，絕不重試。
extern char g_pin_path[300];
bool sim_pin_load(char *out, size_t cap);
int sim_pin_save(const char *pin);
void sim_pin_forget(void);
bool sim_pin_saved(void);
bool sim_pin_valid(const char *pin);
const char *state_name(dt_state st);

// 背景執行緒：在 DT_SOCKET_PATH 接受 App 的指令。
int control_start(const char *config_path);
