#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef DT_VERSION
#define DT_VERSION "dev"
#endif

extern int g_verbose;
extern atomic_bool g_stop;   // 整個行程要結束
extern atomic_bool g_reset;  // 結束目前這次連線（暫停、改設定、手動重連）

static inline bool stopping(void) {
    return g_stop || g_reset;
}

void log_msg(const char *level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#define LOGI(...) log_msg("INFO", __VA_ARGS__)
#define LOGW(...) log_msg("WARN", __VA_ARGS__)
#define LOGE(...) log_msg("ERR ", __VA_ARGS__)
#define LOGD(...)                                  \
    do {                                           \
        if (g_verbose) log_msg("DBG ", __VA_ARGS__); \
    } while (0)

static inline void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint32_t get_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline uint16_t get_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

// 執行外部指令（不經過 shell），回傳結束碼；失敗回傳 -1。
int run_cmd(const char *const argv[]);

// 可被 g_stop / g_reset 中斷的睡眠。
void sleep_ms_interruptible(int ms);

const char *ip_str(uint32_t ip_be, char buf[16]);
