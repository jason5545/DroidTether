#pragma once

#include "common.h"

// 連線時暫時關掉 Wi-Fi，手機不在了再打開。只打開我們自己關掉的：
// 接上前 Wi-Fi 本來就關著就不碰，連線中使用者自己打開也不再關。
// 「是我們關的」記在標記檔，daemon 當掉或重開機後還知道要開回來。
// 只在主執行緒呼叫。

void wifi_init(const char *config_path);

// tether 連上時呼叫，連線期間也定期呼叫（設定改了不用重連就生效）。
// want：設定開著，而且 tether 是主要連線。
void wifi_tether_up(bool want);

// 手機拔掉、沒開分享、暫停、連線失敗、daemon 結束時呼叫。
void wifi_tether_gone(const char *why);
