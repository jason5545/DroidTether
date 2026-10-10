#pragma once

#include <libusb.h>
#include <pthread.h>

#include "common.h"

typedef enum {
    DEV_RNDIS = 0,
    DEV_MBIM = 1,  // 4G/5G USB 數據機
} dev_kind;

typedef struct {
    libusb_context *ctx;
    dev_kind kind;
    libusb_device_handle *h;
    int comm_if;
    int data_if;
    uint8_t ep_in;
    uint8_t ep_out;
    uint8_t ep_int;  // 0 表示沒有中斷端點
    int out_maxpkt;
    int data_alt;            // 資料介面有 bulk 端點的 alternate setting
    uint32_t mbim_max_ctrl;  // MBIM 功能描述元的 wMaxControlMessage
    uint16_t vid, pid;
    char name[128];
    pthread_mutex_t tx_lock;  // bulk OUT 會同時被 DHCP 與轉送執行緒使用
} usbdev_t;

typedef enum {
    USB_FOUND = 0,
    USB_NOT_FOUND = 1,
    USB_BUSY = 2,            // 找到了但介面被別的程式占用
    USB_PHONE_NO_TETHER = 3, // 有 Android 手機（adb / MTP），但沒有 RNDIS
    USB_ERROR = -1,
} usb_find_result;

// 找到 RNDIS 或 MBIM 就開啟並占用介面。沒找到時，hint 會填入看得到的手機名稱（如果有）。
usb_find_result usb_find_open(libusb_context *ctx, usbdev_t *u, char *hint, size_t hint_cap);
// 在設定描述元裡找 RNDIS 或 MBIM 控制介面與配對的資料介面，填進 u（不開啟裝置）。
bool usb_match_config(const struct libusb_config_descriptor *cfg, usbdev_t *u);

void usb_close(usbdev_t *u);

// 送出一個 bulk OUT 傳輸，必要時補一個位元組避免剛好整除 max packet size（同 Linux usbnet）。
int usb_send(usbdev_t *u, uint8_t *buf, int len, int buf_cap);
