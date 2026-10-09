#pragma once

#include <libusb.h>
#include <pthread.h>

#include "common.h"

typedef struct {
    libusb_context *ctx;
    libusb_device_handle *h;
    int comm_if;
    int data_if;
    uint8_t ep_in;
    uint8_t ep_out;
    uint8_t ep_int;  // 0 表示沒有中斷端點
    int out_maxpkt;
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

// 找到 RNDIS 就開啟並占用介面。沒找到時，hint 會填入看得到的手機名稱（如果有）。
usb_find_result usb_find_open(libusb_context *ctx, usbdev_t *u, char *hint, size_t hint_cap);
void usb_close(usbdev_t *u);

// 送出一個 bulk OUT 傳輸，必要時補一個位元組避免剛好整除 max packet size（同 Linux usbnet）。
int usb_send(usbdev_t *u, uint8_t *buf, int len, int buf_cap);
