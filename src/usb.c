#include "usb.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>

// 從 IORegistry 讀產品名稱，不需要開啟裝置（開啟會干擾 adb、MTP）。
static void product_name(uint16_t vid, uint16_t pid, char *buf, size_t cap) {
    snprintf(buf, cap, "%04x:%04x", vid, pid);
    CFMutableDictionaryRef m = IOServiceMatching("IOUSBHostDevice");
    if (!m) return;
    int v = vid, p = pid;
    CFNumberRef nv = CFNumberCreate(NULL, kCFNumberIntType, &v);
    CFNumberRef np = CFNumberCreate(NULL, kCFNumberIntType, &p);
    CFDictionarySetValue(m, CFSTR("idVendor"), nv);
    CFDictionarySetValue(m, CFSTR("idProduct"), np);
    CFRelease(nv);
    CFRelease(np);
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    if (!svc) return;
    CFTypeRef name = IORegistryEntryCreateCFProperty(svc, CFSTR("USB Product Name"), NULL, 0);
    if (name && CFGetTypeID(name) == CFStringGetTypeID()) CFStringGetCString(name, buf, (CFIndex)cap, kCFStringEncodingUTF8);
    if (name) CFRelease(name);
    IOObjectRelease(svc);
}

// adb（0xFF/0x42/0x01）或 MTP（0x06/0x01/0x01）介面，視為 Android 手機。Apple 裝置也有 PTP，排除。
static bool looks_like_android(const struct libusb_config_descriptor *cfg, uint16_t vid) {
    if (vid == 0x05AC) return false;
    for (int i = 0; i < cfg->bNumInterfaces; i++) {
        const struct libusb_interface *itf = &cfg->interface[i];
        for (int a = 0; a < itf->num_altsetting; a++) {
            const struct libusb_interface_descriptor *d = &itf->altsetting[a];
            if (d->bInterfaceClass == 0xFF && d->bInterfaceSubClass == 0x42 && d->bInterfaceProtocol == 0x01) return true;
            if (d->bInterfaceClass == 0x06 && d->bInterfaceSubClass == 0x01 && d->bInterfaceProtocol == 0x01) return true;
        }
    }
    return false;
}

usb_find_result usb_find_open(libusb_context *ctx, usbdev_t *u, char *hint, size_t hint_cap) {
    if (hint_cap) hint[0] = '\0';
    libusb_device **list = NULL;
    ssize_t n = libusb_get_device_list(ctx, &list);
    if (n < 0) {
        LOGE("libusb_get_device_list: %s", libusb_error_name((int)n));
        return USB_ERROR;
    }

    usb_find_result result = USB_NOT_FOUND;
    for (ssize_t i = 0; i < n; i++) {
        libusb_device *dev = list[i];
        struct libusb_config_descriptor *cfg = NULL;
        if (libusb_get_active_config_descriptor(dev, &cfg) != 0) continue;

        struct libusb_device_descriptor dd;
        libusb_get_device_descriptor(dev, &dd);

        usbdev_t cand;
        memset(&cand, 0, sizeof cand);
        bool ok = usb_match_config(cfg, &cand);
        bool phone = !ok && looks_like_android(cfg, dd.idVendor);
        libusb_free_config_descriptor(cfg);
        if (phone && result == USB_NOT_FOUND) {
            product_name(dd.idVendor, dd.idProduct, hint, hint_cap);
            result = USB_PHONE_NO_TETHER;
        }
        if (!ok) continue;

        libusb_device_handle *h = NULL;
        int rc = libusb_open(dev, &h);
        if (rc != 0) {
            LOGD("libusb_open %04x:%04x: %s", dd.idVendor, dd.idProduct, libusb_error_name(rc));
            product_name(dd.idVendor, dd.idProduct, hint, hint_cap);
            result = USB_BUSY;
            continue;
        }
        libusb_set_auto_detach_kernel_driver(h, 1);

        rc = libusb_claim_interface(h, cand.comm_if);
        if (rc == 0) {
            rc = libusb_claim_interface(h, cand.data_if);
            if (rc != 0) libusb_release_interface(h, cand.comm_if);
        }
        if (rc != 0) {
            LOGD("claim interface %04x:%04x: %s", dd.idVendor, dd.idProduct, libusb_error_name(rc));
            libusb_close(h);
            product_name(dd.idVendor, dd.idProduct, hint, hint_cap);
            result = USB_BUSY;
            continue;
        }

        cand.ctx = ctx;
        cand.h = h;
        cand.vid = dd.idVendor;
        cand.pid = dd.idProduct;
        cand.name[0] = '\0';
        if (dd.iProduct)
            libusb_get_string_descriptor_ascii(h, dd.iProduct, (unsigned char *)cand.name, sizeof cand.name);
        if (!cand.name[0]) product_name(dd.idVendor, dd.idProduct, cand.name, sizeof cand.name);
        pthread_mutex_init(&cand.tx_lock, NULL);

        *u = cand;
        result = USB_FOUND;
        break;
    }
    libusb_free_device_list(list, 1);
    return result;
}

void usb_close(usbdev_t *u) {
    if (!u->h) return;
    libusb_release_interface(u->h, u->data_if);
    libusb_release_interface(u->h, u->comm_if);
    libusb_close(u->h);
    u->h = NULL;
    pthread_mutex_destroy(&u->tx_lock);
}

int usb_send(usbdev_t *u, uint8_t *buf, int len, int buf_cap) {
    // 長度剛好是 max packet size 的倍數時，裝置會等下一個封包才結束這次傳輸。
    // Linux usbnet 的做法是多送一個 0，RNDIS 的 MessageLength 不變。
    if (u->out_maxpkt > 0 && len % u->out_maxpkt == 0 && len < buf_cap) buf[len++] = 0;

    pthread_mutex_lock(&u->tx_lock);
    int sent = 0;
    int rc = libusb_bulk_transfer(u->h, u->ep_out, buf, len, &sent, 2000);
    pthread_mutex_unlock(&u->tx_lock);
    if (rc != 0) return rc;
    return sent == len ? 0 : LIBUSB_ERROR_IO;
}
