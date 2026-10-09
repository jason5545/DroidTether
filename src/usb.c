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

// RNDIS 控制介面的三種常見 class/subclass/protocol 組合：
// Android 用 0xEF/0x04/0x01（Misc / RNDIS over Ethernet），
// 部分裝置用 0xE0/0x01/0x03（Wireless / RNDIS），少數用 0x02/0x02/0xFF（CDC ACM vendor）。
static bool is_rndis_comm(const struct libusb_interface_descriptor *d) {
    return (d->bInterfaceClass == 0xEF && d->bInterfaceSubClass == 0x04 && d->bInterfaceProtocol == 0x01) ||
           (d->bInterfaceClass == 0xE0 && d->bInterfaceSubClass == 0x01 && d->bInterfaceProtocol == 0x03) ||
           (d->bInterfaceClass == 0x02 && d->bInterfaceSubClass == 0x02 && d->bInterfaceProtocol == 0xFF);
}

// 在設定描述元裡找 RNDIS 控制介面和緊接著的 CDC Data 介面。
static bool match_config(const struct libusb_config_descriptor *cfg, usbdev_t *u) {
    for (int i = 0; i < cfg->bNumInterfaces; i++) {
        const struct libusb_interface *itf = &cfg->interface[i];
        if (itf->num_altsetting < 1) continue;
        const struct libusb_interface_descriptor *c = &itf->altsetting[0];
        if (!is_rndis_comm(c)) continue;

        u->comm_if = c->bInterfaceNumber;
        u->ep_int = 0;
        for (int e = 0; e < c->bNumEndpoints; e++) {
            const struct libusb_endpoint_descriptor *ep = &c->endpoint[e];
            if ((ep->bmAttributes & 0x03) == LIBUSB_TRANSFER_TYPE_INTERRUPT && (ep->bEndpointAddress & 0x80))
                u->ep_int = ep->bEndpointAddress;
        }

        for (int j = 0; j < cfg->bNumInterfaces; j++) {
            const struct libusb_interface *ditf = &cfg->interface[j];
            for (int a = 0; a < ditf->num_altsetting; a++) {
                const struct libusb_interface_descriptor *d = &ditf->altsetting[a];
                if (d->bInterfaceClass != 0x0A || d->bInterfaceNumber == c->bInterfaceNumber) continue;
                uint8_t in = 0, out = 0;
                int out_max = 0;
                for (int e = 0; e < d->bNumEndpoints; e++) {
                    const struct libusb_endpoint_descriptor *ep = &d->endpoint[e];
                    if ((ep->bmAttributes & 0x03) != LIBUSB_TRANSFER_TYPE_BULK) continue;
                    if (ep->bEndpointAddress & 0x80) {
                        in = ep->bEndpointAddress;
                    } else {
                        out = ep->bEndpointAddress;
                        out_max = ep->wMaxPacketSize;
                    }
                }
                if (in && out) {
                    u->data_if = d->bInterfaceNumber;
                    u->ep_in = in;
                    u->ep_out = out;
                    u->out_maxpkt = out_max > 0 ? out_max : 512;
                    return true;
                }
            }
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
        bool ok = match_config(cfg, &cand);
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
