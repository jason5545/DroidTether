// 從設定描述元辨認 RNDIS 或 MBIM 裝置。不碰 IOKit，Linux 上的 tests/mbim_probe.c 也用這份。

#include "usb.h"

// RNDIS 控制介面的三種常見 class/subclass/protocol 組合：
// Android 用 0xEF/0x04/0x01（Misc / RNDIS over Ethernet），
// 部分裝置用 0xE0/0x01/0x03（Wireless / RNDIS），少數用 0x02/0x02/0xFF（CDC ACM vendor）。
static bool is_rndis_comm(const struct libusb_interface_descriptor *d) {
    return (d->bInterfaceClass == 0xEF && d->bInterfaceSubClass == 0x04 && d->bInterfaceProtocol == 0x01) ||
           (d->bInterfaceClass == 0xE0 && d->bInterfaceSubClass == 0x01 && d->bInterfaceProtocol == 0x03) ||
           (d->bInterfaceClass == 0x02 && d->bInterfaceSubClass == 0x02 && d->bInterfaceProtocol == 0xFF);
}

// MBIM 控制介面：CDC（0x02）/ MBIM（0x0E）/ 0x00。
static bool is_mbim_comm(const struct libusb_interface_descriptor *d) {
    return d->bInterfaceClass == 0x02 && d->bInterfaceSubClass == 0x0E && d->bInterfaceProtocol == 0x00;
}

// 控制介面附帶的 CDC 功能描述元：Union 指出配對的資料介面，MBIM 功能描述元給控制訊息的上限。
static void parse_cdc_extra(const struct libusb_interface_descriptor *c, int *slave, uint32_t *max_ctrl) {
    const uint8_t *p = c->extra;
    int n = c->extra_length;
    while (n >= 3) {
        int l = p[0];
        if (l < 3 || l > n) break;
        if (p[1] == 0x24 && p[2] == 0x06 && l >= 5) *slave = p[4];
        if (p[1] == 0x24 && p[2] == 0x1B && l >= 7) *max_ctrl = (uint32_t)(p[5] | (p[6] << 8));
        p += l;
        n -= l;
    }
}

// 在設定描述元裡找 RNDIS 或 MBIM 控制介面，以及配對的 CDC Data 介面（有 bulk 端點的那個 alternate setting）。
bool usb_match_config(const struct libusb_config_descriptor *cfg, usbdev_t *u) {
    for (int i = 0; i < cfg->bNumInterfaces; i++) {
        const struct libusb_interface *itf = &cfg->interface[i];
        if (itf->num_altsetting < 1) continue;
        const struct libusb_interface_descriptor *c = &itf->altsetting[0];
        bool mbim = is_mbim_comm(c);
        if (!mbim && !is_rndis_comm(c)) continue;

        u->kind = mbim ? DEV_MBIM : DEV_RNDIS;
        u->comm_if = c->bInterfaceNumber;
        u->ep_int = 0;
        for (int e = 0; e < c->bNumEndpoints; e++) {
            const struct libusb_endpoint_descriptor *ep = &c->endpoint[e];
            if ((ep->bmAttributes & 0x03) == LIBUSB_TRANSFER_TYPE_INTERRUPT && (ep->bEndpointAddress & 0x80))
                u->ep_int = ep->bEndpointAddress;
        }
        int slave = -1;
        u->mbim_max_ctrl = 0;
        parse_cdc_extra(c, &slave, &u->mbim_max_ctrl);

        for (int j = 0; j < cfg->bNumInterfaces; j++) {
            const struct libusb_interface *ditf = &cfg->interface[j];
            for (int a = 0; a < ditf->num_altsetting; a++) {
                const struct libusb_interface_descriptor *d = &ditf->altsetting[a];
                if (d->bInterfaceClass != 0x0A || d->bInterfaceNumber == c->bInterfaceNumber) continue;
                if (mbim && slave >= 0 && d->bInterfaceNumber != slave) continue;  // RNDIS 照舊，不靠 Union
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
                    u->data_alt = d->bAlternateSetting;
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
