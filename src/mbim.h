#pragma once

// MBIM（Mobile Broadband Interface Model）：4G/5G USB 數據機的標準介面。
// 跟 RNDIS 手機不同，數據機本身不撥號、不配 IP：主機要用控制訊息開 session、等註冊、用 APN 撥號，
// 再用 IP_CONFIGURATION 查位址。資料是沒有乙太網路標頭的 IP 封包，包在 NCM 的 NTB16 裡。
// 這個檔案前半是不碰 USB 的編解碼（tests/test_mbim.c 測），後半是走 libusb 的控制通道。

#include <pthread.h>

#include "usb.h"

#define MBIM_OPEN_MSG 0x00000001u
#define MBIM_CLOSE_MSG 0x00000002u
#define MBIM_COMMAND_MSG 0x00000003u
#define MBIM_OPEN_DONE 0x80000001u
#define MBIM_CLOSE_DONE 0x80000002u
#define MBIM_COMMAND_DONE 0x80000003u
#define MBIM_FUNCTION_ERROR 0x80000004u
#define MBIM_INDICATE_STATUS 0x80000007u

// Basic Connect 服務的 CID
#define MBIM_CID_SUBSCRIBER_READY 2
#define MBIM_CID_RADIO_STATE 3
#define MBIM_CID_REGISTER_STATE 9
#define MBIM_CID_PACKET_SERVICE 10
#define MBIM_CID_CONNECT 12
#define MBIM_CID_IP_CONFIGURATION 15

// SUBSCRIBER_READY 的 ReadyState
#define MBIM_SIM_INITIALIZED 1
#define MBIM_SIM_NOT_INSERTED 2
#define MBIM_SIM_BAD 3
#define MBIM_SIM_FAILURE 4
#define MBIM_SIM_NOT_ACTIVATED 5
#define MBIM_SIM_LOCKED 6

// REGISTER_STATE 的 RegisterState
#define MBIM_REG_HOME 3
#define MBIM_REG_ROAMING 4
#define MBIM_REG_PARTNER 5
#define MBIM_REG_DENIED 6

// PACKET_SERVICE 的 PacketServiceState
#define MBIM_PS_ATTACHED 2

// CONNECT 的 ActivationState
#define MBIM_ACT_ACTIVATED 1
#define MBIM_ACT_DEACTIVATED 3

#define MBIM_IP_TYPE_IPV4 1

extern const uint8_t MBIM_UUID_BASIC_CONNECT[16];
extern const uint8_t MBIM_CONTEXT_INTERNET[16];

// ---------- 訊息組裝 ----------

int mbim_build_open(uint8_t *buf, int cap, uint32_t tid, uint32_t max_ctrl);
int mbim_build_close(uint8_t *buf, int cap, uint32_t tid);
int mbim_build_command(uint8_t *buf, int cap, uint32_t tid, const uint8_t uuid[16], uint32_t cid, bool set,
                       const uint8_t *info, int info_len);

// InformationBuffer，回傳長度
int mbim_info_radio_set(uint8_t *p, bool on);
int mbim_info_packet_service_set(uint8_t *p, bool attach);
int mbim_info_connect_set(uint8_t *p, int cap, uint32_t session, bool activate, const char *apn, uint32_t ip_type);
int mbim_info_connect_query(uint8_t *p, int cap, uint32_t session);
int mbim_info_ip_config_query(uint8_t *p, int cap, uint32_t session);

// ---------- 訊息解析 ----------

typedef struct {
    uint32_t type, tid;
    uint32_t status;  // *_DONE 的 Status；FUNCTION_ERROR 的 ErrorStatusCode
    uint8_t uuid[16];
    uint32_t cid;
    const uint8_t *info;
    uint32_t info_len;
} mbim_msg_t;

// 解析一則完整（已重組）的訊息。
int mbim_parse(const uint8_t *buf, int len, mbim_msg_t *m);

// 超過 MaxControlTransfer 的訊息會分段送；這裡把同一則的片段接回去。
typedef struct {
    uint8_t *buf;
    int cap;
    int len;
    uint32_t tid, type, total, next;
} mbim_reasm_t;

// 餵一段控制通道收到的資料。回傳 1 表示 r->buf 裡有一則完整訊息（長度 r->len），0 表示還要等下一段，-1 表示丟掉。
int mbim_reasm_feed(mbim_reasm_t *r, const uint8_t *frag, int len);

int mbim_parse_subscriber_ready(const uint8_t *p, uint32_t n, uint32_t *ready_state);
int mbim_parse_radio_state(const uint8_t *p, uint32_t n, uint32_t *hw, uint32_t *sw);
int mbim_parse_register_state(const uint8_t *p, uint32_t n, uint32_t *nw_error, uint32_t *state);
int mbim_parse_packet_service(const uint8_t *p, uint32_t n, uint32_t *nw_error, uint32_t *state);

typedef struct {
    uint32_t session, activation, voice, ip_type, nw_error;
    uint8_t context[16];
} mbim_connect_info_t;
int mbim_parse_connect(const uint8_t *p, uint32_t n, mbim_connect_info_t *c);

// 位址一律 network byte order。
typedef struct {
    uint32_t ip, gw;
    int prefix;  // 0 表示沒給
    uint32_t dns[4];
    int ndns;
    uint32_t mtu;  // 0 表示沒給
} mbim_ipv4_t;
int mbim_parse_ip_config(const uint8_t *p, uint32_t n, mbim_ipv4_t *out);

// 子網路遮罩（network order）：數據機給的 prefix 不一定把閘道包進來（例如 /32），那就放寬到包得住為止。
uint32_t mbim_netmask(uint32_t ip, uint32_t gw, int prefix);

const char *mbim_status_name(uint32_t status);

// ---------- NTB16（資料通道） ----------

typedef struct {
    uint16_t formats;  // bit0 NTB16、bit1 NTB32
    uint32_t in_max;   // 裝置一次最多送來多大的 NTB
    uint32_t out_max;  // 我們一次最多送多大
    uint16_t out_divisor, out_remainder, out_align, out_max_datagrams;
} ntb_params_t;

// 解析 GET_NTB_PARAMETERS 的 28 bytes。
int ntb_parse_params(const uint8_t *p, int len, ntb_params_t *o);

// 把一個 IP 封包包成 session 0 的 NTB16，回傳總長度。
int ntb16_build(uint8_t *buf, int cap, uint16_t seq, const ntb_params_t *np, const uint8_t *dgram, int dlen);

typedef void (*ntb_dgram_cb)(void *ctx, const uint8_t *d, int len);
// 解析一次 bulk IN 收到的 NTB16，session 0 的每個 IP 封包呼叫一次 cb。回傳封包數，格式錯誤回傳 -1。
int ntb16_parse(const uint8_t *buf, int len, ntb_dgram_cb cb, void *ctx);

// ---------- 系統端的乙太網路（feth） ----------

// 系統送出的 frame：
//   回傳 1：ARP 請求，reply 填好回覆的 frame（reply_len 是長度）
//   回傳 2：IPv4，*ip 指向 IP 封包
//   回傳 0：其他（IPv6 等），丟掉
int l2_from_host(const uint8_t *f, int len, uint32_t host_ip, const uint8_t gw_mac[6], uint8_t *reply, int *reply_len,
                 const uint8_t **ip, int *ip_len);
// 收到的 IPv4 封包補上乙太網路標頭，回傳 frame 長度；不是 IPv4 回傳 0。
int l2_to_host(uint8_t *frame, int cap, const uint8_t *ip, int len, const uint8_t host_mac[6], const uint8_t gw_mac[6]);

// 判斷有沒有斷線用的 ICMP echo（數據機偶爾會「連著但不通」）。
int icmp_echo_build(uint8_t *buf, int cap, uint32_t src, uint32_t dst, uint16_t id, uint16_t seq);
bool icmp_is_echo_reply(const uint8_t *ip, int len, uint32_t to, uint16_t id);

// ---------- 控制通道（libusb） ----------

typedef void (*mbim_indicate_cb)(void *ctx, const mbim_msg_t *m);

typedef struct {
    usbdev_t *u;
    uint32_t max_ctrl;
    uint32_t next_tid;
    pthread_t thr;
    bool thr_started;
    atomic_bool run;
    atomic_bool dead;
    pthread_mutex_t ctrl_lock;  // 控制傳輸一次一個
    pthread_mutex_t lock;
    pthread_cond_t cond;
    uint32_t wait_tid;
    uint8_t *resp;
    int resp_cap, resp_len;
    mbim_reasm_t reasm;
    mbim_indicate_cb on_indicate;
    void *ind_ctx;
} mbim_dev_t;

int mbim_dev_start(mbim_dev_t *d, usbdev_t *u, mbim_indicate_cb cb, void *ctx);
void mbim_dev_stop(mbim_dev_t *d);

// 先 CLOSE（上一個主機可能沒關）再 OPEN。
int mbim_dev_open(mbim_dev_t *d);
void mbim_dev_close(mbim_dev_t *d);

// 送一個 Basic Connect 指令，回應的 InformationBuffer 複製到 out，回傳長度；*status 是裝置回的 Status。
// 傳輸失敗或逾時回傳 -1。
int mbim_dev_command(mbim_dev_t *d, uint32_t cid, bool set, const uint8_t *info, int info_len, uint8_t *out, int cap,
                     uint32_t *status, int timeout_ms);

// SIM 準備好、開射頻、註冊、附著、用 APN 撥號（session 0、IPv4）、查 IP。
// 成功回傳 NULL；失敗回傳錯誤代碼（App 端翻譯）：mbim_failed、sim_missing、sim_locked、sim_failed、
// radio_off、not_registered、connect_failed。
const char *mbim_connect(mbim_dev_t *d, const char *apn, mbim_ipv4_t *ipc);
// 掛斷 session 0（盡力而為）。
void mbim_disconnect(mbim_dev_t *d);

// 讀 NTB 參數、把資料介面切到有端點的 alternate setting。
int mbim_data_start(usbdev_t *u, ntb_params_t *np);
