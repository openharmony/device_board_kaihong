/*
 * CDC Ethernet based the networking peripherals of Huawei data card devices
 * This driver is developed based on usbnet.c and cdc_ether.c
 * Copyright (C) 2009 by Franko Fang (Huawei Technologies Co., Ltd.)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will support Huawei data card devices for Linux networking,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */



#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/workqueue.h>
#include <linux/mii.h>
#include <linux/usb.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#include <linux/usb/cdc.h>
#include <linux/usbdevice_fs.h>
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/slab.h>
/////////////////////////////////////////////////////////////////////////////////////////////////
#define DRIVER_VERSION "v0.5.4"
#define DRIVER_AUTHOR "Zhao PengFei<zhaopengfei@meigsmart.com>"
#define DRIVER_DESC "Meig ether driver for 4G data card device"
//////////////////////////////////////////////////////////////////////////////////////////////////////
#define RX_MAX_QUEUE_MEMORY (60 * 1518)
#define    RX_QLEN(dev) ( ((dev)->udev->speed == USB_SPEED_HIGH) ? \
            (RX_MAX_QUEUE_MEMORY / (dev)->rx_urb_size) : 4)
#define    TX_QLEN(dev) (((dev)->udev->speed == USB_SPEED_HIGH) ? \
            (RX_MAX_QUEUE_MEMORY / (dev)->hard_mtu) : 4)

// reawaken network queue this soon after stopping; else watchdog barks
#define TX_TIMEOUT_JIFFIES    (5 * HZ)

// throttle rx/tx briefly after some faults, so khubd might disconnect()
// us (it polls at HZ/4 usually) before we report too many false errors.
#define THROTTLE_JIFFIES    (HZ / 8)

// between wakeups
#define UNLINK_TIMEOUT_MS    3
//////////////////////////////////////////////////////////////////////////////////////////////
// randomly generated ethernet address
static u8    node_id [ETH_ALEN];

static const char driver_name [] = "hw_cdc_net";

/* use ethtool to change the level for any given device */
static int msg_level = -1;
module_param (msg_level, int, 0);
MODULE_PARM_DESC (msg_level, "Override default message level");
//////////////////////////////////////////////////////////////////////////////////////////
#define HW_TLP_MASK_SYNC   0xF800
#define HW_TLP_MASK_LENGTH 0x07FF
#define HW_TLP_BITS_SYNC   0xF800
#pragma pack(push, 1)
struct hw_cdc_tlp
{
    unsigned short pktlength;
    unsigned char payload;
};
#define HW_TLP_HDR_LENGTH sizeof(unsigned short)
#pragma pack(pop)

typedef enum __HW_TLP_BUF_STATE {
    HW_TLP_BUF_STATE_IDLE = 0,
    HW_TLP_BUF_STATE_PARTIAL_FILL,
    HW_TLP_BUF_STATE_PARTIAL_HDR,
    HW_TLP_BUF_STATE_HDR_ONLY,
    HW_TLP_BUF_STATE_ERROR
}HW_TLP_BUF_STATE;

struct hw_cdc_tlp_tmp{
    void *buffer;
    unsigned short pktlength;
    unsigned short bytesneeded;
};
/*max ethernet pkt size 1514*/
#define HW_USB_RECEIVE_BUFFER_SIZE    1600L  
/*for Tin-layer-protocol (TLP)*/
#define HW_USB_MRECEIVE_BUFFER_SIZE   4096L  
/*for TLP*/
#define HW_USB_MRECEIVE_MAX_BUFFER_SIZE (1024 * 16)  

#define HW_JUNGO_BCDDEVICE_VALUE 0x0102
#define BINTERFACESUBCLASS 0x02
#define BINTERFACESUBCLASS_HW 0x03 
///////////////////////////////////////////////////////////////////////////////////////////
#define EVENT_TX_HALT 0
#define EVENT_RX_HALT 1
#define EVENT_RX_MEMORY 2
#define EVENT_STS_SPLIT 3
#define EVENT_LINK_RESET 4


#define NCM_TX_DEFAULT_TIMEOUT_MS 2

static int ncm_prefer_32 = 1;
//module_param(ncm_prefer_32, bool, S_IRUGO);
module_param(ncm_prefer_32, int, S_IRUGO);

static int ncm_prefer_crc = 0;
//module_param(ncm_prefer_crc, bool, S_IRUGO);
module_param(ncm_prefer_crc, int, S_IRUGO);

static unsigned long ncm_tx_timeout = NCM_TX_DEFAULT_TIMEOUT_MS;
module_param(ncm_tx_timeout, ulong, S_IRUGO);

static unsigned int ncm_read_buf_count = 4;
module_param(ncm_read_buf_count, uint, S_IRUGO);

static unsigned short ncm_read_size_in1k = 4;
module_param(ncm_read_size_in1k, short , S_IRUGO);

static int rt_debug = 0;
//module_param(rt_debug, bool, S_IRUGO|S_IWUSR);
module_param(rt_debug, int, S_IRUGO | S_IWUSR);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
//#include <linux/unaligned/access_ok.h>
#else
static inline u16 get_unaligned_le16(const void *p)
{
    return le16_to_cpup((__le16 *)p);
}

static inline u32 get_unaligned_le32(const void *p)
{
    return le32_to_cpup((__le32 *)p);
}

static inline void put_unaligned_le16(u16 val, void *p)
{
    *((__le16 *)p) = cpu_to_le16(val);
}

static inline void put_unaligned_le32(u32 val, void *p)
{
    *((__le32 *)p) = cpu_to_le32(val);
}
#endif
bool deviceisBalong = false; 

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
#define LINUX_VERSION37_LATER 1
#else
#define LINUX_VERSION37_LATER 0 
#endif



/*
  >2.6.36 some syetem not find ncm.h but find cdc.h 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
#include <linux/usb/ncm.h>
#else
*/
#define USB_CDC_NCM_TYPE        0x1a

/* NCM Functional Descriptor */
/* change usb_cdc_ncm_desc -> usb_cdc_ncm_desc_hw ,prevent cdc.h redefinition 11-05*/
struct usb_cdc_ncm_desc_hw {
    __u8    bLength;
    __u8    bDescriptorType;
    __u8    bDescriptorSubType;
    __le16    bcdNcmVersion;
    __u8    bmNetworkCapabilities;
} __attribute__ ((packed));

#ifdef NCM_NCAP_ETH_FILTER 
#undef NCM_NCAP_ETH_FILTER 
#endif
#ifdef NCM_NCAP_NET_ADDRESS 
#undef NCM_NCAP_NET_ADDRESS 
#endif
#ifdef NCM_NCAP_ENCAP_COMM 
#undef NCM_NCAP_ENCAP_COMM 
#endif
#ifdef NCM_NCAP_MAX_DGRAM 
#undef NCM_NCAP_MAX_DGRAM 
#endif
#ifdef NCM_NCAP_CRC_MODE 
#undef NCM_NCAP_CRC_MODE 
#endif

#define NCM_NCAP_ETH_FILTER    (1 << 0)
#define NCM_NCAP_NET_ADDRESS    (1 << 1)
#define NCM_NCAP_ENCAP_COMM    (1 << 2)
#define NCM_NCAP_MAX_DGRAM    (1 << 3)
#define NCM_NCAP_CRC_MODE    (1 << 4)

#ifdef USB_CDC_GET_NTB_PARAMETERS 
#undef USB_CDC_GET_NTB_PARAMETERS 
#endif
#ifdef USB_CDC_GET_NET_ADDRESS 
#undef USB_CDC_GET_NET_ADDRESS 
#endif
#ifdef USB_CDC_SET_NET_ADDRESS 
#undef USB_CDC_SET_NET_ADDRESS 
#endif
#ifdef USB_CDC_GET_NTB_FORMAT 
#undef USB_CDC_GET_NTB_FORMAT 
#endif
#ifdef USB_CDC_SET_NTB_FORMAT 
#undef USB_CDC_SET_NTB_FORMAT 
#endif
#ifdef USB_CDC_GET_NTB_INPUT_SIZE 
#undef USB_CDC_GET_NTB_INPUT_SIZE 
#endif
#ifdef USB_CDC_SET_NTB_INPUT_SIZE 
#undef USB_CDC_SET_NTB_INPUT_SIZE 
#endif
#ifdef USB_CDC_GET_MAX_DATAGRAM_SIZE 
#undef USB_CDC_GET_MAX_DATAGRAM_SIZE 
#endif
#ifdef USB_CDC_SET_MAX_DATAGRAM_SIZE 
#undef USB_CDC_SET_MAX_DATAGRAM_SIZE 
#endif
#ifdef USB_CDC_GET_CRC_MODE 
#undef USB_CDC_GET_CRC_MODE 
#endif
#ifdef USB_CDC_SET_CRC_MODE 
#undef USB_CDC_SET_CRC_MODE 
#endif

#define USB_CDC_GET_NTB_PARAMETERS        0x80
#define USB_CDC_GET_NET_ADDRESS            0x81
#define USB_CDC_SET_NET_ADDRESS            0x82
#define USB_CDC_GET_NTB_FORMAT            0x83
#define USB_CDC_SET_NTB_FORMAT            0x84
#define USB_CDC_GET_NTB_INPUT_SIZE        0x85
#define USB_CDC_SET_NTB_INPUT_SIZE        0x86
#define USB_CDC_GET_MAX_DATAGRAM_SIZE        0x87
#define USB_CDC_SET_MAX_DATAGRAM_SIZE        0x88
#define USB_CDC_GET_CRC_MODE            0x89
#define USB_CDC_SET_CRC_MODE            0x8a

/*
 * Class Specific structures and constants
 *
 * CDC NCM parameter structure, CDC NCM subclass 6.2.1
 *
 */
struct usb_cdc_ncm_ntb_parameter_hw {
    __le16    wLength;
    __le16    bmNtbFormatSupported;
    __le32    dwNtbInMaxSize;
    __le16    wNdpInDivisor;
    __le16    wNdpInPayloadRemainder;
    __le16    wNdpInAlignment;
    __le16    wPadding1;
    __le32    dwNtbOutMaxSize;
    __le16    wNdpOutDivisor;
    __le16    wNdpOutPayloadRemainder;
    __le16    wNdpOutAlignment;
    __le16    wPadding2;
} __attribute__ ((packed));

/*
 * CDC NCM transfer headers, CDC NCM subclass 3.2
 */
#ifdef NCM_NTH16_SIGN 
#undef NCM_NTH16_SIGN 
#endif
#ifdef NCM_NTH32_SIGN 
#undef NCM_NTH32_SIGN 
#endif

#define NCM_NTH16_SIGN        0x484D434E /* NCMH */
#define NCM_NTH32_SIGN        0x686D636E /* ncmh */

/* change usb_cdc_ncm_nth16 -> usb_cdc_ncm_nth16_hw ,prevent cdc.h redefinition */
struct usb_cdc_ncm_nth16_hw {
    __le32    dwSignature;
    __le16    wHeaderLength;
    __le16    wSequence;
    __le16    wBlockLength;
    __le16    wFpIndex;
} __attribute__ ((packed));

/* change usb_cdc_ncm_nth32 -> usb_cdc_ncm_nth_hw ,prevent cdc.h redefinition */
struct usb_cdc_ncm_nth32_hw {
    __le32    dwSignature;
    __le16    wHeaderLength;
    __le16    wSequence;
    __le32    dwBlockLength;
    __le32    dwFpIndex;
} __attribute__ ((packed));

/*
 * CDC NCM datagram pointers, CDC NCM subclass 3.3
 */
#ifdef NCM_NDP16_CRC_SIGN 
#undef NCM_NDP16_CRC_SIGN 
#endif
#ifdef NCM_NDP16_NOCRC_SIGN 
#undef NCM_NDP16_NOCRC_SIGN 
#endif
#ifdef NCM_NDP32_CRC_SIGN 
#undef NCM_NDP32_CRC_SIGN 
#endif
#ifdef NCM_NDP32_NOCRC_SIGN 
#undef NCM_NDP32_NOCRC_SIGN 
#endif

#define NCM_NDP16_CRC_SIGN    0x314D434E /* NCM1 */
#define NCM_NDP16_NOCRC_SIGN    0x304D434E /* NCM0 */
#define NCM_NDP32_CRC_SIGN    0x316D636E /* ncm1 */
#define NCM_NDP32_NOCRC_SIGN    0x306D636E /* ncm0 */

/* change usb_cdc_ncm_ndp16 -> usb_cdc_ncm_ndp16_hw ,prevent cdc.h redefinition */
struct usb_cdc_ncm_ndp16_hw {
    __le32    dwSignature;
    __le16    wLength;
    __le16    wNextFpIndex;
    __u8    data[0];
} __attribute__ ((packed));

/* change usb_cdc_ncm_ndp32 -> usb_cdc_ncm_ndp32_hw ,prevent cdc.h redefinition */
struct usb_cdc_ncm_ndp32_hw {
    __le32    dwSignature;
    __le16    wLength;
    __le16    wReserved6;
    __le32    dwNextFpIndex;
    __le32    dwReserved12;
    __u8    data[0];
} __attribute__ ((packed));

/*
 * Here are options for NCM Datagram Pointer table (NDP) parser.
 * There are 2 different formats: NDP16 and NDP32 in the spec (ch. 3),
 * in NDP16 offsets and sizes fields are 1 16bit word wide,
 * in NDP32 -- 2 16bit words wide. Also signatures are different.
 * To make the parser code the same, put the differences in the structure,
 * and switch pointers to the structures when the format is changed.
 */

/* change usb_cdc_ncm_ndp32 -> usb_cdc_ncm_ndp32_hw ,prevent redefinition */
struct ndp_parser_opts_hw {
    u32        nth_sign;
    u32        ndp_sign;
    unsigned    nth_size;
    unsigned    ndp_size;
    unsigned    ndplen_align;
    /* sizes in u16 units */
    unsigned    dgram_item_len; /* index or length */
    unsigned    block_length;
    unsigned    fp_index;
    unsigned    reserved1;
    unsigned    reserved2;
    unsigned    next_fp_index;
};

#ifdef INIT_NDP16_OPTS 
#undef INIT_NDP16_OPTS 
#endif
#ifdef INIT_NDP32_OPTS 
#undef INIT_NDP32_OPTS 
#endif

#define INIT_NDP16_OPTS {                    \
        .nth_sign = NCM_NTH16_SIGN,            \
        .ndp_sign = NCM_NDP16_NOCRC_SIGN,        \
        .nth_size = sizeof(struct usb_cdc_ncm_nth16_hw),    \
        .ndp_size = sizeof(struct usb_cdc_ncm_ndp16_hw),    \
        .ndplen_align = 4,                \
        .dgram_item_len = 1,                \
        .block_length = 1,                \
        .fp_index = 1,                    \
        .reserved1 = 0,                    \
        .reserved2 = 0,                    \
        .next_fp_index = 1,                \
    }

#define INIT_NDP32_OPTS {                    \
        .nth_sign = NCM_NTH32_SIGN,            \
        .ndp_sign = NCM_NDP32_NOCRC_SIGN,        \
        .nth_size = sizeof(struct usb_cdc_ncm_nth32_hw),    \
        .ndp_size = sizeof(struct usb_cdc_ncm_ndp32_hw),    \
        .ndplen_align = 8,                \
        .dgram_item_len = 2,                \
        .block_length = 2,                \
        .fp_index = 2,                    \
        .reserved1 = 1,                    \
        .reserved2 = 2,                    \
        .next_fp_index = 2,                \
    }

static inline void put_ncm(__le16 **p, unsigned size, unsigned val)
{
    switch (size) {
    case 1:
        put_unaligned_le16((u16)val, *p);
        break;
    case 2:
        put_unaligned_le32((u32)val, *p);

        break;
    default:
        BUG();
    }

    *p += size;
}

static inline unsigned get_ncm(__le16 **p, unsigned size)
{
    unsigned tmp;

    switch (size) {
    case 1:
        tmp = get_unaligned_le16(*p);
        break;
    case 2:
        tmp = get_unaligned_le32(*p);
        break;
    default:
        BUG();
    }

    *p += size;
    return tmp;
}

#ifdef NCM_CONTROL_TIMEOUT 
#undef NCM_CONTROL_TIMEOUT 
#endif

#define NCM_CONTROL_TIMEOUT        (5 * 1000)
/*#endif*/

/* 'u' must be of unsigned type */
#define IS_POWER2(u) (((u) > 0) && !((u) & ((u) - 1)))

/* 'p' must designate a variable of type * __le16 (in all get/put_ncm_leXX) */
#define get_ncm_le16(p)                \
    ({ __le16 val = get_unaligned_le16(p); p += 1; val; })

#define get_ncm_le32(p)                \
    ({ __le32 val = get_unaligned_le32(p); p += 2; val; })

#define put_ncm_le16(val, p)                \
    ({ put_unaligned_le16((val), p); p += 1; })

#define put_ncm_le32(val, p)                \
    ({ put_unaligned_le32((val), p); p += 2; })

#define NCM_NDP_MIN_ALIGNMENT        4

#ifdef NCM_NTB_MIN_IN_SIZE
#undef NCM_NTB_MIN_IN_SIZE
#endif
#define NCM_NTB_MIN_IN_SIZE        2048

#ifdef NCM_NTB_MIN_OUT_SIZE
#undef NCM_NTB_MIN_OUT_SIZE
#endif

#define NCM_NDP16_ENTRY_LEN        4

/* NTB16 must include: NTB16 header, NDP16 header, datagram pointer entry,
 * terminating (NULL) datagram entry
 */
#define NCM_NTB_MIN_OUT_SIZE        (sizeof(struct usb_cdc_ncm_nth16_hw) \
    + sizeof(struct usb_cdc_ncm_ndp16_hw) + 2 * NCM_NDP16_ENTRY_LEN)

#ifndef max
#define max(_a, _b)     (((_a) > (_b)) ? (_a) : (_b))
#endif

#ifndef min
#define min(_a, _b)     (((_a) < (_b)) ? (_a) : (_b))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
#define NCM_NTB_HARD_MAX_IN_SIZE ((u32)(max(16,(int)ncm_read_size_in1k) * 1024))
#else
#define NCM_NTB_HARD_MAX_IN_SIZE ((u32)(max(2,(int)ncm_read_size_in1k) * 1024))
#endif

#define RX_QLEN_NCM ncm_read_buf_count
#define TX_QLEN_NCM 4

/* These are actually defined in usbnet.c and we need to redefine these here in
 * order to calculate the size of the SKB pool
 */


static struct ndp_parser_opts_hw ndp16_opts = INIT_NDP16_OPTS;
static struct ndp_parser_opts_hw ndp32_opts = INIT_NDP32_OPTS;

struct ndp_entry {
    struct list_head list;
    unsigned idx;
    unsigned len;
};

struct ntb {
    /* Maximum possible length of this NTB */
    unsigned max_len;
    /* The current offset of the NDP */
    unsigned ndp_off;
    /* The current length of the NDP */
    unsigned ndp_len;
    /* End of the datagrams section */
    unsigned dgrams_end;
    /* Entries list (datagram index/lenght pairs) */
    struct list_head entries;
    /* Number of datagrams in this NTB */
    unsigned ndgrams;
    /* The SKB with the actual NTB data */
    struct sk_buff *skb;
};

#define NTB_LEN(n) ((n)->ndp_off + (n)->ndp_len)
#define NTB_IS_EMPTY(n) ((n)->ndgrams == 0)

struct ncm_ctx {
    struct usb_cdc_ncm_desc_hw *ncm_desc;
    //struct usbnet *unet;
    struct hw_cdc_net *ndev;
    struct usb_interface *control;
    struct usb_interface *data;

#define NTB_FORMAT_SUPPORTED_16BIT 0x0001
#define NTB_FORMAT_SUPPORTED_32BIT 0x0002
    u16 formats;
    u32 rx_max_ntb;
    u32 tx_max_ntb;
    u16 tx_divisor;
    u16 tx_remainder;
    u16 tx_align;

#define NCM_BIT_MODE_16        0
#define NCM_BIT_MODE_32        1
    u8 bit_mode;
#define NCM_CRC_MODE_NO        0
#define NCM_CRC_MODE_YES    1
    u8 crc_mode;

    struct ndp_parser_opts_hw popts;

    struct ntb curr_ntb;
    spinlock_t tx_lock;
    struct sk_buff **skb_pool;
    unsigned skb_pool_size;
    struct timer_list tx_timer;
    /* The maximum amount of jiffies that a datagram can be held (in the
     * current-NTB) before it must be sent on the bus
     */
    unsigned long tx_timeout_jiffies;
#ifdef CONFIG_CDC_ENCAP_COMMAND
    struct cdc_encap *cdc_encap_ctx;
#endif
};


struct hw_cdc_net{
    /* housekeeping */
    struct usb_device    *udev;
    struct usb_interface    *intf;
    const char        *driver_name;
    const char         *driver_desc;
    void            *driver_priv;
    wait_queue_head_t    *wait;
    struct mutex        phy_mutex;
    unsigned char        suspend_count;

    /* i/o info: pipes etc */
    unsigned        in, out;
    struct usb_host_endpoint *status;
    unsigned        maxpacket;
    struct timer_list    delay;

    /* protocol/interface state */
    struct net_device    *net;
    struct net_device_stats    stats;
    int            msg_enable;
    unsigned long        data [5];
    u32            xid;
    u32            hard_mtu;    /* count any extra framing */
    size_t            rx_urb_size;    /* size for rx urbs */
    struct mii_if_info    mii;

    /* various kinds of pending driver work */
    struct sk_buff_head    rxq;
    struct sk_buff_head    txq; 
    struct sk_buff_head    done;
    struct urb        *interrupt;
    struct tasklet_struct    bh;

    struct work_struct    kevent;
    struct delayed_work status_work;
    int            qmi_sync;
    unsigned long        flags;

    /*The state and buffer for the data of TLP*/
    HW_TLP_BUF_STATE hw_tlp_buffer_state;
    struct hw_cdc_tlp_tmp hw_tlp_tmp_buf;
    /*indicate the download tlp feature is activated or not*/
    int hw_tlp_download_is_actived;

    /*Add for ncm */
    int is_ncm;
    struct ncm_ctx *ncm_ctx;
    
};

static inline struct usb_driver *driver_of(struct usb_interface *intf)
{
    return to_usb_driver(intf->dev.driver);
}


/* Drivers that reuse some of the standard USB CDC infrastructure
 * (notably, using multiple interfaces according to the CDC
 * union descriptor) get some helper code.
 */
struct hw_dev_state {
    struct usb_cdc_header_desc    *header;
    struct usb_cdc_union_desc    *u;
    struct usb_cdc_ether_desc    *ether;
    struct usb_interface        *control;
    struct usb_interface        *data;
};


/* we record the state for each of our queued skbs */
enum skb_state {
    illegal = 0,
    tx_start, tx_done,
    rx_start, rx_done, rx_cleanup
};

struct skb_data {    /* skb->cb is one of these */
    struct urb        *urb;
    struct hw_cdc_net        *dev;
    enum skb_state        state;
    size_t            length;
};
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define devdbg(hw_cdc_net, fmt, arg...) \
    ((void)(rt_debug && printk(KERN_ERR "Meig_cdc_driver######: " fmt "\n" , ## arg)))


#define deverr(hw_cdc_net, fmt, arg...) \
    printk(KERN_ERR "%s: " fmt "\n" , (hw_cdc_net)->net->name , ## arg)
#define devwarn(hw_cdc_net, fmt, arg...) \
    printk(KERN_WARNING "%s: " fmt "\n" , (hw_cdc_net)->net->name , ## arg)

#define devinfo(hw_cdc_net, fmt, arg...) \
    printk(KERN_INFO "%s: " fmt "\n" , (hw_cdc_net)->net->name , ## arg); \


////////////////////////////////////////////////////////////////////////////////
static void hw_cdc_status(struct hw_cdc_net *dev, struct urb *urb);
static inline int hw_get_ethernet_addr(struct hw_cdc_net *dev);
static int hw_cdc_bind(struct hw_cdc_net *dev, struct usb_interface *intf);
void hw_cdc_unbind(struct hw_cdc_net *dev, struct usb_interface *intf);
static int cdc_ncm_rx_fixup(struct hw_cdc_net *dev, struct sk_buff *skb);
static struct sk_buff * cdc_ncm_tx_fixup(struct hw_cdc_net *dev, struct sk_buff *skb,
    gfp_t mem_flags);
///////////////////////////
int hw_get_endpoints(struct hw_cdc_net *, struct usb_interface *);
void hw_skb_return (struct hw_cdc_net *, struct sk_buff *);
void hw_unlink_rx_urbs(struct hw_cdc_net *);
void hw_defer_kevent (struct hw_cdc_net *, int );
int hw_get_settings (struct net_device *, struct ethtool_cmd *);
int hw_set_settings (struct net_device *, struct ethtool_cmd *);
u32 hw_get_link (struct net_device *);
int hw_nway_reset(struct net_device *);
void hw_get_drvinfo (struct net_device *, struct ethtool_drvinfo *);
u32 hw_get_msglevel (struct net_device *);
void hw_set_msglevel (struct net_device *, u32 );
void hw_disconnect (struct usb_interface *);
int hw_cdc_probe (struct usb_interface *, const struct usb_device_id *);
int hw_resume (struct usb_interface *);
int hw_suspend (struct usb_interface *, pm_message_t );
//////////////////////////


static void hw_cdc_check_status_work(struct work_struct *work);
/*{
    struct delayed_work *option_suspend_wq
}*/









/* handles CDC Ethernet and many other network "bulk data" interfaces */
int hw_get_endpoints(struct hw_cdc_net *dev, struct usb_interface *intf)
{
    int                tmp;
    struct usb_host_interface    *alt = NULL;
    struct usb_host_endpoint    *in = NULL, *out = NULL;
    struct usb_host_endpoint    *status = NULL;

    for (tmp = 0; tmp < intf->num_altsetting; tmp++) {
        unsigned    ep;

        //in = out = status = NULL;
        in = NULL;
        out = NULL;
        status = NULL;
        alt = intf->altsetting + tmp;

        /* take the first altsetting with in-bulk + out-bulk;
         * remember any status endpoint, just in case;
         * ignore other endpoints and altsetttings.
         */
        for (ep = 0; ep < alt->desc.bNumEndpoints; ep++) {
            
            struct usb_host_endpoint    *e;
            int                intr = 0;

            e = alt->endpoint + ep;
            switch (e->desc.bmAttributes) {
            case USB_ENDPOINT_XFER_INT:
                if (!usb_endpoint_dir_in(&e->desc)){
                    continue;
                }
                intr = 1;
                /* FALLTHROUGH */
            case USB_ENDPOINT_XFER_BULK:
                break;
            default:
                continue;
            }
            if (usb_endpoint_dir_in(&e->desc)) {
                if (!intr && !in){
                    in = e;
                }else if (intr && !status){
                    status = e;
                }
            } else {
                if (!out){
                    out = e;
                }
            }
        }
        if (in && out){
            break;
        }
    }
    if (!alt || !in || !out){
        return -EINVAL;
    }
    if (alt->desc.bAlternateSetting != 0) {
        tmp = usb_set_interface (dev->udev, alt->desc.bInterfaceNumber,
                alt->desc.bAlternateSetting);
        if (tmp < 0){
            return tmp;
        }
    }

    dev->in = usb_rcvbulkpipe (dev->udev,
            in->desc.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK);
    dev->out = usb_sndbulkpipe (dev->udev,
            out->desc.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK);
    dev->status = status;
    return 0;
}
EXPORT_SYMBOL_GPL(hw_get_endpoints);

static void intr_complete (struct urb *urb);

static int init_status (struct hw_cdc_net *dev, struct usb_interface *intf)
{
    char        *buf = NULL;
    unsigned    pipe = 0;
    unsigned    maxp;
    unsigned    period;


    pipe = usb_rcvintpipe (dev->udev,
            dev->status->desc.bEndpointAddress
                & USB_ENDPOINT_NUMBER_MASK);
    maxp = usb_maxpacket (dev->udev, pipe, 0);

    /* avoid 1 msec chatter:  min 8 msec poll rate */
    period = max ((int) dev->status->desc.bInterval,
        (dev->udev->speed == USB_SPEED_HIGH) ? 7 : 3);

    buf = kmalloc (maxp, GFP_KERNEL);
    if (buf) {
        dev->interrupt = usb_alloc_urb (0, GFP_KERNEL);
        if (!dev->interrupt) {
            kfree (buf);
            return -ENOMEM;
        } else {
            usb_fill_int_urb(dev->interrupt, dev->udev, pipe,
                buf, maxp, intr_complete, dev, period);
            dev_dbg(&intf->dev,
                "status ep%din, %d bytes period %d\n",
                usb_pipeendpoint(pipe), maxp, period);
        }
    }
    return 0;
}
/*[zhaopf@meigsmart.com-2020-0903] add for higher version kernel support { */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0))
struct timespec64 current_kernel_time(void){
    struct timespec64 lTime;
    ktime_get_coarse_real_ts64(&lTime);
    return lTime;
}
#endif
/*[zhaopf@meigsmart.com-2020-0903] add for higher version kernel support } */

/* Passes this packet up the stack, updating its accounting.
 * Some link protocols batch packets, so their rx_fixup paths
 * can return clones as well as just modify the original skb.
 */
void hw_skb_return (struct hw_cdc_net *dev, struct sk_buff *skb)
{
    int    status;
    u32     sn;

    if(skb->len > 128)
    {
        sn = be32_to_cpu(*(u32 *)(skb->data + 0x26));
        devdbg(dev,"hw_skb_return,len:%d receive sn:%x,  time:%ld-%ld",
               skb->len,sn,current_kernel_time().tv_sec,current_kernel_time().tv_nsec);
    }    
    else
    {
        sn = be32_to_cpu(*(u32 *)(skb->data + 0x2a));
        devdbg(dev,"hw_skb_return,len:%d receive ack sn:%x,  time:%ld-%ld",
               skb->len,sn,current_kernel_time().tv_sec,current_kernel_time().tv_nsec);
    }

    skb->protocol = eth_type_trans (skb, dev->net);
    dev->stats.rx_packets++;
    dev->stats.rx_bytes += skb->len;

    if (netif_msg_rx_status (dev)){
        devdbg (dev, "< rx, len %zu, type 0x%x",
            skb->len + sizeof (struct ethhdr), skb->protocol);
    }
    memset (skb->cb, 0, sizeof (struct skb_data));
    status = netif_rx (skb);
    if (status != NET_RX_SUCCESS && netif_msg_rx_err (dev)){
        devdbg (dev, "netif_rx status %d", status);
    }
}
EXPORT_SYMBOL_GPL(hw_skb_return);

// unlink pending rx/tx; completion handlers do all other cleanup

static int unlink_urbs (struct hw_cdc_net *dev, struct sk_buff_head *q)
{
    unsigned long        flags;
    struct sk_buff        *skb, *skbnext;
    int            count = 0;

    spin_lock_irqsave (&q->lock, flags);
    for (skb = q->next; skb != (struct sk_buff *) q; skb = skbnext) {
        struct skb_data        *entry;
        struct urb        *urb;
        int            retval;

        entry = (struct skb_data *) skb->cb;
        urb = entry->urb;
        skbnext = skb->next;

        // during some PM-driven resume scenarios,
        // these (async) unlinks complete immediately
        retval = usb_unlink_urb (urb);
        if (retval != -EINPROGRESS && retval != 0){
            devdbg (dev, "unlink urb err, %d", retval);
        }
        else
        {
            count++;
        }
    }
    spin_unlock_irqrestore (&q->lock, flags);
    return count;
}


// Flush all pending rx urbs
// minidrivers may need to do this when the MTU changes

void hw_unlink_rx_urbs(struct hw_cdc_net *dev)
{
    if (netif_running(dev->net)) {
        (void) unlink_urbs (dev, &dev->rxq);
        tasklet_schedule(&dev->bh);
    }
}
EXPORT_SYMBOL_GPL(hw_unlink_rx_urbs);


/*-------------------------------------------------------------------------
 *
 * Network Device Driver (peer link to "Host Device", from USB host)
 *
 *-------------------------------------------------------------------------*/

static int hw_change_mtu (struct net_device *net, int new_mtu)
{
    struct hw_cdc_net    *dev = netdev_priv(net);
    int        ll_mtu = new_mtu + net->hard_header_len;
    int        old_hard_mtu = dev->hard_mtu;
    int        old_rx_urb_size = dev->rx_urb_size;


    if (new_mtu <= 0){
        return -EINVAL;
    }
    // no second zero-length packet read wanted after mtu-sized packets
    if ((ll_mtu % dev->maxpacket) == 0){
        return -EDOM;
    }
    net->mtu = new_mtu;

    dev->hard_mtu = net->mtu + net->hard_header_len;
    if (dev->rx_urb_size == old_hard_mtu && !dev->is_ncm) {
        dev->rx_urb_size = dev->hard_mtu;
        if (dev->rx_urb_size > old_rx_urb_size)
        {
            hw_unlink_rx_urbs(dev);
        }
    }

    devdbg(dev,"change mtu :%d, urb_size:%u",new_mtu,(u32)dev->rx_urb_size);

    return 0;
}

/*-------------------------------------------------------------------------*/
//#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
static struct net_device_stats *hw_get_stats (struct net_device *net)
{
    struct hw_cdc_net    *dev = netdev_priv(net);
    return &dev->stats;
}
//#endif
/*-------------------------------------------------------------------------*/

static void tx_defer_bh(struct hw_cdc_net *dev, 
                        struct sk_buff *skb, 
                        struct sk_buff_head *list)
{
    unsigned long        flags;

    spin_lock_irqsave(&list->lock, flags);
    __skb_unlink(skb, list);
    spin_unlock(&list->lock);
    spin_lock(&dev->done.lock);
    __skb_queue_tail(&dev->done, skb);
    if (1 <= dev->done.qlen){
        tasklet_schedule(&dev->bh);
    }
    spin_unlock_irqrestore(&dev->done.lock, flags);
}
////////////////////////////////////////////
static HW_TLP_BUF_STATE submit_skb(struct hw_cdc_net *dev,
                                    unsigned char *data, 
                                    unsigned int len)
{
    struct sk_buff        *skb;
    struct skb_data * entry;
    
    unsigned long flags;
    
    if (len > dev->rx_urb_size){
        devdbg(dev, "The package length is too large\n");
        return HW_TLP_BUF_STATE_ERROR;
    }
    
    if ((skb = alloc_skb (len + NET_IP_ALIGN, GFP_ATOMIC)) == NULL) {
        return HW_TLP_BUF_STATE_ERROR;
    }
    skb_reserve (skb, NET_IP_ALIGN);

    
    entry = (struct skb_data *) skb->cb;
    entry->urb = NULL;
    entry->dev = dev;
    entry->state = rx_done;
    entry->length = skb->len;

    memcpy(skb->data, data, len);
    skb->len = len;

    spin_lock_irqsave(&dev->done.lock, flags);
    __skb_queue_tail(&dev->done, skb);
    if (1 <= dev->done.qlen){
        tasklet_schedule(&dev->bh);
    }
    spin_unlock_irqrestore(&dev->done.lock, flags);
    return HW_TLP_BUF_STATE_IDLE;
}
static void reset_tlp_tmp_buf(struct hw_cdc_net *dev)
{
    dev->hw_tlp_tmp_buf.bytesneeded = 0;
    dev->hw_tlp_tmp_buf.pktlength = 0;
}
static void rx_tlp_parse(struct hw_cdc_net *dev, struct sk_buff *skb)
{
    struct hw_cdc_tlp *tlp = NULL;
    int remain_bytes = (int)skb->len;
    unsigned short pktlen = 0;
    unsigned char *cur_ptr = skb->data;
    unsigned char *payload_ptr = NULL;
    unsigned char *buf_start = skb->data;
    unsigned char *buf_end = buf_start + skb->len;
        unsigned char *ptr = NULL;

    /*decoding the TLP packets into the ether packet*/
    while (remain_bytes > 0){
        switch (dev->hw_tlp_buffer_state){
            case HW_TLP_BUF_STATE_IDLE:
            {
                if (HW_TLP_HDR_LENGTH < remain_bytes ){
                    tlp = (struct hw_cdc_tlp *)cur_ptr;
                    pktlen = (tlp->pktlength & HW_TLP_MASK_LENGTH);
                    payload_ptr = (unsigned char *)&(tlp->payload);

                    //validate the tlp packet header
                    if (HW_TLP_BITS_SYNC != (tlp->pktlength & HW_TLP_MASK_SYNC)){
                        devdbg(dev, "The pktlength is error");                
                        dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_ERROR;
                        break;
                    }
                    /*The receiced buffer has the whole ether packet */
                    if ( (payload_ptr + pktlen) <= buf_end){
                        /*Get the ether packet from the TLP packet, and put it into the done queue*/
                        submit_skb(dev, payload_ptr, pktlen);
                        cur_ptr = payload_ptr + pktlen;
                        remain_bytes = buf_end - cur_ptr;
                    }else{/*has the part of the ether packet*/
                        if (pktlen > dev->rx_urb_size){
                            devdbg(dev, "The pktlen is invalid");
                            dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_ERROR;
                            break;
                        }
                        dev->hw_tlp_tmp_buf.bytesneeded = (payload_ptr + pktlen) - buf_end;
                        dev->hw_tlp_tmp_buf.pktlength = buf_end - payload_ptr;
                        memcpy(dev->hw_tlp_tmp_buf.buffer, payload_ptr, 
                               dev->hw_tlp_tmp_buf.pktlength);
                        dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_PARTIAL_FILL;
                        remain_bytes = 0;
                    }
                }
                else if (HW_TLP_HDR_LENGTH == remain_bytes){
                    memcpy(dev->hw_tlp_tmp_buf.buffer, cur_ptr, remain_bytes);
                    dev->hw_tlp_tmp_buf.bytesneeded = 0;
                    dev->hw_tlp_tmp_buf.pktlength = remain_bytes;
                    dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_HDR_ONLY;
                    remain_bytes = 0;
                }
                else if (remain_bytes > 0){
                    memcpy(dev->hw_tlp_tmp_buf.buffer, cur_ptr, remain_bytes);
                    dev->hw_tlp_tmp_buf.bytesneeded = HW_TLP_HDR_LENGTH - remain_bytes;
                    dev->hw_tlp_tmp_buf.pktlength = remain_bytes;
                    dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_PARTIAL_HDR;
                    remain_bytes = 0;
                }
                else{
                    dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_ERROR;
                }
                break;
            }
            case HW_TLP_BUF_STATE_HDR_ONLY:
            {
                tlp->pktlength = *((unsigned short*)dev->hw_tlp_tmp_buf.buffer);
                pktlen = (tlp->pktlength & HW_TLP_MASK_LENGTH);
                payload_ptr = cur_ptr;
                reset_tlp_tmp_buf(dev);
                /*validate the tlp packet header*/
                if (HW_TLP_BITS_SYNC != (tlp->pktlength & HW_TLP_MASK_SYNC)){
                    devdbg(dev, "The pktlength is error");                
                    dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_ERROR;
                    break;
                }
                if ( (payload_ptr + pktlen) <= buf_end){
                    submit_skb(dev, payload_ptr, pktlen);
                    cur_ptr = payload_ptr + pktlen;
                    remain_bytes = buf_end - cur_ptr; 
                    dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_IDLE;
                }else{
                    if (pktlen > dev->rx_urb_size){
                        dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_ERROR;
                        break;
                    }
                    dev->hw_tlp_tmp_buf.bytesneeded = (payload_ptr + pktlen) - buf_end;
                    dev->hw_tlp_tmp_buf.pktlength = buf_end - payload_ptr;
                    memcpy(dev->hw_tlp_tmp_buf.buffer, payload_ptr, 
                           dev->hw_tlp_tmp_buf.pktlength);
                    dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_PARTIAL_FILL;
                    remain_bytes = 0;
                }
                break;
            }
            case HW_TLP_BUF_STATE_PARTIAL_HDR:
            {
                memcpy(dev->hw_tlp_tmp_buf.buffer + dev->hw_tlp_tmp_buf.pktlength, 
                       cur_ptr, dev->hw_tlp_tmp_buf.bytesneeded);
                cur_ptr += dev->hw_tlp_tmp_buf.bytesneeded;
                dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_HDR_ONLY;
                remain_bytes -= dev->hw_tlp_tmp_buf.bytesneeded;
                break;
            }
            case HW_TLP_BUF_STATE_PARTIAL_FILL:
            {
                if (remain_bytes < dev->hw_tlp_tmp_buf.bytesneeded){
                    memcpy(dev->hw_tlp_tmp_buf.buffer + dev->hw_tlp_tmp_buf.pktlength, 
                           cur_ptr, remain_bytes);
                    dev->hw_tlp_tmp_buf.pktlength += remain_bytes;
                    dev->hw_tlp_tmp_buf.bytesneeded -= remain_bytes;
                    dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_PARTIAL_FILL;
                    cur_ptr += remain_bytes;
                    remain_bytes = 0;
                }else{
                    unsigned short tmplen = dev->hw_tlp_tmp_buf.bytesneeded 
                                          + dev->hw_tlp_tmp_buf.pktlength;
                    if (HW_USB_RECEIVE_BUFFER_SIZE < tmplen){
                        devdbg(dev, "The tlp length is larger than 1600");
                        ptr = (unsigned char *)kmalloc(dev->hw_tlp_tmp_buf.bytesneeded 
                                             + dev->hw_tlp_tmp_buf.pktlength,GFP_KERNEL);
                        if (NULL != ptr){
                            memcpy(ptr, dev->hw_tlp_tmp_buf.buffer, 
                                   dev->hw_tlp_tmp_buf.pktlength);
                            memcpy(ptr + dev->hw_tlp_tmp_buf.pktlength, cur_ptr, 
                                dev->hw_tlp_tmp_buf.bytesneeded);
                            submit_skb(dev, ptr, tmplen);
                            kfree(ptr);
                        }
                        
                    }else{
                        memcpy(dev->hw_tlp_tmp_buf.buffer + dev->hw_tlp_tmp_buf.pktlength, 
                            cur_ptr, dev->hw_tlp_tmp_buf.bytesneeded);
                        submit_skb(dev, dev->hw_tlp_tmp_buf.buffer, tmplen);
                    }
                    remain_bytes -= dev->hw_tlp_tmp_buf.bytesneeded;
                    cur_ptr += dev->hw_tlp_tmp_buf.bytesneeded;
                    dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_IDLE;
                    reset_tlp_tmp_buf(dev);
                }
                break;
            }
            case HW_TLP_BUF_STATE_ERROR:
            default:
            {
                remain_bytes = 0;
                reset_tlp_tmp_buf(dev);
                dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_IDLE;
                break;
            }
        }
    }
}

static void rx_defer_bh(struct hw_cdc_net *dev, 
                        struct sk_buff *skb, 
                        struct sk_buff_head *list)
{
    unsigned long        flags;
    spin_lock_irqsave(&list->lock, flags);
    __skb_unlink(skb, list);
    spin_unlock_irqrestore(&list->lock, flags);
    
    /*deal with the download tlp feature*/
    if (1 == dev->hw_tlp_download_is_actived){
        rx_tlp_parse(dev, skb);
        dev_kfree_skb_any(skb);
    }else{
        spin_lock_irqsave(&dev->done.lock, flags);
        __skb_queue_tail(&dev->done, skb);
        if (1 <= dev->done.qlen){
            tasklet_schedule(&dev->bh);
        }
        spin_unlock_irqrestore(&dev->done.lock, flags);
    }
}
////////////////////////

/* some work can't be done in tasklets, so we use keventd
 *
 * NOTE:  annoying asymmetry:  if it's active, schedule_work() fails,
 * but tasklet_schedule() doesn't.  hope the failure is rare.
 */
void hw_defer_kevent (struct hw_cdc_net *dev, int work)
{
    set_bit (work, &dev->flags);
    if (!schedule_work (&dev->kevent)){
        deverr (dev, "kevent %d may have been dropped", work);
    }
    else{
        devdbg (dev, "kevent %d scheduled", work);
    }
}
EXPORT_SYMBOL_GPL(hw_defer_kevent);

/*-------------------------------------------------------------------------*/




static void rx_complete (struct urb *urb);
static void rx_submit (struct hw_cdc_net *dev, struct urb *urb, gfp_t flags)
{
    struct sk_buff        *skb;
    struct skb_data        *entry;
    int            retval = 0;
    unsigned long        lockflags;
    size_t            size = dev->rx_urb_size;

    
    if ((skb = alloc_skb (size + NET_IP_ALIGN, flags)) == NULL) {
        deverr (dev, "no rx skb");
        hw_defer_kevent (dev, EVENT_RX_MEMORY);
        usb_free_urb (urb);
        return;
    }
    skb_reserve (skb, NET_IP_ALIGN);

    entry = (struct skb_data *) skb->cb;
    entry->urb = urb;
    entry->dev = dev;
    entry->state = rx_start;
    entry->length = 0;


    usb_fill_bulk_urb (urb, dev->udev, dev->in,
        skb->data, size, rx_complete, skb);

    spin_lock_irqsave (&dev->rxq.lock, lockflags);


    if (netif_running (dev->net)
            && netif_device_present (dev->net)
            && !test_bit (EVENT_RX_HALT, &dev->flags)) {
        switch (retval = usb_submit_urb (urb, GFP_ATOMIC)) {

        case 0://submit successfully
            __skb_queue_tail (&dev->rxq, skb);
            break;
        case -EPIPE:
            hw_defer_kevent (dev, EVENT_RX_HALT);
            break;
        case -ENOMEM:
            hw_defer_kevent (dev, EVENT_RX_MEMORY);
            break;
        case -ENODEV:
            if (netif_msg_ifdown (dev)){
                devdbg (dev, "device gone");
            }
            netif_device_detach (dev->net);
            break;
        default:
            if (netif_msg_rx_err (dev)){
                devdbg (dev, "rx submit, %d", retval);
            }
            tasklet_schedule (&dev->bh);
            break;
        }
    } else {
        if (netif_msg_ifdown (dev)){
            devdbg (dev, "rx: stopped");
        }
        retval = -ENOLINK;
    }
    spin_unlock_irqrestore (&dev->rxq.lock, lockflags);
    
    devdbg (dev, "usb_submit_urb status:%x, time:%ld-%ld",
            retval,current_kernel_time().tv_sec,current_kernel_time().tv_nsec);

    if (retval) {

        dev_kfree_skb_any (skb);
        usb_free_urb (urb);
    }
}

/*-------------------------------------------------------------------------*/

static inline void rx_process (struct hw_cdc_net *dev, struct sk_buff *skb)
{

    if (dev->is_ncm)
    {   
        if(!cdc_ncm_rx_fixup(dev, skb)){
            goto error;
        }
    }
    if (skb->len){
        hw_skb_return (dev, skb);
    }
    else {
        if (netif_msg_rx_err (dev)){
            devdbg (dev, "drop");
        }
error:
        dev->stats.rx_errors++;
        skb_queue_tail (&dev->done, skb);
    }
}

/*-------------------------------------------------------------------------*/
static void rx_complete (struct urb *urb)
{
    struct sk_buff        *skb = (struct sk_buff *) urb->context;
    struct skb_data        *entry = (struct skb_data *) skb->cb;
    struct hw_cdc_net        *dev = entry->dev;
    int            urb_status = urb->status;


    devdbg (dev, "rx_complete,urb:%p,rx length %d, time %ld-%ld",
            urb, urb->actual_length,current_kernel_time().tv_sec,
            current_kernel_time().tv_nsec);
    skb_put (skb, urb->actual_length);
    entry->state = rx_done;
    entry->urb = NULL;

    switch (urb_status) {
    /* success */
    case 0:
        if (skb->len < dev->net->hard_header_len) {
            entry->state = rx_cleanup;
            dev->stats.rx_errors++;
            dev->stats.rx_length_errors++;
            if (netif_msg_rx_err (dev)){
                devdbg (dev, "rx length %d", skb->len);
            }
        }
        break;

    /* stalls need manual reset. this is rare ... except that
     * when going through USB 2.0 TTs, unplug appears this way.
     * we avoid the highspeed version of the ETIMEOUT/EILSEQ
     * storm, recovering as needed.
     */
    case -EPIPE:
        dev->stats.rx_errors++;
        hw_defer_kevent (dev, EVENT_RX_HALT);
        // FALLTHROUGH

    /* software-driven interface shutdown */
    case -ECONNRESET:        /* async unlink */
    case -ESHUTDOWN:        /* hardware gone */
        if (netif_msg_ifdown (dev)){
            devdbg (dev, "rx shutdown, code %d", urb_status);
        }
        goto block;

    /* we get controller i/o faults during khubd disconnect() delays.
     * throttle down resubmits, to avoid log floods; just temporarily,
     * so we still recover when the fault isn't a khubd delay.
     */
    case -EPROTO:
    case -ETIME:
    case -EILSEQ:
        dev->stats.rx_errors++;
        if (!timer_pending (&dev->delay)) {
            mod_timer (&dev->delay, jiffies + THROTTLE_JIFFIES);
            if (netif_msg_link (dev)){
                devdbg (dev, "rx throttle %d", urb_status);
            }
        }
block:
        entry->state = rx_cleanup;
        entry->urb = urb;
        urb = NULL;
        break;

    /* data overrun ... flush fifo? */
    case -EOVERFLOW:
        dev->stats.rx_over_errors++;
        // FALLTHROUGH

    default:
        entry->state = rx_cleanup;
        dev->stats.rx_errors++;
        if (netif_msg_rx_err (dev)){
            devdbg (dev, "rx status %d", urb_status);
        }
        break;
    }

    rx_defer_bh(dev, skb, &dev->rxq);

    if (urb) {
        if (netif_running (dev->net)
                && !test_bit (EVENT_RX_HALT, &dev->flags)) {
            rx_submit (dev, urb, GFP_ATOMIC);
            return;
        }
        usb_free_urb (urb);
    }
    if (netif_msg_rx_err (dev)){
        devdbg (dev, "no read resubmitted");
    }
}
static void intr_complete (struct urb *urb)
{
    struct hw_cdc_net    *dev = urb->context;
    int        status = urb->status;
    switch (status) {
    /* success */
    case 0:
        hw_cdc_status(dev, urb);
        break;

    /* software-driven interface shutdown */
    case -ENOENT:        /* urb killed */
    case -ESHUTDOWN:    /* hardware gone */
        if (netif_msg_ifdown (dev)){
            devdbg (dev, "intr shutdown, code %d", status);
        }
        return;

    /* NOTE:  not throttling like RX/TX, since this endpoint
     * already polls infrequently
     */
    default:
        devdbg (dev, "intr status %d", status);
        break;
    }

    if (!netif_running (dev->net)){
        return;
    }

    memset(urb->transfer_buffer, 0, urb->transfer_buffer_length);
    status = usb_submit_urb (urb, GFP_ATOMIC);
    if (status != 0 && netif_msg_timer (dev)){
        deverr(dev, "intr resubmit --> %d", status);
    }
}

/*-------------------------------------------------------------------------*/




/*-------------------------------------------------------------------------*/

// precondition: never called in_interrupt

static int hw_stop (struct net_device *net)
{
    struct hw_cdc_net        *dev = netdev_priv(net);
    int            temp;
    DECLARE_WAIT_QUEUE_HEAD_ONSTACK (unlink_wakeup);
    DECLARE_WAITQUEUE (wait, current);

    netif_stop_queue (net);

    if (netif_msg_ifdown (dev)){
        devinfo (dev, "stop stats: rx/tx %ld/%ld, errs %ld/%ld",
            dev->stats.rx_packets, dev->stats.tx_packets,
            dev->stats.rx_errors, dev->stats.tx_errors
            );
    }

    // ensure there are no more active urbs
    add_wait_queue (&unlink_wakeup, &wait);
    dev->wait = &unlink_wakeup;
    temp = unlink_urbs (dev, &dev->txq) + unlink_urbs (dev, &dev->rxq);

    // maybe wait for deletions to finish.
    while (!skb_queue_empty(&dev->rxq)
            && !skb_queue_empty(&dev->txq)
            && !skb_queue_empty(&dev->done)) {
        msleep(UNLINK_TIMEOUT_MS);
        if (netif_msg_ifdown (dev)){
            devdbg (dev, "waited for %d urb completions", temp);
        }
    }
    dev->wait = NULL;
    remove_wait_queue (&unlink_wakeup, &wait);

    /*cleanup the data for TLP*/
    dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_IDLE;
    if (NULL != dev->hw_tlp_tmp_buf.buffer){
        kfree(dev->hw_tlp_tmp_buf.buffer);
        dev->hw_tlp_tmp_buf.buffer = NULL;
    }
    dev->hw_tlp_tmp_buf.pktlength = 0;
    dev->hw_tlp_tmp_buf.bytesneeded = 0;

    usb_kill_urb(dev->interrupt);

    /* deferred work (task, timer, softirq) must also stop.
     * can't flush_scheduled_work() until we drop rtnl (later),
     * else workers could deadlock; so make workers a NOP.
     */
    dev->flags = 0;
    del_timer_sync (&dev->delay);
    tasklet_kill (&dev->bh);
    usb_autopm_put_interface(dev->intf);

    return 0;
}

/*-------------------------------------------------------------------------*/

// posts reads, and enables write queuing

// precondition: never called in_interrupt

static int hw_open (struct net_device *net)
{
    struct hw_cdc_net        *dev = netdev_priv(net);
    int            retval;
    if ((retval = usb_autopm_get_interface(dev->intf)) < 0) {
        if (netif_msg_ifup (dev)){
            devinfo (dev,
                "resumption fail (%d) hw_cdc_net usb-%s-%s, %s",
                retval,
                dev->udev->bus->bus_name, dev->udev->devpath,
            dev->driver_desc);
        }
        goto done_nopm;
    }    

    /*Initialized the data for TLP*/
    dev->hw_tlp_buffer_state = HW_TLP_BUF_STATE_IDLE;
    dev->hw_tlp_tmp_buf.buffer = kmalloc(HW_USB_RECEIVE_BUFFER_SIZE, GFP_KERNEL);
    if (NULL != dev->hw_tlp_tmp_buf.buffer){
        memset(dev->hw_tlp_tmp_buf.buffer, 0, HW_USB_RECEIVE_BUFFER_SIZE);
    }
    dev->hw_tlp_tmp_buf.pktlength = 0;
    dev->hw_tlp_tmp_buf.bytesneeded = 0;

    
    /* start any status interrupt transfer */
    if (dev->interrupt) {
        retval = usb_submit_urb (dev->interrupt, GFP_KERNEL);
        if (retval < 0) {
            if (netif_msg_ifup (dev)){
                deverr (dev, "intr submit %d", retval);
            }
            goto done;
        }
    }
    
    netif_start_queue (net);

    // delay posting reads until we're fully open
    tasklet_schedule (&dev->bh);
    return retval;
done:
    usb_autopm_put_interface(dev->intf);
done_nopm:
    return retval;
}

/*-------------------------------------------------------------------------*/

/* ethtool methods; minidrivers may need to add some more, but
 * they'll probably want to use this base set.
 */

int hw_get_settings (struct net_device *net, struct ethtool_cmd *cmd)
{
    struct hw_cdc_net *dev = netdev_priv(net);

    if (!dev->mii.mdio_read){
        return -EOPNOTSUPP;
    }

    return mii_ethtool_gset(&dev->mii, cmd);
}
EXPORT_SYMBOL_GPL(hw_get_settings);

int hw_set_settings (struct net_device *net, struct ethtool_cmd *cmd)
{
    struct hw_cdc_net *dev = netdev_priv(net);
    int retval;

    if (!dev->mii.mdio_write){
        return -EOPNOTSUPP;
    }

    retval = mii_ethtool_sset(&dev->mii, cmd);

    return retval;

}
EXPORT_SYMBOL_GPL(hw_set_settings);

u32 hw_get_link (struct net_device *net)
{
    struct hw_cdc_net *dev = netdev_priv(net);

    /* if the device has mii operations, use those */
    if (dev->mii.mdio_read){
        return mii_link_ok(&dev->mii);
    }

    /* Otherwise, say we're up (to avoid breaking scripts) */
    return 1;
}
EXPORT_SYMBOL_GPL(hw_get_link);

int hw_nway_reset(struct net_device *net)
{
    struct hw_cdc_net *dev = netdev_priv(net);

    if (!dev->mii.mdio_write){
        return -EOPNOTSUPP;
    }

    return mii_nway_restart(&dev->mii);
}
EXPORT_SYMBOL_GPL(hw_nway_reset);

void hw_get_drvinfo (struct net_device *net, struct ethtool_drvinfo *info)
{
    struct hw_cdc_net *dev = netdev_priv(net);

    strncpy (info->driver, dev->driver_name, sizeof info->driver);
    strncpy (info->version, DRIVER_VERSION, sizeof info->version);
    strncpy (info->fw_version, dev->driver_desc,
        sizeof info->fw_version);
    usb_make_path (dev->udev, info->bus_info, sizeof info->bus_info);
}
EXPORT_SYMBOL_GPL(hw_get_drvinfo);

u32 hw_get_msglevel (struct net_device *net)
{
    struct hw_cdc_net *dev = netdev_priv(net);

    return dev->msg_enable;
}
EXPORT_SYMBOL_GPL(hw_get_msglevel);

void hw_set_msglevel (struct net_device *net, u32 level)
{
    struct hw_cdc_net *dev = netdev_priv(net);

    dev->msg_enable = level;
}
EXPORT_SYMBOL_GPL(hw_set_msglevel);

/* drivers may override default ethtool_ops in their bind() routine */
static struct ethtool_ops hw_ethtool_ops = {
/*[zhaopf@meigsmart.com-2020-0903] add for higher version kernel support { */
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4,19,0))
    .get_settings        = hw_get_settings,
    .set_settings        = hw_set_settings,
#endif
/*[zhaopf@meigsmart.com-2020-0903] add for higher version kernel support } */
    .get_link        = hw_get_link,
    .nway_reset        = hw_nway_reset,
    .get_drvinfo        = hw_get_drvinfo,
    .get_msglevel        = hw_get_msglevel,
    .set_msglevel        = hw_set_msglevel,
};

/*-------------------------------------------------------------------------*/

/* work that cannot be done in interrupt context uses keventd.
 *
 * NOTE:  with 2.5 we could do more of this using completion callbacks,
 * especially now that control transfers can be queued.
 */
static void
kevent (struct work_struct *work)
{
    struct hw_cdc_net        *dev =
        container_of(work, struct hw_cdc_net, kevent);
    int            status;

    /* usb_clear_halt() needs a thread context */
    if (test_bit (EVENT_TX_HALT, &dev->flags)) {
        unlink_urbs (dev, &dev->txq);
        status = usb_clear_halt (dev->udev, dev->out);
        if (status < 0
                && status != -EPIPE
                && status != -ESHUTDOWN) {
            if (netif_msg_tx_err (dev)){
                deverr (dev, "can't clear tx halt, status %d",
                    status);
            }
        } else {
            clear_bit (EVENT_TX_HALT, &dev->flags);
            if (status != -ESHUTDOWN){
                netif_wake_queue (dev->net);
            }
        }
    }
    if (test_bit (EVENT_RX_HALT, &dev->flags)) {
        unlink_urbs (dev, &dev->rxq);
        status = usb_clear_halt (dev->udev, dev->in);
        if (status < 0
                && status != -EPIPE
                && status != -ESHUTDOWN) {
            if (netif_msg_rx_err (dev)){
                deverr (dev, "can't clear rx halt, status %d",
                    status);
            }
        } else {
            clear_bit (EVENT_RX_HALT, &dev->flags);
            tasklet_schedule (&dev->bh);
        }
    }

    /* tasklet could resubmit itself forever if memory is tight */
    if (test_bit (EVENT_RX_MEMORY, &dev->flags)) {
        struct urb    *urb = NULL;

        if (netif_running (dev->net)){
            urb = usb_alloc_urb (0, GFP_KERNEL);
        }else{
            clear_bit (EVENT_RX_MEMORY, &dev->flags);
        }
        if (urb != NULL) {
            clear_bit (EVENT_RX_MEMORY, &dev->flags);
            rx_submit (dev, urb, GFP_KERNEL);
            tasklet_schedule (&dev->bh);
        }
    }

    if (test_bit (EVENT_LINK_RESET, &dev->flags)) {
        clear_bit (EVENT_LINK_RESET, &dev->flags);
    }

    if (dev->flags){
        devdbg (dev, "kevent done, flags = 0x%lx",
            dev->flags);
    }
}

/*-------------------------------------------------------------------------*/

static void tx_complete (struct urb *urb)
{
    struct sk_buff        *skb = (struct sk_buff *) urb->context;
    struct skb_data        *entry = (struct skb_data *) skb->cb;
    struct hw_cdc_net        *dev = entry->dev;

    devdbg(dev,"tx_complete,status:%d,len:%d, *********time:%ld-%ld",
           urb->status,(int)entry->length,
           current_kernel_time().tv_sec,
           current_kernel_time().tv_nsec);

    if (urb->status == 0) {
        dev->stats.tx_packets++;
        dev->stats.tx_bytes += entry->length;
    } else {
        dev->stats.tx_errors++;

        switch (urb->status) {
        case -EPIPE:
            hw_defer_kevent (dev, EVENT_TX_HALT);
            break;

        /* software-driven interface shutdown */
        case -ECONNRESET:        // async unlink
        case -ESHUTDOWN:        // hardware gone
            break;

        // like rx, tx gets controller i/o faults during khubd delays
        // and so it uses the same throttling mechanism.
        case -EPROTO:
        case -ETIME:
        case -EILSEQ:
            if (!timer_pending (&dev->delay)) {
                mod_timer (&dev->delay,
                    jiffies + THROTTLE_JIFFIES);
                if (netif_msg_link (dev)){
                    devdbg (dev, "tx throttle %d",
                            urb->status);
                }
            }
            netif_stop_queue (dev->net);
            break;
        default:
            if (netif_msg_tx_err (dev)){
                devdbg (dev, "tx err %d", entry->urb->status);
            }
            break;
        }
    }

    urb->dev = NULL;
    entry->state = tx_done;
    tx_defer_bh(dev, skb, &dev->txq);
}

/*-------------------------------------------------------------------------*/

static void hw_tx_timeout (struct net_device *net, unsigned int data)
{
    struct hw_cdc_net        *dev = netdev_priv(net);

    unlink_urbs (dev, &dev->txq);
    tasklet_schedule (&dev->bh);

    // FIXME: device recovery -- reset?
}

#if LINUX_VERSION37_LATER
/*-------------------------------------------------------------------------*/

/* net_device->trans_start is expensive for high speed devices on SMP,
 * so use netdev_queue->trans_start instaed as linux suggest.
 *
 * NOTE:  from linux kernel 4.7.1,linux not support net_device->trans_start.
 * 
 */
static void hw_netif_trans_update(struct net_device *dev)
{
    struct netdev_queue *txq = NULL;

    if(NULL == dev)
    {
        printk(KERN_ERR"%s invalid dev paramter\n",__FUNCTION__);
        return;
    }

    //netdev_get_tx_queue(const struct net_device *dev,unsigned int index) only returned netdev_queue's address, 
    //so linux kernel trans index 0 to get netdev_queue's address
    txq = netdev_get_tx_queue(dev, 0);

    if(NULL == txq)
    {
        printk(KERN_ERR"%s invalid txq paramter\n",__FUNCTION__);
        return;
    }

    if(txq->trans_start != jiffies)
    {
        txq->trans_start = jiffies;
    }
}
#endif

/*-------------------------------------------------------------------------*/
