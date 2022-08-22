/*
 * Linux cfg80211 driver - Android related functions
 *
 * Copyright (C) 2022 Broadcom.
 *
 *      Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2 (the "GPL"),
 * available at http://www.broadcom.com/licenses/GPLv2.php, with the
 * following added to such license:
 *
 *      As a special exception, the copyright holders of this software give you
 * permission to link this software with independent modules, and to copy and
 * distribute the resulting executable under terms of your choice, provided that
 * you also meet, for each linked independent module, the terms and conditions of
 * the license of that module.  An independent module is a module which is not
 * derived from this software.  The special exception does not apply to any
 * modifications of the software.
 *
 *      Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a license
 * other than the GPL, without Broadcom's express prior written consent.
 *
 *
 * <<Broadcom-WL-IPTag/Open:>>
 *
 * $Id: wl_android.c 825470 2019-06-14 09:08:11Z $
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/netlink.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif // endif

#include <wl_android.h>
#include <wldev_common.h>
#include <wlioctl.h>
#include <wlioctl_utils.h>
#include <bcmutils.h>
#include <bcmstdlib_s.h>
#include <linux_osl.h>
#include <dhd_dbg.h>
#include <dngl_stats.h>
#include <dhd.h>
#include <dhd_config.h>
#include <bcmip.h>
#ifdef PNO_SUPPORT
#include <dhd_pno.h>
#endif // endif
#ifdef BCMSDIO
#include <bcmsdbus.h>
#endif // endif
#ifdef WL_CFG80211
#include <wl_cfg80211.h>
#include <wl_cfgscan.h>
#endif // endif
#ifdef WL_NAN
#include <wl_cfgnan.h>
#endif /* WL_NAN */
#ifdef DHDTCPACK_SUPPRESS
#include <dhd_ip.h>
#endif /* DHDTCPACK_SUPPRESS */
#include <bcmwifi_rspec.h>
#include <dhd_linux.h>
#include <bcmiov.h>
#ifdef WL_BCNRECV
#include <wl_cfgvendor.h>
#include <brcm_nl80211.h>
#endif /* WL_BCNRECV */
#ifdef WL_MBO
#include <mbo.h>
#endif /* WL_MBO */
#ifdef RTT_SUPPORT
#include <dhd_rtt.h>
#endif /* RTT_SUPPORT */
#ifdef WL_ESCAN
#include <wl_escan.h>
#endif

#ifdef WL_STATIC_IF
#define WL_BSSIDX_MAX	16
#endif /* WL_STATIC_IF */

#ifdef CONFIG_AP6XXX_WIFI6_HDF
#include "net_device.h"

extern int g_event_ifidx;
struct NetDevice * get_hdf_netdev(int ifidx);
#endif


uint android_msg_level = ANDROID_ERROR_LEVEL | ANDROID_MSG_LEVEL;

#define ANDROID_ERROR_MSG(x, args...) \
	do { \
		if (android_msg_level & ANDROID_ERROR_LEVEL) { \
			printk(KERN_ERR DHD_LOG_PREFIXS "ANDROID-ERROR) " x, ## args); \
		} \
	} while (0)
#define ANDROID_TRACE_MSG(x, args...) \
	do { \
		if (android_msg_level & ANDROID_TRACE_LEVEL) { \
			printk(KERN_INFO DHD_LOG_PREFIXS "ANDROID-TRACE) " x, ## args); \
		} \
	} while (0)
#define ANDROID_INFO_MSG(x, args...) \
	do { \
		if (android_msg_level & ANDROID_INFO_LEVEL) { \
			printk(KERN_INFO DHD_LOG_PREFIXS "ANDROID-INFO) " x, ## args); \
		} \
	} while (0)
#define ANDROID_ERROR(x) ANDROID_ERROR_MSG x
#define ANDROID_TRACE(x) ANDROID_TRACE_MSG x
#define ANDROID_INFO(x) ANDROID_INFO_MSG x

/*
 * Android private command strings, PLEASE define new private commands here
 * so they can be updated easily in the future (if needed)
 */

#define CMD_START		"START"
#define CMD_STOP		"STOP"
#define	CMD_SCAN_ACTIVE		"SCAN-ACTIVE"
#define	CMD_SCAN_PASSIVE	"SCAN-PASSIVE"
#define CMD_RSSI		"RSSI"
#define CMD_LINKSPEED		"LINKSPEED"
#define CMD_RXFILTER_START	"RXFILTER-START"
#define CMD_RXFILTER_STOP	"RXFILTER-STOP"
#define CMD_RXFILTER_ADD	"RXFILTER-ADD"
#define CMD_RXFILTER_REMOVE	"RXFILTER-REMOVE"
#define CMD_BTCOEXSCAN_START	"BTCOEXSCAN-START"
#define CMD_BTCOEXSCAN_STOP	"BTCOEXSCAN-STOP"
#define CMD_BTCOEXMODE		"BTCOEXMODE"
#define CMD_SETSUSPENDOPT	"SETSUSPENDOPT"
#define CMD_SETSUSPENDMODE      "SETSUSPENDMODE"
#define CMD_SETDTIM_IN_SUSPEND  "SET_DTIM_IN_SUSPEND"
#define CMD_MAXDTIM_IN_SUSPEND  "MAX_DTIM_IN_SUSPEND"
#define CMD_DISDTIM_IN_SUSPEND  "DISABLE_DTIM_IN_SUSPEND"
#define CMD_P2P_DEV_ADDR	"P2P_DEV_ADDR"
#define CMD_SETFWPATH		"SETFWPATH"
#define CMD_SETBAND		"SETBAND"
#define CMD_GETBAND		"GETBAND"
#define CMD_COUNTRY		"COUNTRY"
#define CMD_P2P_SET_NOA		"P2P_SET_NOA"
#define CMD_P2P_GET_NOA			"P2P_GET_NOA"
#define CMD_P2P_SD_OFFLOAD		"P2P_SD_"
#define CMD_P2P_LISTEN_OFFLOAD		"P2P_LO_"
#define CMD_P2P_SET_PS		"P2P_SET_PS"
#define CMD_P2P_ECSA		"P2P_ECSA"
#define CMD_P2P_INC_BW		"P2P_INCREASE_BW"
#define CMD_SET_AP_WPS_P2P_IE 		"SET_AP_WPS_P2P_IE"
#define CMD_SETROAMMODE 	"SETROAMMODE"
#define CMD_SETIBSSBEACONOUIDATA	"SETIBSSBEACONOUIDATA"
#define CMD_MIRACAST		"MIRACAST"
#ifdef WL_NAN
#define CMD_NAN         "NAN_"
#endif /* WL_NAN */
#define CMD_COUNTRY_DELIMITER "/"

#if defined(WL_SUPPORT_AUTO_CHANNEL)
#define CMD_GET_BEST_CHANNELS	"GET_BEST_CHANNELS"
#endif /* WL_SUPPORT_AUTO_CHANNEL */

#define CMD_80211_MODE    "MODE"  /* 802.11 mode a/b/g/n/ac */
#define CMD_CHANSPEC      "CHANSPEC"
#define CMD_DATARATE      "DATARATE"
#define CMD_ASSOC_CLIENTS "ASSOCLIST"
#define CMD_SET_CSA       "SETCSA"
#ifdef WL_SUPPORT_AUTO_CHANNEL
#define CMD_SET_HAPD_AUTO_CHANNEL	"HAPD_AUTO_CHANNEL"
#endif /* WL_SUPPORT_AUTO_CHANNEL */
#define CMD_KEEP_ALIVE		"KEEPALIVE"

#ifdef PNO_SUPPORT
#define CMD_PNOSSIDCLR_SET	"PNOSSIDCLR"
#define CMD_PNOSETUP_SET	"PNOSETUP "
#define CMD_PNOENABLE_SET	"PNOFORCE"
#define CMD_PNODEBUG_SET	"PNODEBUG"
#define CMD_WLS_BATCHING	"WLS_BATCHING"
#endif /* PNO_SUPPORT */

#define	CMD_HAPD_MAC_FILTER	"HAPD_MAC_FILTER"

#ifdef WLFBT
#define CMD_GET_FTKEY      "GET_FTKEY"
#endif // endif

#define CMD_ROAM_OFFLOAD			"SETROAMOFFLOAD"
#define CMD_INTERFACE_CREATE			"INTERFACE_CREATE"
#define CMD_INTERFACE_DELETE			"INTERFACE_DELETE"
#define CMD_GET_LINK_STATUS			"GETLINKSTATUS"

#define CMD_GET_STA_INFO   "GETSTAINFO"

/* related with CMD_GET_LINK_STATUS */
#define WL_ANDROID_LINK_VHT					0x01
#define WL_ANDROID_LINK_MIMO					0x02
#define WL_ANDROID_LINK_AP_VHT_SUPPORT		0x04
#define WL_ANDROID_LINK_AP_MIMO_SUPPORT	0x08

#ifdef P2PRESP_WFDIE_SRC
#define CMD_P2P_SET_WFDIE_RESP      "P2P_SET_WFDIE_RESP"
#define CMD_P2P_GET_WFDIE_RESP      "P2P_GET_WFDIE_RESP"
#endif /* P2PRESP_WFDIE_SRC */

#define CMD_DFS_AP_MOVE			"DFS_AP_MOVE"
#define CMD_WBTEXT_ENABLE		"WBTEXT_ENABLE"
#define CMD_WBTEXT_PROFILE_CONFIG	"WBTEXT_PROFILE_CONFIG"
#define CMD_WBTEXT_WEIGHT_CONFIG	"WBTEXT_WEIGHT_CONFIG"
#define CMD_WBTEXT_TABLE_CONFIG		"WBTEXT_TABLE_CONFIG"
#define CMD_WBTEXT_DELTA_CONFIG		"WBTEXT_DELTA_CONFIG"
#define CMD_WBTEXT_BTM_TIMER_THRESHOLD	"WBTEXT_BTM_TIMER_THRESHOLD"
#define CMD_WBTEXT_BTM_DELTA		"WBTEXT_BTM_DELTA"
#define CMD_WBTEXT_ESTM_ENABLE	"WBTEXT_ESTM_ENABLE"

#define BUFSZ 8
#define BUFSZN	BUFSZ + 1

#define _S(x) #x
#define S(x) _S(x)

#define  MAXBANDS    2  /**< Maximum #of bands */
#define BAND_2G_INDEX      0
#define BAND_5G_INDEX      0

typedef union {
	wl_roam_prof_band_v1_t v1;
	wl_roam_prof_band_v2_t v2;
	wl_roam_prof_band_v3_t v3;
} wl_roamprof_band_t;

#ifdef WLWFDS
#define CMD_ADD_WFDS_HASH	"ADD_WFDS_HASH"
#define CMD_DEL_WFDS_HASH	"DEL_WFDS_HASH"
#endif /* WLWFDS */

#ifdef SET_RPS_CPUS
#define CMD_RPSMODE  "RPSMODE"
#endif /* SET_RPS_CPUS */

#ifdef BT_WIFI_HANDOVER
#define CMD_TBOW_TEARDOWN "TBOW_TEARDOWN"
#endif /* BT_WIFI_HANDOVER */

#define CMD_MURX_BFE_CAP "MURX_BFE_CAP"

#ifdef SUPPORT_RSSI_SUM_REPORT
#define CMD_SET_RSSI_LOGGING				"SET_RSSI_LOGGING"
#define CMD_GET_RSSI_LOGGING				"GET_RSSI_LOGGING"
#define CMD_GET_RSSI_PER_ANT				"GET_RSSI_PER_ANT"
#endif /* SUPPORT_RSSI_SUM_REPORT */

#define CMD_GET_SNR							"GET_SNR"

#ifdef SUPPORT_AP_HIGHER_BEACONRATE
#define CMD_SET_AP_BEACONRATE				"SET_AP_BEACONRATE"
#define CMD_GET_AP_BASICRATE				"GET_AP_BASICRATE"
#endif /* SUPPORT_AP_HIGHER_BEACONRATE */

#ifdef SUPPORT_AP_RADIO_PWRSAVE
#define CMD_SET_AP_RPS						"SET_AP_RPS"
#define CMD_GET_AP_RPS						"GET_AP_RPS"
#define CMD_SET_AP_RPS_PARAMS				"SET_AP_RPS_PARAMS"
#endif /* SUPPORT_AP_RADIO_PWRSAVE */

#ifdef SUPPORT_AP_SUSPEND
#define CMD_SET_AP_SUSPEND			"SET_AP_SUSPEND"
#endif /* SUPPORT_AP_SUSPEND */

#ifdef SUPPORT_AP_BWCTRL
#define CMD_SET_AP_BW			"SET_AP_BW"
#define CMD_GET_AP_BW			"GET_AP_BW"
#endif /* SUPPORT_AP_BWCTRL */

/* miracast related definition */
#define MIRACAST_MODE_OFF	0
#define MIRACAST_MODE_SOURCE	1
#define MIRACAST_MODE_SINK	2

#ifdef CONNECTION_STATISTICS
#define CMD_GET_CONNECTION_STATS	"GET_CONNECTION_STATS"

struct connection_stats {
	u32 txframe;
	u32 txbyte;
	u32 txerror;
	u32 rxframe;
	u32 rxbyte;
	u32 txfail;
	u32 txretry;
	u32 txretrie;
	u32 txrts;
	u32 txnocts;
	u32 txexptime;
	u32 txrate;
	u8	chan_idle;
};
#endif /* CONNECTION_STATISTICS */

#ifdef SUPPORT_LQCM
#define CMD_SET_LQCM_ENABLE			"SET_LQCM_ENABLE"
#define CMD_GET_LQCM_REPORT			"GET_LQCM_REPORT"
#endif // endif

static LIST_HEAD(miracast_resume_list);
#ifdef WL_CFG80211
static u8 miracast_cur_mode;
#endif /* WL_CFG80211 */

#ifdef DHD_LOG_DUMP
#define CMD_NEW_DEBUG_PRINT_DUMP	"DEBUG_DUMP"
#define SUBCMD_UNWANTED			"UNWANTED"
#define SUBCMD_DISCONNECTED		"DISCONNECTED"
void dhd_log_dump_trigger(dhd_pub_t *dhdp, int subcmd);
#endif /* DHD_LOG_DUMP */

#ifdef DHD_STATUS_LOGGING
#define CMD_DUMP_STATUS_LOG		"DUMP_STAT_LOG"
#define CMD_QUERY_STATUS_LOG		"QUERY_STAT_LOG"
#endif /* DHD_STATUS_LOGGING */

#ifdef DHD_DEBUG_UART
extern bool dhd_debug_uart_is_running(struct net_device *dev);
#endif	/* DHD_DEBUG_UART */

#ifdef RTT_GEOFENCE_INTERVAL
#if defined(RTT_SUPPORT) && defined(WL_NAN)
#define CMD_GEOFENCE_INTERVAL	"GEOFENCE_INT"
#endif /* RTT_SUPPORT && WL_NAN */
#endif /* RTT_GEOFENCE_INTERVAL */

struct io_cfg {
	s8 *iovar;
	s32 param;
	u32 ioctl;
	void *arg;
	u32 len;
	struct list_head list;
};

typedef enum {
	HEAD_SAR_BACKOFF_DISABLE = -1,
	HEAD_SAR_BACKOFF_ENABLE = 0,
	GRIP_SAR_BACKOFF_DISABLE,
	GRIP_SAR_BACKOFF_ENABLE,
	NR_mmWave_SAR_BACKOFF_DISABLE,
	NR_mmWave_SAR_BACKOFF_ENABLE,
	NR_Sub6_SAR_BACKOFF_DISABLE,
	NR_Sub6_SAR_BACKOFF_ENABLE,
	SAR_BACKOFF_DISABLE_ALL
} sar_modes;

#if defined(BCMFW_ROAM_ENABLE)
#define CMD_SET_ROAMPREF	"SET_ROAMPREF"

#define MAX_NUM_SUITES		10
#define WIDTH_AKM_SUITE		8
#define JOIN_PREF_RSSI_LEN		0x02
#define JOIN_PREF_RSSI_SIZE		4	/* RSSI pref header size in bytes */
#define JOIN_PREF_WPA_HDR_SIZE		4 /* WPA pref header size in bytes */
#define JOIN_PREF_WPA_TUPLE_SIZE	12	/* Tuple size in bytes */
#define JOIN_PREF_MAX_WPA_TUPLES	16
#define MAX_BUF_SIZE		(JOIN_PREF_RSSI_SIZE + JOIN_PREF_WPA_HDR_SIZE +	\
				           (JOIN_PREF_WPA_TUPLE_SIZE * JOIN_PREF_MAX_WPA_TUPLES))
#endif /* BCMFW_ROAM_ENABLE */

#define CMD_DEBUG_VERBOSE          "DEBUG_VERBOSE"
#ifdef WL_NATOE

#define CMD_NATOE		"NATOE"

#define NATOE_MAX_PORT_NUM	65535

/* natoe command info structure */
typedef struct wl_natoe_cmd_info {
	uint8  *command;        /* pointer to the actual command */
	uint16 tot_len;        /* total length of the command */
	uint16 bytes_written;  /* Bytes written for get response */
} wl_natoe_cmd_info_t;

typedef struct wl_natoe_sub_cmd wl_natoe_sub_cmd_t;
typedef int (natoe_cmd_handler_t)(struct net_device *dev,
		const wl_natoe_sub_cmd_t *cmd, char *command, wl_natoe_cmd_info_t *cmd_info);

struct wl_natoe_sub_cmd {
	char *name;
	uint8  version;              /* cmd  version */
	uint16 id;                   /* id for the dongle f/w switch/case */
	uint16 type;                 /* base type of argument */
	natoe_cmd_handler_t *handler; /* cmd handler  */
};

#define WL_ANDROID_NATOE_FUNC(suffix) wl_android_natoe_subcmd_ ##suffix
static int wl_android_process_natoe_cmd(struct net_device *dev,
		char *command, int total_len);
static int wl_android_natoe_subcmd_enable(struct net_device *dev,
		const wl_natoe_sub_cmd_t *cmd, char *command, wl_natoe_cmd_info_t *cmd_info);
static int wl_android_natoe_subcmd_config_ips(struct net_device *dev,
		const wl_natoe_sub_cmd_t *cmd, char *command, wl_natoe_cmd_info_t *cmd_info);
static int wl_android_natoe_subcmd_config_ports(struct net_device *dev,
		const wl_natoe_sub_cmd_t *cmd, char *command, wl_natoe_cmd_info_t *cmd_info);
static int wl_android_natoe_subcmd_dbg_stats(struct net_device *dev,
		const wl_natoe_sub_cmd_t *cmd, char *command, wl_natoe_cmd_info_t *cmd_info);
static int wl_android_natoe_subcmd_tbl_cnt(struct net_device *dev,
		const wl_natoe_sub_cmd_t *cmd, char *command, wl_natoe_cmd_info_t *cmd_info);

static const wl_natoe_sub_cmd_t natoe_cmd_list[] = {
	/* wl natoe enable [0/1] or new: "wl natoe [0/1]" */
	{"enable", 0x01, WL_NATOE_CMD_ENABLE,
	IOVT_BUFFER, WL_ANDROID_NATOE_FUNC(enable)
	},
	{"config_ips", 0x01, WL_NATOE_CMD_CONFIG_IPS,
	IOVT_BUFFER, WL_ANDROID_NATOE_FUNC(config_ips)
	},
	{"config_ports", 0x01, WL_NATOE_CMD_CONFIG_PORTS,
	IOVT_BUFFER, WL_ANDROID_NATOE_FUNC(config_ports)
	},
	{"stats", 0x01, WL_NATOE_CMD_DBG_STATS,
	IOVT_BUFFER, WL_ANDROID_NATOE_FUNC(dbg_stats)
	},
	{"tbl_cnt", 0x01, WL_NATOE_CMD_TBL_CNT,
	IOVT_BUFFER, WL_ANDROID_NATOE_FUNC(tbl_cnt)
	},
	{NULL, 0, 0, 0, NULL}
};

#endif /* WL_NATOE */

#ifdef SET_PCIE_IRQ_CPU_CORE
#define CMD_PCIE_IRQ_CORE	"PCIE_IRQ_CORE"
#endif /* SET_PCIE_IRQ_CPU_CORE */

#ifdef WL_BCNRECV
#define CMD_BEACON_RECV "BEACON_RECV"
#endif /* WL_BCNRECV */
#ifdef WL_CAC_TS
#define CMD_CAC_TSPEC "CAC_TSPEC"
#endif /* WL_CAC_TS */
#ifdef WL_CHAN_UTIL
#define CMD_GET_CHAN_UTIL "GET_CU"
#endif /* WL_CHAN_UTIL */

#ifdef SUPPORT_SOFTAP_ELNA_BYPASS
#define CMD_SET_SOFTAP_ELNA_BYPASS				"SET_SOFTAP_ELNA_BYPASS"
#define CMD_GET_SOFTAP_ELNA_BYPASS				"GET_SOFTAP_ELNA_BYPASS"
#endif /* SUPPORT_SOFTAP_ELNA_BYPASS */

#ifdef WL_NAN
#define CMD_GET_NAN_STATUS	"GET_NAN_STATUS"
#endif /* WL_NAN */

/* drv command info structure */
typedef struct wl_drv_cmd_info {
	uint8  *command;        /* pointer to the actual command */
	uint16 tot_len;         /* total length of the command */
	uint16 bytes_written;   /* Bytes written for get response */
} wl_drv_cmd_info_t;

typedef struct wl_drv_sub_cmd wl_drv_sub_cmd_t;
typedef int (drv_cmd_handler_t)(struct net_device *dev,
		const wl_drv_sub_cmd_t *cmd, char *command, wl_drv_cmd_info_t *cmd_info);

struct wl_drv_sub_cmd {
	char *name;
	uint8  version;              /* cmd  version */
	uint16 id;                   /* id for the dongle f/w switch/case */
	uint16 type;                 /* base type of argument */
	drv_cmd_handler_t *handler;  /* cmd handler  */
};

#ifdef WL_MBO

#define CMD_MBO		"MBO"
enum {
	WL_MBO_CMD_NON_CHAN_PREF = 1,
	WL_MBO_CMD_CELL_DATA_CAP = 2
};
#define WL_ANDROID_MBO_FUNC(suffix) wl_android_mbo_subcmd_ ##suffix

static int wl_android_process_mbo_cmd(struct net_device *dev,
		char *command, int total_len);
static int wl_android_mbo_subcmd_cell_data_cap(struct net_device *dev,
		const wl_drv_sub_cmd_t *cmd, char *command, wl_drv_cmd_info_t *cmd_info);
static int wl_android_mbo_subcmd_non_pref_chan(struct net_device *dev,
		const wl_drv_sub_cmd_t *cmd, char *command, wl_drv_cmd_info_t *cmd_info);

static const wl_drv_sub_cmd_t mbo_cmd_list[] = {
	{"non_pref_chan", 0x01, WL_MBO_CMD_NON_CHAN_PREF,
	IOVT_BUFFER, WL_ANDROID_MBO_FUNC(non_pref_chan)
	},
	{"cell_data_cap", 0x01, WL_MBO_CMD_CELL_DATA_CAP,
	IOVT_BUFFER, WL_ANDROID_MBO_FUNC(cell_data_cap)
	},
	{NULL, 0, 0, 0, NULL}
};

#endif /* WL_MBO */

#ifdef WL_GENL
static s32 wl_genl_handle_msg(struct sk_buff *skb, struct genl_info *info);
static int wl_genl_init(void);
static int wl_genl_deinit(void);

extern struct net init_net;
/* attribute policy: defines which attribute has which type (e.g int, char * etc)
 * possible values defined in net/netlink.h
 */
static struct nla_policy wl_genl_policy[BCM_GENL_ATTR_MAX + 1] = {
	[BCM_GENL_ATTR_STRING] = { .type = NLA_NUL_STRING },
	[BCM_GENL_ATTR_MSG] = { .type = NLA_BINARY },
};

#define WL_GENL_VER 1
/* family definition */
static struct genl_family wl_genl_family = {
	.id = GENL_ID_GENERATE,    /* Genetlink would generate the ID */
	.hdrsize = 0,
	.name = "bcm-genl",        /* Netlink I/F for Android */
	.version = WL_GENL_VER,     /* Version Number */
	.maxattr = BCM_GENL_ATTR_MAX,
};

/* commands: mapping between the command enumeration and the actual function */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0))
struct genl_ops wl_genl_ops[] = {
	{
	.cmd = BCM_GENL_CMD_MSG,
	.flags = 0,
	.policy = wl_genl_policy,
	.doit = wl_genl_handle_msg,
	.dumpit = NULL,
	},
};
#else
struct genl_ops wl_genl_ops = {
	.cmd = BCM_GENL_CMD_MSG,
	.flags = 0,
	.policy = wl_genl_policy,
	.doit = wl_genl_handle_msg,
	.dumpit = NULL,

};
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0) */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0))
static struct genl_multicast_group wl_genl_mcast[] = {
	 { .name = "bcm-genl-mcast", },
};
#else
static struct genl_multicast_group wl_genl_mcast = {
	.id = GENL_ID_GENERATE,    /* Genetlink would generate the ID */
	.name = "bcm-genl-mcast",
};
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0) */
#endif /* WL_GENL */

#ifdef SUPPORT_LQCM
#define LQCM_ENAB_MASK			0x000000FF	/* LQCM enable flag mask */
#define LQCM_TX_INDEX_MASK		0x0000FF00	/* LQCM tx index mask */
#define LQCM_RX_INDEX_MASK		0x00FF0000	/* LQCM rx index mask */

#define LQCM_TX_INDEX_SHIFT		8	/* LQCM tx index shift */
#define LQCM_RX_INDEX_SHIFT		16	/* LQCM rx index shift */
#endif /* SUPPORT_LQCM */

#ifdef DHD_SEND_HANG_PRIVCMD_ERRORS
#define NUMBER_SEQUENTIAL_PRIVCMD_ERRORS	7
static int priv_cmd_errors = 0;
#endif /* DHD_SEND_HANG_PRIVCMD_ERRORS */

/**
 * Extern function declarations (TODO: move them to dhd_linux.h)
 */
int dhd_net_bus_devreset(struct net_device *dev, uint8 flag);
int dhd_dev_init_ioctl(struct net_device *dev);
#ifdef WL_CFG80211
int wl_cfg80211_get_p2p_dev_addr(struct net_device *net, struct ether_addr *p2pdev_addr);
int wl_cfg80211_set_btcoex_dhcp(struct net_device *dev, dhd_pub_t *dhd, char *command);
#else
int wl_cfg80211_get_p2p_dev_addr(struct net_device *net, struct ether_addr *p2pdev_addr)
{ return 0; }
int wl_cfg80211_set_p2p_noa(struct net_device *net, char* buf, int len)
{ return 0; }
int wl_cfg80211_get_p2p_noa(struct net_device *net, char* buf, int len)
{ return 0; }
int wl_cfg80211_set_p2p_ps(struct net_device *net, char* buf, int len)
{ return 0; }
int wl_cfg80211_set_p2p_ecsa(struct net_device *net, char* buf, int len)
{ return 0; }
int wl_cfg80211_increase_p2p_bw(struct net_device *net, char* buf, int len)
{ return 0; }
#endif /* WL_CFG80211 */
#ifdef ROAM_CHANNEL_CACHE
extern void wl_update_roamscan_cache_by_band(struct net_device *dev, int band);
#endif /* ROAM_CHANNEL_CACHE */

#ifdef ENABLE_4335BT_WAR
extern int bcm_bt_lock(int cookie);
extern void bcm_bt_unlock(int cookie);
static int lock_cookie_wifi = 'W' | 'i'<<8 | 'F'<<16 | 'i'<<24;	/* cookie is "WiFi" */
#endif /* ENABLE_4335BT_WAR */

extern bool ap_fw_loaded;
extern char iface_name[IFNAMSIZ];
#ifdef DHD_PM_CONTROL_FROM_FILE
extern bool g_pm_control;
#endif	/* DHD_PM_CONTROL_FROM_FILE */

/* private command support for restoring roam/scan parameters */
#ifdef SUPPORT_RESTORE_SCAN_PARAMS
#define CMD_RESTORE_SCAN_PARAMS "RESTORE_SCAN_PARAMS"

typedef int (*PRIV_CMD_HANDLER) (struct net_device *dev, char *command);
typedef int (*PRIV_CMD_HANDLER_WITH_LEN) (struct net_device *dev, char *command, int total_len);

enum {
	RESTORE_TYPE_UNSPECIFIED = 0,
	RESTORE_TYPE_PRIV_CMD = 1,
	RESTORE_TYPE_PRIV_CMD_WITH_LEN = 2
};

typedef struct android_restore_scan_params {
	char command[64];
	int parameter;
	int cmd_type;
	union {
		PRIV_CMD_HANDLER cmd_handler;
		PRIV_CMD_HANDLER_WITH_LEN cmd_handler_w_len;
	};
} android_restore_scan_params_t;

/* function prototypes of private command handler */
static int wl_android_set_roam_trigger(struct net_device *dev, char* command);
int wl_android_set_roam_delta(struct net_device *dev, char* command);
int wl_android_set_roam_scan_period(struct net_device *dev, char* command);
int wl_android_set_full_roam_scan_period(struct net_device *dev, char* command, int total_len);
int wl_android_set_roam_scan_control(struct net_device *dev, char *command);
int wl_android_set_scan_channel_time(struct net_device *dev, char *command);
int wl_android_set_scan_home_time(struct net_device *dev, char *command);
int wl_android_set_scan_home_away_time(struct net_device *dev, char *command);
int wl_android_set_scan_nprobes(struct net_device *dev, char *command);
static int wl_android_set_band(struct net_device *dev, char *command);
int wl_android_set_scan_dfs_channel_mode(struct net_device *dev, char *command);
int wl_android_set_wes_mode(struct net_device *dev, char *command);
int wl_android_set_okc_mode(struct net_device *dev, char *command);

/* default values */
#ifdef ROAM_API
#define DEFAULT_ROAM_TIRGGER	-75
#define DEFAULT_ROAM_DELTA	10
#define DEFAULT_ROAMSCANPERIOD	10
#define DEFAULT_FULLROAMSCANPERIOD_SET	120
#endif /* ROAM_API */
#define DEFAULT_BAND		0

/* restoring parameter list, please don't change order */
static android_restore_scan_params_t restore_params[] =
{
/* wbtext need to be disabled while updating roam/scan parameters */
#ifdef ROAM_API
	{ CMD_ROAMTRIGGER_SET, DEFAULT_ROAM_TIRGGER,
		RESTORE_TYPE_PRIV_CMD, .cmd_handler = wl_android_set_roam_trigger},
	{ CMD_ROAMDELTA_SET, DEFAULT_ROAM_DELTA,
		RESTORE_TYPE_PRIV_CMD, .cmd_handler = wl_android_set_roam_delta},
	{ CMD_ROAMSCANPERIOD_SET, DEFAULT_ROAMSCANPERIOD,
		RESTORE_TYPE_PRIV_CMD, .cmd_handler = wl_android_set_roam_scan_period},
	{ CMD_FULLROAMSCANPERIOD_SET, DEFAULT_FULLROAMSCANPERIOD_SET,
		RESTORE_TYPE_PRIV_CMD_WITH_LEN,
		.cmd_handler_w_len = wl_android_set_full_roam_scan_period},
#endif /* ROAM_API */
	{ CMD_SETBAND, DEFAULT_BAND,
		RESTORE_TYPE_PRIV_CMD, .cmd_handler = wl_android_set_band},
	{ "\0", 0, RESTORE_TYPE_UNSPECIFIED, .cmd_handler = NULL}
};
#endif /* SUPPORT_RESTORE_SCAN_PARAMS */

/**
 * Local (static) functions and variables
 */

/* Initialize g_wifi_on to 1 so dhd_bus_start will be called for the first
 * time (only) in dhd_open, subsequential wifi on will be handled by
 * wl_android_wifi_on
 */
int g_wifi_on = TRUE;

/**
 * Local (static) function definitions
 */

#ifdef WLWFDS
static int wl_android_set_wfds_hash(
	struct net_device *dev, char *command, bool enable)
{
	int error = 0;
	wl_p2p_wfds_hash_t *wfds_hash = NULL;
	char *smbuf = NULL;
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);

	smbuf = (char *)MALLOC(cfg->osh, WLC_IOCTL_MAXLEN);
	if (smbuf == NULL) {
		ANDROID_ERROR(("wl_android_set_wfds_hash: failed to allocated memory %d bytes\n",
			WLC_IOCTL_MAXLEN));
		return -ENOMEM;
	}

	if (enable) {
		wfds_hash = (wl_p2p_wfds_hash_t *)(command + strlen(CMD_ADD_WFDS_HASH) + 1);
		error = wldev_iovar_setbuf(dev, "p2p_add_wfds_hash", wfds_hash,
			sizeof(wl_p2p_wfds_hash_t), smbuf, WLC_IOCTL_MAXLEN, NULL);
	}
	else {
		wfds_hash = (wl_p2p_wfds_hash_t *)(command + strlen(CMD_DEL_WFDS_HASH) + 1);
		error = wldev_iovar_setbuf(dev, "p2p_del_wfds_hash", wfds_hash,
			sizeof(wl_p2p_wfds_hash_t), smbuf, WLC_IOCTL_MAXLEN, NULL);
	}

	if (error) {
		ANDROID_ERROR(("wl_android_set_wfds_hash: failed to %s, error=%d\n", command, error));
	}

	if (smbuf) {
		MFREE(cfg->osh, smbuf, WLC_IOCTL_MAXLEN);
	}
	return error;
}
#endif /* WLWFDS */

static int wl_android_get_link_speed(struct net_device *net, char *command, int total_len)
{
	int link_speed;
	int bytes_written;
	int error;

	error = wldev_get_link_speed(net, &link_speed);
	if (error) {
		ANDROID_ERROR(("Get linkspeed failed \n"));
		return -1;
	}

	/* Convert Kbps to Android Mbps */
	link_speed = link_speed / 1000;
	bytes_written = snprintf(command, total_len, "LinkSpeed %d", link_speed);
	ANDROID_INFO(("wl_android_get_link_speed: command result is %s\n", command));
	return bytes_written;
}

static int wl_android_get_rssi(struct net_device *net, char *command, int total_len)
{
	wlc_ssid_t ssid = {0, {0}};
	int bytes_written = 0;
	int error = 0;
	scb_val_t scbval;
	char *delim = NULL;
	struct net_device *target_ndev = net;
#ifdef WL_VIRTUAL_APSTA
	char *pos = NULL;
	struct bcm_cfg80211 *cfg;
#endif /* WL_VIRTUAL_APSTA */

	delim = strchr(command, ' ');
	/* For Ap mode rssi command would be
	 * driver rssi <sta_mac_addr>
	 * for STA/GC mode
	 * driver rssi
	*/
	if (delim) {
		/* Ap/GO mode
		* driver rssi <sta_mac_addr>
		*/
		ANDROID_TRACE(("wl_android_get_rssi: cmd:%s\n", delim));
		/* skip space from delim after finding char */
		delim++;
		if (!(bcm_ether_atoe((delim), &scbval.ea))) {
			ANDROID_ERROR(("wl_android_get_rssi: address err\n"));
			return -1;
		}
		scbval.val = htod32(0);
		ANDROID_TRACE(("wl_android_get_rssi: address:"MACDBG, MAC2STRDBG(scbval.ea.octet)));
#ifdef WL_VIRTUAL_APSTA
		/* RSDB AP may have another virtual interface
		 * In this case, format of private command is as following,
		 * DRIVER rssi <sta_mac_addr> <AP interface name>
		 */

		/* Current position is start of MAC address string */
		pos = delim;
		delim = strchr(pos, ' ');
		if (delim) {
			/* skip space from delim after finding char */
			delim++;
			if (strnlen(delim, IFNAMSIZ)) {
				cfg = wl_get_cfg(net);
				target_ndev = wl_get_ap_netdev(cfg, delim);
				if (target_ndev == NULL)
					target_ndev = net;
			}
		}
#endif /* WL_VIRTUAL_APSTA */
	}
	else {
		/* STA/GC mode */
		bzero(&scbval, sizeof(scb_val_t));
	}

	error = wldev_get_rssi(target_ndev, &scbval);
	if (error)
		return -1;
#if defined(RSSIOFFSET)
	scbval.val = wl_update_rssi_offset(net, scbval.val);
#endif

	error = wldev_get_ssid(target_ndev, &ssid);
	if (error)
		return -1;
	if ((ssid.SSID_len == 0) || (ssid.SSID_len > DOT11_MAX_SSID_LEN)) {
		ANDROID_ERROR(("wl_android_get_rssi: wldev_get_ssid failed\n"));
	} else if (total_len <= ssid.SSID_len) {
		return -ENOMEM;
	} else {
		memcpy(command, ssid.SSID, ssid.SSID_len);
		bytes_written = ssid.SSID_len;
	}
	if ((total_len - bytes_written) < (strlen(" rssi -XXX") + 1))
		return -ENOMEM;

	bytes_written += scnprintf(&command[bytes_written], total_len - bytes_written,
		" rssi %d", scbval.val);
	command[bytes_written] = '\0';

	ANDROID_TRACE(("wl_android_get_rssi: command result is %s (%d)\n", command, bytes_written));
	return bytes_written;
}

static int wl_android_set_suspendopt(struct net_device *dev, char *command)
{
	int suspend_flag;
	int ret_now;
	int ret = 0;

	suspend_flag = *(command + strlen(CMD_SETSUSPENDOPT) + 1) - '0';

	if (suspend_flag != 0) {
		suspend_flag = 1;
	}
	ret_now = net_os_set_suspend_disable(dev, suspend_flag);

	if (ret_now != suspend_flag) {
		if (!(ret = net_os_set_suspend(dev, ret_now, 1))) {
			ANDROID_INFO(("wl_android_set_suspendopt: Suspend Flag %d -> %d\n",
				ret_now, suspend_flag));
		} else {
			ANDROID_ERROR(("wl_android_set_suspendopt: failed %d\n", ret));
		}
	}

	return ret;
}

static int wl_android_set_suspendmode(struct net_device *dev, char *command)
{
	int ret = 0;

#if !defined(CONFIG_HAS_EARLYSUSPEND) || !defined(DHD_USE_EARLYSUSPEND)
	int suspend_flag;

	suspend_flag = *(command + strlen(CMD_SETSUSPENDMODE) + 1) - '0';
	if (suspend_flag != 0)
		suspend_flag = 1;

	if (!(ret = net_os_set_suspend(dev, suspend_flag, 0)))
		ANDROID_INFO(("wl_android_set_suspendmode: Suspend Mode %d\n", suspend_flag));
	else
		ANDROID_ERROR(("wl_android_set_suspendmode: failed %d\n", ret));
#endif // endif

	return ret;
}

#ifdef WL_CFG80211
int wl_android_get_80211_mode(struct net_device *dev, char *command, int total_len)
{
	uint8 mode[5];
	int  error = 0;
	int bytes_written = 0;

	error = wldev_get_mode(dev, mode, sizeof(mode));
	if (error)
		return -1;

	ANDROID_INFO(("wl_android_get_80211_mode: mode:%s\n", mode));
	bytes_written = snprintf(command, total_len, "%s %s", CMD_80211_MODE, mode);
	ANDROID_INFO(("wl_android_get_80211_mode: command:%s EXIT\n", command));
	return bytes_written;

}

extern chanspec_t
wl_chspec_driver_to_host(chanspec_t chanspec);
int wl_android_get_chanspec(struct net_device *dev, char *command, int total_len)
{
	int error = 0;
	int bytes_written = 0;
	int chsp = {0};
	uint16 band = 0;
	uint16 bw = 0;
	uint16 channel = 0;
	u32 sb = 0;
	chanspec_t chanspec;

	/* command is
	 * driver chanspec
	 */
	error = wldev_iovar_getint(dev, "chanspec", &chsp);
	if (error)
		return -1;

	chanspec = wl_chspec_driver_to_host(chsp);
	ANDROID_INFO(("wl_android_get_80211_mode: return value of chanspec:%x\n", chanspec));

	channel = chanspec & WL_CHANSPEC_CHAN_MASK;
	band = chanspec & WL_CHANSPEC_BAND_MASK;
	bw = chanspec & WL_CHANSPEC_BW_MASK;

	ANDROID_INFO(("wl_android_get_80211_mode: channel:%d band:%d bandwidth:%d\n",
		channel, band, bw));

	if (bw == WL_CHANSPEC_BW_80)
		bw = WL_CH_BANDWIDTH_80MHZ;
	else if (bw == WL_CHANSPEC_BW_40)
		bw = WL_CH_BANDWIDTH_40MHZ;
	else if	(bw == WL_CHANSPEC_BW_20)
		bw = WL_CH_BANDWIDTH_20MHZ;
	else
		bw = WL_CH_BANDWIDTH_20MHZ;

	if (bw == WL_CH_BANDWIDTH_40MHZ) {
		if (CHSPEC_SB_UPPER(chanspec)) {
			channel += CH_10MHZ_APART;
		} else {
			channel -= CH_10MHZ_APART;
		}
	}
	else if (bw == WL_CH_BANDWIDTH_80MHZ) {
		sb = chanspec & WL_CHANSPEC_CTL_SB_MASK;
		if (sb == WL_CHANSPEC_CTL_SB_LL) {
			channel -= (CH_10MHZ_APART + CH_20MHZ_APART);
		} else if (sb == WL_CHANSPEC_CTL_SB_LU) {
			channel -= CH_10MHZ_APART;
		} else if (sb == WL_CHANSPEC_CTL_SB_UL) {
			channel += CH_10MHZ_APART;
		} else {
			/* WL_CHANSPEC_CTL_SB_UU */
			channel += (CH_10MHZ_APART + CH_20MHZ_APART);
		}
	}
	bytes_written = snprintf(command, total_len, "%s channel %d band %s bw %d", CMD_CHANSPEC,
		channel, band == WL_CHANSPEC_BAND_5G ? "5G":"2G", bw);

	ANDROID_INFO(("wl_android_get_chanspec: command:%s EXIT\n", command));
	return bytes_written;

}
#endif /* WL_CFG80211 */

/* returns current datarate datarate returned from firmware are in 500kbps */
int wl_android_get_datarate(struct net_device *dev, char *command, int total_len)
{
	int  error = 0;
	int datarate = 0;
	int bytes_written = 0;

	error = wldev_get_datarate(dev, &datarate);
	if (error)
		return -1;

	ANDROID_INFO(("wl_android_get_datarate: datarate:%d\n", datarate));

	bytes_written = snprintf(command, total_len, "%s %d", CMD_DATARATE, (datarate/2));
	return bytes_written;
}
int wl_android_get_assoclist(struct net_device *dev, char *command, int total_len)
{
	int  error = 0;
	int bytes_written = 0;
	uint i;
	int len = 0;
	char mac_buf[MAX_NUM_OF_ASSOCLIST *
		sizeof(struct ether_addr) + sizeof(uint)] = {0};
	struct maclist *assoc_maclist = (struct maclist *)mac_buf;

	ANDROID_TRACE(("wl_android_get_assoclist: ENTER\n"));

	assoc_maclist->count = htod32(MAX_NUM_OF_ASSOCLIST);

	error = wldev_ioctl_get(dev, WLC_GET_ASSOCLIST, assoc_maclist, sizeof(mac_buf));
	if (error)
		return -1;

	assoc_maclist->count = dtoh32(assoc_maclist->count);
	bytes_written = snprintf(command, total_len, "%s listcount: %d Stations:",
		CMD_ASSOC_CLIENTS, assoc_maclist->count);

	for (i = 0; i < assoc_maclist->count; i++) {
		len = snprintf(command + bytes_written, total_len - bytes_written, " " MACDBG,
			MAC2STRDBG(assoc_maclist->ea[i].octet));
		/* A return value of '(total_len - bytes_written)' or more means that the
		 * output was truncated
		 */
		if ((len > 0) && (len < (total_len - bytes_written))) {
			bytes_written += len;
		} else {
			ANDROID_ERROR(("wl_android_get_assoclist: Insufficient buffer %d,"
				" bytes_written %d\n",
				total_len, bytes_written));
			bytes_written = -1;
			break;
		}
	}
	return bytes_written;
}

#ifdef WL_CFG80211
extern chanspec_t
wl_chspec_host_to_driver(chanspec_t chanspec);
static int wl_android_set_csa(struct net_device *dev, char *command)
{
	int error = 0;
	char smbuf[WLC_IOCTL_SMLEN];
	wl_chan_switch_t csa_arg;
	u32 chnsp = 0;
	int err = 0;

	ANDROID_INFO(("wl_android_set_csa: command:%s\n", command));

	command = (command + strlen(CMD_SET_CSA));
	/* Order is mode, count channel */
	if (!*++command) {
		ANDROID_ERROR(("wl_android_set_csa:error missing arguments\n"));
		return -1;
	}
	csa_arg.mode = bcm_atoi(command);

	if (csa_arg.mode != 0 && csa_arg.mode != 1) {
		ANDROID_ERROR(("Invalid mode\n"));
		return -1;
	}

	if (!*++command) {
		ANDROID_ERROR(("wl_android_set_csa: error missing count\n"));
		return -1;
	}
	command++;
	csa_arg.count = bcm_atoi(command);

	csa_arg.reg = 0;
	csa_arg.chspec = 0;
	command += 2;
	if (!*command) {
		ANDROID_ERROR(("wl_android_set_csa: error missing channel\n"));
		return -1;
	}

	chnsp = wf_chspec_aton(command);
	if (chnsp == 0)	{
		ANDROID_ERROR(("wl_android_set_csa:chsp is not correct\n"));
		return -1;
	}
	chnsp = wl_chspec_host_to_driver(chnsp);
	csa_arg.chspec = chnsp;

	if (chnsp & WL_CHANSPEC_BAND_5G) {
		u32 chanspec = chnsp;
		err = wldev_iovar_getint(dev, "per_chan_info", &chanspec);
		if (!err) {
			if ((chanspec & WL_CHAN_RADAR) || (chanspec & WL_CHAN_PASSIVE)) {
				ANDROID_ERROR(("Channel is radar sensitive\n"));
				return -1;
			}
			if (chanspec == 0) {
				ANDROID_ERROR(("Invalid hw channel\n"));
				return -1;
			}
		} else  {
			ANDROID_ERROR(("does not support per_chan_info\n"));
			return -1;
		}
		ANDROID_INFO(("non radar sensitivity\n"));
	}
	error = wldev_iovar_setbuf(dev, "csa", &csa_arg, sizeof(csa_arg),
		smbuf, sizeof(smbuf), NULL);
	if (error) {
		ANDROID_ERROR(("wl_android_set_csa:set csa failed:%d\n", error));
		return -1;
	}
	return 0;
}
#endif /* WL_CFG80211 */

static int
wl_android_set_bcn_li_dtim(struct net_device *dev, char *command)
{
	int ret = 0;
	int dtim;

	dtim = *(command + strlen(CMD_SETDTIM_IN_SUSPEND) + 1) - '0';

	if (dtim > (MAX_DTIM_ALLOWED_INTERVAL / MAX_DTIM_SKIP_BEACON_INTERVAL)) {
		ANDROID_ERROR(("%s: failed, invalid dtim %d\n",
			__FUNCTION__, dtim));
		return BCME_ERROR;
	}

	if (!(ret = net_os_set_suspend_bcn_li_dtim(dev, dtim))) {
		ANDROID_TRACE(("%s: SET bcn_li_dtim in suspend %d\n",
			__FUNCTION__, dtim));
	} else {
		ANDROID_ERROR(("%s: failed %d\n", __FUNCTION__, ret));
	}

	return ret;
}

static int
wl_android_set_max_dtim(struct net_device *dev, char *command)
{
	int ret = 0;
	int dtim_flag;

	dtim_flag = *(command + strlen(CMD_MAXDTIM_IN_SUSPEND) + 1) - '0';

	if (!(ret = net_os_set_max_dtim_enable(dev, dtim_flag))) {
		ANDROID_TRACE(("wl_android_set_max_dtim: use Max bcn_li_dtim in suspend %s\n",
			(dtim_flag ? "Enable" : "Disable")));
	} else {
		ANDROID_ERROR(("wl_android_set_max_dtim: failed %d\n", ret));
	}

	return ret;
}

#ifdef DISABLE_DTIM_IN_SUSPEND
static int
wl_android_set_disable_dtim_in_suspend(struct net_device *dev, char *command)
{
	int ret = 0;
	int dtim_flag;

	dtim_flag = *(command + strlen(CMD_DISDTIM_IN_SUSPEND) + 1) - '0';

	if (!(ret = net_os_set_disable_dtim_in_suspend(dev, dtim_flag))) {
		ANDROID_TRACE(("wl_android_set_disable_dtim_in_suspend: "
			"use Disable bcn_li_dtim in suspend %s\n",
			(dtim_flag ? "Enable" : "Disable")));
	} else {
		ANDROID_ERROR(("wl_android_set_disable_dtim_in_suspend: failed %d\n", ret));
	}

	return ret;
}
#endif /* DISABLE_DTIM_IN_SUSPEND */

static int wl_android_get_band(struct net_device *dev, char *command, int total_len)
{
	uint band;
	int bytes_written;
	int error;

	error = wldev_get_band(dev, &band);
	if (error)
		return -1;
	bytes_written = snprintf(command, total_len, "Band %d", band);
	return bytes_written;
}

#ifdef WL_CFG80211
static int
wl_android_set_band(struct net_device *dev, char *command)
{
	int error = 0;
	uint band = *(command + strlen(CMD_SETBAND) + 1) - '0';
#ifdef WL_HOST_BAND_MGMT
	int ret = 0;
	if ((ret = wl_cfg80211_set_band(dev, band)) < 0) {
		if (ret == BCME_UNSUPPORTED) {
			/* If roam_var is unsupported, fallback to the original method */
			ANDROID_ERROR(("WL_HOST_BAND_MGMT defined, "
				"but roam_band iovar unsupported in the firmware\n"));
		} else {
			error = -1;
		}
	}
	if (((ret == 0) && (band == WLC_BAND_AUTO)) || (ret == BCME_UNSUPPORTED)) {
		/* Apply if roam_band iovar is not supported or band setting is AUTO */
		error = wldev_set_band(dev, band);
	}
#else
	error = wl_cfg80211_set_if_band(dev, band);
#endif /* WL_HOST_BAND_MGMT */
#ifdef ROAM_CHANNEL_CACHE
	wl_update_roamscan_cache_by_band(dev, band);
#endif /* ROAM_CHANNEL_CACHE */
	return error;
}
#endif /* WL_CFG80211 */

#ifdef PNO_SUPPORT
#define PNO_PARAM_SIZE 50
#define VALUE_SIZE 50
#define LIMIT_STR_FMT  ("%50s %50s")

static int
wls_parse_batching_cmd(struct net_device *dev, char *command, int total_len)
{
	int err = BCME_OK;
	uint i, tokens, len_remain;
	char *pos, *pos2, *token, *token2, *delim;
	char param[PNO_PARAM_SIZE+1], value[VALUE_SIZE+1];
	struct dhd_pno_batch_params batch_params;

	ANDROID_INFO(("wls_parse_batching_cmd: command=%s, len=%d\n", command, total_len));
	len_remain = total_len;
	if (len_remain > (strlen(CMD_WLS_BATCHING) + 1)) {
		pos = command + strlen(CMD_WLS_BATCHING) + 1;
		len_remain -= strlen(CMD_WLS_BATCHING) + 1;
	} else {
		ANDROID_ERROR(("wls_parse_batching_cmd: No arguments, total_len %d\n", total_len));
		err = BCME_ERROR;
		goto exit;
	}
	bzero(&batch_params, sizeof(struct dhd_pno_batch_params));
	if (!strncmp(pos, PNO_BATCHING_SET, strlen(PNO_BATCHING_SET))) {
		if (len_remain > (strlen(PNO_BATCHING_SET) + 1)) {
			pos += strlen(PNO_BATCHING_SET) + 1;
		} else {
			ANDROID_ERROR(("wls_parse_batching_cmd: %s missing arguments, total_len %d\n",
				PNO_BATCHING_SET, total_len));
			err = BCME_ERROR;
			goto exit;
		}
		while ((token = strsep(&pos, PNO_PARAMS_DELIMETER)) != NULL) {
			bzero(param, sizeof(param));
			bzero(value, sizeof(value));
			if (token == NULL || !*token)
				break;
			if (*token == '\0')
				continue;
			delim = strchr(token, PNO_PARAM_VALUE_DELLIMETER);
			if (delim != NULL)
				*delim = ' ';

			tokens = sscanf(token, LIMIT_STR_FMT, param, value);
			if (!strncmp(param, PNO_PARAM_SCANFREQ, strlen(PNO_PARAM_SCANFREQ))) {
				batch_params.scan_fr = simple_strtol(value, NULL, 0);
				ANDROID_INFO(("scan_freq : %d\n", batch_params.scan_fr));
			} else if (!strncmp(param, PNO_PARAM_BESTN, strlen(PNO_PARAM_BESTN))) {
				batch_params.bestn = simple_strtol(value, NULL, 0);
				ANDROID_INFO(("bestn : %d\n", batch_params.bestn));
			} else if (!strncmp(param, PNO_PARAM_MSCAN, strlen(PNO_PARAM_MSCAN))) {
				batch_params.mscan = simple_strtol(value, NULL, 0);
				ANDROID_INFO(("mscan : %d\n", batch_params.mscan));
			} else if (!strncmp(param, PNO_PARAM_CHANNEL, strlen(PNO_PARAM_CHANNEL))) {
				i = 0;
				pos2 = value;
				tokens = sscanf(value, "<%s>", value);
				if (tokens != 1) {
					err = BCME_ERROR;
					ANDROID_ERROR(("wls_parse_batching_cmd: invalid format"
					" for channel"
					" <> params\n"));
					goto exit;
				}
				while ((token2 = strsep(&pos2,
						PNO_PARAM_CHANNEL_DELIMETER)) != NULL) {
					if (token2 == NULL || !*token2)
						break;
					if (*token2 == '\0')
						continue;
					if (*token2 == 'A' || *token2 == 'B') {
						batch_params.band = (*token2 == 'A')?
							WLC_BAND_5G : WLC_BAND_2G;
						ANDROID_INFO(("band : %s\n",
							(*token2 == 'A')? "A" : "B"));
					} else {
						if ((batch_params.nchan >= WL_NUMCHANNELS) ||
							(i >= WL_NUMCHANNELS)) {
							ANDROID_ERROR(("Too many nchan %d\n",
								batch_params.nchan));
							err = BCME_BUFTOOSHORT;
							goto exit;
						}
						batch_params.chan_list[i++] =
							simple_strtol(token2, NULL, 0);
						batch_params.nchan++;
						ANDROID_INFO(("channel :%d\n",
							batch_params.chan_list[i-1]));
					}
				 }
			} else if (!strncmp(param, PNO_PARAM_RTT, strlen(PNO_PARAM_RTT))) {
				batch_params.rtt = simple_strtol(value, NULL, 0);
				ANDROID_INFO(("rtt : %d\n", batch_params.rtt));
			} else {
				ANDROID_ERROR(("wls_parse_batching_cmd : unknown param: %s\n", param));
				err = BCME_ERROR;
				goto exit;
			}
		}
		err = dhd_dev_pno_set_for_batch(dev, &batch_params);
		if (err < 0) {
			ANDROID_ERROR(("failed to configure batch scan\n"));
		} else {
			bzero(command, total_len);
			err = snprintf(command, total_len, "%d", err);
		}
	} else if (!strncmp(pos, PNO_BATCHING_GET, strlen(PNO_BATCHING_GET))) {
		err = dhd_dev_pno_get_for_batch(dev, command, total_len);
		if (err < 0) {
			ANDROID_ERROR(("failed to getting batching results\n"));
		} else {
			err = strlen(command);
		}
	} else if (!strncmp(pos, PNO_BATCHING_STOP, strlen(PNO_BATCHING_STOP))) {
		err = dhd_dev_pno_stop_for_batch(dev);
		if (err < 0) {
			ANDROID_ERROR(("failed to stop batching scan\n"));
		} else {
			bzero(command, total_len);
			err = snprintf(command, total_len, "OK");
		}
	} else {
		ANDROID_ERROR(("wls_parse_batching_cmd : unknown command\n"));
		err = BCME_ERROR;
		goto exit;
	}
exit:
	return err;
}

#ifndef WL_SCHED_SCAN
static int wl_android_set_pno_setup(struct net_device *dev, char *command, int total_len)
{
	wlc_ssid_ext_t ssids_local[MAX_PFN_LIST_COUNT];
	int res = -1;
	int nssid = 0;
	cmd_tlv_t *cmd_tlv_temp;
	char *str_ptr;
	int tlv_size_left;
	int pno_time = 0;
	int pno_repeat = 0;
	int pno_freq_expo_max = 0;

#ifdef PNO_SET_DEBUG
	int i;
	char pno_in_example[] = {
		'P', 'N', 'O', 'S', 'E', 'T', 'U', 'P', ' ',
		'S', '1', '2', '0',
		'S',
		0x05,
		'd', 'l', 'i', 'n', 'k',
		'S',
		0x04,
		'G', 'O', 'O', 'G',
		'T',
		'0', 'B',
		'R',
		'2',
		'M',
		'2',
		0x00
		};
#endif /* PNO_SET_DEBUG */
	ANDROID_INFO(("wl_android_set_pno_setup: command=%s, len=%d\n", command, total_len));

	if (total_len < (strlen(CMD_PNOSETUP_SET) + sizeof(cmd_tlv_t))) {
		ANDROID_ERROR(("wl_android_set_pno_setup: argument=%d less min size\n", total_len));
		goto exit_proc;
	}
#ifdef PNO_SET_DEBUG
	memcpy(command, pno_in_example, sizeof(pno_in_example));
	total_len = sizeof(pno_in_example);
#endif // endif
	str_ptr = command + strlen(CMD_PNOSETUP_SET);
	tlv_size_left = total_len - strlen(CMD_PNOSETUP_SET);

	cmd_tlv_temp = (cmd_tlv_t *)str_ptr;
	bzero(ssids_local, sizeof(ssids_local));

	if ((cmd_tlv_temp->prefix == PNO_TLV_PREFIX) &&
		(cmd_tlv_temp->version == PNO_TLV_VERSION) &&
		(cmd_tlv_temp->subtype == PNO_TLV_SUBTYPE_LEGACY_PNO)) {

		str_ptr += sizeof(cmd_tlv_t);
		tlv_size_left -= sizeof(cmd_tlv_t);

		if ((nssid = wl_parse_ssid_list_tlv(&str_ptr, ssids_local,
			MAX_PFN_LIST_COUNT, &tlv_size_left)) <= 0) {
			ANDROID_ERROR(("SSID is not presented or corrupted ret=%d\n", nssid));
			goto exit_proc;
		} else {
			if ((str_ptr[0] != PNO_TLV_TYPE_TIME) || (tlv_size_left <= 1)) {
				ANDROID_ERROR(("wl_android_set_pno_setup: scan duration corrupted"
					" field size %d\n",
					tlv_size_left));
				goto exit_proc;
			}
			str_ptr++;
			pno_time = simple_strtoul(str_ptr, &str_ptr, 16);
			ANDROID_INFO(("wl_android_set_pno_setup: pno_time=%d\n", pno_time));

			if (str_ptr[0] != 0) {
				if ((str_ptr[0] != PNO_TLV_FREQ_REPEAT)) {
					ANDROID_ERROR(("wl_android_set_pno_setup: pno repeat:"
						" corrupted field\n"));
					goto exit_proc;
				}
				str_ptr++;
				pno_repeat = simple_strtoul(str_ptr, &str_ptr, 16);
				ANDROID_INFO(("wl_android_set_pno_setup: got pno_repeat=%d\n",
					pno_repeat));
				if (str_ptr[0] != PNO_TLV_FREQ_EXPO_MAX) {
					ANDROID_ERROR(("wl_android_set_pno_setup: FREQ_EXPO_MAX"
						" corrupted field size\n"));
					goto exit_proc;
				}
				str_ptr++;
				pno_freq_expo_max = simple_strtoul(str_ptr, &str_ptr, 16);
				ANDROID_INFO(("wl_android_set_pno_setup: pno_freq_expo_max=%d\n",
					pno_freq_expo_max));
			}
		}
	} else {
		ANDROID_ERROR(("wl_android_set_pno_setup: get wrong TLV command\n"));
		goto exit_proc;
	}

	res = dhd_dev_pno_set_for_ssid(dev, ssids_local, nssid, pno_time, pno_repeat,
		pno_freq_expo_max, NULL, 0);
exit_proc:
	return res;
}
#endif /* !WL_SCHED_SCAN */
#endif /* PNO_SUPPORT  */

static int wl_android_get_p2p_dev_addr(struct net_device *ndev, char *command, int total_len)
{
	int ret;
	struct ether_addr p2pdev_addr;

#define MAC_ADDR_STR_LEN 18
	if (total_len < MAC_ADDR_STR_LEN) {
		ANDROID_ERROR(("wl_android_get_p2p_dev_addr: buflen %d is less than p2p dev addr\n",
			total_len));
		return -1;
	}

	ret = wl_cfg80211_get_p2p_dev_addr(ndev, &p2pdev_addr);
	if (ret) {
		ANDROID_ERROR(("wl_android_get_p2p_dev_addr: Failed to get p2p dev addr\n"));
		return -1;
	}
	return (snprintf(command, total_len, MACF, ETHERP_TO_MACF(&p2pdev_addr)));
}

int
wl_android_set_ap_mac_list(struct net_device *dev, int macmode, struct maclist *maclist)
{
	int i, j, match;
	int ret	= 0;
	char mac_buf[MAX_NUM_OF_ASSOCLIST *
		sizeof(struct ether_addr) + sizeof(uint)] = {0};
	struct maclist *assoc_maclist = (struct maclist *)mac_buf;

	/* set filtering mode */
	if ((ret = wldev_ioctl_set(dev, WLC_SET_MACMODE, &macmode, sizeof(macmode)) != 0)) {
		ANDROID_ERROR(("wl_android_set_ap_mac_list : WLC_SET_MACMODE error=%d\n", ret));
		return ret;
	}
	if (macmode != MACLIST_MODE_DISABLED) {
		/* set the MAC filter list */
		if ((ret = wldev_ioctl_set(dev, WLC_SET_MACLIST, maclist,
			sizeof(int) + sizeof(struct ether_addr) * maclist->count)) != 0) {
			ANDROID_ERROR(("wl_android_set_ap_mac_list : WLC_SET_MACLIST error=%d\n", ret));
			return ret;
		}
		/* get the current list of associated STAs */
		assoc_maclist->count = MAX_NUM_OF_ASSOCLIST;
		if ((ret = wldev_ioctl_get(dev, WLC_GET_ASSOCLIST, assoc_maclist,
			sizeof(mac_buf))) != 0) {
			ANDROID_ERROR(("wl_android_set_ap_mac_list: WLC_GET_ASSOCLIST error=%d\n",
				ret));
			return ret;
		}
		/* do we have any STA associated?  */
		if (assoc_maclist->count) {
			/* iterate each associated STA */
			for (i = 0; i < assoc_maclist->count; i++) {
				match = 0;
				/* compare with each entry */
				for (j = 0; j < maclist->count; j++) {
					ANDROID_INFO(("wl_android_set_ap_mac_list: associated="MACDBG
					"list = "MACDBG "\n",
					MAC2STRDBG(assoc_maclist->ea[i].octet),
					MAC2STRDBG(maclist->ea[j].octet)));
					if (memcmp(assoc_maclist->ea[i].octet,
						maclist->ea[j].octet, ETHER_ADDR_LEN) == 0) {
						match = 1;
						break;
					}
				}
				/* do conditional deauth */
				/*   "if not in the allow list" or "if in the deny list" */
				if ((macmode == MACLIST_MODE_ALLOW && !match) ||
					(macmode == MACLIST_MODE_DENY && match)) {
					scb_val_t scbval;

					scbval.val = htod32(1);
					memcpy(&scbval.ea, &assoc_maclist->ea[i],
						ETHER_ADDR_LEN);
					if ((ret = wldev_ioctl_set(dev,
						WLC_SCB_DEAUTHENTICATE_FOR_REASON,
						&scbval, sizeof(scb_val_t))) != 0)
						ANDROID_ERROR(("wl_android_set_ap_mac_list:"
							" WLC_SCB_DEAUTHENTICATE"
							" error=%d\n",
							ret));
				}
			}
		}
	}
	return ret;
}

/*
 * HAPD_MAC_FILTER mac_mode mac_cnt mac_addr1 mac_addr2
 *
 */
static int
wl_android_set_mac_address_filter(struct net_device *dev, char* str)
{
	int i;
	int ret = 0;
	int macnum = 0;
	int macmode = MACLIST_MODE_DISABLED;
	struct maclist *list;
	char eabuf[ETHER_ADDR_STR_LEN];
	const char *token;
	dhd_pub_t *dhd = dhd_get_pub(dev);

	/* string should look like below (macmode/macnum/maclist) */
	/*   1 2 00:11:22:33:44:55 00:11:22:33:44:ff  */

	/* get the MAC filter mode */
	token = strsep((char**)&str, " ");
	if (!token) {
		return -1;
	}
	macmode = bcm_atoi(token);

	if (macmode < MACLIST_MODE_DISABLED || macmode > MACLIST_MODE_ALLOW) {
		ANDROID_ERROR(("wl_android_set_mac_address_filter: invalid macmode %d\n", macmode));
		return -1;
	}

	token = strsep((char**)&str, " ");
	if (!token) {
		return -1;
	}
	macnum = bcm_atoi(token);
	if (macnum < 0 || macnum > MAX_NUM_MAC_FILT) {
		ANDROID_ERROR(("wl_android_set_mac_address_filter: invalid number of MAC"
			" address entries %d\n",
			macnum));
		return -1;
	}
	/* allocate memory for the MAC list */
	list = (struct maclist*) MALLOCZ(dhd->osh, sizeof(int) +
		sizeof(struct ether_addr) * macnum);
	if (!list) {
		ANDROID_ERROR(("wl_android_set_mac_address_filter : failed to allocate memory\n"));
		return -1;
	}
	/* prepare the MAC list */
	list->count = htod32(macnum);
	bzero((char *)eabuf, ETHER_ADDR_STR_LEN);
	for (i = 0; i < list->count; i++) {
		token = strsep((char**)&str, " ");
		if (token == NULL) {
			ANDROID_ERROR(("wl_android_set_mac_address_filter : No mac address present\n"));
			ret = -EINVAL;
			goto exit;
		}
		strlcpy(eabuf, token, sizeof(eabuf));
		if (!(ret = bcm_ether_atoe(eabuf, &list->ea[i]))) {
			ANDROID_ERROR(("wl_android_set_mac_address_filter : mac parsing err index=%d,"
				" addr=%s\n",
				i, eabuf));
			list->count = i;
			break;
		}
		ANDROID_INFO(("wl_android_set_mac_address_filter : %d/%d MACADDR=%s",
			i, list->count, eabuf));
	}
	if (i == 0)
		goto exit;

	/* set the list */
	if ((ret = wl_android_set_ap_mac_list(dev, macmode, list)) != 0)
		ANDROID_ERROR(("wl_android_set_mac_address_filter: Setting MAC list failed error=%d\n",
			ret));

exit:
	MFREE(dhd->osh, list, sizeof(int) + sizeof(struct ether_addr) * macnum);

	return ret;
}

/**
 * Global function definitions (declared in wl_android.h)
 */

int wl_android_wifi_on(struct net_device *dev)
{
	int ret = 0;
	int retry = POWERUP_MAX_RETRY;

	if (!dev) {
		ANDROID_ERROR(("wl_android_wifi_on: dev is null\n"));
		return -EINVAL;
	}

	dhd_net_if_lock(dev);
	WL_MSG(dev->name, "in g_wifi_on=%d\n", g_wifi_on);
	if (!g_wifi_on) {
		do {
			dhd_net_wifi_platform_set_power(dev, TRUE, WIFI_TURNON_DELAY);
#ifdef BCMSDIO
			ret = dhd_net_bus_resume(dev, 0);
#endif /* BCMSDIO */
#ifdef BCMPCIE
			ret = dhd_net_bus_devreset(dev, FALSE);
#endif /* BCMPCIE */
			if (ret == 0) {
				break;
			}
			ANDROID_ERROR(("failed to power up wifi chip, retry again (%d left) **\n\n",
				retry));
#ifdef BCMPCIE
			dhd_net_bus_devreset(dev, TRUE);
#endif /* BCMPCIE */
			dhd_net_wifi_platform_set_power(dev, FALSE, WIFI_TURNOFF_DELAY);
		} while (retry-- > 0);
		if (ret != 0) {
			ANDROID_ERROR(("failed to power up wifi chip, max retry reached **\n\n"));
#ifdef BCM_DETECT_TURN_ON_FAILURE
			BUG_ON(1);
#endif /* BCM_DETECT_TURN_ON_FAILURE */
			goto exit;
		}
#if defined(BCMSDIO) || defined(BCMDBUS)
		ret = dhd_net_bus_devreset(dev, FALSE);
		if (ret)
			goto err;
#ifdef BCMSDIO
		dhd_net_bus_resume(dev, 1);
#endif /* BCMSDIO */
#endif /* BCMSDIO || BCMDBUS */
#if defined(BCMSDIO) || defined(BCMDBUS)
		if (!ret) {
			if (dhd_dev_init_ioctl(dev) < 0) {
				ret = -EFAULT;
				goto err;
			}
		}
#endif /* BCMSDIO || BCMDBUS */
		g_wifi_on = TRUE;
	}

exit:
	WL_MSG(dev->name, "Success\n");
	dhd_net_if_unlock(dev);
	return ret;

#if defined(BCMSDIO) || defined(BCMDBUS)
err:
	dhd_net_bus_devreset(dev, TRUE);
#ifdef BCMSDIO
	dhd_net_bus_suspend(dev);
#endif /* BCMSDIO */
	dhd_net_wifi_platform_set_power(dev, FALSE, WIFI_TURNOFF_DELAY);
	WL_MSG(dev->name, "Failed\n");
	dhd_net_if_unlock(dev);
	return ret;
#endif /* BCMSDIO || BCMDBUS */
}

int wl_android_wifi_off(struct net_device *dev, bool on_failure)
{
	int ret = 0;

	if (!dev) {
		ANDROID_ERROR(("%s: dev is null\n", __FUNCTION__));
		return -EINVAL;
	}

#if defined(BCMPCIE) && defined(DHD_DEBUG_UART)
	ret = dhd_debug_uart_is_running(dev);
	if (ret) {
		ANDROID_ERROR(("wl_android_wifi_off: - Debug UART App is running\n"));
		return -EBUSY;
	}
#endif	/* BCMPCIE && DHD_DEBUG_UART */
	dhd_net_if_lock(dev);
	WL_MSG(dev->name, "in g_wifi_on=%d, on_failure=%d\n", g_wifi_on, on_failure);
	if (g_wifi_on || on_failure) {
#if defined(BCMSDIO) || defined(BCMPCIE) || defined(BCMDBUS)
		ret = dhd_net_bus_devreset(dev, TRUE);
#ifdef BCMSDIO
		dhd_net_bus_suspend(dev);
#endif /* BCMSDIO */
#endif /* BCMSDIO || BCMPCIE || BCMDBUS */
		dhd_net_wifi_platform_set_power(dev, FALSE, WIFI_TURNOFF_DELAY);
		g_wifi_on = FALSE;
	}
	WL_MSG(dev->name, "out\n");
	dhd_net_if_unlock(dev);

	return ret;
}

static int wl_android_set_fwpath(struct net_device *net, char *command, int total_len)
{
	if ((strlen(command) - strlen(CMD_SETFWPATH)) > MOD_PARAM_PATHLEN)
		return -1;
	return dhd_net_set_fw_path(net, command + strlen(CMD_SETFWPATH) + 1);
}

#ifdef CONNECTION_STATISTICS
static int
wl_chanim_stats(struct net_device *dev, u8 *chan_idle)
{
	int err;
	wl_chanim_stats_t *list;
	/* Parameter _and_ returned buffer of chanim_stats. */
	wl_chanim_stats_t param;
	u8 result[WLC_IOCTL_SMLEN];
	chanim_stats_t *stats;

	bzero(&param, sizeof(param));

	param.buflen = htod32(sizeof(wl_chanim_stats_t));
	param.count = htod32(WL_CHANIM_COUNT_ONE);

	if ((err = wldev_iovar_getbuf(dev, "chanim_stats", (char*)&param, sizeof(wl_chanim_stats_t),
		(char*)result, sizeof(result), 0)) < 0) {
		ANDROID_ERROR(("Failed to get chanim results %d \n", err));
		return err;
	}

	list = (wl_chanim_stats_t*)result;

	list->buflen = dtoh32(list->buflen);
	list->version = dtoh32(list->version);
	list->count = dtoh32(list->count);

	if (list->buflen == 0) {
		list->version = 0;
		list->count = 0;
	} else if (list->version != WL_CHANIM_STATS_VERSION) {
		ANDROID_ERROR(("Sorry, firmware has wl_chanim_stats version %d "
			"but driver supports only version %d.\n",
				list->version, WL_CHANIM_STATS_VERSION));
		list->buflen = 0;
		list->count = 0;
	}

	stats = list->stats;
	stats->glitchcnt = dtoh32(stats->glitchcnt);
	stats->badplcp = dtoh32(stats->badplcp);
	stats->chanspec = dtoh16(stats->chanspec);
	stats->timestamp = dtoh32(stats->timestamp);
	stats->chan_idle = dtoh32(stats->chan_idle);

	ANDROID_INFO(("chanspec: 0x%4x glitch: %d badplcp: %d idle: %d timestamp: %d\n",
		stats->chanspec, stats->glitchcnt, stats->badplcp, stats->chan_idle,
		stats->timestamp));

	*chan_idle = stats->chan_idle;

	return (err);
}

static int
wl_android_get_connection_stats(struct net_device *dev, char *command, int total_len)
{
	static char iovar_buf[WLC_IOCTL_MAXLEN];
	const wl_cnt_wlc_t* wlc_cnt = NULL;
#ifndef DISABLE_IF_COUNTERS
	wl_if_stats_t* if_stats = NULL;
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);
	dhd_pub_t *dhdp = wl_cfg80211_get_dhdp(dev);
#endif /* DISABLE_IF_COUNTERS */

	int link_speed = 0;
	struct connection_stats *output;
	unsigned int bufsize = 0;
	int bytes_written = -1;
	int ret = 0;

	ANDROID_INFO(("wl_android_get_connection_stats: enter Get Connection Stats\n"));

	if (total_len <= 0) {
		ANDROID_ERROR(("wl_android_get_connection_stats: invalid buffer size %d\n", total_len));
		goto error;
	}

	bufsize = total_len;
	if (bufsize < sizeof(struct connection_stats)) {
		ANDROID_ERROR(("wl_android_get_connection_stats: not enough buffer size, provided=%u,"
			" requires=%zu\n",
			bufsize,
			sizeof(struct connection_stats)));
		goto error;
	}

	output = (struct connection_stats *)command;

#ifndef DISABLE_IF_COUNTERS
	if_stats = (wl_if_stats_t *)MALLOCZ(cfg->osh, sizeof(*if_stats));
	if (if_stats == NULL) {
		ANDROID_ERROR(("wl_android_get_connection_stats: MALLOCZ failed\n"));
		goto error;
	}
	bzero(if_stats, sizeof(*if_stats));

	if (FW_SUPPORTED(dhdp, ifst)) {
		ret = wl_cfg80211_ifstats_counters(dev, if_stats);
	} else
	{
		ret = wldev_iovar_getbuf(dev, "if_counters", NULL, 0,
			(char *)if_stats, sizeof(*if_stats), NULL);
	}

	ret = wldev_iovar_getbuf(dev, "if_counters", NULL, 0,
		(char *)if_stats, sizeof(*if_stats), NULL);
	if (ret) {
		ANDROID_ERROR(("wl_android_get_connection_stats: if_counters not supported ret=%d\n",
			ret));

		/* In case if_stats IOVAR is not supported, get information from counters. */
#endif /* DISABLE_IF_COUNTERS */
		ret = wldev_iovar_getbuf(dev, "counters", NULL, 0,
			iovar_buf, WLC_IOCTL_MAXLEN, NULL);
		if (unlikely(ret)) {
			ANDROID_ERROR(("counters error (%d) - size = %zu\n", ret, sizeof(wl_cnt_wlc_t)));
			goto error;
		}
		ret = wl_cntbuf_to_xtlv_format(NULL, iovar_buf, WL_CNTBUF_MAX_SIZE, 0);
		if (ret != BCME_OK) {
			ANDROID_ERROR(("wl_android_get_connection_stats:"
			" wl_cntbuf_to_xtlv_format ERR %d\n",
			ret));
			goto error;
		}

		if (!(wlc_cnt = GET_WLCCNT_FROM_CNTBUF(iovar_buf))) {
			ANDROID_ERROR(("wl_android_get_connection_stats: wlc_cnt NULL!\n"));
			goto error;
		}

		output->txframe   = dtoh32(wlc_cnt->txframe);
		output->txbyte    = dtoh32(wlc_cnt->txbyte);
		output->txerror   = dtoh32(wlc_cnt->txerror);
		output->rxframe   = dtoh32(wlc_cnt->rxframe);
		output->rxbyte    = dtoh32(wlc_cnt->rxbyte);
		output->txfail    = dtoh32(wlc_cnt->txfail);
		output->txretry   = dtoh32(wlc_cnt->txretry);
		output->txretrie  = dtoh32(wlc_cnt->txretrie);
		output->txrts     = dtoh32(wlc_cnt->txrts);
		output->txnocts   = dtoh32(wlc_cnt->txnocts);
		output->txexptime = dtoh32(wlc_cnt->txexptime);
#ifndef DISABLE_IF_COUNTERS
	} else {
		/* Populate from if_stats. */
		if (dtoh16(if_stats->version) > WL_IF_STATS_T_VERSION) {
			ANDROID_ERROR(("wl_android_get_connection_stats: incorrect version of"
				" wl_if_stats_t,"
				" expected=%u got=%u\n",
				WL_IF_STATS_T_VERSION, if_stats->version));
			goto error;
		}

		output->txframe   = (uint32)dtoh64(if_stats->txframe);
		output->txbyte    = (uint32)dtoh64(if_stats->txbyte);
		output->txerror   = (uint32)dtoh64(if_stats->txerror);
		output->rxframe   = (uint32)dtoh64(if_stats->rxframe);
		output->rxbyte    = (uint32)dtoh64(if_stats->rxbyte);
		output->txfail    = (uint32)dtoh64(if_stats->txfail);
		output->txretry   = (uint32)dtoh64(if_stats->txretry);
		output->txretrie  = (uint32)dtoh64(if_stats->txretrie);
		if (dtoh16(if_stats->length) > OFFSETOF(wl_if_stats_t, txexptime)) {
			output->txexptime = (uint32)dtoh64(if_stats->txexptime);
			output->txrts     = (uint32)dtoh64(if_stats->txrts);
			output->txnocts   = (uint32)dtoh64(if_stats->txnocts);
		} else {
			output->txexptime = 0;
			output->txrts     = 0;
			output->txnocts   = 0;
		}
	}
#endif /* DISABLE_IF_COUNTERS */

	/* link_speed is in kbps */
	ret = wldev_get_link_speed(dev, &link_speed);
	if (ret || link_speed < 0) {
		ANDROID_ERROR(("wl_android_get_connection_stats: wldev_get_link_speed()"
			" failed, ret=%d, speed=%d\n",
			ret, link_speed));
		goto error;
	}

	output->txrate    = link_speed;

	/* Channel idle ratio. */
	if (wl_chanim_stats(dev, &(output->chan_idle)) < 0) {
		output->chan_idle = 0;
	};

	bytes_written = sizeof(struct connection_stats);

error:
#ifndef DISABLE_IF_COUNTERS
	if (if_stats) {
		MFREE(cfg->osh, if_stats, sizeof(*if_stats));
	}
#endif /* DISABLE_IF_COUNTERS */

	return bytes_written;
}
#endif /* CONNECTION_STATISTICS */

#ifdef WL_NATOE
static int
wl_android_process_natoe_cmd(struct net_device *dev, char *command, int total_len)
{
	int ret = BCME_ERROR;
	char *pcmd = command;
	char *str = NULL;
	wl_natoe_cmd_info_t cmd_info;
	const wl_natoe_sub_cmd_t *natoe_cmd = &natoe_cmd_list[0];

	/* skip to cmd name after "natoe" */
	str = bcmstrtok(&pcmd, " ", NULL);

	/* If natoe subcmd name is not provided, return error */
	if (*pcmd == '\0') {
		ANDROID_ERROR(("natoe subcmd not provided wl_android_process_natoe_cmd\n"));
		ret = -EINVAL;
		return ret;
	}

	/* get the natoe command name to str */
	str = bcmstrtok(&pcmd, " ", NULL);

	while (natoe_cmd->name != NULL) {
		if (strcmp(natoe_cmd->name, str) == 0)  {
			/* dispacth cmd to appropriate handler */
			if (natoe_cmd->handler) {
				cmd_info.command = command;
				cmd_info.tot_len = total_len;
				ret = natoe_cmd->handler(dev, natoe_cmd, pcmd, &cmd_info);
			}
			return ret;
		}
		natoe_cmd++;
	}
	return ret;
}

static int
wlu_natoe_set_vars_cbfn(void *ctx, uint8 *data, uint16 type, uint16 len)
{
	int res = BCME_OK;
	wl_natoe_cmd_info_t *cmd_info = (wl_natoe_cmd_info_t *)ctx;
	uint8 *command = cmd_info->command;
	uint16 total_len = cmd_info->tot_len;
	uint16 bytes_written = 0;

	UNUSED_PARAMETER(len);

	switch (type) {

	case WL_NATOE_XTLV_ENABLE:
	{
		bytes_written = snprintf(command, total_len, "natoe: %s\n",
				*data?"enabled":"disabled");
		cmd_info->bytes_written = bytes_written;
		break;
	}

	case WL_NATOE_XTLV_CONFIG_IPS:
	{
		wl_natoe_config_ips_t *config_ips;
		uint8 buf[16];

		config_ips = (wl_natoe_config_ips_t *)data;
		bcm_ip_ntoa((struct ipv4_addr *)&config_ips->sta_ip, buf);
		bytes_written = snprintf(command, total_len, "sta ip: %s\n", buf);
		bcm_ip_ntoa((struct ipv4_addr *)&config_ips->sta_netmask, buf);
		bytes_written += snprintf(command + bytes_written, total_len,
				"sta netmask: %s\n", buf);
		bcm_ip_ntoa((struct ipv4_addr *)&config_ips->sta_router_ip, buf);
		bytes_written += snprintf(command + bytes_written, total_len,
				"sta router ip: %s\n", buf);
		bcm_ip_ntoa((struct ipv4_addr *)&config_ips->sta_dnsip, buf);
		bytes_written += snprintf(command + bytes_written, total_len,
				"sta dns ip: %s\n", buf);
		bcm_ip_ntoa((struct ipv4_addr *)&config_ips->ap_ip, buf);
		bytes_written += snprintf(command + bytes_written, total_len,
				"ap ip: %s\n", buf);
		bcm_ip_ntoa((struct ipv4_addr *)&config_ips->ap_netmask, buf);
		bytes_written += snprintf(command + bytes_written, total_len,
				"ap netmask: %s\n", buf);
		cmd_info->bytes_written = bytes_written;
		break;
	}

	case WL_NATOE_XTLV_CONFIG_PORTS:
	{
		wl_natoe_ports_config_t *ports_config;

		ports_config = (wl_natoe_ports_config_t *)data;
		bytes_written = snprintf(command, total_len, "starting port num: %d\n",
				dtoh16(ports_config->start_port_num));
		bytes_written += snprintf(command + bytes_written, total_len,
				"number of ports: %d\n", dtoh16(ports_config->no_of_ports));
		cmd_info->bytes_written = bytes_written;
		break;
	}

	case WL_NATOE_XTLV_DBG_STATS:
	{
		char *stats_dump = (char *)data;

		bytes_written = snprintf(command, total_len, "%s\n", stats_dump);
		cmd_info->bytes_written = bytes_written;
		break;
	}

	case WL_NATOE_XTLV_TBL_CNT:
	{
		bytes_written = snprintf(command, total_len, "natoe max tbl entries: %d\n",
				dtoh32(*(uint32 *)data));
		cmd_info->bytes_written = bytes_written;
		break;
	}

	default:
		/* ignore */
		break;
	}

	return res;
}

/*
 *   --- common for all natoe get commands ----
 */
static int
wl_natoe_get_ioctl(struct net_device *dev, wl_natoe_ioc_t *natoe_ioc,
		uint16 iocsz, uint8 *buf, uint16 buflen, wl_natoe_cmd_info_t *cmd_info)
{
	/* for gets we only need to pass ioc header */
	wl_natoe_ioc_t *iocresp = (wl_natoe_ioc_t *)buf;
	int res;

	/*  send getbuf natoe iovar */
	res = wldev_iovar_getbuf(dev, "natoe", natoe_ioc, iocsz, buf,
			buflen, NULL);

	/*  check the response buff  */
	if ((res == BCME_OK)) {
		/* scans ioctl tlvbuf f& invokes the cbfn for processing  */
		res = bcm_unpack_xtlv_buf(cmd_info, iocresp->data, iocresp->len,
				BCM_XTLV_OPTION_ALIGN32, wlu_natoe_set_vars_cbfn);

		if (res == BCME_OK) {
			res = cmd_info->bytes_written;
		}
	}
	else
	{
		ANDROID_ERROR(("wl_natoe_get_ioctl: get command failed code %d\n", res));
		res = BCME_ERROR;
	}

	return res;
}

static int
wl_android_natoe_subcmd_enable(struct net_device *dev, const wl_natoe_sub_cmd_t *cmd,
		char *command, wl_natoe_cmd_info_t *cmd_info)
{
	int ret = BCME_OK;
	wl_natoe_ioc_t *natoe_ioc;
	char *pcmd = command;
	uint16 iocsz = sizeof(*natoe_ioc) + WL_NATOE_IOC_BUFSZ;
	uint16 buflen = WL_NATOE_IOC_BUFSZ;
	bcm_xtlv_t *pxtlv = NULL;
	char *ioctl_buf = NULL;
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);

	ioctl_buf = (char *)MALLOCZ(cfg->osh, WLC_IOCTL_MEDLEN);
	if (!ioctl_buf) {
		ANDROID_ERROR(("ioctl memory alloc failed\n"));
		return -ENOMEM;
	}

	/* alloc mem for ioctl headr + tlv data */
	natoe_ioc = (wl_natoe_ioc_t *)MALLOCZ(cfg->osh, iocsz);
	if (!natoe_ioc) {
		ANDROID_ERROR(("ioctl header memory alloc failed\n"));
		MFREE(cfg->osh, ioctl_buf, WLC_IOCTL_MEDLEN);
		return -ENOMEM;
	}

	/* make up natoe cmd ioctl header */
	natoe_ioc->version = htod16(WL_NATOE_IOCTL_VERSION);
	natoe_ioc->id = htod16(cmd->id);
	natoe_ioc->len = htod16(WL_NATOE_IOC_BUFSZ);
	pxtlv = (bcm_xtlv_t *)natoe_ioc->data;

	if(*pcmd == WL_IOCTL_ACTION_GET) { /* get */
		iocsz = sizeof(*natoe_ioc) + sizeof(*pxtlv);
		ret = wl_natoe_get_ioctl(dev, natoe_ioc, iocsz, ioctl_buf,
				WLC_IOCTL_MEDLEN, cmd_info);
		if (ret != BCME_OK) {
			ANDROID_ERROR(("Fail to get iovar wl_android_natoe_subcmd_enable\n"));
			ret = -EINVAL;
		}
	} else {	/* set */
		uint8 val = bcm_atoi(pcmd);

		/* buflen is max tlv data we can write, it will be decremented as we pack */
		/* save buflen at start */
		uint16 buflen_at_start = buflen;

		/* we'll adjust final ioc size at the end */
		ret = bcm_pack_xtlv_entry((uint8**)&pxtlv, &buflen, WL_NATOE_XTLV_ENABLE,
			sizeof(uint8), &val, BCM_XTLV_OPTION_ALIGN32);

		if (ret != BCME_OK) {
			ret = -EINVAL;
			goto exit;
		}

		/* adjust iocsz to the end of last data record */
		natoe_ioc->len = (buflen_at_start - buflen);
		iocsz = sizeof(*natoe_ioc) + natoe_ioc->len;

		ret = wldev_iovar_setbuf(dev, "natoe",
				natoe_ioc, iocsz, ioctl_buf, WLC_IOCTL_MEDLEN, NULL);
		if (ret != BCME_OK) {
			ANDROID_ERROR(("Fail to set iovar %d\n", ret));
			ret = -EINVAL;
		}
	}

exit:
	MFREE(cfg->osh, ioctl_buf, WLC_IOCTL_MEDLEN);
	MFREE(cfg->osh, natoe_ioc, iocsz);

	return ret;
}

static int
wl_android_natoe_subcmd_config_ips(struct net_device *dev,
		const wl_natoe_sub_cmd_t *cmd, char *command, wl_natoe_cmd_info_t *cmd_info)
{
	int ret = BCME_OK;
	wl_natoe_config_ips_t config_ips;
	wl_natoe_ioc_t *natoe_ioc;
	char *pcmd = command;
	char *str;
	uint16 iocsz = sizeof(*natoe_ioc) + WL_NATOE_IOC_BUFSZ;
	uint16 buflen = WL_NATOE_IOC_BUFSZ;
	bcm_xtlv_t *pxtlv = NULL;
	char *ioctl_buf = NULL;
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);

	ioctl_buf = (char *)MALLOCZ(cfg->osh, WLC_IOCTL_MEDLEN);
	if (!ioctl_buf) {
		ANDROID_ERROR(("ioctl memory alloc failed\n"));
		return -ENOMEM;
	}

	/* alloc mem for ioctl headr + tlv data */
	natoe_ioc = (wl_natoe_ioc_t *)MALLOCZ(cfg->osh, iocsz);
	if (!natoe_ioc) {
		ANDROID_ERROR(("ioctl header memory alloc failed\n"));
		MFREE(cfg->osh, ioctl_buf, WLC_IOCTL_MEDLEN);
		return -ENOMEM;
	}

	/* make up natoe cmd ioctl header */
	natoe_ioc->version = htod16(WL_NATOE_IOCTL_VERSION);
	natoe_ioc->id = htod16(cmd->id);
	natoe_ioc->len = htod16(WL_NATOE_IOC_BUFSZ);
	pxtlv = (bcm_xtlv_t *)natoe_ioc->data;

	if(*pcmd == WL_IOCTL_ACTION_GET) { /* get */
		iocsz = sizeof(*natoe_ioc) + sizeof(*pxtlv);
		ret = wl_natoe_get_ioctl(dev, natoe_ioc, iocsz, ioctl_buf,
				WLC_IOCTL_MEDLEN, cmd_info);
		if (ret != BCME_OK) {
			ANDROID_ERROR(("Fail to get iovar wl_android_natoe_subcmd_config_ips\n"));
			ret = -EINVAL;
		}
	} else {	/* set */
		/* buflen is max tlv data we can write, it will be decremented as we pack */
		/* save buflen at start */
		uint16 buflen_at_start = buflen;

		bzero(&config_ips, sizeof(config_ips));

		str = bcmstrtok(&pcmd, " ", NULL);
		if (!str || !bcm_atoipv4(str, (struct ipv4_addr *)&config_ips.sta_ip)) {
			ANDROID_ERROR(("Invalid STA IP addr %s\n", str));
			ret = -EINVAL;
			goto exit;
		}

		str = bcmstrtok(&pcmd, " ", NULL);
		if (!str || !bcm_atoipv4(str, (struct ipv4_addr *)&config_ips.sta_netmask)) {
			ANDROID_ERROR(("Invalid STA netmask %s\n", str));
			ret = -EINVAL;
			goto exit;
		}

		str = bcmstrtok(&pcmd, " ", NULL);
		if (!str || !bcm_atoipv4(str, (struct ipv4_addr *)&config_ips.sta_router_ip)) {
			ANDROID_ERROR(("Invalid STA router IP addr %s\n", str));
			ret = -EINVAL;
			goto exit;
		}

		str = bcmstrtok(&pcmd, " ", NULL);
		if (!str || !bcm_atoipv4(str, (struct ipv4_addr *)&config_ips.sta_dnsip)) {
			ANDROID_ERROR(("Invalid STA DNS IP addr %s\n", str));
			ret = -EINVAL;
			goto exit;
		}

		str = bcmstrtok(&pcmd, " ", NULL);
		if (!str || !bcm_atoipv4(str, (struct ipv4_addr *)&config_ips.ap_ip)) {
			ANDROID_ERROR(("Invalid AP IP addr %s\n", str));
			ret = -EINVAL;
			goto exit;
		}

		str = bcmstrtok(&pcmd, " ", NULL);
		if (!str || !bcm_atoipv4(str, (struct ipv4_addr *)&config_ips.ap_netmask)) {
			ANDROID_ERROR(("Invalid AP netmask %s\n", str));
			ret = -EINVAL;
			goto exit;
		}

		ret = bcm_pack_xtlv_entry((uint8**)&pxtlv,
				&buflen, WL_NATOE_XTLV_CONFIG_IPS, sizeof(config_ips),
				&config_ips, BCM_XTLV_OPTION_ALIGN32);

		if (ret != BCME_OK) {
			ret = -EINVAL;
			goto exit;
		}

		/* adjust iocsz to the end of last data record */
		natoe_ioc->len = (buflen_at_start - buflen);
		iocsz = sizeof(*natoe_ioc) + natoe_ioc->len;

		ret = wldev_iovar_setbuf(dev, "natoe",
				natoe_ioc, iocsz, ioctl_buf, WLC_IOCTL_MEDLEN, NULL);
		if (ret != BCME_OK) {
			ANDROID_ERROR(("Fail to set iovar %d\n", ret));
			ret = -EINVAL;
		}
	}

exit:
	MFREE(cfg->osh, ioctl_buf, WLC_IOCTL_MEDLEN);
	MFREE(cfg->osh, natoe_ioc, sizeof(*natoe_ioc) + WL_NATOE_IOC_BUFSZ);

	return ret;
}

static int
wl_android_natoe_subcmd_config_ports(struct net_device *dev,
		const wl_natoe_sub_cmd_t *cmd, char *command, wl_natoe_cmd_info_t *cmd_info)
{
	int ret = BCME_OK;
	wl_natoe_ports_config_t ports_config;
	wl_natoe_ioc_t *natoe_ioc;
	char *pcmd = command;
	char *str;
	uint16 iocsz = sizeof(*natoe_ioc) + WL_NATOE_IOC_BUFSZ;
	uint16 buflen = WL_NATOE_IOC_BUFSZ;
	bcm_xtlv_t *pxtlv = NULL;
	char *ioctl_buf = NULL;
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);

	ioctl_buf = (char *)MALLOCZ(cfg->osh, WLC_IOCTL_MEDLEN);
	if (!ioctl_buf) {
		ANDROID_ERROR(("ioctl memory alloc failed\n"));
		return -ENOMEM;
	}

	/* alloc mem for ioctl headr + tlv data */
	natoe_ioc = (wl_natoe_ioc_t *)MALLOCZ(cfg->osh, iocsz);
	if (!natoe_ioc) {
		ANDROID_ERROR(("ioctl header memory alloc failed\n"));
		MFREE(cfg->osh, ioctl_buf, WLC_IOCTL_MEDLEN);
		return -ENOMEM;
	}

	/* make up natoe cmd ioctl header */
	natoe_ioc->version = htod16(WL_NATOE_IOCTL_VERSION);
	natoe_ioc->id = htod16(cmd->id);
	natoe_ioc->len = htod16(WL_NATOE_IOC_BUFSZ);
	pxtlv = (bcm_xtlv_t *)natoe_ioc->data;

	if(*pcmd == WL_IOCTL_ACTION_GET) { /* get */
		iocsz = sizeof(*natoe_ioc) + sizeof(*pxtlv);
		ret = wl_natoe_get_ioctl(dev, natoe_ioc, iocsz, ioctl_buf,
				WLC_IOCTL_MEDLEN, cmd_info);
		if (ret != BCME_OK) {
			ANDROID_ERROR(("Fail to get iovar wl_android_natoe_subcmd_config_ports\n"));
			ret = -EINVAL;
		}
	} else {	/* set */
		/* buflen is max tlv data we can write, it will be decremented as we pack */
		/* save buflen at start */
		uint16 buflen_at_start = buflen;

		bzero(&ports_config, sizeof(ports_config));

		str = bcmstrtok(&pcmd, " ", NULL);
		if (!str) {
			ANDROID_ERROR(("Invalid port string %s\n", str));
			ret = -EINVAL;
			goto exit;
		}
		ports_config.start_port_num = htod16(bcm_atoi(str));

		str = bcmstrtok(&pcmd, " ", NULL);
		if (!str) {
			ANDROID_ERROR(("Invalid port string %s\n", str));
			ret = -EINVAL;
			goto exit;
		}
		ports_config.no_of_ports = htod16(bcm_atoi(str));

		if ((uint32)(ports_config.start_port_num + ports_config.no_of_ports) >
				NATOE_MAX_PORT_NUM) {
			ANDROID_ERROR(("Invalid port configuration\n"));
			ret = -EINVAL;
			goto exit;
		}
		ret = bcm_pack_xtlv_entry((uint8**)&pxtlv,
				&buflen, WL_NATOE_XTLV_CONFIG_PORTS, sizeof(ports_config),
				&ports_config, BCM_XTLV_OPTION_ALIGN32);

		if (ret != BCME_OK) {
			ret = -EINVAL;
			goto exit;
		}

		/* adjust iocsz to the end of last data record */
		natoe_ioc->len = (buflen_at_start - buflen);
		iocsz = sizeof(*natoe_ioc) + natoe_ioc->len;

		ret = wldev_iovar_setbuf(dev, "natoe",
				natoe_ioc, iocsz, ioctl_buf, WLC_IOCTL_MEDLEN, NULL);
		if (ret != BCME_OK) {
			ANDROID_ERROR(("Fail to set iovar %d\n", ret));
			ret = -EINVAL;
		}
	}

exit:
	MFREE(cfg->osh, ioctl_buf, WLC_IOCTL_MEDLEN);
	MFREE(cfg->osh, natoe_ioc, sizeof(*natoe_ioc) + WL_NATOE_IOC_BUFSZ);

	return ret;
}

static int
wl_android_natoe_subcmd_dbg_stats(struct net_device *dev, const wl_natoe_sub_cmd_t *cmd,
		char *command, wl_natoe_cmd_info_t *cmd_info)
{
	int ret = BCME_OK;
	wl_natoe_ioc_t *natoe_ioc;
	char *pcmd = command;
	uint16 kflags = in_atomic() ? GFP_ATOMIC : GFP_KERNEL;
	uint16 iocsz = sizeof(*natoe_ioc) + WL_NATOE_DBG_STATS_BUFSZ;
	uint16 buflen = WL_NATOE_DBG_STATS_BUFSZ;
	bcm_xtlv_t *pxtlv = NULL;
	char *ioctl_buf = NULL;
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);

	ioctl_buf = (char *)MALLOCZ(cfg->osh, WLC_IOCTL_MAXLEN);
	if (!ioctl_buf) {
		ANDROID_ERROR(("ioctl memory alloc failed\n"));
		return -ENOMEM;
	}

	/* alloc mem for ioctl headr + tlv data */
	natoe_ioc = (wl_natoe_ioc_t *)MALLOCZ(cfg->osh, iocsz);
	if (!natoe_ioc) {
		ANDROID_ERROR(("ioctl header memory alloc failed\n"));
		MFREE(cfg->osh, ioctl_buf, WLC_IOCTL_MAXLEN);
		return -ENOMEM;
	}

	/* make up natoe cmd ioctl header */
	natoe_ioc->version = htod16(WL_NATOE_IOCTL_VERSION);
	natoe_ioc->id = htod16(cmd->id);
	natoe_ioc->len = htod16(WL_NATOE_DBG_STATS_BUFSZ);
	pxtlv = (bcm_xtlv_t *)natoe_ioc->data;

	if(*pcmd == WL_IOCTL_ACTION_GET) { /* get */
		iocsz = sizeof(*natoe_ioc) + sizeof(*pxtlv);
		ret = wl_natoe_get_ioctl(dev, natoe_ioc, iocsz, ioctl_buf,
				WLC_IOCTL_MAXLEN, cmd_info);
		if (ret != BCME_OK) {
			ANDROID_ERROR(("Fail to get iovar wl_android_natoe_subcmd_dbg_stats\n"));
			ret = -EINVAL;
		}
	} else {	/* set */
		uint8 val = bcm_atoi(pcmd);

		/* buflen is max tlv data we can write, it will be decremented as we pack */
		/* save buflen at start */
		uint16 buflen_at_start = buflen;

		/* we'll adjust final ioc size at the end */
		ret = bcm_pack_xtlv_entry((uint8**)&pxtlv, &buflen, WL_NATOE_XTLV_ENABLE,
			sizeof(uint8), &val, BCM_XTLV_OPTION_ALIGN32);

		if (ret != BCME_OK) {
			ret = -EINVAL;
			goto exit;
		}

		/* adjust iocsz to the end of last data record */
		natoe_ioc->len = (buflen_at_start - buflen);
		iocsz = sizeof(*natoe_ioc) + natoe_ioc->len;

		ret = wldev_iovar_setbuf(dev, "natoe",
				natoe_ioc, iocsz, ioctl_buf, WLC_IOCTL_MAXLEN, NULL);
		if (ret != BCME_OK) {
			ANDROID_ERROR(("Fail to set iovar %d\n", ret));
			ret = -EINVAL;
		}
	}

exit:
	MFREE(cfg->osh, ioctl_buf, WLC_IOCTL_MAXLEN);
	MFREE(cfg->osh, natoe_ioc, sizeof(*natoe_ioc) + WL_NATOE_DBG_STATS_BUFSZ);

	return ret;
}

static int
wl_android_natoe_subcmd_tbl_cnt(struct net_device *dev, const wl_natoe_sub_cmd_t *cmd,
		char *command, wl_natoe_cmd_info_t *cmd_info)
{
	int ret = BCME_OK;
	wl_natoe_ioc_t *natoe_ioc;
	char *pcmd = command;
	uint16 kflags = in_atomic() ? GFP_ATOMIC : GFP_KERNEL;
	uint16 iocsz = sizeof(*natoe_ioc) + WL_NATOE_IOC_BUFSZ;
	uint16 buflen = WL_NATOE_IOC_BUFSZ;
	bcm_xtlv_t *pxtlv = NULL;
	char *ioctl_buf = NULL;
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);

	ioctl_buf = (char *)MALLOCZ(cfg->osh, WLC_IOCTL_MEDLEN);
	if (!ioctl_buf) {
		ANDROID_ERROR(("ioctl memory alloc failed\n"));
		return -ENOMEM;
	}

	/* alloc mem for ioctl headr + tlv data */
	natoe_ioc = (wl_natoe_ioc_t *)MALLOCZ(cfg->osh, iocsz);
	if (!natoe_ioc) {
		ANDROID_ERROR(("ioctl header memory alloc failed\n"));
		MFREE(cfg->osh, ioctl_buf, WLC_IOCTL_MEDLEN);
		return -ENOMEM;
	}

	/* make up natoe cmd ioctl header */
	natoe_ioc->version = htod16(WL_NATOE_IOCTL_VERSION);
	natoe_ioc->id = htod16(cmd->id);
	natoe_ioc->len = htod16(WL_NATOE_IOC_BUFSZ);
	pxtlv = (bcm_xtlv_t *)natoe_ioc->data;

	if(*pcmd == WL_IOCTL_ACTION_GET) { /* get */
		iocsz = sizeof(*natoe_ioc) + sizeof(*pxtlv);
		ret = wl_natoe_get_ioctl(dev, natoe_ioc, iocsz, ioctl_buf,
				WLC_IOCTL_MEDLEN, cmd_info);
		if (ret != BCME_OK) {
			ANDROID_ERROR(("Fail to get iovar wl_android_natoe_subcmd_tbl_cnt\n"));
			ret = -EINVAL;
		}
	} else {	/* set */
		uint32 val = bcm_atoi(pcmd);

		/* buflen is max tlv data we can write, it will be decremented as we pack */
		/* save buflen at start */
		uint16 buflen_at_start = buflen;

		/* we'll adjust final ioc size at the end */
		ret = bcm_pack_xtlv_entry((uint8**)&pxtlv, &buflen, WL_NATOE_XTLV_TBL_CNT,
			sizeof(uint32), &val, BCM_XTLV_OPTION_ALIGN32);

		if (ret != BCME_OK) {
			ret = -EINVAL;
			goto exit;
		}

		/* adjust iocsz to the end of last data record */
		natoe_ioc->len = (buflen_at_start - buflen);
		iocsz = sizeof(*natoe_ioc) + natoe_ioc->len;

		ret = wldev_iovar_setbuf(dev, "natoe",
				natoe_ioc, iocsz, ioctl_buf, WLC_IOCTL_MEDLEN, NULL);
		if (ret != BCME_OK) {
			ANDROID_ERROR(("Fail to set iovar %d\n", ret));
			ret = -EINVAL;
		}
	}

exit:
	MFREE(cfg->osh, ioctl_buf, WLC_IOCTL_MEDLEN);
	MFREE(cfg->osh, natoe_ioc, sizeof(*natoe_ioc) + WL_NATOE_IOC_BUFSZ);

	return ret;
}

#endif /* WL_NATOE */

#ifdef WL_MBO
static int
wl_android_process_mbo_cmd(struct net_device *dev, char *command, int total_len)
{
	int ret = BCME_ERROR;
	char *pcmd = command;
	char *str = NULL;
	wl_drv_cmd_info_t cmd_info;
	const wl_drv_sub_cmd_t *mbo_cmd = &mbo_cmd_list[0];

	/* skip to cmd name after "mbo" */
	str = bcmstrtok(&pcmd, " ", NULL);

	/* If mbo subcmd name is not provided, return error */
	if (*pcmd == '\0') {
		ANDROID_ERROR(("mbo subcmd not provided %s\n", __FUNCTION__));
		ret = -EINVAL;
		return ret;
	}

	/* get the mbo command name to str */
	str = bcmstrtok(&pcmd, " ", NULL);

	while (mbo_cmd->name != NULL) {
		if (strnicmp(mbo_cmd->name, str, strlen(mbo_cmd->name)) == 0) {
			/* dispatch cmd to appropriate handler */
			if (mbo_cmd->handler) {
				cmd_info.command = command;
				cmd_info.tot_len = total_len;
				ret = mbo_cmd->handler(dev, mbo_cmd, pcmd, &cmd_info);
			}
			return ret;
		}
		mbo_cmd++;
	}
	return ret;
}

static int
wl_android_send_wnm_notif(struct net_device *dev, bcm_iov_buf_t *iov_buf,
	uint16 iov_buf_len, uint8 *iov_resp, uint16 iov_resp_len, uint8 sub_elem_type)
{
	int ret = BCME_OK;
	uint8 *pxtlv = NULL;
	uint16 iovlen = 0;
	uint16 buflen = 0, buflen_start = 0;

	memset_s(iov_buf, iov_buf_len, 0, iov_buf_len);
	iov_buf->version = WL_MBO_IOV_VERSION;
	iov_buf->id = WL_MBO_CMD_SEND_NOTIF;
	buflen = buflen_start = iov_buf_len - sizeof(bcm_iov_buf_t);
	pxtlv = (uint8 *)&iov_buf->data[0];
	ret = bcm_pack_xtlv_entry(&pxtlv, &buflen, WL_MBO_XTLV_SUB_ELEM_TYPE,
		sizeof(sub_elem_type), &sub_elem_type, BCM_XTLV_OPTION_ALIGN32);
	if (ret != BCME_OK) {
		return ret;
	}
	iov_buf->len = buflen_start - buflen;
	iovlen = sizeof(bcm_iov_buf_t) + iov_buf->len;
	ret = wldev_iovar_setbuf(dev, "mbo",
			iov_buf, iovlen, iov_resp, WLC_IOCTL_MAXLEN, NULL);
	if (ret != BCME_OK) {
		ANDROID_ERROR(("Fail to sent wnm notif %d\n", ret));
	}
	return ret;
}

static int
wl_android_mbo_resp_parse_cbfn(void *ctx, const uint8 *data, uint16 type, uint16 len)
{
	wl_drv_cmd_info_t *cmd_info = (wl_drv_cmd_info_t *)ctx;
	uint8 *command = cmd_info->command;
	uint16 total_len = cmd_info->tot_len;
	uint16 bytes_written = 0;

	UNUSED_PARAMETER(len);
	/* TODO: validate data value */
	if (data == NULL) {
		ANDROID_ERROR(("%s: Bad argument !!\n", __FUNCTION__));
		return -EINVAL;
	}
	switch (type) {
		case WL_MBO_XTLV_CELL_DATA_CAP:
		{
			bytes_written = snprintf(command, total_len, "cell_data_cap: %u\n", *data);
			cmd_info->bytes_written = bytes_written;
		}
		break;
		default:
			ANDROID_ERROR(("%s: Unknown tlv %u\n", __FUNCTION__, type));
	}
	return BCME_OK;
}

static int
wl_android_mbo_subcmd_cell_data_cap(struct net_device *dev, const wl_drv_sub_cmd_t *cmd,
		char *command, wl_drv_cmd_info_t *cmd_info)
{
	int ret = BCME_OK;
	uint8 *pxtlv = NULL;
	uint16 buflen = 0, buflen_start = 0;
	uint16 iovlen = 0;
	char *pcmd = command;
	bcm_iov_buf_t *iov_buf = NULL;
	bcm_iov_buf_t *p_resp = NULL;
	uint8 *iov_resp = NULL;
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);
	uint16 version;

	/* first get the configured value */
	iov_buf = (bcm_iov_buf_t *)MALLOCZ(cfg->osh, WLC_IOCTL_MEDLEN);
	if (iov_buf == NULL) {
		ret = -ENOMEM;
		ANDROID_ERROR(("iov buf memory alloc exited\n"));
		goto exit;
	}
	iov_resp = (uint8 *)MALLOCZ(cfg->osh, WLC_IOCTL_MAXLEN);
	if (iov_resp == NULL) {
		ret = -ENOMEM;
		ANDROID_ERROR(("iov resp memory alloc exited\n"));
		goto exit;
	}

	/* fill header */
	iov_buf->version = WL_MBO_IOV_VERSION;
	iov_buf->id = WL_MBO_CMD_CELLULAR_DATA_CAP;

	ret = wldev_iovar_getbuf(dev, "mbo", iov_buf, WLC_IOCTL_MEDLEN, iov_resp,
		WLC_IOCTL_MAXLEN,
		NULL);
	if (ret != BCME_OK) {
		goto exit;
	}
	p_resp = (bcm_iov_buf_t *)iov_resp;

	/* get */
	if (*pcmd == WL_IOCTL_ACTION_GET) {
		/* Check for version */
		version = dtoh16(*(uint16 *)iov_resp);
		if (version != WL_MBO_IOV_VERSION) {
			ret = -EINVAL;
		}
		if (p_resp->id == WL_MBO_CMD_CELLULAR_DATA_CAP) {
			ret = bcm_unpack_xtlv_buf((void *)cmd_info, (uint8 *)p_resp->data,
				p_resp->len, BCM_XTLV_OPTION_ALIGN32,
				wl_android_mbo_resp_parse_cbfn);
			if (ret == BCME_OK) {
				ret = cmd_info->bytes_written;
			}
		} else {
			ret = -EINVAL;
			ANDROID_ERROR(("Mismatch: resp id %d req id %d\n", p_resp->id, cmd->id));
			goto exit;
		}
	} else {
		uint8 cell_cap = bcm_atoi(pcmd);
		const uint8* old_cell_cap = NULL;
		uint16 len = 0;

		old_cell_cap = bcm_get_data_from_xtlv_buf((uint8 *)p_resp->data, p_resp->len,
			WL_MBO_XTLV_CELL_DATA_CAP, &len, BCM_XTLV_OPTION_ALIGN32);
		if (old_cell_cap && *old_cell_cap == cell_cap) {
			ANDROID_ERROR(("No change is cellular data capability\n"));
			/* No change in value */
			goto exit;
		}

		buflen = buflen_start = WLC_IOCTL_MEDLEN - sizeof(bcm_iov_buf_t);

		if (cell_cap < MBO_CELL_DATA_CONN_AVAILABLE ||
			cell_cap > MBO_CELL_DATA_CONN_NOT_CAPABLE) {
			ANDROID_ERROR(("wrong value %u\n", cell_cap));
			ret = -EINVAL;
			goto exit;
		}
		pxtlv = (uint8 *)&iov_buf->data[0];
		ret = bcm_pack_xtlv_entry(&pxtlv, &buflen, WL_MBO_XTLV_CELL_DATA_CAP,
			sizeof(cell_cap), &cell_cap, BCM_XTLV_OPTION_ALIGN32);
		if (ret != BCME_OK) {
			goto exit;
		}
		iov_buf->len = buflen_start - buflen;
		iovlen = sizeof(bcm_iov_buf_t) + iov_buf->len;
		ret = wldev_iovar_setbuf(dev, "mbo",
				iov_buf, iovlen, iov_resp, WLC_IOCTL_MAXLEN, NULL);
		if (ret != BCME_OK) {
			ANDROID_ERROR(("Fail to set iovar %d\n", ret));
			ret = -EINVAL;
			goto exit;
		}
		/* Skip for CUSTOMER_HW4 - WNM notification
		 * for cellular data capability is handled by host
		 */
		/* send a WNM notification request to associated AP */
		if (wl_get_drv_status(cfg, CONNECTED, dev)) {
			ANDROID_INFO(("Sending WNM Notif\n"));
			ret = wl_android_send_wnm_notif(dev, iov_buf, WLC_IOCTL_MEDLEN,
				iov_resp, WLC_IOCTL_MAXLEN, MBO_ATTR_CELL_DATA_CAP);
			if (ret != BCME_OK) {
				ANDROID_ERROR(("Fail to send WNM notification %d\n", ret));
				ret = -EINVAL;
			}
		}
	}
exit:
	if (iov_buf) {
		MFREE(cfg->osh, iov_buf, WLC_IOCTL_MEDLEN);
	}
	if (iov_resp) {
		MFREE(cfg->osh, iov_resp, WLC_IOCTL_MAXLEN);
	}
	return ret;
}

static int
wl_android_mbo_non_pref_chan_parse_cbfn(void *ctx, const uint8 *data, uint16 type, uint16 len)
{
	wl_drv_cmd_info_t *cmd_info = (wl_drv_cmd_info_t *)ctx;
	uint8 *command = cmd_info->command + cmd_info->bytes_written;
	uint16 total_len = cmd_info->tot_len;
	uint16 bytes_written = 0;

	ANDROID_INFO(("Total bytes written at begining %u\n", cmd_info->bytes_written));
	UNUSED_PARAMETER(len);
	if (data == NULL) {
		ANDROID_ERROR(("%s: Bad argument !!\n", __FUNCTION__));
		return -EINVAL;
	}
	switch (type) {
		case WL_MBO_XTLV_OPCLASS:
		{
			bytes_written = snprintf(command, total_len, "%u:", *data);
			ANDROID_ERROR(("wr %u %u\n", bytes_written, *data));
			command += bytes_written;
			cmd_info->bytes_written += bytes_written;
		}
		break;
		case WL_MBO_XTLV_CHAN:
		{
			bytes_written = snprintf(command, total_len, "%u:", *data);
			ANDROID_ERROR(("wr %u\n", bytes_written));
			command += bytes_written;
			cmd_info->bytes_written += bytes_written;
		}
		break;
		case WL_MBO_XTLV_PREFERENCE:
		{
			bytes_written = snprintf(command, total_len, "%u:", *data);
			ANDROID_ERROR(("wr %u\n", bytes_written));
			command += bytes_written;
			cmd_info->bytes_written += bytes_written;
		}
		break;
		case WL_MBO_XTLV_REASON_CODE:
		{
			bytes_written = snprintf(command, total_len, "%u ", *data);
			ANDROID_ERROR(("wr %u\n", bytes_written));
			command += bytes_written;
			cmd_info->bytes_written += bytes_written;
		}
		break;
		default:
			ANDROID_ERROR(("%s: Unknown tlv %u\n", __FUNCTION__, type));
	}
	ANDROID_INFO(("Total bytes written %u\n", cmd_info->bytes_written));
	return BCME_OK;
}

static int
wl_android_mbo_subcmd_non_pref_chan(struct net_device *dev,
		const wl_drv_sub_cmd_t *cmd, char *command,
		wl_drv_cmd_info_t *cmd_info)
{
	int ret = BCME_OK;
	uint8 *pxtlv = NULL;
	uint16 buflen = 0, buflen_start = 0;
	uint16 iovlen = 0;
	char *pcmd = command;
	bcm_iov_buf_t *iov_buf = NULL;
	bcm_iov_buf_t *p_resp = NULL;
	uint8 *iov_resp = NULL;
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);
	uint16 version;

	ANDROID_ERROR(("%s:%d\n", __FUNCTION__, __LINE__));
	iov_buf = (bcm_iov_buf_t *)MALLOCZ(cfg->osh, WLC_IOCTL_MEDLEN);
	if (iov_buf == NULL) {
		ret = -ENOMEM;
		ANDROID_ERROR(("iov buf memory alloc exited\n"));
		goto exit;
	}
	iov_resp = (uint8 *)MALLOCZ(cfg->osh, WLC_IOCTL_MAXLEN);
	if (iov_resp == NULL) {
		ret = -ENOMEM;
		ANDROID_ERROR(("iov resp memory alloc exited\n"));
		goto exit;
	}
	/* get */
	if (*pcmd == WL_IOCTL_ACTION_GET) {
		/* fill header */
		iov_buf->version = WL_MBO_IOV_VERSION;
		iov_buf->id = WL_MBO_CMD_LIST_CHAN_PREF;

		ret = wldev_iovar_getbuf(dev, "mbo", iov_buf, WLC_IOCTL_MEDLEN, iov_resp,
				WLC_IOCTL_MAXLEN, NULL);
		if (ret != BCME_OK) {
			goto exit;
		}
		p_resp = (bcm_iov_buf_t *)iov_resp;
		/* Check for version */
		version = dtoh16(*(uint16 *)iov_resp);
		if (version != WL_MBO_IOV_VERSION) {
			ANDROID_ERROR(("Version mismatch. returned ver %u expected %u\n",
				version, WL_MBO_IOV_VERSION));
			ret = -EINVAL;
		}
		if (p_resp->id == WL_MBO_CMD_LIST_CHAN_PREF) {
			ret = bcm_unpack_xtlv_buf((void *)cmd_info, (uint8 *)p_resp->data,
				p_resp->len, BCM_XTLV_OPTION_ALIGN32,
				wl_android_mbo_non_pref_chan_parse_cbfn);
			if (ret == BCME_OK) {
				ret = cmd_info->bytes_written;
			}
		} else {
			ret = -EINVAL;
			ANDROID_ERROR(("Mismatch: resp id %d req id %d\n", p_resp->id, cmd->id));
			goto exit;
		}
	} else {
		char *str = pcmd;
		uint opcl = 0, ch = 0, pref = 0, rc = 0;

		str = bcmstrtok(&pcmd, " ", NULL);
		if (!(strnicmp(str, "set", 3)) || (!strnicmp(str, "clear", 5))) {
			/* delete all configurations */
			iov_buf->version = WL_MBO_IOV_VERSION;
			iov_buf->id = WL_MBO_CMD_DEL_CHAN_PREF;
			iov_buf->len = 0;
			iovlen = sizeof(bcm_iov_buf_t) + iov_buf->len;
			ret = wldev_iovar_setbuf(dev, "mbo",
				iov_buf, iovlen, iov_resp, WLC_IOCTL_MAXLEN, NULL);
			if (ret != BCME_OK) {
				ANDROID_ERROR(("Fail to set iovar %d\n", ret));
				ret = -EINVAL;
				goto exit;
			}
		} else {
			ANDROID_ERROR(("Unknown command %s\n", str));
			goto exit;
		}
		/* parse non pref channel list */
		if (strnicmp(str, "set", 3) == 0) {
			uint8 cnt = 0;
			str = bcmstrtok(&pcmd, " ", NULL);
			while (str != NULL) {
				ret = sscanf(str, "%u:%u:%u:%u", &opcl, &ch, &pref, &rc);
				ANDROID_ERROR(("buflen %u op %u, ch %u, pref %u rc %u\n",
					buflen, opcl, ch, pref, rc));
				if (ret != 4) {
					ANDROID_ERROR(("Not all parameter presents\n"));
					ret = -EINVAL;
				}
				/* TODO: add a validation check here */
				memset_s(iov_buf, WLC_IOCTL_MEDLEN, 0, WLC_IOCTL_MEDLEN);
				buflen = buflen_start = WLC_IOCTL_MEDLEN;
				pxtlv = (uint8 *)&iov_buf->data[0];
				/* opclass */
				ret = bcm_pack_xtlv_entry(&pxtlv, &buflen, WL_MBO_XTLV_OPCLASS,
					sizeof(uint8), (uint8 *)&opcl, BCM_XTLV_OPTION_ALIGN32);
				if (ret != BCME_OK) {
					goto exit;
				}
				/* channel */
				ret = bcm_pack_xtlv_entry(&pxtlv, &buflen, WL_MBO_XTLV_CHAN,
					sizeof(uint8), (uint8 *)&ch, BCM_XTLV_OPTION_ALIGN32);
				if (ret != BCME_OK) {
					goto exit;
				}
				/* preference */
				ret = bcm_pack_xtlv_entry(&pxtlv, &buflen, WL_MBO_XTLV_PREFERENCE,
					sizeof(uint8), (uint8 *)&pref, BCM_XTLV_OPTION_ALIGN32);
				if (ret != BCME_OK) {
					goto exit;
				}
				/* reason */
				ret = bcm_pack_xtlv_entry(&pxtlv, &buflen, WL_MBO_XTLV_REASON_CODE,
					sizeof(uint8), (uint8 *)&rc, BCM_XTLV_OPTION_ALIGN32);
				if (ret != BCME_OK) {
					goto exit;
				}
				ANDROID_ERROR(("len %u\n", (buflen_start - buflen)));
				/* Now set the new non pref channels */
				iov_buf->version = WL_MBO_IOV_VERSION;
				iov_buf->id = WL_MBO_CMD_ADD_CHAN_PREF;
				iov_buf->len = buflen_start - buflen;
				iovlen = sizeof(bcm_iov_buf_t) + iov_buf->len;
				ret = wldev_iovar_setbuf(dev, "mbo",
					iov_buf, iovlen, iov_resp, WLC_IOCTL_MEDLEN, NULL);
				if (ret != BCME_OK) {
					ANDROID_ERROR(("Fail to set iovar %d\n", ret));
					ret = -EINVAL;
					goto exit;
				}
				cnt++;
				if (cnt >= MBO_MAX_CHAN_PREF_ENTRIES) {
					break;
				}
				ANDROID_ERROR(("%d cnt %u\n", __LINE__, cnt));
				str = bcmstrtok(&pcmd, " ", NULL);
			}
		}
		/* send a WNM notification request to associated AP */
		if (wl_get_drv_status(cfg, CONNECTED, dev)) {
			ANDROID_INFO(("Sending WNM Notif\n"));
			ret = wl_android_send_wnm_notif(dev, iov_buf, WLC_IOCTL_MEDLEN,
				iov_resp, WLC_IOCTL_MAXLEN, MBO_ATTR_NON_PREF_CHAN_REPORT);
			if (ret != BCME_OK) {
				ANDROID_ERROR(("Fail to send WNM notification %d\n", ret));
				ret = -EINVAL;
			}
		}
	}
exit:
	if (iov_buf) {
		MFREE(cfg->osh, iov_buf, WLC_IOCTL_MEDLEN);
	}
	if (iov_resp) {
		MFREE(cfg->osh, iov_resp, WLC_IOCTL_MAXLEN);
	}
	return ret;
}
#endif /* WL_MBO */

#if defined(CONFIG_WLAN_BEYONDX) || defined(CONFIG_SEC_5GMODEL)
extern int wl_cfg80211_send_msg_to_ril(void);
extern void wl_cfg80211_register_dev_ril_bridge_event_notifier(void);
extern void wl_cfg80211_unregister_dev_ril_bridge_event_notifier(void);
extern int g_mhs_chan_for_cpcoex;
#endif /* CONFIG_WLAN_BEYONDX || defined(CONFIG_SEC_5GMODEL) */

#if defined(WL_SUPPORT_AUTO_CHANNEL)
/* SoftAP feature */
#define APCS_BAND_2G_LEGACY1	20
#define APCS_BAND_2G_LEGACY2	0
#define APCS_BAND_AUTO		"band=auto"
#define APCS_BAND_2G		"band=2g"
#define APCS_BAND_5G		"band=5g"
#define APCS_MAX_2G_CHANNELS	11
#define APCS_MAX_RETRY		10
#define APCS_DEFAULT_2G_CH	1
#define APCS_DEFAULT_5G_CH	149

static int
wl_android_set_auto_channel(struct net_device *dev, const char* cmd_str,
	char* command, int total_len)
{
	int channel = 0;
	int chosen = 0;
	int retry = 0;
	int ret = 0;
	int spect = 0;
	u8 *reqbuf = NULL;
	uint32 band = WLC_BAND_2G, sta_band = WLC_BAND_2G;
	uint32 buf_size;
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);

	if (cmd_str) {
		ANDROID_INFO(("Command: %s len:%d \n", cmd_str, (int)strlen(cmd_str)));
		if (strnicmp(cmd_str, APCS_BAND_AUTO, strlen(APCS_BAND_AUTO)) == 0) {
			band = WLC_BAND_AUTO;
		} else if (strnicmp(cmd_str, APCS_BAND_5G, strlen(APCS_BAND_5G)) == 0) {
			band = WLC_BAND_5G;
		} else if (strnicmp(cmd_str, APCS_BAND_2G, strlen(APCS_BAND_2G)) == 0) {
			band = WLC_BAND_2G;
		} else {
			/*
			 * For backward compatibility: Some platforms used to issue argument 20 or 0
			 * to enforce the 2G channel selection
			 */
			channel = bcm_atoi(cmd_str);
			if ((channel == APCS_BAND_2G_LEGACY1) ||
				(channel == APCS_BAND_2G_LEGACY2)) {
				band = WLC_BAND_2G;
			} else {
				ANDROID_ERROR(("Invalid argument\n"));
				return -EINVAL;
			}
		}
	} else {
		/* If no argument is provided, default to 2G */
		ANDROID_ERROR(("No argument given default to 2.4G scan\n"));
		band = WLC_BAND_2G;
	}
	ANDROID_INFO(("HAPD_AUTO_CHANNEL = %d, band=%d \n", channel, band));

#if defined(CONFIG_WLAN_BEYONDX) || defined(CONFIG_SEC_5GMODEL)
	wl_cfg80211_register_dev_ril_bridge_event_notifier();
	if (band == WLC_BAND_2G) {
		wl_cfg80211_send_msg_to_ril();

		if (g_mhs_chan_for_cpcoex) {
			channel = g_mhs_chan_for_cpcoex;
			g_mhs_chan_for_cpcoex = 0;
			goto done2;
		}
	}
	wl_cfg80211_unregister_dev_ril_bridge_event_notifier();
#endif /* CONFIG_WLAN_BEYONDX || defined(CONFIG_SEC_5GMODEL) */

	/* If STA is connected, return is STA channel, else ACS can be issued,
	 * set spect to 0 and proceed with ACS
	 */
	channel = wl_cfg80211_get_sta_channel(cfg);
	if (channel) {
		sta_band = WL_GET_BAND(channel);
		switch (sta_band) {
			case (WL_CHANSPEC_BAND_5G): {
				if (band == WLC_BAND_2G || band == WLC_BAND_AUTO) {
					channel = APCS_DEFAULT_2G_CH;
				}
				break;
			}
			case (WL_CHANSPEC_BAND_2G): {
				if (band == WLC_BAND_5G) {
					channel = APCS_DEFAULT_5G_CH;
				}
				break;
			}
			default:
				/* Intentional fall through to use same sta channel for softap */
				break;
		}
		WL_MSG(dev->name, "band=%d, sta_band=%d, channel=%d\n", band, sta_band, channel);
		goto done2;
	}

	channel = wl_ext_autochannel(dev, ACS_FW_BIT|ACS_DRV_BIT, band);
	if (channel)
		goto done2;
	else
		goto done;

	ret = wldev_ioctl_get(dev, WLC_GET_SPECT_MANAGMENT, &spect, sizeof(spect));
	if (ret) {
		ANDROID_ERROR(("ACS: error getting the spect, ret=%d\n", ret));
		goto done;
	}

	if (spect > 0) {
		ret = wl_cfg80211_set_spect(dev, 0);
		if (ret < 0) {
			ANDROID_ERROR(("ACS: error while setting spect, ret=%d\n", ret));
			goto done;
		}
	}

	reqbuf = (u8 *)MALLOCZ(cfg->osh, CHANSPEC_BUF_SIZE);
	if (reqbuf == NULL) {
		ANDROID_ERROR(("failed to allocate chanspec buffer\n"));
		return -ENOMEM;
	}

	if (band == WLC_BAND_AUTO) {
		ANDROID_INFO(("ACS full channel scan \n"));
		reqbuf[0] = htod32(0);
	} else if (band == WLC_BAND_5G) {
		ANDROID_INFO(("ACS 5G band scan \n"));
		if ((ret = wl_cfg80211_get_chanspecs_5g(dev, reqbuf, CHANSPEC_BUF_SIZE)) < 0) {
			ANDROID_ERROR(("ACS 5g chanspec retreival failed! \n"));
			goto done;
		}
	} else if (band == WLC_BAND_2G) {
		/*
		 * If channel argument is not provided/ argument 20 is provided,
		 * Restrict channel to 2GHz, 20MHz BW, No SB
		 */
		ANDROID_INFO(("ACS 2G band scan \n"));
		if ((ret = wl_cfg80211_get_chanspecs_2g(dev, reqbuf, CHANSPEC_BUF_SIZE)) < 0) {
			ANDROID_ERROR(("ACS 2g chanspec retreival failed! \n"));
			goto done;
		}
	} else {
		ANDROID_ERROR(("ACS: No band chosen\n"));
		goto done2;
	}

	buf_size = (band == WLC_BAND_AUTO) ? sizeof(int) : CHANSPEC_BUF_SIZE;
	ret = wldev_ioctl_set(dev, WLC_START_CHANNEL_SEL, (void *)reqbuf,
		buf_size);
	if (ret < 0) {
		ANDROID_ERROR(("can't start auto channel scan, err = %d\n", ret));
		channel = 0;
		goto done;
	}

	/* Wait for auto channel selection, max 3000 ms */
	if ((band == WLC_BAND_2G) || (band == WLC_BAND_5G)) {
		OSL_SLEEP(500);
	} else {
		/*
		 * Full channel scan at the minimum takes 1.2secs
		 * even with parallel scan. max wait time: 3500ms
		 */
		OSL_SLEEP(1000);
	}

	retry = APCS_MAX_RETRY;
	while (retry--) {
		ret = wldev_ioctl_get(dev, WLC_GET_CHANNEL_SEL, &chosen,
			sizeof(chosen));
		if (ret < 0) {
			chosen = 0;
		} else {
			chosen = dtoh32(chosen);
		}

		if (chosen) {
			int chosen_band;
			int apcs_band;
#ifdef D11AC_IOTYPES
			if (wl_cfg80211_get_ioctl_version() == 1) {
				channel = LCHSPEC_CHANNEL((chanspec_t)chosen);
			} else {
				channel = CHSPEC_CHANNEL((chanspec_t)chosen);
			}
#else
			channel = CHSPEC_CHANNEL((chanspec_t)chosen);
#endif /* D11AC_IOTYPES */
			apcs_band = (band == WLC_BAND_AUTO) ? WLC_BAND_2G : band;
			chosen_band = (channel <= CH_MAX_2G_CHANNEL) ? WLC_BAND_2G : WLC_BAND_5G;
			if (apcs_band == chosen_band) {
				WL_MSG(dev->name, "selected channel = %d\n", channel);
				break;
			}
		}
		ANDROID_INFO(("%d tried, ret = %d, chosen = 0x%x\n",
			(APCS_MAX_RETRY - retry), ret, chosen));
		OSL_SLEEP(250);
	}

done:
	if ((retry == 0) || (ret < 0)) {
		/* On failure, fallback to a default channel */
		if (band == WLC_BAND_5G) {
			channel = APCS_DEFAULT_5G_CH;
		} else {
			channel = APCS_DEFAULT_2G_CH;
		}
		ANDROID_ERROR(("ACS failed. Fall back to default channel (%d) \n", channel));
	}
done2:
	if (spect > 0) {
		if ((ret = wl_cfg80211_set_spect(dev, spect) < 0)) {
			ANDROID_ERROR(("ACS: error while setting spect\n"));
		}
	}

	if (reqbuf) {
		MFREE(cfg->osh, reqbuf, CHANSPEC_BUF_SIZE);
	}

	if (channel) {
		ret = snprintf(command, total_len, "%d", channel);
		ANDROID_INFO(("command result is %s \n", command));
	}

	return ret;
}
#endif /* WL_SUPPORT_AUTO_CHANNEL */

int wl_android_set_roam_mode(struct net_device *dev, char *command)
{
	int error = 0;
	int mode = 0;

	if (sscanf(command, "%*s %d", &mode) != 1) {
		ANDROID_ERROR(("%s: Failed to get Parameter\n", __FUNCTION__));
		return -1;
	}

	error = wldev_iovar_setint(dev, "roam_off", mode);
	if (error) {
		ANDROID_ERROR(("%s: Failed to set roaming Mode %d, error = %d\n",
		__FUNCTION__, mode, error));
		return -1;
	}
	else
		ANDROID_ERROR(("%s: succeeded to set roaming Mode %d, error = %d\n",
		__FUNCTION__, mode, error));
	return 0;
}

#ifdef WL_CFG80211
int wl_android_set_ibss_beacon_ouidata(struct net_device *dev, char *command, int total_len)
{
	char ie_buf[VNDR_IE_MAX_LEN];
	char *ioctl_buf = NULL;
	char hex[] = "XX";
	char *pcmd = NULL;
	int ielen = 0, datalen = 0, idx = 0, tot_len = 0;
	vndr_ie_setbuf_t *vndr_ie = NULL;
	s32 iecount;
	uint32 pktflag;
	s32 err = BCME_OK, bssidx;
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);

	/* Check the VSIE (Vendor Specific IE) which was added.
	 *  If exist then send IOVAR to delete it
	 */
	if (wl_cfg80211_ibss_vsie_delete(dev) != BCME_OK) {
		return -EINVAL;
	}

	if (total_len < (strlen(CMD_SETIBSSBEACONOUIDATA) + 1)) {
		ANDROID_ERROR(("error. total_len:%d\n", total_len));
		return -EINVAL;
	}

	pcmd = command + strlen(CMD_SETIBSSBEACONOUIDATA) + 1;
	for (idx = 0; idx < DOT11_OUI_LEN; idx++) {
		if (*pcmd == '\0') {
			ANDROID_ERROR(("error while parsing OUI.\n"));
			return -EINVAL;
		}
		hex[0] = *pcmd++;
		hex[1] = *pcmd++;
		ie_buf[idx] =  (uint8)simple_strtoul(hex, NULL, 16);
	}
	pcmd++;
	while ((*pcmd != '\0') && (idx < VNDR_IE_MAX_LEN)) {
		hex[0] = *pcmd++;
		hex[1] = *pcmd++;
		ie_buf[idx++] =  (uint8)simple_strtoul(hex, NULL, 16);
		datalen++;
	}

	if (datalen <= 0) {
		ANDROID_ERROR(("error. vndr ie len:%d\n", datalen));
		return -EINVAL;
	}

	tot_len = (int)(sizeof(vndr_ie_setbuf_t) + (datalen - 1));
	vndr_ie = (vndr_ie_setbuf_t *)MALLOCZ(cfg->osh, tot_len);
	if (!vndr_ie) {
		ANDROID_ERROR(("IE memory alloc failed\n"));
		return -ENOMEM;
	}
	/* Copy the vndr_ie SET command ("add"/"del") to the buffer */
	strlcpy(vndr_ie->cmd, "add", sizeof(vndr_ie->cmd));

	/* Set the IE count - the buffer contains only 1 IE */
	iecount = htod32(1);
	memcpy((void *)&vndr_ie->vndr_ie_buffer.iecount, &iecount, sizeof(s32));

	/* Set packet flag to indicate that BEACON's will contain this IE */
	pktflag = htod32(VNDR_IE_BEACON_FLAG | VNDR_IE_PRBRSP_FLAG);
	memcpy((void *)&vndr_ie->vndr_ie_buffer.vndr_ie_list[0].pktflag, &pktflag,
		sizeof(u32));
	/* Set the IE ID */
	vndr_ie->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.id = (uchar) DOT11_MNG_PROPR_ID;

	memcpy(&vndr_ie->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.oui, &ie_buf,
		DOT11_OUI_LEN);
	memcpy(&vndr_ie->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.data,
		&ie_buf[DOT11_OUI_LEN], datalen);

	ielen = DOT11_OUI_LEN + datalen;
	vndr_ie->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.len = (uchar) ielen;

	ioctl_buf = (char *)MALLOC(cfg->osh, WLC_IOCTL_MEDLEN);
	if (!ioctl_buf) {
		ANDROID_ERROR(("ioctl memory alloc failed\n"));
		if (vndr_ie) {
			MFREE(cfg->osh, vndr_ie, tot_len);
		}
		return -ENOMEM;
	}
	bzero(ioctl_buf, WLC_IOCTL_MEDLEN);	/* init the buffer */
	if ((bssidx = wl_get_bssidx_by_wdev(cfg, dev->ieee80211_ptr)) < 0) {
		ANDROID_ERROR(("Find index failed\n"));
		err = BCME_ERROR;
		goto end;
	}
	err = wldev_iovar_setbuf_bsscfg(dev, "vndr_ie", vndr_ie, tot_len, ioctl_buf,
			WLC_IOCTL_MEDLEN, bssidx, &cfg->ioctl_buf_sync);
end:
	if (err != BCME_OK) {
		err = -EINVAL;
		if (vndr_ie) {
			MFREE(cfg->osh, vndr_ie, tot_len);
		}
	}
	else {
		/* do NOT free 'vndr_ie' for the next process */
		wl_cfg80211_ibss_vsie_set_buffer(dev, vndr_ie, tot_len);
	}

	if (ioctl_buf) {
		MFREE(cfg->osh, ioctl_buf, WLC_IOCTL_MEDLEN);
	}

	return err;
}
#endif /* WL_CFG80211 */
