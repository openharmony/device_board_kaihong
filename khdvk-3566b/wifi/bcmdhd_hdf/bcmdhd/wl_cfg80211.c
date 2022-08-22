/*
 * Linux cfg80211 driver
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
 * $Id: wl_cfg80211.c 826086 2019-06-18 19:23:59Z $
 */
/* */
#include <typedefs.h>
#include <linuxver.h>
#include <linux/kernel.h>
#ifdef CONFIG_AP6XXX_WIFI6_HDF
#include "hdf_mac80211_sta_event.h"
#endif
#include <bcmutils.h>
#include <bcmstdlib_s.h>
#include <bcmwifi_channels.h>
#include <bcmendian.h>
#include <ethernet.h>
#ifdef WL_WPS_SYNC
#include <dhd_eapol.h>
#endif /* WL_WPS_SYNC */
#include <802.11.h>
#include <bcmiov.h>
#include <linux/if_arp.h>
#include <asm/uaccess.h>

#include <ethernet.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/wait.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>

#include <wlioctl.h>
#include <bcmevent.h>
#include <wldev_common.h>
#include <wl_cfg80211.h>
#include <wl_cfgp2p.h>
#include <wl_cfgscan.h>
#include <bcmdevs.h>
#ifdef WL_FILS
#include <fils.h>
#include <frag.h>
#endif /* WL_FILS */
#include <wl_android.h>
#include <dngl_stats.h>
#include <dhd.h>
#include <dhd_linux.h>
#include <dhd_linux_pktdump.h>
#include <dhd_debug.h>
#include <dhdioctl.h>
#include <wlioctl.h>
#include <dhd_cfg80211.h>
#include <dhd_bus.h>
#ifdef PNO_SUPPORT
#include <dhd_pno.h>
#endif /* PNO_SUPPORT */
#include <wl_cfgvendor.h>

#if !defined(WL_VENDOR_EXT_SUPPORT)
#undef GSCAN_SUPPORT
#endif
#include <dhd_config.h>

#ifdef WL_NAN
#include <wl_cfgnan.h>
#endif /* WL_NAN */

#ifdef PROP_TXSTATUS
#include <dhd_wlfc.h>
#endif // endif

#ifdef BCMPCIE
#include <dhd_flowring.h>
#endif // endif
#ifdef RTT_SUPPORT
#include <dhd_rtt.h>
#endif /* RTT_SUPPORT */

#define BRCM_SAE_VENDOR_EVENT_BUF_LEN 500

#ifdef DNGL_AXI_ERROR_LOGGING
#include <bcmtlv.h>
#endif /* DNGL_AXI_ERROR_LOGGING */

#if defined(CONFIG_WLAN_BEYONDX) || defined(CONFIG_SEC_5GMODEL)
#include <linux/dev_ril_bridge.h>
#include <linux/notifier.h>
#endif /* CONFIG_WLAN_BEYONDX || defined(CONFIG_SEC_5GMODEL) */

#ifdef BCMWAPI_WPI
/* these items should evetually go into wireless.h of the linux system headfile dir */
#ifndef IW_ENCODE_ALG_SM4
#define IW_ENCODE_ALG_SM4 0x20
#endif // endif

#ifndef IW_AUTH_WAPI_ENABLED
#define IW_AUTH_WAPI_ENABLED 0x20
#endif // endif

#ifndef IW_AUTH_WAPI_VERSION_1
#define IW_AUTH_WAPI_VERSION_1  0x00000008
#endif // endif

#ifndef IW_AUTH_CIPHER_SMS4
#define IW_AUTH_CIPHER_SMS4     0x00000020
#endif // endif

#ifndef IW_AUTH_KEY_MGMT_WAPI_PSK
#define IW_AUTH_KEY_MGMT_WAPI_PSK 4
#endif // endif

#ifndef IW_AUTH_KEY_MGMT_WAPI_CERT
#define IW_AUTH_KEY_MGMT_WAPI_CERT 8
#endif // endif
#endif /* BCMWAPI_WPI */

#ifdef BCMWAPI_WPI
#define IW_WSEC_ENABLED(wsec)   ((wsec) & (WEP_ENABLED | TKIP_ENABLED | AES_ENABLED | SMS4_ENABLED))
#else /* BCMWAPI_WPI */
#define IW_WSEC_ENABLED(wsec)   ((wsec) & (WEP_ENABLED | TKIP_ENABLED | AES_ENABLED))
#endif /* BCMWAPI_WPI */

#if (defined(WL_FW_OCE_AP_SELECT) || defined(BCMFW_ROAM_ENABLE) && ((LINUX_VERSION_CODE \
	>= KERNEL_VERSION(3, 2, 0)) || defined(WL_COMPAT_WIRELESS)))
uint fw_ap_select = true;
#else
uint fw_ap_select = false;
#endif /* WL_FW_OCE_AP_SELECT && (ROAM_ENABLE || BCMFW_ROAM_ENABLE) */
module_param(fw_ap_select, uint, 0660);

static struct device *cfg80211_parent_dev = NULL;
static struct bcm_cfg80211 *g_bcmcfg = NULL;
u32 wl_dbg_level = 0xff;
//u32 wl_dbg_level = WL_DBG_ERR; // | WL_DBG_P2P_ACTION | WL_DBG_INFO;

#define	MAX_VIF_OFFSET	15
#define MAX_WAIT_TIME 1500
#ifdef WLAIBSS_MCHAN
#define IBSS_IF_NAME "ibss%d"
#endif /* WLAIBSS_MCHAN */

#ifdef VSDB
/* sleep time to keep STA's connecting or connection for continuous af tx or finding a peer */
#define DEFAULT_SLEEP_TIME_VSDB		120
#define OFF_CHAN_TIME_THRESHOLD_MS	200
#define AF_RETRY_DELAY_TIME			40

/* if sta is connected or connecting, sleep for a while before retry af tx or finding a peer */
#define WL_AF_TX_KEEP_PRI_CONNECTION_VSDB(cfg)	\
	do {	\
		if (wl_get_drv_status(cfg, CONNECTED, bcmcfg_to_prmry_ndev(cfg)) ||	\
			wl_get_drv_status(cfg, CONNECTING, bcmcfg_to_prmry_ndev(cfg))) {	\
			OSL_SLEEP(DEFAULT_SLEEP_TIME_VSDB);			\
		}	\
	} while (0)
#else /* VSDB */
/* if not VSDB, do nothing */
#define WL_AF_TX_KEEP_PRI_CONNECTION_VSDB(cfg)
#endif /* VSDB */

#define DNGL_FUNC(func, parameters) func parameters
#define COEX_DHCP

#define WLAN_EID_SSID	0
#define CH_MIN_5G_CHANNEL 34

#ifdef WL_RELMCAST
enum rmc_event_type {
	RMC_EVENT_NONE,
	RMC_EVENT_LEADER_CHECK_FAIL
};
#endif /* WL_RELMCAST */

#ifdef CONFIG_AP6XXX_WIFI6_HDF
#include "hdf_wl_interface.h"
#include "net_device.h"
int32_t HdfWifiEventMgmtTxStatus(const struct NetDevice *netDev, const uint8_t *buf, size_t len, uint8_t ack);
int32_t HdfWifiEventRxMgmt(const struct NetDevice *netDev, int32_t freq, int32_t sigMbm, const uint8_t *buf, size_t len);
int32_t HdfWifiEventCsaChannelSwitch(const struct NetDevice *netDev, int32_t freq);
int32_t HdfWifiEventRemainOnChannel(const struct NetDevice *netDev, uint32_t freq, uint32_t duration);

struct NetDevice * GetHdfNetDeviceByLinuxInf(struct net_device *dev);

int ChangNewSta(struct net_device *dev, const uint8_t *macAddr, uint8_t addrLen,
    const struct station_info *info);
int ChangDelSta(struct net_device *dev,const uint8_t *macAddr, uint8_t addrLen);
extern void HdfInformBssFrameEventCallback(struct net_device *ndev, struct ieee80211_channel *channel, int32_t signal,
    int16_t freq, struct ieee80211_mgmt *mgmt, uint32_t mgmtLen);
extern int32_t HdfConnectResultEventCallback(struct net_device *ndev, uint8_t *bssid, uint8_t *reqIe,
    uint8_t *rspIe, uint32_t reqIeLen, uint32_t rspIeLen, uint16_t connectStatus, uint16_t freq);

extern int g_event_ifidx;
extern struct hdf_inf_map g_hdf_infmap[HDF_INF_MAX];
struct NetDevice * get_hdf_netdev(int ifidx);

extern int g_mgmt_tx_event_ifidx;

#endif

/* This is to override regulatory domains defined in cfg80211 module (reg.c)
 * By default world regulatory domain defined in reg.c puts the flags NL80211_RRF_PASSIVE_SCAN
 * and NL80211_RRF_NO_IBSS for 5GHz channels (for 36..48 and 149..165).
 * With respect to these flags, wpa_supplicant doesn't start p2p operations on 5GHz channels.
 * All the chnages in world regulatory domain are to be done here.
 *
 * this definition reuires disabling missing-field-initializer warning
 * as the ieee80211_regdomain definition differs in plain linux and in Android
 */
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == \
	4 && __GNUC_MINOR__ >= 6))
_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wmissing-field-initializers\"")
#endif // endif
static const struct ieee80211_regdomain brcm_regdom = {
	.n_reg_rules = 4,
	.alpha2 =  "99",
	.reg_rules = {
		/* IEEE 802.11b/g, channels 1..11 */
		REG_RULE(2412-10, 2472+10, 40, 6, 20, 0),
		/* If any */
		/* IEEE 802.11 channel 14 - Only JP enables
		 * this and for 802.11b only
		 */
		REG_RULE(2484-10, 2484+10, 20, 6, 20, 0),
		/* IEEE 802.11a, channel 36..64 */
		REG_RULE(5150-10, 5350+10, 40, 6, 20, 0),
		/* IEEE 802.11a, channel 100..165 */
		REG_RULE(5470-10, 5850+10, 40, 6, 20, 0), }
};

#ifdef CONFIG_AP6XXX_WIFI6_HDF
const struct ieee80211_regdomain * bdh6_get_regdomain(void)
{
    return &brcm_regdom;
}
#endif

#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == \
	4 && __GNUC_MINOR__ >= 6))
_Pragma("GCC diagnostic pop")
#endif // endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)) && \
	(defined(WL_IFACE_COMB_NUM_CHANNELS) || defined(WL_CFG80211_P2P_DEV_IF))
static const struct ieee80211_iface_limit common_if_limits[] = {
	{
	/*
	 * Driver can support up to 2 AP's
	 */
	.max = 2,
	.types = BIT(NL80211_IFTYPE_AP),
	},
	{
	/*
	 * During P2P-GO removal, P2P-GO is first changed to STA and later only
	 * removed. So setting maximum possible number of STA interfaces according
	 * to kernel version.
	 *
	 * less than linux-3.8 - max:3 (wlan0 + p2p0 + group removal of p2p-p2p0-x)
	 * linux-3.8 and above - max:4
	 * sta + NAN NMI + NAN DPI open + NAN DPI sec (since there is no iface type
	 * for NAN defined, registering it as STA type)
	 */
#ifdef WL_ENABLE_P2P_IF
	.max = 5,
#else
	.max = 4,
#endif /* WL_ENABLE_P2P_IF */
	.types = BIT(NL80211_IFTYPE_STATION),
	},
	{
	.max = 2,
	.types = BIT(NL80211_IFTYPE_P2P_GO) | BIT(NL80211_IFTYPE_P2P_CLIENT),
	},
#if defined(WL_CFG80211_P2P_DEV_IF)
	{
	.max = 1,
	.types = BIT(NL80211_IFTYPE_P2P_DEVICE),
	},
#endif /* WL_CFG80211_P2P_DEV_IF */
	{
	.max = 1,
	.types = BIT(NL80211_IFTYPE_ADHOC),
	},
};

#define NUM_DIFF_CHANNELS 2

static const struct ieee80211_iface_combination
common_iface_combinations[] = {
	{
	.num_different_channels = NUM_DIFF_CHANNELS,
	/*
	 * At Max 5 network interfaces can be registered concurrently
	 */
	.max_interfaces = IFACE_MAX_CNT,
	.limits = common_if_limits,
	.n_limits = ARRAY_SIZE(common_if_limits),
	},
};
#endif /* LINUX_VER >= 3.0 && (WL_IFACE_COMB_NUM_CHANNELS || WL_CFG80211_P2P_DEV_IF) */

static const char *wl_if_state_strs[WL_IF_STATE_MAX + 1] = {
	"WL_IF_CREATE_REQ",
	"WL_IF_CREATE_DONE",
	"WL_IF_DELETE_REQ",
	"WL_IF_DELETE_DONE",
	"WL_IF_CHANGE_REQ",
	"WL_IF_CHANGE_DONE",
	"WL_IF_STATE_MAX"
};

#ifdef BCMWAPI_WPI
#if defined(ANDROID_PLATFORM_VERSION) && (ANDROID_PLATFORM_VERSION >= 8)
/* WAPI define in ieee80211.h is used */
#else
#undef WLAN_AKM_SUITE_WAPI_PSK
#define WLAN_AKM_SUITE_WAPI_PSK         0x000FAC04

#undef WLAN_AKM_SUITE_WAPI_CERT
#define WLAN_AKM_SUITE_WAPI_CERT        0x000FAC12

#undef NL80211_WAPI_VERSION_1
#define NL80211_WAPI_VERSION_1			1 << 2
#endif /* ANDROID_PLATFORM_VERSION && ANDROID_PLATFORM_VERSION >= 8 */
#endif /* BCMWAPI_WPI */

/* Data Element Definitions */
#define WPS_ID_CONFIG_METHODS     0x1008
#define WPS_ID_REQ_TYPE           0x103A
#define WPS_ID_DEVICE_NAME        0x1011
#define WPS_ID_VERSION            0x104A
#define WPS_ID_DEVICE_PWD_ID      0x1012
#define WPS_ID_REQ_DEV_TYPE       0x106A
#define WPS_ID_SELECTED_REGISTRAR_CONFIG_METHODS 0x1053
#define WPS_ID_PRIM_DEV_TYPE      0x1054

/* Device Password ID */
#define DEV_PW_DEFAULT 0x0000
#define DEV_PW_USER_SPECIFIED 0x0001,
#define DEV_PW_MACHINE_SPECIFIED 0x0002
#define DEV_PW_REKEY 0x0003
#define DEV_PW_PUSHBUTTON 0x0004
#define DEV_PW_REGISTRAR_SPECIFIED 0x0005

/* Config Methods */
#define WPS_CONFIG_USBA 0x0001
#define WPS_CONFIG_ETHERNET 0x0002
#define WPS_CONFIG_LABEL 0x0004
#define WPS_CONFIG_DISPLAY 0x0008
#define WPS_CONFIG_EXT_NFC_TOKEN 0x0010
#define WPS_CONFIG_INT_NFC_TOKEN 0x0020
#define WPS_CONFIG_NFC_INTERFACE 0x0040
#define WPS_CONFIG_PUSHBUTTON 0x0080
#define WPS_CONFIG_KEYPAD 0x0100
#define WPS_CONFIG_VIRT_PUSHBUTTON 0x0280
#define WPS_CONFIG_PHY_PUSHBUTTON 0x0480
#define WPS_CONFIG_VIRT_DISPLAY 0x2008
#define WPS_CONFIG_PHY_DISPLAY 0x4008

#define PM_BLOCK 1
#define PM_ENABLE 0

/* GCMP crypto supported above kernel v4.0 */
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0))
#define WL_GCMP
#endif /* (LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0) */

#ifndef IBSS_COALESCE_ALLOWED
#define IBSS_COALESCE_ALLOWED IBSS_COALESCE_DEFAULT
#endif // endif

#ifndef IBSS_INITIAL_SCAN_ALLOWED
#define IBSS_INITIAL_SCAN_ALLOWED IBSS_INITIAL_SCAN_ALLOWED_DEFAULT
#endif // endif

#define CUSTOM_RETRY_MASK 0xff000000 /* Mask for retry counter of custom dwell time */
#define LONG_LISTEN_TIME 2000

#ifdef RTT_SUPPORT
static s32 wl_cfg80211_rtt_event_handler(struct bcm_cfg80211 *cfg, bcm_struct_cfgdev *cfgdev,
		const wl_event_msg_t *e, void *data);
#endif /* RTT_SUPPORT */
#ifdef WL_CHAN_UTIL
static s32 wl_cfg80211_bssload_report_event_handler(struct bcm_cfg80211 *cfg,
	bcm_struct_cfgdev *cfgdev, const wl_event_msg_t *e, void *data);
static s32 wl_cfg80211_start_bssload_report(struct net_device *ndev);
#endif /* WL_CHAN_UTIL */

#ifdef SUPPORT_AP_RADIO_PWRSAVE
#define RADIO_PWRSAVE_PPS					10
#define RADIO_PWRSAVE_QUIET_TIME			10
#define RADIO_PWRSAVE_LEVEL				3
#define RADIO_PWRSAVE_STAS_ASSOC_CHECK	0

#define RADIO_PWRSAVE_LEVEL_MIN				1
#define RADIO_PWRSAVE_LEVEL_MAX				9
#define RADIO_PWRSAVE_PPS_MIN					1
#define RADIO_PWRSAVE_QUIETTIME_MIN			1
#define RADIO_PWRSAVE_ASSOCCHECK_MIN		0
#define RADIO_PWRSAVE_ASSOCCHECK_MAX		1

#define RADIO_PWRSAVE_MAJOR_VER 1
#define RADIO_PWRSAVE_MINOR_VER 1
#define RADIO_PWRSAVE_MAJOR_VER_SHIFT 8
#define RADIO_PWRSAVE_VERSION \
	((RADIO_PWRSAVE_MAJOR_VER << RADIO_PWRSAVE_MAJOR_VER_SHIFT)| RADIO_PWRSAVE_MINOR_VER)
#endif /* SUPPORT_AP_RADIO_PWRSAVE */

/* SoftAP related parameters */
#define DEFAULT_2G_SOFTAP_CHANNEL	1
#define DEFAULT_5G_SOFTAP_CHANNEL	149
#define WL_MAX_NUM_CSA_COUNTERS		255

#define MAX_VNDR_OUI_STR_LEN	256u
#define VNDR_OUI_STR_LEN	10u
#define DOT11_DISCONNECT_RC     2u
static const uchar *exclude_vndr_oui_list[] = {
	"\x00\x50\xf2",			/* Microsoft */
	"\x00\x00\xf0",			/* Samsung Elec */
	WFA_OUI,			/* WFA */
	NULL
};

typedef struct wl_vndr_oui_entry {
	uchar oui[DOT11_OUI_LEN];
	struct list_head list;
} wl_vndr_oui_entry_t;

#if defined(WL_DISABLE_HE_SOFTAP) || defined(WL_DISABLE_HE_P2P) || \
	defined(SUPPORT_AP_BWCTRL)
#define WL_HE_FEATURES_HE_AP		0x8
#define WL_HE_FEATURES_HE_P2P		0x20
#endif // endif

static int wl_vndr_ies_get_vendor_oui(struct bcm_cfg80211 *cfg,
		struct net_device *ndev, char *vndr_oui, u32 vndr_oui_len);
static void wl_vndr_ies_clear_vendor_oui_list(struct bcm_cfg80211 *cfg);
static s32 wl_cfg80211_parse_vndr_ies(const u8 *parse, u32 len,
		struct parsed_vndr_ies *vndr_ies);

#if defined(WL_FW_OCE_AP_SELECT)
static bool
wl_cfgoce_has_ie(const u8 *ie, const u8 **tlvs, u32 *tlvs_len, const u8 *oui, u32 oui_len, u8 type);

/* Check whether the given IE looks like WFA OCE IE. */
#define wl_cfgoce_is_oce_ie(ie, tlvs, len)      wl_cfgoce_has_ie(ie, tlvs, len, \
	(const uint8 *)WFA_OUI, WFA_OUI_LEN, WFA_OUI_TYPE_MBO_OCE)

/* Is any of the tlvs the expected entry? If
 * not update the tlvs buffer pointer/length.
 */
static bool
wl_cfgoce_has_ie(const u8 *ie, const u8 **tlvs, u32 *tlvs_len, const u8 *oui, u32 oui_len, u8 type)
{
	/* If the contents match the OUI and the type */
	if (ie[TLV_LEN_OFF] >= oui_len + 1 &&
			!bcmp(&ie[TLV_BODY_OFF], oui, oui_len) &&
			type == ie[TLV_BODY_OFF + oui_len]) {
		return TRUE;
	}

	return FALSE;
}
#endif /* WL_FW_OCE_AP_SELECT */

/*
 * cfg80211_ops api/callback list
 */
static s32 wl_frame_get_mgmt(struct bcm_cfg80211 *cfg, u16 fc,
	const struct ether_addr *da, const struct ether_addr *sa,
	const struct ether_addr *bssid, u8 **pheader, u32 *body_len, u8 *pbody);
static s32 wl_cfg80211_set_wiphy_params(struct wiphy *wiphy, u32 changed);
#ifdef WLAIBSS_MCHAN
static bcm_struct_cfgdev* bcm_cfg80211_add_ibss_if(struct wiphy *wiphy, char *name);
static s32 bcm_cfg80211_del_ibss_if(struct wiphy *wiphy, bcm_struct_cfgdev *cfgdev);
#endif /* WLAIBSS_MCHAN */
static s32 wl_cfg80211_join_ibss(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_ibss_params *params);
static s32 wl_cfg80211_leave_ibss(struct wiphy *wiphy,
	struct net_device *dev);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
static s32 wl_cfg80211_get_station(struct wiphy *wiphy,
	struct net_device *dev, const u8 *mac,
	struct station_info *sinfo);
#else
static s32 wl_cfg80211_get_station(struct wiphy *wiphy,
	struct net_device *dev, u8 *mac,
	struct station_info *sinfo);
#endif // endif
static s32 wl_cfg80211_set_power_mgmt(struct wiphy *wiphy,
	struct net_device *dev, bool enabled,
	s32 timeout);
#ifndef CONFIG_AP6XXX_WIFI6_HDF
static 
#endif
int wl_cfg80211_connect(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_connect_params *sme);
#if defined(WL_FILS)
static int wl_cfg80211_update_connect_params(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_connect_params *sme, u32 changed);
#endif /* WL_FILS */
#ifndef CONFIG_AP6XXX_WIFI6_HDF
static 
#endif
s32 wl_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *dev,
	u16 reason_code);
#if defined(WL_CFG80211_P2P_DEV_IF)
static s32
wl_cfg80211_set_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev,
	enum nl80211_tx_power_setting type, s32 mbm);
#else
static s32
wl_cfg80211_set_tx_power(struct wiphy *wiphy,
	enum nl80211_tx_power_setting type, s32 dbm);
#endif /* WL_CFG80211_P2P_DEV_IF */
#if defined(WL_CFG80211_P2P_DEV_IF)
static s32 wl_cfg80211_get_tx_power(struct wiphy *wiphy,
	struct wireless_dev *wdev, s32 *dbm);
#else
static s32 wl_cfg80211_get_tx_power(struct wiphy *wiphy, s32 *dbm);
#endif /* WL_CFG80211_P2P_DEV_IF */
static s32 wl_cfg80211_config_default_key(struct wiphy *wiphy,
	struct net_device *dev,
	u8 key_idx, bool unicast, bool multicast);
static s32 wl_cfg80211_add_key(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, bool pairwise, const u8 *mac_addr,
	struct key_params *params);
static s32 wl_cfg80211_del_key(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, bool pairwise, const u8 *mac_addr);
static s32 wl_cfg80211_get_key(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, bool pairwise, const u8 *mac_addr,
	void *cookie, void (*callback) (void *cookie,
	struct key_params *params));
static s32 wl_cfg80211_config_default_mgmt_key(struct wiphy *wiphy,
	struct net_device *dev,	u8 key_idx);
static s32 wl_cfg80211_resume(struct wiphy *wiphy);
#if defined(WL_SUPPORT_BACKPORTED_KPATCHES) || (LINUX_VERSION_CODE >= KERNEL_VERSION(3, \
	2, 0))
static s32 wl_cfg80211_mgmt_tx_cancel_wait(struct wiphy *wiphy,
	bcm_struct_cfgdev *cfgdev, u64 cookie);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0))
static s32 wl_cfg80211_del_station(
		struct wiphy *wiphy, struct net_device *ndev,
		struct station_del_parameters *params);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
static s32 wl_cfg80211_del_station(struct wiphy *wiphy,
	struct net_device *ndev, const u8* mac_addr);
#else
static s32 wl_cfg80211_del_station(struct wiphy *wiphy,
	struct net_device *ndev, u8* mac_addr);
#endif // endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
static s32 wl_cfg80211_change_station(struct wiphy *wiphy,
	struct net_device *dev, const u8 *mac, struct station_parameters *params);
#else
static s32 wl_cfg80211_change_station(struct wiphy *wiphy,
	struct net_device *dev, u8 *mac, struct station_parameters *params);
#endif // endif
#endif /* WL_SUPPORT_BACKPORTED_KPATCHES || KERNEL_VER >= KERNEL_VERSION(3, 2, 0)) */
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 39)) || defined(WL_COMPAT_WIRELESS)
static s32 wl_cfg80211_suspend(struct wiphy *wiphy, struct cfg80211_wowlan *wow);
#else
static s32 wl_cfg80211_suspend(struct wiphy *wiphy);
#endif // endif
static s32 wl_cfg80211_set_pmksa(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_pmksa *pmksa);
static s32 wl_cfg80211_del_pmksa(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_pmksa *pmksa);
static s32 wl_cfg80211_flush_pmksa(struct wiphy *wiphy,
	struct net_device *dev);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 2, 0)) || defined(WL_COMPAT_WIRELESS)
#if (defined(CONFIG_ARCH_MSM) && defined(TDLS_MGMT_VERSION2)) || (LINUX_VERSION_CODE < \
	KERNEL_VERSION(3, 16, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
static s32 wl_cfg80211_tdls_mgmt(struct wiphy *wiphy, struct net_device *dev,
	u8 *peer, u8 action_code, u8 dialog_token, u16 status_code,
	u32 peer_capability, const u8 *buf, size_t len);
#elif ((LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)) && \
		(LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)))
static s32 wl_cfg80211_tdls_mgmt(struct wiphy *wiphy, struct net_device *dev,
	const u8 *peer, u8 action_code, u8 dialog_token, u16 status_code,
	u32 peer_capability, const u8 *buf, size_t len);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
static s32 wl_cfg80211_tdls_mgmt(struct wiphy *wiphy, struct net_device *dev,
       const u8 *peer, u8 action_code, u8 dialog_token, u16 status_code,
       u32 peer_capability, bool initiator, const u8 *buf, size_t len);
#else /* CONFIG_ARCH_MSM && TDLS_MGMT_VERSION2 */
static s32 wl_cfg80211_tdls_mgmt(struct wiphy *wiphy, struct net_device *dev,
	u8 *peer, u8 action_code, u8 dialog_token, u16 status_code,
	const u8 *buf, size_t len);
#endif /* CONFIG_ARCH_MSM && TDLS_MGMT_VERSION2 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
static s32 wl_cfg80211_tdls_oper(struct wiphy *wiphy, struct net_device *dev,
	const u8 *peer, enum nl80211_tdls_operation oper);
#else
static s32 wl_cfg80211_tdls_oper(struct wiphy *wiphy, struct net_device *dev,
	u8 *peer, enum nl80211_tdls_operation oper);
#endif // endif
#endif /* LINUX_VERSION > KERNEL_VERSION(3,2,0) || WL_COMPAT_WIRELESS */
static s32 wl_cfg80211_set_ap_role(struct bcm_cfg80211 *cfg, struct net_device *dev);

struct wireless_dev *
wl_cfg80211_create_iface(struct wiphy *wiphy, wl_iftype_t
	iface_type, u8 *mac_addr, const char *name);
s32
wl_cfg80211_del_iface(struct wiphy *wiphy, struct wireless_dev *wdev);

s32 wl_cfg80211_interface_ops(struct bcm_cfg80211 *cfg,
	struct net_device *ndev, s32 bsscfg_idx,
	wl_iftype_t iftype, s32 del, u8 *addr);
s32 wl_cfg80211_add_del_bss(struct bcm_cfg80211 *cfg,
	struct net_device *ndev, s32 bsscfg_idx,
	wl_iftype_t brcm_iftype, s32 del, u8 *addr);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)) || defined(WL_COMPAT_WIRELESS)
static s32 wl_cfg80211_stop_ap(struct wiphy *wiphy, struct net_device *dev);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0) */
#ifdef GTK_OFFLOAD_SUPPORT
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0))
static s32 wl_cfg80211_set_rekey_data(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_gtk_rekey_data *data);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0) */
#endif /* GTK_OFFLOAD_SUPPORT */
chanspec_t wl_chspec_driver_to_host(chanspec_t chanspec);
chanspec_t wl_chspec_host_to_driver(chanspec_t chanspec);
static void wl_cfg80211_wait_for_disconnection(struct bcm_cfg80211 *cfg, struct net_device *dev);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0))
int wl_cfg80211_channel_switch(struct wiphy *wiphy, struct net_device *dev,
        struct cfg80211_csa_settings *params);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0) */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0))
static int wl_cfg80211_set_pmk(struct wiphy *wiphy, struct net_device *dev,
        const struct cfg80211_pmk_conf *conf);
static int wl_cfg80211_del_pmk(struct wiphy *wiphy, struct net_device *dev,
        const u8 *aa);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) */

/*
 * event & event Q handlers for cfg80211 interfaces
 */
static s32 wl_create_event_handler(struct bcm_cfg80211 *cfg);
static void wl_destroy_event_handler(struct bcm_cfg80211 *cfg);
static void wl_event_handler(struct work_struct *work_data);
static void wl_init_eq(struct bcm_cfg80211 *cfg);
static void wl_flush_eq(struct bcm_cfg80211 *cfg);
static unsigned long wl_lock_eq(struct bcm_cfg80211 *cfg);
static void wl_unlock_eq(struct bcm_cfg80211 *cfg, unsigned long flags);
static void wl_init_eq_lock(struct bcm_cfg80211 *cfg);
static void wl_init_event_handler(struct bcm_cfg80211 *cfg);
static struct wl_event_q *wl_deq_event(struct bcm_cfg80211 *cfg);
static s32 wl_enq_event(struct bcm_cfg80211 *cfg, struct net_device *ndev, u32 type,
	const wl_event_msg_t *msg, void *data);
static void wl_put_event(struct bcm_cfg80211 *cfg, struct wl_event_q *e);
static s32 wl_notify_connect_status_ap(struct bcm_cfg80211 *cfg, struct net_device *ndev,
	const wl_event_msg_t *e, void *data);
static s32 wl_notify_connect_status(struct bcm_cfg80211 *cfg,
	bcm_struct_cfgdev *cfgdev, const wl_event_msg_t *e, void *data);
static s32 wl_notify_roaming_status(struct bcm_cfg80211 *cfg,
	bcm_struct_cfgdev *cfgdev, const wl_event_msg_t *e, void *data);
static s32 wl_bss_connect_done(struct bcm_cfg80211 *cfg, struct net_device *ndev,
	const wl_event_msg_t *e, void *data, bool completed);
static s32 wl_bss_roaming_done(struct bcm_cfg80211 *cfg, struct net_device *ndev,
	const wl_event_msg_t *e, void *data);
static s32 wl_notify_mic_status(struct bcm_cfg80211 *cfg, bcm_struct_cfgdev *cfgdev,
	const wl_event_msg_t *e, void *data);
#ifdef BT_WIFI_HANDOVER
static s32 wl_notify_bt_wifi_handover_req(struct bcm_cfg80211 *cfg,
	bcm_struct_cfgdev *cfgdev, const wl_event_msg_t *e, void *data);
#endif /* BT_WIFI_HANDOVER */
#ifdef GSCAN_SUPPORT
static s32 wl_handle_roam_exp_event(struct bcm_cfg80211 *wl, bcm_struct_cfgdev *cfgdev,
	const wl_event_msg_t *e, void *data);
#endif /* GSCAN_SUPPORT */
#ifdef RSSI_MONITOR_SUPPORT
static s32 wl_handle_rssi_monitor_event(struct bcm_cfg80211 *wl, bcm_struct_cfgdev *cfgdev,
	const wl_event_msg_t *e, void *data);
#endif /* RSSI_MONITOR_SUPPORT */
static s32 wl_notifier_change_state(struct bcm_cfg80211 *cfg, struct net_info *_net_info,
	enum wl_status state, bool set);
#ifdef CUSTOM_EVENT_PM_WAKE
static s32 wl_check_pmstatus(struct bcm_cfg80211 *cfg, bcm_struct_cfgdev *cfgdev,
	const wl_event_msg_t *e, void *data);
#endif	/* CUSTOM_EVENT_PM_WAKE */
#if defined(DHD_LOSSLESS_ROAMING) || defined(DBG_PKT_MON)
static s32 wl_notify_roam_prep_status(struct bcm_cfg80211 *cfg,
	bcm_struct_cfgdev *cfgdev, const wl_event_msg_t *e, void *data);
#endif /* DHD_LOSSLESS_ROAMING || DBG_PKT_MON */
#ifdef DHD_LOSSLESS_ROAMING
static void wl_del_roam_timeout(struct bcm_cfg80211 *cfg);
#endif /* DHD_LOSSLESS_ROAMING */

#ifdef WL_MBO
static s32
wl_mbo_event_handler(struct bcm_cfg80211 *cfg, bcm_struct_cfgdev *cfgdev,
	const wl_event_msg_t *e, void *data);
#endif /* WL_MBO */

#ifdef WL_CLIENT_SAE
static bool wl_is_pmkid_available(struct net_device *dev, const u8 *bssid);
static s32 wl_notify_start_auth(struct bcm_cfg80211 *cfg,
	bcm_struct_cfgdev *cfgdev, const wl_event_msg_t *e, void *data);
static s32 wl_handle_auth_event(struct bcm_cfg80211 *cfg, struct net_device *ndev,
	const wl_event_msg_t *e, void *data);
static s32 wl_cfg80211_external_auth(struct wiphy *wiphy,
	struct net_device *dev, struct cfg80211_external_auth_params *ext_auth);
static s32
wl_cfg80211_mgmt_auth_tx(struct net_device *dev, bcm_struct_cfgdev *cfgdev,
	struct bcm_cfg80211 *cfg, const u8 *buf, size_t len, s32 bssidx, u64 *cookie);
#endif /* WL_CLIENT_SAE */
static s32
wl_cfg80211_config_rsnxe_ie(struct net_device *dev, const u8 *parse, u32 len);

/*
 * register/deregister parent device
 */
static void wl_cfg80211_clear_parent_dev(void);
/*
 * ioctl utilites
 */

/*
 * cfg80211 set_wiphy_params utilities
 */
static s32 wl_set_frag(struct net_device *dev, u32 frag_threshold);
static s32 wl_set_rts(struct net_device *dev, u32 frag_threshold);
static s32 wl_set_retry(struct net_device *dev, u32 retry, bool l);

/*
 * cfg profile utilities
 */
static s32 wl_update_prof(struct bcm_cfg80211 *cfg, struct net_device *ndev,
	const wl_event_msg_t *e, const void *data, s32 item);
static void wl_init_prof(struct bcm_cfg80211 *cfg, struct net_device *ndev);

/*
 * cfg80211 connect utilites
 */
static s32 wl_set_wpa_version(struct net_device *dev,
	struct cfg80211_connect_params *sme);
static s32 wl_set_auth_type(struct net_device *dev,
	struct cfg80211_connect_params *sme);
static s32 wl_set_set_cipher(struct net_device *dev,
	struct cfg80211_connect_params *sme);
static s32 wl_set_key_mgmt(struct net_device *dev,
	struct cfg80211_connect_params *sme);
static s32 wl_set_set_sharedkey(struct net_device *dev,
	struct cfg80211_connect_params *sme);
#ifdef WL_FILS
static s32 wl_set_fils_params(struct net_device *dev,
	struct cfg80211_connect_params *sme);
#endif // endif
#ifdef BCMWAPI_WPI
static s32 wl_set_set_wapi_ie(struct net_device *dev,
	struct cfg80211_connect_params *sme);
#endif // endif
#ifdef WL_GCMP
static s32 wl_set_wsec_info_algos(struct net_device *dev, uint32 algos, uint32 mask);
#endif /* WL_GCMP */
static s32 wl_get_assoc_ies(struct bcm_cfg80211 *cfg, struct net_device *ndev);
static s32 wl_ch_to_chanspec(struct net_device *dev, int ch,
	struct wl_join_params *join_params, size_t *join_params_size);
void wl_cfg80211_clear_security(struct bcm_cfg80211 *cfg);

/*
 * information element utilities
 */
static void wl_rst_ie(struct bcm_cfg80211 *cfg);
static __used s32 wl_add_ie(struct bcm_cfg80211 *cfg, u8 t, u8 l, u8 *v);
static void wl_update_hidden_ap_ie(wl_bss_info_t *bi, const u8 *ie_stream, u32 *ie_size,
	bool update_ssid);
static s32 wl_mrg_ie(struct bcm_cfg80211 *cfg, u8 *ie_stream, u16 ie_size);
static s32 wl_cp_ie(struct bcm_cfg80211 *cfg, u8 *dst, u16 dst_size);
static u32 wl_get_ielen(struct bcm_cfg80211 *cfg);
#ifdef MFP
static int wl_cfg80211_get_rsn_capa(const bcm_tlv_t *wpa2ie, const u8** rsn_cap);
#endif // endif

static s32 wl_setup_wiphy(struct wireless_dev *wdev, struct device *dev, dhd_pub_t *data);
static void wl_free_wdev(struct bcm_cfg80211 *cfg);
#ifdef CONFIG_CFG80211_INTERNAL_REGDB
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 11))
static int
#else
static void
#endif /* kernel version < 3.10.11 */
wl_cfg80211_reg_notifier(struct wiphy *wiphy, struct regulatory_request *request);
#endif /* CONFIG_CFG80211_INTERNAL_REGDB */

static s32 wl_inform_single_bss(struct bcm_cfg80211 *cfg, wl_bss_info_t *bi, bool update_ssid);
static s32 wl_update_bss_info(struct bcm_cfg80211 *cfg, struct net_device *ndev, bool update_ssid);
static chanspec_t wl_cfg80211_get_shared_freq(struct wiphy *wiphy);
s32 wl_cfg80211_channel_to_freq(u32 channel);
static void wl_cfg80211_work_handler(struct work_struct *work);
static s32 wl_add_keyext(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, const u8 *mac_addr,
	struct key_params *params);
/*
 * key indianess swap utilities
 */
static void swap_key_from_BE(struct wl_wsec_key *key);
static void swap_key_to_BE(struct wl_wsec_key *key);

/*
 * bcm_cfg80211 memory init/deinit utilities
 */
static s32 wl_init_priv_mem(struct bcm_cfg80211 *cfg);
static void wl_deinit_priv_mem(struct bcm_cfg80211 *cfg);

static void wl_delay(u32 ms);

/*
 * ibss mode utilities
 */
static bool wl_is_ibssmode(struct bcm_cfg80211 *cfg, struct net_device *ndev);
static __used bool wl_is_ibssstarter(struct bcm_cfg80211 *cfg);

/*
 * link up/down , default configuration utilities
 */
static s32 __wl_cfg80211_up(struct bcm_cfg80211 *cfg);
static s32 __wl_cfg80211_down(struct bcm_cfg80211 *cfg);
static bool wl_is_linkdown(struct bcm_cfg80211 *cfg, const wl_event_msg_t *e);

static bool wl_is_linkup(struct bcm_cfg80211 *cfg, const wl_event_msg_t *e,
	struct net_device *ndev);
static bool wl_is_nonetwork(struct bcm_cfg80211 *cfg, const wl_event_msg_t *e);
static void wl_link_up(struct bcm_cfg80211 *cfg);
static void wl_link_down(struct bcm_cfg80211 *cfg);
static s32 wl_config_infra(struct bcm_cfg80211 *cfg, struct net_device *ndev, u16 iftype);
static void wl_init_conf(struct wl_conf *conf);
int wl_cfg80211_get_ioctl_version(void);

/*
 * find most significant bit set
 */
static __used u32 wl_find_msb(u16 bit16);

/*
 * rfkill support
 */
static int wl_setup_rfkill(struct bcm_cfg80211 *cfg, bool setup);
static int wl_rfkill_set(void *data, bool blocked);
#ifdef DEBUGFS_CFG80211
static s32 wl_setup_debugfs(struct bcm_cfg80211 *cfg);
static s32 wl_free_debugfs(struct bcm_cfg80211 *cfg);
#endif // endif
static bool check_dev_role_integrity(struct bcm_cfg80211 *cfg, u32 dev_role);

#ifdef WL_CFG80211_ACL
/* ACL */
static int wl_cfg80211_set_mac_acl(struct wiphy *wiphy, struct net_device *cfgdev,
	const struct cfg80211_acl_data *acl);
#endif /* WL_CFG80211_ACL */

/*
 * Some external functions, TODO: move them to dhd_linux.h
 */
int dhd_add_monitor(const char *name, struct net_device **new_ndev);
int dhd_del_monitor(struct net_device *ndev);
int dhd_monitor_init(void *dhd_pub);
int dhd_monitor_uninit(void);
netdev_tx_t dhd_start_xmit(struct sk_buff *skb, struct net_device *net);

#ifdef ESCAN_CHANNEL_CACHE
void reset_roam_cache(struct bcm_cfg80211 *cfg);
void add_roam_cache(struct bcm_cfg80211 *cfg, wl_bss_info_t *bi);
int  get_roam_channel_list(int target_chan, chanspec_t *channels,
	int n_channels, const wlc_ssid_t *ssid, int ioctl_ver);
void set_roam_band(int band);
#endif /* ESCAN_CHANNEL_CACHE */

#ifdef ROAM_CHANNEL_CACHE
int init_roam_cache(struct bcm_cfg80211 *cfg, int ioctl_ver);
void print_roam_cache(struct bcm_cfg80211 *cfg);
void update_roam_cache(struct bcm_cfg80211 *cfg, int ioctl_ver);
#endif /* ROAM_CHANNEL_CACHE */

#ifdef P2P_LISTEN_OFFLOADING
s32 wl_cfg80211_p2plo_deinit(struct bcm_cfg80211 *cfg);
#endif /* P2P_LISTEN_OFFLOADING */

#ifdef PKT_FILTER_SUPPORT
extern uint dhd_pkt_filter_enable;
extern uint dhd_master_mode;
extern void dhd_pktfilter_offload_enable(dhd_pub_t * dhd, char *arg, int enable, int master_mode);
#endif /* PKT_FILTER_SUPPORT */

#ifdef SUPPORT_SET_CAC
static void wl_cfg80211_set_cac(struct bcm_cfg80211 *cfg, int enable);
#endif /* SUPPORT_SET_CAC */

static int wl_cfg80211_delayed_roam(struct bcm_cfg80211 *cfg, struct net_device *ndev,
	const struct ether_addr *bssid);
static s32 __wl_update_wiphybands(struct bcm_cfg80211 *cfg, bool notify);

#ifdef WL_WPS_SYNC
static void wl_init_wps_reauth_sm(struct bcm_cfg80211 *cfg);
static void wl_deinit_wps_reauth_sm(struct bcm_cfg80211 *cfg);
static void wl_wps_reauth_timeout(unsigned long data);
static s32 wl_get_free_wps_inst(struct bcm_cfg80211 *cfg);
static s32 wl_get_wps_inst_match(struct bcm_cfg80211 *cfg, struct net_device *ndev);
static s32 wl_wps_session_add(struct net_device *ndev, u16 mode, u8 *peer_mac);
static void wl_wps_session_del(struct net_device *ndev);
static s32 wl_wps_session_update(struct net_device *ndev, u16 state, const u8 *peer_mac);
static void wl_wps_handle_ifdel(struct net_device *ndev);
#endif /* WL_WPS_SYNC */

#if defined(WL_FW_OCE_AP_SELECT)
bool static wl_cfg80211_is_oce_ap(struct wiphy *wiphy, const u8 *bssid_hint);
#endif /* WL_FW_OCE_AP_SELECT */

#ifdef WL_BCNRECV
static s32 wl_bcnrecv_aborted_event_handler(struct bcm_cfg80211 *cfg, bcm_struct_cfgdev *cfgdev,
		const wl_event_msg_t *e, void *data);
#endif /* WL_BCNRECV */

#ifdef WL_CAC_TS
static s32 wl_cfg80211_cac_event_handler(struct bcm_cfg80211 *cfg, bcm_struct_cfgdev *cfgdev,
		const wl_event_msg_t *e, void *data);
#endif /* WL_CAC_TS */

#if defined(WL_MBO) || defined(WL_OCE)
static s32 wl_bssid_prune_event_handler(struct bcm_cfg80211 *cfg, bcm_struct_cfgdev *cfgdev,
		const wl_event_msg_t *e, void *data);
#endif /* WL_MBO || WL_OCE */

static int bw2cap[] = { 0, 0, WLC_BW_CAP_20MHZ, WLC_BW_CAP_40MHZ, WLC_BW_CAP_80MHZ,
	WLC_BW_CAP_160MHZ, WLC_BW_CAP_160MHZ };

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)) || (defined(CONFIG_ARCH_MSM) && \
	defined(CFG80211_DISCONNECTED_V2))
#define CFG80211_GET_BSS(wiphy, channel, bssid, ssid, ssid_len) \
	cfg80211_get_bss(wiphy, channel, bssid, ssid, ssid_len,	\
			IEEE80211_BSS_TYPE_ANY, IEEE80211_PRIVACY_ANY);
#else
#define CFG80211_GET_BSS(wiphy, channel, bssid, ssid, ssid_len) \
	cfg80211_get_bss(wiphy, channel, bssid, ssid, ssid_len,	\
			WLAN_CAPABILITY_ESS, WLAN_CAPABILITY_ESS);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)) */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)) || \
	defined(CFG80211_CONNECT_TIMEOUT_REASON_CODE) || defined(WL_FILS) || \
	defined(CONFIG_CFG80211_FILS_BKPORT)
#define CFG80211_CONNECT_RESULT(dev, bssid, bss, req_ie, req_ie_len, resp_ie, \
		resp_ie_len, status, gfp) \
	cfg80211_connect_bss(dev, bssid, bss, req_ie, req_ie_len, resp_ie, \
		resp_ie_len, status, gfp, NL80211_TIMEOUT_UNSPECIFIED);
#else
#define CFG80211_CONNECT_RESULT(dev, bssid, bss, req_ie, req_ie_len, resp_ie, \
		resp_ie_len, status, gfp) \
	cfg80211_connect_bss(dev, bssid, bss, req_ie, req_ie_len, resp_ie, \
		resp_ie_len, status, gfp);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || \
	* (CFG80211_CONNECT_TIMEOUT_REASON_CODE) ||
	* WL_FILS || CONFIG_CFG80211_FILS_BKPORT
	*/
#elif defined(CFG80211_CONNECT_TIMEOUT_REASON_CODE)
/* There are customer kernels with backported changes for
 *  connect timeout. CFG80211_CONNECT_TIMEOUT_REASON_CODE define
 * is available for kernels < 4.7 in such cases.
 */
#define CFG80211_CONNECT_RESULT(dev, bssid, bss, req_ie, req_ie_len, resp_ie, \
		resp_ie_len, status, gfp) \
	cfg80211_connect_bss(dev, bssid, bss, req_ie, req_ie_len, resp_ie, \
		resp_ie_len, status, gfp, NL80211_TIMEOUT_UNSPECIFIED);
#else
/* Kernels < 4.7 doesn't support cfg80211_connect_bss */
#define CFG80211_CONNECT_RESULT(dev, bssid, bss, req_ie, req_ie_len, resp_ie, \
		resp_ie_len, status, gfp) \
	cfg80211_connect_result(dev, bssid, req_ie, req_ie_len, resp_ie, \
		resp_ie_len, status, gfp);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0) */

#define IS_WPA_AKM(akm) ((akm) == RSN_AKM_NONE ||			\
				 (akm) == RSN_AKM_UNSPECIFIED ||	\
				 (akm) == RSN_AKM_PSK)

extern int dhd_wait_pend8021x(struct net_device *dev);
#ifdef PROP_TXSTATUS_VSDB
extern int disable_proptx;
#endif /* PROP_TXSTATUS_VSDB */

static s32
wl_ap_start_ind(struct bcm_cfg80211 *cfg, bcm_struct_cfgdev *cfgdev,
	const wl_event_msg_t *e, void *data);
static s32
wl_csa_complete_ind(struct bcm_cfg80211 *cfg, bcm_struct_cfgdev *cfgdev,
	const wl_event_msg_t *e, void *data);
#ifdef SUPPORT_AP_BWCTRL
static void
wl_update_apchan_bwcap(struct bcm_cfg80211 *cfg, struct net_device *ndev, chanspec_t chanspec);
static void
wl_restore_ap_bw(struct bcm_cfg80211 *cfg);
#endif /* SUPPORT_AP_BWCTRL */

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION (3, 5, 0)) && (LINUX_VERSION_CODE <= (3, 7, \
	0)))
struct chan_info {
	int freq;
	int chan_type;
};
#endif // endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0))
#define CFG80211_PUT_BSS(wiphy, bss) cfg80211_put_bss(wiphy, bss);
#else
#define CFG80211_PUT_BSS(wiphy, bss) cfg80211_put_bss(bss);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0) */

#define CHAN2G(_channel, _freq, _flags) {			\
	.band			= IEEE80211_BAND_2GHZ,		\
	.center_freq		= (_freq),			\
	.hw_value		= (_channel),			\
	.flags			= (_flags),			\
	.max_antenna_gain	= 0,				\
	.max_power		= 30,				\
}

#define CHAN5G(_channel, _flags) {				\
	.band			= IEEE80211_BAND_5GHZ,		\
	.center_freq		= 5000 + (5 * (_channel)),	\
	.hw_value		= (_channel),			\
	.flags			= (_flags),			\
	.max_antenna_gain	= 0,				\
	.max_power		= 30,				\
}

#define RATE_TO_BASE100KBPS(rate)   (((rate) * 10) / 2)
#define RATETAB_ENT(_rateid, _flags) \
	{								\
		.bitrate	= RATE_TO_BASE100KBPS(_rateid),     \
		.hw_value	= (_rateid),			    \
		.flags	  = (_flags),			     \
	}

static struct ieee80211_rate __wl_rates[] = {
	RATETAB_ENT(DOT11_RATE_1M, 0),
	RATETAB_ENT(DOT11_RATE_2M, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(DOT11_RATE_5M5, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(DOT11_RATE_11M, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(DOT11_RATE_6M, 0),
	RATETAB_ENT(DOT11_RATE_9M, 0),
	RATETAB_ENT(DOT11_RATE_12M, 0),
	RATETAB_ENT(DOT11_RATE_18M, 0),
	RATETAB_ENT(DOT11_RATE_24M, 0),
	RATETAB_ENT(DOT11_RATE_36M, 0),
	RATETAB_ENT(DOT11_RATE_48M, 0),
	RATETAB_ENT(DOT11_RATE_54M, 0)
};

#define wl_a_rates		(__wl_rates + 4)
#define wl_a_rates_size	8
#define wl_g_rates		(__wl_rates + 0)
#define wl_g_rates_size	12

static struct ieee80211_channel __wl_2ghz_channels[] = {
	CHAN2G(1, 2412, 0),
	CHAN2G(2, 2417, 0),
	CHAN2G(3, 2422, 0),
	CHAN2G(4, 2427, 0),
	CHAN2G(5, 2432, 0),
	CHAN2G(6, 2437, 0),
	CHAN2G(7, 2442, 0),
	CHAN2G(8, 2447, 0),
	CHAN2G(9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0)
};

static struct ieee80211_channel __wl_5ghz_a_channels[] = {
	CHAN5G(34, 0), CHAN5G(36, 0),
	CHAN5G(38, 0), CHAN5G(40, 0),
	CHAN5G(42, 0), CHAN5G(44, 0),
	CHAN5G(46, 0), CHAN5G(48, 0),
	CHAN5G(52, 0), CHAN5G(56, 0),
	CHAN5G(60, 0), CHAN5G(64, 0),
	CHAN5G(100, 0), CHAN5G(104, 0),
	CHAN5G(108, 0), CHAN5G(112, 0),
	CHAN5G(116, 0), CHAN5G(120, 0),
	CHAN5G(124, 0), CHAN5G(128, 0),
	CHAN5G(132, 0), CHAN5G(136, 0),
	CHAN5G(140, 0), CHAN5G(144, 0),
	CHAN5G(149, 0), CHAN5G(153, 0),
	CHAN5G(157, 0), CHAN5G(161, 0),
	CHAN5G(165, 0)
};

static struct ieee80211_supported_band __wl_band_2ghz = {
	.band = IEEE80211_BAND_2GHZ,
	.channels = __wl_2ghz_channels,
	.n_channels = ARRAY_SIZE(__wl_2ghz_channels),
	.bitrates = wl_g_rates,
	.n_bitrates = wl_g_rates_size
};

static struct ieee80211_supported_band __wl_band_5ghz_a = {
	.band = IEEE80211_BAND_5GHZ,
	.channels = __wl_5ghz_a_channels,
	.n_channels = ARRAY_SIZE(__wl_5ghz_a_channels),
	.bitrates = wl_a_rates,
	.n_bitrates = wl_a_rates_size
};

static const u32 __wl_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
#ifdef MFP
	/*
	 * Advertising AES_CMAC cipher suite to userspace would imply that we
	 * are supporting MFP. So advertise only when MFP support is enabled.
	 */
	WLAN_CIPHER_SUITE_AES_CMAC,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))
	WLAN_CIPHER_SUITE_BIP_GMAC_256,
	WLAN_CIPHER_SUITE_BIP_GMAC_128,
	WLAN_CIPHER_SUITE_BIP_CMAC_256,
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0) */
#endif /* MFP */

#ifdef BCMWAPI_WPI
	WLAN_CIPHER_SUITE_SMS4,
#endif // endif
#if defined(WLAN_CIPHER_SUITE_PMK)
	WLAN_CIPHER_SUITE_PMK,
#endif /* WLAN_CIPHER_SUITE_PMK */
#ifdef WL_GCMP
	WLAN_CIPHER_SUITE_GCMP,
	WLAN_CIPHER_SUITE_GCMP_256,
	WLAN_CIPHER_SUITE_BIP_GMAC_128,
	WLAN_CIPHER_SUITE_BIP_GMAC_256,
#endif /* WL_GCMP */
};

#ifdef WL_SUPPORT_ACS
/*
 * The firmware code required for this feature to work is currently under
 * BCMINTERNAL flag. In future if this is to enabled we need to bring the
 * required firmware code out of the BCMINTERNAL flag.
 */
struct wl_dump_survey {
	u32 obss;
	u32 ibss;
	u32 no_ctg;
	u32 no_pckt;
	u32 tx;
	u32 idle;
};
#endif /* WL_SUPPORT_ACS */

#ifdef WL_CFG80211_GON_COLLISION
#define BLOCK_GON_REQ_MAX_NUM 5
#endif /* WL_CFG80211_GON_COLLISION */

#if defined(USE_DYNAMIC_MAXPKT_RXGLOM)
static int maxrxpktglom = 0;
#endif // endif

/* IOCtl version read from targeted driver */
int ioctl_version;
#ifdef DEBUGFS_CFG80211
#define SUBLOGLEVEL 20
#define SUBLOGLEVELZ ((SUBLOGLEVEL) + (1))
static const struct {
	u32 log_level;
	char *sublogname;
} sublogname_map[] = {
	{WL_DBG_ERR, "ERR"},
	{WL_DBG_INFO, "INFO"},
	{WL_DBG_DBG, "DBG"},
	{WL_DBG_SCAN, "SCAN"},
	{WL_DBG_TRACE, "TRACE"},
	{WL_DBG_P2P_ACTION, "P2PACTION"}
};
#endif // endif

typedef struct rsn_cipher_algo_entry {
	u32 cipher_suite;
	u32 wsec_algo;
	u32 wsec_key_algo;
} rsn_cipher_algo_entry_t;

static const rsn_cipher_algo_entry_t rsn_cipher_algo_lookup_tbl[] = {
	{WLAN_CIPHER_SUITE_WEP40, WEP_ENABLED, CRYPTO_ALGO_WEP1},
	{WLAN_CIPHER_SUITE_WEP104, WEP_ENABLED, CRYPTO_ALGO_WEP128},
	{WLAN_CIPHER_SUITE_TKIP, TKIP_ENABLED, CRYPTO_ALGO_TKIP},
	{WLAN_CIPHER_SUITE_CCMP, AES_ENABLED, CRYPTO_ALGO_AES_CCM},
	{WLAN_CIPHER_SUITE_AES_CMAC, AES_ENABLED, CRYPTO_ALGO_BIP},
#ifdef BCMWAPI_WPI
	{WLAN_CIPHER_SUITE_SMS4, SMS4_ENABLED, CRYPTO_ALGO_SMS4},
#endif /* BCMWAPI_WPI */
#ifdef WL_GCMP
	{WLAN_CIPHER_SUITE_GCMP, AES_ENABLED, CRYPTO_ALGO_AES_GCM},
	{WLAN_CIPHER_SUITE_GCMP_256, AES_ENABLED, CRYPTO_ALGO_AES_GCM256},
	{WLAN_CIPHER_SUITE_BIP_GMAC_128, AES_ENABLED, CRYPTO_ALGO_BIP_GMAC},
	{WLAN_CIPHER_SUITE_BIP_GMAC_256, AES_ENABLED, CRYPTO_ALGO_BIP_GMAC256},
#endif /* WL_GCMP */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))
	{WLAN_CIPHER_SUITE_BIP_CMAC_256, AES_ENABLED, CRYPTO_ALGO_BIP_CMAC256},
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0) */
};

typedef struct rsn_akm_wpa_auth_entry {
	u32 akm_suite;
	u32 wpa_auth;
} rsn_akm_wpa_auth_entry_t;

static const rsn_akm_wpa_auth_entry_t rsn_akm_wpa_auth_lookup_tbl[] = {
#ifdef WL_OWE
	{WLAN_AKM_SUITE_OWE, WPA3_AUTH_OWE},
#endif /* WL_OWE */
	{WLAN_AKM_SUITE_8021X, WPA2_AUTH_UNSPECIFIED},
	{WL_AKM_SUITE_SHA256_1X, WPA2_AUTH_1X_SHA256},
	{WL_AKM_SUITE_SHA256_PSK, WPA2_AUTH_PSK_SHA256},
	{WLAN_AKM_SUITE_PSK, WPA2_AUTH_PSK},
	{WLAN_AKM_SUITE_FT_8021X, WPA2_AUTH_UNSPECIFIED | WPA2_AUTH_FT},
	{WLAN_AKM_SUITE_FT_PSK, WPA2_AUTH_PSK | WPA2_AUTH_FT},
	{WLAN_AKM_SUITE_FILS_SHA256, WPA2_AUTH_FILS_SHA256},
	{WLAN_AKM_SUITE_FILS_SHA384, WPA2_AUTH_FILS_SHA384},
	{WLAN_AKM_SUITE_8021X_SUITE_B, WPA3_AUTH_1X_SUITE_B_SHA256},
	{WLAN_AKM_SUITE_8021X_SUITE_B_192, WPA3_AUTH_1X_SUITE_B_SHA384},
#ifdef BCMWAPI_WPI
	{WLAN_AKM_SUITE_WAPI_CERT, WAPI_AUTH_UNSPECIFIED},
	{WLAN_AKM_SUITE_WAPI_PSK, WAPI_AUTH_PSK},
#endif /* BCMWAPI_WPI */
#if defined(WL_SAE) || defined(WL_CLIENT_SAE)
	{WLAN_AKM_SUITE_SAE, WPA3_AUTH_SAE_PSK},
#endif /* WL_SAE || WL_CLIENT_SAE */
	{WLAN_AKM_SUITE_FT_8021X_SHA384, WPA3_AUTH_1X_SUITE_B_SHA384 | WPA2_AUTH_FT}
};

#define BUFSZ 8
#define BUFSZN	BUFSZ + 1

#define _S(x) #x
#define S(x) _S(x)

#define SOFT_AP_IF_NAME         "swlan0"

/* watchdog timer for disconnecting when fw is not associated for FW_ASSOC_WATCHDOG_TIME ms */
uint32 fw_assoc_watchdog_ms = 0;
bool fw_assoc_watchdog_started = 0;
#define FW_ASSOC_WATCHDOG_TIME 10 * 1000 /* msec */

static void wl_add_remove_pm_enable_work(struct bcm_cfg80211 *cfg,
	enum wl_pm_workq_act_type type)
{
	u16 wq_duration = 0;
	dhd_pub_t *dhd =  NULL;

	if (cfg == NULL)
		return;

	dhd = (dhd_pub_t *)(cfg->pub);

	mutex_lock(&cfg->pm_sync);
	/*
	 * Make cancel and schedule work part mutually exclusive
	 * so that while cancelling, we are sure that there is no
	 * work getting scheduled.
	 */
	if (delayed_work_pending(&cfg->pm_enable_work)) {
		cancel_delayed_work(&cfg->pm_enable_work);
		DHD_PM_WAKE_UNLOCK(cfg->pub);
	}

	if (type == WL_PM_WORKQ_SHORT) {
		wq_duration = WL_PM_ENABLE_TIMEOUT;
	} else if (type == WL_PM_WORKQ_LONG) {
		wq_duration = (WL_PM_ENABLE_TIMEOUT*2);
	}

	/* It should schedule work item only if driver is up */
	if (wq_duration && dhd->up) {
		if (schedule_delayed_work(&cfg->pm_enable_work,
				msecs_to_jiffies((const unsigned int)wq_duration))) {
			DHD_PM_WAKE_LOCK_TIMEOUT(cfg->pub, wq_duration);
		} else {
			WL_ERR(("Can't schedule pm work handler\n"));
		}
	}
	mutex_unlock(&cfg->pm_sync);
}

/* Return a new chanspec given a legacy chanspec
 * Returns INVCHANSPEC on error
 */
chanspec_t
wl_chspec_from_legacy(chanspec_t legacy_chspec)
{
	chanspec_t chspec;

	/* get the channel number */
	chspec = LCHSPEC_CHANNEL(legacy_chspec);
