/*
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/netlink.h>
#include <typedefs.h>
#include <linuxver.h>
#include <osl.h>

#include <bcmutils.h>
#include <bcmendian.h>
#include <ethernet.h>

#include <wl_android.h>
#include <linux/if_arp.h>
#include <asm/uaccess.h>
#include <linux/wireless.h>
#if defined(WL_WIRELESS_EXT)
#include <wl_iw.h>
#endif /* WL_WIRELESS_EXT */
#include <wldev_common.h>
#include <wlioctl.h>
#include <bcmutils.h>
#include <linux_osl.h>
#include <dhd_dbg.h>
#include <dngl_stats.h>
#include <dhd.h>
#include <dhd_config.h>
#ifdef WL_CFG80211
#include <wl_cfg80211.h>
#endif /* WL_CFG80211 */
#ifdef WL_ESCAN
#include <wl_escan.h>
#endif /* WL_ESCAN */

#define AEXT_ERROR(name, arg1, args...) \
	do { \
		if (android_msg_level & ANDROID_ERROR_LEVEL) { \
			printk(KERN_ERR DHD_LOG_PREFIX "[%s] AEXT-ERROR) %s : " arg1, name, __func__, ## args); \
		} \
	} while (0)
#define AEXT_TRACE(name, arg1, args...) \
	do { \
		if (android_msg_level & ANDROID_TRACE_LEVEL) { \
			printk(KERN_INFO DHD_LOG_PREFIX "[%s] AEXT-TRACE) %s : " arg1, name, __func__, ## args); \
		} \
	} while (0)
#define AEXT_INFO(name, arg1, args...) \
	do { \
		if (android_msg_level & ANDROID_INFO_LEVEL) { \
			printk(KERN_INFO DHD_LOG_PREFIX "[%s] AEXT-INFO) %s : " arg1, name, __func__, ## args); \
		} \
	} while (0)
#define AEXT_DBG(name, arg1, args...) \
	do { \
		if (android_msg_level & ANDROID_DBG_LEVEL) { \
			printk(KERN_INFO DHD_LOG_PREFIX "[%s] AEXT-DBG) %s : " arg1, name, __func__, ## args); \
		} \
	} while (0)

#ifndef WL_CFG80211
#define htod32(i) i
#define htod16(i) i
#define dtoh32(i) i
#define dtoh16(i) i
#define htodchanspec(i) i
#define dtohchanspec(i) i
#define IEEE80211_BAND_2GHZ 0
#define IEEE80211_BAND_5GHZ 1
#define WL_SCAN_JOIN_PROBE_INTERVAL_MS 		20
#define WL_SCAN_JOIN_ACTIVE_DWELL_TIME_MS 	320
#define WL_SCAN_JOIN_PASSIVE_DWELL_TIME_MS 	400
#endif /* WL_CFG80211 */

#ifndef IW_CUSTOM_MAX
#define IW_CUSTOM_MAX 256 /* size of extra buffer used for translation of events */
#endif /* IW_CUSTOM_MAX */

#define CMD_CHANNEL				"CHANNEL"
#define CMD_CHANNELS			"CHANNELS"
#define CMD_ROAM_TRIGGER		"ROAM_TRIGGER"
#define CMD_PM					"PM"
#define CMD_MONITOR				"MONITOR"
#define CMD_SET_SUSPEND_BCN_LI_DTIM		"SET_SUSPEND_BCN_LI_DTIM"
#define CMD_WLMSGLEVEL			"WLMSGLEVEL"
#ifdef WL_EXT_IAPSTA
#define CMD_IAPSTA_INIT			"IAPSTA_INIT"
#define CMD_IAPSTA_CONFIG		"IAPSTA_CONFIG"
#define CMD_IAPSTA_ENABLE		"IAPSTA_ENABLE"
#define CMD_IAPSTA_DISABLE		"IAPSTA_DISABLE"
#define CMD_ISAM_INIT			"ISAM_INIT"
#define CMD_ISAM_CONFIG			"ISAM_CONFIG"
#define CMD_ISAM_ENABLE			"ISAM_ENABLE"
#define CMD_ISAM_DISABLE		"ISAM_DISABLE"
#define CMD_ISAM_STATUS			"ISAM_STATUS"
#define CMD_ISAM_PEER_PATH		"ISAM_PEER_PATH"
#define CMD_ISAM_PARAM			"ISAM_PARAM"
#endif /* WL_EXT_IAPSTA */
#define CMD_AUTOCHANNEL		"AUTOCHANNEL"
#define CMD_WL		"WL"
#define CMD_CONF	"CONF"

#if defined(PKT_STATICS) && defined(BCMSDIO)
#define CMD_DUMP_PKT_STATICS			"DUMP_PKT_STATICS"
#define CMD_CLEAR_PKT_STATICS			"CLEAR_PKT_STATICS"
extern void dhd_bus_dump_txpktstatics(dhd_pub_t *dhdp);
extern void dhd_bus_clear_txpktstatics(dhd_pub_t *dhdp);
#endif /* PKT_STATICS && BCMSDIO */

#ifdef IDHCP
typedef struct dhcpc_parameter {
	uint32 ip_addr;
	uint32 ip_serv;
	uint32 lease_time;
} dhcpc_para_t;
#endif /* IDHCP */

#ifdef WL_EXT_WOWL
#define WL_WOWL_TCPFIN	(1 << 26)
typedef struct wl_wowl_pattern2 {
	char cmd[4];
	wl_wowl_pattern_t wowl_pattern;
} wl_wowl_pattern2_t;
#endif /* WL_EXT_WOWL */

#ifdef WL_EXT_TCPKA
typedef struct tcpka_conn {
	uint32 sess_id;
	struct ether_addr dst_mac;	/* Destinition Mac */
	struct ipv4_addr  src_ip;	/* Sorce IP */
	struct ipv4_addr  dst_ip;	/* Destinition IP */
	uint16 ipid;	/* Ip Identification */
	uint16 srcport;	/* Source Port Address */
	uint16 dstport;	/* Destination Port Address */
	uint32 seq;		/* TCP Sequence Number */
	uint32 ack;		/* TCP Ack Number */
	uint16 tcpwin;	/* TCP window */
	uint32 tsval;	/* Timestamp Value */
	uint32 tsecr;	/* Timestamp Echo Reply */
	uint32 len;		/* last packet payload len */
	uint32 ka_payload_len;	/* keep alive payload length */
	uint8  ka_payload[1];	/* keep alive payload */
} tcpka_conn_t;

typedef struct tcpka_conn_sess {
	uint32 sess_id;	/* session id */
	uint32 flag;	/* enable/disable flag */
	wl_mtcpkeep_alive_timers_pkt_t  tcpka_timers;
} tcpka_conn_sess_t;

typedef struct tcpka_conn_info {
	uint32 ipid;
	uint32 seq;
	uint32 ack;
} tcpka_conn_sess_info_t;
#endif /* WL_EXT_TCPKA */

typedef struct auth_name_map_t {
	uint auth;
	uint wpa_auth;
	char *auth_name;
} auth_name_map_t;

const auth_name_map_t auth_name_map[] = {
	{WL_AUTH_OPEN_SYSTEM,	WPA_AUTH_DISABLED,	"open"},
	{WL_AUTH_SHARED_KEY,	WPA_AUTH_DISABLED,	"shared"},
	{WL_AUTH_OPEN_SYSTEM,	WPA_AUTH_PSK,		"wpapsk"},
	{WL_AUTH_OPEN_SYSTEM,	WPA2_AUTH_PSK,		"wpa2psk"},
	{WL_AUTH_OPEN_SYSTEM,	WPA2_AUTH_PSK_SHA256|WPA2_AUTH_PSK,	"wpa2psksha256"},
	{WL_AUTH_OPEN_SYSTEM,	WPA2_AUTH_FT|WPA2_AUTH_PSK,			"wpa2psk-ft"},
	{WL_AUTH_OPEN_SYSTEM,	WPA2_AUTH_UNSPECIFIED,				"wpa2eap"},
	{WL_AUTH_OPEN_SYSTEM,	WPA2_AUTH_FT|WPA2_AUTH_UNSPECIFIED,	"wpa2eap-ft"},
	{WL_AUTH_OPEN_SYSTEM,	WPA3_AUTH_SAE_PSK,	"wpa3psk"},
	{WL_AUTH_SAE_KEY,		WPA3_AUTH_SAE_PSK,	"wpa3psk"},
	{WL_AUTH_OPEN_SYSTEM,	WPA3_AUTH_SAE_PSK|WPA2_AUTH_PSK,	"wpa3psk"},
	{WL_AUTH_SAE_KEY,		WPA3_AUTH_SAE_PSK|WPA2_AUTH_PSK,	"wpa3psk"},
	{WL_AUTH_OPEN_SYSTEM,	0x20,	"wpa3psk"},
	{WL_AUTH_SAE_KEY,		0x20,	"wpa3psk"},
	{WL_AUTH_OPEN_SYSTEM,	WPA3_AUTH_SAE_PSK|WPA2_AUTH_PSK_SHA256|WPA2_AUTH_PSK,	"wpa3psksha256"},
	{WL_AUTH_SAE_KEY,		WPA3_AUTH_SAE_PSK|WPA2_AUTH_PSK_SHA256|WPA2_AUTH_PSK,	"wpa3psksha256"},
	{WL_AUTH_OPEN_SYSTEM,	0x20|WPA2_AUTH_PSK_SHA256|WPA2_AUTH_PSK,	"wpa3psksha256"},
	{WL_AUTH_SAE_KEY,		0x20|WPA2_AUTH_PSK_SHA256|WPA2_AUTH_PSK,	"wpa3psksha256"},
};

typedef struct wsec_name_map_t {
	uint wsec;
	char *wsec_name;
} wsec_name_map_t;

const wsec_name_map_t wsec_name_map[] = {
	{WSEC_NONE,		"none"},
	{WEP_ENABLED,	"wep"},
	{TKIP_ENABLED,	"tkip"},
	{AES_ENABLED,	"aes"},
	{TKIP_ENABLED|AES_ENABLED,	"tkipaes"},
};

static int wl_ext_wl_iovar(struct net_device *dev, char *command, int total_len);

int
wl_ext_ioctl(struct net_device *dev, u32 cmd, void *arg, u32 len, u32 set)
{
	int ret;

	ret = wldev_ioctl(dev, cmd, arg, len, set);
	if (ret)
		AEXT_ERROR(dev->name, "cmd=%d, ret=%d\n", cmd, ret);
	return ret;
}

int
wl_ext_iovar_getint(struct net_device *dev, s8 *iovar, s32 *val)
{
	int ret;

	ret = wldev_iovar_getint(dev, iovar, val);
	if (ret)
		AEXT_ERROR(dev->name, "iovar=%s, ret=%d\n", iovar, ret);

	return ret;
}

int
wl_ext_iovar_setint(struct net_device *dev, s8 *iovar, s32 val)
{
	int ret;

	ret = wldev_iovar_setint(dev, iovar, val);
	if (ret)
		AEXT_ERROR(dev->name, "iovar=%s, ret=%d\n", iovar, ret);

	return ret;
}

int
wl_ext_iovar_getbuf(struct net_device *dev, s8 *iovar_name,
	void *param, s32 paramlen, void *buf, s32 buflen, struct mutex* buf_sync)
{
	int ret;

	ret = wldev_iovar_getbuf(dev, iovar_name, param, paramlen, buf, buflen, buf_sync);
	if (ret != 0)
		AEXT_ERROR(dev->name, "iovar=%s, ret=%d\n", iovar_name, ret);

	return ret;
}

int
wl_ext_iovar_setbuf(struct net_device *dev, s8 *iovar_name,
	void *param, s32 paramlen, void *buf, s32 buflen, struct mutex* buf_sync)
{
	int ret;

	ret = wldev_iovar_setbuf(dev, iovar_name, param, paramlen, buf, buflen, buf_sync);
	if (ret != 0)
		AEXT_ERROR(dev->name, "iovar=%s, ret=%d\n", iovar_name, ret);

	return ret;
}

int
wl_ext_iovar_setbuf_bsscfg(struct net_device *dev, s8 *iovar_name,
	void *param, s32 paramlen, void *buf, s32 buflen, s32 bsscfg_idx,
	struct mutex* buf_sync)
{
	int ret;

	ret = wldev_iovar_setbuf_bsscfg(dev, iovar_name, param, paramlen,
		buf, buflen, bsscfg_idx, buf_sync);
	if (ret < 0)
		AEXT_ERROR(dev->name, "iovar=%s, ret=%d\n", iovar_name, ret);

	return ret;
}

static chanspec_t
wl_ext_chspec_to_legacy(chanspec_t chspec)
{
	chanspec_t lchspec;

	if (wf_chspec_malformed(chspec)) {
		AEXT_ERROR("wlan", "input chanspec (0x%04X) malformed\n", chspec);
		return INVCHANSPEC;
	}

	/* get the channel number */
	lchspec = CHSPEC_CHANNEL(chspec);

	/* convert the band */
	if (CHSPEC_IS2G(chspec)) {
		lchspec |= WL_LCHANSPEC_BAND_2G;
	} else {
		lchspec |= WL_LCHANSPEC_BAND_5G;
	}

	/* convert the bw and sideband */
	if (CHSPEC_IS20(chspec)) {
		lchspec |= WL_LCHANSPEC_BW_20;
		lchspec |= WL_LCHANSPEC_CTL_SB_NONE;
	} else if (CHSPEC_IS40(chspec)) {
		lchspec |= WL_LCHANSPEC_BW_40;
		if (CHSPEC_CTL_SB(chspec) == WL_CHANSPEC_CTL_SB_L) {
			lchspec |= WL_LCHANSPEC_CTL_SB_LOWER;
		} else {
			lchspec |= WL_LCHANSPEC_CTL_SB_UPPER;
		}
	} else {
		/* cannot express the bandwidth */
		char chanbuf[CHANSPEC_STR_LEN];
		AEXT_ERROR("wlan", "unable to convert chanspec %s (0x%04X) "
			"to pre-11ac format\n",
			wf_chspec_ntoa(chspec, chanbuf), chspec);
		return INVCHANSPEC;
	}

	return lchspec;
}

chanspec_t
wl_ext_chspec_host_to_driver(int ioctl_ver, chanspec_t chanspec)
{
	if (ioctl_ver == 1) {
		chanspec = wl_ext_chspec_to_legacy(chanspec);
		if (chanspec == INVCHANSPEC) {
			return chanspec;
		}
	}
	chanspec = htodchanspec(chanspec);

	return chanspec;
}

static void
wl_ext_ch_to_chanspec(int ioctl_ver, int ch,
	struct wl_join_params *join_params, size_t *join_params_size)
{
	chanspec_t chanspec = 0;

	if (ch != 0) {
		join_params->params.chanspec_num = 1;
		join_params->params.chanspec_list[0] = ch;

		if (join_params->params.chanspec_list[0] <= CH_MAX_2G_CHANNEL)
			chanspec |= WL_CHANSPEC_BAND_2G;
		else
			chanspec |= WL_CHANSPEC_BAND_5G;

		chanspec |= WL_CHANSPEC_BW_20;
		chanspec |= WL_CHANSPEC_CTL_SB_NONE;

		*join_params_size += WL_ASSOC_PARAMS_FIXED_SIZE +
			join_params->params.chanspec_num * sizeof(chanspec_t);

		join_params->params.chanspec_list[0]  &= WL_CHANSPEC_CHAN_MASK;
		join_params->params.chanspec_list[0] |= chanspec;
		join_params->params.chanspec_list[0] =
			wl_ext_chspec_host_to_driver(ioctl_ver,
				join_params->params.chanspec_list[0]);

		join_params->params.chanspec_num =
			htod32(join_params->params.chanspec_num);
	}
}

#if defined(WL_EXT_IAPSTA) || defined(WL_CFG80211) || defined(WL_ESCAN)
static chanspec_t
wl_ext_chspec_from_legacy(chanspec_t legacy_chspec)
{
	chanspec_t chspec;

	/* get the channel number */
	chspec = LCHSPEC_CHANNEL(legacy_chspec);

	/* convert the band */
	if (LCHSPEC_IS2G(legacy_chspec)) {
		chspec |= WL_CHANSPEC_BAND_2G;
	} else {
		chspec |= WL_CHANSPEC_BAND_5G;
	}

	/* convert the bw and sideband */
	if (LCHSPEC_IS20(legacy_chspec)) {
		chspec |= WL_CHANSPEC_BW_20;
	} else {
		chspec |= WL_CHANSPEC_BW_40;
		if (LCHSPEC_CTL_SB(legacy_chspec) == WL_LCHANSPEC_CTL_SB_LOWER) {
			chspec |= WL_CHANSPEC_CTL_SB_L;
		} else {
			chspec |= WL_CHANSPEC_CTL_SB_U;
		}
	}

	if (wf_chspec_malformed(chspec)) {
		AEXT_ERROR("wlan", "output chanspec (0x%04X) malformed\n", chspec);
		return INVCHANSPEC;
	}

	return chspec;
}

chanspec_t
wl_ext_chspec_driver_to_host(int ioctl_ver, chanspec_t chanspec)
{
	chanspec = dtohchanspec(chanspec);
	if (ioctl_ver == 1) {
		chanspec = wl_ext_chspec_from_legacy(chanspec);
	}

	return chanspec;
}
#endif /* WL_EXT_IAPSTA || WL_CFG80211 || WL_ESCAN */

bool
wl_ext_check_scan(struct net_device *dev, dhd_pub_t *dhdp)
{
#ifdef WL_CFG80211
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);
#endif /* WL_CFG80211 */
#ifdef WL_ESCAN
	struct wl_escan_info *escan = dhdp->escan;
#endif /* WL_ESCAN */

#ifdef WL_CFG80211
	if (wl_get_drv_status_all(cfg, SCANNING)) {
		AEXT_ERROR(dev->name, "cfg80211 scanning...\n");
		return TRUE;
	}
#endif /* WL_CFG80211 */

#ifdef WL_ESCAN
	if (escan->escan_state == ESCAN_STATE_SCANING) {
		AEXT_ERROR(dev->name, "escan scanning...\n");
		return TRUE;
	}
#endif /* WL_ESCAN */

	return FALSE;
}

#if defined(WL_CFG80211) || defined(WL_ESCAN)
void
wl_ext_user_sync(struct dhd_pub *dhd, int ifidx, bool lock)
{
	struct net_device *dev = dhd_idx2net(dhd, ifidx);
#ifdef WL_CFG80211
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);
#endif /* WL_CFG80211 */
#ifdef WL_ESCAN
	struct wl_escan_info *escan = dhd->escan;
#endif /* WL_ESCAN */

	AEXT_INFO(dev->name, "lock=%d\n", lock);

	if (lock) {
#if defined(WL_CFG80211)
		mutex_lock(&cfg->usr_sync);
#endif
#if defined(WL_ESCAN)
		mutex_lock(&escan->usr_sync);
#endif
	} else {
#if defined(WL_CFG80211)
		mutex_unlock(&cfg->usr_sync);
#endif
#if defined(WL_ESCAN)
		mutex_unlock(&escan->usr_sync);
#endif
	}
}
#endif /* WL_CFG80211 && WL_ESCAN */

static bool
wl_ext_event_complete(struct dhd_pub *dhd, int ifidx)
{
	struct net_device *dev = dhd_idx2net(dhd, ifidx);
#ifdef WL_CFG80211
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);
#endif /* WL_CFG80211 */
#ifdef WL_ESCAN
	struct wl_escan_info *escan = dhd->escan;
#endif /* WL_ESCAN */
	bool complete = TRUE;

#ifdef WL_CFG80211
	if (wl_get_drv_status_all(cfg, SCANNING)) {
		AEXT_INFO(dev->name, "SCANNING\n");
		complete = FALSE;
	}
	if (wl_get_drv_status_all(cfg, CONNECTING)) {
		AEXT_INFO(dev->name, "CONNECTING\n");
		complete = FALSE;
	}
	if (wl_get_drv_status_all(cfg, DISCONNECTING)) {
		AEXT_INFO(dev->name, "DISCONNECTING\n");
		complete = FALSE;
	}
#endif /* WL_CFG80211 */
#ifdef WL_ESCAN
	if (escan->escan_state == ESCAN_STATE_SCANING) {
		AEXT_INFO(dev->name, "ESCAN_STATE_SCANING\n");
		complete = FALSE;
	}
#endif /* WL_ESCAN */
#ifdef WL_EXT_IAPSTA
	if (wl_ext_sta_connecting(dev)) {
		complete = FALSE;
	}
#endif /* WL_EXT_IAPSTA */

	return complete;
}

void
wl_ext_wait_event_complete(struct dhd_pub *dhd, int ifidx)
{
	struct net_device *net;
	s32 timeout = -1;

	timeout = wait_event_interruptible_timeout(dhd->conf->event_complete,
		wl_ext_event_complete(dhd, ifidx), msecs_to_jiffies(10000));
	if (timeout <= 0 || !wl_ext_event_complete(dhd, ifidx)) {
		wl_ext_event_complete(dhd, ifidx);
		net = dhd_idx2net(dhd, ifidx);
		AEXT_ERROR(net->name, "timeout\n");
	}
}

int
wl_ext_get_ioctl_ver(struct net_device *dev, int *ioctl_ver)
{
	int ret = 0;
	s32 val = 0;

	val = 1;
	ret = wl_ext_ioctl(dev, WLC_GET_VERSION, &val, sizeof(val), 0);
	if (ret) {
		return ret;
	}
	val = dtoh32(val);
	if (val != WLC_IOCTL_VERSION && val != 1) {
		AEXT_ERROR(dev->name, "Version mismatch, please upgrade. Got %d, expected %d or 1\n",
			val, WLC_IOCTL_VERSION);
		return BCME_VERSION;
	}
	*ioctl_ver = val;

	return ret;
}

void
wl_ext_bss_iovar_war(struct net_device *ndev, s32 *val)
{
	dhd_pub_t *dhd = dhd_get_pub(ndev);
	uint chip;
	bool need_war = false;

	chip = dhd_conf_get_chip(dhd);

	if (chip == BCM43362_CHIP_ID || chip == BCM4330_CHIP_ID ||
		chip == BCM4354_CHIP_ID || chip == BCM4356_CHIP_ID ||
		chip == BCM4371_CHIP_ID ||
		chip == BCM43430_CHIP_ID ||
		chip == BCM4345_CHIP_ID || chip == BCM43454_CHIP_ID ||
		chip == BCM4359_CHIP_ID ||
		chip == BCM43143_CHIP_ID || chip == BCM43242_CHIP_ID ||
		chip == BCM43569_CHIP_ID) {
		need_war = true;
	}

	if (need_war) {
		/* Few firmware branches have issues in bss iovar handling and
		 * that can't be changed since they are in production.
		 */
		if (*val == WLC_AP_IOV_OP_MANUAL_AP_BSSCFG_CREATE) {
			*val = WLC_AP_IOV_OP_MANUAL_STA_BSSCFG_CREATE;
		} else if (*val == WLC_AP_IOV_OP_MANUAL_STA_BSSCFG_CREATE) {
			*val = WLC_AP_IOV_OP_MANUAL_AP_BSSCFG_CREATE;
		} else {
			/* Ignore for other bss enums */
			return;
		}
		AEXT_TRACE(ndev->name, "wl bss %d\n", *val);
	}
}

int
wl_ext_set_chanspec(struct net_device *dev, int ioctl_ver,
	uint16 channel, chanspec_t *ret_chspec)
{
	s32 _chan = channel;
	chanspec_t chspec = 0;
	chanspec_t fw_chspec = 0;
	u32 bw = WL_CHANSPEC_BW_20;
	s32 err = BCME_OK;
	s32 bw_cap = 0;
	s8 iovar_buf[WLC_IOCTL_SMLEN];
	struct {
		u32 band;
		u32 bw_cap;
	} param = {0, 0};
	uint band;

	if (_chan <= CH_MAX_2G_CHANNEL)
		band = IEEE80211_BAND_2GHZ;
	else
		band = IEEE80211_BAND_5GHZ;

	if (band == IEEE80211_BAND_5GHZ) {
		param.band = WLC_BAND_5G;
		err = wl_ext_iovar_getbuf(dev, "bw_cap", &param, sizeof(param),
			iovar_buf, WLC_IOCTL_SMLEN, NULL);
		if (err) {
			if (err != BCME_UNSUPPORTED) {
				AEXT_ERROR(dev->name, "bw_cap failed, %d\n", err);
				return err;
			} else {
				err = wl_ext_iovar_getint(dev, "mimo_bw_cap", &bw_cap);
				if (bw_cap != WLC_N_BW_20ALL)
					bw = WL_CHANSPEC_BW_40;
			}
		} else {
			if (WL_BW_CAP_80MHZ(iovar_buf[0]))
				bw = WL_CHANSPEC_BW_80;
			else if (WL_BW_CAP_40MHZ(iovar_buf[0]))
				bw = WL_CHANSPEC_BW_40;
			else
				bw = WL_CHANSPEC_BW_20;

		}
	}
	else if (band == IEEE80211_BAND_2GHZ)
		bw = WL_CHANSPEC_BW_20;

set_channel:
	chspec = wf_channel2chspec(_chan, bw);
	if (wf_chspec_valid(chspec)) {
		fw_chspec = wl_ext_chspec_host_to_driver(ioctl_ver, chspec);
		if (fw_chspec != INVCHANSPEC) {
			if ((err = wl_ext_iovar_setint(dev, "chanspec", fw_chspec)) == BCME_BADCHAN) {
				if (bw == WL_CHANSPEC_BW_80)
					goto change_bw;
				err = wl_ext_ioctl(dev, WLC_SET_CHANNEL, &_chan, sizeof(_chan), 1);
				WL_MSG(dev->name, "channel %d\n", _chan);
			} else if (err) {
				AEXT_ERROR(dev->name, "failed to set chanspec error %d\n", err);
			} else
				WL_MSG(dev->name, "channel %d, 0x%x\n", channel, chspec);
		} else {
			AEXT_ERROR(dev->name, "failed to convert host chanspec to fw chanspec\n");
			err = BCME_ERROR;
		}
	} else {
change_bw:
		if (bw == WL_CHANSPEC_BW_80)
			bw = WL_CHANSPEC_BW_40;
		else if (bw == WL_CHANSPEC_BW_40)
			bw = WL_CHANSPEC_BW_20;
		else
			bw = 0;
		if (bw)
			goto set_channel;
		AEXT_ERROR(dev->name, "Invalid chanspec 0x%x\n", chspec);
		err = BCME_ERROR;
	}
	*ret_chspec = fw_chspec;

	return err;
}

static int
wl_ext_channel(struct net_device *dev, char* command, int total_len)
{
	int ret;
	int channel=0;
	channel_info_t ci;
	int bytes_written = 0;
	chanspec_t fw_chspec;
	int ioctl_ver = 0;

	AEXT_TRACE(dev->name, "cmd %s", command);

	sscanf(command, "%*s %d", &channel);

	if (channel > 0) {
		wl_ext_get_ioctl_ver(dev, &ioctl_ver);
		ret = wl_ext_set_chanspec(dev, ioctl_ver, channel, &fw_chspec);
	} else {
		if (!(ret = wl_ext_ioctl(dev, WLC_GET_CHANNEL, &ci,
				sizeof(channel_info_t), FALSE))) {
			AEXT_TRACE(dev->name, "hw_channel %d\n", ci.hw_channel);
			AEXT_TRACE(dev->name, "target_channel %d\n", ci.target_channel);
			AEXT_TRACE(dev->name, "scan_channel %d\n", ci.scan_channel);
			bytes_written = snprintf(command, sizeof(channel_info_t)+2,
				"channel %d", ci.hw_channel);
			AEXT_TRACE(dev->name, "command result is %s\n", command);
			ret = bytes_written;
		}
	}

	return ret;
}

static int
wl_ext_channels(struct net_device *dev, char* command, int total_len)
{
	int ret, i;
	int bytes_written = -1;
	u8 valid_chan_list[sizeof(u32)*(WL_NUMCHANNELS + 1)];
	wl_uint32_list_t *list;

	AEXT_TRACE(dev->name, "cmd %s", command);

	memset(valid_chan_list, 0, sizeof(valid_chan_list));
	list = (wl_uint32_list_t *)(void *) valid_chan_list;
	list->count = htod32(WL_NUMCHANNELS);
	ret = wl_ext_ioctl(dev, WLC_GET_VALID_CHANNELS, valid_chan_list,
		sizeof(valid_chan_list), 0);
	if (ret<0) {
		AEXT_ERROR(dev->name, "get channels failed with %d\n", ret);
	} else {
		bytes_written = snprintf(command, total_len, "channels");
		for (i = 0; i < dtoh32(list->count); i++) {
			bytes_written += snprintf(command+bytes_written, total_len, " %d",
				dtoh32(list->element[i]));
		}
		AEXT_TRACE(dev->name, "command result is %s\n", command);
		ret = bytes_written;
	}

	return ret;
}

static int
wl_ext_roam_trigger(struct net_device *dev, char* command, int total_len)
{
	int ret = 0;
	int roam_trigger[2] = {0, 0};
	int trigger[2]= {0, 0};
	int bytes_written=-1;

	sscanf(command, "%*s %10d", &roam_trigger[0]);

	if (roam_trigger[0]) {
		roam_trigger[1] = WLC_BAND_ALL;
		ret = wl_ext_ioctl(dev, WLC_SET_ROAM_TRIGGER, roam_trigger,
			sizeof(roam_trigger), 1);
	} else {
		roam_trigger[1] = WLC_BAND_2G;
		ret = wl_ext_ioctl(dev, WLC_GET_ROAM_TRIGGER, roam_trigger,
			sizeof(roam_trigger), 0);
		if (!ret)
			trigger[0] = roam_trigger[0];

		roam_trigger[1] = WLC_BAND_5G;
		ret = wl_ext_ioctl(dev, WLC_GET_ROAM_TRIGGER, &roam_trigger,
			sizeof(roam_trigger), 0);
		if (!ret)
			trigger[1] = roam_trigger[0];

		AEXT_TRACE(dev->name, "roam_trigger %d %d\n", trigger[0], trigger[1]);
		bytes_written = snprintf(command, total_len, "%d %d", trigger[0], trigger[1]);
		ret = bytes_written;
	}

	return ret;
}

static int
wl_ext_pm(struct net_device *dev, char *command, int total_len)
{
	int pm=-1, ret = -1;
	char *pm_local;
	int bytes_written=-1;

	AEXT_TRACE(dev->name, "cmd %s", command);

	sscanf(command, "%*s %d", &pm);

	if (pm >= 0) {
		ret = wl_ext_ioctl(dev, WLC_SET_PM, &pm, sizeof(pm), 1);
	} else {
		ret = wl_ext_ioctl(dev, WLC_GET_PM, &pm, sizeof(pm), 0);
		if (!ret) {
			AEXT_TRACE(dev->name, "PM = %d", pm);
			if (pm == PM_OFF)
				pm_local = "PM_OFF";
			else if(pm == PM_MAX)
				pm_local = "PM_MAX";
			else if(pm == PM_FAST)
				pm_local = "PM_FAST";
			else {
				pm = 0;
				pm_local = "Invalid";
			}
			bytes_written = snprintf(command, total_len, "PM %s", pm_local);
			AEXT_TRACE(dev->name, "command result is %s\n", command);
			ret = bytes_written;
		}
	}

	return ret;
}

static int
wl_ext_monitor(struct net_device *dev, char *command, int total_len)
{
	int val = -1, ret = -1;
	int bytes_written=-1;

	sscanf(command, "%*s %d", &val);

	if (val >=0) {
		ret = wl_ext_ioctl(dev, WLC_SET_MONITOR, &val, sizeof(val), 1);
	} else {
		ret = wl_ext_ioctl(dev, WLC_GET_MONITOR, &val, sizeof(val), 0);
		if (!ret) {
			AEXT_TRACE(dev->name, "monitor = %d\n", val);
			bytes_written = snprintf(command, total_len, "monitor %d", val);
			AEXT_TRACE(dev->name, "command result is %s\n", command);
			ret = bytes_written;
		}
	}

	return ret;
}

s32
wl_ext_connect(struct net_device *dev, struct wl_conn_info *conn_info)
{
	struct dhd_pub *dhd = dhd_get_pub(dev);
	wl_extjoin_params_t *ext_join_params = NULL;
	struct wl_join_params join_params;
	size_t join_params_size;
	s32 err = 0;
	u32 chan_cnt = 0;
	s8 *iovar_buf = NULL;
	int ioctl_ver = 0;
	char sec[32];

	wl_ext_get_ioctl_ver(dev, &ioctl_ver);

	if (dhd->conf->chip == BCM43362_CHIP_ID)
		goto set_ssid;

	if (conn_info->channel) {
		chan_cnt = 1;
	}

	iovar_buf = kzalloc(WLC_IOCTL_MAXLEN, GFP_KERNEL);
	if (iovar_buf == NULL) {
		err = -ENOMEM;
		goto exit;
	}

	/*
	 *	Join with specific BSSID and cached SSID
	 *	If SSID is zero join based on BSSID only
	 */
	join_params_size = WL_EXTJOIN_PARAMS_FIXED_SIZE +
		chan_cnt * sizeof(chanspec_t);
	ext_join_params =  (wl_extjoin_params_t*)kzalloc(join_params_size, GFP_KERNEL);
	if (ext_join_params == NULL) {
		err = -ENOMEM;
		goto exit;
	}
	ext_join_params->ssid.SSID_len = min((uint32)sizeof(ext_join_params->ssid.SSID),
		conn_info->ssid.SSID_len);
	memcpy(&ext_join_params->ssid.SSID, conn_info->ssid.SSID, ext_join_params->ssid.SSID_len);
	ext_join_params->ssid.SSID_len = htod32(ext_join_params->ssid.SSID_len);
	/* increate dwell time to receive probe response or detect Beacon
	* from target AP at a noisy air only during connect command
	*/
	ext_join_params->scan.active_time = chan_cnt ? WL_SCAN_JOIN_ACTIVE_DWELL_TIME_MS : -1;
	ext_join_params->scan.passive_time = chan_cnt ? WL_SCAN_JOIN_PASSIVE_DWELL_TIME_MS : -1;
	/* Set up join scan parameters */
	ext_join_params->scan.scan_type = -1;
	ext_join_params->scan.nprobes = chan_cnt ?
		(ext_join_params->scan.active_time/WL_SCAN_JOIN_PROBE_INTERVAL_MS) : -1;
	ext_join_params->scan.home_time = -1;

	if (memcmp(&ether_null, &conn_info->bssid, ETHER_ADDR_LEN))
		memcpy(&ext_join_params->assoc.bssid, &conn_info->bssid, ETH_ALEN);
	else
		memcpy(&ext_join_params->assoc.bssid, &ether_bcast, ETH_ALEN);
	ext_join_params->assoc.chanspec_num = chan_cnt;
	if (chan_cnt) {
		u16 band, bw, ctl_sb;
		chanspec_t chspec;
		band = (conn_info->channel <= CH_MAX_2G_CHANNEL) ? WL_CHANSPEC_BAND_2G
			: WL_CHANSPEC_BAND_5G;
		bw = WL_CHANSPEC_BW_20;
		ctl_sb = WL_CHANSPEC_CTL_SB_NONE;
		chspec = (conn_info->channel | band | bw | ctl_sb);
		ext_join_params->assoc.chanspec_list[0]  &= WL_CHANSPEC_CHAN_MASK;
		ext_join_params->assoc.chanspec_list[0] |= chspec;
		ext_join_params->assoc.chanspec_list[0] =
			wl_ext_chspec_host_to_driver(ioctl_ver,
				ext_join_params->assoc.chanspec_list[0]);
	}
	ext_join_params->assoc.chanspec_num = htod32(ext_join_params->assoc.chanspec_num);

	wl_ext_get_sec(dev, 0, sec, sizeof(sec), TRUE);
	WL_MSG(dev->name,
		"Connecting with %pM channel (%d) ssid \"%s\", len (%d), sec=%s\n\n",
		&ext_join_params->assoc.bssid, conn_info->channel,
		ext_join_params->ssid.SSID, ext_join_params->ssid.SSID_len, sec);
	err = wl_ext_iovar_setbuf_bsscfg(dev, "join", ext_join_params,
		join_params_size, iovar_buf, WLC_IOCTL_MAXLEN, conn_info->bssidx, NULL);

	if (err) {
		if (err == BCME_UNSUPPORTED) {
			AEXT_TRACE(dev->name, "join iovar is not supported\n");
			goto set_ssid;
		} else {
			AEXT_ERROR(dev->name, "error (%d)\n", err);
			goto exit;
		}
	} else
		goto exit;

set_ssid:
	memset(&join_params, 0, sizeof(join_params));
	join_params_size = sizeof(join_params.ssid);

	join_params.ssid.SSID_len = min((uint32)sizeof(join_params.ssid.SSID),
		conn_info->ssid.SSID_len);
	memcpy(&join_params.ssid.SSID, conn_info->ssid.SSID, join_params.ssid.SSID_len);
	join_params.ssid.SSID_len = htod32(join_params.ssid.SSID_len);
	if (memcmp(&ether_null, &conn_info->bssid, ETHER_ADDR_LEN))
		memcpy(&join_params.params.bssid, &conn_info->bssid, ETH_ALEN);
	else
		memcpy(&join_params.params.bssid, &ether_bcast, ETH_ALEN);

	wl_ext_ch_to_chanspec(ioctl_ver, conn_info->channel, &join_params, &join_params_size);
	AEXT_TRACE(dev->name, "join_param_size %zu\n", join_params_size);

	if (join_params.ssid.SSID_len < IEEE80211_MAX_SSID_LEN) {
		AEXT_INFO(dev->name, "ssid \"%s\", len (%d)\n", join_params.ssid.SSID,
			join_params.ssid.SSID_len);
	}
	wl_ext_get_sec(dev, 0, sec, sizeof(sec), TRUE);
	WL_MSG(dev->name,
		"Connecting with %pM channel (%d) ssid \"%s\", len (%d), sec=%s\n\n",
		&join_params.params.bssid, conn_info->channel,
		join_params.ssid.SSID, join_params.ssid.SSID_len, sec);
	err = wl_ext_ioctl(dev, WLC_SET_SSID, &join_params, join_params_size, 1);

exit:
#ifdef WL_EXT_IAPSTA
	if (!err)
		wl_ext_add_remove_pm_enable_work(dev, TRUE);
#endif /* WL_EXT_IAPSTA */
	if (iovar_buf)
		kfree(iovar_buf);
	if (ext_join_params)
		kfree(ext_join_params);
	return err;

}

void
wl_ext_get_sec(struct net_device *dev, int ifmode, char *sec, int total_len, bool dump)
{
	int auth=0, wpa_auth=0, wsec=0, mfp=0, i;
	int bytes_written=0;
	bool match = FALSE;

	memset(sec, 0, total_len);
	wl_ext_iovar_getint(dev, "auth", &auth);
	wl_ext_iovar_getint(dev, "wpa_auth", &wpa_auth);
	wl_ext_iovar_getint(dev, "wsec", &wsec);
	wldev_iovar_getint(dev, "mfp", &mfp);

#ifdef WL_EXT_IAPSTA
	if (ifmode == IMESH_MODE) {
		if (auth == WL_AUTH_OPEN_SYSTEM && wpa_auth == WPA_AUTH_DISABLED) {
			bytes_written += snprintf(sec+bytes_written, total_len, "open");
		} else if (auth == WL_AUTH_OPEN_SYSTEM && wpa_auth == WPA2_AUTH_PSK) {
			bytes_written += snprintf(sec+bytes_written, total_len, "sae");
		} else {
			bytes_written += snprintf(sec+bytes_written, total_len, "%d/0x%x",
				auth, wpa_auth);
		}
	} else
#endif /* WL_EXT_IAPSTA */
	{
		match = FALSE;
		for (i=0; i<sizeof(auth_name_map)/sizeof(auth_name_map[0]); i++) {
			const auth_name_map_t* row = &auth_name_map[i];
			if (row->auth == auth && row->wpa_auth == wpa_auth) {
				bytes_written += snprintf(sec+bytes_written, total_len, "%s",
					row->auth_name);
				match = TRUE;
				break;
			}
		}
		if (!match) {
			bytes_written += snprintf(sec+bytes_written, total_len, "%d/0x%x",
				auth, wpa_auth);
		}
	}

	if (mfp == WL_MFP_NONE) {
		bytes_written += snprintf(sec+bytes_written, total_len, "/mfpn");
	} else if (mfp == WL_MFP_CAPABLE) {
		bytes_written += snprintf(sec+bytes_written, total_len, "/mfpc");
	} else if (mfp == WL_MFP_REQUIRED) {
		bytes_written += snprintf(sec+bytes_written, total_len, "/mfpr");
	} else {
		bytes_written += snprintf(sec+bytes_written, total_len, "/%d", mfp);
	}

#ifdef WL_EXT_IAPSTA
	if (ifmode == IMESH_MODE) {
		if (wsec == WSEC_NONE) {
			bytes_written += snprintf(sec+bytes_written, total_len, "/none");
		} else {
			bytes_written += snprintf(sec+bytes_written, total_len, "/aes");
		}
	} else
#endif /* WL_EXT_IAPSTA */
	{
		match = FALSE;
		for (i=0; i<sizeof(wsec_name_map)/sizeof(wsec_name_map[0]); i++) {
			const wsec_name_map_t* row = &wsec_name_map[i];
			if (row->wsec == (wsec&0x7)) {
				bytes_written += snprintf(sec+bytes_written, total_len, "/%s",
					row->wsec_name);
				match = TRUE;
				break;
			}
		}
		if (!match) {
			bytes_written += snprintf(sec+bytes_written, total_len, "/0x%x", wsec);
		}
	}
	if (dump) {
		AEXT_INFO(dev->name, "auth/wpa_auth/mfp/wsec = %d/0x%x/%d/0x%x\n",
			auth, wpa_auth, mfp, wsec);
	}
}

bool
wl_ext_dfs_chan(uint16 chan)
{
	if (chan >= 52 && chan <= 144)
		return TRUE;
	return FALSE;
}

uint16
wl_ext_get_default_chan(struct net_device *dev,
	uint16 *chan_2g, uint16 *chan_5g, bool nodfs)
{
	struct dhd_pub *dhd = dhd_get_pub(dev);
	uint16 chan_tmp = 0, chan = 0;
	wl_uint32_list_t *list;
	u8 valid_chan_list[sizeof(u32)*(WL_NUMCHANNELS + 1)];
	s32 ret = BCME_OK;
	int i;

	*chan_2g = 0;
	*chan_5g = 0;
	memset(valid_chan_list, 0, sizeof(valid_chan_list));
	list = (wl_uint32_list_t *)(void *) valid_chan_list;
	list->count = htod32(WL_NUMCHANNELS);
	ret = wl_ext_ioctl(dev, WLC_GET_VALID_CHANNELS, valid_chan_list,
		sizeof(valid_chan_list), 0);
	if (ret == 0) {
		for (i=0; i<dtoh32(list->count); i++) {
			chan_tmp = dtoh32(list->element[i]);
			if (!dhd_conf_match_channel(dhd, chan_tmp))
				continue;
			if (chan_tmp <= 13 && !*chan_2g) {
				*chan_2g = chan_tmp;
			} else if (chan_tmp >= 36 && chan_tmp <= 161 && !*chan_5g) {
				if (wl_ext_dfs_chan(chan_tmp) && nodfs)
					continue;
				else
					*chan_5g = chan_tmp;
			}
		}
	}

	return chan;
}

int
wl_ext_set_scan_time(struct net_device *dev, int scan_time,
	uint32 scan_get, uint32 scan_set)
{
	int ret, cur_scan_time;

	ret = wl_ext_ioctl(dev, scan_get, &cur_scan_time, sizeof(cur_scan_time), 0);
	if (ret)
		return 0;

	if (scan_time != cur_scan_time)
		wl_ext_ioctl(dev, scan_set, &scan_time, sizeof(scan_time), 1);

	return cur_scan_time;
}

static int
wl_ext_wlmsglevel(struct net_device *dev, char *command, int total_len)
{
	int val = -1, ret = 0;
	int bytes_written = 0;

	sscanf(command, "%*s %x", &val);

	if (val >=0) {
		if (val & DHD_ANDROID_VAL) {
			android_msg_level = (uint)(val & 0xFFFF);
			WL_MSG(dev->name, "android_msg_level=0x%x\n", android_msg_level);
		}
#if defined(WL_WIRELESS_EXT)
		else if (val & DHD_IW_VAL) {
			iw_msg_level = (uint)(val & 0xFFFF);
			WL_MSG(dev->name, "iw_msg_level=0x%x\n", iw_msg_level);
		}
#endif
#ifdef WL_CFG80211
		else if (val & DHD_CFG_VAL) {
			wl_cfg80211_enable_trace((u32)(val & 0xFFFF));
		}
#endif
		else if (val & DHD_CONFIG_VAL) {
			config_msg_level = (uint)(val & 0xFFFF);
			WL_MSG(dev->name, "config_msg_level=0x%x\n", config_msg_level);
		}
		else if (val & DHD_DUMP_VAL) {
			dump_msg_level = (uint)(val & 0xFFFF);
			WL_MSG(dev->name, "dump_msg_level=0x%x\n", dump_msg_level);
		}
	}
	else {
		bytes_written += snprintf(command+bytes_written, total_len,
			"android_msg_level=0x%x", android_msg_level);
#if defined(WL_WIRELESS_EXT)
		bytes_written += snprintf(command+bytes_written, total_len,
			"\niw_msg_level=0x%x", iw_msg_level);
#endif
#ifdef WL_CFG80211
		bytes_written += snprintf(command+bytes_written, total_len,
			"\nwl_dbg_level=0x%x", wl_dbg_level);
#endif
		bytes_written += snprintf(command+bytes_written, total_len,
			"\nconfig_msg_level=0x%x", config_msg_level);
		bytes_written += snprintf(command+bytes_written, total_len,
			"\ndump_msg_level=0x%x", dump_msg_level);
		AEXT_INFO(dev->name, "%s\n", command);
		ret = bytes_written;
	}

	return ret;
}

#ifdef WL_CFG80211
bool
wl_legacy_chip_check(struct net_device *net)
{
	struct dhd_pub *dhd = dhd_get_pub(net);
	uint chip;

	chip = dhd_conf_get_chip(dhd);

	if (chip == BCM43362_CHIP_ID || chip == BCM4330_CHIP_ID ||
		chip == BCM4334_CHIP_ID || chip == BCM43340_CHIP_ID ||
		chip == BCM43341_CHIP_ID || chip == BCM4324_CHIP_ID ||
		chip == BCM4335_CHIP_ID || chip == BCM4339_CHIP_ID ||
		chip == BCM4354_CHIP_ID || chip == BCM4356_CHIP_ID ||
		chip == BCM4371_CHIP_ID ||
		chip == BCM43430_CHIP_ID ||
		chip == BCM4345_CHIP_ID || chip == BCM43454_CHIP_ID ||
		chip == BCM4359_CHIP_ID ||
		chip == BCM43143_CHIP_ID || chip == BCM43242_CHIP_ID ||
		chip == BCM43569_CHIP_ID) {
		return true;
	}

	return false;
}

bool
wl_new_chip_check(struct net_device *net)
{
	struct dhd_pub *dhd = dhd_get_pub(net);
	uint chip;

	chip = dhd_conf_get_chip(dhd);

	if (chip == BCM4359_CHIP_ID || chip == BCM43012_CHIP_ID ||
			chip == BCM43751_CHIP_ID || chip == BCM43752_CHIP_ID) {
		return true;
	}

	return false;
}

bool
wl_extsae_chip(struct dhd_pub *dhd)
{
	uint chip;

	chip = dhd_conf_get_chip(dhd);

	if (chip == BCM43362_CHIP_ID || chip == BCM4330_CHIP_ID ||
		chip == BCM4334_CHIP_ID || chip == BCM43340_CHIP_ID ||
		chip == BCM43341_CHIP_ID || chip == BCM4324_CHIP_ID ||
		chip == BCM4335_CHIP_ID || chip == BCM4339_CHIP_ID ||
		chip == BCM4354_CHIP_ID || chip == BCM4356_CHIP_ID ||
		chip == BCM43143_CHIP_ID || chip == BCM43242_CHIP_ID ||
		chip == BCM43569_CHIP_ID) {
		return false;
	}

	return true;
}

#ifdef WL_EXT_IAPSTA
void
wl_ext_war(struct net_device *dev)
{
	struct dhd_pub *dhd = dhd_get_pub(dev);
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);
	struct dhd_conf *conf = dhd->conf;

	if (conf->war & FW_REINIT_INCSA) {
		if (wl_get_mode_by_netdev(cfg, dev) == WL_MODE_BSS) {
			if (wl_ext_iapsta_iftype_enabled(dev, WL_IF_TYPE_AP)) {
				AEXT_INFO(dev->name, "wl reinit\n");
				wl_ext_ioctl(dev, WLC_INIT, NULL, 0, 1);
			}
		}
	}
}
#endif
#endif

#ifdef WLEASYMESH
#define CMD_EASYMESH "EASYMESH"
//Set map 4 and dwds 1 on wlan0 interface
#define EASYMESH_SLAVE		"slave"
#define EASYMESH_MASTER		"master"

static int
wl_ext_easymesh(struct net_device *dev, char* command, int total_len)
{
	int ret = 0, wlc_down = 1, wlc_up = 1, map = 4, dwds = 1;

	AEXT_TRACE(dev->name, "command=%s, len=%d\n", command, total_len);
	if (strncmp(command, EASYMESH_SLAVE, strlen(EASYMESH_SLAVE)) == 0) {
		WL_MSG(dev->name, "try to set map %d, dwds %d\n", map, dwds);
		ret = wl_ext_ioctl(dev, WLC_DOWN, &wlc_down, sizeof(wlc_down), 1);
		if (ret)
			goto exit;
		wl_ext_iovar_setint(dev, "map", map);
		wl_ext_iovar_setint(dev, "dwds", dwds);
		ret = wl_ext_ioctl(dev, WLC_UP, &wlc_up, sizeof(wlc_up), 1);
		if (ret)
			goto exit;
	}
	else if (strncmp(command, EASYMESH_MASTER, strlen(EASYMESH_MASTER)) == 0) {
		map = dwds = 0;
		WL_MSG(dev->name, "try to set map %d, dwds %d\n", map, dwds);
		ret = wl_ext_ioctl(dev, WLC_DOWN, &wlc_down, sizeof(wlc_down), 1);
		if (ret) {
			goto exit;
		}
		wl_ext_iovar_setint(dev, "map", map);
		wl_ext_iovar_setint(dev, "dwds", dwds);
		ret = wl_ext_ioctl(dev, WLC_UP, &wlc_up, sizeof(wlc_up), 1);
		if (ret) {
			goto exit;
		}
	}

exit:
	return ret;
}
#endif /* WLEASYMESH */

int
wl_ext_add_del_ie(struct net_device *dev, uint pktflag, char *ie_data, const char* add_del_cmd)
{
	vndr_ie_setbuf_t *vndr_ie = NULL;
	char iovar_buf[WLC_IOCTL_SMLEN]="\0";
	int ie_data_len = 0, tot_len = 0, iecount;
	int err = -1;

	if (!strlen(ie_data)) {
		AEXT_ERROR(dev->name, "wrong ie %s\n", ie_data);
		goto exit;
	}

	tot_len = (int)(sizeof(vndr_ie_setbuf_t) + ((strlen(ie_data)-2)/2));
	vndr_ie = (vndr_ie_setbuf_t *) kzalloc(tot_len, GFP_KERNEL);
	if (!vndr_ie) {
		AEXT_ERROR(dev->name, "IE memory alloc failed\n");
		err = -ENOMEM;
		goto exit;
	}

	/* Copy the vndr_ie SET command ("add"/"del") to the buffer */
	strncpy(vndr_ie->cmd, add_del_cmd, VNDR_IE_CMD_LEN - 1);
	vndr_ie->cmd[VNDR_IE_CMD_LEN - 1] = '\0';

	/* Set the IE count - the buffer contains only 1 IE */
	iecount = htod32(1);
	memcpy((void *)&vndr_ie->vndr_ie_buffer.iecount, &iecount, sizeof(s32));

	/* Set packet flag to indicate that BEACON's will contain this IE */
	pktflag = htod32(pktflag);
	memcpy((void *)&vndr_ie->vndr_ie_buffer.vndr_ie_list[0].pktflag, &pktflag,
		sizeof(u32));

	/* Set the IE ID */
	vndr_ie->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.id = (uchar)DOT11_MNG_VS_ID;

	/* Set the IE LEN */
	vndr_ie->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.len = (strlen(ie_data)-2)/2;

	/* Set the IE OUI and DATA */
	ie_data_len = wl_pattern_atoh(ie_data,
		(char *)vndr_ie->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.oui);
	if (ie_data_len <= 0) {
		AEXT_ERROR(dev->name, "wrong ie_data_len %d\n", (int)strlen(ie_data)-2);
		goto exit;
	}

	err = wl_ext_iovar_setbuf(dev, "vndr_ie", vndr_ie, tot_len, iovar_buf,
		sizeof(iovar_buf), NULL);

exit:
	if (vndr_ie) {
		kfree(vndr_ie);
	}
	return err;
}

#ifdef IDHCP
/*
terence 20190409:
dhd_priv wl dhcpc_dump
dhd_priv wl dhcpc_param <client ip> <server ip> <lease time>
*/
static int
wl_ext_dhcpc_dump(struct net_device *dev, char *data, char *command,
	int total_len)
{
	int ret = 0;
	int bytes_written = 0;
	uint32 ip_addr;
	char buf[20]="";

	if (!data) {
		ret = wl_ext_iovar_getint(dev, "dhcpc_ip_addr", &ip_addr);
		if (!ret) {
			bcm_ip_ntoa((struct ipv4_addr *)&ip_addr, buf);
			bytes_written += snprintf(command+bytes_written, total_len,
				"ipaddr %s ", buf);
		}

		ret = wl_ext_iovar_getint(dev, "dhcpc_ip_mask", &ip_addr);
		if (!ret) {
			bcm_ip_ntoa((struct ipv4_addr *)&ip_addr, buf);
			bytes_written += snprintf(command+bytes_written, total_len,
				"mask %s ", buf);
		}

		ret = wl_ext_iovar_getint(dev, "dhcpc_ip_gateway", &ip_addr);
		if (!ret) {
			bcm_ip_ntoa((struct ipv4_addr *)&ip_addr, buf);
			bytes_written += snprintf(command+bytes_written, total_len,
				"gw %s ", buf);
		}

		ret = wl_ext_iovar_getint(dev, "dhcpc_ip_dnsserv", &ip_addr);
		if (!ret) {
			bcm_ip_ntoa((struct ipv4_addr *)&ip_addr, buf);
			bytes_written += snprintf(command+bytes_written, total_len,
				"dnsserv %s ", buf);
		}

		if (!bytes_written)
			bytes_written = -1;

		AEXT_TRACE(dev->name, "command result is %s\n", command);
	}

	return bytes_written;
}

int
wl_ext_dhcpc_param(struct net_device *dev, char *data, char *command,
	int total_len)
{
	int ret = -1, bytes_written = 0;
	char ip_addr_str[20]="", ip_serv_str[20]="";
	struct dhcpc_parameter dhcpc_param;
	uint32 ip_addr, ip_serv, lease_time;
	char iovar_buf[WLC_IOCTL_SMLEN]="\0";

	if (data) {
		AEXT_TRACE(dev->name, "cmd %s", command);
		sscanf(data, "%s %s %d", ip_addr_str, ip_serv_str, &lease_time);
		AEXT_TRACE(dev->name, "ip_addr = %s, ip_serv = %s, lease_time = %d",
			ip_addr_str, ip_serv_str, lease_time);

		memset(&dhcpc_param, 0, sizeof(struct dhcpc_parameter));
		if (!bcm_atoipv4(ip_addr_str, (struct ipv4_addr *)&ip_addr)) {
			AEXT_ERROR(dev->name, "wrong ip_addr_str %s\n", ip_addr_str);
			ret = -1;
			goto exit;
		}
		dhcpc_param.ip_addr = ip_addr;

		if (!bcm_atoipv4(ip_addr_str, (struct ipv4_addr *)&ip_serv)) {
			AEXT_ERROR(dev->name, "wrong ip_addr_str %s\n", ip_addr_str);
			ret = -1;
			goto exit;
		}
		dhcpc_param.ip_serv = ip_serv;
		dhcpc_param.lease_time = lease_time;
		ret = wl_ext_iovar_setbuf(dev, "dhcpc_param", &dhcpc_param,
			sizeof(struct dhcpc_parameter), iovar_buf, sizeof(iovar_buf), NULL);
	} else {
		ret = wl_ext_iovar_getbuf(dev, "dhcpc_param", &dhcpc_param,
			sizeof(struct dhcpc_parameter), iovar_buf, WLC_IOCTL_SMLEN, NULL);
		if (!ret) {
			bcm_ip_ntoa((struct ipv4_addr *)&dhcpc_param.ip_addr, ip_addr_str);
			bytes_written += snprintf(command + bytes_written, total_len,
				"ip_addr %s\n", ip_addr_str);
			bcm_ip_ntoa((struct ipv4_addr *)&dhcpc_param.ip_serv, ip_serv_str);
			bytes_written += snprintf(command + bytes_written, total_len,
				"ip_serv %s\n", ip_serv_str);
			bytes_written += snprintf(command + bytes_written, total_len,
				"lease_time %d\n", dhcpc_param.lease_time);
			AEXT_TRACE(dev->name, "command result is %s\n", command);
			ret = bytes_written;
		}
	}

	exit:
		return ret;
}
#endif /* IDHCP */

int
wl_ext_mkeep_alive(struct net_device *dev, char *data, char *command,
	int total_len)
{
	struct dhd_pub *dhd = dhd_get_pub(dev);
	wl_mkeep_alive_pkt_t *mkeep_alive_pktp;
	int ret = -1, i, ifidx, id, period=-1;
	char *packet = NULL, *buf = NULL;
	int bytes_written = 0;

	if (data) {
		buf = kmalloc(total_len, GFP_KERNEL);
		if (buf == NULL) {
			AEXT_ERROR(dev->name, "Failed to allocate buffer of %d bytes\n", WLC_IOCTL_SMLEN);
			goto exit;
		}
		packet = kmalloc(WLC_IOCTL_SMLEN, GFP_KERNEL);
		if (packet == NULL) {
			AEXT_ERROR(dev->name, "Failed to allocate buffer of %d bytes\n", WLC_IOCTL_SMLEN);
			goto exit;
		}
		AEXT_TRACE(dev->name, "cmd %s", command);
		sscanf(data, "%d %d %s", &id, &period, packet);
		AEXT_TRACE(dev->name, "id=%d, period=%d, packet=%s", id, period, packet);
		if (period >= 0) {
			ifidx = dhd_net2idx(dhd->info, dev);
			ret = dhd_conf_mkeep_alive(dhd, ifidx, id, period, packet, FALSE);
		} else {
			if (id < 0)
				id = 0;
			ret = wl_ext_iovar_getbuf(dev, "mkeep_alive", &id, sizeof(id), buf,
				total_len, NULL);
			if (!ret) {
				mkeep_alive_pktp = (wl_mkeep_alive_pkt_t *) buf;
				bytes_written += snprintf(command+bytes_written, total_len,
					"Id            :%d\n"
					"Period (msec) :%d\n"
					"Length        :%d\n"
					"Packet        :0x",
					mkeep_alive_pktp->keep_alive_id,
					dtoh32(mkeep_alive_pktp->period_msec),
					dtoh16(mkeep_alive_pktp->len_bytes));
				for (i=0; i<mkeep_alive_pktp->len_bytes; i++) {
					bytes_written += snprintf(command+bytes_written, total_len,
						"%02x", mkeep_alive_pktp->data[i]);
				}
				AEXT_TRACE(dev->name, "command result is %s\n", command);
				ret = bytes_written;
			}
		}
	}

exit:
	if (buf)
		kfree(buf);
	if (packet)
		kfree(packet);
	return ret;
}

#ifdef WL_EXT_TCPKA
static int
wl_ext_tcpka_conn_add(struct net_device *dev, char *data, char *command,
	int total_len)
{
	int ret = 0;
	s8 iovar_buf[WLC_IOCTL_SMLEN];
	tcpka_conn_t *tcpka = NULL;
	uint32 sess_id = 0, ipid = 0, srcport = 0, dstport = 0, seq = 0, ack = 0,
		tcpwin = 0, tsval = 0, tsecr = 0, len = 0, ka_payload_len = 0;
	char dst_mac[ETHER_ADDR_STR_LEN], src_ip[IPV4_ADDR_STR_LEN],
		dst_ip[IPV4_ADDR_STR_LEN], ka_payload[32];

	if (data) {
		memset(dst_mac, 0, sizeof(dst_mac));
		memset(src_ip, 0, sizeof(src_ip));
		memset(dst_ip, 0, sizeof(dst_ip));
		memset(ka_payload, 0, sizeof(ka_payload));
		sscanf(data, "%d %s %s %s %d %d %d %u %u %d %u %u %u %32s",
			&sess_id, dst_mac, src_ip, dst_ip, &ipid, &srcport, &dstport, &seq,
			&ack, &tcpwin, &tsval, &tsecr, &len, ka_payload);

		ka_payload_len = strlen(ka_payload) / 2;
		tcpka = kmalloc(sizeof(struct tcpka_conn) + ka_payload_len, GFP_KERNEL);
		if (tcpka == NULL) {
			AEXT_ERROR(dev->name, "Failed to allocate buffer of %d bytes\n",
				sizeof(struct tcpka_conn) + ka_payload_len);
			ret = -1;
			goto exit;
		}
		memset(tcpka, 0, sizeof(struct tcpka_conn) + ka_payload_len);

		tcpka->sess_id = sess_id;
		if (!(ret = bcm_ether_atoe(dst_mac, &tcpka->dst_mac))) {
			AEXT_ERROR(dev->name, "mac parsing err addr=%s\n", dst_mac);
			ret = -1;
			goto exit;
		}
		if (!bcm_atoipv4(src_ip, &tcpka->src_ip)) {
			AEXT_ERROR(dev->name, "src_ip parsing err ip=%s\n", src_ip);
			ret = -1;
			goto exit;
		}
		if (!bcm_atoipv4(dst_ip, &tcpka->dst_ip)) {
			AEXT_ERROR(dev->name, "dst_ip parsing err ip=%s\n", dst_ip);
			ret = -1;
			goto exit;
		}
		tcpka->ipid = ipid;
		tcpka->srcport = srcport;
		tcpka->dstport = dstport;
		tcpka->seq = seq;
		tcpka->ack = ack;
		tcpka->tcpwin = tcpwin;
		tcpka->tsval = tsval;
		tcpka->tsecr = tsecr;
		tcpka->len = len;
		ka_payload_len = wl_pattern_atoh(ka_payload, (char *)tcpka->ka_payload);
		if (ka_payload_len == -1) {
			AEXT_ERROR(dev->name,"rejecting ka_payload=%s\n", ka_payload);
			ret = -1;
			goto exit;
		}
		tcpka->ka_payload_len = ka_payload_len;

		AEXT_INFO(dev->name,
			"tcpka_conn_add %d %pM %pM %pM %d %d %d %u %u %d %u %u %u %u \"%s\"\n",
			tcpka->sess_id, &tcpka->dst_mac, &tcpka->src_ip, &tcpka->dst_ip,
			tcpka->ipid, tcpka->srcport, tcpka->dstport, tcpka->seq,
			tcpka->ack, tcpka->tcpwin, tcpka->tsval, tcpka->tsecr,
			tcpka->len, tcpka->ka_payload_len, tcpka->ka_payload);

		ret = wl_ext_iovar_setbuf(dev, "tcpka_conn_add", (char *)tcpka,
			(sizeof(tcpka_conn_t) + tcpka->ka_payload_len - 1),
			iovar_buf, sizeof(iovar_buf), NULL);
	}

exit:
	if (tcpka)
		kfree(tcpka);
	return ret;
}

static int
wl_ext_tcpka_conn_enable(struct net_device *dev, char *data, char *command,
	int total_len)
{
	s8 iovar_buf[WLC_IOCTL_SMLEN];
	tcpka_conn_sess_t tcpka_conn;
	int ret = 0;
	uint32 sess_id = 0, flag, interval = 0, retry_interval = 0, retry_count = 0;

	if (data) {
		sscanf(data, "%d %d %d %d %d",
			&sess_id, &flag, &interval, &retry_interval, &retry_count);
		tcpka_conn.sess_id = sess_id;
		tcpka_conn.flag = flag;
		if (tcpka_conn.flag) {
			tcpka_conn.tcpka_timers.interval = interval;
			tcpka_conn.tcpka_timers.retry_interval = retry_interval;
			tcpka_conn.tcpka_timers.retry_count = retry_count;
		} else {
			tcpka_conn.tcpka_timers.interval = 0;
			tcpka_conn.tcpka_timers.retry_interval = 0;
			tcpka_conn.tcpka_timers.retry_count = 0;
		}

		AEXT_INFO(dev->name, "tcpka_conn_enable %d %d %d %d %d\n",
			tcpka_conn.sess_id, tcpka_conn.flag,
			tcpka_conn.tcpka_timers.interval,
			tcpka_conn.tcpka_timers.retry_interval,
			tcpka_conn.tcpka_timers.retry_count);

		ret = wl_ext_iovar_setbuf(dev, "tcpka_conn_enable", (char *)&tcpka_conn,
			sizeof(tcpka_conn_sess_t), iovar_buf, sizeof(iovar_buf), NULL);
	}

	return ret;
}

