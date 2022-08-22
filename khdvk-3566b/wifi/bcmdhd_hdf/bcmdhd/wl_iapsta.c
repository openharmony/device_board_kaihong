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

#ifdef WL_EXT_IAPSTA
#include <net/rtnetlink.h>
#include <bcmendian.h>
#include <dhd_linux.h>
#include <wl_android.h>
#include <dhd_config.h>
#ifdef WL_CFG80211
#include <wl_cfg80211.h>
#endif /* WL_CFG80211 */
#ifdef WL_ESCAN
#include <wl_escan.h>
#endif /* WL_ESCAN */

#define IAPSTA_ERROR(name, arg1, args...) \
	do { \
		if (android_msg_level & ANDROID_ERROR_LEVEL) { \
			printk(KERN_ERR DHD_LOG_PREFIX "[%s] IAPSTA-ERROR) %s : " arg1, name, __func__, ## args); \
		} \
	} while (0)
#define IAPSTA_TRACE(name, arg1, args...) \
	do { \
		if (android_msg_level & ANDROID_TRACE_LEVEL) { \
			printk(KERN_INFO DHD_LOG_PREFIX "[%s] IAPSTA-TRACE) %s : " arg1, name, __func__, ## args); \
		} \
	} while (0)
#define IAPSTA_INFO(name, arg1, args...) \
	do { \
		if (android_msg_level & ANDROID_INFO_LEVEL) { \
			printk(KERN_INFO DHD_LOG_PREFIX "[%s] IAPSTA-INFO) %s : " arg1, name, __func__, ## args); \
		} \
	} while (0)
#define IAPSTA_DBG(name, arg1, args...) \
	do { \
		if (android_msg_level & ANDROID_DBG_LEVEL) { \
			printk(KERN_INFO DHD_LOG_PREFIX "[%s] IAPSTA-DBG) %s : " arg1, name, __func__, ## args); \
		} \
	} while (0)

#ifdef PROP_TXSTATUS
#include <dhd_wlfc.h>
#ifdef PROP_TXSTATUS_VSDB
extern int disable_proptx;
#endif /* PROP_TXSTATUS_VSDB */
#endif /* PROP_TXSTATUS */

#ifndef WL_CFG80211
#define htod32(i) i
#define htod16(i) i
#define dtoh32(i) i
#define dtoh16(i) i
#define IEEE80211_BAND_2GHZ 0
#define IEEE80211_BAND_5GHZ 1
#endif /* WL_CFG80211 */

#define CSA_FW_BIT		(1<<0)
#define CSA_DRV_BIT		(1<<1)

#define MAX_AP_LINK_WAIT_TIME   3000
#define MAX_STA_LINK_WAIT_TIME   15000
#define STA_CONNECT_TIMEOUT	10500
enum wifi_isam_status {
	ISAM_STATUS_IF_ADDING = 0,
	ISAM_STATUS_IF_READY,
	ISAM_STATUS_STA_CONNECTING,
	ISAM_STATUS_STA_CONNECTED,
	ISAM_STATUS_AP_CREATING,
	ISAM_STATUS_AP_CREATED
};

enum wifi_isam_reason {
	ISAM_RC_MESH_ACS = 1,
	ISAM_RC_TPUT_MONITOR = 2,
	ISAM_RC_AP_ACS = 3
};

#define wl_get_isam_status(cur_if, stat) \
	(test_bit(ISAM_STATUS_ ## stat, &(cur_if)->status))
#define wl_set_isam_status(cur_if, stat) \
	(set_bit(ISAM_STATUS_ ## stat, &(cur_if)->status))
#define wl_clr_isam_status(cur_if, stat) \
	(clear_bit(ISAM_STATUS_ ## stat, &(cur_if)->status))
#define wl_chg_isam_status(cur_if, stat) \
	(change_bit(ISAM_STATUS_ ## stat, &(cur_if)->status))

static int wl_ext_enable_iface(struct net_device *dev, char *ifname,
	int wait_up, bool lock);
static int wl_ext_disable_iface(struct net_device *dev, char *ifname);
#if defined(WLMESH) && defined(WL_ESCAN)
static int wl_mesh_escan_attach(dhd_pub_t *dhd, struct wl_if_info *cur_if);
#endif /* WLMESH && WL_ESCAN */

static struct wl_if_info *
wl_get_cur_if(struct net_device *dev)
{
	dhd_pub_t *dhd = dhd_get_pub(dev);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *cur_if = NULL, *tmp_if = NULL;
	int i;

	for (i=0; i<MAX_IF_NUM; i++) {
		tmp_if = &apsta_params->if_info[i];
		if (tmp_if->dev && tmp_if->dev == dev) {
			cur_if = tmp_if;
			break;
		}
	}

	return cur_if;
}

#define WL_PM_ENABLE_TIMEOUT 10000
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == \
	4 && __GNUC_MINOR__ >= 6))
#define BCM_SET_CONTAINER_OF(entry, ptr, type, member) \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wcast-qual\"") \
entry = container_of((ptr), type, member); \
_Pragma("GCC diagnostic pop")
#else
#define BCM_SET_CONTAINER_OF(entry, ptr, type, member) \
entry = container_of((ptr), type, member);
#endif /* STRICT_GCC_WARNINGS */

static void
wl_ext_pm_work_handler(struct work_struct *work)
{
	struct wl_if_info *cur_if;
	s32 pm = PM_FAST;
	dhd_pub_t *dhd;

	BCM_SET_CONTAINER_OF(cur_if, work, struct wl_if_info, pm_enable_work.work);

	IAPSTA_TRACE("wlan", "%s: Enter\n", __FUNCTION__);

	if (cur_if->dev == NULL)
		return;

#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == \
	4 && __GNUC_MINOR__ >= 6))
_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wcast-qual\"")
#endif

	dhd = dhd_get_pub(cur_if->dev);

	if (!dhd || !dhd->up) {
		IAPSTA_TRACE(cur_if->ifname, "dhd is null or not up\n");
		return;
	}
	if (dhd_conf_get_pm(dhd) >= 0)
		pm = dhd_conf_get_pm(dhd);
	wl_ext_ioctl(cur_if->dev, WLC_SET_PM, &pm, sizeof(pm), 1);
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == \
	4 && __GNUC_MINOR__ >= 6))
_Pragma("GCC diagnostic pop")
#endif
	DHD_PM_WAKE_UNLOCK(dhd);

}

void
wl_ext_add_remove_pm_enable_work(struct net_device *dev, bool add)
{
	dhd_pub_t *dhd = dhd_get_pub(dev);
	struct wl_if_info *cur_if = NULL;
	u16 wq_duration = 0;
	s32 pm = PM_OFF;

	cur_if = wl_get_cur_if(dev);
	if (!cur_if)
		return;

	mutex_lock(&cur_if->pm_sync);
	/*
	 * Make cancel and schedule work part mutually exclusive
	 * so that while cancelling, we are sure that there is no
	 * work getting scheduled.
	 */

	if (delayed_work_pending(&cur_if->pm_enable_work)) {
		cancel_delayed_work_sync(&cur_if->pm_enable_work);
		DHD_PM_WAKE_UNLOCK(dhd);
	}

	if (add) {
		wq_duration = (WL_PM_ENABLE_TIMEOUT);
	}

	/* It should schedule work item only if driver is up */
	if (dhd->up) {
		if (add) {
			if (dhd_conf_get_pm(dhd) >= 0)
				pm = dhd_conf_get_pm(dhd);
			wl_ext_ioctl(cur_if->dev, WLC_SET_PM, &pm, sizeof(pm), 1);
		}
		if (wq_duration) {
			if (schedule_delayed_work(&cur_if->pm_enable_work,
					msecs_to_jiffies((const unsigned int)wq_duration))) {
				DHD_PM_WAKE_LOCK_TIMEOUT(dhd, wq_duration);
			} else {
				IAPSTA_ERROR(cur_if->ifname, "Can't schedule pm work handler\n");
			}
		}
	}
	mutex_unlock(&cur_if->pm_sync);

}

static int
wl_ext_parse_wep(char *key, struct wl_wsec_key *wsec_key)
{
	char hex[] = "XX";
	unsigned char *data = wsec_key->data;
	char *keystr = key;

	switch (strlen(keystr)) {
	case 5:
	case 13:
	case 16:
		wsec_key->len = strlen(keystr);
		memcpy(data, keystr, wsec_key->len + 1);
		break;
	case 12:
	case 28:
	case 34:
	case 66:
		/* strip leading 0x */
		if (!strnicmp(keystr, "0x", 2))
			keystr += 2;
		else
			return -1;
		/* fall through */
	case 10:
	case 26:
	case 32:
	case 64:
		wsec_key->len = strlen(keystr) / 2;
		while (*keystr) {
			strncpy(hex, keystr, 2);
			*data++ = (char) strtoul(hex, NULL, 16);
			keystr += 2;
		}
		break;
	default:
		return -1;
	}

	switch (wsec_key->len) {
	case 5:
		wsec_key->algo = CRYPTO_ALGO_WEP1;
		break;
	case 13:
		wsec_key->algo = CRYPTO_ALGO_WEP128;
		break;
	case 16:
		/* default to AES-CCM */
		wsec_key->algo = CRYPTO_ALGO_AES_CCM;
		break;
	case 32:
		wsec_key->algo = CRYPTO_ALGO_TKIP;
		break;
	default:
		return -1;
	}

	/* Set as primary wsec_key by default */
	wsec_key->flags |= WL_PRIMARY_KEY;

	return 0;
}

static int
wl_ext_set_bgnmode(struct wl_if_info *cur_if)
{
	struct net_device *dev = cur_if->dev;
	bgnmode_t bgnmode = cur_if->bgnmode;
	int val;

	if (bgnmode == 0)
		return 0;

	wl_ext_ioctl(dev, WLC_DOWN, NULL, 0, 1);
	if (bgnmode == IEEE80211B) {
		wl_ext_iovar_setint(dev, "nmode", 0);
		val = 0;
		wl_ext_ioctl(dev, WLC_SET_GMODE, &val, sizeof(val), 1);
		IAPSTA_TRACE(dev->name, "Network mode: B only\n");
	} else if (bgnmode == IEEE80211G) {
		wl_ext_iovar_setint(dev, "nmode", 0);
		val = 2;
		wl_ext_ioctl(dev, WLC_SET_GMODE, &val, sizeof(val), 1);
		IAPSTA_TRACE(dev->name, "Network mode: G only\n");
	} else if (bgnmode == IEEE80211BG) {
		wl_ext_iovar_setint(dev, "nmode", 0);
		val = 1;
		wl_ext_ioctl(dev, WLC_SET_GMODE, &val, sizeof(val), 1);
		IAPSTA_TRACE(dev->name, "Network mode: B/G mixed\n");
	} else if (bgnmode == IEEE80211BGN) {
		wl_ext_iovar_setint(dev, "nmode", 0);
		wl_ext_iovar_setint(dev, "nmode", 1);
		wl_ext_iovar_setint(dev, "vhtmode", 0);
		val = 1;
		wl_ext_ioctl(dev, WLC_SET_GMODE, &val, sizeof(val), 1);
		IAPSTA_TRACE(dev->name, "Network mode: B/G/N mixed\n");
	} else if (bgnmode == IEEE80211BGNAC) {
		wl_ext_iovar_setint(dev, "nmode", 0);
		wl_ext_iovar_setint(dev, "nmode", 1);
		wl_ext_iovar_setint(dev, "vhtmode", 1);
		val = 1;
		wl_ext_ioctl(dev, WLC_SET_GMODE, &val, sizeof(val), 1);
		IAPSTA_TRACE(dev->name, "Network mode: B/G/N/AC mixed\n");
	}
	wl_ext_ioctl(dev, WLC_UP, NULL, 0, 1);

	return 0;
}

static int
wl_ext_set_amode(struct wl_if_info *cur_if)
{
	struct net_device *dev = cur_if->dev;
	authmode_t amode = cur_if->amode;
	int auth=0, wpa_auth=0;

#ifdef WLMESH
	if (cur_if->ifmode == IMESH_MODE) {
		if (amode == AUTH_SAE) {
			auth = WL_AUTH_OPEN_SYSTEM;
			wpa_auth = WPA2_AUTH_PSK;
			IAPSTA_INFO(dev->name, "SAE\n");
		} else {
			auth = WL_AUTH_OPEN_SYSTEM;
			wpa_auth = WPA_AUTH_DISABLED;
			IAPSTA_INFO(dev->name, "Open System\n");
		}
	} else
#endif /* WLMESH */
	if (amode == AUTH_OPEN) {
		auth = WL_AUTH_OPEN_SYSTEM;
		wpa_auth = WPA_AUTH_DISABLED;
		IAPSTA_INFO(dev->name, "Open System\n");
	} else if (amode == AUTH_SHARED) {
		auth = WL_AUTH_SHARED_KEY;
		wpa_auth = WPA_AUTH_DISABLED;
		IAPSTA_INFO(dev->name, "Shared Key\n");
	} else if (amode == AUTH_WPAPSK) {
		auth = WL_AUTH_OPEN_SYSTEM;
		wpa_auth = WPA_AUTH_PSK;
		IAPSTA_INFO(dev->name, "WPA-PSK\n");
	} else if (amode == AUTH_WPA2PSK) {
		auth = WL_AUTH_OPEN_SYSTEM;
		wpa_auth = WPA2_AUTH_PSK;
		IAPSTA_INFO(dev->name, "WPA2-PSK\n");
	} else if (amode == AUTH_WPAWPA2PSK) {
		auth = WL_AUTH_OPEN_SYSTEM;
		wpa_auth = WPA2_AUTH_PSK | WPA_AUTH_PSK;
		IAPSTA_INFO(dev->name, "WPA/WPA2-PSK\n");
	}
#ifdef WLMESH
	if (cur_if->ifmode == IMESH_MODE) {
		s32 val = WL_BSSTYPE_MESH;
		wl_ext_ioctl(dev, WLC_SET_INFRA, &val, sizeof(val), 1);
	} else
#endif /* WLMESH */
	if (cur_if->ifmode == ISTA_MODE) {
		s32 val = WL_BSSTYPE_INFRA;
		wl_ext_ioctl(dev, WLC_SET_INFRA, &val, sizeof(val), 1);
	}
	wl_ext_iovar_setint(dev, "auth", auth);

	wl_ext_iovar_setint(dev, "wpa_auth", wpa_auth);

	return 0;
}

static int
wl_ext_set_emode(struct wl_apsta_params *apsta_params,
	struct wl_if_info *cur_if)
{
	struct net_device *dev = cur_if->dev;
	int wsec=0;
	struct wl_wsec_key wsec_key;
	wsec_pmk_t psk;
	authmode_t amode = cur_if->amode;
	encmode_t emode = cur_if->emode;
	char *key = cur_if->key;
	struct dhd_pub *dhd = apsta_params->dhd;

	memset(&wsec_key, 0, sizeof(wsec_key));
	memset(&psk, 0, sizeof(psk));

#ifdef WLMESH
	if (cur_if->ifmode == IMESH_MODE) {
		if (amode == AUTH_SAE) {
			wsec = AES_ENABLED;
		} else {
			wsec = WSEC_NONE;
		}
	} else
#endif /* WLMESH */
	if (emode == ENC_NONE) {
		wsec = WSEC_NONE;
		IAPSTA_INFO(dev->name, "No securiy\n");
	} else if (emode == ENC_WEP) {
		wsec = WEP_ENABLED;
		wl_ext_parse_wep(key, &wsec_key);
		IAPSTA_INFO(dev->name, "WEP key \"%s\"\n", wsec_key.data);
	} else if (emode == ENC_TKIP) {
		wsec = TKIP_ENABLED;
		psk.key_len = strlen(key);
		psk.flags = WSEC_PASSPHRASE;
		memcpy(psk.key, key, strlen(key));
		IAPSTA_INFO(dev->name, "TKIP key \"%s\"\n", psk.key);
	} else if (emode == ENC_AES || amode == AUTH_SAE) {
		wsec = AES_ENABLED;
		psk.key_len = strlen(key);
		psk.flags = WSEC_PASSPHRASE;
		memcpy(psk.key, key, strlen(key));
		IAPSTA_INFO(dev->name, "AES key \"%s\"\n", psk.key);
	} else if (emode == ENC_TKIPAES) {
		wsec = TKIP_ENABLED | AES_ENABLED;
		psk.key_len = strlen(key);
		psk.flags = WSEC_PASSPHRASE;
		memcpy(psk.key, key, strlen(key));
		IAPSTA_INFO(dev->name, "TKIP/AES key \"%s\"\n", psk.key);
	}
	if (dhd->conf->chip == BCM43430_CHIP_ID && cur_if->ifidx > 0 && wsec >= 2 &&
			apsta_params->apstamode == ISTAAP_MODE) {
		wsec |= WSEC_SWFLAG; // terence 20180628: fix me, this is a workaround
	}

	wl_ext_iovar_setint(dev, "wsec", wsec);

#ifdef WLMESH
	if (cur_if->ifmode == IMESH_MODE) {
		if (amode == AUTH_SAE) {
			s8 iovar_buf[WLC_IOCTL_SMLEN];
			IAPSTA_INFO(dev->name, "AES key \"%s\"\n", key);
			wl_ext_iovar_setint(dev, "mesh_auth_proto", 1);
			wl_ext_iovar_setint(dev, "mfp", WL_MFP_REQUIRED);
			wl_ext_iovar_setbuf(dev, "sae_password", key, strlen(key),
				iovar_buf, WLC_IOCTL_SMLEN, NULL);
		} else {
			IAPSTA_INFO(dev->name, "No securiy\n");
			wl_ext_iovar_setint(dev, "mesh_auth_proto", 0);
			wl_ext_iovar_setint(dev, "mfp", WL_MFP_NONE);
		}
	} else
#endif /* WLMESH */
	if (emode == ENC_WEP) {
		wl_ext_ioctl(dev, WLC_SET_KEY, &wsec_key, sizeof(wsec_key), 1);
	} else if (emode == ENC_TKIP || emode == ENC_AES || emode == ENC_TKIPAES) {
		if (cur_if->ifmode == ISTA_MODE)
			wl_ext_iovar_setint(dev, "sup_wpa", 1);
		wl_ext_ioctl(dev, WLC_SET_WSEC_PMK, &psk, sizeof(psk), 1);
	}

	return 0;
}

static u32
wl_ext_get_chanspec(struct wl_apsta_params *apsta_params,
	struct net_device *dev)
{
	int ret = 0;
	struct ether_addr bssid;
	u32 chanspec = 0;

	ret = wldev_ioctl(dev, WLC_GET_BSSID, &bssid, sizeof(bssid), 0);
	if (ret != BCME_NOTASSOCIATED && memcmp(&ether_null, &bssid, ETHER_ADDR_LEN)) {
		if (wl_ext_iovar_getint(dev, "chanspec", (s32 *)&chanspec) == BCME_OK) {
			chanspec = wl_ext_chspec_driver_to_host(apsta_params->ioctl_ver, chanspec);
			return chanspec;
		}
	}

	return 0;
}

static uint16
wl_ext_get_chan(struct wl_apsta_params *apsta_params, struct net_device *dev)
{
	int ret = 0;
	uint16 chan = 0, ctl_chan;
	struct ether_addr bssid;
	u32 chanspec = 0;

	ret = wldev_ioctl(dev, WLC_GET_BSSID, &bssid, sizeof(bssid), 0);
	if (ret != BCME_NOTASSOCIATED && memcmp(&ether_null, &bssid, ETHER_ADDR_LEN)) {
		if (wl_ext_iovar_getint(dev, "chanspec", (s32 *)&chanspec) == BCME_OK) {
			chanspec = wl_ext_chspec_driver_to_host(apsta_params->ioctl_ver, chanspec);
			ctl_chan = wf_chspec_ctlchan(chanspec);
			chan = (u16)(ctl_chan & 0x00FF);
			return chan;
		}
	}

	return 0;
}

static chanspec_t
wl_ext_chan_to_chanspec(struct wl_apsta_params *apsta_params,
	struct net_device *dev, uint16 channel)
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
				IAPSTA_ERROR(dev->name, "bw_cap failed, %d\n", err);
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
		fw_chspec = wl_ext_chspec_host_to_driver(apsta_params->ioctl_ver, chspec);
		if (fw_chspec == INVCHANSPEC) {
			IAPSTA_ERROR(dev->name, "failed to convert host chanspec to fw chanspec\n");
			fw_chspec = 0;
		}
	} else {
		if (bw == WL_CHANSPEC_BW_80)
			bw = WL_CHANSPEC_BW_40;
		else if (bw == WL_CHANSPEC_BW_40)
			bw = WL_CHANSPEC_BW_20;
		else
			bw = 0;
		if (bw)
			goto set_channel;
		IAPSTA_ERROR(dev->name, "Invalid chanspec 0x%x\n", chspec);
		err = BCME_ERROR;
	}

	return fw_chspec;
}

static bool
wl_ext_radar_detect(struct net_device *dev)
{
	int ret = BCME_OK;
	bool radar = FALSE;
	s32 val = 0;

	if ((ret = wldev_ioctl(dev, WLC_GET_RADAR, &val, sizeof(int), false) == 0)) {
		radar = TRUE;
	}

	return radar;
}

static int
wl_ext_assoclist(struct net_device *dev, char *data, char *command,
	int total_len)
{
	int ret = 0, i, maxassoc = 0, bytes_written = 0;
	char mac_buf[MAX_NUM_OF_ASSOCLIST *
		sizeof(struct ether_addr) + sizeof(uint)] = {0};
	struct maclist *assoc_maclist = (struct maclist *)mac_buf;

	assoc_maclist->count = htod32(MAX_NUM_OF_ASSOCLIST);
	ret = wl_ext_ioctl(dev, WLC_GET_ASSOCLIST, assoc_maclist, sizeof(mac_buf), 0);
	if (ret)
		return -1;
	maxassoc = dtoh32(assoc_maclist->count);
	bytes_written += snprintf(command+bytes_written, total_len,
		"%2s: %12s",
		"no", "------addr------");
	for (i=0; i<maxassoc; i++) {
		bytes_written += snprintf(command+bytes_written, total_len,
			"\n%2d: %pM", i, &assoc_maclist->ea[i]);
	}

	return bytes_written;
}

static void
wl_ext_mod_timer(timer_list_compat_t *timer, uint sec, uint msec)
{
	uint timeout = sec * 1000 + msec;

	IAPSTA_TRACE("wlan", "timeout=%d\n", timeout);

	if (timer_pending(timer))
		del_timer_sync(timer);

	if (timeout)
		mod_timer(timer, jiffies + msecs_to_jiffies(timeout));
}

static void
wl_ext_connect_timeout(unsigned long data)
{
	struct wl_if_info *cur_if = (struct wl_if_info *)data;
	struct dhd_pub *dhd;
	struct wl_apsta_params *apsta_params;
	wl_event_msg_t msg;

	if (!cur_if) {
		IAPSTA_ERROR("wlan", "cur_if is not ready\n");
		return;
	}

	dhd = dhd_get_pub(cur_if->dev);
	apsta_params = dhd->iapsta_params;

	bzero(&msg, sizeof(wl_event_msg_t));
	IAPSTA_ERROR(cur_if->dev->name, "timer expired\n");

	msg.ifidx = hton32(cur_if->ifidx);
	msg.event_type = hton32(WLC_E_SET_SSID);
	msg.status = hton32(WLC_E_STATUS_ABORT);
	
#ifdef WL_EVENT
	wl_ext_event_send(dhd->event_params, &msg, NULL);
#endif
#ifdef WL_CFG80211
	if (dhd->up && cur_if->dev) {
		wl_cfg80211_event(cur_if->dev, &msg, NULL);
	}
#endif /* defined(WL_CFG80211) */
}

#if defined(WL_CFG80211) || (defined(WLMESH) && defined(WL_ESCAN))
static struct wl_if_info *
wl_ext_if_enabled(struct wl_apsta_params *apsta_params, ifmode_t ifmode)
{
	struct wl_if_info *tmp_if, *target_if = NULL;
	int i;

	for (i=0; i<MAX_IF_NUM; i++) {
		tmp_if = &apsta_params->if_info[i];
		if (tmp_if && tmp_if->ifmode == ifmode &&
				wl_get_isam_status(tmp_if, IF_READY)) {
			if (wl_ext_get_chan(apsta_params, tmp_if->dev)) {
				target_if = tmp_if;
				break;
			}
		}
	}

	return target_if;
}
#endif

#ifdef WLMESH
static int
wl_mesh_print_peer_info(mesh_peer_info_ext_t *mpi_ext,
	uint32 peer_results_count, char *command, int total_len)
{
	char *peering_map[] = MESH_PEERING_STATE_STRINGS;
	uint32 count = 0;
	int bytes_written = 0;

	bytes_written += snprintf(command+bytes_written, total_len,
		"%2s: %12s : %6s : %-6s : %6s :"
		" %5s : %4s : %4s : %11s : %4s",
		"no", "------addr------ ", "l.aid", "state", "p.aid",
		"mppid", "llid", "plid", "entry_state", "rssi");
	for (count=0; count < peer_results_count; count++) {
		if (mpi_ext->entry_state != MESH_SELF_PEER_ENTRY_STATE_TIMEDOUT) {
			bytes_written += snprintf(command+bytes_written, total_len,
				"\n%2d: %pM : 0x%4x : %6s : 0x%4x :"
				" %5d : %4d : %4d : %11s : %4d",
				count, &mpi_ext->ea, mpi_ext->local_aid,
				peering_map[mpi_ext->peer_info.state],
				mpi_ext->peer_info.peer_aid,
				mpi_ext->peer_info.mesh_peer_prot_id,
				mpi_ext->peer_info.local_link_id,
				mpi_ext->peer_info.peer_link_id,
				(mpi_ext->entry_state == MESH_SELF_PEER_ENTRY_STATE_ACTIVE) ?
				"ACTIVE" :
				"EXTERNAL",
				mpi_ext->rssi);
		} else {
			bytes_written += snprintf(command+bytes_written, total_len,
				"\n%2d: %pM : %6s : %5s : %6s :"
				" %5s : %4s : %4s : %11s : %4s",
				count, &mpi_ext->ea, "  NA  ", "  NA  ", "  NA  ",
				"  NA ", " NA ", " NA ", "  TIMEDOUT ", " NA ");
		}
		mpi_ext++;
	}

	return bytes_written;
}

static int
wl_mesh_get_peer_results(struct net_device *dev, char *buf, int len)
{
	int indata, inlen;
	mesh_peer_info_dump_t *peer_results;
	int ret;

	memset(buf, 0, len);
	peer_results = (mesh_peer_info_dump_t *)buf;
	indata = htod32(len);
	inlen = 4;
	ret = wl_ext_iovar_getbuf(dev, "mesh_peer_status", &indata, inlen, buf, len, NULL);
	if (!ret) {
		peer_results = (mesh_peer_info_dump_t *)buf;
		ret = peer_results->count;
	}

	return ret;
}

int
wl_ext_mesh_peer_status(struct net_device *dev, char *data, char *command,
	int total_len)
{
	struct wl_if_info *cur_if;
	mesh_peer_info_dump_t *peer_results;
	mesh_peer_info_ext_t *mpi_ext;
	char *peer_buf = NULL;
	int peer_len = WLC_IOCTL_MAXLEN;
	int dump_written = 0, ret;

	if (!data) {
		peer_buf = kmalloc(peer_len, GFP_KERNEL);
		if (peer_buf == NULL) {
			IAPSTA_ERROR(dev->name, "Failed to allocate buffer of %d bytes\n",
				peer_len); 
			return -1;
		}
		cur_if = wl_get_cur_if(dev);
		if (cur_if && cur_if->ifmode == IMESH_MODE) {
			memset(peer_buf, 0, peer_len);
			ret = wl_mesh_get_peer_results(dev, peer_buf, peer_len);
			if (ret >= 0) {
				peer_results = (mesh_peer_info_dump_t *)peer_buf;
				mpi_ext = (mesh_peer_info_ext_t *)peer_results->mpi_ext;
				dump_written += wl_mesh_print_peer_info(mpi_ext,
					peer_results->count, command+dump_written,
					total_len-dump_written);
			}
		} else if (cur_if) {
			IAPSTA_ERROR(dev->name, "[%s][%c] is not mesh interface\n",
				cur_if->ifname, cur_if->prefix);
		}
	}

	if (peer_buf)
		kfree(peer_buf);
	return dump_written;
}

#ifdef WL_ESCAN
#define WL_MESH_DELAY_SCAN_TMO	3
static void
wl_mesh_timer(unsigned long data)
{
	wl_event_msg_t msg;
	struct wl_if_info *mesh_if = (struct wl_if_info *)data;
	struct dhd_pub *dhd;

	if (!mesh_if) {
		IAPSTA_ERROR("wlan", "mesh_if is not ready\n");
		return;
	}

	if (!mesh_if->dev) {
		IAPSTA_ERROR("wlan", "ifidx %d is not ready\n", mesh_if->ifidx);
		return;
	}
	dhd = dhd_get_pub(mesh_if->dev);

	bzero(&msg, sizeof(wl_event_msg_t));
	IAPSTA_TRACE(mesh_if->dev->name, "timer expired\n");

	msg.ifidx = mesh_if->ifidx;
	msg.event_type = hton32(WLC_E_RESERVED);
	msg.reason = hton32(ISAM_RC_MESH_ACS);
	wl_ext_event_send(dhd->event_params, &msg, NULL);
}

static int
wl_mesh_clear_vndr_ie(struct net_device *dev, uchar *oui)
{
	char *vndr_ie_buf = NULL;
	vndr_ie_setbuf_t *vndr_ie = NULL;
	ie_getbuf_t vndr_ie_tmp;
	char *iovar_buf = NULL;
	int err = -1, i;
	vndr_ie_buf_t *vndr_ie_dump = NULL;
	uchar *iebuf;
	vndr_ie_info_t *ie_info;
	vndr_ie_t *ie;

	vndr_ie_buf = kzalloc(WLC_IOCTL_SMLEN, GFP_KERNEL);
	if (!vndr_ie_buf) {
		IAPSTA_ERROR(dev->name, "IE memory alloc failed\n");
		err = -ENOMEM;
		goto exit;
	}

	iovar_buf = kzalloc(WLC_IOCTL_MEDLEN, GFP_KERNEL);
	if (!iovar_buf) {
		IAPSTA_ERROR(dev->name, "iovar_buf alloc failed\n");
		err = -ENOMEM;
		goto exit;
	}

	memset(iovar_buf, 0, WLC_IOCTL_MEDLEN);
	vndr_ie_tmp.pktflag = (uint32) -1;
	vndr_ie_tmp.id = (uint8) DOT11_MNG_PROPR_ID;
	err = wl_ext_iovar_getbuf(dev, "vndr_ie", &vndr_ie_tmp, sizeof(vndr_ie_tmp),
		iovar_buf, WLC_IOCTL_MEDLEN, NULL);
	if (err)
		goto exit;

	vndr_ie_dump = (vndr_ie_buf_t *)iovar_buf;
	if (!vndr_ie_dump->iecount)
		goto exit;

	iebuf = (uchar *)&vndr_ie_dump->vndr_ie_list[0];
	for (i=0; i<vndr_ie_dump->iecount; i++) {
		ie_info = (vndr_ie_info_t *) iebuf;
		ie = &ie_info->vndr_ie_data;
		if (memcmp(ie->oui, oui, 3))
			memset(ie->oui, 0, 3);
		iebuf += sizeof(uint32) + ie->len + VNDR_IE_HDR_LEN;
	}

	vndr_ie = (vndr_ie_setbuf_t *) vndr_ie_buf;
	strncpy(vndr_ie->cmd, "del", VNDR_IE_CMD_LEN - 1);
	vndr_ie->cmd[VNDR_IE_CMD_LEN - 1] = '\0';
	memcpy(&vndr_ie->vndr_ie_buffer, vndr_ie_dump, WLC_IOCTL_SMLEN-VNDR_IE_CMD_LEN-1);

	memset(iovar_buf, 0, WLC_IOCTL_MEDLEN);
	err = wl_ext_iovar_setbuf(dev, "vndr_ie", vndr_ie, WLC_IOCTL_SMLEN, iovar_buf,
		WLC_IOCTL_MEDLEN, NULL);

exit:
	if (vndr_ie) {
		kfree(vndr_ie);
	}
	if (iovar_buf) {
		kfree(iovar_buf);
	}
	return err;
}

static int
wl_mesh_clear_mesh_info(struct wl_apsta_params *apsta_params,
	struct wl_if_info *mesh_if, bool scan)
{
	struct wl_mesh_params *mesh_info = &apsta_params->mesh_info;
	uchar mesh_oui[]={0x00, 0x22, 0xf4};
	int ret;

	IAPSTA_TRACE(mesh_if->dev->name, "Enter\n");

	ret = wl_mesh_clear_vndr_ie(mesh_if->dev, mesh_oui);
	memset(mesh_info, 0, sizeof(struct wl_mesh_params));
	if (scan) {
		mesh_info->scan_channel = wl_ext_get_chan(apsta_params, mesh_if->dev);
		wl_ext_mod_timer(&mesh_if->delay_scan, 0, 100);
	}

	return ret;
}

static int
wl_mesh_update_vndr_ie(struct wl_apsta_params *apsta_params,
	struct wl_if_info *mesh_if)
{
	struct wl_mesh_params *mesh_info = &apsta_params->mesh_info;
	char *vndr_ie;
	uchar mesh_oui[]={0x00, 0x22, 0xf4};
	int bytes_written = 0;
	int ret = 0, i, vndr_ie_len;
	uint8 *peer_bssid;

	wl_mesh_clear_vndr_ie(mesh_if->dev, mesh_oui);

	vndr_ie_len = WLC_IOCTL_MEDLEN;
	vndr_ie = kmalloc(vndr_ie_len, GFP_KERNEL);
	if (vndr_ie == NULL) {
		IAPSTA_ERROR(mesh_if->dev->name, "Failed to allocate buffer of %d bytes\n",
			WLC_IOCTL_MEDLEN); 
		ret = -1;
		goto exit;
	}

	bytes_written += snprintf(vndr_ie+bytes_written, vndr_ie_len,
		"0x%02x%02x%02x", mesh_oui[0], mesh_oui[1], mesh_oui[2]);

	bytes_written += snprintf(vndr_ie+bytes_written, vndr_ie_len,
		"%02x%02x%02x%02x%02x%02x%02x%02x", MESH_INFO_MASTER_BSSID, ETHER_ADDR_LEN,
		((u8 *)(&mesh_info->master_bssid))[0], ((u8 *)(&mesh_info->master_bssid))[1],
		((u8 *)(&mesh_info->master_bssid))[2], ((u8 *)(&mesh_info->master_bssid))[3],
		((u8 *)(&mesh_info->master_bssid))[4], ((u8 *)(&mesh_info->master_bssid))[5]);

	bytes_written += snprintf(vndr_ie+bytes_written, vndr_ie_len,
		"%02x%02x%02x", MESH_INFO_MASTER_CHANNEL, 1, mesh_info->master_channel);

	bytes_written += snprintf(vndr_ie+bytes_written, vndr_ie_len,
		"%02x%02x%02x", MESH_INFO_HOP_CNT, 1, mesh_info->hop_cnt);

	bytes_written += snprintf(vndr_ie+bytes_written, vndr_ie_len,
		"%02x%02x", MESH_INFO_PEER_BSSID, mesh_info->hop_cnt*ETHER_ADDR_LEN);
	for (i=0; i<mesh_info->hop_cnt && i<MAX_HOP_LIST; i++) {
		peer_bssid = (uint8 *)&mesh_info->peer_bssid[i];
		bytes_written += snprintf(vndr_ie+bytes_written, vndr_ie_len,
			"%02x%02x%02x%02x%02x%02x",
 			peer_bssid[0], peer_bssid[1], peer_bssid[2],
			peer_bssid[3], peer_bssid[4], peer_bssid[5]);
	}

	ret = wl_ext_add_del_ie(mesh_if->dev, VNDR_IE_BEACON_FLAG|VNDR_IE_PRBRSP_FLAG,
		vndr_ie, "add");
	if (!ret) {
		IAPSTA_INFO(mesh_if->dev->name, "mbssid=%pM, mchannel=%d, hop=%d, pbssid=%pM\n",
			&mesh_info->master_bssid, mesh_info->master_channel, mesh_info->hop_cnt,
			mesh_info->peer_bssid); 
	}

exit:
	if (vndr_ie)
		kfree(vndr_ie);
	return ret;
}

static bool
wl_mesh_update_master_info(struct wl_apsta_params *apsta_params,
	struct wl_if_info *mesh_if)
{
	struct wl_mesh_params *mesh_info = &apsta_params->mesh_info;
	struct wl_if_info *sta_if = NULL;
	bool updated = FALSE;

	sta_if = wl_ext_if_enabled(apsta_params, ISTA_MODE);
	if (sta_if) {
		wldev_ioctl(mesh_if->dev, WLC_GET_BSSID, &mesh_info->master_bssid,
			ETHER_ADDR_LEN, 0);
		mesh_info->master_channel = wl_ext_get_chan(apsta_params, mesh_if->dev);
		mesh_info->hop_cnt = 0;
		memset(mesh_info->peer_bssid, 0, MAX_HOP_LIST*ETHER_ADDR_LEN);
		if (!wl_mesh_update_vndr_ie(apsta_params, mesh_if))
			updated = TRUE;
	}

	return updated;
}

static bool
wl_mesh_update_mesh_info(struct wl_apsta_params *apsta_params,
	struct wl_if_info *mesh_if)
{
	struct wl_mesh_params *mesh_info = &apsta_params->mesh_info, peer_mesh_info;
	uint32 count = 0;
	char *dump_buf = NULL;
	mesh_peer_info_dump_t *peer_results;
	mesh_peer_info_ext_t *mpi_ext;
	struct ether_addr bssid;
	bool updated = FALSE, bss_found = FALSE;
	uint16 cur_chan;

	dump_buf = kmalloc(WLC_IOCTL_MAXLEN, GFP_KERNEL);
	if (dump_buf == NULL) {
		IAPSTA_ERROR(mesh_if->dev->name, "Failed to allocate buffer of %d bytes\n",
			WLC_IOCTL_MAXLEN); 
		return FALSE;
	}
	count = wl_mesh_get_peer_results(mesh_if->dev, dump_buf, WLC_IOCTL_MAXLEN);
	if (count > 0) {
		memset(&bssid, 0, ETHER_ADDR_LEN);
		wldev_ioctl(mesh_if->dev, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN, 0);
		peer_results = (mesh_peer_info_dump_t *)dump_buf;
		mpi_ext = (mesh_peer_info_ext_t *)peer_results->mpi_ext;
		for (count = 0; count < peer_results->count; count++) {
			if (mpi_ext->entry_state != MESH_SELF_PEER_ENTRY_STATE_TIMEDOUT &&
					mpi_ext->peer_info.state == MESH_PEERING_ESTAB) {
				memset(&peer_mesh_info, 0, sizeof(struct wl_mesh_params));
				bss_found = wl_escan_mesh_info(mesh_if->dev, mesh_if->escan,
					&mpi_ext->ea, &peer_mesh_info);
				if (bss_found && (mesh_info->master_channel == 0 ||
						peer_mesh_info.hop_cnt <= mesh_info->hop_cnt) &&
						memcmp(&peer_mesh_info.peer_bssid, &bssid, ETHER_ADDR_LEN)) {
					memcpy(&mesh_info->master_bssid, &peer_mesh_info.master_bssid,
						ETHER_ADDR_LEN);
					mesh_info->master_channel = peer_mesh_info.master_channel;
					mesh_info->hop_cnt = peer_mesh_info.hop_cnt+1;
					memset(mesh_info->peer_bssid, 0, MAX_HOP_LIST*ETHER_ADDR_LEN);
					memcpy(&mesh_info->peer_bssid, &mpi_ext->ea, ETHER_ADDR_LEN);
					memcpy(&mesh_info->peer_bssid[1], peer_mesh_info.peer_bssid,
						(MAX_HOP_LIST-1)*ETHER_ADDR_LEN);
					updated = TRUE;
				}
			}
			mpi_ext++;
		}
		if (updated) {
			if (wl_mesh_update_vndr_ie(apsta_params, mesh_if)) {
				IAPSTA_ERROR(mesh_if->dev->name, "update failed\n");
				mesh_info->master_channel = 0;
				updated = FALSE;
				goto exit;
			}
		}
	}

	if (!mesh_info->master_channel) {
		wlc_ssid_t cur_ssid;
		char sec[32];
		bool sae = FALSE;
		memset(&peer_mesh_info, 0, sizeof(struct wl_mesh_params));
		wl_ext_ioctl(mesh_if->dev, WLC_GET_SSID, &cur_ssid, sizeof(cur_ssid), 0);
		wl_ext_get_sec(mesh_if->dev, mesh_if->ifmode, sec, sizeof(sec), FALSE);
		if (strnicmp(sec, "sae/sae", strlen("sae/sae")) == 0)
			sae = TRUE;
		cur_chan = wl_ext_get_chan(apsta_params, mesh_if->dev);
		bss_found = wl_escan_mesh_peer(mesh_if->dev, mesh_if->escan, &cur_ssid, cur_chan,
			sae, &peer_mesh_info);

		if (bss_found && peer_mesh_info.master_channel&&
				(cur_chan != peer_mesh_info.master_channel)) {
			WL_MSG(mesh_if->ifname, "moving channel %d -> %d\n",
				cur_chan, peer_mesh_info.master_channel);
			wl_ext_disable_iface(mesh_if->dev, mesh_if->ifname);
			mesh_if->channel = peer_mesh_info.master_channel;
			wl_ext_enable_iface(mesh_if->dev, mesh_if->ifname, 500, TRUE);
		}
	}

exit:
	if (dump_buf)
		kfree(dump_buf);
	return updated;
}

static void
wl_mesh_event_handler(struct wl_apsta_params *apsta_params,
	struct wl_if_info *mesh_if, const wl_event_msg_t *e, void *data)
{
	struct wl_mesh_params *mesh_info = &apsta_params->mesh_info;
	uint32 event_type = ntoh32(e->event_type);
	uint32 status = ntoh32(e->status);
	uint32 reason = ntoh32(e->reason);
	int ret;

	if (wl_get_isam_status(mesh_if, AP_CREATED) &&
			((event_type == WLC_E_SET_SSID && status == WLC_E_STATUS_SUCCESS) ||
			(event_type == WLC_E_LINK && status == WLC_E_STATUS_SUCCESS &&
			reason == WLC_E_REASON_INITIAL_ASSOC))) {
		if (!wl_mesh_update_master_info(apsta_params, mesh_if)) {
			mesh_info->scan_channel = wl_ext_get_chan(apsta_params, mesh_if->dev);
			wl_ext_mod_timer(&mesh_if->delay_scan, WL_MESH_DELAY_SCAN_TMO, 0);
		}
	}
	else if ((event_type == WLC_E_LINK && reason == WLC_E_LINK_BSSCFG_DIS) ||
			(event_type == WLC_E_LINK && status == WLC_E_STATUS_SUCCESS &&
			reason == WLC_E_REASON_DEAUTH)) {
		wl_mesh_clear_mesh_info(apsta_params, mesh_if, FALSE);
	}
	else if (wl_get_isam_status(mesh_if, AP_CREATED) &&
			(event_type == WLC_E_ASSOC_IND || event_type == WLC_E_REASSOC_IND) &&
			reason == DOT11_SC_SUCCESS) {
		mesh_info->scan_channel = wl_ext_get_chan(apsta_params, mesh_if->dev);
		wl_ext_mod_timer(&mesh_if->delay_scan, 0, 100);
	}
	else if (event_type == WLC_E_DISASSOC_IND || event_type == WLC_E_DEAUTH_IND ||
			(event_type == WLC_E_DEAUTH && reason != DOT11_RC_RESERVED)) {
		if (!memcmp(&mesh_info->peer_bssid, &e->addr, ETHER_ADDR_LEN))
			wl_mesh_clear_mesh_info(apsta_params, mesh_if, TRUE);
	}
	else if (wl_get_isam_status(mesh_if, AP_CREATED) &&
			event_type == WLC_E_RESERVED && reason == ISAM_RC_MESH_ACS) {
		if (!wl_mesh_update_master_info(apsta_params, mesh_if)) {
			wl_scan_info_t scan_info;
			memset(&scan_info, 0, sizeof(wl_scan_info_t));
			wl_ext_ioctl(mesh_if->dev, WLC_GET_SSID, &scan_info.ssid, sizeof(wlc_ssid_t), 0);
			scan_info.channels.count = 1;
			scan_info.channels.channel[0] = mesh_info->scan_channel;
			ret = wl_escan_set_scan(mesh_if->dev, &scan_info);
			if (ret)
				wl_ext_mod_timer(&mesh_if->delay_scan, WL_MESH_DELAY_SCAN_TMO, 0);
		}
	}
	else if (wl_get_isam_status(mesh_if, AP_CREATED) &&
			((event_type == WLC_E_ESCAN_RESULT && status == WLC_E_STATUS_SUCCESS) ||
			(event_type == WLC_E_ESCAN_RESULT &&
			(status == WLC_E_STATUS_ABORT || status == WLC_E_STATUS_NEWSCAN ||
			status == WLC_E_STATUS_11HQUIET || status == WLC_E_STATUS_CS_ABORT ||
			status == WLC_E_STATUS_NEWASSOC || status == WLC_E_STATUS_TIMEOUT)))) {
		if (!wl_mesh_update_master_info(apsta_params, mesh_if)) {
			if (!wl_mesh_update_mesh_info(apsta_params, mesh_if)) {
				mesh_info->scan_channel = 0;
				wl_ext_mod_timer(&mesh_if->delay_scan, WL_MESH_DELAY_SCAN_TMO, 0);
			}
		}
	}
}

static void
wl_mesh_escan_detach(dhd_pub_t *dhd, struct wl_if_info *mesh_if)
{
	IAPSTA_TRACE(mesh_if->dev->name, "Enter\n");

	del_timer_sync(&mesh_if->delay_scan);

	if (mesh_if->escan) {
		mesh_if->escan = NULL;
	}
}

static int
wl_mesh_escan_attach(dhd_pub_t *dhd, struct wl_if_info *mesh_if)
{
	IAPSTA_TRACE(mesh_if->dev->name, "Enter\n");

	mesh_if->escan = dhd->escan;
	init_timer_compat(&mesh_if->delay_scan, wl_mesh_timer, mesh_if);

	return 0;
}

static uint
wl_mesh_update_peer_path(struct wl_if_info *mesh_if, char *command,
	int total_len)
{
	struct wl_mesh_params peer_mesh_info;
	uint32 count = 0;
	char *dump_buf = NULL;
	mesh_peer_info_dump_t *peer_results;
	mesh_peer_info_ext_t *mpi_ext;
	int bytes_written = 0, j, k;
	bool bss_found = FALSE;

	dump_buf = kmalloc(WLC_IOCTL_MAXLEN, GFP_KERNEL);
	if (dump_buf == NULL) {
		IAPSTA_ERROR(mesh_if->dev->name, "Failed to allocate buffer of %d bytes\n",
			WLC_IOCTL_MAXLEN); 
		return FALSE;
	}
	count = wl_mesh_get_peer_results(mesh_if->dev, dump_buf, WLC_IOCTL_MAXLEN);
	if (count > 0) {
		peer_results = (mesh_peer_info_dump_t *)dump_buf;
		mpi_ext = (mesh_peer_info_ext_t *)peer_results->mpi_ext;
		for (count = 0; count < peer_results->count; count++) {
			if (mpi_ext->entry_state != MESH_SELF_PEER_ENTRY_STATE_TIMEDOUT &&
					mpi_ext->peer_info.state == MESH_PEERING_ESTAB) {
				memset(&peer_mesh_info, 0, sizeof(struct wl_mesh_params));
				bss_found = wl_escan_mesh_info(mesh_if->dev, mesh_if->escan,
					&mpi_ext->ea, &peer_mesh_info);
				if (bss_found) {
					bytes_written += snprintf(command+bytes_written, total_len,
						"\npeer=%pM, hop=%d",
						&mpi_ext->ea, peer_mesh_info.hop_cnt);
					for (j=1; j<peer_mesh_info.hop_cnt; j++) {
						bytes_written += snprintf(command+bytes_written,
							total_len, "\n");
						for (k=0; k<j; k++) {
							bytes_written += snprintf(command+bytes_written,
								total_len, " ");
						}
						bytes_written += snprintf(command+bytes_written, total_len,
							"%pM", &peer_mesh_info.peer_bssid[j]);
					}
				}
			}
			mpi_ext++;
		}
	}

	if (dump_buf)
		kfree(dump_buf);
	return bytes_written;
}

int
wl_ext_isam_peer_path(struct net_device *dev, char *command, int total_len)
{
	struct dhd_pub *dhd = dhd_get_pub(dev);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_mesh_params *mesh_info = &apsta_params->mesh_info;
	struct wl_if_info *tmp_if;
	uint16 chan = 0;
	char *dump_buf = NULL;
	int dump_len = WLC_IOCTL_MEDLEN;
	int dump_written = 0;
	int i;

	if (command || android_msg_level & ANDROID_INFO_LEVEL) {
		if (command) {
			dump_buf = command;
			dump_len = total_len;
		} else {
			dump_buf = kmalloc(dump_len, GFP_KERNEL);
			if (dump_buf == NULL) {
				IAPSTA_ERROR(dev->name, "Failed to allocate buffer of %d bytes\n",
					dump_len); 
				return -1;
			}
		}
		for (i=0; i<MAX_IF_NUM; i++) {
			tmp_if = &apsta_params->if_info[i];
			if (tmp_if->dev && tmp_if->ifmode == IMESH_MODE && apsta_params->macs) {
				chan = wl_ext_get_chan(apsta_params, tmp_if->dev);
				if (chan) {
					dump_written += snprintf(dump_buf+dump_written, dump_len,
						DHD_LOG_PREFIX "[%s-%c] mbssid=%pM, mchan=%d, hop=%d, pbssid=%pM",
						tmp_if->ifname, tmp_if->prefix, &mesh_info->master_bssid,
						mesh_info->master_channel, mesh_info->hop_cnt,
						&mesh_info->peer_bssid);
					dump_written += wl_mesh_update_peer_path(tmp_if,
						dump_buf+dump_written, dump_len-dump_written);
				}
			}
		}
		IAPSTA_INFO(dev->name, "%s\n", dump_buf);
	}

	if (!command && dump_buf)
		kfree(dump_buf);
	return dump_written;
}
#endif /* WL_ESCAN */
#endif /* WLMESH */

static bool
wl_ext_master_if(struct wl_if_info *cur_if)
{
	if (cur_if->ifmode == IAP_MODE || cur_if->ifmode == IMESH_MODE)
		return TRUE;
	else
		return FALSE;
}

static int
wl_ext_if_down(struct wl_apsta_params *apsta_params, struct wl_if_info *cur_if)
{
	s8 iovar_buf[WLC_IOCTL_SMLEN];
	scb_val_t scbval;
	struct {
		s32 cfg;
		s32 val;
	} bss_setbuf;
	apstamode_t apstamode = apsta_params->apstamode;

	WL_MSG(cur_if->ifname, "[%c] Turning off...\n", cur_if->prefix);

	if (cur_if->ifmode == ISTA_MODE) {
		wl_ext_ioctl(cur_if->dev, WLC_DISASSOC, NULL, 0, 1);
		return 0;
	} else if (cur_if->ifmode == IAP_MODE || cur_if->ifmode == IMESH_MODE) {
		// deauthenticate all STA first
		memcpy(scbval.ea.octet, &ether_bcast, ETHER_ADDR_LEN);
		wl_ext_ioctl(cur_if->dev, WLC_SCB_DEAUTHENTICATE, &scbval.ea, ETHER_ADDR_LEN, 1);
	}

	if (apstamode == IAPONLY_MODE || apstamode == IMESHONLY_MODE) {
		wl_ext_ioctl(cur_if->dev, WLC_DOWN, NULL, 0, 1);
	} else {
		bss_setbuf.cfg = 0xffffffff;
		bss_setbuf.val = htod32(0);
		wl_ext_iovar_setbuf(cur_if->dev, "bss", &bss_setbuf, sizeof(bss_setbuf),
			iovar_buf, WLC_IOCTL_SMLEN, NULL);
	}
	wl_clr_isam_status(cur_if, AP_CREATED);

	return 0;
}

static int
wl_ext_if_up(struct wl_apsta_params *apsta_params, struct wl_if_info *cur_if,
	bool force_enable, int wait_up)
{
	s8 iovar_buf[WLC_IOCTL_SMLEN];
	struct {
		s32 cfg;
		s32 val;
	} bss_setbuf;
	apstamode_t apstamode = apsta_params->apstamode;
	chanspec_t fw_chspec;
	u32 timeout;
	wlc_ssid_t ssid = { 0, {0} };
	uint16 chan = 0;

	if (cur_if->ifmode != IAP_MODE) {
		IAPSTA_ERROR(cur_if->ifname, "Wrong ifmode\n");
		return 0;
	}

	if (wl_ext_dfs_chan(cur_if->channel) && !apsta_params->radar && !force_enable) {
		WL_MSG(cur_if->ifname, "[%c] skip DFS channel %d\n",
			cur_if->prefix, cur_if->channel);
		return 0;
	} else if (!cur_if->channel) {
		WL_MSG(cur_if->ifname, "[%c] no valid channel\n", cur_if->prefix);
		return 0;
	}

	WL_MSG(cur_if->ifname, "[%c] Turning on...\n", cur_if->prefix);

	wl_ext_set_chanspec(cur_if->dev, apsta_params->ioctl_ver, cur_if->channel,
		&fw_chspec);

	wl_clr_isam_status(cur_if, AP_CREATED);
	wl_set_isam_status(cur_if, AP_CREATING);
	if (apstamode == IAPONLY_MODE) {
		wl_ext_ioctl(cur_if->dev, WLC_UP, NULL, 0, 1);
	} else {
		bss_setbuf.cfg = 0xffffffff;	
		bss_setbuf.val = htod32(1);
		wl_ext_iovar_setbuf(cur_if->dev, "bss", &bss_setbuf,
			sizeof(bss_setbuf), iovar_buf, WLC_IOCTL_SMLEN, NULL);
	}

	if (wait_up) {
		OSL_SLEEP(wait_up);
	} else {
		timeout = wait_event_interruptible_timeout(apsta_params->netif_change_event,
			wl_get_isam_status(cur_if, AP_CREATED),
			msecs_to_jiffies(MAX_AP_LINK_WAIT_TIME));
		if (timeout <= 0 || !wl_get_isam_status(cur_if, AP_CREATED)) {
			wl_ext_if_down(apsta_params, cur_if);
			WL_MSG(cur_if->ifname, "[%c] failed to up with SSID: \"%s\"\n",
				cur_if->prefix, cur_if->ssid);
		}
	}

	wl_ext_ioctl(cur_if->dev, WLC_GET_SSID, &ssid, sizeof(ssid), 0);
	chan = wl_ext_get_chan(apsta_params, cur_if->dev);
	WL_MSG(cur_if->ifname, "[%c] enabled with SSID: \"%s\" on channel %d\n",
		cur_if->prefix, ssid.SSID, chan);

	wl_clr_isam_status(cur_if, AP_CREATING);

	wl_ext_isam_status(cur_if->dev, NULL, 0);

	return 0;
}

static bool
wl_ext_diff_band(uint16 chan1, uint16 chan2)
{
	if ((chan1 <= CH_MAX_2G_CHANNEL && chan2 > CH_MAX_2G_CHANNEL) ||
		(chan1 > CH_MAX_2G_CHANNEL && chan2 <= CH_MAX_2G_CHANNEL)) {
		return TRUE;
	}
	return FALSE;
}

static uint16
wl_ext_same_band(struct wl_apsta_params *apsta_params,
	struct wl_if_info *cur_if, bool nodfs)
{
	struct wl_if_info *tmp_if;
	uint16 tmp_chan, target_chan = 0;
	wl_prio_t max_prio;
	int i;

	// find the max prio
	max_prio = cur_if->prio;
	for (i=0; i<MAX_IF_NUM; i++) {
		tmp_if = &apsta_params->if_info[i];
		if (cur_if != tmp_if && wl_get_isam_status(tmp_if, IF_READY) &&
				tmp_if->prio > max_prio) {
			tmp_chan = wl_ext_get_chan(apsta_params, tmp_if->dev);
			if (wl_ext_dfs_chan(tmp_chan) && nodfs)
				continue;
			if (tmp_chan && !wl_ext_diff_band(cur_if->channel, tmp_chan)) {
				target_chan = tmp_chan;
				max_prio = tmp_if->prio;
			}
		}
	}

	return target_chan;
}

static uint16
wl_ext_get_vsdb_chan(struct wl_apsta_params *apsta_params,
	struct wl_if_info *cur_if, struct wl_if_info *target_if)
{
	uint16 target_chan = 0, cur_chan = cur_if->channel;

	if (cur_if->vsdb && target_if->vsdb)
		return 0;

	target_chan = wl_ext_get_chan(apsta_params, target_if->dev);
	if (target_chan) {
		IAPSTA_INFO(cur_if->ifname, "cur_chan=%d, target_chan=%d\n",
			cur_chan, target_chan);
		if (wl_ext_diff_band(cur_chan, target_chan)) {
			if (!apsta_params->rsdb)
				return target_chan;
		} else {
			if (cur_chan != target_chan)
				return target_chan;
		}
	}

	return 0;
}

static int
wl_ext_rsdb_core_conflict(struct wl_apsta_params *apsta_params,
	struct wl_if_info *cur_if)
{
	struct wl_if_info *tmp_if;
	uint16 cur_chan, tmp_chan;
	int i;

	if (apsta_params->rsdb) {
		cur_chan = wl_ext_get_chan(apsta_params, cur_if->dev);
		for (i=0; i<MAX_IF_NUM; i++) {
			tmp_if = &apsta_params->if_info[i];
			if (tmp_if != cur_if && wl_get_isam_status(tmp_if, IF_READY) &&
					tmp_if->prio > cur_if->prio) {
				tmp_chan = wl_ext_get_chan(apsta_params, tmp_if->dev);
				if (!tmp_chan)
					continue;
				if (wl_ext_diff_band(cur_chan, tmp_chan) &&
						wl_ext_diff_band(cur_chan, cur_if->channel))
					return TRUE;
				else if (!wl_ext_diff_band(cur_chan, tmp_chan) &&
						wl_ext_diff_band(cur_chan, cur_if->channel))
					return TRUE;
			}
		}
	}
	return FALSE;
}

static int
wl_ext_trigger_csa(struct wl_apsta_params *apsta_params, struct wl_if_info *cur_if)
{
	s8 iovar_buf[WLC_IOCTL_SMLEN];
	bool core_conflict = FALSE;

	if (wl_ext_master_if(cur_if) && (apsta_params->csa & CSA_DRV_BIT)) {
		if (!cur_if->channel) {
			WL_MSG(cur_if->ifname, "[%c] no valid channel\n", cur_if->prefix);
		} else if (wl_ext_dfs_chan(cur_if->channel) && !apsta_params->radar) {
			WL_MSG(cur_if->ifname, "[%c] skip DFS channel %d\n",
				cur_if->prefix, cur_if->channel);
			wl_ext_if_down(apsta_params, cur_if);
		} else {
			wl_chan_switch_t csa_arg;
			memset(&csa_arg, 0, sizeof(csa_arg));
			csa_arg.mode = 1;
			csa_arg.count = 3;
			csa_arg.chspec = wl_ext_chan_to_chanspec(apsta_params, cur_if->dev,
				cur_if->channel);
			core_conflict = wl_ext_rsdb_core_conflict(apsta_params, cur_if);
			if (core_conflict) {
				WL_MSG(cur_if->ifname, "[%c] Skip CSA due to rsdb core conflict\n",
					cur_if->prefix);
			} else if (csa_arg.chspec) {
				WL_MSG(cur_if->ifname, "[%c] Trigger CSA to channel %d(0x%x)\n",
					cur_if->prefix, cur_if->channel, csa_arg.chspec);
				wl_set_isam_status(cur_if, AP_CREATING);
				wl_ext_iovar_setbuf(cur_if->dev, "csa", &csa_arg, sizeof(csa_arg),
					iovar_buf, sizeof(iovar_buf), NULL);
				OSL_SLEEP(500);
				wl_clr_isam_status(cur_if, AP_CREATING);
				wl_ext_isam_status(cur_if->dev, NULL, 0);
			} else {
				IAPSTA_ERROR(cur_if->ifname, "fail to get chanspec\n");
			}
		}
	}

	return 0;
}

static void
wl_ext_move_cur_dfs_channel(struct wl_apsta_params *apsta_params,
	struct wl_if_info *cur_if)
{
	uint16 other_chan = 0, cur_chan = cur_if->channel;
	uint16 chan_2g = 0, chan_5g = 0;
	uint32 auto_band = WLC_BAND_2G;

	if (wl_ext_master_if(cur_if) && wl_ext_dfs_chan(cur_if->channel) &&
			!apsta_params->radar) {

		wl_ext_get_default_chan(cur_if->dev, &chan_2g, &chan_5g, TRUE);
		if (!chan_2g && !chan_5g) {
			cur_if->channel = 0;
			WL_MSG(cur_if->ifname, "[%c] no valid channel\n", cur_if->prefix);
			return;
		}

		if (apsta_params->vsdb) {
			if (chan_5g) {
				cur_if->channel = chan_5g;
				auto_band = WLC_BAND_5G;
				other_chan = wl_ext_same_band(apsta_params, cur_if, TRUE);
			} else {
				cur_if->channel = chan_2g;
				auto_band = WLC_BAND_2G;
				other_chan = wl_ext_same_band(apsta_params, cur_if, TRUE);
			}
			if (!other_chan) {
				other_chan = wl_ext_autochannel(cur_if->dev, ACS_FW_BIT|ACS_DRV_BIT,
					auto_band);
			}
			if (other_chan)
				cur_if->channel = other_chan;
		} else if (apsta_params->rsdb) {
			if (chan_5g) {
				cur_if->channel = chan_5g;
				auto_band = WLC_BAND_5G;
				other_chan = wl_ext_same_band(apsta_params, cur_if, FALSE);
				if (wl_ext_dfs_chan(other_chan) && chan_2g) {
					cur_if->channel = chan_2g;
					auto_band = WLC_BAND_2G;
					other_chan = wl_ext_same_band(apsta_params, cur_if, TRUE);
				}
			} else {
				cur_if->channel = chan_2g;
				auto_band = WLC_BAND_2G;
				other_chan = wl_ext_same_band(apsta_params, cur_if, TRUE);
			}
			if (!other_chan) {
				other_chan = wl_ext_autochannel(cur_if->dev, ACS_FW_BIT|ACS_DRV_BIT,
					auto_band);
			}
			if (other_chan)
				cur_if->channel = other_chan;
		} else {
			cur_if->channel = chan_5g;
			other_chan = wl_ext_same_band(apsta_params, cur_if, FALSE);
			if (other_chan) {
				cur_if->channel = other_chan;
			} else {
				auto_band = WLC_BAND_5G;
				other_chan = wl_ext_autochannel(cur_if->dev, ACS_FW_BIT|ACS_DRV_BIT,
					auto_band);
				if (other_chan)
					cur_if->channel = other_chan;
			}
		}
		WL_MSG(cur_if->ifname, "[%c] move channel %d => %d\n",
			cur_if->prefix, cur_chan, cur_if->channel);
	}
}

static void
wl_ext_move_other_dfs_channel(struct wl_apsta_params *apsta_params,
	struct wl_if_info *cur_if)
{
	uint16 other_chan = 0, cur_chan = cur_if->channel;
	uint16 chan_2g = 0, chan_5g = 0;
	uint32 auto_band = WLC_BAND_2G;

	if (wl_ext_master_if(cur_if) && wl_ext_dfs_chan(cur_if->channel) &&
			!apsta_params->radar) {

		wl_ext_get_default_chan(cur_if->dev, &chan_2g, &chan_5g, TRUE);
		if (!chan_2g && !chan_5g) {
			cur_if->channel = 0;
			WL_MSG(cur_if->ifname, "[%c] no valid channel\n", cur_if->prefix);
			return;
		}

		if (apsta_params->vsdb) {
			if (chan_5g) {
				cur_if->channel = chan_5g;
				auto_band = WLC_BAND_5G;
				other_chan = wl_ext_same_band(apsta_params, cur_if, TRUE);
			} else {
				cur_if->channel = chan_2g;
				auto_band = WLC_BAND_2G;
				other_chan = wl_ext_same_band(apsta_params, cur_if, TRUE);
			}
			if (!other_chan) {
				other_chan = wl_ext_autochannel(cur_if->dev, ACS_FW_BIT|ACS_DRV_BIT,
					auto_band);
			}
			if (other_chan)
				cur_if->channel = other_chan;
		} else if (apsta_params->rsdb) {
			if (chan_2g) {
				cur_if->channel = chan_2g;
				auto_band = WLC_BAND_2G;
				other_chan = wl_ext_same_band(apsta_params, cur_if, TRUE);
				if (!other_chan) {
					other_chan = wl_ext_autochannel(cur_if->dev, ACS_FW_BIT|ACS_DRV_BIT,
						auto_band);
				}
			} else {
				cur_if->channel = 0;
			}
			if (other_chan)
				cur_if->channel = other_chan;
		} else {
			cur_if->channel = 0;
		}
		WL_MSG(cur_if->ifname, "[%c] move channel %d => %d\n",
			cur_if->prefix, cur_chan, cur_if->channel);
	}
}

static uint16
wl_ext_move_cur_channel(struct wl_apsta_params *apsta_params,
	struct wl_if_info *cur_if)
{
	struct wl_if_info *tmp_if, *target_if = NULL;
	uint16 tmp_chan, target_chan = 0;
	wl_prio_t max_prio;
	int i;

	if (apsta_params->vsdb) {
		target_chan = cur_if->channel;
		goto exit;
	}

	// find the max prio
	max_prio = cur_if->prio;
	for (i=0; i<MAX_IF_NUM; i++) {
		tmp_if = &apsta_params->if_info[i];
		if (cur_if != tmp_if && wl_get_isam_status(tmp_if, IF_READY) &&
				tmp_if->prio > max_prio) {
			tmp_chan = wl_ext_get_vsdb_chan(apsta_params, cur_if, tmp_if);
			if (tmp_chan) {
				target_if = tmp_if;
				target_chan = tmp_chan;
				max_prio = tmp_if->prio;
			}
		}
	}

	if (target_chan) {
		tmp_chan = wl_ext_get_chan(apsta_params, cur_if->dev);
		if (apsta_params->rsdb && tmp_chan &&
				wl_ext_diff_band(tmp_chan, target_chan)) {
			WL_MSG(cur_if->ifname, "[%c] keep on current channel %d\n",
				cur_if->prefix, tmp_chan);
			cur_if->channel = 0;
		} else {
			WL_MSG(cur_if->ifname, "[%c] channel=%d => %s[%c] channel=%d\n",
				cur_if->prefix, cur_if->channel,
				target_if->ifname, target_if->prefix, target_chan);
			cur_if->channel = target_chan;
		}
	}

exit:
	wl_ext_move_cur_dfs_channel(apsta_params, cur_if);

	return cur_if->channel;
}

static void
wl_ext_move_other_channel(struct wl_apsta_params *apsta_params,
	struct wl_if_info *cur_if)
{
	struct wl_if_info *tmp_if, *target_if=NULL;
	uint16 tmp_chan, target_chan = 0;
	wl_prio_t max_prio = 0, cur_prio;
	int i;

	if (apsta_params->vsdb || !cur_if->channel) {
		return;
	}

	// find the max prio, but lower than cur_if
	cur_prio = cur_if->prio;
	for (i=0; i<MAX_IF_NUM; i++) {
		tmp_if = &apsta_params->if_info[i];
		if (cur_if != tmp_if && wl_get_isam_status(tmp_if, IF_READY) &&
				tmp_if->prio >= max_prio && tmp_if->prio <= cur_prio) {
			tmp_chan = wl_ext_get_vsdb_chan(apsta_params, cur_if, tmp_if);
			if (tmp_chan) {
				target_if = tmp_if;
				target_chan = tmp_chan;
				max_prio = tmp_if->prio;
			}
		}
	}

	if (target_if) {
		WL_MSG(target_if->ifname, "channel=%d => %s channel=%d\n",
			target_chan, cur_if->ifname, cur_if->channel);
		target_if->channel = cur_if->channel;
		wl_ext_move_other_dfs_channel(apsta_params, target_if);
		if (apsta_params->csa == 0) {
			wl_ext_if_down(apsta_params, target_if);
			wl_ext_move_other_channel(apsta_params, cur_if);
			if (target_if->ifmode == IMESH_MODE) {
				wl_ext_enable_iface(target_if->dev, target_if->ifname, 0, FALSE);
			} else if (target_if->ifmode == IAP_MODE) {
				wl_ext_if_up(apsta_params, target_if, FALSE, 0);
			}
		} else {
			wl_ext_trigger_csa(apsta_params, target_if);
		}
	}

}

static bool
wl_ext_wait_other_enabling(struct wl_apsta_params *apsta_params,
	struct wl_if_info *cur_if)
{
	struct wl_if_info *tmp_if;
	bool enabling = FALSE;
	u32 timeout = 1;
	int i;

	for (i=0; i<MAX_IF_NUM; i++) {
		tmp_if = &apsta_params->if_info[i];
		if (tmp_if->dev && tmp_if->dev != cur_if->dev) {
			if (tmp_if->ifmode == ISTA_MODE)
				enabling = wl_get_isam_status(tmp_if, STA_CONNECTING);
			else if (tmp_if->ifmode == IAP_MODE || tmp_if->ifmode == IMESH_MODE)
				enabling = wl_get_isam_status(tmp_if, AP_CREATING);
			if (enabling)
				WL_MSG(cur_if->ifname, "waiting for %s[%c] enabling...\n",
					tmp_if->ifname, tmp_if->prefix);
			if (enabling && tmp_if->ifmode == ISTA_MODE) {
				timeout = wait_event_interruptible_timeout(
					apsta_params->netif_change_event,
					!wl_get_isam_status(tmp_if, STA_CONNECTING),
					msecs_to_jiffies(MAX_STA_LINK_WAIT_TIME));
			} else if (enabling &&
					(tmp_if->ifmode == IAP_MODE || tmp_if->ifmode == IMESH_MODE)) {
				timeout = wait_event_interruptible_timeout(
					apsta_params->netif_change_event,
					!wl_get_isam_status(tmp_if, AP_CREATING),
					msecs_to_jiffies(MAX_STA_LINK_WAIT_TIME));
			}
			if (tmp_if->ifmode == ISTA_MODE)
				enabling = wl_get_isam_status(tmp_if, STA_CONNECTING);
			else if (tmp_if->ifmode == IAP_MODE || tmp_if->ifmode == IMESH_MODE)
				enabling = wl_get_isam_status(tmp_if, AP_CREATING);
			if (timeout <= 0 || enabling) {
				WL_MSG(cur_if->ifname, "%s[%c] is still enabling...\n",
					tmp_if->ifname, tmp_if->prefix);
			}
		}
	}

	return enabling;
}

bool
wl_ext_iapsta_other_if_enabled(struct net_device *net)
{
	struct dhd_pub *dhd = dhd_get_pub(net);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *tmp_if;
	bool enabled = FALSE;
	int i;

	for (i=0; i<MAX_IF_NUM; i++) {
		tmp_if = &apsta_params->if_info[i];
		if (tmp_if && wl_get_isam_status(tmp_if, IF_READY)) {
			if (wl_ext_get_chan(apsta_params, tmp_if->dev)) {
				enabled = TRUE;
				break;
			}
		}
	}

	return enabled;
}

bool
wl_ext_sta_connecting(struct net_device *dev)
{
	struct wl_if_info *cur_if = NULL;
	bool connecting = FALSE;
	int eapol_status;

	cur_if = wl_get_cur_if(dev);
	if (!cur_if)
		return FALSE;

	if (cur_if->ifmode != ISTA_MODE)
		return FALSE;

	eapol_status = cur_if->eapol_status;
	if ((eapol_status >= EAPOL_STATUS_CONNECTING &&
			eapol_status < EAPOL_STATUS_CONNECTED) ||
			(eapol_status >= EAPOL_STATUS_4WAY_START &&
			eapol_status <= EAPOL_STATUS_4WAY_M4) ||
			(eapol_status >= EAPOL_STATUS_WSC_START &&
			eapol_status < EAPOL_STATUS_WSC_DONE)) {
		connecting = TRUE;
		IAPSTA_INFO(dev->name, "4-WAY handshaking %d\n", eapol_status);
	}

	return connecting;
}

#ifdef PROPTX_MAXCOUNT
int
wl_ext_get_wlfc_maxcount(struct dhd_pub *dhd, int ifidx)
{
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *tmp_if, *cur_if = NULL;
	int i, maxcount = WL_TXSTATUS_FREERUNCTR_MASK;

	if (!apsta_params->rsdb)
		return maxcount;

	for (i=0; i<MAX_IF_NUM; i++) {
		tmp_if = &apsta_params->if_info[i];
		if (tmp_if->dev && tmp_if->ifidx == ifidx) {
			cur_if = tmp_if;
			maxcount = cur_if->transit_maxcount;
		}
	}

	if (cur_if)
		IAPSTA_INFO(cur_if->ifname, "update maxcount %d\n", maxcount);
	else
		IAPSTA_INFO("wlan", "update maxcount %d for ifidx %d\n", maxcount, ifidx);
	return maxcount;
}

static void
wl_ext_update_wlfc_maxcount(struct dhd_pub *dhd)
{
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *tmp_if;
	bool band_5g = FALSE;
	uint16 chan = 0;
	int i, ret;

	if (!apsta_params->rsdb)
		return;

	for (i=0; i<MAX_IF_NUM; i++) {
		tmp_if = &apsta_params->if_info[i];
		if (tmp_if->dev) {
			chan = wl_ext_get_chan(apsta_params, tmp_if->dev);
			if (chan > CH_MAX_2G_CHANNEL) {
				tmp_if->transit_maxcount = dhd->conf->proptx_maxcnt_5g;
				ret = dhd_wlfc_update_maxcount(dhd, tmp_if->ifidx,
					tmp_if->transit_maxcount);
				if (ret == 0)
					IAPSTA_INFO(tmp_if->ifname, "updated maxcount %d\n",
						tmp_if->transit_maxcount);
				band_5g = TRUE;
			}
		}
	}

	for (i=0; i<MAX_IF_NUM; i++) {
		tmp_if = &apsta_params->if_info[i];
		if (tmp_if->dev) {
			chan = wl_ext_get_chan(apsta_params, tmp_if->dev);
			if ((chan == 0) || (chan <= CH_MAX_2G_CHANNEL && chan >= CH_MIN_2G_CHANNEL)) {
				if (chan == 0) {
					tmp_if->transit_maxcount = WL_TXSTATUS_FREERUNCTR_MASK;
				} else if (band_5g) {
					tmp_if->transit_maxcount = dhd->conf->proptx_maxcnt_2g;
				} else {
					tmp_if->transit_maxcount = dhd->conf->proptx_maxcnt_5g;
				}
				ret = dhd_wlfc_update_maxcount(dhd, tmp_if->ifidx,
					tmp_if->transit_maxcount);
				if (ret == 0)
					IAPSTA_INFO(tmp_if->ifname, "updated maxcount %d\n",
						tmp_if->transit_maxcount);
			}
		}
	}
}
#endif /* PROPTX_MAXCOUNT */

#ifdef WL_CFG80211
static struct wl_if_info *
wl_ext_get_dfs_master_if(struct wl_apsta_params *apsta_params)
{
	struct wl_if_info *cur_if = NULL;
	uint16 chan = 0;
	int i;

	for (i=0; i<MAX_IF_NUM; i++) {
		cur_if = &apsta_params->if_info[i];
		if (!cur_if->dev || !wl_ext_master_if(cur_if))
			continue;
		chan = wl_ext_get_chan(apsta_params, cur_if->dev);
		if (wl_ext_dfs_chan(chan)) {
			return cur_if;
		}
	}
	return NULL;
}

static void
wl_ext_save_master_channel(struct wl_apsta_params *apsta_params,
	uint16 post_channel)
{
	struct wl_if_info *cur_if = NULL;
	uint16 chan = 0;
	int i;

	if (apsta_params->vsdb)
		return;

	for (i=0; i<MAX_IF_NUM; i++) {
		cur_if = &apsta_params->if_info[i];
		if (!cur_if->dev || !wl_ext_master_if(cur_if))
			continue;
		chan = wl_ext_get_chan(apsta_params, cur_if->dev);
		if (chan) {
			cur_if->prev_channel = chan;
			cur_if->post_channel = post_channel;
		}
	}
}

u32
wl_ext_iapsta_update_channel(dhd_pub_t *dhd, struct net_device *dev,
	u32 channel)
{
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *cur_if = NULL;
	struct dhd_conf *conf = dhd->conf;

	cur_if = wl_get_cur_if(dev);
	if (cur_if) {
		mutex_lock(&apsta_params->usr_sync);
		wl_ext_isam_status(cur_if->dev, NULL, 0);
		cur_if->channel = channel;
		if (wl_ext_master_if(cur_if) && apsta_params->acs) {
			uint auto_band = WL_GET_BAND(channel);
			cur_if->channel = wl_ext_autochannel(cur_if->dev, apsta_params->acs,
				auto_band);
		}
		channel = wl_ext_move_cur_channel(apsta_params, cur_if);
		if (channel) {
			if (cur_if->ifmode == ISTA_MODE && wl_ext_dfs_chan(channel))
				wl_ext_save_master_channel(apsta_params, channel);
			wl_ext_move_other_channel(apsta_params, cur_if);
		}
		if (cur_if->ifmode == ISTA_MODE) {
			if (conf->war & SET_CHAN_INCONN) {
				chanspec_t fw_chspec;
			    IAPSTA_INFO(dev->name, "set channel %d\n", channel);
			    wl_ext_set_chanspec(cur_if->dev, apsta_params->ioctl_ver, channel,
			            &fw_chspec);
			}
			wl_set_isam_status(cur_if, STA_CONNECTING);
		}
		mutex_unlock(&apsta_params->usr_sync);
	}

	return channel;
}

static int
wl_ext_iftype_to_ifmode(struct net_device *net, int wl_iftype, ifmode_t *ifmode)
{	
	switch (wl_iftype) {
		case WL_IF_TYPE_STA:
			*ifmode = ISTA_MODE;
			break;
		case WL_IF_TYPE_AP:
			*ifmode = IAP_MODE;
			break;
		case WL_IF_TYPE_P2P_GO:
			*ifmode = IGO_MODE;
			break;
		case WL_IF_TYPE_P2P_GC:
			*ifmode = IGC_MODE;
			break;
		default:
			IAPSTA_ERROR(net->name, "Unknown interface wl_iftype:0x%x\n", wl_iftype);
			return BCME_ERROR;
	}
	return BCME_OK;
}

void
wl_ext_iapsta_update_iftype(struct net_device *net, int ifidx, int wl_iftype)
{
	struct dhd_pub *dhd = dhd_get_pub(net);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *cur_if = NULL;

	IAPSTA_TRACE(net->name, "ifidx=%d, wl_iftype=%d\n", ifidx, wl_iftype);

	if (ifidx < MAX_IF_NUM) {
		cur_if = &apsta_params->if_info[ifidx];
	}

	if (cur_if) {
		if (wl_iftype == WL_IF_TYPE_STA) {
			cur_if->ifmode = ISTA_MODE;
			cur_if->prio = PRIO_STA;
			cur_if->vsdb = TRUE;
			cur_if->prefix = 'S';
		} else if (wl_iftype == WL_IF_TYPE_AP && cur_if->ifmode != IMESH_MODE) {
			cur_if->ifmode = IAP_MODE;
			cur_if->prio = PRIO_AP;
			cur_if->vsdb = FALSE;
			cur_if->prefix = 'A';
		} else if (wl_iftype == WL_IF_TYPE_P2P_GO) {
			cur_if->ifmode = IGO_MODE;
			cur_if->prio = PRIO_P2P;
			cur_if->vsdb = TRUE;
			cur_if->prefix = 'P';
		} else if (wl_iftype == WL_IF_TYPE_P2P_GC) {
			cur_if->ifmode = IGC_MODE;
			cur_if->prio = PRIO_P2P;
			cur_if->vsdb = TRUE;
			cur_if->prefix = 'P';
			wl_ext_iovar_setint(cur_if->dev, "assoc_retry_max", 3);
		}
	}
}

void
wl_ext_iapsta_ifadding(struct net_device *net, int ifidx)
{
	struct dhd_pub *dhd = dhd_get_pub(net);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *cur_if = NULL;

	IAPSTA_TRACE(net->name, "ifidx=%d\n", ifidx);
	if (ifidx < MAX_IF_NUM) {
		cur_if = &apsta_params->if_info[ifidx];
		wl_set_isam_status(cur_if, IF_ADDING);
	}
}

bool
wl_ext_iapsta_iftype_enabled(struct net_device *net, int wl_iftype)
{
	struct dhd_pub *dhd = dhd_get_pub(net);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *cur_if = NULL;
	ifmode_t ifmode = 0;

	wl_ext_iftype_to_ifmode(net, wl_iftype, &ifmode);
	cur_if = wl_ext_if_enabled(apsta_params, ifmode);
	if (cur_if)
		return TRUE;

	return FALSE;
}

void
wl_ext_iapsta_enable_master_if(struct net_device *dev, bool post)
{
	dhd_pub_t *dhd = dhd_get_pub(dev);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *cur_if = NULL;
	int i;

	for (i=0; i<MAX_IF_NUM; i++) {
		cur_if = &apsta_params->if_info[i];
		if (cur_if && cur_if->post_channel) {
			if (post)
				cur_if->channel = cur_if->post_channel;
			else
				cur_if->channel = cur_if->prev_channel;
			wl_ext_if_up(apsta_params, cur_if, TRUE, 0);
			cur_if->prev_channel = 0;
			cur_if->post_channel = 0;
		}
	}
}

void
wl_ext_iapsta_restart_master(struct net_device *dev)
{
	dhd_pub_t *dhd = dhd_get_pub(dev);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *ap_if = NULL;

	if (apsta_params->radar)
		return;

	ap_if = wl_ext_get_dfs_master_if(apsta_params);
	if (ap_if) {
		uint16 chan_2g, chan_5g;
		wl_ext_if_down(apsta_params, ap_if);
		wl_ext_iapsta_restart_master(dev);
		wl_ext_get_default_chan(ap_if->dev, &chan_2g, &chan_5g, TRUE);
		if (chan_5g)
			ap_if->channel = chan_5g;
		else if (chan_2g)
			ap_if->channel = chan_2g;
		else
			ap_if->channel = 0;
		if (ap_if->channel) {
			wl_ext_move_cur_channel(apsta_params, ap_if);
			wl_ext_if_up(apsta_params, ap_if, FALSE, 0);
		}
	}
}

bool
wl_ext_iapsta_mesh_creating(struct net_device *net)
{
	struct dhd_pub *dhd = dhd_get_pub(net);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *cur_if;
	int i;

	if (apsta_params) {
		for (i=0; i<MAX_IF_NUM; i++) {
			cur_if = &apsta_params->if_info[i];
			if (cur_if->ifmode==IMESH_MODE && wl_get_isam_status(cur_if, IF_ADDING))
				return TRUE;
		}
	}
	return FALSE;
}

#ifdef STA_MGMT
static void
wl_ext_flush_sta_list(struct net_device *net, int ifidx)
{
	struct dhd_pub *dhd = dhd_get_pub(net);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	wl_sta_list_t *sta_list = &apsta_params->sta_list;
	wl_sta_info_t *node, *prev, **sta_head;
	int i = -1, tmp = 0;

	sta_head = &sta_list->sta_info;
	node = *sta_head;
	prev = node;
	for (;node;) {
		i++;
		if (node->ifidx == ifidx || ifidx == 0xFF) {
			if (node == *sta_head) {
				tmp = 1;
				*sta_head = node->next;
			} else {
				tmp = 0;
				prev->next = node->next;
			}
			IAPSTA_INFO(net->name, "Del BSSID %pM(%d)\n", &node->bssid, i);
			kfree(node);
			if (tmp == 1) {
				node = *sta_head;
				prev = node;
			} else {
				node = prev->next;
			}
			continue;
		}
		prev = node;
		node = node->next;
	}
}

bool
wl_ext_del_sta_info(struct net_device *net, u8 *bssid)
{
	struct dhd_pub *dhd = dhd_get_pub(net);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	int ifidx = dhd_net2idx(dhd->info, net);
	wl_sta_list_t *sta_list = &apsta_params->sta_list;
	wl_sta_info_t *node, *prev, **sta_head;
	int i = -1, tmp = 0;
	bool in_list = FALSE;

	sta_head = &sta_list->sta_info;
	node = *sta_head;
	prev = node;
	for (;node;) {
		i++;
		if (node->ifidx == ifidx && !memcmp(&node->bssid, bssid, ETHER_ADDR_LEN)) {
			if (node == *sta_head) {
				tmp = 1;
				*sta_head = node->next;
			} else {
				tmp = 0;
				prev->next = node->next;
			}
			IAPSTA_INFO(net->name, "Del BSSID %pM(%d)\n", &node->bssid, i);
			in_list = TRUE;
			kfree(node);
			if (tmp == 1) {
				node = *sta_head;
				prev = node;
			} else {
				node = prev->next;
			}
			continue;
		}
		prev = node;
		node = node->next;
	}

	return in_list;
}

bool
wl_ext_add_sta_info(struct net_device *net, u8 *bssid)
{
	struct dhd_pub *dhd = dhd_get_pub(net);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	int ifidx = dhd_net2idx(dhd->info, net);
	wl_sta_list_t *sta_list = &apsta_params->sta_list;
	wl_sta_info_t *node, *prev, *leaf, **sta_head;
	int i;

	sta_head = &sta_list->sta_info;
	node = *sta_head;
	prev = NULL;
	i = 0;
	for (;node;) {
		if (node->ifidx == ifidx && !memcmp(&node->bssid, bssid, ETHER_ADDR_LEN)) {
			IAPSTA_INFO(net->name, "BSSID %pM(%d) already in list\n", bssid, i);
			return FALSE;
		}
		prev = node;
		node = node->next;
		i++;
	}

	leaf = kmalloc(sizeof(wl_sta_info_t), GFP_KERNEL);
	if (!leaf) {
		IAPSTA_ERROR(net->name, "Memory alloc failure %d\n",
			(int)sizeof(wl_sta_info_t));
		return FALSE;
	}
	IAPSTA_INFO(net->name, "Add BSSID %pM(%d) in the leaf\n", bssid, i);

	leaf->next = NULL;
	leaf->ifidx = ifidx;
	memcpy(&leaf->bssid, bssid, ETHER_ADDR_LEN);

	if (!prev)
		*sta_head = leaf;
	else
		prev->next = leaf;
	return TRUE;
}
#endif /* STA_MGMT */
#endif /* WL_CFG80211 */

#ifndef WL_STATIC_IF
s32
wl_ext_add_del_bss(struct net_device *ndev, s32 bsscfg_idx,
	int iftype, s32 del, u8 *addr)
{
	s32 ret = BCME_OK;
	s32 val = 0;
	u8 ioctl_buf[WLC_IOCTL_SMLEN];
	struct {
		s32 cfg;
		s32 val;
		struct ether_addr ea;
	} bss_setbuf;

	IAPSTA_TRACE(ndev->name, "wl_iftype:%d del:%d \n", iftype, del);

	bzero(&bss_setbuf, sizeof(bss_setbuf));

	/* AP=2, STA=3, up=1, down=0, val=-1 */
	if (del) {
		val = WLC_AP_IOV_OP_DELETE;
	} else if (iftype == WL_INTERFACE_TYPE_AP) {
		/* Add/role change to AP Interface */
		IAPSTA_TRACE(ndev->name, "Adding AP Interface\n");
		val = WLC_AP_IOV_OP_MANUAL_AP_BSSCFG_CREATE;
	} else if (iftype == WL_INTERFACE_TYPE_STA) {
		/* Add/role change to STA Interface */
		IAPSTA_TRACE(ndev->name, "Adding STA Interface\n");
		val = WLC_AP_IOV_OP_MANUAL_STA_BSSCFG_CREATE;
	} else {
		IAPSTA_ERROR(ndev->name, "add_del_bss NOT supported for IFACE type:0x%x", iftype);
		return -EINVAL;
	}

	if (!del) {
		wl_ext_bss_iovar_war(ndev, &val);
	}

	bss_setbuf.cfg = htod32(bsscfg_idx);
	bss_setbuf.val = htod32(val);

	if (addr) {
		memcpy(&bss_setbuf.ea.octet, addr, ETH_ALEN);
	}

	IAPSTA_INFO(ndev->name, "wl bss %d bssidx:%d\n", val, bsscfg_idx);
	ret = wl_ext_iovar_setbuf(ndev, "bss", &bss_setbuf, sizeof(bss_setbuf),
		ioctl_buf, WLC_IOCTL_SMLEN, NULL);
	if (ret != 0)
		IAPSTA_ERROR(ndev->name, "'bss %d' failed with %d\n", val, ret);

	return ret;
}

static int
wl_ext_interface_ops(struct net_device *dev,
	struct wl_apsta_params *apsta_params, int iftype, u8 *addr)
{
	s32 ret;
	struct wl_interface_create_v2 iface;
	wl_interface_create_v3_t iface_v3;
	struct wl_interface_info_v1 *info;
	wl_interface_info_v2_t *info_v2;
	uint32 ifflags = 0;
	bool use_iface_info_v2 = false;
	u8 ioctl_buf[WLC_IOCTL_SMLEN];
	wl_wlc_version_t wlc_ver;

	/* Interface create */
	bzero(&iface, sizeof(iface));

	if (addr) {
		ifflags |= WL_INTERFACE_MAC_USE;
	}

	ret = wldev_iovar_getbuf(dev, "wlc_ver", NULL, 0,
		&wlc_ver, sizeof(wl_wlc_version_t), NULL);
	if ((ret == BCME_OK) && (wlc_ver.wlc_ver_major >= 5)) {
		ret = wldev_iovar_getbuf(dev, "interface_create",
			&iface, sizeof(struct wl_interface_create_v2),
			ioctl_buf, sizeof(ioctl_buf), NULL);
		if ((ret == BCME_OK) && (*((uint32 *)ioctl_buf) == WL_INTERFACE_CREATE_VER_3)) {
			use_iface_info_v2 = true;
			bzero(&iface_v3, sizeof(wl_interface_create_v3_t));
			iface_v3.ver = WL_INTERFACE_CREATE_VER_3;
			iface_v3.iftype = iftype;
			iface_v3.flags = ifflags;
			if (addr) {
				memcpy(&iface_v3.mac_addr.octet, addr, ETH_ALEN);
			}
			ret = wl_ext_iovar_getbuf(dev, "interface_create",
				&iface_v3, sizeof(wl_interface_create_v3_t),
				ioctl_buf, sizeof(ioctl_buf), NULL);
			if (unlikely(ret)) {
				IAPSTA_ERROR(dev->name, "Interface v3 create failed!! ret %d\n", ret);
				return ret;
			}
		}
	}

	/* success case */
	if (use_iface_info_v2 == true) {
		info_v2 = (wl_interface_info_v2_t *)ioctl_buf;
		ret = info_v2->bsscfgidx;
	} else {
		/* Use v1 struct */
		iface.ver = WL_INTERFACE_CREATE_VER_2;
		iface.iftype = iftype;
		iface.flags = iftype | ifflags;
		if (addr) {
			memcpy(&iface.mac_addr.octet, addr, ETH_ALEN);
		}
		ret = wldev_iovar_getbuf(dev, "interface_create",
			&iface, sizeof(struct wl_interface_create_v2),
			ioctl_buf, sizeof(ioctl_buf), NULL);
		if (ret == BCME_OK) {
			info = (struct wl_interface_info_v1 *)ioctl_buf;
			ret = info->bsscfgidx;
		}
	}

	IAPSTA_INFO(dev->name, "wl interface create success!! bssidx:%d \n", ret);
	return ret;
}

static void
wl_ext_wait_netif_change(struct wl_apsta_params *apsta_params,
	struct wl_if_info *cur_if)
{
	rtnl_unlock();
	wait_event_interruptible_timeout(apsta_params->netif_change_event,
		wl_get_isam_status(cur_if, IF_READY),
		msecs_to_jiffies(MAX_AP_LINK_WAIT_TIME));
	rtnl_lock();
}

static void
wl_ext_interface_create(struct net_device *dev, struct wl_apsta_params *apsta_params,
	struct wl_if_info *cur_if, int iftype, u8 *addr)
{
	s32 ret;

	wl_set_isam_status(cur_if, IF_ADDING);
	ret = wl_ext_interface_ops(dev, apsta_params, iftype, addr);
	if (ret == BCME_UNSUPPORTED) {
		wl_ext_add_del_bss(dev, 1, iftype, 0, addr);
	}
	wl_ext_wait_netif_change(apsta_params, cur_if);
}

static void
wl_ext_iapsta_intf_add(struct net_device *dev, struct wl_apsta_params *apsta_params)
{
	struct dhd_pub *dhd;
	apstamode_t apstamode = apsta_params->apstamode;
	struct wl_if_info *cur_if;
	s8 iovar_buf[WLC_IOCTL_SMLEN];
	wl_p2p_if_t ifreq;
	struct ether_addr mac_addr;

	dhd = dhd_get_pub(dev);
	bzero(&mac_addr, sizeof(mac_addr));

	if (apstamode == ISTAAP_MODE) {
		cur_if = &apsta_params->if_info[IF_VIF];
		wl_ext_interface_create(dev, apsta_params, cur_if, WL_INTERFACE_TYPE_AP, NULL);
	}
	else if (apstamode == ISTAGO_MODE) {
		bzero(&ifreq, sizeof(wl_p2p_if_t));
		ifreq.type = htod32(WL_P2P_IF_GO);
		cur_if = &apsta_params->if_info[IF_VIF];
		wl_set_isam_status(cur_if, IF_ADDING);
		wl_ext_iovar_setbuf(dev, "p2p_ifadd", &ifreq, sizeof(ifreq),
			iovar_buf, WLC_IOCTL_SMLEN, NULL);
		wl_ext_wait_netif_change(apsta_params, cur_if);
	}
	else if (apstamode == ISTASTA_MODE) {
		cur_if = &apsta_params->if_info[IF_VIF];
		memcpy(&mac_addr, dev->dev_addr, ETHER_ADDR_LEN);
		mac_addr.octet[0] |= 0x02;
		wl_ext_interface_create(dev, apsta_params, cur_if, WL_INTERFACE_TYPE_STA,
			(u8*)&mac_addr);
	}
	else if (apstamode == IDUALAP_MODE) {
		cur_if = &apsta_params->if_info[IF_VIF];
		wl_ext_interface_create(dev, apsta_params, cur_if, WL_INTERFACE_TYPE_AP, NULL);
	}
	else if (apstamode == ISTAAPAP_MODE) {
		u8 rand_bytes[2] = {0, };
		get_random_bytes(&rand_bytes, sizeof(rand_bytes));
		cur_if = &apsta_params->if_info[IF_VIF];
		memcpy(&mac_addr, dev->dev_addr, ETHER_ADDR_LEN);
		mac_addr.octet[0] |= 0x02;
		mac_addr.octet[5] += 0x01;
		memcpy(&mac_addr.octet[3], rand_bytes, sizeof(rand_bytes));
		wl_ext_interface_create(dev, apsta_params, cur_if, WL_INTERFACE_TYPE_AP,
			(u8*)&mac_addr);
		cur_if = &apsta_params->if_info[IF_VIF2];
		memcpy(&mac_addr, dev->dev_addr, ETHER_ADDR_LEN);
		mac_addr.octet[0] |= 0x02;
		mac_addr.octet[5] += 0x02;
		memcpy(&mac_addr.octet[3], rand_bytes, sizeof(rand_bytes));
		wl_ext_interface_create(dev, apsta_params, cur_if, WL_INTERFACE_TYPE_AP,
			(u8*)&mac_addr);
	}
#ifdef WLMESH
	else if (apstamode == ISTAMESH_MODE) {
		cur_if = &apsta_params->if_info[IF_VIF];
		wl_ext_interface_create(dev, apsta_params, cur_if, WL_INTERFACE_TYPE_STA, NULL);
	}
	else if (apstamode == IMESHAP_MODE) {
		cur_if = &apsta_params->if_info[IF_VIF];
		wl_ext_interface_create(dev, apsta_params, cur_if, WL_INTERFACE_TYPE_AP, NULL);
	}
	else if (apstamode == ISTAAPMESH_MODE) {
		cur_if = &apsta_params->if_info[IF_VIF];
		wl_ext_interface_create(dev, apsta_params, cur_if, WL_INTERFACE_TYPE_AP, NULL);
		cur_if = &apsta_params->if_info[IF_VIF2];
		wl_ext_interface_create(dev, apsta_params, cur_if, WL_INTERFACE_TYPE_STA, NULL);
	}
	else if (apstamode == IMESHAPAP_MODE) {
		cur_if = &apsta_params->if_info[IF_VIF];
		wl_ext_interface_create(dev, apsta_params, cur_if, WL_INTERFACE_TYPE_AP, NULL);
		cur_if = &apsta_params->if_info[IF_VIF2];
		wl_ext_interface_create(dev, apsta_params, cur_if, WL_INTERFACE_TYPE_AP, NULL);
	}
#endif /* WLMESH */

}
#endif /* WL_STATIC_IF */

void
wl_ext_update_eapol_status(dhd_pub_t *dhd, int ifidx, uint eapol_status)
{
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *cur_if = NULL;

	if (ifidx < MAX_IF_NUM) {
		cur_if = &apsta_params->if_info[ifidx];
		cur_if->eapol_status = eapol_status;
	}
}

#if defined(WL_CFG80211) && defined(SCAN_SUPPRESS)
void
wl_ext_populate_scan_channel(dhd_pub_t *dhd, u16 *channel_list,
	u32 channel, u32 n_channels)
{
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	u32 j = 0;
	u32 chanspec = 0;

	if (!dhd_conf_match_channel(dhd, channel))
		return;

	chanspec = WL_CHANSPEC_BW_20;
	if (chanspec == INVCHANSPEC) {
		WL_ERR(("Invalid chanspec! Skipping channel\n"));
		return;
	}

	if (channel <= CH_MAX_2G_CHANNEL) {
		chanspec |= WL_CHANSPEC_BAND_2G;
	} else {
		chanspec |= WL_CHANSPEC_BAND_5G;
	}
	channel_list[j] = channel;
	channel_list[j] &= WL_CHANSPEC_CHAN_MASK;
	channel_list[j] |= chanspec;
	IAPSTA_INFO("wlan", "Chan : %d, Channel spec: %x \n", channel, channel_list[j]);
	channel_list[j] = wl_ext_chspec_host_to_driver(apsta_params->ioctl_ver, channel_list[j]);
}

static void
wl_ext_scan_suppress_prep(struct net_device *dev, void *scan_params, bool scan_v2)
{
	wl_scan_params_t *params = NULL;
	wl_scan_params_v2_t *params_v2 = NULL;

	if (!scan_params) {
		IAPSTA_ERROR(dev->name, "NULL scan_params\n");
		return;
	}
	IAPSTA_INFO(dev->name, "Enter\n");

	if (scan_v2) {
		params_v2 = (wl_scan_params_v2_t *)scan_params;
	} else {
		params = (wl_scan_params_t *)scan_params;
	}

	if (params_v2) {
		/* scan params ver2 */
		params_v2->nprobes = 1;
		params_v2->active_time = 20;
		params_v2->home_time = 150;
	} else {
		/* scan params ver 1 */
		if (!params) {
			ASSERT(0);
			return;
		}
		params->nprobes = 1;
		params->active_time = 20;
		params->home_time = 150;
	}

	return;
}

uint16
wl_ext_scan_suppress(struct net_device *dev, void *scan_params, bool scan_v2)
{
	struct dhd_pub *dhd = dhd_get_pub(dev);
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct dhd_conf *conf = dhd->conf;
	struct wl_if_info *tmp_if;
	uint16 chan = 0;
	int i;

	if (apsta_params->tput_sum >= conf->scan_tput_thresh) {
		IAPSTA_INFO(dev->name, "scan_intput=0x%x, "\
			"tput %dMbps >= %dMbps (busy cnt/thresh %d/%d)\n",
			conf->scan_intput, apsta_params->tput_sum, conf->scan_tput_thresh,
			apsta_params->scan_busy_cnt, conf->scan_busy_thresh);
		if ((conf->scan_intput & SCAN_CURCHAN_INTPUT) && apsta_params->scan_busy_cnt) {
			for (i=0; i<MAX_IF_NUM; i++) {
				tmp_if = &apsta_params->if_info[i];
				if (tmp_if->dev) {
					chan = wl_ext_get_chan(apsta_params, tmp_if->dev);
					if (chan)
						break;
				}
			}
		}
		if (conf->scan_intput & SCAN_LIGHT_INTPUT)
			wl_ext_scan_suppress_prep(dev, scan_params, scan_v2);
		apsta_params->scan_busy_cnt++;
		if (apsta_params->scan_busy_cnt >= conf->scan_busy_thresh)
			apsta_params->scan_busy_cnt = 0;
	}

	return chan;
}

static int
wl_ext_scan_busy(dhd_pub_t *dhd, struct wl_if_info *cur_if)
{
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct dhd_conf *conf = dhd->conf;
	struct osl_timespec cur_ts;
	uint32 diff_ms;
	int ret = 0;

	if (apsta_params->tput_sum >= conf->scan_tput_thresh) {
		if (apsta_params->scan_busy_cnt == 1)
			osl_do_gettimeofday(&apsta_params->scan_busy_ts);
		else if (apsta_params->scan_busy_cnt >= 2) {
			osl_do_gettimeofday(&cur_ts);
			diff_ms = osl_do_gettimediff(&cur_ts, &apsta_params->scan_busy_ts)/1000;
			if ((diff_ms/1000) >= conf->scan_busy_tmo) {
				apsta_params->scan_busy_cnt = 0;
				IAPSTA_INFO(cur_if->dev->name, "reset scan_busy_cnt\n");
			}
		}
		if (apsta_params->scan_busy_cnt >= 1) {
			if (conf->scan_intput & NO_SCAN_INTPUT) {
				IAPSTA_INFO(cur_if->dev->name,
					"scan suppressed tput %dMbps >= %dMbps(busy cnt/thresh %d/%d)\n",
					apsta_params->tput_sum, conf->scan_tput_thresh,
					apsta_params->scan_busy_cnt, conf->scan_busy_thresh);
				apsta_params->scan_busy_cnt++;
				if (apsta_params->scan_busy_cnt >= conf->scan_busy_thresh)
					apsta_params->scan_busy_cnt = 0;
				return -EBUSY;
			}
		}
	}
	else {
		apsta_params->scan_busy_cnt = 0;
	}

	return ret;
}
#endif /* SCAN_SUPPRESS */

#ifdef SET_CARRIER
static void
wl_ext_net_setcarrier(struct wl_if_info *cur_if, bool on, bool force)
{
	IAPSTA_TRACE(cur_if->ifname, "carrier=%d\n", on);
	if (on) {
		if (!netif_carrier_ok(cur_if->dev) || force)
			netif_carrier_on(cur_if->dev);
	} else {
		if (netif_carrier_ok(cur_if->dev) || force)
			netif_carrier_off(cur_if->dev);
	}
}
#endif /* SET_CARRIER */

void
wl_iapsta_wait_event_complete(struct dhd_pub *dhd)
{
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *cur_if;
	int i;

	for (i=0; i<MAX_IF_NUM; i++) {
		cur_if = &apsta_params->if_info[i];
		if (cur_if->dev && cur_if->ifmode == ISTA_MODE) {
			wl_ext_wait_event_complete(dhd, cur_if->ifidx);
		}
	}
}

int
wl_iapsta_suspend_resume_ap(dhd_pub_t *dhd, struct wl_if_info *cur_if,
	int suspend)
{
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	uint insuspend = 0;

	insuspend = dhd_conf_get_insuspend(dhd, ALL_IN_SUSPEND);
	if (insuspend)
		WL_MSG(cur_if->ifname, "suspend %d\n", suspend);

	if (suspend) {
		if (insuspend & AP_DOWN_IN_SUSPEND) {
			cur_if->channel = wl_ext_get_chan(apsta_params, cur_if->dev);
			if (cur_if->channel)
				wl_ext_if_down(apsta_params, cur_if);
		}
	} else {
		if (insuspend & AP_DOWN_IN_SUSPEND) {
			if (cur_if->channel)
				wl_ext_if_up(apsta_params, cur_if, FALSE, 0);
		}
	}

	return 0;
}

int
wl_iapsta_suspend_resume(dhd_pub_t *dhd, int suspend)
{
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct wl_if_info *cur_if;
	int i;

#ifdef TPUT_MONITOR
	if (suspend)
		wl_ext_mod_timer(&apsta_params->monitor_timer, 0, 0);
#endif /* TPUT_MONITOR */

	for (i=0; i<MAX_IF_NUM; i++) {
		cur_if = &apsta_params->if_info[i];
		if (cur_if->dev && cur_if->ifmode == ISTA_MODE) {
			if (!suspend)
				memcpy(&dhd->conf->bssid_insuspend, &cur_if->bssid, ETHER_ADDR_LEN);
			dhd_conf_suspend_resume_sta(dhd, cur_if->ifidx, suspend);
			if (suspend)
				memcpy(&cur_if->bssid, &dhd->conf->bssid_insuspend, ETHER_ADDR_LEN);
		}
		else if (cur_if->dev && cur_if->ifmode == IAP_MODE) {
			wl_iapsta_suspend_resume_ap(dhd, cur_if, suspend);
		}
	}

#ifdef TPUT_MONITOR
	if (!suspend)
		wl_ext_mod_timer(&apsta_params->monitor_timer, 0, dhd->conf->tput_monitor_ms);
#endif /* TPUT_MONITOR */

	return 0;
}

static int
wl_ext_in4way_sync_sta(dhd_pub_t *dhd, struct wl_if_info *cur_if,
	uint action, enum wl_ext_status status, void *context)
{
	struct wl_apsta_params *apsta_params = dhd->iapsta_params;
	struct dhd_conf *conf = dhd->conf;
	struct net_device *dev = cur_if->dev;
	struct osl_timespec cur_ts, *sta_disc_ts = &apsta_params->sta_disc_ts;
	struct osl_timespec *sta_conn_ts = &apsta_params->sta_conn_ts;
	uint32 diff_ms = 0;
	int ret = 0, err, cur_eapol_status;
	int max_wait_time, max_wait_cnt;
	int suppressed = 0, wpa_auth = 0;
	bool connecting = FALSE;
	wl_event_msg_t *e = (wl_event_msg_t *)context;
#ifdef WL_CFG80211
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);
#endif /* WL_CFG80211 */

	action = action & conf->in4way;
#ifdef WL_CFG80211
	if ((conf->in4way & STA_FAKE_SCAN_IN_CONNECT) && (action & STA_NO_SCAN_IN4WAY))
		action &= ~(STA_NO_SCAN_IN4WAY);
#endif /* WL_CFG80211 */
	cur_eapol_status = cur_if->eapol_status;
	IAPSTA_TRACE(dev->name, "status=%d, action=0x%x, in4way=0x%x\n",
		status, action, conf->in4way);

	connecting = wl_ext_sta_connecting(cur_if->dev);

	switch (status) {
		case WL_EXT_STATUS_SCAN:
			wldev_ioctl(dev, WLC_GET_SCANSUPPRESS, &suppressed, sizeof(int), false);
			if (suppressed) {
				IAPSTA_ERROR(dev->name, "scan suppressed\n");
				ret = -EBUSY;
				break;
			}
#ifdef WL_ESCAN
			if (dhd->escan->escan_state == ESCAN_STATE_SCANING) {
				IAPSTA_ERROR(dev->name, "escan busy\n");
				ret = -EBUSY;
				break;
			}
#endif /* WL_ESCAN */
#ifdef WL_CFG80211
			if (wl_get_drv_status_all(cfg, SCANNING) && cfg->scan_request) {
				IAPSTA_ERROR(dev->name, "cfg80211 scanning\n");
				ret = -EAGAIN;
				break;
			}
#endif /* WL_CFG80211 */
#if defined(WL_CFG80211) && defined(SCAN_SUPPRESS)
			ret = wl_ext_scan_busy(dhd, cur_if);
			if (ret) {
				IAPSTA_ERROR(dev->name, "no scan intput\n");
				break;
			}
#endif /* WL_CFG80211 && SCAN_SUPPRESS */
			if (action & STA_NO_SCAN_IN4WAY) {
				osl_do_gettimeofday(&cur_ts);
				diff_ms = osl_do_gettimediff(&cur_ts, sta_conn_ts)/1000;
				if (connecting && diff_ms <= STA_CONNECT_TIMEOUT) {
					IAPSTA_ERROR(dev->name, "connecting... %d\n", cur_eapol_status);
					ret = -EBUSY;
					break;
				}
			}
			break;
#ifdef WL_CFG80211
		case WL_EXT_STATUS_SCANNING:
			if (action & STA_FAKE_SCAN_IN_CONNECT) {
				osl_do_gettimeofday(&cur_ts);
				diff_ms = osl_do_gettimediff(&cur_ts, sta_conn_ts)/1000;
				if (wl_get_drv_status(cfg, CONNECTING, dev) ||
						(connecting && diff_ms <= STA_CONNECT_TIMEOUT)) {
					unsigned long flags = 0;
					spin_lock_irqsave(&dhd->up_lock, flags);
					if (dhd->up) {
						wl_event_msg_t msg;
						bzero(&msg, sizeof(wl_event_msg_t));
						msg.event_type = hton32(WLC_E_ESCAN_RESULT);
						msg.status = hton32(WLC_E_STATUS_SUCCESS);
						WL_MSG(dev->name, "FAKE SCAN\n");
						wl_cfg80211_event(dev, &msg, NULL);
						ret = -EBUSY;
					}
					spin_unlock_irqrestore(&dhd->up_lock, flags);
				}
			}
			break;
		case WL_EXT_STATUS_SCAN_COMPLETE:
			osl_do_gettimeofday(&cur_ts);
			diff_ms = osl_do_gettimediff(&cur_ts, sta_disc_ts)/1000;
			if ((conf->war & FW_REINIT_EMPTY_SCAN) && diff_ms < 10000 &&
					apsta_params->linkdown_reason == WLC_E_LINK_BCN_LOSS &&
					cfg->bss_list->count == 0) {
				IAPSTA_INFO(dev->name, "wl reinit for empty scan\n");
				wl_ext_ioctl(dev, WLC_INIT, NULL, 0, 1);
				apsta_params->linkdown_reason = 0;
			}
			break;
#endif /* WL_CFG80211 */
 		case WL_EXT_STATUS_DISCONNECTING:
			wl_ext_mod_timer(&cur_if->connect_timer, 0, 0);
#ifdef SCAN_SUPPRESS
			apsta_params->scan_busy_cnt = 0;
#endif /* SCAN_SUPPRESS */
			if (cur_eapol_status == EAPOL_STATUS_CONNECTING) {
				IAPSTA_ERROR(dev->name, "OPEN failed at %d\n", cur_eapol_status);
				cur_if->eapol_status = EAPOL_STATUS_NONE;
			} else if (cur_eapol_status >= EAPOL_STATUS_4WAY_START &&
					cur_eapol_status < EAPOL_STATUS_4WAY_DONE) {
				IAPSTA_ERROR(dev->name, "WPA failed at %d\n", cur_eapol_status);
				cur_if->eapol_status = EAPOL_STATUS_NONE;
			} else if (cur_eapol_status >= EAPOL_STATUS_WSC_START &&
					cur_eapol_status < EAPOL_STATUS_WSC_DONE) {
				IAPSTA_ERROR(dev->name, "WPS failed at %d\n", cur_eapol_status);
				cur_if->eapol_status = EAPOL_STATUS_NONE;
			}
			if (action & STA_NO_BTC_IN4WAY) {
				if (cur_if->ifidx == 0 && apsta_params->sta_btc_mode) {
					IAPSTA_INFO(dev->name, "status=%d, restore btc_mode %d\n",
						status, apsta_params->sta_btc_mode);
					wldev_iovar_setint(dev, "btc_mode", apsta_params->sta_btc_mode);
					apsta_params->sta_btc_mode = 0;
				}
			}
			if (action & STA_WAIT_DISCONNECTED) {
				max_wait_time = 200;
				max_wait_cnt = 20;
				if (cur_eapol_status > EAPOL_STATUS_NONE)
					osl_do_gettimeofday(sta_disc_ts);
				osl_do_gettimeofday(&cur_ts);
				diff_ms = osl_do_gettimediff(&cur_ts, sta_disc_ts)/1000;
				while (diff_ms < max_wait_time && max_wait_cnt) {
					IAPSTA_INFO(dev->name, "status=%d, max_wait_cnt=%d waiting...\n",
						status, max_wait_cnt);
					mutex_unlock(&apsta_params->in4way_sync);
					OSL_SLEEP(50);
					mutex_lock(&apsta_params->in4way_sync);
					max_wait_cnt--;
					osl_do_gettimeofday(&cur_ts);
					diff_ms = osl_do_gettimediff(&cur_ts, sta_disc_ts)/1000;
				}
				wake_up_interruptible(&conf->event_complete);
			}
			break;
		case WL_EXT_STATUS_CONNECTING:
			wl_ext_mod_timer(&cur_if->connect_timer, 0, STA_CONNECT_TIMEOUT);
			osl_do_gettimeofday(sta_conn_ts);
			wl_ext_iovar_getint(dev, "wpa_auth", &wpa_auth);
			if ((wpa_auth >= WPA_AUTH_UNSPECIFIED) && !(wpa_auth & WPA2_AUTH_FT))
				cur_if->eapol_status = EAPOL_STATUS_4WAY_START;
			else
				cur_if->eapol_status = EAPOL_STATUS_CONNECTING;
			if (action & STA_NO_BTC_IN4WAY) {
				if (cur_if->ifidx == 0) {
					err = wldev_iovar_getint(dev, "btc_mode", &apsta_params->sta_btc_mode);
					if (!err && apsta_params->sta_btc_mode) {
						IAPSTA_INFO(dev->name, "status=%d, disable current btc_mode %d\n",
							status, apsta_params->sta_btc_mode);
						wldev_iovar_setint(dev, "btc_mode", 0);
					}
				}
			}
#ifdef WL_CLIENT_SAE
			if (action & STA_START_AUTH_DELAY) {
				struct wireless_dev *wdev = dev->ieee80211_ptr;
				max_wait_cnt = 5;
				while (max_wait_cnt) {
					if (wdev->conn_owner_nlportid)
						break;
					IAPSTA_INFO(dev->name, "status=%d, max_wait_cnt=%d, waiting...\n",
						status, max_wait_cnt);
					mutex_unlock(&apsta_params->in4way_sync);
					OSL_SLEEP(10);
					mutex_lock(&apsta_params->in4way_sync);
					max_wait_cnt--;
				}
				if (max_wait_cnt == 0) {
					wl_ext_ioctl(dev, WLC_DISASSOC, NULL, 0, 1);
					ret = -1;
					break;
				}
			}
#endif /* WL_CLIENT_SAE */
			break;
		case WL_EXT_STATUS_CONNECTED:
			wl_ext_mod_timer(&cur_if->connect_timer, 0, 0);
			if ((wpa_auth >= WPA_AUTH_UNSPECIFIED) && !(wpa_auth & WPA2_AUTH_FT)) {
				// do not need to set eapol_status here
			} else {
				cur_if->eapol_status = EAPOL_STATUS_CONNECTED;
			}
			if (cur_if->ifmode == ISTA_MODE) {
				dhd_conf_set_wme(dhd, cur_if->ifidx, 0);
				wake_up_interruptible(&conf->event_complete);
			}
			else if (cur_if->ifmode == IGC_MODE) {
				dhd_conf_set_mchan_bw(dhd, WL_P2P_IF_CLIENT, -1);
			}
			break;
		case WL_EXT_STATUS_DISCONNECTED:
#ifdef SCAN_SUPPRESS
			apsta_params->scan_busy_cnt = 0;
#endif /* SCAN_SUPPRESS */
			if (e && ntoh32(e->event_type) == WLC_E_LINK &&
					!(ntoh16(e->flags) & WLC_EVENT_MSG_LINK)) {
				apsta_params->linkdown_reason = ntoh32(e->reason);
			}
			wl_ext_mod_timer(&cur_if->connect_timer, 0, 0);
			if (cur_eapol_status == EAPOL_STATUS_CONNECTING) {
				IAPSTA_ERROR(dev->name, "OPEN failed at %d\n", cur_eapol_status);
			} else if (cur_eapol_status >= EAPOL_STATUS_4WAY_START &&
					cur_eapol_status < EAPOL_STATUS_4WAY_DONE) {
				IAPSTA_ERROR(dev->name, "WPA failed at %d\n", cur_eapol_status);
			} else if (cur_eapol_status >= EAPOL_STATUS_WSC_START &&
					cur_eapol_status < EAPOL_STATUS_WSC_DONE) {
				IAPSTA_ERROR(dev->name, "WPS failed at %d\n", cur_eapol_status);
			}
			cur_if->eapol_status = EAPOL_STATUS_NONE;
			if (action & STA_NO_BTC_IN4WAY) {
				if (cur_if->ifidx == 0 && apsta_params->sta_btc_mode) {
					IAPSTA_INFO(dev->name, "status=%d, restore btc_mode %d\n",
						status, apsta_params->sta_btc_mode);
					wldev_iovar_setint(dev, "btc_mode", apsta_params->sta_btc_mode);
					apsta_params->sta_btc_mode = 0;
				}
			}
			osl_do_gettimeofday(sta_disc_ts);
			wake_up_interruptible(&conf->event_complete);
			break;
		case WL_EXT_STATUS_ADD_KEY:
			cur_if->eapol_status = EAPOL_STATUS_4WAY_DONE;
			if (action & STA_NO_BTC_IN4WAY) {
				if (cur_if->ifidx == 0 && apsta_params->sta_btc_mode) {
					IAPSTA_INFO(dev->name, "status=%d, restore btc_mode %d\n",
						status, apsta_params->sta_btc_mode);
					wldev_iovar_setint(dev, "btc_mode", apsta_params->sta_btc_mode);
					apsta_params->sta_btc_mode = 0;
				}
			}
			wake_up_interruptible(&conf->event_complete);
			IAPSTA_INFO(dev->name, "WPA 4-WAY complete %d\n", cur_eapol_status);
			break;
		default:
			IAPSTA_INFO(dev->name, "Unknown action=0x%x, status=%d\n", action, status);
	}

	return ret;
}
