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
