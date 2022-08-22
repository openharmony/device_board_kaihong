/*
 * Broadcom Dongle Host Driver (DHD)
 * Prefered Network Offload and Wi-Fi Location Service(WLS) code.
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
 * $Id: dhd_pno.c 812762 2019-04-02 09:36:26Z $
 */

#if defined(GSCAN_SUPPORT) && !defined(PNO_SUPPORT)
#error "GSCAN needs PNO to be enabled!"
#endif // endif

#ifdef PNO_SUPPORT
#include <typedefs.h>
#include <osl.h>

#include <epivers.h>
#include <bcmutils.h>

#include <bcmendian.h>
#include <linuxver.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/sort.h>
#include <dngl_stats.h>
#include <wlioctl.h>

#include <bcmevent.h>
#include <dhd.h>
#include <dhd_pno.h>
#include <dhd_dbg.h>
#ifdef GSCAN_SUPPORT
#include <linux/gcd.h>
#endif /* GSCAN_SUPPORT */
#ifdef WL_CFG80211
#include <wl_cfg80211.h>
#endif /* WL_CFG80211 */

#ifdef __BIG_ENDIAN
#include <bcmendian.h>
#define htod32(i) (bcmswap32(i))
#define htod16(i) (bcmswap16(i))
#define dtoh32(i) (bcmswap32(i))
#define dtoh16(i) (bcmswap16(i))
#define htodchanspec(i) htod16(i)
#define dtohchanspec(i) dtoh16(i)
#else
#define htod32(i) (i)
#define htod16(i) (i)
#define dtoh32(i) (i)
#define dtoh16(i) (i)
#define htodchanspec(i) (i)
#define dtohchanspec(i) (i)
#endif /* IL_BIGENDINA */

#define NULL_CHECK(p, s, err)  \
			do { \
				if (!(p)) { \
					printf("NULL POINTER (%s) : %s\n", __FUNCTION__, (s)); \
					err = BCME_ERROR; \
					return err; \
				} \
			} while (0)
#define PNO_GET_PNOSTATE(dhd) ((dhd_pno_status_info_t *)dhd->pno_state)

#define PNO_BESTNET_LEN		WLC_IOCTL_MEDLEN

#define PNO_ON 1
#define PNO_OFF 0
#define CHANNEL_2G_MIN 1
#define CHANNEL_2G_MAX 14
#define CHANNEL_5G_MIN 34
#define CHANNEL_5G_MAX 165
#define IS_2G_CHANNEL(ch) ((ch >= CHANNEL_2G_MIN) && \
	(ch <= CHANNEL_2G_MAX))
#define IS_5G_CHANNEL(ch) ((ch >= CHANNEL_5G_MIN) && \
	(ch <= CHANNEL_5G_MAX))
#define MAX_NODE_CNT 5
#define WLS_SUPPORTED(pno_state) (pno_state->wls_supported == TRUE)
#define TIME_DIFF(timestamp1, timestamp2) (abs((uint32)(timestamp1/1000)  \
						- (uint32)(timestamp2/1000)))
#define TIME_DIFF_MS(timestamp1, timestamp2) (abs((uint32)(timestamp1)  \
						- (uint32)(timestamp2)))
#define TIMESPEC_TO_US(ts)  (((uint64)(ts).tv_sec * USEC_PER_SEC) + \
							(ts).tv_nsec / NSEC_PER_USEC)

#define ENTRY_OVERHEAD strlen("bssid=\nssid=\nfreq=\nlevel=\nage=\ndist=\ndistSd=\n====")
#define TIME_MIN_DIFF 5

#define EVENT_DATABUF_MAXLEN	(512 - sizeof(bcm_event_t))
#define EVENT_MAX_NETCNT_V1 \
	((EVENT_DATABUF_MAXLEN - sizeof(wl_pfn_scanresults_v1_t)) \
	/ sizeof(wl_pfn_net_info_v1_t) + 1)
#define EVENT_MAX_NETCNT_V2 \
	((EVENT_DATABUF_MAXLEN - sizeof(wl_pfn_scanresults_v2_t)) \
	/ sizeof(wl_pfn_net_info_v2_t) + 1)

#ifdef GSCAN_SUPPORT
static int _dhd_pno_flush_ssid(dhd_pub_t *dhd);
static wl_pfn_gscan_ch_bucket_cfg_t *
dhd_pno_gscan_create_channel_list(dhd_pub_t *dhd, dhd_pno_status_info_t *pno_state,
	uint16 *chan_list, uint32 *num_buckets, uint32 *num_buckets_to_fw);
#endif /* GSCAN_SUPPORT */

static int dhd_pno_set_legacy_pno(dhd_pub_t *dhd, uint16  scan_fr, int pno_repeat,
	int pno_freq_expo_max, uint16 *channel_list, int nchan);

static inline bool
is_dfs(dhd_pub_t *dhd, uint16 channel)
{
	u32 ch;
	s32 err;
	u8 buf[32];

	ch = wl_ch_host_to_driver(channel);
	err = dhd_iovar(dhd, 0, "per_chan_info", (char *)&ch,
		sizeof(u32), buf, sizeof(buf), FALSE);
	if (unlikely(err)) {
		DHD_ERROR(("get per chan info failed:%d\n", err));
		return FALSE;
	}
	/* Check the channel flags returned by fw */
	if (*((u32 *)buf) & WL_CHAN_PASSIVE) {
		return TRUE;
	}
	return FALSE;
}

int
dhd_pno_clean(dhd_pub_t *dhd)
{
	int pfn = 0;
	int err;
	dhd_pno_status_info_t *_pno_state;
	NULL_CHECK(dhd, "dhd is NULL", err);
	NULL_CHECK(dhd->pno_state, "pno_state is NULL", err);
	_pno_state = PNO_GET_PNOSTATE(dhd);
	DHD_PNO(("%s enter\n", __FUNCTION__));
	/* Disable PNO */
	err = dhd_iovar(dhd, 0, "pfn", (char *)&pfn, sizeof(pfn), NULL, 0, TRUE);
	if (err < 0) {
		DHD_ERROR(("%s : failed to execute pfn(error : %d)\n",
			__FUNCTION__, err));
		goto exit;
	}
	_pno_state->pno_status = DHD_PNO_DISABLED;
	err = dhd_iovar(dhd, 0, "pfnclear", NULL, 0, NULL, 0, TRUE);
	if (err < 0) {
		DHD_ERROR(("%s : failed to execute pfnclear(error : %d)\n",
			__FUNCTION__, err));
	}
exit:
	return err;
}

bool
dhd_is_pno_supported(dhd_pub_t *dhd)
{
	dhd_pno_status_info_t *_pno_state;

	if (!dhd || !dhd->pno_state) {
		DHD_ERROR(("NULL POINTER : %s\n",
			__FUNCTION__));
		return FALSE;
	}
	_pno_state = PNO_GET_PNOSTATE(dhd);
	return WLS_SUPPORTED(_pno_state);
}

bool
dhd_is_legacy_pno_enabled(dhd_pub_t *dhd)
{
	dhd_pno_status_info_t *_pno_state;

	if (!dhd || !dhd->pno_state) {
		DHD_ERROR(("NULL POINTER : %s\n",
			__FUNCTION__));
		return FALSE;
	}
	_pno_state = PNO_GET_PNOSTATE(dhd);
	return ((_pno_state->pno_mode & DHD_PNO_LEGACY_MODE) != 0);
}

#ifdef GSCAN_SUPPORT
static uint64
convert_fw_rel_time_to_systime(struct osl_timespec *ts, uint32 fw_ts_ms)
{
	return ((uint64)(TIMESPEC_TO_US(*ts)) - (uint64)(fw_ts_ms * 1000));
}

static void
dhd_pno_idx_to_ssid(struct dhd_pno_gscan_params *gscan_params,
		dhd_epno_results_t *res, uint32 idx)
{
	dhd_pno_ssid_t *iter, *next;
	int i;

	/* If idx doesn't make sense */
	if (idx >= gscan_params->epno_cfg.num_epno_ssid) {
		DHD_ERROR(("No match, idx %d num_ssid %d\n", idx,
			gscan_params->epno_cfg.num_epno_ssid));
		goto exit;
	}

	if (gscan_params->epno_cfg.num_epno_ssid > 0) {
		i = 0;

		GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
		list_for_each_entry_safe(iter, next,
			&gscan_params->epno_cfg.epno_ssid_list, list) {
			GCC_DIAGNOSTIC_POP();
			if (i++ == idx) {
				memcpy(res->ssid, iter->SSID, iter->SSID_len);
				res->ssid_len = iter->SSID_len;
				return;
			}
		}
	}
exit:
	/* If we are here then there was no match */
	res->ssid[0] = '\0';
	res->ssid_len = 0;
	return;
}

/* Translate HAL flag bitmask to BRCM FW flag bitmask */
void
dhd_pno_translate_epno_fw_flags(uint32 *flags)
{
	uint32 in_flags, fw_flags = 0;
	in_flags = *flags;

	if (in_flags & DHD_EPNO_A_BAND_TRIG) {
		fw_flags |= WL_PFN_SSID_A_BAND_TRIG;
	}

	if (in_flags & DHD_EPNO_BG_BAND_TRIG) {
		fw_flags |= WL_PFN_SSID_BG_BAND_TRIG;
	}

	if (!(in_flags & DHD_EPNO_STRICT_MATCH) &&
			!(in_flags & DHD_EPNO_HIDDEN_SSID)) {
		fw_flags |= WL_PFN_SSID_IMPRECISE_MATCH;
	}

	if (in_flags & DHD_EPNO_SAME_NETWORK) {
		fw_flags |= WL_PFN_SSID_SAME_NETWORK;
	}

	/* Add any hard coded flags needed */
	fw_flags |= WL_PFN_SUPPRESS_AGING_MASK;
	*flags = fw_flags;

	return;
}

/* Translate HAL auth bitmask to BRCM FW bitmask */
void
dhd_pno_set_epno_auth_flag(uint32 *wpa_auth)
{
	switch (*wpa_auth) {
		case DHD_PNO_AUTH_CODE_OPEN:
			*wpa_auth = WPA_AUTH_DISABLED;
			break;
		case DHD_PNO_AUTH_CODE_PSK:
			*wpa_auth = (WPA_AUTH_PSK | WPA2_AUTH_PSK);
			break;
		case DHD_PNO_AUTH_CODE_EAPOL:
			*wpa_auth = ~WPA_AUTH_NONE;
			break;
		default:
			DHD_ERROR(("%s: Unknown auth %d", __FUNCTION__, *wpa_auth));
			*wpa_auth = WPA_AUTH_PFN_ANY;
			break;
	}
	return;
}

/* Cleanup all results */
static void
dhd_gscan_clear_all_batch_results(dhd_pub_t *dhd)
{
	struct dhd_pno_gscan_params *gscan_params;
	dhd_pno_status_info_t *_pno_state;
	gscan_results_cache_t *iter;

	_pno_state = PNO_GET_PNOSTATE(dhd);
	gscan_params = &_pno_state->pno_params_arr[INDEX_OF_GSCAN_PARAMS].params_gscan;
	iter = gscan_params->gscan_batch_cache;
	/* Mark everything as consumed */
	while (iter) {
		iter->tot_consumed = iter->tot_count;
		iter = iter->next;
	}
	dhd_gscan_batch_cache_cleanup(dhd);
	return;
}

static int
_dhd_pno_gscan_cfg(dhd_pub_t *dhd, wl_pfn_gscan_cfg_t *pfncfg_gscan_param, int size)
{
	int err = BCME_OK;
	NULL_CHECK(dhd, "dhd is NULL", err);

	DHD_PNO(("%s enter\n", __FUNCTION__));

	err = dhd_iovar(dhd, 0, "pfn_gscan_cfg", (char *)pfncfg_gscan_param, size, NULL, 0, TRUE);
	if (err < 0) {
		DHD_ERROR(("%s : failed to execute pfncfg_gscan_param\n", __FUNCTION__));
		goto exit;
	}
exit:
	return err;
}

static int
_dhd_pno_flush_ssid(dhd_pub_t *dhd)
{
	int err;
	wl_pfn_t pfn_elem;
	memset(&pfn_elem, 0, sizeof(wl_pfn_t));
	pfn_elem.flags = htod32(WL_PFN_FLUSH_ALL_SSIDS);

	err = dhd_iovar(dhd, 0, "pfn_add", (char *)&pfn_elem, sizeof(wl_pfn_t), NULL, 0, TRUE);
	if (err < 0) {
		DHD_ERROR(("%s : failed to execute pfn_add\n", __FUNCTION__));
	}
	return err;
}

static bool
is_batch_retrieval_complete(struct dhd_pno_gscan_params *gscan_params)
{
	smp_rmb();
	return (gscan_params->get_batch_flag == GSCAN_BATCH_RETRIEVAL_COMPLETE);
}
#endif /* GSCAN_SUPPORT */

static int
_dhd_pno_suspend(dhd_pub_t *dhd)
{
	int err;
	int suspend = 1;
	dhd_pno_status_info_t *_pno_state;
	NULL_CHECK(dhd, "dhd is NULL", err);
	NULL_CHECK(dhd->pno_state, "pno_state is NULL", err);

	DHD_PNO(("%s enter\n", __FUNCTION__));
	_pno_state = PNO_GET_PNOSTATE(dhd);
	err = dhd_iovar(dhd, 0, "pfn_suspend", (char *)&suspend, sizeof(suspend), NULL, 0, TRUE);
	if (err < 0) {
		DHD_ERROR(("%s : failed to suspend pfn(error :%d)\n", __FUNCTION__, err));
		goto exit;

	}
	_pno_state->pno_status = DHD_PNO_SUSPEND;
exit:
	return err;
}
static int
_dhd_pno_enable(dhd_pub_t *dhd, int enable)
{
	int err = BCME_OK;
	dhd_pno_status_info_t *_pno_state;
	NULL_CHECK(dhd, "dhd is NULL", err);
	NULL_CHECK(dhd->pno_state, "pno_state is NULL", err);
	_pno_state = PNO_GET_PNOSTATE(dhd);
	DHD_PNO(("%s enter\n", __FUNCTION__));

	if (enable & 0xfffe) {
		DHD_ERROR(("%s invalid value\n", __FUNCTION__));
		err = BCME_BADARG;
		goto exit;
	}
	if (!dhd_support_sta_mode(dhd)) {
		DHD_ERROR(("PNO is not allowed for non-STA mode"));
		err = BCME_BADOPTION;
		goto exit;
	}
	if (enable) {
		if ((_pno_state->pno_mode & DHD_PNO_LEGACY_MODE) &&
			dhd_is_associated(dhd, 0, NULL)) {
			DHD_ERROR(("%s Legacy PNO mode cannot be enabled "
				"in assoc mode , ignore it\n", __FUNCTION__));
			err = BCME_BADOPTION;
			goto exit;
		}
	}
	/* Enable/Disable PNO */
	err = dhd_iovar(dhd, 0, "pfn", (char *)&enable, sizeof(enable), NULL, 0, TRUE);
	if (err < 0) {
		DHD_ERROR(("%s : failed to execute pfn_set - %d\n", __FUNCTION__, err));
		goto exit;
	}
	_pno_state->pno_status = (enable)?
		DHD_PNO_ENABLED : DHD_PNO_DISABLED;
	if (!enable)
		_pno_state->pno_mode = DHD_PNO_NONE_MODE;

	DHD_PNO(("%s set pno as %s\n",
		__FUNCTION__, enable ? "Enable" : "Disable"));
exit:
	return err;
}

static int
_dhd_pno_set(dhd_pub_t *dhd, const dhd_pno_params_t *pno_params, dhd_pno_mode_t mode)
{
	int err = BCME_OK;
	wl_pfn_param_t pfn_param;
	dhd_pno_params_t *_params;
	dhd_pno_status_info_t *_pno_state;
	bool combined_scan = FALSE;
	DHD_PNO(("%s enter\n", __FUNCTION__));

	NULL_CHECK(dhd, "dhd is NULL", err);
	NULL_CHECK(dhd->pno_state, "pno_state is NULL", err);
	_pno_state = PNO_GET_PNOSTATE(dhd);

	memset(&pfn_param, 0, sizeof(pfn_param));

	/* set pfn parameters */
	pfn_param.version = htod32(PFN_VERSION);
	pfn_param.flags = ((PFN_LIST_ORDER << SORT_CRITERIA_BIT) |
		(ENABLE << IMMEDIATE_SCAN_BIT) | (ENABLE << REPORT_SEPERATELY_BIT));
	if (mode == DHD_PNO_LEGACY_MODE) {
		/* check and set extra pno params */
		if ((pno_params->params_legacy.pno_repeat != 0) ||
			(pno_params->params_legacy.pno_freq_expo_max != 0)) {
			pfn_param.flags |= htod16(ENABLE << ENABLE_ADAPTSCAN_BIT);
			pfn_param.repeat = (uchar) (pno_params->params_legacy.pno_repeat);
			pfn_param.exp = (uchar) (pno_params->params_legacy.pno_freq_expo_max);
		}
		/* set up pno scan fr */
		if (pno_params->params_legacy.scan_fr != 0)
			pfn_param.scan_freq = htod32(pno_params->params_legacy.scan_fr);
		if (_pno_state->pno_mode & DHD_PNO_BATCH_MODE) {
			DHD_PNO(("will enable combined scan with BATCHIG SCAN MODE\n"));
			mode |= DHD_PNO_BATCH_MODE;
			combined_scan = TRUE;
		} else if (_pno_state->pno_mode & DHD_PNO_HOTLIST_MODE) {
			DHD_PNO(("will enable combined scan with HOTLIST SCAN MODE\n"));
			mode |= DHD_PNO_HOTLIST_MODE;
			combined_scan = TRUE;
		}
#ifdef GSCAN_SUPPORT
		else if (_pno_state->pno_mode & DHD_PNO_GSCAN_MODE) {
			DHD_PNO(("will enable combined scan with GSCAN SCAN MODE\n"));
			mode |= DHD_PNO_GSCAN_MODE;
		}
#endif /* GSCAN_SUPPORT */
	}
	if (mode & (DHD_PNO_BATCH_MODE | DHD_PNO_HOTLIST_MODE)) {
		/* Scan frequency of 30 sec */
		pfn_param.scan_freq = htod32(30);
		/* slow adapt scan is off by default */
		pfn_param.slow_freq = htod32(0);
		/* RSSI margin of 30 dBm */
		pfn_param.rssi_margin = htod16(PNO_RSSI_MARGIN_DBM);
		/* Network timeout 60 sec */
		pfn_param.lost_network_timeout = htod32(60);
		/* best n = 2 by default */
		pfn_param.bestn = DEFAULT_BESTN;
		/* mscan m=0 by default, so not record best networks by default */
		pfn_param.mscan = DEFAULT_MSCAN;
		/*  default repeat = 10 */
		pfn_param.repeat = DEFAULT_REPEAT;
		/* by default, maximum scan interval = 2^2
		 * scan_freq when adaptive scan is turned on
		 */
		pfn_param.exp = DEFAULT_EXP;
		if (mode == DHD_PNO_BATCH_MODE) {
			/* In case of BATCH SCAN */
			if (pno_params->params_batch.bestn)
				pfn_param.bestn = pno_params->params_batch.bestn;
			if (pno_params->params_batch.scan_fr)
				pfn_param.scan_freq = htod32(pno_params->params_batch.scan_fr);
			if (pno_params->params_batch.mscan)
				pfn_param.mscan = pno_params->params_batch.mscan;
			/* enable broadcast scan */
			pfn_param.flags |= (ENABLE << ENABLE_BD_SCAN_BIT);
		} else if (mode == DHD_PNO_HOTLIST_MODE) {
			/* In case of HOTLIST SCAN */
			if (pno_params->params_hotlist.scan_fr)
				pfn_param.scan_freq = htod32(pno_params->params_hotlist.scan_fr);
			pfn_param.bestn = 0;
			pfn_param.repeat = 0;
			/* enable broadcast scan */
			pfn_param.flags |= (ENABLE << ENABLE_BD_SCAN_BIT);
		}
		if (combined_scan) {
			/* Disable Adaptive Scan */
			pfn_param.flags &= ~(htod16(ENABLE << ENABLE_ADAPTSCAN_BIT));
			pfn_param.flags |= (ENABLE << ENABLE_BD_SCAN_BIT);
			pfn_param.repeat = 0;
			pfn_param.exp = 0;
			if (_pno_state->pno_mode & DHD_PNO_BATCH_MODE) {
				/* In case of Legacy PNO + BATCH SCAN */
				_params = &(_pno_state->pno_params_arr[INDEX_OF_BATCH_PARAMS]);
				if (_params->params_batch.bestn)
					pfn_param.bestn = _params->params_batch.bestn;
				if (_params->params_batch.scan_fr)
					pfn_param.scan_freq = htod32(_params->params_batch.scan_fr);
				if (_params->params_batch.mscan)
					pfn_param.mscan = _params->params_batch.mscan;
			} else if (_pno_state->pno_mode & DHD_PNO_HOTLIST_MODE) {
				/* In case of Legacy PNO + HOTLIST SCAN */
				_params = &(_pno_state->pno_params_arr[INDEX_OF_HOTLIST_PARAMS]);
				if (_params->params_hotlist.scan_fr)
				pfn_param.scan_freq = htod32(_params->params_hotlist.scan_fr);
				pfn_param.bestn = 0;
				pfn_param.repeat = 0;
			}
		}
	}
#ifdef GSCAN_SUPPORT
	if (mode & DHD_PNO_GSCAN_MODE) {
		uint32 lost_network_timeout;

		pfn_param.scan_freq = htod32(pno_params->params_gscan.scan_fr);
		if (pno_params->params_gscan.mscan) {
			pfn_param.bestn = pno_params->params_gscan.bestn;
			pfn_param.mscan =  pno_params->params_gscan.mscan;
			pfn_param.flags |= (ENABLE << ENABLE_BD_SCAN_BIT);
		}
		/* RSSI margin of 30 dBm */
		pfn_param.rssi_margin = htod16(PNO_RSSI_MARGIN_DBM);
		pfn_param.repeat = 0;
		pfn_param.exp = 0;
		pfn_param.slow_freq = 0;
		pfn_param.flags |= htod16(ENABLE << ENABLE_ADAPTSCAN_BIT);

		if (_pno_state->pno_mode & DHD_PNO_LEGACY_MODE) {
			dhd_pno_params_t *params;

			params = &(_pno_state->pno_params_arr[INDEX_OF_LEGACY_PARAMS]);

			pfn_param.scan_freq = gcd(pno_params->params_gscan.scan_fr,
			                 params->params_legacy.scan_fr);

			if ((params->params_legacy.pno_repeat != 0) ||
				(params->params_legacy.pno_freq_expo_max != 0)) {
				pfn_param.repeat = (uchar) (params->params_legacy.pno_repeat);
				pfn_param.exp = (uchar) (params->params_legacy.pno_freq_expo_max);
			}
		}

		lost_network_timeout = (pno_params->params_gscan.max_ch_bucket_freq *
		                        pfn_param.scan_freq *
		                        pno_params->params_gscan.lost_ap_window);
		if (lost_network_timeout) {
			pfn_param.lost_network_timeout = htod32(MIN(lost_network_timeout,
			                                 GSCAN_MIN_BSSID_TIMEOUT));
		} else {
			pfn_param.lost_network_timeout = htod32(GSCAN_MIN_BSSID_TIMEOUT);
		}
	} else
#endif /* GSCAN_SUPPORT */
	{
		if (pfn_param.scan_freq < htod32(PNO_SCAN_MIN_FW_SEC) ||
			pfn_param.scan_freq > htod32(PNO_SCAN_MAX_FW_SEC)) {
			DHD_ERROR(("%s pno freq(%d sec) is not valid \n",
				__FUNCTION__, PNO_SCAN_MIN_FW_SEC));
			err = BCME_BADARG;
			goto exit;
		}
	}

	err = dhd_set_rand_mac_oui(dhd);
	/* Ignore if chip doesnt support the feature */
	if (err < 0 && err != BCME_UNSUPPORTED) {
		DHD_ERROR(("%s : failed to set random mac for PNO scan, %d\n", __FUNCTION__, err));
		goto exit;
	}

#ifdef GSCAN_SUPPORT
	if (mode == DHD_PNO_BATCH_MODE ||
	((mode & DHD_PNO_GSCAN_MODE) && pno_params->params_gscan.mscan))
#else
	if (mode == DHD_PNO_BATCH_MODE)
#endif /* GSCAN_SUPPORT */
	{
		int _tmp = pfn_param.bestn;
		/* set bestn to calculate the max mscan which firmware supports */
		err = dhd_iovar(dhd, 0, "pfnmem", (char *)&_tmp, sizeof(_tmp), NULL, 0, TRUE);
		if (err < 0) {
			DHD_ERROR(("%s : failed to set pfnmem\n", __FUNCTION__));
			goto exit;
		}
		/* get max mscan which the firmware supports */
		err = dhd_iovar(dhd, 0, "pfnmem", NULL, 0, (char *)&_tmp, sizeof(_tmp), FALSE);
		if (err < 0) {
			DHD_ERROR(("%s : failed to get pfnmem\n", __FUNCTION__));
			goto exit;
		}
		pfn_param.mscan = MIN(pfn_param.mscan, _tmp);
		DHD_PNO((" returned mscan : %d, set bestn : %d mscan %d\n", _tmp, pfn_param.bestn,
		        pfn_param.mscan));
	}
	err = dhd_iovar(dhd, 0, "pfn_set", (char *)&pfn_param, sizeof(pfn_param), NULL, 0, TRUE);
	if (err < 0) {
		DHD_ERROR(("%s : failed to execute pfn_set %d\n", __FUNCTION__, err));
		goto exit;
	}
	/* need to return mscan if this is for batch scan instead of err */
	err = (mode == DHD_PNO_BATCH_MODE)? pfn_param.mscan : err;
exit:
	return err;
}

static int
_dhd_pno_add_ssid(dhd_pub_t *dhd, struct list_head* ssid_list, int nssid)
{
	int err = BCME_OK;
	int i = 0, mem_needed;
	wl_pfn_t *pfn_elem_buf;
	struct dhd_pno_ssid *iter, *next;

	NULL_CHECK(dhd, "dhd is NULL", err);
	if (!nssid) {
		NULL_CHECK(ssid_list, "ssid list is NULL", err);
		return BCME_ERROR;
	}
	mem_needed = (sizeof(wl_pfn_t) * nssid);
	pfn_elem_buf = (wl_pfn_t *) MALLOCZ(dhd->osh, mem_needed);
	if (!pfn_elem_buf) {
		DHD_ERROR(("%s: Can't malloc %d bytes!\n", __FUNCTION__, mem_needed));
		return BCME_NOMEM;
	}

	GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
	list_for_each_entry_safe(iter, next, ssid_list, list) {
		GCC_DIAGNOSTIC_POP();
		pfn_elem_buf[i].infra = htod32(1);
		pfn_elem_buf[i].auth = htod32(DOT11_OPEN_SYSTEM);
		pfn_elem_buf[i].wpa_auth = htod32(iter->wpa_auth);
		pfn_elem_buf[i].flags = htod32(iter->flags);
		if (iter->hidden)
			pfn_elem_buf[i].flags |= htod32(ENABLE << WL_PFN_HIDDEN_BIT);
		/* If a single RSSI threshold is defined, use that */
#ifdef PNO_MIN_RSSI_TRIGGER
		pfn_elem_buf[i].flags |= ((PNO_MIN_RSSI_TRIGGER & 0xFF) << WL_PFN_RSSI_SHIFT);
#else
		pfn_elem_buf[i].flags |= ((iter->rssi_thresh & 0xFF) << WL_PFN_RSSI_SHIFT);
#endif /* PNO_MIN_RSSI_TRIGGER */
		memcpy((char *)pfn_elem_buf[i].ssid.SSID, iter->SSID,
			iter->SSID_len);
		pfn_elem_buf[i].ssid.SSID_len = iter->SSID_len;
		DHD_PNO(("%s size = %d hidden = %d flags = %x rssi_thresh %d\n",
			iter->SSID, iter->SSID_len, iter->hidden,
			iter->flags, iter->rssi_thresh));
		if (++i >= nssid) {
			/* shouldn't happen */
			break;
		}
	}

	err = dhd_iovar(dhd, 0, "pfn_add", (char *)pfn_elem_buf, mem_needed, NULL, 0, TRUE);
	if (err < 0) {
		DHD_ERROR(("%s : failed to execute pfn_add\n", __FUNCTION__));
	}
	MFREE(dhd->osh, pfn_elem_buf, mem_needed);
	return err;
}

/* qsort compare function */
static int
_dhd_pno_cmpfunc(const void *a, const void *b)
{
	return (*(const uint16*)a - *(const uint16*)b);
}

static int
_dhd_pno_chan_merge(uint16 *d_chan_list, int *nchan,
	uint16 *chan_list1, int nchan1, uint16 *chan_list2, int nchan2)
{
	int err = BCME_OK;
	int i = 0, j = 0, k = 0;
	uint16 tmp;
	NULL_CHECK(d_chan_list, "d_chan_list is NULL", err);
	NULL_CHECK(nchan, "nchan is NULL", err);
	NULL_CHECK(chan_list1, "chan_list1 is NULL", err);
	NULL_CHECK(chan_list2, "chan_list2 is NULL", err);
	/* chan_list1 and chan_list2 should be sorted at first */
	while (i < nchan1 && j < nchan2) {
		tmp = chan_list1[i] < chan_list2[j]?
			chan_list1[i++] : chan_list2[j++];
		for (; i < nchan1 && chan_list1[i] == tmp; i++);
		for (; j < nchan2 && chan_list2[j] == tmp; j++);
		d_chan_list[k++] = tmp;
	}

	while (i < nchan1) {
		tmp = chan_list1[i++];
		for (; i < nchan1 && chan_list1[i] == tmp; i++);
		d_chan_list[k++] = tmp;
	}

	while (j < nchan2) {
		tmp = chan_list2[j++];
		for (; j < nchan2 && chan_list2[j] == tmp; j++);
		d_chan_list[k++] = tmp;

	}
	*nchan = k;
	return err;
}

static int
_dhd_pno_get_channels(dhd_pub_t *dhd, uint16 *d_chan_list,
	int *nchan, uint8 band, bool skip_dfs)
{
	int err = BCME_OK;
	int i, j;
	uint32 chan_buf[WL_NUMCHANNELS + 1];
	wl_uint32_list_t *list;
	NULL_CHECK(dhd, "dhd is NULL", err);
	if (*nchan) {
		NULL_CHECK(d_chan_list, "d_chan_list is NULL", err);
	}
	memset(&chan_buf, 0, sizeof(chan_buf));
	list = (wl_uint32_list_t *) (void *)chan_buf;
	list->count = htod32(WL_NUMCHANNELS);
	err = dhd_wl_ioctl_cmd(dhd, WLC_GET_VALID_CHANNELS, chan_buf, sizeof(chan_buf), FALSE, 0);
	if (err < 0) {
		DHD_ERROR(("failed to get channel list (err: %d)\n", err));
		return err;
	}
	for (i = 0, j = 0; i < dtoh32(list->count) && i < *nchan; i++) {
		if (IS_2G_CHANNEL(dtoh32(list->element[i]))) {
			if (!(band & WLC_BAND_2G)) {
				/* Skip, if not 2g */
				continue;
			}
			/* fall through to include the channel */
		} else if (IS_5G_CHANNEL(dtoh32(list->element[i]))) {
			bool dfs_channel = is_dfs(dhd, dtoh32(list->element[i]));
			if ((skip_dfs && dfs_channel) ||
				(!(band & WLC_BAND_5G) && !dfs_channel)) {
				/* Skip the channel if:
				* the DFS bit is NOT set & the channel is a dfs channel
				* the band 5G is not set & the channel is a non DFS 5G channel
				*/
				continue;
			}
			/* fall through to include the channel */
		} else {
			/* Not in range. Bad channel */
			DHD_ERROR(("Not in range. bad channel\n"));
			*nchan = 0;
			return BCME_BADCHAN;
		}

		/* Include the channel */
		d_chan_list[j++] = (uint16) dtoh32(list->element[i]);
	}
	*nchan = j;
	return err;
}

static int
_dhd_pno_convert_format(dhd_pub_t *dhd, struct dhd_pno_batch_params *params_batch,
	char *buf, int nbufsize)
{
	int err = BCME_OK;
	int bytes_written = 0, nreadsize = 0;
	int t_delta = 0;
	int nleftsize = nbufsize;
	uint8 cnt = 0;
	char *bp = buf;
	char eabuf[ETHER_ADDR_STR_LEN];
#ifdef PNO_DEBUG
	char *_base_bp;
	char msg[150];
#endif // endif
	dhd_pno_bestnet_entry_t *iter, *next;
	dhd_pno_scan_results_t *siter, *snext;
	dhd_pno_best_header_t *phead, *pprev;
	NULL_CHECK(params_batch, "params_batch is NULL", err);
	if (nbufsize > 0)
		NULL_CHECK(buf, "buf is NULL", err);
	/* initialize the buffer */
	memset(buf, 0, nbufsize);
	DHD_PNO(("%s enter \n", __FUNCTION__));
	/* # of scans */
	if (!params_batch->get_batch.batch_started) {
		bp += nreadsize = snprintf(bp, nleftsize, "scancount=%d\n",
			params_batch->get_batch.expired_tot_scan_cnt);
		nleftsize -= nreadsize;
		params_batch->get_batch.batch_started = TRUE;
	}
	DHD_PNO(("%s scancount %d\n", __FUNCTION__, params_batch->get_batch.expired_tot_scan_cnt));
	/* preestimate scan count until which scan result this report is going to end */
	GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
	list_for_each_entry_safe(siter, snext,
		&params_batch->get_batch.expired_scan_results_list, list) {
		GCC_DIAGNOSTIC_POP();
		phead = siter->bestnetheader;
		while (phead != NULL) {
			/* if left_size is less than bestheader total size , stop this */
			if (nleftsize <=
				(phead->tot_size + phead->tot_cnt * ENTRY_OVERHEAD))
				goto exit;
			/* increase scan count */
			cnt++;
			/* # best of each scan */
			DHD_PNO(("\n<loop : %d, apcount %d>\n", cnt - 1, phead->tot_cnt));
			/* attribute of the scan */
			if (phead->reason & PNO_STATUS_ABORT_MASK) {
				bp += nreadsize = snprintf(bp, nleftsize, "trunc\n");
				nleftsize -= nreadsize;
			}
			GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
			list_for_each_entry_safe(iter, next,
				&phead->entry_list, list) {
				GCC_DIAGNOSTIC_POP();
				t_delta = jiffies_to_msecs(jiffies - iter->recorded_time);
#ifdef PNO_DEBUG
				_base_bp = bp;
				memset(msg, 0, sizeof(msg));
#endif // endif
				/* BSSID info */
				bp += nreadsize = snprintf(bp, nleftsize, "bssid=%s\n",
				bcm_ether_ntoa((const struct ether_addr *)&iter->BSSID, eabuf));
				nleftsize -= nreadsize;
				/* SSID */
				bp += nreadsize = snprintf(bp, nleftsize, "ssid=%s\n", iter->SSID);
				nleftsize -= nreadsize;
				/* channel */
				bp += nreadsize = snprintf(bp, nleftsize, "freq=%d\n",
				wf_channel2mhz(iter->channel,
				iter->channel <= CH_MAX_2G_CHANNEL?
				WF_CHAN_FACTOR_2_4_G : WF_CHAN_FACTOR_5_G));
				nleftsize -= nreadsize;
				/* RSSI */
				bp += nreadsize = snprintf(bp, nleftsize, "level=%d\n", iter->RSSI);
				nleftsize -= nreadsize;
				/* add the time consumed in Driver to the timestamp of firmware */
				iter->timestamp += t_delta;
				bp += nreadsize = snprintf(bp, nleftsize,
					"age=%d\n", iter->timestamp);
				nleftsize -= nreadsize;
				/* RTT0 */
				bp += nreadsize = snprintf(bp, nleftsize, "dist=%d\n",
				(iter->rtt0 == 0)? -1 : iter->rtt0);
				nleftsize -= nreadsize;
				/* RTT1 */
				bp += nreadsize = snprintf(bp, nleftsize, "distSd=%d\n",
				(iter->rtt0 == 0)? -1 : iter->rtt1);
				nleftsize -= nreadsize;
				bp += nreadsize = snprintf(bp, nleftsize, "%s", AP_END_MARKER);
				nleftsize -= nreadsize;
				list_del(&iter->list);
				MFREE(dhd->osh, iter, BESTNET_ENTRY_SIZE);
#ifdef PNO_DEBUG
				memcpy(msg, _base_bp, bp - _base_bp);
				DHD_PNO(("Entry : \n%s", msg));
#endif // endif
			}
			bp += nreadsize = snprintf(bp, nleftsize, "%s", SCAN_END_MARKER);
			DHD_PNO(("%s", SCAN_END_MARKER));
			nleftsize -= nreadsize;
			pprev = phead;
			/* reset the header */
			siter->bestnetheader = phead = phead->next;
			MFREE(dhd->osh, pprev, BEST_HEADER_SIZE);

			siter->cnt_header--;
		}
		if (phead == NULL) {
			/* we store all entry in this scan , so it is ok to delete */
			list_del(&siter->list);
			MFREE(dhd->osh, siter, SCAN_RESULTS_SIZE);
		}
	}
exit:
	if (cnt < params_batch->get_batch.expired_tot_scan_cnt) {
		DHD_ERROR(("Buffer size is small to save all batch entry,"
			" cnt : %d (remained_scan_cnt): %d\n",
			cnt, params_batch->get_batch.expired_tot_scan_cnt - cnt));
	}
	params_batch->get_batch.expired_tot_scan_cnt -= cnt;
	/* set FALSE only if the link list  is empty after returning the data */
	GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
	if (list_empty(&params_batch->get_batch.expired_scan_results_list)) {
		GCC_DIAGNOSTIC_POP();
		params_batch->get_batch.batch_started = FALSE;
		bp += snprintf(bp, nleftsize, "%s", RESULTS_END_MARKER);
		DHD_PNO(("%s", RESULTS_END_MARKER));
		DHD_PNO(("%s : Getting the batching data is complete\n", __FUNCTION__));
	}
	/* return used memory in buffer */
	bytes_written = (int32)(bp - buf);
	return bytes_written;
}

static int
_dhd_pno_clear_all_batch_results(dhd_pub_t *dhd, struct list_head *head, bool only_last)
{
	int err = BCME_OK;
	int removed_scan_cnt = 0;
	dhd_pno_scan_results_t *siter, *snext;
	dhd_pno_best_header_t *phead, *pprev;
	dhd_pno_bestnet_entry_t *iter, *next;
	NULL_CHECK(dhd, "dhd is NULL", err);
	NULL_CHECK(head, "head is NULL", err);
	NULL_CHECK(head->next, "head->next is NULL", err);
	DHD_PNO(("%s enter\n", __FUNCTION__));

	GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
	list_for_each_entry_safe(siter, snext,
		head, list) {
		if (only_last) {
			/* in case that we need to delete only last one */
			if (!list_is_last(&siter->list, head)) {
				/* skip if the one is not last */
				continue;
			}
		}
		/* delete all data belong if the one is last */
		phead = siter->bestnetheader;
		while (phead != NULL) {
			removed_scan_cnt++;
			list_for_each_entry_safe(iter, next,
			&phead->entry_list, list) {
				list_del(&iter->list);
				MFREE(dhd->osh, iter, BESTNET_ENTRY_SIZE);
			}
			pprev = phead;
			phead = phead->next;
			MFREE(dhd->osh, pprev, BEST_HEADER_SIZE);
		}
		if (phead == NULL) {
			/* it is ok to delete top node */
			list_del(&siter->list);
			MFREE(dhd->osh, siter, SCAN_RESULTS_SIZE);
		}
	}
	GCC_DIAGNOSTIC_POP();
	return removed_scan_cnt;
}

static int
_dhd_pno_cfg(dhd_pub_t *dhd, uint16 *channel_list, int nchan)
{
	int err = BCME_OK;
	int i = 0;
	wl_pfn_cfg_t pfncfg_param;
	NULL_CHECK(dhd, "dhd is NULL", err);
	if (nchan) {
		NULL_CHECK(channel_list, "nchan is NULL", err);
	}
	if (nchan > WL_NUMCHANNELS) {
		return BCME_RANGE;
	}
	DHD_PNO(("%s enter :  nchan : %d\n", __FUNCTION__, nchan));
	memset(&pfncfg_param, 0, sizeof(wl_pfn_cfg_t));
	/* Setup default values */
	pfncfg_param.reporttype = htod32(WL_PFN_REPORT_ALLNET);
	pfncfg_param.channel_num = htod32(0);

	for (i = 0; i < nchan; i++)
		pfncfg_param.channel_list[i] = channel_list[i];

	pfncfg_param.channel_num = htod32(nchan);
	err = dhd_iovar(dhd, 0, "pfn_cfg", (char *)&pfncfg_param, sizeof(pfncfg_param), NULL, 0,
			TRUE);
	if (err < 0) {
		DHD_ERROR(("%s : failed to execute pfn_cfg\n", __FUNCTION__));
		goto exit;
	}
exit:
	return err;
}

static int
_dhd_pno_reinitialize_prof(dhd_pub_t *dhd, dhd_pno_params_t *params, dhd_pno_mode_t mode)
{
	int err = BCME_OK;
	dhd_pno_status_info_t *_pno_state;
	NULL_CHECK(dhd, "dhd is NULL\n", err);
	NULL_CHECK(dhd->pno_state, "pno_state is NULL\n", err);
	DHD_PNO(("%s enter\n", __FUNCTION__));
	_pno_state = PNO_GET_PNOSTATE(dhd);
	mutex_lock(&_pno_state->pno_mutex);
	switch (mode) {
	case DHD_PNO_LEGACY_MODE: {
		struct dhd_pno_ssid *iter, *next;
		if (params->params_legacy.nssid > 0) {
			GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
			list_for_each_entry_safe(iter, next,
				&params->params_legacy.ssid_list, list) {
				GCC_DIAGNOSTIC_POP();
				list_del(&iter->list);
				MFREE(dhd->osh, iter, sizeof(struct dhd_pno_ssid));
			}
		}

		params->params_legacy.nssid = 0;
		params->params_legacy.scan_fr = 0;
		params->params_legacy.pno_freq_expo_max = 0;
		params->params_legacy.pno_repeat = 0;
		params->params_legacy.nchan = 0;
		memset(params->params_legacy.chan_list, 0,
			sizeof(params->params_legacy.chan_list));
		break;
	}
	case DHD_PNO_BATCH_MODE: {
		params->params_batch.scan_fr = 0;
		params->params_batch.mscan = 0;
		params->params_batch.nchan = 0;
		params->params_batch.rtt = 0;
		params->params_batch.bestn = 0;
		params->params_batch.nchan = 0;
		params->params_batch.band = WLC_BAND_AUTO;
		memset(params->params_batch.chan_list, 0,
			sizeof(params->params_batch.chan_list));
		params->params_batch.get_batch.batch_started = FALSE;
		params->params_batch.get_batch.buf = NULL;
		params->params_batch.get_batch.bufsize = 0;
		params->params_batch.get_batch.reason = 0;
		_dhd_pno_clear_all_batch_results(dhd,
			&params->params_batch.get_batch.scan_results_list, FALSE);
		_dhd_pno_clear_all_batch_results(dhd,
			&params->params_batch.get_batch.expired_scan_results_list, FALSE);
		params->params_batch.get_batch.tot_scan_cnt = 0;
		params->params_batch.get_batch.expired_tot_scan_cnt = 0;
		params->params_batch.get_batch.top_node_cnt = 0;
		INIT_LIST_HEAD(&params->params_batch.get_batch.scan_results_list);
		INIT_LIST_HEAD(&params->params_batch.get_batch.expired_scan_results_list);
		break;
	}
	case DHD_PNO_HOTLIST_MODE: {
		struct dhd_pno_bssid *iter, *next;
		if (params->params_hotlist.nbssid > 0) {
			GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
			list_for_each_entry_safe(iter, next,
				&params->params_hotlist.bssid_list, list) {
				GCC_DIAGNOSTIC_POP();
				list_del(&iter->list);
				MFREE(dhd->osh, iter, sizeof(struct dhd_pno_ssid));
			}
		}
		params->params_hotlist.scan_fr = 0;
		params->params_hotlist.nbssid = 0;
		params->params_hotlist.nchan = 0;
		params->params_batch.band = WLC_BAND_AUTO;
		memset(params->params_hotlist.chan_list, 0,
			sizeof(params->params_hotlist.chan_list));
		break;
	}
	default:
		DHD_ERROR(("%s : unknown mode : %d\n", __FUNCTION__, mode));
		break;
	}
	mutex_unlock(&_pno_state->pno_mutex);
	return err;
}

static int
_dhd_pno_add_bssid(dhd_pub_t *dhd, wl_pfn_bssid_t *p_pfn_bssid, int nbssid)
{
	int err = BCME_OK;
	NULL_CHECK(dhd, "dhd is NULL", err);
	if (nbssid) {
		NULL_CHECK(p_pfn_bssid, "bssid list is NULL", err);
	}
	err = dhd_iovar(dhd, 0, "pfn_add_bssid", (char *)p_pfn_bssid,
			sizeof(wl_pfn_bssid_t) * nbssid, NULL, 0, TRUE);
	if (err < 0) {
		DHD_ERROR(("%s : failed to execute pfn_cfg\n", __FUNCTION__));
		goto exit;
	}
exit:
	return err;
}

int
dhd_pno_stop_for_ssid(dhd_pub_t *dhd)
{
	int err = BCME_OK;
	uint32 mode = 0, cnt = 0;
	dhd_pno_status_info_t *_pno_state;
	dhd_pno_params_t *_params = NULL;
	wl_pfn_bssid_t *p_pfn_bssid = NULL, *tmp_bssid;

	NULL_CHECK(dhd, "dev is NULL", err);
	NULL_CHECK(dhd->pno_state, "pno_state is NULL", err);
	_pno_state = PNO_GET_PNOSTATE(dhd);
	if (!(_pno_state->pno_mode & DHD_PNO_LEGACY_MODE)) {
		DHD_ERROR(("%s : LEGACY PNO MODE is not enabled\n", __FUNCTION__));
		goto exit;
	}
	DHD_PNO(("%s enter\n", __FUNCTION__));
	/* If pno mode is PNO_LEGACY_MODE clear the pno values and unset the DHD_PNO_LEGACY_MODE */
	_params = &_pno_state->pno_params_arr[INDEX_OF_LEGACY_PARAMS];
	_dhd_pno_reinitialize_prof(dhd, _params, DHD_PNO_LEGACY_MODE);
	_pno_state->pno_mode &= ~DHD_PNO_LEGACY_MODE;

#ifdef GSCAN_SUPPORT
	if (_pno_state->pno_mode & DHD_PNO_GSCAN_MODE) {
		struct dhd_pno_gscan_params *gscan_params;

		_params = &_pno_state->pno_params_arr[INDEX_OF_GSCAN_PARAMS];
		gscan_params = &_params->params_gscan;
		if (gscan_params->mscan) {
			/* retrieve the batching data from firmware into host */
			err = dhd_wait_batch_results_complete(dhd);
			if (err != BCME_OK)
				goto exit;
		}
		/* save current pno_mode before calling dhd_pno_clean */
		mutex_lock(&_pno_state->pno_mutex);
		mode = _pno_state->pno_mode;
		err = dhd_pno_clean(dhd);
		if (err < 0) {
			DHD_ERROR(("%s : failed to call dhd_pno_clean (err: %d)\n",
				__FUNCTION__, err));
			mutex_unlock(&_pno_state->pno_mutex);
			goto exit;
		}
		/* restore previous pno_mode */
		_pno_state->pno_mode = mode;
		mutex_unlock(&_pno_state->pno_mutex);
		/* Restart gscan */
		err = dhd_pno_initiate_gscan_request(dhd, 1, 0);
		goto exit;
	}
#endif /* GSCAN_SUPPORT */
	/* restart Batch mode  if the batch mode is on */
	if (_pno_state->pno_mode & (DHD_PNO_BATCH_MODE | DHD_PNO_HOTLIST_MODE)) {
		/* retrieve the batching data from firmware into host */
		dhd_pno_get_for_batch(dhd, NULL, 0, PNO_STATUS_DISABLE);
		/* save current pno_mode before calling dhd_pno_clean */
		mode = _pno_state->pno_mode;
		err = dhd_pno_clean(dhd);
		if (err < 0) {
			err = BCME_ERROR;
			DHD_ERROR(("%s : failed to call dhd_pno_clean (err: %d)\n",
				__FUNCTION__, err));
			goto exit;
		}

		/* restore previous pno_mode */
		_pno_state->pno_mode = mode;
		if (_pno_state->pno_mode & DHD_PNO_BATCH_MODE) {
			_params = &(_pno_state->pno_params_arr[INDEX_OF_BATCH_PARAMS]);
			/* restart BATCH SCAN */
			err = dhd_pno_set_for_batch(dhd, &_params->params_batch);
			if (err < 0) {
				_pno_state->pno_mode &= ~DHD_PNO_BATCH_MODE;
				DHD_ERROR(("%s : failed to restart batch scan(err: %d)\n",
					__FUNCTION__, err));
				goto exit;
			}
		} else if (_pno_state->pno_mode & DHD_PNO_HOTLIST_MODE) {
			/* restart HOTLIST SCAN */
			struct dhd_pno_bssid *iter, *next;
			_params = &(_pno_state->pno_params_arr[INDEX_OF_HOTLIST_PARAMS]);
			p_pfn_bssid = MALLOCZ(dhd->osh, sizeof(wl_pfn_bssid_t) *
			_params->params_hotlist.nbssid);
			if (p_pfn_bssid == NULL) {
				DHD_ERROR(("%s : failed to allocate wl_pfn_bssid_t array"
				" (count: %d)",
					__FUNCTION__, _params->params_hotlist.nbssid));
				err = BCME_ERROR;
				_pno_state->pno_mode &= ~DHD_PNO_HOTLIST_MODE;
				goto exit;
			}
			/* convert dhd_pno_bssid to wl_pfn_bssid */
			GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
			cnt = 0;
			tmp_bssid = p_pfn_bssid;
			list_for_each_entry_safe(iter, next,
			&_params->params_hotlist.bssid_list, list) {
				GCC_DIAGNOSTIC_POP();
				memcpy(&tmp_bssid->macaddr,
				&iter->macaddr, ETHER_ADDR_LEN);
				tmp_bssid->flags = iter->flags;
				if (cnt < _params->params_hotlist.nbssid) {
					tmp_bssid++;
					cnt++;
				} else {
					DHD_ERROR(("%s: Allocated insufficient memory\n",
						__FUNCTION__));
					break;
				}
			}
			err = dhd_pno_set_for_hotlist(dhd, p_pfn_bssid, &_params->params_hotlist);
			if (err < 0) {
				_pno_state->pno_mode &= ~DHD_PNO_HOTLIST_MODE;
				DHD_ERROR(("%s : failed to restart hotlist scan(err: %d)\n",
					__FUNCTION__, err));
				goto exit;
			}
		}
	} else {
		err = dhd_pno_clean(dhd);
		if (err < 0) {
			DHD_ERROR(("%s : failed to call dhd_pno_clean (err: %d)\n",
				__FUNCTION__, err));
			goto exit;
		}
	}
exit:
	if (p_pfn_bssid) {
		MFREE(dhd->osh, p_pfn_bssid, sizeof(wl_pfn_bssid_t) *
			_params->params_hotlist.nbssid);
	}
	return err;
}

int
dhd_pno_enable(dhd_pub_t *dhd, int enable)
{
	int err = BCME_OK;
	NULL_CHECK(dhd, "dhd is NULL", err);
	DHD_PNO(("%s enter\n", __FUNCTION__));
	return (_dhd_pno_enable(dhd, enable));
}

static int
dhd_pno_add_to_ssid_list(dhd_pub_t *dhd, struct list_head *ptr, wlc_ssid_ext_t *ssid_list,
    int nssid, int *num_ssid_added)
{
	int ret = BCME_OK;
	int i;
	struct dhd_pno_ssid *_pno_ssid;

	for (i = 0; i < nssid; i++) {
		if (ssid_list[i].SSID_len > DOT11_MAX_SSID_LEN) {
			DHD_ERROR(("%s : Invalid SSID length %d\n",
				__FUNCTION__, ssid_list[i].SSID_len));
			ret = BCME_ERROR;
			goto exit;
		}
		/* Check for broadcast ssid */
		if (!ssid_list[i].SSID_len) {
			DHD_ERROR(("%d: Broadcast SSID is illegal for PNO setting\n", i));
			ret = BCME_ERROR;
			goto exit;
		}
		_pno_ssid = (struct dhd_pno_ssid *)MALLOCZ(dhd->osh,
			sizeof(struct dhd_pno_ssid));
		if (_pno_ssid == NULL) {
			DHD_ERROR(("%s : failed to allocate struct dhd_pno_ssid\n",
				__FUNCTION__));
			ret = BCME_ERROR;
			goto exit;
		}
		_pno_ssid->SSID_len = ssid_list[i].SSID_len;
		_pno_ssid->hidden = ssid_list[i].hidden;
		_pno_ssid->rssi_thresh = ssid_list[i].rssi_thresh;
		_pno_ssid->flags = ssid_list[i].flags;
		_pno_ssid->wpa_auth = WPA_AUTH_PFN_ANY;

		memcpy(_pno_ssid->SSID, ssid_list[i].SSID, _pno_ssid->SSID_len);
		list_add_tail(&_pno_ssid->list, ptr);
	}

exit:
	*num_ssid_added = i;
	return ret;
}

int
dhd_pno_set_for_ssid(dhd_pub_t *dhd, wlc_ssid_ext_t* ssid_list, int nssid,
	uint16  scan_fr, int pno_repeat, int pno_freq_expo_max, uint16 *channel_list, int nchan)
{
	dhd_pno_status_info_t *_pno_state;
	dhd_pno_params_t *_params;
	struct dhd_pno_legacy_params *params_legacy;
	int err = BCME_OK;

	if (!dhd || !dhd->pno_state) {
		DHD_ERROR(("%s: PNO Not enabled/Not ready\n", __FUNCTION__));
		return BCME_NOTREADY;
	}

	if (!dhd_support_sta_mode(dhd)) {
		return BCME_BADOPTION;
	}

	_pno_state = PNO_GET_PNOSTATE(dhd);
	_params = &(_pno_state->pno_params_arr[INDEX_OF_LEGACY_PARAMS]);
	params_legacy = &(_params->params_legacy);
	err = _dhd_pno_reinitialize_prof(dhd, _params, DHD_PNO_LEGACY_MODE);

	if (err < 0) {
		DHD_ERROR(("%s : failed to reinitialize profile (err %d)\n",
			__FUNCTION__, err));
		return err;
	}

	INIT_LIST_HEAD(&params_legacy->ssid_list);

	if (dhd_pno_add_to_ssid_list(dhd, &params_legacy->ssid_list, ssid_list,
		nssid, &params_legacy->nssid) < 0) {
		_dhd_pno_reinitialize_prof(dhd, _params, DHD_PNO_LEGACY_MODE);
		return BCME_ERROR;
	}

	DHD_PNO(("%s enter : nssid %d, scan_fr :%d, pno_repeat :%d,"
		"pno_freq_expo_max: %d, nchan :%d\n", __FUNCTION__,
		params_legacy->nssid, scan_fr, pno_repeat, pno_freq_expo_max, nchan));

	return dhd_pno_set_legacy_pno(dhd, scan_fr, pno_repeat,
		pno_freq_expo_max, channel_list, nchan);

}

static int
dhd_pno_set_legacy_pno(dhd_pub_t *dhd, uint16  scan_fr, int pno_repeat,
	int pno_freq_expo_max, uint16 *channel_list, int nchan)
{
	dhd_pno_params_t *_params;
	dhd_pno_params_t *_params2;
	dhd_pno_status_info_t *_pno_state;
	uint16 _chan_list[WL_NUMCHANNELS];
	int32 tot_nchan = 0;
	int err = BCME_OK;
	int i, nssid;
	int mode = 0;
	struct list_head *ssid_list;

	_pno_state = PNO_GET_PNOSTATE(dhd);

	_params = &(_pno_state->pno_params_arr[INDEX_OF_LEGACY_PARAMS]);
	/* If GSCAN is also ON will handle this down below */
#ifdef GSCAN_SUPPORT
	if (_pno_state->pno_mode & DHD_PNO_LEGACY_MODE &&
		!(_pno_state->pno_mode & DHD_PNO_GSCAN_MODE))
#else
	if (_pno_state->pno_mode & DHD_PNO_LEGACY_MODE)
#endif /* GSCAN_SUPPORT */
	{
		DHD_ERROR(("%s : Legacy PNO mode was already started, "
			"will disable previous one to start new one\n", __FUNCTION__));
		err = dhd_pno_stop_for_ssid(dhd);
		if (err < 0) {
			DHD_ERROR(("%s : failed to stop legacy PNO (err %d)\n",
				__FUNCTION__, err));
			return err;
		}
	}
	_pno_state->pno_mode |= DHD_PNO_LEGACY_MODE;
	memset(_chan_list, 0, sizeof(_chan_list));
	tot_nchan = MIN(nchan, WL_NUMCHANNELS);
	if (tot_nchan > 0 && channel_list) {
		for (i = 0; i < tot_nchan; i++)
		_params->params_legacy.chan_list[i] = _chan_list[i] = channel_list[i];
	}
#ifdef GSCAN_SUPPORT
	else {
		tot_nchan = WL_NUMCHANNELS;
		err = _dhd_pno_get_channels(dhd, _chan_list, &tot_nchan,
			(WLC_BAND_2G | WLC_BAND_5G), FALSE);
		if (err < 0) {
			tot_nchan = 0;
			DHD_PNO(("Could not get channel list for PNO SSID\n"));
		} else {
			for (i = 0; i < tot_nchan; i++)
				_params->params_legacy.chan_list[i] = _chan_list[i];
		}
	}
#endif /* GSCAN_SUPPORT */

	if (_pno_state->pno_mode & (DHD_PNO_BATCH_MODE | DHD_PNO_HOTLIST_MODE)) {
		DHD_PNO(("BATCH SCAN is on progress in firmware\n"));
		/* retrieve the batching data from firmware into host */
		dhd_pno_get_for_batch(dhd, NULL, 0, PNO_STATUS_DISABLE);
		/* store current pno_mode before disabling pno */
		mode = _pno_state->pno_mode;
		err = _dhd_pno_enable(dhd, PNO_OFF);
		if (err < 0) {
			DHD_ERROR(("%s : failed to disable PNO\n", __FUNCTION__));
			goto exit;
		}
		/* restore the previous mode */
		_pno_state->pno_mode = mode;
		/* use superset of channel list between two mode */
		if (_pno_state->pno_mode & DHD_PNO_BATCH_MODE) {
			_params2 = &(_pno_state->pno_params_arr[INDEX_OF_BATCH_PARAMS]);
			if (_params2->params_batch.nchan > 0 && tot_nchan > 0) {
				err = _dhd_pno_chan_merge(_chan_list, &tot_nchan,
					&_params2->params_batch.chan_list[0],
					_params2->params_batch.nchan,
					&channel_list[0], tot_nchan);
				if (err < 0) {
					DHD_ERROR(("%s : failed to merge channel list"
					" between legacy and batch\n",
						__FUNCTION__));
					goto exit;
				}
			}  else {
				DHD_PNO(("superset channel will use"
				" all channels in firmware\n"));
			}
		} else if (_pno_state->pno_mode & DHD_PNO_HOTLIST_MODE) {
			_params2 = &(_pno_state->pno_params_arr[INDEX_OF_HOTLIST_PARAMS]);
			if (_params2->params_hotlist.nchan > 0 && tot_nchan > 0) {
				err = _dhd_pno_chan_merge(_chan_list, &tot_nchan,
					&_params2->params_hotlist.chan_list[0],
					_params2->params_hotlist.nchan,
					&channel_list[0], tot_nchan);
				if (err < 0) {
					DHD_ERROR(("%s : failed to merge channel list"
					" between legacy and hotlist\n",
						__FUNCTION__));
					goto exit;
				}
			}
		}
	}
	_params->params_legacy.scan_fr = scan_fr;
	_params->params_legacy.pno_repeat = pno_repeat;
	_params->params_legacy.pno_freq_expo_max = pno_freq_expo_max;
	_params->params_legacy.nchan = tot_nchan;
	ssid_list = &_params->params_legacy.ssid_list;
	nssid = _params->params_legacy.nssid;

#ifdef GSCAN_SUPPORT
	/* dhd_pno_initiate_gscan_request will handle simultaneous Legacy PNO and GSCAN */
	if (_pno_state->pno_mode & DHD_PNO_GSCAN_MODE) {
		struct dhd_pno_gscan_params *gscan_params;
		gscan_params = &_pno_state->pno_params_arr[INDEX_OF_GSCAN_PARAMS].params_gscan;
		/* ePNO and Legacy PNO do not co-exist */
		if (gscan_params->epno_cfg.num_epno_ssid) {
			DHD_PNO(("ePNO and Legacy PNO do not co-exist\n"));
			err = BCME_EPERM;
			goto exit;
		}
		DHD_PNO(("GSCAN mode is ON! Will restart GSCAN+Legacy PNO\n"));
		err = dhd_pno_initiate_gscan_request(dhd, 1, 0);
		goto exit;
	}
#endif /* GSCAN_SUPPORT */
	if ((err = _dhd_pno_set(dhd, _params, DHD_PNO_LEGACY_MODE)) < 0) {
		DHD_ERROR(("failed to set call pno_set (err %d) in firmware\n", err));
		goto exit;
	}
	if ((err = _dhd_pno_add_ssid(dhd, ssid_list, nssid)) < 0) {
		DHD_ERROR(("failed to add ssid list(err %d), %d in firmware\n", err, nssid));
		goto exit;
	}
	if (tot_nchan > 0) {
		if ((err = _dhd_pno_cfg(dhd, _chan_list, tot_nchan)) < 0) {
			DHD_ERROR(("%s : failed to set call pno_cfg (err %d) in firmware\n",
				__FUNCTION__, err));
			goto exit;
		}
	}
	if (_pno_state->pno_status == DHD_PNO_DISABLED) {
		if ((err = _dhd_pno_enable(dhd, PNO_ON)) < 0)
			DHD_ERROR(("%s : failed to enable PNO\n", __FUNCTION__));
	}
exit:
	if (err < 0) {
		_dhd_pno_reinitialize_prof(dhd, _params, DHD_PNO_LEGACY_MODE);
	}
	/* clear mode in case of error */
	if (err < 0) {
		int ret = dhd_pno_clean(dhd);

		if (ret < 0) {
			DHD_ERROR(("%s : failed to call dhd_pno_clean (err: %d)\n",
				__FUNCTION__, ret));
		} else {
			_pno_state->pno_mode &= ~DHD_PNO_LEGACY_MODE;
		}
	}
	return err;
}

int
dhd_pno_set_for_batch(dhd_pub_t *dhd, struct dhd_pno_batch_params *batch_params)
{
	int err = BCME_OK;
	uint16 _chan_list[WL_NUMCHANNELS];
	int rem_nchan = 0, tot_nchan = 0;
	int mode = 0, mscan = 0;
	dhd_pno_params_t *_params;
	dhd_pno_params_t *_params2;
	dhd_pno_status_info_t *_pno_state;
	NULL_CHECK(dhd, "dhd is NULL", err);
	NULL_CHECK(dhd->pno_state, "pno_state is NULL", err);
	NULL_CHECK(batch_params, "batch_params is NULL", err);
	_pno_state = PNO_GET_PNOSTATE(dhd);
	DHD_PNO(("%s enter\n", __FUNCTION__));
	if (!dhd_support_sta_mode(dhd)) {
		err = BCME_BADOPTION;
		goto exit;
	}
	if (!WLS_SUPPORTED(_pno_state)) {
		DHD_ERROR(("%s : wifi location service is not supported\n", __FUNCTION__));
		err = BCME_UNSUPPORTED;
		goto exit;
	}
	_params = &_pno_state->pno_params_arr[INDEX_OF_BATCH_PARAMS];
	if (!(_pno_state->pno_mode & DHD_PNO_BATCH_MODE)) {
		_pno_state->pno_mode |= DHD_PNO_BATCH_MODE;
		err = _dhd_pno_reinitialize_prof(dhd, _params, DHD_PNO_BATCH_MODE);
		if (err < 0) {
			DHD_ERROR(("%s : failed to call _dhd_pno_reinitialize_prof\n",
				__FUNCTION__));
			goto exit;
		}
	} else {
		/* batch mode is already started */
		return -EBUSY;
	}
	_params->params_batch.scan_fr = batch_params->scan_fr;
	_params->params_batch.bestn = batch_params->bestn;
	_params->params_batch.mscan = (batch_params->mscan)?
		batch_params->mscan : DEFAULT_BATCH_MSCAN;
	_params->params_batch.nchan = batch_params->nchan;
	memcpy(_params->params_batch.chan_list, batch_params->chan_list,
		sizeof(_params->params_batch.chan_list));

	memset(_chan_list, 0, sizeof(_chan_list));

	rem_nchan = ARRAYSIZE(batch_params->chan_list) - batch_params->nchan;
	if (batch_params->band == WLC_BAND_2G || batch_params->band == WLC_BAND_5G) {
		/* get a valid channel list based on band B or A */
		err = _dhd_pno_get_channels(dhd,
		&_params->params_batch.chan_list[batch_params->nchan],
		&rem_nchan, batch_params->band, FALSE);
		if (err < 0) {
			DHD_ERROR(("%s: failed to get valid channel list(band : %d)\n",
				__FUNCTION__, batch_params->band));
			goto exit;
		}
		/* now we need to update nchan because rem_chan has valid channel count */
		_params->params_batch.nchan += rem_nchan;
		/* need to sort channel list */
		sort(_params->params_batch.chan_list, _params->params_batch.nchan,
			sizeof(_params->params_batch.chan_list[0]), _dhd_pno_cmpfunc, NULL);
	}
#ifdef PNO_DEBUG
{
		DHD_PNO(("Channel list : "));
		for (i = 0; i < _params->params_batch.nchan; i++) {
			DHD_PNO(("%d ", _params->params_batch.chan_list[i]));
		}
		DHD_PNO(("\n"));
}
#endif // endif
	if (_params->params_batch.nchan) {
		/* copy the channel list into local array */
		memcpy(_chan_list, _params->params_batch.chan_list, sizeof(_chan_list));
		tot_nchan = _params->params_batch.nchan;
	}
	if (_pno_state->pno_mode & DHD_PNO_LEGACY_MODE) {
		DHD_PNO(("PNO SSID is on progress in firmware\n"));
		/* store current pno_mode before disabling pno */
		mode = _pno_state->pno_mode;
		err = _dhd_pno_enable(dhd, PNO_OFF);
		if (err < 0) {
			DHD_ERROR(("%s : failed to disable PNO\n", __FUNCTION__));
			goto exit;
		}
		/* restore the previous mode */
		_pno_state->pno_mode = mode;
		/* Use the superset for channelist between two mode */
		_params2 = &(_pno_state->pno_params_arr[INDEX_OF_LEGACY_PARAMS]);
		if (_params2->params_legacy.nchan > 0 && _params->params_batch.nchan > 0) {
			err = _dhd_pno_chan_merge(_chan_list, &tot_nchan,
				&_params2->params_legacy.chan_list[0],
				_params2->params_legacy.nchan,
				&_params->params_batch.chan_list[0], _params->params_batch.nchan);
			if (err < 0) {
				DHD_ERROR(("%s : failed to merge channel list"
				" between legacy and batch\n",
					__FUNCTION__));
				goto exit;
			}
		} else {
			DHD_PNO(("superset channel will use all channels in firmware\n"));
		}
		if ((err = _dhd_pno_add_ssid(dhd, &_params2->params_legacy.ssid_list,
				_params2->params_legacy.nssid)) < 0) {
			DHD_ERROR(("failed to add ssid list (err %d) in firmware\n", err));
			goto exit;
		}
	}
	if ((err = _dhd_pno_set(dhd, _params, DHD_PNO_BATCH_MODE)) < 0) {
		DHD_ERROR(("%s : failed to set call pno_set (err %d) in firmware\n",
			__FUNCTION__, err));
		goto exit;
	} else {
		/* we need to return mscan */
		mscan = err;
	}
	if (tot_nchan > 0) {
		if ((err = _dhd_pno_cfg(dhd, _chan_list, tot_nchan)) < 0) {
			DHD_ERROR(("%s : failed to set call pno_cfg (err %d) in firmware\n",
				__FUNCTION__, err));
			goto exit;
		}
	}
	if (_pno_state->pno_status == DHD_PNO_DISABLED) {
		if ((err = _dhd_pno_enable(dhd, PNO_ON)) < 0)
			DHD_ERROR(("%s : failed to enable PNO\n", __FUNCTION__));
	}
exit:
	/* clear mode in case of error */
	if (err < 0)
		_pno_state->pno_mode &= ~DHD_PNO_BATCH_MODE;
	else {
		/* return #max scan firmware can do */
		err = mscan;
	}
	return err;
}

#ifdef GSCAN_SUPPORT
