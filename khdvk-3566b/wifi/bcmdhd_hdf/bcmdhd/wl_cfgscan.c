/*
 * Linux cfg80211 driver scan related code
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
 * $Id$
 */
/* */
#include <typedefs.h>
#include <linuxver.h>
#include <osl.h>
#include <linux/kernel.h>

#include <bcmutils.h>
#include <bcmstdlib_s.h>
#include <bcmwifi_channels.h>
#include <bcmendian.h>
#include <ethernet.h>
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
#include <wl_cfgscan.h>
#include <wl_cfgp2p.h>
#include <bcmdevs.h>
#include <wl_android.h>
#include <dngl_stats.h>
#include <dhd.h>
#include <dhd_linux.h>
#include <dhd_debug.h>
#include <dhdioctl.h>
#include <wlioctl.h>
#include <dhd_cfg80211.h>
#include <dhd_bus.h>
#include <wl_cfgvendor.h>
#ifdef BCMPCIE
#include <dhd_flowring.h>
#endif // endif
#ifdef PNO_SUPPORT
#include <dhd_pno.h>
#endif /* PNO_SUPPORT */
#ifdef RTT_SUPPORT
#include "dhd_rtt.h"
#endif /* RTT_SUPPORT */
#include <dhd_config.h>
#ifdef CONFIG_AP6XXX_WIFI6_HDF
#include "hdf_mac80211_sta_event.h"
#endif

#define ACTIVE_SCAN 1
#define PASSIVE_SCAN 0

#define MIN_P2P_IE_LEN	8	/* p2p_ie->OUI(3) + p2p_ie->oui_type(1) +
				 * Attribute ID(1) + Length(2) + 1(Mininum length:1)
				 */
#define MAX_P2P_IE_LEN	251	/* Up To 251 */

#define WPS_ATTR_REQ_TYPE 0x103a
#define WPS_REQ_TYPE_ENROLLEE 0x01

#if defined(USE_INITIAL_2G_SCAN) || defined(USE_INITIAL_SHORT_DWELL_TIME)
#define FIRST_SCAN_ACTIVE_DWELL_TIME_MS 40
bool g_first_broadcast_scan = TRUE;
#endif /* USE_INITIAL_2G_SCAN || USE_INITIAL_SHORT_DWELL_TIME */
#ifdef P2P_LISTEN_OFFLOADING
void wl_cfg80211_cancel_p2plo(struct bcm_cfg80211 *cfg);
#endif /* P2P_LISTEN_OFFLOADING */
static void _wl_notify_scan_done(struct bcm_cfg80211 *cfg, bool aborted);

extern int passive_channel_skip;

#ifdef WL11U
static bcm_tlv_t *
wl_cfg80211_find_interworking_ie(const u8 *parse, u32 len)
{
	bcm_tlv_t *ie;

/* unfortunately it's too much work to dispose the const cast - bcm_parse_tlvs
 * is used everywhere and changing its prototype to take const qualifier needs
 * a massive change to all its callers...
 */

	if ((ie = bcm_parse_tlvs(parse, len, DOT11_MNG_INTERWORKING_ID))) {
		return ie;
	}
	return NULL;
}

static s32
wl_cfg80211_clear_iw_ie(struct bcm_cfg80211 *cfg, struct net_device *ndev, s32 bssidx)
{
	ie_setbuf_t ie_setbuf;

	WL_DBG(("clear interworking IE\n"));

	bzero(&ie_setbuf, sizeof(ie_setbuf_t));

	ie_setbuf.ie_buffer.iecount = htod32(1);
	ie_setbuf.ie_buffer.ie_list[0].ie_data.id = DOT11_MNG_INTERWORKING_ID;
	ie_setbuf.ie_buffer.ie_list[0].ie_data.len = 0;

	return wldev_iovar_setbuf_bsscfg(ndev, "ie", &ie_setbuf, sizeof(ie_setbuf),
		cfg->ioctl_buf, WLC_IOCTL_MAXLEN, bssidx, &cfg->ioctl_buf_sync);
}

static s32
wl_cfg80211_add_iw_ie(struct bcm_cfg80211 *cfg, struct net_device *ndev, s32 bssidx, s32 pktflag,
                      uint8 ie_id, uint8 *data, uint8 data_len)
{
	s32 err = BCME_OK;
	s32 buf_len;
	ie_setbuf_t *ie_setbuf;
	ie_getbuf_t ie_getbufp;
	char getbuf[WLC_IOCTL_SMLEN];

	if (ie_id != DOT11_MNG_INTERWORKING_ID) {
		WL_ERR(("unsupported (id=%d)\n", ie_id));
		return BCME_UNSUPPORTED;
	}

	/* access network options (1 octet)  is the mandatory field */
	if (!data || data_len == 0 || data_len > IW_IES_MAX_BUF_LEN) {
		WL_ERR(("wrong interworking IE (len=%d)\n", data_len));
		return BCME_BADARG;
	}

	/* Validate the pktflag parameter */
	if ((pktflag & ~(VNDR_IE_BEACON_FLAG | VNDR_IE_PRBRSP_FLAG |
			VNDR_IE_ASSOCRSP_FLAG | VNDR_IE_AUTHRSP_FLAG |
			VNDR_IE_PRBREQ_FLAG | VNDR_IE_ASSOCREQ_FLAG|
			VNDR_IE_CUSTOM_FLAG))) {
		WL_ERR(("invalid packet flag 0x%x\n", pktflag));
		return BCME_BADARG;
	}

	buf_len = sizeof(ie_setbuf_t) + data_len - 1;

	ie_getbufp.id = DOT11_MNG_INTERWORKING_ID;
	if (wldev_iovar_getbuf_bsscfg(ndev, "ie", (void *)&ie_getbufp,
			sizeof(ie_getbufp), getbuf, WLC_IOCTL_SMLEN, bssidx, &cfg->ioctl_buf_sync)
			== BCME_OK) {
		if (!memcmp(&getbuf[TLV_HDR_LEN], data, data_len)) {
			WL_DBG(("skip to set interworking IE\n"));
			return BCME_OK;
		}
	}

	/* if already set with previous values, delete it first */
	if (cfg->wl11u) {
		if ((err = wl_cfg80211_clear_iw_ie(cfg, ndev, bssidx)) != BCME_OK) {
			return err;
		}
	}

	ie_setbuf = (ie_setbuf_t *)MALLOCZ(cfg->osh, buf_len);
	if (!ie_setbuf) {
		WL_ERR(("Error allocating buffer for IE\n"));
		return -ENOMEM;
	}
	strlcpy(ie_setbuf->cmd, "add", sizeof(ie_setbuf->cmd));

	/* Buffer contains only 1 IE */
	ie_setbuf->ie_buffer.iecount = htod32(1);
	/* use VNDR_IE_CUSTOM_FLAG flags for none vendor IE . currently fixed value */
	ie_setbuf->ie_buffer.ie_list[0].pktflag = htod32(pktflag);

	/* Now, add the IE to the buffer */
	ie_setbuf->ie_buffer.ie_list[0].ie_data.id = DOT11_MNG_INTERWORKING_ID;
	ie_setbuf->ie_buffer.ie_list[0].ie_data.len = data_len;
	/* Returning void here as max data_len can be 8 */
	(void)memcpy_s((uchar *)&ie_setbuf->ie_buffer.ie_list[0].ie_data.data[0], sizeof(uint8),
		data, data_len);

	if ((err = wldev_iovar_setbuf_bsscfg(ndev, "ie", ie_setbuf, buf_len,
			cfg->ioctl_buf, WLC_IOCTL_MAXLEN, bssidx, &cfg->ioctl_buf_sync))
			== BCME_OK) {
		WL_DBG(("set interworking IE\n"));
		cfg->wl11u = TRUE;
		err = wldev_iovar_setint_bsscfg(ndev, "grat_arp", 1, bssidx);
	}

	MFREE(cfg->osh, ie_setbuf, buf_len);
	return err;
}
#endif /* WL11U */

#ifdef WL_BCNRECV
/* Beacon recv results handler sending to upper layer */
static s32
wl_bcnrecv_result_handler(struct bcm_cfg80211 *cfg, bcm_struct_cfgdev *cfgdev,
		wl_bss_info_v109_2_t *bi, uint32 scan_status)
{
	s32 err = BCME_OK;
	struct wiphy *wiphy = NULL;
	wl_bcnrecv_result_t *bcn_recv = NULL;
	struct osl_timespec ts;
	if (!bi) {
		WL_ERR(("%s: bi is NULL\n", __func__));
		err = BCME_NORESOURCE;
		goto exit;
	}
	if ((bi->length - bi->ie_length) < sizeof(wl_bss_info_v109_2_t)) {
		WL_ERR(("bi info version doesn't support bcn_recv attributes\n"));
		goto exit;
	}

	if (scan_status == WLC_E_STATUS_RXBCN) {
		wiphy = cfg->wdev->wiphy;
		if (!wiphy) {
			 WL_ERR(("wiphy is NULL\n"));
			 err = BCME_NORESOURCE;
			 goto exit;
		}
		bcn_recv = (wl_bcnrecv_result_t *)MALLOCZ(cfg->osh, sizeof(*bcn_recv));
		if (unlikely(!bcn_recv)) {
			WL_ERR(("Failed to allocate memory\n"));
			return -ENOMEM;
		}
		/* Returning void here as copy size does not exceed dest size of SSID */
		(void)memcpy_s((char *)bcn_recv->SSID, DOT11_MAX_SSID_LEN,
			(char *)bi->SSID, DOT11_MAX_SSID_LEN);
		/* Returning void here as copy size does not exceed dest size of ETH_LEN */
		(void)memcpy_s(&bcn_recv->BSSID, ETHER_ADDR_LEN, &bi->BSSID, ETH_ALEN);
		bcn_recv->channel = wf_chspec_ctlchan(
			wl_chspec_driver_to_host(bi->chanspec));
		bcn_recv->beacon_interval = bi->beacon_period;

		/* kernal timestamp */
		osl_get_monotonic_boottime(&ts);
		bcn_recv->system_time = ((u64)ts.tv_sec*1000000)
				+ ts.tv_nsec / 1000;
		bcn_recv->timestamp[0] = bi->timestamp[0];
		bcn_recv->timestamp[1] = bi->timestamp[1];
		if ((err = wl_android_bcnrecv_event(cfgdev_to_wlc_ndev(cfgdev, cfg),
				BCNRECV_ATTR_BCNINFO, 0, 0,
				(uint8 *)bcn_recv, sizeof(*bcn_recv)))
				!= BCME_OK) {
			WL_ERR(("failed to send bcnrecv event, error:%d\n", err));
		}
	} else {
		WL_DBG(("Ignoring Escan Event:%d \n", scan_status));
	}
exit:
	if (bcn_recv) {
		MFREE(cfg->osh, bcn_recv, sizeof(*bcn_recv));
	}
	return err;
}
#endif /* WL_BCNRECV */

#ifdef ESCAN_BUF_OVERFLOW_MGMT
#ifndef WL_DRV_AVOID_SCANCACHE
static void
wl_cfg80211_find_removal_candidate(wl_bss_info_t *bss, removal_element_t *candidate)
{
	int idx;
	for (idx = 0; idx < BUF_OVERFLOW_MGMT_COUNT; idx++) {
		int len = BUF_OVERFLOW_MGMT_COUNT - idx - 1;
		if (bss->RSSI < candidate[idx].RSSI) {
			if (len) {
				/* In the below memcpy operation the candidate array always has the
				* buffer space available to max 'len' calculated in the for loop.
				*/
				(void)memcpy_s(&candidate[idx + 1],
					(sizeof(removal_element_t) * len),
					&candidate[idx], sizeof(removal_element_t) * len);
			}
			candidate[idx].RSSI = bss->RSSI;
			candidate[idx].length = bss->length;
			(void)memcpy_s(&candidate[idx].BSSID, ETHER_ADDR_LEN,
				&bss->BSSID, ETHER_ADDR_LEN);
			return;
		}
	}
}

static void
wl_cfg80211_remove_lowRSSI_info(wl_scan_results_t *list, removal_element_t *candidate,
	wl_bss_info_t *bi)
{
	int idx1, idx2;
	int total_delete_len = 0;
	for (idx1 = 0; idx1 < BUF_OVERFLOW_MGMT_COUNT; idx1++) {
		int cur_len = WL_SCAN_RESULTS_FIXED_SIZE;
		wl_bss_info_t *bss = NULL;
		if (candidate[idx1].RSSI >= bi->RSSI)
			continue;
		for (idx2 = 0; idx2 < list->count; idx2++) {
			bss = bss ? (wl_bss_info_t *)((uintptr)bss + dtoh32(bss->length)) :
				list->bss_info;
			if (!bcmp(&candidate[idx1].BSSID, &bss->BSSID, ETHER_ADDR_LEN) &&
				candidate[idx1].RSSI == bss->RSSI &&
				candidate[idx1].length == dtoh32(bss->length)) {
				u32 delete_len = dtoh32(bss->length);
				WL_DBG(("delete scan info of " MACDBG " to add new AP\n",
					MAC2STRDBG(bss->BSSID.octet)));
				if (idx2 < list->count -1) {
					memmove((u8 *)bss, (u8 *)bss + delete_len,
						list->buflen - cur_len - delete_len);
				}
				list->buflen -= delete_len;
				list->count--;
				total_delete_len += delete_len;
				/* if delete_len is greater than or equal to result length */
				if (total_delete_len >= bi->length) {
					return;
				}
				break;
			}
			cur_len += dtoh32(bss->length);
		}
	}
}
#endif /* WL_DRV_AVOID_SCANCACHE */
#endif /* ESCAN_BUF_OVERFLOW_MGMT */

s32
wl_escan_handler(struct bcm_cfg80211 *cfg, bcm_struct_cfgdev *cfgdev,
	const wl_event_msg_t *e, void *data)
{
	s32 err = BCME_OK;
	s32 status = ntoh32(e->status);
	wl_escan_result_t *escan_result;
	struct net_device *ndev = NULL;
#ifndef WL_DRV_AVOID_SCANCACHE
	wl_bss_info_t *bi;
	u32 bi_length;
	const wifi_p2p_ie_t * p2p_ie;
	const u8 *p2p_dev_addr = NULL;
	wl_scan_results_t *list;
	wl_bss_info_t *bss = NULL;
	u32 i;
#endif /* WL_DRV_AVOID_SCANCACHE */
	u16 channel;
	struct ieee80211_supported_band *band;

	WL_DBG((" enter event type : %d, status : %d \n",
		ntoh32(e->event_type), ntoh32(e->status)));

	ndev = cfgdev_to_wlc_ndev(cfgdev, cfg);

	mutex_lock(&cfg->scan_sync);
	/* P2P SCAN is coming from primary interface */
	if (wl_get_p2p_status(cfg, SCANNING)) {
		if (wl_get_drv_status_all(cfg, SENDING_ACT_FRM))
			ndev = cfg->afx_hdl->dev;
		else
			ndev = cfg->escan_info.ndev;
	}
	escan_result = (wl_escan_result_t *)data;
#ifdef WL_BCNRECV
	if (cfg->bcnrecv_info.bcnrecv_state == BEACON_RECV_STARTED &&
		status == WLC_E_STATUS_RXBCN) {
		/* handle beacon recv scan results */
		wl_bss_info_v109_2_t *bi_info;
		bi_info = (wl_bss_info_v109_2_t *)escan_result->bss_info;
		err = wl_bcnrecv_result_handler(cfg, cfgdev, bi_info, status);
		goto exit;
	}
#endif /* WL_BCNRECV */
	if (!ndev || (!wl_get_drv_status(cfg, SCANNING, ndev) && !cfg->sched_scan_running)) {
		WL_ERR_RLMT(("escan is not ready. drv_scan_status 0x%x"
			" e_type %d e_states %d\n",
			wl_get_drv_status(cfg, SCANNING, ndev),
			ntoh32(e->event_type), ntoh32(e->status)));
		goto exit;
	}

#ifndef WL_DRV_AVOID_SCANCACHE
	if (status == WLC_E_STATUS_PARTIAL) {
		WL_DBG(("WLC_E_STATUS_PARTIAL \n"));
		DBG_EVENT_LOG((dhd_pub_t *)cfg->pub, WIFI_EVENT_DRIVER_SCAN_RESULT_FOUND);
		if (!escan_result) {
			WL_ERR(("Invalid escan result (NULL pointer)\n"));
			goto exit;
		}
		if ((dtoh32(escan_result->buflen) > (int)ESCAN_BUF_SIZE) ||
		    (dtoh32(escan_result->buflen) < sizeof(wl_escan_result_t))) {
			WL_ERR(("Invalid escan buffer len:%d\n", dtoh32(escan_result->buflen)));
			goto exit;
		}
		if (dtoh16(escan_result->bss_count) != 1) {
			WL_ERR(("Invalid bss_count %d: ignoring\n", escan_result->bss_count));
			goto exit;
		}
		bi = escan_result->bss_info;
		if (!bi) {
			WL_ERR(("Invalid escan bss info (NULL pointer)\n"));
			goto exit;
		}
		bi_length = dtoh32(bi->length);
		if (bi_length != (dtoh32(escan_result->buflen) - WL_ESCAN_RESULTS_FIXED_SIZE)) {
			WL_ERR(("Invalid bss_info length %d: ignoring\n", bi_length));
			goto exit;
		}

		/* +++++ terence 20130524: skip invalid bss */
		channel =
			bi->ctl_ch ? bi->ctl_ch : CHSPEC_CHANNEL(wl_chspec_driver_to_host(bi->chanspec));
		if (channel <= CH_MAX_2G_CHANNEL)
			band = bcmcfg_to_wiphy(cfg)->bands[IEEE80211_BAND_2GHZ];
		else
			band = bcmcfg_to_wiphy(cfg)->bands[IEEE80211_BAND_5GHZ];
		if (!band) {
			WL_ERR(("No valid band\n"));
			goto exit;
		}
		if (!dhd_conf_match_channel(cfg->pub, channel))
			goto exit;
		/* ----- terence 20130524: skip invalid bss */

		if (wl_escan_check_sync_id(status, escan_result->sync_id,
				cfg->escan_info.cur_sync_id) < 0)
			goto exit;

		if (!(bcmcfg_to_wiphy(cfg)->interface_modes & BIT(NL80211_IFTYPE_ADHOC))) {
			if (dtoh16(bi->capability) & DOT11_CAP_IBSS) {
				WL_DBG(("Ignoring IBSS result\n"));
				goto exit;
			}
		}

		if (wl_get_drv_status_all(cfg, FINDING_COMMON_CHANNEL)) {
			p2p_dev_addr = wl_cfgp2p_retreive_p2p_dev_addr(bi, bi_length);
			if (p2p_dev_addr && !memcmp(p2p_dev_addr,
				cfg->afx_hdl->tx_dst_addr.octet, ETHER_ADDR_LEN)) {
				s32 channel = wf_chspec_ctlchan(
					wl_chspec_driver_to_host(bi->chanspec));

				if ((channel > MAXCHANNEL) || (channel <= 0))
					channel = WL_INVALID;
				else
					WL_ERR(("ACTION FRAME SCAN : Peer " MACDBG " found,"
						" channel : %d\n",
						MAC2STRDBG(cfg->afx_hdl->tx_dst_addr.octet),
						channel));

				wl_clr_p2p_status(cfg, SCANNING);
				cfg->afx_hdl->peer_chan = channel;
				complete(&cfg->act_frm_scan);
				goto exit;
			}

		} else {
			int cur_len = WL_SCAN_RESULTS_FIXED_SIZE;
#ifdef ESCAN_BUF_OVERFLOW_MGMT
			removal_element_t candidate[BUF_OVERFLOW_MGMT_COUNT];
			int remove_lower_rssi = FALSE;

			bzero(candidate, sizeof(removal_element_t)*BUF_OVERFLOW_MGMT_COUNT);
#endif /* ESCAN_BUF_OVERFLOW_MGMT */

			list = wl_escan_get_buf(cfg, FALSE);
			if (scan_req_match(cfg)) {
#ifdef WL_HOST_BAND_MGMT
				s32 channel_band = 0;
				chanspec_t chspec;
#endif /* WL_HOST_BAND_MGMT */
				/* p2p scan && allow only probe response */
				if ((cfg->p2p->search_state != WL_P2P_DISC_ST_SCAN) &&
					(bi->flags & WL_BSS_FLAGS_FROM_BEACON))
					goto exit;
				if ((p2p_ie = wl_cfgp2p_find_p2pie(((u8 *) bi) + bi->ie_offset,
					bi->ie_length)) == NULL) {
						WL_ERR(("Couldn't find P2PIE in probe"
							" response/beacon\n"));
						goto exit;
				}
#ifdef WL_HOST_BAND_MGMT
				chspec = wl_chspec_driver_to_host(bi->chanspec);
				channel_band = CHSPEC2WLC_BAND(chspec);

				if ((cfg->curr_band == WLC_BAND_5G) &&
					(channel_band == WLC_BAND_2G)) {
					/* Avoid sending the GO results in band conflict */
					if (wl_cfgp2p_retreive_p2pattrib(p2p_ie,
						P2P_SEID_GROUP_ID) != NULL)
						goto exit;
				}
#endif /* WL_HOST_BAND_MGMT */
			}
#ifdef ESCAN_BUF_OVERFLOW_MGMT
			if (bi_length > ESCAN_BUF_SIZE - list->buflen)
				remove_lower_rssi = TRUE;
#endif /* ESCAN_BUF_OVERFLOW_MGMT */

			for (i = 0; i < list->count; i++) {
				bss = bss ? (wl_bss_info_t *)((uintptr)bss + dtoh32(bss->length))
					: list->bss_info;
				if (!bss) {
					WL_ERR(("bss is NULL\n"));
					goto exit;
				}
#ifdef ESCAN_BUF_OVERFLOW_MGMT
				WL_DBG(("%s("MACDBG"), i=%d bss: RSSI %d list->count %d\n",
					bss->SSID, MAC2STRDBG(bss->BSSID.octet),
					i, bss->RSSI, list->count));

				if (remove_lower_rssi)
					wl_cfg80211_find_removal_candidate(bss, candidate);
#endif /* ESCAN_BUF_OVERFLOW_MGMT */

				if (!bcmp(&bi->BSSID, &bss->BSSID, ETHER_ADDR_LEN) &&
					(CHSPEC_BAND(wl_chspec_driver_to_host(bi->chanspec))
					== CHSPEC_BAND(wl_chspec_driver_to_host(bss->chanspec))) &&
					bi->SSID_len == bss->SSID_len &&
					!bcmp(bi->SSID, bss->SSID, bi->SSID_len)) {

					/* do not allow beacon data to update
					*the data recd from a probe response
					*/
					if (!(bss->flags & WL_BSS_FLAGS_FROM_BEACON) &&
						(bi->flags & WL_BSS_FLAGS_FROM_BEACON))
						goto exit;

					WL_DBG(("%s("MACDBG"), i=%d prev: RSSI %d"
						" flags 0x%x, new: RSSI %d flags 0x%x\n",
						bss->SSID, MAC2STRDBG(bi->BSSID.octet), i,
						bss->RSSI, bss->flags, bi->RSSI, bi->flags));

					if ((bss->flags & WL_BSS_FLAGS_RSSI_ONCHANNEL) ==
						(bi->flags & WL_BSS_FLAGS_RSSI_ONCHANNEL)) {
						/* preserve max RSSI if the measurements are
						* both on-channel or both off-channel
						*/
						WL_DBG(("%s("MACDBG"), same onchan"
						", RSSI: prev %d new %d\n",
						bss->SSID, MAC2STRDBG(bi->BSSID.octet),
						bss->RSSI, bi->RSSI));
						bi->RSSI = MAX(bss->RSSI, bi->RSSI);
					} else if ((bss->flags & WL_BSS_FLAGS_RSSI_ONCHANNEL) &&
						(bi->flags & WL_BSS_FLAGS_RSSI_ONCHANNEL) == 0) {
						/* preserve the on-channel rssi measurement
						* if the new measurement is off channel
						*/
						WL_DBG(("%s("MACDBG"), prev onchan"
						", RSSI: prev %d new %d\n",
						bss->SSID, MAC2STRDBG(bi->BSSID.octet),
						bss->RSSI, bi->RSSI));
						bi->RSSI = bss->RSSI;
						bi->flags |= WL_BSS_FLAGS_RSSI_ONCHANNEL;
					}
					if (dtoh32(bss->length) != bi_length) {
						u32 prev_len = dtoh32(bss->length);

						WL_DBG(("bss info replacement"
							" is occured(bcast:%d->probresp%d)\n",
							bss->ie_length, bi->ie_length));
						WL_DBG(("%s("MACDBG"), replacement!(%d -> %d)\n",
						bss->SSID, MAC2STRDBG(bi->BSSID.octet),
						prev_len, bi_length));

						if ((list->buflen - prev_len) + bi_length
							> ESCAN_BUF_SIZE) {
							WL_ERR(("Buffer is too small: keep the"
								" previous result of this AP\n"));
							/* Only update RSSI */
							bss->RSSI = bi->RSSI;
							bss->flags |= (bi->flags
								& WL_BSS_FLAGS_RSSI_ONCHANNEL);
							goto exit;
						}

						if (i < list->count - 1) {
							/* memory copy required by this case only */
							memmove((u8 *)bss + bi_length,
								(u8 *)bss + prev_len,
								list->buflen - cur_len - prev_len);
						}
						list->buflen -= prev_len;
						list->buflen += bi_length;
					}
					list->version = dtoh32(bi->version);
					/* In the above code under check
					*  '(dtoh32(bss->length) != bi_length)'
					* buffer overflow is avoided. bi_length
					* is already accounted in list->buflen
					*/
					if ((err = memcpy_s((u8 *)bss,
						(ESCAN_BUF_SIZE - (list->buflen - bi_length)),
						(u8 *)bi, bi_length)) != BCME_OK) {
						WL_ERR(("Failed to copy the recent bss_info."
							"err:%d recv_len:%d bi_len:%d\n", err,
							ESCAN_BUF_SIZE - (list->buflen - bi_length),
							bi_length));
						/* This scenario should never happen. If it happens,
						 * set list->count to zero for recovery
						 */
						list->count = 0;
						list->buflen = 0;
						ASSERT(0);
					}
					goto exit;
				}
				cur_len += dtoh32(bss->length);
			}
			if (bi_length > ESCAN_BUF_SIZE - list->buflen) {
#ifdef ESCAN_BUF_OVERFLOW_MGMT
				wl_cfg80211_remove_lowRSSI_info(list, candidate, bi);
				if (bi_length > ESCAN_BUF_SIZE - list->buflen) {
					WL_DBG(("RSSI(" MACDBG ") is too low(%d) to add Buffer\n",
						MAC2STRDBG(bi->BSSID.octet), bi->RSSI));
					goto exit;
				}
#else
				WL_ERR(("Buffer is too small: ignoring\n"));
				goto exit;
#endif /* ESCAN_BUF_OVERFLOW_MGMT */
			}
			/* In the previous step check is added to ensure the bi_legth does not
			* exceed the ESCAN_BUF_SIZE
			*/
			(void)memcpy_s(&(((char *)list)[list->buflen]),
				(ESCAN_BUF_SIZE - list->buflen), bi, bi_length);
			list->version = dtoh32(bi->version);
			list->buflen += bi_length;
			list->count++;

			/*
			 * !Broadcast && number of ssid = 1 && number of channels =1
			 * means specific scan to association
			 */
			if (wl_cfgp2p_is_p2p_specific_scan(cfg->scan_request)) {
				WL_ERR(("P2P assoc scan fast aborted.\n"));
				wl_notify_escan_complete(cfg, cfg->escan_info.ndev, false, true);
				goto exit;
			}
		}
	}
	else if (status == WLC_E_STATUS_SUCCESS) {
		cfg->escan_info.escan_state = WL_ESCAN_STATE_IDLE;
		wl_escan_print_sync_id(status, cfg->escan_info.cur_sync_id,
			escan_result->sync_id);

		if (wl_get_drv_status_all(cfg, FINDING_COMMON_CHANNEL)) {
			WL_DBG(("ACTION FRAME SCAN DONE\n"));
			wl_clr_p2p_status(cfg, SCANNING);
			wl_clr_drv_status(cfg, SCANNING, cfg->afx_hdl->dev);
			if (cfg->afx_hdl->peer_chan == WL_INVALID)
				complete(&cfg->act_frm_scan);
		} else if ((likely(cfg->scan_request)) || (cfg->sched_scan_running)) {
			WL_INFORM_MEM(("ESCAN COMPLETED\n"));
			DBG_EVENT_LOG((dhd_pub_t *)cfg->pub, WIFI_EVENT_DRIVER_SCAN_COMPLETE);
			cfg->bss_list = wl_escan_get_buf(cfg, FALSE);
			if (!scan_req_match(cfg)) {
				WL_DBG(("SCAN COMPLETED: scanned AP count=%d\n",
					cfg->bss_list->count));
			}
			wl_inform_bss(cfg);
			wl_notify_escan_complete(cfg, ndev, false, false);
#ifdef CONFIG_AP6XXX_WIFI6_HDF
			printk("scan done success!\n");
			HdfScanEventCallback(ndev, HDF_WIFI_SCAN_SUCCESS);
#endif
		}
		wl_escan_increment_sync_id(cfg, SCAN_BUF_NEXT);
	} else if ((status == WLC_E_STATUS_ABORT) || (status == WLC_E_STATUS_NEWSCAN) ||
		(status == WLC_E_STATUS_11HQUIET) || (status == WLC_E_STATUS_CS_ABORT) ||
		(status == WLC_E_STATUS_NEWASSOC)) {
#ifdef CONFIG_AP6XXX_WIFI6_HDF
		printk("scan abort status=%d\n", status);
        //HdfScanEventCallback(ndev, HDF_WIFI_SCAN_FAILED);
#endif
		/* Dump FW preserve buffer content */
		if (status == WLC_E_STATUS_ABORT) {
			wl_flush_fw_log_buffer(ndev, FW_LOGSET_MASK_ALL);
		}
		/* Handle all cases of scan abort */
		cfg->escan_info.escan_state = WL_ESCAN_STATE_IDLE;
		wl_escan_print_sync_id(status, escan_result->sync_id,
			cfg->escan_info.cur_sync_id);
		WL_DBG(("ESCAN ABORT reason: %d\n", status));
		if (wl_get_drv_status_all(cfg, FINDING_COMMON_CHANNEL)) {
			WL_DBG(("ACTION FRAME SCAN DONE\n"));
			wl_clr_drv_status(cfg, SCANNING, cfg->afx_hdl->dev);
			wl_clr_p2p_status(cfg, SCANNING);
			if (cfg->afx_hdl->peer_chan == WL_INVALID)
				complete(&cfg->act_frm_scan);
		} else if ((likely(cfg->scan_request)) || (cfg->sched_scan_running)) {
			WL_INFORM_MEM(("ESCAN ABORTED\n"));

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
			if (p2p_scan(cfg) && cfg->scan_request &&
				(cfg->scan_request->flags & NL80211_SCAN_FLAG_FLUSH)) {
				WL_ERR(("scan list is changed"));
				cfg->bss_list = wl_escan_get_buf(cfg, FALSE);
			} else
#endif // endif
				cfg->bss_list = wl_escan_get_buf(cfg, TRUE);

			if (!scan_req_match(cfg)) {
				WL_TRACE_HW4(("SCAN ABORTED: scanned AP count=%d\n",
					cfg->bss_list->count));
			}
#ifdef DUAL_ESCAN_RESULT_BUFFER
			if (escan_result->sync_id != cfg->escan_info.cur_sync_id) {
				/* If sync_id is not matching, then the abort might have
				 * come for the old scan req or for the in-driver initiated
				 * scan. So do abort for scan_req for which sync_id is
				 * matching.
				 */
				WL_INFORM_MEM(("sync_id mismatch (%d != %d). "
					"Ignore the scan abort event.\n",
					escan_result->sync_id, cfg->escan_info.cur_sync_id));
				goto exit;
			} else {
				/* sync id is matching, abort the scan */
				WL_INFORM_MEM(("scan aborted for sync_id: %d \n",
					cfg->escan_info.cur_sync_id));
				wl_inform_bss(cfg);
				wl_notify_escan_complete(cfg, ndev, true, false);
			}
#else
			wl_inform_bss(cfg);
			wl_notify_escan_complete(cfg, ndev, true, false);
#endif /* DUAL_ESCAN_RESULT_BUFFER */
		} else {
			/* If there is no pending host initiated scan, do nothing */
			WL_DBG(("ESCAN ABORT: No pending scans. Ignoring event.\n"));
		}
		wl_escan_increment_sync_id(cfg, SCAN_BUF_CNT);
	} else if (status == WLC_E_STATUS_TIMEOUT) {
#ifdef CONFIG_AP6XXX_WIFI6_HDF
		HdfScanEventCallback(ndev, HDF_WIFI_SCAN_TIMEOUT); 
#endif
		WL_ERR(("WLC_E_STATUS_TIMEOUT : scan_request[%p]\n", cfg->scan_request));
		WL_ERR(("reason[0x%x]\n", e->reason));
		if (e->reason == 0xFFFFFFFF) {
			wl_notify_escan_complete(cfg, cfg->escan_info.ndev, true, true);
		}
	} else {
#ifdef CONFIG_AP6XXX_WIFI6_HDF
		printk("scan failed 3\n");
        HdfScanEventCallback(ndev, HDF_WIFI_SCAN_FAILED); 
#endif
		WL_ERR(("unexpected Escan Event %d : abort\n", status));
		cfg->escan_info.escan_state = WL_ESCAN_STATE_IDLE;
		wl_escan_print_sync_id(status, escan_result->sync_id,
			cfg->escan_info.cur_sync_id);
		if (wl_get_drv_status_all(cfg, FINDING_COMMON_CHANNEL)) {
			WL_DBG(("ACTION FRAME SCAN DONE\n"));
			wl_clr_p2p_status(cfg, SCANNING);
			wl_clr_drv_status(cfg, SCANNING, cfg->afx_hdl->dev);
			if (cfg->afx_hdl->peer_chan == WL_INVALID)
				complete(&cfg->act_frm_scan);
		} else if ((likely(cfg->scan_request)) || (cfg->sched_scan_running)) {
			cfg->bss_list = wl_escan_get_buf(cfg, TRUE);
			if (!scan_req_match(cfg)) {
				WL_TRACE_HW4(("SCAN ABORTED(UNEXPECTED): "
					"scanned AP count=%d\n",
					cfg->bss_list->count));
			}
			wl_inform_bss(cfg);
			wl_notify_escan_complete(cfg, ndev, true, false);
		}
		wl_escan_increment_sync_id(cfg, 2);
	}
#else /* WL_DRV_AVOID_SCANCACHE */
	err = wl_escan_without_scan_cache(cfg, escan_result, ndev, e, status);
#endif /* WL_DRV_AVOID_SCANCACHE */
exit:
	mutex_unlock(&cfg->scan_sync);
	return err;
}

/* Find listen channel */
static s32 wl_find_listen_channel(struct bcm_cfg80211 *cfg,
	const u8 *ie, u32 ie_len)
{
	const wifi_p2p_ie_t *p2p_ie;
	const u8 *end, *pos;
	s32 listen_channel;

	pos = (const u8 *)ie;

	p2p_ie = wl_cfgp2p_find_p2pie(pos, ie_len);

	if (p2p_ie == NULL) {
		return 0;
	}

	if (p2p_ie->len < MIN_P2P_IE_LEN || p2p_ie->len > MAX_P2P_IE_LEN) {
		CFGP2P_ERR(("p2p_ie->len out of range - %d\n", p2p_ie->len));
		return 0;
	}
	pos = p2p_ie->subelts;
	end = p2p_ie->subelts + (p2p_ie->len - 4);

	CFGP2P_DBG((" found p2p ie ! lenth %d \n",
		p2p_ie->len));

	while (pos < end) {
		uint16 attr_len;
		if (pos + 2 >= end) {
			CFGP2P_DBG((" -- Invalid P2P attribute"));
			return 0;
		}
		attr_len = ((uint16) (((pos + 1)[1] << 8) | (pos + 1)[0]));

		if (pos + 3 + attr_len > end) {
			CFGP2P_DBG(("P2P: Attribute underflow "
				   "(len=%u left=%d)",
				   attr_len, (int) (end - pos - 3)));
			return 0;
		}

		/* if Listen Channel att id is 6 and the vailue is valid,
		 * return the listen channel
		 */
		if (pos[0] == 6) {
			/* listen channel subel length format
			 * 1(id) + 2(len) + 3(country) + 1(op. class) + 1(chan num)
			 */
			listen_channel = pos[1 + 2 + 3 + 1];

			if (listen_channel == SOCIAL_CHAN_1 ||
				listen_channel == SOCIAL_CHAN_2 ||
				listen_channel == SOCIAL_CHAN_3) {
				CFGP2P_DBG((" Found my Listen Channel %d \n", listen_channel));
				return listen_channel;
			}
		}
		pos += 3 + attr_len;
	}
	return 0;
}

#ifdef WL_SCAN_TYPE
static u32
wl_cfgscan_map_nl80211_scan_type(struct bcm_cfg80211 *cfg, struct cfg80211_scan_request *request)
{
	u32 scan_flags = 0;

	if (!request) {
		return scan_flags;
	}

	if (request->flags & NL80211_SCAN_FLAG_LOW_SPAN) {
		scan_flags |= WL_SCANFLAGS_LOW_SPAN;
	}
	if (request->flags & NL80211_SCAN_FLAG_HIGH_ACCURACY) {
		scan_flags |= WL_SCANFLAGS_HIGH_ACCURACY;
	}
	if (request->flags & NL80211_SCAN_FLAG_LOW_POWER) {
		scan_flags |= WL_SCANFLAGS_LOW_POWER_SCAN;
	}
	if (request->flags & NL80211_SCAN_FLAG_LOW_PRIORITY) {
		scan_flags |= WL_SCANFLAGS_LOW_PRIO;
	}

	WL_INFORM(("scan flags. wl:%x cfg80211:%x\n", scan_flags, request->flags));
	return scan_flags;
}
#endif /* WL_SCAN_TYPE */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0))
#define IS_RADAR_CHAN(flags) (flags & (IEEE80211_CHAN_RADAR | IEEE80211_CHAN_PASSIVE_SCAN))
#else
#define IS_RADAR_CHAN(flags) (flags & (IEEE80211_CHAN_RADAR | IEEE80211_CHAN_NO_IR))
#endif // endif
static void
wl_cfgscan_populate_scan_channels(struct bcm_cfg80211 *cfg, u16 *channel_list,
	struct cfg80211_scan_request *request, u32 *num_channels)
{
	u32 i = 0, j = 0;
	u32 channel;
	u32 n_channels = 0;
	u32 chanspec = 0;

	if (!request || !request->n_channels) {
		/* Do full channel scan */
		return;
	}

	n_channels = request->n_channels;
	for (i = 0; i < n_channels; i++) {
			channel = ieee80211_frequency_to_channel(request->channels[i]->center_freq);
			/* SKIP DFS channels for Secondary interface */
			if ((cfg->escan_info.ndev != bcmcfg_to_prmry_ndev(cfg)) &&
				(IS_RADAR_CHAN(request->channels[i]->flags)))
				continue;
			if (!dhd_conf_match_channel(cfg->pub, channel))
				continue;

			chanspec = WL_CHANSPEC_BW_20;
			if (chanspec == INVCHANSPEC) {
				WL_ERR(("Invalid chanspec! Skipping channel\n"));
				continue;
			}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0))
			if (request->channels[i]->band == IEEE80211_BAND_60GHZ) {
				/* Not supported */
				continue;
			}
#endif /* LINUX_VER >= 3.6 */

			if (request->channels[i]->band == IEEE80211_BAND_2GHZ) {
#ifdef WL_HOST_BAND_MGMT
				if (cfg->curr_band == WLC_BAND_5G) {
					WL_DBG(("In 5G only mode, omit 2G channel:%d\n", channel));
					continue;
				}
#endif /* WL_HOST_BAND_MGMT */
				chanspec |= WL_CHANSPEC_BAND_2G;
			} else {
#ifdef WL_HOST_BAND_MGMT
				if (cfg->curr_band == WLC_BAND_2G) {
					WL_DBG(("In 2G only mode, omit 5G channel:%d\n", channel));
					continue;
				}
#endif /* WL_HOST_BAND_MGMT */
				chanspec |= WL_CHANSPEC_BAND_5G;
			}
			channel_list[j] = channel;
			channel_list[j] &= WL_CHANSPEC_CHAN_MASK;
			channel_list[j] |= chanspec;
			WL_SCAN(("Chan : %d, Channel spec: %x \n",
				channel, channel_list[j]));
			channel_list[j] = wl_chspec_host_to_driver(channel_list[j]);
			j++;
	}
	*num_channels = j;

}

static void
wl_cfgscan_populate_scan_ssids(struct bcm_cfg80211 *cfg, u8 *buf_ptr, u32 buf_len,
	struct cfg80211_scan_request *request, u32 *ssid_num)
{
	u32 n_ssids;
	wlc_ssid_t ssid;
	int i, j = 0;

	if (!request || !buf_ptr) {
		/* Do full channel scan */
		return;
	}

	n_ssids = request->n_ssids;
	if (n_ssids > 0) {

		if (buf_len < (n_ssids * sizeof(wlc_ssid_t))) {
			WL_ERR(("buf len not sufficient for scan ssids\n"));
			return;
		}

		for (i = 0; i < n_ssids; i++) {
			bzero(&ssid, sizeof(wlc_ssid_t));
			ssid.SSID_len = MIN(request->ssids[i].ssid_len, DOT11_MAX_SSID_LEN);
			/* Returning void here, as per previous line copy length does not exceed
			* DOT11_MAX_SSID_LEN
			*/
			(void)memcpy_s(ssid.SSID, DOT11_MAX_SSID_LEN, request->ssids[i].ssid,
				ssid.SSID_len);
			if (!ssid.SSID_len) {
				WL_SCAN(("%d: Broadcast scan\n", i));
			} else {
				WL_SCAN(("%d: scan  for  %s size =%d\n", i,
				ssid.SSID, ssid.SSID_len));
			}
			/* For multiple ssid case copy the each SSID info the ptr below corresponds
			* to that so dest is of type wlc_ssid_t
			*/
			(void)memcpy_s(buf_ptr, sizeof(wlc_ssid_t), &ssid, sizeof(wlc_ssid_t));
			buf_ptr += sizeof(wlc_ssid_t);
			j++;
		}
	} else {
		WL_SCAN(("Broadcast scan\n"));
	}
	*ssid_num = j;
}

static s32
wl_scan_prep(struct bcm_cfg80211 *cfg, struct net_device *ndev, void *scan_params, u32 len,
	struct cfg80211_scan_request *request)
{
#ifdef SCAN_SUPPRESS
	u32 channel;
#endif
	wl_scan_params_t *params = NULL;
	wl_scan_params_v2_t *params_v2 = NULL;
	u32 scan_type = 0;
	u32 scan_param_size = 0;
	u32 n_channels = 0;
	u32 n_ssids = 0;
	uint16 *chan_list = NULL;
	u32 channel_offset = 0;
	u32 cur_offset;

	if (!scan_params) {
		return BCME_ERROR;
	}

	if (cfg->active_scan == PASSIVE_SCAN) {
		WL_INFORM_MEM(("Enforcing passive scan\n"));
		scan_type = WL_SCANFLAGS_PASSIVE;
	}

	WL_DBG(("Preparing Scan request\n"));
	if (cfg->scan_params_v2) {
		params_v2 = (wl_scan_params_v2_t *)scan_params;
		scan_param_size = sizeof(wl_scan_params_v2_t);
		channel_offset = offsetof(wl_scan_params_v2_t, channel_list);
	} else {
		params = (wl_scan_params_t *)scan_params;
		scan_param_size = sizeof(wl_scan_params_t);
		channel_offset = offsetof(wl_scan_params_t, channel_list);
	}

	if (params_v2) {
		/* scan params ver2 */
#if defined(WL_SCAN_TYPE)
		scan_type  += wl_cfgscan_map_nl80211_scan_type(cfg, request);
#endif /* WL_SCAN_TYPE */

		(void)memcpy_s(&params_v2->bssid, ETHER_ADDR_LEN, &ether_bcast, ETHER_ADDR_LEN);
		params_v2->version = htod16(WL_SCAN_PARAMS_VERSION_V2);
		params_v2->length = htod16(sizeof(wl_scan_params_v2_t));
		params_v2->bss_type = DOT11_BSSTYPE_ANY;
		params_v2->scan_type = htod32(scan_type);
		params_v2->nprobes = htod32(-1);
		params_v2->active_time = htod32(-1);
		params_v2->passive_time = htod32(-1);
		params_v2->home_time = htod32(-1);
		params_v2->channel_num = 0;
		bzero(&params_v2->ssid, sizeof(wlc_ssid_t));
		chan_list = params_v2->channel_list;
	} else {
		/* scan params ver 1 */
		if (!params) {
			ASSERT(0);
			return BCME_ERROR;
		}
		(void)memcpy_s(&params->bssid, ETHER_ADDR_LEN, &ether_bcast, ETHER_ADDR_LEN);
		params->bss_type = DOT11_BSSTYPE_ANY;
		params->scan_type = 0;
		params->nprobes = htod32(-1);
		params->active_time = htod32(-1);
		params->passive_time = htod32(-1);
		params->home_time = htod32(-1);
		params->channel_num = 0;
		bzero(&params->ssid, sizeof(wlc_ssid_t));
		chan_list = params->channel_list;
	}

	if (!request) {
		/* scan_request null, do scan based on base config */
		WL_DBG(("scan_request is null\n"));
		return BCME_OK;
	}

	WL_INFORM(("n_channels:%d n_ssids:%d\n", request->n_channels, request->n_ssids));

	cur_offset = channel_offset;
	/* Copy channel array if applicable */
#ifdef SCAN_SUPPRESS
	channel = wl_ext_scan_suppress(ndev, scan_params, cfg->scan_params_v2);
	if (channel) {
		n_channels = 1;
		if ((n_channels > 0) && chan_list) {
			if (len >= (scan_param_size + (n_channels * sizeof(u16)))) {
				wl_ext_populate_scan_channel(cfg->pub, chan_list, channel, n_channels);
				cur_offset += (n_channels * (sizeof(u16)));
			}
		}
	} else
#endif
	{
		if ((request->n_channels > 0) && chan_list) {
			if (len >= (scan_param_size + (request->n_channels * sizeof(u16)))) {
				wl_cfgscan_populate_scan_channels(cfg,
						chan_list, request, &n_channels);
				cur_offset += (n_channels * (sizeof(u16)));
			}
		}
	}

	/* Copy ssid array if applicable */
	if (request->n_ssids > 0) {
		cur_offset = (u32) roundup(cur_offset, sizeof(u32));
		if (len > (cur_offset + (request->n_ssids * sizeof(wlc_ssid_t)))) {
			u32 rem_len = len - cur_offset;
			wl_cfgscan_populate_scan_ssids(cfg,
				((u8 *)scan_params + cur_offset), rem_len, request, &n_ssids);
		}
	}

	if (n_ssids || n_channels) {
		u32 channel_num =
				htod32((n_ssids << WL_SCAN_PARAMS_NSSID_SHIFT) |
				(n_channels & WL_SCAN_PARAMS_COUNT_MASK));
		if (params_v2) {
			params_v2->channel_num = channel_num;
			if (n_channels == 1) {
				params_v2->active_time = htod32(WL_SCAN_CONNECT_DWELL_TIME_MS);
				params_v2->nprobes = htod32(
					params_v2->active_time / WL_SCAN_JOIN_PROBE_INTERVAL_MS);
			}
		} else {
			params->channel_num = channel_num;
			if (n_channels == 1) {
				params->active_time = htod32(WL_SCAN_CONNECT_DWELL_TIME_MS);
				params->nprobes = htod32(
					params->active_time / WL_SCAN_JOIN_PROBE_INTERVAL_MS);
			}
		}
	}

	WL_INFORM(("scan_prep done. n_channels:%d n_ssids:%d\n", n_channels, n_ssids));
	return BCME_OK;
}

static s32
wl_get_valid_channels(struct net_device *ndev, u8 *valid_chan_list, s32 size)
{
	wl_uint32_list_t *list;
	s32 err = BCME_OK;
	if (valid_chan_list == NULL || size <= 0)
		return -ENOMEM;

	bzero(valid_chan_list, size);
	list = (wl_uint32_list_t *)(void *) valid_chan_list;
	list->count = htod32(WL_NUMCHANNELS);
	err = wldev_ioctl_get(ndev, WLC_GET_VALID_CHANNELS, valid_chan_list, size);
	if (err != 0) {
		WL_ERR(("get channels failed with %d\n", err));
	}

	return err;
}

static s32
wl_run_escan(struct bcm_cfg80211 *cfg, struct net_device *ndev,
	struct cfg80211_scan_request *request, uint16 action)
{
	s32 err = BCME_OK;
	u32 n_channels;
	u32 n_ssids;
	s32 params_size;
	wl_escan_params_t *eparams = NULL;
	wl_escan_params_v2_t *eparams_v2 = NULL;
	u8 *scan_params = NULL;
	u8 *params = NULL;
	u8 chan_buf[sizeof(u32)*(WL_NUMCHANNELS + 1)];
	u32 num_chans = 0;
	s32 channel;
	u32 n_valid_chan;
	s32 search_state = WL_P2P_DISC_ST_SCAN;
	u32 i, j, n_nodfs = 0;
	u16 *default_chan_list = NULL;
	wl_uint32_list_t *list;
	s32 bssidx = -1;
	struct net_device *dev = NULL;
#if defined(USE_INITIAL_2G_SCAN) || defined(USE_INITIAL_SHORT_DWELL_TIME)
	bool is_first_init_2g_scan = false;
#endif /* USE_INITIAL_2G_SCAN || USE_INITIAL_SHORT_DWELL_TIME */
	p2p_scan_purpose_t	p2p_scan_purpose = P2P_SCAN_PURPOSE_MIN;
	u32 chan_mem = 0;
	u32 sync_id = 0;

	WL_DBG(("Enter \n"));

	/* scan request can come with empty request : perform all default scan */
	if (!cfg) {
		err = -EINVAL;
		goto exit;
	}

	if (cfg->scan_params_v2) {
		params_size = (WL_SCAN_PARAMS_V2_FIXED_SIZE +
				OFFSETOF(wl_escan_params_v2_t, params));
	} else {
		params_size = (WL_SCAN_PARAMS_FIXED_SIZE + OFFSETOF(wl_escan_params_t, params));
	}

	if (!cfg->p2p_supported || !p2p_scan(cfg)) {
		/* LEGACY SCAN TRIGGER */
		WL_SCAN((" LEGACY E-SCAN START\n"));

#if defined(USE_INITIAL_2G_SCAN) || defined(USE_INITIAL_SHORT_DWELL_TIME)
		if (!request) {
			err = -EINVAL;
			goto exit;
		}
		if (ndev == bcmcfg_to_prmry_ndev(cfg) && g_first_broadcast_scan == true) {
#ifdef USE_INITIAL_2G_SCAN
			struct ieee80211_channel tmp_channel_list[CH_MAX_2G_CHANNEL];
			/* allow one 5G channel to add previous connected channel in 5G */
			bool allow_one_5g_channel = TRUE;
			j = 0;
			for (i = 0; i < request->n_channels; i++) {
				int tmp_chan = ieee80211_frequency_to_channel
					(request->channels[i]->center_freq);
				if (tmp_chan > CH_MAX_2G_CHANNEL) {
					if (allow_one_5g_channel)
						allow_one_5g_channel = FALSE;
					else
						continue;
				}
				if (j > CH_MAX_2G_CHANNEL) {
					WL_ERR(("Index %d exceeds max 2.4GHz channels %d"
						" and previous 5G connected channel\n",
						j, CH_MAX_2G_CHANNEL));
					break;
				}
				bcopy(request->channels[i], &tmp_channel_list[j],
					sizeof(struct ieee80211_channel));
				WL_SCAN(("channel of request->channels[%d]=%d\n", i, tmp_chan));
				j++;
			}
			if ((j > 0) && (j <= CH_MAX_2G_CHANNEL)) {
				for (i = 0; i < j; i++)
					bcopy(&tmp_channel_list[i], request->channels[i],
						sizeof(struct ieee80211_channel));

				request->n_channels = j;
				is_first_init_2g_scan = true;
			}
			else
				WL_ERR(("Invalid number of 2.4GHz channels %d\n", j));

			WL_SCAN(("request->n_channels=%d\n", request->n_channels));
#else /* USE_INITIAL_SHORT_DWELL_TIME */
			is_first_init_2g_scan = true;
#endif /* USE_INITIAL_2G_SCAN */
			g_first_broadcast_scan = false;
		}
#endif /* USE_INITIAL_2G_SCAN || USE_INITIAL_SHORT_DWELL_TIME */

		/* if scan request is not empty parse scan request paramters */
		if (request != NULL) {
			n_channels = request->n_channels;
			n_ssids = request->n_ssids;
			if (n_channels % 2)
				/* If n_channels is odd, add a padd of u16 */
				params_size += sizeof(u16) * (n_channels + 1);
			else
				params_size += sizeof(u16) * n_channels;

			/* Allocate space for populating ssids in wl_escan_params_t struct */
			params_size += sizeof(struct wlc_ssid) * n_ssids;
		}
		params = MALLOCZ(cfg->osh, params_size);
		if (params == NULL) {
			err = -ENOMEM;
			goto exit;
		}

		wl_escan_set_sync_id(sync_id, cfg);
		if (cfg->scan_params_v2) {
			eparams_v2 = (wl_escan_params_v2_t *)params;
			scan_params = (u8 *)&eparams_v2->params;
			eparams_v2->version = htod32(ESCAN_REQ_VERSION_V2);
			eparams_v2->action =  htod16(action);
			eparams_v2->sync_id = sync_id;
		} else {
			eparams = (wl_escan_params_t *)params;
			scan_params = (u8 *)&eparams->params;
			eparams->version = htod32(ESCAN_REQ_VERSION);
			eparams->action =  htod16(action);
			eparams->sync_id = sync_id;
		}

		if (wl_scan_prep(cfg, ndev, scan_params, params_size, request) < 0) {
			WL_ERR(("scan_prep failed\n"));
			err = -EINVAL;
			goto exit;
		}

#if defined(USE_INITIAL_2G_SCAN) || defined(USE_INITIAL_SHORT_DWELL_TIME)
		/* Override active_time to reduce scan time if it's first bradcast scan. */
		if (is_first_init_2g_scan) {
			if (eparams_v2) {
				eparams_v2->params.active_time = FIRST_SCAN_ACTIVE_DWELL_TIME_MS;
			} else {
				eparams->params.active_time = FIRST_SCAN_ACTIVE_DWELL_TIME_MS;
			}
		}
#endif /* USE_INITIAL_2G_SCAN || USE_INITIAL_SHORT_DWELL_TIME */

		wl_escan_set_type(cfg, WL_SCANTYPE_LEGACY);
		if (params_size + sizeof("escan") >= WLC_IOCTL_MEDLEN) {
			WL_ERR(("ioctl buffer length not sufficient\n"));
			MFREE(cfg->osh, params, params_size);
			err = -ENOMEM;
			goto exit;
		}

		bssidx = wl_get_bssidx_by_wdev(cfg, ndev->ieee80211_ptr);
		WL_MSG(ndev->name, "LEGACY_SCAN sync ID: %d, bssidx: %d\n", sync_id, bssidx);
		err = wldev_iovar_setbuf(ndev, "escan", params, params_size,
			cfg->escan_ioctl_buf, WLC_IOCTL_MEDLEN, NULL);
		if (unlikely(err)) {
			if (err == BCME_EPERM)
				/* Scan Not permitted at this point of time */
				WL_DBG((" Escan not permitted at this time (%d)\n", err));
			else
				WL_ERR((" Escan set error (%d)\n", err));
		} else {
			DBG_EVENT_LOG((dhd_pub_t *)cfg->pub, WIFI_EVENT_DRIVER_SCAN_REQUESTED);
		}
		MFREE(cfg->osh, params, params_size);
	}
	else if (p2p_is_on(cfg) && p2p_scan(cfg)) {
		/* P2P SCAN TRIGGER */
		s32 _freq = 0;
		n_nodfs = 0;

		if (request && request->n_channels) {
			num_chans = request->n_channels;
			WL_SCAN((" chann number : %d\n", num_chans));
			chan_mem = (u32)(num_chans * sizeof(*default_chan_list));
			default_chan_list = MALLOCZ(cfg->osh, chan_mem);
			if (default_chan_list == NULL) {
				WL_ERR(("channel list allocation failed \n"));
				err = -ENOMEM;
				goto exit;
			}
			if (!wl_get_valid_channels(ndev, chan_buf, sizeof(chan_buf))) {
#ifdef P2P_SKIP_DFS
				int is_printed = false;
#endif /* P2P_SKIP_DFS */
				list = (wl_uint32_list_t *) chan_buf;
				n_valid_chan = dtoh32(list->count);
				if (n_valid_chan > WL_NUMCHANNELS) {
					WL_ERR(("wrong n_valid_chan:%d\n", n_valid_chan));
					MFREE(cfg->osh, default_chan_list, chan_mem);
					err = -EINVAL;
					goto exit;
				}

				for (i = 0; i < num_chans; i++)
				{
#ifdef WL_HOST_BAND_MGMT
					int channel_band = 0;
#endif /* WL_HOST_BAND_MGMT */
					_freq = request->channels[i]->center_freq;
					channel = ieee80211_frequency_to_channel(_freq);
#ifdef WL_HOST_BAND_MGMT
					channel_band = (channel > CH_MAX_2G_CHANNEL) ?
						WLC_BAND_5G : WLC_BAND_2G;
					if ((cfg->curr_band != WLC_BAND_AUTO) &&
						(cfg->curr_band != channel_band) &&
						!IS_P2P_SOCIAL_CHANNEL(channel))
							continue;
#endif /* WL_HOST_BAND_MGMT */

					/* ignore DFS channels */
					if (request->channels[i]->flags &
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0))
						(IEEE80211_CHAN_NO_IR
						| IEEE80211_CHAN_RADAR))
#else
						(IEEE80211_CHAN_RADAR
						| IEEE80211_CHAN_PASSIVE_SCAN))
#endif // endif
						continue;
#ifdef P2P_SKIP_DFS
					if (channel >= 52 && channel <= 144) {
						if (is_printed == false) {
							WL_ERR(("SKIP DFS CHANs(52~144)\n"));
							is_printed = true;
						}
						continue;
					}
#endif /* P2P_SKIP_DFS */

					for (j = 0; j < n_valid_chan; j++) {
						/* allows only supported channel on
						*  current reguatory
						*/
						if (n_nodfs >= num_chans) {
							break;
						}
						if (channel == (dtoh32(list->element[j]))) {
							default_chan_list[n_nodfs++] =
								channel;
						}
					}

				}
			}
			if (num_chans == SOCIAL_CHAN_CNT && (
						(default_chan_list[0] == SOCIAL_CHAN_1) &&
						(default_chan_list[1] == SOCIAL_CHAN_2) &&
						(default_chan_list[2] == SOCIAL_CHAN_3))) {
				/* SOCIAL CHANNELS 1, 6, 11 */
				search_state = WL_P2P_DISC_ST_SEARCH;
				p2p_scan_purpose = P2P_SCAN_SOCIAL_CHANNEL;
				WL_DBG(("P2P SEARCH PHASE START \n"));
			} else if (((dev = wl_to_p2p_bss_ndev(cfg, P2PAPI_BSSCFG_CONNECTION1)) &&
				(wl_get_mode_by_netdev(cfg, dev) == WL_MODE_AP)) ||
				((dev = wl_to_p2p_bss_ndev(cfg, P2PAPI_BSSCFG_CONNECTION2)) &&
				(wl_get_mode_by_netdev(cfg, dev) == WL_MODE_AP))) {
				/* If you are already a GO, then do SEARCH only */
				WL_DBG(("Already a GO. Do SEARCH Only"));
				search_state = WL_P2P_DISC_ST_SEARCH;
				num_chans = n_nodfs;
				p2p_scan_purpose = P2P_SCAN_NORMAL;

			} else if (num_chans == 1) {
				p2p_scan_purpose = P2P_SCAN_CONNECT_TRY;
				WL_INFORM_MEM(("Trigger p2p join scan\n"));
			} else if (num_chans == SOCIAL_CHAN_CNT + 1) {
			/* SOCIAL_CHAN_CNT + 1 takes care of the Progressive scan supported by
			 * the supplicant
			 */
				p2p_scan_purpose = P2P_SCAN_SOCIAL_CHANNEL;
			} else {
				WL_DBG(("P2P SCAN STATE START \n"));
				num_chans = n_nodfs;
				p2p_scan_purpose = P2P_SCAN_NORMAL;
			}
		} else {
			err = -EINVAL;
			goto exit;
		}
		err = wl_cfgp2p_escan(cfg, ndev, ACTIVE_SCAN, num_chans, default_chan_list,
			search_state, action,
			wl_to_p2p_bss_bssidx(cfg, P2PAPI_BSSCFG_DEVICE), NULL,
			p2p_scan_purpose);

		if (!err)
			cfg->p2p->search_state = search_state;

		MFREE(cfg->osh, default_chan_list, chan_mem);
	}
exit:
	if (unlikely(err)) {
		/* Don't print Error incase of Scan suppress */
		if ((err == BCME_EPERM) && cfg->scan_suppressed)
			WL_DBG(("Escan failed: Scan Suppressed \n"));
		else
			WL_ERR(("scan error (%d)\n", err));
	}
	return err;
}

s32
wl_do_escan(struct bcm_cfg80211 *cfg, struct wiphy *wiphy, struct net_device *ndev,
	struct cfg80211_scan_request *request)
{
	s32 err = BCME_OK;
	s32 passive_scan;
	s32 passive_scan_time;
	s32 passive_scan_time_org;
	wl_scan_results_t *results;
	WL_SCAN(("Enter \n"));

	results = wl_escan_get_buf(cfg, FALSE);
	results->version = 0;
	results->count = 0;
	results->buflen = WL_SCAN_RESULTS_FIXED_SIZE;

	cfg->escan_info.ndev = ndev;
	cfg->escan_info.wiphy = wiphy;
	cfg->escan_info.escan_state = WL_ESCAN_STATE_SCANING;
	passive_scan = cfg->active_scan ? 0 : 1;
	err = wldev_ioctl_set(ndev, WLC_SET_PASSIVE_SCAN,
	                      &passive_scan, sizeof(passive_scan));
	if (unlikely(err)) {
		WL_ERR(("error (%d)\n", err));
		goto exit;
	}

	if (passive_channel_skip) {

		err = wldev_ioctl_get(ndev, WLC_GET_SCAN_PASSIVE_TIME,
			&passive_scan_time_org, sizeof(passive_scan_time_org));
		if (unlikely(err)) {
			WL_ERR(("== error (%d)\n", err));
			goto exit;
		}

		WL_SCAN(("PASSIVE SCAN time : %d \n", passive_scan_time_org));

		passive_scan_time = 0;
		err = wldev_ioctl_set(ndev, WLC_SET_SCAN_PASSIVE_TIME,
			&passive_scan_time, sizeof(passive_scan_time));
		if (unlikely(err)) {
			WL_ERR(("== error (%d)\n", err));
			goto exit;
		}

		WL_SCAN(("PASSIVE SCAN SKIPED!! (passive_channel_skip:%d) \n",
			passive_channel_skip));
	}

	err = wl_run_escan(cfg, ndev, request, WL_SCAN_ACTION_START);

	if (passive_channel_skip) {
		err = wldev_ioctl_set(ndev, WLC_SET_SCAN_PASSIVE_TIME,
			&passive_scan_time_org, sizeof(passive_scan_time_org));
		if (unlikely(err)) {
			WL_ERR(("== error (%d)\n", err));
			goto exit;
		}

		WL_SCAN(("PASSIVE SCAN RECOVERED!! (passive_scan_time_org:%d) \n",
			passive_scan_time_org));
	}

exit:
	return err;
}

static s32
wl_get_scan_timeout_val(struct bcm_cfg80211 *cfg)
{
	u32 scan_timer_interval_ms = WL_SCAN_TIMER_INTERVAL_MS;

	/* If NAN is enabled adding +10 sec to the existing timeout value */
#ifdef WL_NAN
	if (cfg->nan_enable) {
		scan_timer_interval_ms += WL_SCAN_TIMER_INTERVAL_MS_NAN;
	}
#endif /* WL_NAN */
	WL_MEM(("scan_timer_interval_ms %d\n", scan_timer_interval_ms));
	return scan_timer_interval_ms;
}

#define SCAN_EBUSY_RETRY_LIMIT 20
static s32
wl_cfgscan_handle_scanbusy(struct bcm_cfg80211 *cfg, struct net_device *ndev, s32 err)
{
	s32	scanbusy_err = 0;
	static u32 busy_count = 0;

	if (!err) {
		busy_count = 0;
		return scanbusy_err;
	}
	if (err == BCME_BUSY || err == BCME_NOTREADY) {
		WL_ERR(("Scan err = (%d), busy?%d\n", err, -EBUSY));
		scanbusy_err = -EBUSY;
	} else if ((err == BCME_EPERM) && cfg->scan_suppressed) {
		WL_ERR(("Scan not permitted due to scan suppress\n"));
		scanbusy_err = -EPERM;
	} else {
		/* For all other fw errors, use a generic error code as return
		 * value to cfg80211 stack
		 */
		scanbusy_err = -EAGAIN;
	}

	if (scanbusy_err == -EBUSY) {
		/* Flush FW preserve buffer logs for checking failure */
		if (busy_count++ > (SCAN_EBUSY_RETRY_LIMIT/5)) {
			wl_flush_fw_log_buffer(ndev, FW_LOGSET_MASK_ALL);
		}
		if (busy_count > SCAN_EBUSY_RETRY_LIMIT) {
			struct ether_addr bssid;
			s32 ret = 0;
			dhd_pub_t *dhdp = (dhd_pub_t *)(cfg->pub);
			if (dhd_query_bus_erros(dhdp)) {
				return BCME_NOTREADY;
			}
			dhdp->scan_busy_occurred = TRUE;
			busy_count = 0;
			WL_ERR(("Unusual continuous EBUSY error, %d %d %d %d %d %d %d %d %d\n",
				wl_get_drv_status(cfg, SCANNING, ndev),
				wl_get_drv_status(cfg, SCAN_ABORTING, ndev),
				wl_get_drv_status(cfg, CONNECTING, ndev),
				wl_get_drv_status(cfg, CONNECTED, ndev),
				wl_get_drv_status(cfg, DISCONNECTING, ndev),
				wl_get_drv_status(cfg, AP_CREATING, ndev),
				wl_get_drv_status(cfg, AP_CREATED, ndev),
				wl_get_drv_status(cfg, SENDING_ACT_FRM, ndev),
				wl_get_drv_status(cfg, SENDING_ACT_FRM, ndev)));

#if defined(DHD_DEBUG) && defined(DHD_FW_COREDUMP)
			if (dhdp->memdump_enabled) {
				dhdp->memdump_type = DUMP_TYPE_SCAN_BUSY;
				dhd_bus_mem_dump(dhdp);
			}
#endif /* DHD_DEBUG && DHD_FW_COREDUMP */
			dhdp->hang_reason = HANG_REASON_SCAN_BUSY;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27))
			dhd_os_send_hang_message(dhdp);
#else
			WL_ERR(("%s: HANG event is unsupported\n", __FUNCTION__));
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27) && OEM_ANDROID */

			bzero(&bssid, sizeof(bssid));
			if ((ret = wldev_ioctl_get(ndev, WLC_GET_BSSID,
				&bssid, ETHER_ADDR_LEN)) == 0) {
				WL_ERR(("FW is connected with " MACDBG "\n",
					MAC2STRDBG(bssid.octet)));
			} else {
				WL_ERR(("GET BSSID failed with %d\n", ret));
			}

			wl_cfg80211_scan_abort(cfg);

		} else {
			/* Hold the context for 400msec, so that 10 subsequent scans
			* can give a buffer of 4sec which is enough to
			* cover any on-going scan in the firmware
			*/
			WL_DBG(("Enforcing delay for EBUSY case \n"));
			msleep(400);
		}
	} else {
		busy_count = 0;
	}

	return scanbusy_err;
}

s32
__wl_cfg80211_scan(struct wiphy *wiphy, struct net_device *ndev,
	struct cfg80211_scan_request *request,
	struct cfg80211_ssid *this_ssid)
{
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	struct cfg80211_ssid *ssids;
	struct ether_addr primary_mac;
	bool p2p_ssid;
#ifdef WL11U
	bcm_tlv_t *interworking_ie;
#endif // endif
	s32 err = 0;
	s32 bssidx = -1;
	s32 i;
	bool escan_req_failed = false;
	s32 scanbusy_err = 0;

	unsigned long flags;
#ifdef WL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST
	struct net_device *remain_on_channel_ndev = NULL;
#endif // endif
	/*
	 * Hostapd triggers scan before starting automatic channel selection
	 * to collect channel characteristics. However firmware scan engine
	 * doesn't support any channel characteristics collection along with
	 * scan. Hence return scan success.
	 */
	if (request && (scan_req_iftype(request) == NL80211_IFTYPE_AP)) {
		WL_DBG(("Scan Command on SoftAP Interface. Ignoring...\n"));
// terence 20161023: let it scan in SoftAP mode
//		return 0;
	}

	ndev = ndev_to_wlc_ndev(ndev, cfg);

	if (WL_DRV_STATUS_SENDING_AF_FRM_EXT(cfg)) {
		WL_ERR(("Sending Action Frames. Try it again.\n"));
		return -EAGAIN;
	}

	WL_DBG(("Enter wiphy (%p)\n", wiphy));
	if (wl_get_drv_status_all(cfg, SCANNING)) {
		if (cfg->scan_request == NULL) {
			wl_clr_drv_status_all(cfg, SCANNING);
			WL_DBG(("<<<<<<<<<<<Force Clear Scanning Status>>>>>>>>>>>\n"));
		} else {
			WL_ERR(("Scanning already\n"));
			return -EAGAIN;
		}
	}
	if (wl_get_drv_status(cfg, SCAN_ABORTING, ndev)) {
		WL_ERR(("Scanning being aborted\n"));
		return -EAGAIN;
	}
	if (request && request->n_ssids > WL_SCAN_PARAMS_SSID_MAX) {
		WL_ERR(("request null or n_ssids > WL_SCAN_PARAMS_SSID_MAX\n"));
		return -EOPNOTSUPP;
	}
#ifdef WL_BCNRECV
	/* check fakeapscan in progress then abort */
	wl_android_bcnrecv_stop(ndev, WL_BCNRECV_SCANBUSY);
#endif /* WL_BCNRECV */

#ifdef WL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST
	mutex_lock(&cfg->scan_sync);
	remain_on_channel_ndev = wl_cfg80211_get_remain_on_channel_ndev(cfg);
	if (remain_on_channel_ndev) {
		WL_DBG(("Remain_on_channel bit is set, somehow it didn't get cleared\n"));
		wl_notify_escan_complete(cfg, remain_on_channel_ndev, true, true);
	}
	mutex_unlock(&cfg->scan_sync);
#endif /* WL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST */

#ifdef P2P_LISTEN_OFFLOADING
	wl_cfg80211_cancel_p2plo(cfg);
#endif /* P2P_LISTEN_OFFLOADING */

	if (request) {		/* scan bss */
		ssids = request->ssids;
		p2p_ssid = false;
		for (i = 0; i < request->n_ssids; i++) {
			if (ssids[i].ssid_len &&
				IS_P2P_SSID(ssids[i].ssid, ssids[i].ssid_len)) {
				/* P2P Scan */
#ifdef WL_BLOCK_P2P_SCAN_ON_STA
				if (!(IS_P2P_IFACE(request->wdev))) {
					/* P2P scan on non-p2p iface. Fail scan */
					WL_ERR(("p2p_search on non p2p iface\n"));
					goto scan_out;
				}
#endif /* WL_BLOCK_P2P_SCAN_ON_STA */
				p2p_ssid = true;
				break;
			}
		}
		if (p2p_ssid) {
			if (cfg->p2p_supported) {
				/* p2p scan trigger */
				if (p2p_on(cfg) == false) {
					/* p2p on at the first time */
					p2p_on(cfg) = true;
					wl_cfgp2p_set_firm_p2p(cfg);
					get_primary_mac(cfg, &primary_mac);
#ifndef WL_P2P_USE_RANDMAC
					wl_cfgp2p_generate_bss_mac(cfg, &primary_mac);
#endif /* WL_P2P_USE_RANDMAC */
#if defined(P2P_IE_MISSING_FIX)
					cfg->p2p_prb_noti = false;
#endif // endif
				}
				wl_clr_p2p_status(cfg, GO_NEG_PHASE);
				WL_DBG(("P2P: GO_NEG_PHASE status cleared \n"));
				p2p_scan(cfg) = true;
			}
		} else {
			/* legacy scan trigger
			 * So, we have to disable p2p discovery if p2p discovery is on
			 */
			if (cfg->p2p_supported) {
				p2p_scan(cfg) = false;
				/* If Netdevice is not equals to primary and p2p is on
				*  , we will do p2p scan using P2PAPI_BSSCFG_DEVICE.
				*/

				if (p2p_scan(cfg) == false) {
					if (wl_get_p2p_status(cfg, DISCOVERY_ON)) {
						err = wl_cfgp2p_discover_enable_search(cfg,
						false);
						if (unlikely(err)) {
							goto scan_out;
						}

					}
				}
			}
			if (!cfg->p2p_supported || !p2p_scan(cfg)) {
				if ((bssidx = wl_get_bssidx_by_wdev(cfg,
					ndev->ieee80211_ptr)) < 0) {
					WL_ERR(("Find p2p index from ndev(%p) failed\n",
						ndev));
					err = BCME_ERROR;
					goto scan_out;
				}
#ifdef WL11U
				if (request && (interworking_ie = wl_cfg80211_find_interworking_ie(
						request->ie, request->ie_len)) != NULL) {
					if ((err = wl_cfg80211_add_iw_ie(cfg, ndev, bssidx,
							VNDR_IE_CUSTOM_FLAG, interworking_ie->id,
							interworking_ie->data,
							interworking_ie->len)) != BCME_OK) {
						WL_ERR(("Failed to add interworking IE"));
					}
				} else if (cfg->wl11u) {
					/* we have to clear IW IE and disable gratuitous APR */
					wl_cfg80211_clear_iw_ie(cfg, ndev, bssidx);
					err = wldev_iovar_setint_bsscfg(ndev, "grat_arp",
					                                0, bssidx);
					/* we don't care about error here
					 * because the only failure case is unsupported,
					 * which is fine
					 */
					if (unlikely(err)) {
						WL_ERR(("Set grat_arp failed:(%d) Ignore!\n", err));
					}
					cfg->wl11u = FALSE;
				}
#endif /* WL11U */
				if (request) {
					err = wl_cfg80211_set_mgmt_vndr_ies(cfg,
						ndev_to_cfgdev(ndev), bssidx, VNDR_IE_PRBREQ_FLAG,
						request->ie, request->ie_len);
				}

				if (unlikely(err)) {
// terence 20161023: let it scan in SoftAP mode
//					goto scan_out;
				}

			}
		}
	} else {		/* scan in ibss */
		ssids = this_ssid;
	}

	if (request && cfg->p2p_supported) {
		WL_TRACE_HW4(("START SCAN\n"));
		DHD_OS_SCAN_WAKE_LOCK_TIMEOUT((dhd_pub_t *)(cfg->pub),
			SCAN_WAKE_LOCK_TIMEOUT);
		DHD_DISABLE_RUNTIME_PM((dhd_pub_t *)(cfg->pub));
	}

	if (cfg->p2p_supported) {
		if (request && p2p_on(cfg) && p2p_scan(cfg)) {

			/* find my listen channel */
			cfg->afx_hdl->my_listen_chan =
				wl_find_listen_channel(cfg, request->ie,
				request->ie_len);
			err = wl_cfgp2p_enable_discovery(cfg, ndev,
			request->ie, request->ie_len);

			if (unlikely(err)) {
				goto scan_out;
			}
		}
	}

	mutex_lock(&cfg->scan_sync);
#ifdef WL_EXT_IAPSTA
	if (wl_ext_in4way_sync(ndev, STA_FAKE_SCAN_IN_CONNECT,
			WL_EXT_STATUS_SCANNING, NULL))
		goto scan_success;
	else
#endif
	err = wl_do_escan(cfg, wiphy, ndev, request);
	if (likely(!err)) {
		goto scan_success;
	} else {
		escan_req_failed = true;
		goto scan_out;
	}

scan_success:
	wl_cfgscan_handle_scanbusy(cfg, ndev, BCME_OK);
	cfg->scan_request = request;
	wl_set_drv_status(cfg, SCANNING, ndev);
	/* Arm the timer */
	mod_timer(&cfg->scan_timeout,
		jiffies + msecs_to_jiffies(wl_get_scan_timeout_val(cfg)));
	mutex_unlock(&cfg->scan_sync);
	return 0;

scan_out:
	if (escan_req_failed) {
		WL_CFG_DRV_LOCK(&cfg->cfgdrv_lock, flags);
		cfg->scan_request = NULL;
		WL_CFG_DRV_UNLOCK(&cfg->cfgdrv_lock, flags);
		mutex_unlock(&cfg->scan_sync);
		/* Handling for scan busy errors */
		scanbusy_err = wl_cfgscan_handle_scanbusy(cfg, ndev, err);
		if (scanbusy_err == BCME_NOTREADY) {
			/* In case of bus failures avoid ioctl calls */
			DHD_OS_SCAN_WAKE_UNLOCK((dhd_pub_t *)(cfg->pub));
			return -ENODEV;
		}
		err = scanbusy_err;
	}

	DHD_OS_SCAN_WAKE_UNLOCK((dhd_pub_t *)(cfg->pub));
	return err;
}
