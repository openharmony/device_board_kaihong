/*
 * Neighbor Awareness Networking
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
 * $Id: wl_cfgnan.c 825970 2019-06-18 05:28:31Z $
 */

#ifdef WL_NAN
#include <bcmutils.h>
#include <bcmendian.h>
#include <bcmwifi_channels.h>
#include <nan.h>
#include <bcmiov.h>
#include <net/rtnetlink.h>

#include <wl_cfg80211.h>
#include <wl_cfgscan.h>
#include <wl_android.h>
#include <wl_cfgnan.h>

#include <dngl_stats.h>
#include <dhd.h>
#ifdef RTT_SUPPORT
#include <dhd_rtt.h>
#endif /* RTT_SUPPORT */
#include <wl_cfgvendor.h>
#include <bcmbloom.h>
#include <wl_cfgp2p.h>
#ifdef RTT_SUPPORT
#include <dhd_rtt.h>
#endif /* RTT_SUPPORT */
#include <bcmstdlib_s.h>

#define NAN_RANGE_REQ_EVNT 1
#define NAN_RAND_MAC_RETRIES 10
#define NAN_SCAN_DWELL_TIME_DELTA_MS 10

#ifdef WL_NAN_DISC_CACHE
/* Disc Cache Parameters update Flags */
#define NAN_DISC_CACHE_PARAM_SDE_CONTROL	0x0001

static int wl_cfgnan_cache_disc_result(struct bcm_cfg80211 *cfg, void * data,
	u16 *disc_cache_update_flags);
static int wl_cfgnan_remove_disc_result(struct bcm_cfg80211 * cfg, uint8 local_subid);
static nan_disc_result_cache * wl_cfgnan_get_disc_result(struct bcm_cfg80211 *cfg,
	uint8 remote_pubid, struct ether_addr *peer);
#endif /* WL_NAN_DISC_CACHE */
static int wl_cfgnan_clear_disc_cache(struct bcm_cfg80211 *cfg, wl_nan_instance_id_t sub_id);
static int wl_cfgnan_set_if_addr(struct bcm_cfg80211 *cfg);

static int wl_cfgnan_get_capability(struct net_device *ndev,
	struct bcm_cfg80211 *cfg, nan_hal_capabilities_t *capabilities);

static int32 wl_cfgnan_notify_disc_with_ranging(struct bcm_cfg80211 *cfg,
	nan_ranging_inst_t *rng_inst, nan_event_data_t *nan_event_data, uint32 distance);

static void wl_cfgnan_disc_result_on_geofence_cancel(struct bcm_cfg80211 *cfg,
	nan_ranging_inst_t *rng_inst);

static void wl_cfgnan_clear_nan_event_data(struct bcm_cfg80211 *cfg,
	nan_event_data_t *nan_event_data);

void wl_cfgnan_data_remove_peer(struct bcm_cfg80211 *cfg,
        struct ether_addr *peer_addr);

static void wl_cfgnan_send_stop_event(struct bcm_cfg80211 *cfg);

static void wl_cfgnan_terminate_ranging_session(struct bcm_cfg80211 *cfg,
	nan_ranging_inst_t *ranging_inst);

#ifdef RTT_SUPPORT
static s32 wl_cfgnan_clear_peer_ranging(struct bcm_cfg80211 * cfg,
	struct ether_addr * peer, int reason);
#endif /* RTT_SUPPORT */

static const char *nan_role_to_str(u8 role)
{
	switch (role) {
		C2S(WL_NAN_ROLE_AUTO)
		C2S(WL_NAN_ROLE_NON_MASTER_NON_SYNC)
		C2S(WL_NAN_ROLE_NON_MASTER_SYNC)
		C2S(WL_NAN_ROLE_MASTER)
		C2S(WL_NAN_ROLE_ANCHOR_MASTER)
		default:
			return "WL_NAN_ROLE_UNKNOWN";
	}
}

static const char *nan_event_to_str(u16 cmd)
{
	switch (cmd) {
	C2S(WL_NAN_EVENT_START)
	C2S(WL_NAN_EVENT_DISCOVERY_RESULT)
	C2S(WL_NAN_EVENT_TERMINATED)
	C2S(WL_NAN_EVENT_RECEIVE)
	C2S(WL_NAN_EVENT_MERGE)
	C2S(WL_NAN_EVENT_STOP)
	C2S(WL_NAN_EVENT_PEER_DATAPATH_IND)
	C2S(WL_NAN_EVENT_DATAPATH_ESTB)
	C2S(WL_NAN_EVENT_SDF_RX)
	C2S(WL_NAN_EVENT_DATAPATH_END)
	C2S(WL_NAN_EVENT_RNG_REQ_IND)
	C2S(WL_NAN_EVENT_RNG_RPT_IND)
	C2S(WL_NAN_EVENT_RNG_TERM_IND)
	C2S(WL_NAN_EVENT_TXS)
	C2S(WL_NAN_EVENT_INVALID)

	default:
		return "WL_NAN_EVENT_UNKNOWN";
	}
}

static int wl_cfgnan_execute_ioctl(struct net_device *ndev,
	struct bcm_cfg80211 *cfg, bcm_iov_batch_buf_t *nan_buf,
	uint16 nan_buf_size, uint32 *status, uint8 *resp_buf,
	uint16 resp_buf_len);
int
wl_cfgnan_generate_inst_id(struct bcm_cfg80211 *cfg, uint8 *p_inst_id)
{
	s32 ret = BCME_OK;
	uint8 i = 0;
	if (p_inst_id == NULL) {
		WL_ERR(("Invalid arguments\n"));
		ret = -EINVAL;
		goto exit;
	}

	if (cfg->nancfg.inst_id_start == NAN_ID_MAX) {
		WL_ERR(("Consumed all IDs, resetting the counter\n"));
		cfg->nancfg.inst_id_start = 0;
	}

	for (i = cfg->nancfg.inst_id_start; i < NAN_ID_MAX; i++) {
		if (isclr(cfg->nancfg.svc_inst_id_mask, i)) {
			setbit(cfg->nancfg.svc_inst_id_mask, i);
			*p_inst_id = i + 1;
			cfg->nancfg.inst_id_start = *p_inst_id;
			WL_DBG(("Instance ID=%d\n", *p_inst_id));
			goto exit;
		}
	}
	WL_ERR(("Allocated maximum IDs\n"));
	ret = BCME_NORESOURCE;
exit:
	return ret;
}

int
wl_cfgnan_remove_inst_id(struct bcm_cfg80211 *cfg, uint8 inst_id)
{
	s32 ret = BCME_OK;
	WL_DBG(("%s: Removing svc instance id %d\n", __FUNCTION__, inst_id));
	clrbit(cfg->nancfg.svc_inst_id_mask, inst_id-1);
	return ret;
}
s32 wl_cfgnan_parse_sdea_data(osl_t *osh, const uint8 *p_attr,
		uint16 len, nan_event_data_t *tlv_data)
{
	const wifi_nan_svc_desc_ext_attr_t *nan_svc_desc_ext_attr = NULL;
	uint8 offset;
	s32 ret = BCME_OK;

	/* service descriptor ext attributes */
	nan_svc_desc_ext_attr = (const wifi_nan_svc_desc_ext_attr_t *)p_attr;

	/* attribute ID */
	WL_TRACE(("> attr id: 0x%02x\n", nan_svc_desc_ext_attr->id));

	/* attribute length */
	WL_TRACE(("> attr len: 0x%x\n", nan_svc_desc_ext_attr->len));
	if (nan_svc_desc_ext_attr->instance_id == tlv_data->pub_id) {
		tlv_data->sde_control_flag = nan_svc_desc_ext_attr->control;
	}
	offset = sizeof(*nan_svc_desc_ext_attr);
	if (offset > len) {
		WL_ERR(("Invalid event buffer len\n"));
		ret = BCME_BUFTOOSHORT;
		goto fail;
	}
	p_attr += offset;
	len -= offset;

	if (tlv_data->sde_control_flag & NAN_SC_RANGE_LIMITED) {
		WL_TRACE(("> svc_control: range limited present\n"));
	}
	if (tlv_data->sde_control_flag & NAN_SDE_CF_SVC_UPD_IND_PRESENT) {
		WL_TRACE(("> svc_control: sdea svc specific info present\n"));
		tlv_data->sde_svc_info.dlen = (p_attr[1] | (p_attr[2] << 8));
		WL_TRACE(("> sdea svc info len: 0x%02x\n", tlv_data->sde_svc_info.dlen));
		if (!tlv_data->sde_svc_info.dlen ||
				tlv_data->sde_svc_info.dlen > NAN_MAX_SERVICE_SPECIFIC_INFO_LEN) {
			/* must be able to handle null msg which is not error */
			tlv_data->sde_svc_info.dlen = 0;
			WL_ERR(("sde data length is invalid\n"));
			ret = BCME_BADLEN;
			goto fail;
		}

		if (tlv_data->sde_svc_info.dlen > 0) {
			tlv_data->sde_svc_info.data = MALLOCZ(osh, tlv_data->sde_svc_info.dlen);
			if (!tlv_data->sde_svc_info.data) {
				WL_ERR(("%s: memory allocation failed\n", __FUNCTION__));
				tlv_data->sde_svc_info.dlen = 0;
				ret = BCME_NOMEM;
				goto fail;
			}
			/* advance read pointer, consider sizeof of Service Update Indicator */
			offset = sizeof(tlv_data->sde_svc_info.dlen) - 1;
			if (offset > len) {
				WL_ERR(("Invalid event buffer len\n"));
				ret = BCME_BUFTOOSHORT;
				goto fail;
			}
			p_attr += offset;
			len -= offset;
			ret = memcpy_s(tlv_data->sde_svc_info.data, tlv_data->sde_svc_info.dlen,
				p_attr, tlv_data->sde_svc_info.dlen);
			if (ret != BCME_OK) {
				WL_ERR(("Failed to copy sde_svc_info\n"));
				goto fail;
			}
		} else {
			/* must be able to handle null msg which is not error */
			tlv_data->sde_svc_info.dlen = 0;
			WL_DBG(("%s: sdea svc info length is zero, null info data\n",
				__FUNCTION__));
		}
	}
	return ret;
fail:
	if (tlv_data->sde_svc_info.data) {
		MFREE(osh, tlv_data->sde_svc_info.data,
				tlv_data->sde_svc_info.dlen);
		tlv_data->sde_svc_info.data = NULL;
	}

	WL_DBG(("Parse SDEA event data, status = %d\n", ret));
	return ret;
}

/*
 * This attribute contains some mandatory fields and some optional fields
 * depending on the content of the service discovery request.
 */
s32
wl_cfgnan_parse_sda_data(osl_t *osh, const uint8 *p_attr,
		uint16 len, nan_event_data_t *tlv_data)
{
	uint8 svc_control = 0, offset = 0;
	s32 ret = BCME_OK;
	const wifi_nan_svc_descriptor_attr_t *nan_svc_desc_attr = NULL;

	/* service descriptor attributes */
	nan_svc_desc_attr = (const wifi_nan_svc_descriptor_attr_t *)p_attr;
	/* attribute ID */
	WL_TRACE(("> attr id: 0x%02x\n", nan_svc_desc_attr->id));

	/* attribute length */
	WL_TRACE(("> attr len: 0x%x\n", nan_svc_desc_attr->len));

	/* service ID */
	ret = memcpy_s(tlv_data->svc_name, sizeof(tlv_data->svc_name),
		nan_svc_desc_attr->svc_hash, NAN_SVC_HASH_LEN);
	if (ret != BCME_OK) {
		WL_ERR(("Failed to copy svc_hash_name:\n"));
		return ret;
	}
	WL_TRACE(("> svc_hash_name: " MACDBG "\n", MAC2STRDBG(tlv_data->svc_name)));

	/* local instance ID */
	tlv_data->local_inst_id = nan_svc_desc_attr->instance_id;
	WL_TRACE(("> local instance id: 0x%02x\n", tlv_data->local_inst_id));

	/* requestor instance ID */
	tlv_data->requestor_id = nan_svc_desc_attr->requestor_id;
	WL_TRACE(("> requestor id: 0x%02x\n", tlv_data->requestor_id));

	/* service control */
	svc_control = nan_svc_desc_attr->svc_control;
	if ((svc_control & NAN_SVC_CONTROL_TYPE_MASK) == NAN_SC_PUBLISH) {
		WL_TRACE(("> Service control type: NAN_SC_PUBLISH\n"));
	} else if ((svc_control & NAN_SVC_CONTROL_TYPE_MASK) == NAN_SC_SUBSCRIBE) {
		WL_TRACE(("> Service control type: NAN_SC_SUBSCRIBE\n"));
	} else if ((svc_control & NAN_SVC_CONTROL_TYPE_MASK) == NAN_SC_FOLLOWUP) {
		WL_TRACE(("> Service control type: NAN_SC_FOLLOWUP\n"));
	}
	offset = sizeof(*nan_svc_desc_attr);
	if (offset > len) {
		WL_ERR(("Invalid event buffer len\n"));
		ret = BCME_BUFTOOSHORT;
		goto fail;
	}
	p_attr += offset;
	len -= offset;

	/*
	 * optional fields:
	 * must be in order following by service descriptor attribute format
	 */

	/* binding bitmap */
	if (svc_control & NAN_SC_BINDING_BITMAP_PRESENT) {
		uint16 bitmap = 0;
		WL_TRACE(("> svc_control: binding bitmap present\n"));

		/* Copy binding bitmap */
		ret = memcpy_s(&bitmap, sizeof(bitmap),
			p_attr, NAN_BINDING_BITMAP_LEN);
		if (ret != BCME_OK) {
			WL_ERR(("Failed to copy bit map\n"));
			return ret;
		}
		WL_TRACE(("> sc binding bitmap: 0x%04x\n", bitmap));

		if (NAN_BINDING_BITMAP_LEN > len) {
			WL_ERR(("Invalid event buffer len\n"));
			ret = BCME_BUFTOOSHORT;
			goto fail;
		}
		p_attr += NAN_BINDING_BITMAP_LEN;
		len -= NAN_BINDING_BITMAP_LEN;
	}

	/* matching filter */
	if (svc_control & NAN_SC_MATCHING_FILTER_PRESENT) {
		WL_TRACE(("> svc_control: matching filter present\n"));

		tlv_data->tx_match_filter.dlen = *p_attr++;
		WL_TRACE(("> matching filter len: 0x%02x\n",
				tlv_data->tx_match_filter.dlen));

		if (!tlv_data->tx_match_filter.dlen ||
				tlv_data->tx_match_filter.dlen > MAX_MATCH_FILTER_LEN) {
			tlv_data->tx_match_filter.dlen = 0;
			WL_ERR(("tx match filter length is invalid\n"));
			ret = -EINVAL;
			goto fail;
		}
		tlv_data->tx_match_filter.data =
			MALLOCZ(osh, tlv_data->tx_match_filter.dlen);
		if (!tlv_data->tx_match_filter.data) {
			WL_ERR(("%s: memory allocation failed\n", __FUNCTION__));
			tlv_data->tx_match_filter.dlen = 0;
			ret = -ENOMEM;
			goto fail;
		}
		ret = memcpy_s(tlv_data->tx_match_filter.data, tlv_data->tx_match_filter.dlen,
				p_attr, tlv_data->tx_match_filter.dlen);
		if (ret != BCME_OK) {
			WL_ERR(("Failed to copy tx match filter data\n"));
			goto fail;
		}
		/* advance read pointer */
		offset = tlv_data->tx_match_filter.dlen;
		if (offset > len) {
			WL_ERR(("Invalid event buffer\n"));
			ret = BCME_BUFTOOSHORT;
			goto fail;
		}
		p_attr += offset;
		len -= offset;
	}

	/* service response filter */
	if (svc_control & NAN_SC_SR_FILTER_PRESENT) {
		WL_TRACE(("> svc_control: service response filter present\n"));

		tlv_data->rx_match_filter.dlen = *p_attr++;
		WL_TRACE(("> sr match filter len: 0x%02x\n",
				tlv_data->rx_match_filter.dlen));

		if (!tlv_data->rx_match_filter.dlen ||
				tlv_data->rx_match_filter.dlen > MAX_MATCH_FILTER_LEN) {
			tlv_data->rx_match_filter.dlen = 0;
			WL_ERR(("%s: sr matching filter length is invalid\n",
					__FUNCTION__));
			ret = BCME_BADLEN;
			goto fail;
		}
		tlv_data->rx_match_filter.data =
			MALLOCZ(osh, tlv_data->rx_match_filter.dlen);
		if (!tlv_data->rx_match_filter.data) {
			WL_ERR(("%s: memory allocation failed\n", __FUNCTION__));
			tlv_data->rx_match_filter.dlen = 0;
			ret = BCME_NOMEM;
			goto fail;
		}

		ret = memcpy_s(tlv_data->rx_match_filter.data, tlv_data->rx_match_filter.dlen,
				p_attr, tlv_data->rx_match_filter.dlen);
		if (ret != BCME_OK) {
			WL_ERR(("Failed to copy rx match filter data\n"));
			goto fail;
		}

		/* advance read pointer */
		offset = tlv_data->rx_match_filter.dlen;
		if (offset > len) {
			WL_ERR(("Invalid event buffer len\n"));
			ret = BCME_BUFTOOSHORT;
			goto fail;
		}
		p_attr += offset;
		len -= offset;
	}

	/* service specific info */
	if (svc_control & NAN_SC_SVC_INFO_PRESENT) {
		WL_TRACE(("> svc_control: svc specific info present\n"));

		tlv_data->svc_info.dlen = *p_attr++;
		WL_TRACE(("> svc info len: 0x%02x\n", tlv_data->svc_info.dlen));

		if (!tlv_data->svc_info.dlen ||
				tlv_data->svc_info.dlen > NAN_MAX_SERVICE_SPECIFIC_INFO_LEN) {
			/* must be able to handle null msg which is not error */
			tlv_data->svc_info.dlen = 0;
			WL_ERR(("sde data length is invalid\n"));
			ret = BCME_BADLEN;
			goto fail;
		}

		if (tlv_data->svc_info.dlen > 0) {
			tlv_data->svc_info.data =
				MALLOCZ(osh, tlv_data->svc_info.dlen);
			if (!tlv_data->svc_info.data) {
				WL_ERR(("%s: memory allocation failed\n", __FUNCTION__));
				tlv_data->svc_info.dlen = 0;
				ret = BCME_NOMEM;
				goto fail;
			}
			ret = memcpy_s(tlv_data->svc_info.data, tlv_data->svc_info.dlen,
					p_attr, tlv_data->svc_info.dlen);
			if (ret != BCME_OK) {
				WL_ERR(("Failed to copy svc info\n"));
				goto fail;
			}

			/* advance read pointer */
			offset = tlv_data->svc_info.dlen;
			if (offset > len) {
				WL_ERR(("Invalid event buffer len\n"));
				ret = BCME_BUFTOOSHORT;
				goto fail;
			}
			p_attr += offset;
			len -= offset;
		} else {
			/* must be able to handle null msg which is not error */
			tlv_data->svc_info.dlen = 0;
			WL_TRACE(("%s: svc info length is zero, null info data\n",
					__FUNCTION__));
		}
	}

	/*
	 * discovery range limited:
	 * If set to 1, the pub/sub msg is limited in range to close proximity.
	 * If set to 0, the pub/sub msg is not limited in range.
	 * Valid only when the message is either of a publish or a sub.
	 */
	if (svc_control & NAN_SC_RANGE_LIMITED) {
		if (((svc_control & NAN_SVC_CONTROL_TYPE_MASK) == NAN_SC_PUBLISH) ||
				((svc_control & NAN_SVC_CONTROL_TYPE_MASK) == NAN_SC_SUBSCRIBE)) {
			WL_TRACE(("> svc_control: range limited present\n"));
		} else {
			WL_TRACE(("range limited is only valid on pub or sub\n"));
		}

		/* TODO: send up */

		/* advance read pointer */
		p_attr++;
	}
	return ret;
fail:
	if (tlv_data->tx_match_filter.data) {
		MFREE(osh, tlv_data->tx_match_filter.data,
				tlv_data->tx_match_filter.dlen);
		tlv_data->tx_match_filter.data = NULL;
	}
	if (tlv_data->rx_match_filter.data) {
		MFREE(osh, tlv_data->rx_match_filter.data,
				tlv_data->rx_match_filter.dlen);
		tlv_data->rx_match_filter.data = NULL;
	}
	if (tlv_data->svc_info.data) {
		MFREE(osh, tlv_data->svc_info.data,
				tlv_data->svc_info.dlen);
		tlv_data->svc_info.data = NULL;
	}

	WL_DBG(("Parse SDA event data, status = %d\n", ret));
	return ret;
}

static s32
wl_cfgnan_parse_sd_attr_data(osl_t *osh, uint16 len, const uint8 *data,
	nan_event_data_t *tlv_data, uint16 type) {
	const uint8 *p_attr = data;
	uint16 offset = 0;
	s32 ret = BCME_OK;
	const wl_nan_event_disc_result_t *ev_disc = NULL;
	const wl_nan_event_replied_t *ev_replied = NULL;
	const wl_nan_ev_receive_t *ev_fup = NULL;

	/*
	 * Mapping wifi_nan_svc_descriptor_attr_t, and svc controls are optional.
	 */
	if (type == WL_NAN_XTLV_SD_DISC_RESULTS) {
		u8 iter;
		ev_disc = (const wl_nan_event_disc_result_t *)p_attr;

		WL_DBG((">> WL_NAN_XTLV_RESULTS: Discovery result\n"));

		tlv_data->pub_id = (wl_nan_instance_id_t)ev_disc->pub_id;
		tlv_data->sub_id = (wl_nan_instance_id_t)ev_disc->sub_id;
		tlv_data->publish_rssi = ev_disc->publish_rssi;
		ret = memcpy_s(&tlv_data->remote_nmi, ETHER_ADDR_LEN,
				&ev_disc->pub_mac, ETHER_ADDR_LEN);
		if (ret != BCME_OK) {
			WL_ERR(("Failed to copy remote nmi\n"));
			goto fail;
		}

		WL_TRACE(("publish id: %d\n", ev_disc->pub_id));
		WL_TRACE(("subscribe d: %d\n", ev_disc->sub_id));
		WL_TRACE(("publish mac addr: " MACDBG "\n",
				MAC2STRDBG(ev_disc->pub_mac.octet)));
		WL_TRACE(("publish rssi: %d\n", (int8)ev_disc->publish_rssi));
		WL_TRACE(("attribute no: %d\n", ev_disc->attr_num));
		WL_TRACE(("attribute len: %d\n", (uint16)ev_disc->attr_list_len));

		/* advance to the service descricptor */
		offset = OFFSETOF(wl_nan_event_disc_result_t, attr_list[0]);
		if (offset > len) {
			WL_ERR(("Invalid event buffer len\n"));
			ret = BCME_BUFTOOSHORT;
			goto fail;
		}
		p_attr += offset;
		len -= offset;

		iter = ev_disc->attr_num;
		while (iter) {
			if ((uint8)*p_attr == NAN_ATTR_SVC_DESCRIPTOR) {
				WL_TRACE(("> attr id: 0x%02x\n", (uint8)*p_attr));
				ret = wl_cfgnan_parse_sda_data(osh, p_attr, len, tlv_data);
				if (unlikely(ret)) {
					WL_ERR(("wl_cfgnan_parse_sda_data failed,"
							"error = %d \n", ret));
					goto fail;
				}
			}

			if ((uint8)*p_attr == NAN_ATTR_SVC_DESC_EXTENSION) {
				WL_TRACE(("> attr id: 0x%02x\n", (uint8)*p_attr));
				ret = wl_cfgnan_parse_sdea_data(osh, p_attr, len, tlv_data);
				if (unlikely(ret)) {
					WL_ERR(("wl_cfgnan_parse_sdea_data failed,"
							"error = %d \n", ret));
					goto fail;
				}
			}
			offset = (sizeof(*p_attr) +
					sizeof(ev_disc->attr_list_len) +
					(p_attr[1] | (p_attr[2] << 8)));
			if (offset > len) {
				WL_ERR(("Invalid event buffer len\n"));
				ret = BCME_BUFTOOSHORT;
				goto fail;
			}
			p_attr += offset;
			len -= offset;
			iter--;
		}
	} else if (type == WL_NAN_XTLV_SD_FUP_RECEIVED) {
		uint8 iter;
		ev_fup = (const wl_nan_ev_receive_t *)p_attr;

		WL_TRACE((">> WL_NAN_XTLV_SD_FUP_RECEIVED: Transmit follow-up\n"));

		tlv_data->local_inst_id = (wl_nan_instance_id_t)ev_fup->local_id;
		tlv_data->requestor_id = (wl_nan_instance_id_t)ev_fup->remote_id;
		tlv_data->fup_rssi = ev_fup->fup_rssi;
		ret = memcpy_s(&tlv_data->remote_nmi, ETHER_ADDR_LEN,
				&ev_fup->remote_addr, ETHER_ADDR_LEN);
		if (ret != BCME_OK) {
			WL_ERR(("Failed to copy remote nmi\n"));
			goto fail;
		}

		WL_TRACE(("local id: %d\n", ev_fup->local_id));
		WL_TRACE(("remote id: %d\n", ev_fup->remote_id));
		WL_TRACE(("peer mac addr: " MACDBG "\n",
				MAC2STRDBG(ev_fup->remote_addr.octet)));
		WL_TRACE(("peer rssi: %d\n", (int8)ev_fup->fup_rssi));
		WL_TRACE(("attribute no: %d\n", ev_fup->attr_num));
		WL_TRACE(("attribute len: %d\n", ev_fup->attr_list_len));

		/* advance to the service descriptor which is attr_list[0] */
		offset = OFFSETOF(wl_nan_ev_receive_t, attr_list[0]);
		if (offset > len) {
			WL_ERR(("Invalid event buffer len\n"));
			ret = BCME_BUFTOOSHORT;
			goto fail;
		}
		p_attr += offset;
		len -= offset;

		iter = ev_fup->attr_num;
		while (iter) {
			if ((uint8)*p_attr == NAN_ATTR_SVC_DESCRIPTOR) {
				WL_TRACE(("> attr id: 0x%02x\n", (uint8)*p_attr));
				ret = wl_cfgnan_parse_sda_data(osh, p_attr, len, tlv_data);
				if (unlikely(ret)) {
					WL_ERR(("wl_cfgnan_parse_sda_data failed,"
							"error = %d \n", ret));
					goto fail;
				}
			}

			if ((uint8)*p_attr == NAN_ATTR_SVC_DESC_EXTENSION) {
				WL_TRACE(("> attr id: 0x%02x\n", (uint8)*p_attr));
				ret = wl_cfgnan_parse_sdea_data(osh, p_attr, len, tlv_data);
				if (unlikely(ret)) {
					WL_ERR(("wl_cfgnan_parse_sdea_data failed,"
							"error = %d \n", ret));
					goto fail;
				}
			}
			offset = (sizeof(*p_attr) +
					sizeof(ev_fup->attr_list_len) +
					(p_attr[1] | (p_attr[2] << 8)));
			if (offset > len) {
				WL_ERR(("Invalid event buffer len\n"));
				ret = BCME_BUFTOOSHORT;
				goto fail;
			}
			p_attr += offset;
			len -= offset;
			iter--;
		}
	} else if (type == WL_NAN_XTLV_SD_SDF_RX) {
		/*
		 * SDF followed by nan2_pub_act_frame_t and wifi_nan_svc_descriptor_attr_t,
		 * and svc controls are optional.
		 */
		const nan2_pub_act_frame_t *nan_pub_af =
			(const nan2_pub_act_frame_t *)p_attr;

		WL_TRACE((">> WL_NAN_XTLV_SD_SDF_RX\n"));

		/* nan2_pub_act_frame_t */
		WL_TRACE(("pub category: 0x%02x\n", nan_pub_af->category_id));
		WL_TRACE(("pub action: 0x%02x\n", nan_pub_af->action_field));
		WL_TRACE(("nan oui: %2x-%2x-%2x\n",
				nan_pub_af->oui[0], nan_pub_af->oui[1], nan_pub_af->oui[2]));
		WL_TRACE(("oui type: 0x%02x\n", nan_pub_af->oui_type));
		WL_TRACE(("oui subtype: 0x%02x\n", nan_pub_af->oui_sub_type));

		offset = sizeof(*nan_pub_af);
		if (offset > len) {
			WL_ERR(("Invalid event buffer len\n"));
			ret = BCME_BUFTOOSHORT;
			goto fail;
		}
		p_attr += offset;
		len -= offset;
	} else if (type == WL_NAN_XTLV_SD_REPLIED) {
		ev_replied = (const wl_nan_event_replied_t *)p_attr;

		WL_TRACE((">> WL_NAN_XTLV_SD_REPLIED: Replied Event\n"));

		tlv_data->pub_id = (wl_nan_instance_id_t)ev_replied->pub_id;
		tlv_data->sub_id = (wl_nan_instance_id_t)ev_replied->sub_id;
		tlv_data->sub_rssi = ev_replied->sub_rssi;
		ret = memcpy_s(&tlv_data->remote_nmi, ETHER_ADDR_LEN,
				&ev_replied->sub_mac, ETHER_ADDR_LEN);
		if (ret != BCME_OK) {
			WL_ERR(("Failed to copy remote nmi\n"));
			goto fail;
		}

		WL_TRACE(("publish id: %d\n", ev_replied->pub_id));
		WL_TRACE(("subscribe d: %d\n", ev_replied->sub_id));
		WL_TRACE(("Subscriber mac addr: " MACDBG "\n",
				MAC2STRDBG(ev_replied->sub_mac.octet)));
		WL_TRACE(("subscribe rssi: %d\n", (int8)ev_replied->sub_rssi));
		WL_TRACE(("attribute no: %d\n", ev_replied->attr_num));
		WL_TRACE(("attribute len: %d\n", (uint16)ev_replied->attr_list_len));

		/* advance to the service descriptor which is attr_list[0] */
		offset = OFFSETOF(wl_nan_event_replied_t, attr_list[0]);
		if (offset > len) {
			WL_ERR(("Invalid event buffer len\n"));
			ret = BCME_BUFTOOSHORT;
			goto fail;
		}
		p_attr += offset;
		len -= offset;
		ret = wl_cfgnan_parse_sda_data(osh, p_attr, len, tlv_data);
		if (unlikely(ret)) {
			WL_ERR(("wl_cfgnan_parse_sdea_data failed,"
				"error = %d \n", ret));
		}
	}

fail:
	return ret;
}

/* Based on each case of tlv type id, fill into tlv data */
int
wl_cfgnan_set_vars_cbfn(void *ctx, const uint8 *data, uint16 type, uint16 len)
{
	nan_parse_event_ctx_t *ctx_tlv_data = ((nan_parse_event_ctx_t *)(ctx));
	nan_event_data_t *tlv_data = ((nan_event_data_t *)(ctx_tlv_data->nan_evt_data));
	int ret = BCME_OK;

	NAN_DBG_ENTER();
	if (!data || !len) {
		WL_ERR(("data length is invalid\n"));
		ret = BCME_ERROR;
		goto fail;
	}

	switch (type) {
	/*
	 * Need to parse service descript attributes including service control,
	 * when Follow up or Discovery result come
	 */
	case WL_NAN_XTLV_SD_FUP_RECEIVED:
	case WL_NAN_XTLV_SD_DISC_RESULTS: {
		ret = wl_cfgnan_parse_sd_attr_data(ctx_tlv_data->cfg->osh,
			len, data, tlv_data, type);
		break;
	}
	case WL_NAN_XTLV_SD_SVC_INFO: {
		tlv_data->svc_info.data =
			MALLOCZ(ctx_tlv_data->cfg->osh, len);
		if (!tlv_data->svc_info.data) {
			WL_ERR(("%s: memory allocation failed\n", __FUNCTION__));
			tlv_data->svc_info.dlen = 0;
			ret = BCME_NOMEM;
			goto fail;
		}
		tlv_data->svc_info.dlen = len;
		ret = memcpy_s(tlv_data->svc_info.data, tlv_data->svc_info.dlen,
				data, tlv_data->svc_info.dlen);
		if (ret != BCME_OK) {
			WL_ERR(("Failed to copy svc info data\n"));
			goto fail;
		}
		break;
	}
	default:
		WL_ERR(("Not available for tlv type = 0x%x\n", type));
		ret = BCME_ERROR;
		break;
	}
fail:
	NAN_DBG_EXIT();
	return ret;
}

int
wl_cfg_nan_check_cmd_len(uint16 nan_iov_len, uint16 data_size,
		uint16 *subcmd_len)
{
	s32 ret = BCME_OK;

	if (subcmd_len != NULL) {
		*subcmd_len = OFFSETOF(bcm_iov_batch_subcmd_t, data) +
				ALIGN_SIZE(data_size, 4);
		if (*subcmd_len > nan_iov_len) {
			WL_ERR(("%s: Buf short, requested:%d, available:%d\n",
					__FUNCTION__, *subcmd_len, nan_iov_len));
			ret = BCME_NOMEM;
		}
	} else {
		WL_ERR(("Invalid subcmd_len\n"));
		ret = BCME_ERROR;
	}
	return ret;
}

int
wl_cfgnan_config_eventmask(struct net_device *ndev, struct bcm_cfg80211 *cfg,
	uint8 event_ind_flag, bool disable_events)
{
	bcm_iov_batch_buf_t *nan_buf = NULL;
	s32 ret = BCME_OK;
	uint16 nan_buf_size = NAN_IOCTL_BUF_SIZE;
	uint16 subcmd_len;
	uint32 status;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	bcm_iov_batch_subcmd_t *sub_cmd_resp = NULL;
	uint8 event_mask[WL_NAN_EVMASK_EXTN_LEN];
	wl_nan_evmask_extn_t *evmask;
	uint16 evmask_cmd_len;
	uint8 resp_buf[NAN_IOCTL_BUF_SIZE];

	NAN_DBG_ENTER();

	/* same src and dest len here */
	(void)memset_s(event_mask, WL_NAN_EVMASK_EXTN_VER, 0, WL_NAN_EVMASK_EXTN_VER);
	evmask_cmd_len = OFFSETOF(wl_nan_evmask_extn_t, evmask) +
		WL_NAN_EVMASK_EXTN_LEN;
	ret = wl_add_remove_eventmsg(ndev, WLC_E_NAN, true);
	if (unlikely(ret)) {
		WL_ERR((" nan event enable failed, error = %d \n", ret));
		goto fail;
	}

	nan_buf = MALLOCZ(cfg->osh, nan_buf_size);
	if (!nan_buf) {
		WL_ERR(("%s: memory allocation failed\n", __func__));
		ret = BCME_NOMEM;
		goto fail;
	}

	nan_buf->version = htol16(WL_NAN_IOV_BATCH_VERSION);
	nan_buf->count = 0;
	nan_buf_size -= OFFSETOF(bcm_iov_batch_buf_t, cmds[0]);
	sub_cmd = (bcm_iov_batch_subcmd_t*)(uint8 *)(&nan_buf->cmds[0]);

	ret = wl_cfg_nan_check_cmd_len(nan_buf_size,
			evmask_cmd_len, &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		goto fail;
	}

	sub_cmd->id = htod16(WL_NAN_CMD_CFG_EVENT_MASK);
	sub_cmd->len = sizeof(sub_cmd->u.options) + evmask_cmd_len;
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);
	evmask = (wl_nan_evmask_extn_t *)sub_cmd->data;
	evmask->ver = WL_NAN_EVMASK_EXTN_VER;
	evmask->len = WL_NAN_EVMASK_EXTN_LEN;
	nan_buf_size -= subcmd_len;
	nan_buf->count = 1;

	if (disable_events) {
		WL_DBG(("Disabling all nan events..except stop event\n"));
		setbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_STOP));
	} else {
		/*
		 * Android framework event mask configuration.
		 */
		nan_buf->is_set = false;
		memset(resp_buf, 0, sizeof(resp_buf));
		ret = wl_cfgnan_execute_ioctl(ndev, cfg, nan_buf, nan_buf_size, &status,
				(void*)resp_buf, NAN_IOCTL_BUF_SIZE);
		if (unlikely(ret) || unlikely(status)) {
			WL_ERR(("get nan event mask failed ret %d status %d \n",
				ret, status));
			goto fail;
		}
		sub_cmd_resp = &((bcm_iov_batch_buf_t *)(resp_buf))->cmds[0];
		evmask = (wl_nan_evmask_extn_t *)sub_cmd_resp->data;

		/* check the response buff */
		/* same src and dest len here */
		(void)memcpy_s(&event_mask, WL_NAN_EVMASK_EXTN_LEN,
				(uint8*)&evmask->evmask, WL_NAN_EVMASK_EXTN_LEN);

		if (event_ind_flag) {
			if (CHECK_BIT(event_ind_flag, WL_NAN_EVENT_DIC_MAC_ADDR_BIT)) {
				WL_DBG(("Need to add disc mac addr change event\n"));
			}
			/* BIT2 - Disable nan cluster join indication (OTA). */
			if (CHECK_BIT(event_ind_flag, WL_NAN_EVENT_JOIN_EVENT)) {
				clrbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_MERGE));
			}
		}

		setbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_DISCOVERY_RESULT));
		setbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_RECEIVE));
		setbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_TERMINATED));
		setbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_STOP));
		setbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_TXS));
		setbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_PEER_DATAPATH_IND));
		setbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_DATAPATH_ESTB));
		setbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_DATAPATH_END));
		setbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_RNG_REQ_IND));
		setbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_RNG_TERM_IND));
		setbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_DISC_CACHE_TIMEOUT));
		/* Disable below events by default */
		clrbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_PEER_SCHED_UPD_NOTIF));
		clrbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_RNG_RPT_IND));
		clrbit(event_mask, NAN_EVENT_MAP(WL_NAN_EVENT_DW_END));
	}

	nan_buf->is_set = true;
	evmask = (wl_nan_evmask_extn_t *)sub_cmd->data;
	/* same src and dest len here */
	(void)memcpy_s((uint8*)&evmask->evmask, WL_NAN_EVMASK_EXTN_LEN,
		&event_mask, WL_NAN_EVMASK_EXTN_LEN);

	nan_buf_size = (NAN_IOCTL_BUF_SIZE - nan_buf_size);
	ret = wl_cfgnan_execute_ioctl(ndev, cfg, nan_buf, nan_buf_size, &status,
			(void*)resp_buf, NAN_IOCTL_BUF_SIZE);
	if (unlikely(ret) || unlikely(status)) {
		WL_ERR(("set nan event mask failed ret %d status %d \n", ret, status));
		goto fail;
	}
	WL_DBG(("set nan event mask successfull\n"));

fail:
	if (nan_buf) {
		MFREE(cfg->osh, nan_buf, NAN_IOCTL_BUF_SIZE);
	}
	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_set_nan_avail(struct net_device *ndev,
		struct bcm_cfg80211 *cfg, nan_avail_cmd_data *cmd_data, uint8 avail_type)
{
	bcm_iov_batch_buf_t *nan_buf = NULL;
	s32 ret = BCME_OK;
	uint16 nan_buf_size = NAN_IOCTL_BUF_SIZE;
	uint16 subcmd_len;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	wl_nan_iov_t *nan_iov_data = NULL;
	wl_avail_t *avail = NULL;
	wl_avail_entry_t *entry;	/* used for filling entry structure */
	uint8 *p;	/* tracking pointer */
	uint8 i;
	u32 status;
	int c;
	char ndc_id[ETHER_ADDR_LEN] = { 0x50, 0x6f, 0x9a, 0x01, 0x0, 0x0 };
	dhd_pub_t *dhdp = wl_cfg80211_get_dhdp(ndev);
	char *a = WL_AVAIL_BIT_MAP;
	uint8 resp_buf[NAN_IOCTL_BUF_SIZE];

	NAN_DBG_ENTER();

	/* Do not disturb avail if dam is supported */
	if (FW_SUPPORTED(dhdp, autodam)) {
		WL_DBG(("DAM is supported, avail modification not allowed\n"));
		return ret;
	}

	if (avail_type < WL_AVAIL_LOCAL || avail_type > WL_AVAIL_TYPE_MAX) {
		WL_ERR(("Invalid availability type\n"));
		ret = BCME_USAGE_ERROR;
		goto fail;
	}

	nan_buf = MALLOCZ(cfg->osh, nan_buf_size);
	if (!nan_buf) {
		WL_ERR(("%s: memory allocation failed\n", __func__));
		ret = BCME_NOMEM;
		goto fail;
	}

	nan_iov_data = MALLOCZ(cfg->osh, sizeof(*nan_iov_data));
	if (!nan_iov_data) {
		WL_ERR(("%s: memory allocation failed\n", __func__));
		ret = BCME_NOMEM;
		goto fail;
	}

	nan_iov_data->nan_iov_len = NAN_IOCTL_BUF_SIZE;
	nan_buf->version = htol16(WL_NAN_IOV_BATCH_VERSION);
	nan_buf->count = 0;
	nan_iov_data->nan_iov_buf = (uint8 *)(&nan_buf->cmds[0]);
	nan_iov_data->nan_iov_len -= OFFSETOF(bcm_iov_batch_buf_t, cmds[0]);

	sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);
	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(*avail), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		goto fail;
	}
	avail = (wl_avail_t *)sub_cmd->data;

	/* populate wl_avail_type */
	avail->flags = avail_type;
	if (avail_type == WL_AVAIL_RANGING) {
		ret = memcpy_s(&avail->addr, ETHER_ADDR_LEN,
			&cmd_data->peer_nmi, ETHER_ADDR_LEN);
		if (ret != BCME_OK) {
			WL_ERR(("Failed to copy peer nmi\n"));
			goto fail;
		}
	}

	sub_cmd->len = sizeof(sub_cmd->u.options) + subcmd_len;
	sub_cmd->id = htod16(WL_NAN_CMD_CFG_AVAIL);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);

	nan_buf->is_set = false;
	nan_buf->count++;
	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_buf_size = (NAN_IOCTL_BUF_SIZE - nan_iov_data->nan_iov_len);

	WL_TRACE(("Read wl nan avail status\n"));

	memset_s(resp_buf, sizeof(resp_buf), 0, sizeof(resp_buf));
	ret = wl_cfgnan_execute_ioctl(ndev, cfg, nan_buf, nan_buf_size, &status,
			(void*)resp_buf, NAN_IOCTL_BUF_SIZE);
	if (unlikely(ret)) {
		WL_ERR(("\n Get nan avail failed ret %d, status %d \n", ret, status));
		goto fail;
	}

	if (status == BCME_NOTFOUND) {
		nan_buf->count = 0;
		nan_iov_data->nan_iov_buf = (uint8 *)(&nan_buf->cmds[0]);
		nan_iov_data->nan_iov_len -= OFFSETOF(bcm_iov_batch_buf_t, cmds[0]);

		sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);

		avail = (wl_avail_t *)sub_cmd->data;
		p = avail->entry;

		/* populate wl_avail fields */
		avail->length = OFFSETOF(wl_avail_t, entry);
		avail->flags = avail_type;
		avail->num_entries = 0;
		avail->id = 0;
		entry = (wl_avail_entry_t*)p;
		entry->flags = WL_AVAIL_ENTRY_COM;

		/* set default values for optional parameters */
		entry->start_offset = 0;
		entry->u.band = 0;

		if (cmd_data->avail_period) {
			entry->period = cmd_data->avail_period;
		} else {
			entry->period = WL_AVAIL_PERIOD_1024;
		}

		if (cmd_data->duration != NAN_BAND_INVALID) {
			entry->flags |= (3 << WL_AVAIL_ENTRY_USAGE_SHIFT) |
				(cmd_data->duration << WL_AVAIL_ENTRY_BIT_DUR_SHIFT);
		} else {
			entry->flags |= (3 << WL_AVAIL_ENTRY_USAGE_SHIFT) |
				(WL_AVAIL_BIT_DUR_16 << WL_AVAIL_ENTRY_BIT_DUR_SHIFT);
		}
		entry->bitmap_len = 0;

		if (avail_type == WL_AVAIL_LOCAL) {
			entry->flags |= 1 << WL_AVAIL_ENTRY_CHAN_SHIFT;
			/* Check for 5g support, based on that choose 5g channel */
			if (cfg->support_5g) {
				entry->u.channel_info =
					htod32(wf_channel2chspec(WL_AVAIL_CHANNEL_5G,
						WL_AVAIL_BANDWIDTH_5G));
			} else {
				entry->u.channel_info =
					htod32(wf_channel2chspec(WL_AVAIL_CHANNEL_2G,
						WL_AVAIL_BANDWIDTH_2G));
			}
			entry->flags = htod16(entry->flags);
		}

		if (cfg->support_5g) {
			a = WL_5G_AVAIL_BIT_MAP;
		}

		/* point to bitmap value for processing */
		if (cmd_data->bmap) {
			for (c = (WL_NAN_EVENT_CLEAR_BIT-1); c >= 0; c--) {
				i = cmd_data->bmap >> c;
				if (i & 1) {
					setbit(entry->bitmap, (WL_NAN_EVENT_CLEAR_BIT-c-1));
				}
			}
		} else {
			for (i = 0; i < strlen(WL_AVAIL_BIT_MAP); i++) {
				if (*a == '1') {
					setbit(entry->bitmap, i);
				}
				a++;
			}
		}

		/* account for partially filled most significant byte */
		entry->bitmap_len = ((WL_NAN_EVENT_CLEAR_BIT) + NBBY - 1) / NBBY;
		if (avail_type == WL_AVAIL_NDC) {
			ret = memcpy_s(&avail->addr, ETHER_ADDR_LEN,
					ndc_id, ETHER_ADDR_LEN);
			if (ret != BCME_OK) {
				WL_ERR(("Failed to copy ndc id\n"));
				goto fail;
			}
		} else if (avail_type == WL_AVAIL_RANGING) {
			ret = memcpy_s(&avail->addr, ETHER_ADDR_LEN,
					&cmd_data->peer_nmi, ETHER_ADDR_LEN);
			if (ret != BCME_OK) {
				WL_ERR(("Failed to copy peer nmi\n"));
				goto fail;
			}
		}
		/* account for partially filled most significant byte */

		/* update wl_avail and populate wl_avail_entry */
		entry->length = OFFSETOF(wl_avail_entry_t, bitmap) + entry->bitmap_len;
		avail->num_entries++;
		avail->length += entry->length;
		/* advance pointer for next entry */
		p += entry->length;

		/* convert to dongle endianness */
		entry->length = htod16(entry->length);
		entry->start_offset = htod16(entry->start_offset);
		entry->u.channel_info = htod32(entry->u.channel_info);
		entry->flags = htod16(entry->flags);
		/* update avail_len only if
		 * there are avail entries
		 */
		if (avail->num_entries) {
			nan_iov_data->nan_iov_len -= avail->length;
			avail->length = htod16(avail->length);
			avail->flags = htod16(avail->flags);
		}
		avail->length = htod16(avail->length);

		sub_cmd->id = htod16(WL_NAN_CMD_CFG_AVAIL);
		sub_cmd->len = sizeof(sub_cmd->u.options) + avail->length;
		sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);

		nan_buf->is_set = true;
		nan_buf->count++;

		/* Reduce the iov_len size by subcmd_len */
		nan_iov_data->nan_iov_len -= subcmd_len;
		nan_buf_size = (NAN_IOCTL_BUF_SIZE - nan_iov_data->nan_iov_len);

		ret = wl_cfgnan_execute_ioctl(ndev, cfg, nan_buf, nan_buf_size, &status,
				(void*)resp_buf, NAN_IOCTL_BUF_SIZE);
		if (unlikely(ret) || unlikely(status)) {
			WL_ERR(("\n set nan avail failed ret %d status %d \n", ret, status));
			ret = status;
			goto fail;
		}
	} else if (status == BCME_OK) {
		WL_DBG(("Avail type [%d] found to be configured\n", avail_type));
	} else {
		WL_ERR(("set nan avail failed ret %d status %d \n", ret, status));
	}

fail:
	if (nan_buf) {
		MFREE(cfg->osh, nan_buf, NAN_IOCTL_BUF_SIZE);
	}
	if (nan_iov_data) {
		MFREE(cfg->osh, nan_iov_data, sizeof(*nan_iov_data));
	}

	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_config_control_flag(struct net_device *ndev, struct bcm_cfg80211 *cfg,
		uint32 flag, uint32 *status, bool set)
{
	bcm_iov_batch_buf_t *nan_buf = NULL;
	s32 ret = BCME_OK;
	uint16 nan_iov_start, nan_iov_end;
	uint16 nan_buf_size = NAN_IOCTL_BUF_SIZE;
	uint16 subcmd_len;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	bcm_iov_batch_subcmd_t *sub_cmd_resp = NULL;
	wl_nan_iov_t *nan_iov_data = NULL;
	uint32 cfg_ctrl;
	uint8 resp_buf[NAN_IOCTL_BUF_SIZE];

	NAN_DBG_ENTER();
	WL_INFORM_MEM(("%s: Modifying nan ctrl flag %x val %d",
		__FUNCTION__, flag, set));
	nan_buf = MALLOCZ(cfg->osh, nan_buf_size);
	if (!nan_buf) {
		WL_ERR(("%s: memory allocation failed\n", __func__));
		ret = BCME_NOMEM;
		goto fail;
	}

	nan_iov_data = MALLOCZ(cfg->osh, sizeof(*nan_iov_data));
	if (!nan_iov_data) {
		WL_ERR(("%s: memory allocation failed\n", __func__));
		ret = BCME_NOMEM;
		goto fail;
	}

	nan_iov_data->nan_iov_len = nan_iov_start = NAN_IOCTL_BUF_SIZE;
	nan_buf->version = htol16(WL_NAN_IOV_BATCH_VERSION);
	nan_buf->count = 0;
	nan_iov_data->nan_iov_buf = (uint8 *)(&nan_buf->cmds[0]);
	nan_iov_data->nan_iov_len -= OFFSETOF(bcm_iov_batch_buf_t, cmds[0]);
	sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);

	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(cfg_ctrl), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		goto fail;
	}

	sub_cmd->id = htod16(WL_NAN_CMD_CFG_NAN_CONFIG);
	sub_cmd->len = sizeof(sub_cmd->u.options) + sizeof(cfg_ctrl);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);

	nan_buf->is_set = false;
	nan_buf->count++;

	/* Reduce the iov_len size by subcmd_len */
	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_end = nan_iov_data->nan_iov_len;
	nan_buf_size = (nan_iov_start - nan_iov_end);

	memset_s(resp_buf, sizeof(resp_buf), 0, sizeof(resp_buf));
	ret = wl_cfgnan_execute_ioctl(ndev, cfg, nan_buf, nan_buf_size, status,
			(void*)resp_buf, NAN_IOCTL_BUF_SIZE);
	if (unlikely(ret) || unlikely(*status)) {
		WL_ERR(("get nan cfg ctrl failed ret %d status %d \n", ret, *status));
		goto fail;
	}
	sub_cmd_resp = &((bcm_iov_batch_buf_t *)(resp_buf))->cmds[0];

	/* check the response buff */
	cfg_ctrl = (*(uint32 *)&sub_cmd_resp->data[0]);
	if (set) {
		cfg_ctrl |= flag;
	} else {
		cfg_ctrl &= ~flag;
	}
	ret = memcpy_s(sub_cmd->data, sizeof(cfg_ctrl),
			&cfg_ctrl, sizeof(cfg_ctrl));
	if (ret != BCME_OK) {
		WL_ERR(("Failed to copy cfg ctrl\n"));
		goto fail;
	}

	nan_buf->is_set = true;
	ret = wl_cfgnan_execute_ioctl(ndev, cfg, nan_buf, nan_buf_size, status,
			(void*)resp_buf, NAN_IOCTL_BUF_SIZE);
	if (unlikely(ret) || unlikely(*status)) {
		WL_ERR(("set nan cfg ctrl failed ret %d status %d \n", ret, *status));
		goto fail;
	}
	WL_DBG(("set nan cfg ctrl successfull\n"));
fail:
	if (nan_buf) {
		MFREE(cfg->osh, nan_buf, NAN_IOCTL_BUF_SIZE);
	}
	if (nan_iov_data) {
		MFREE(cfg->osh, nan_iov_data, sizeof(*nan_iov_data));
	}

	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_get_iovars_status(void *ctx, const uint8 *data, uint16 type, uint16 len)
{
	bcm_iov_batch_buf_t *b_resp = (bcm_iov_batch_buf_t *)ctx;
	uint32 status;
	/* if all tlvs are parsed, we should not be here */
	if (b_resp->count == 0) {
		return BCME_BADLEN;
	}

	/*  cbfn params may be used in f/w */
	if (len < sizeof(status)) {
		return BCME_BUFTOOSHORT;
	}

	/* first 4 bytes consists status */
	if (memcpy_s(&status, sizeof(status),
			data, sizeof(uint32)) != BCME_OK) {
		WL_ERR(("Failed to copy status\n"));
		goto exit;
	}

	status = dtoh32(status);

	/* If status is non zero */
	if (status != BCME_OK) {
		printf("cmd type %d failed, status: %04x\n", type, status);
		goto exit;
	}

	if (b_resp->count > 0) {
		b_resp->count--;
	}

	if (!b_resp->count) {
		status = BCME_IOV_LAST_CMD;
	}
exit:
	return status;
}

static int
wl_cfgnan_execute_ioctl(struct net_device *ndev, struct bcm_cfg80211 *cfg,
	bcm_iov_batch_buf_t *nan_buf, uint16 nan_buf_size, uint32 *status,
	uint8 *resp_buf, uint16 resp_buf_size)
{
	int ret = BCME_OK;
	uint16 tlvs_len;
	int res = BCME_OK;
	bcm_iov_batch_buf_t *p_resp = NULL;
	char *iov = "nan";
	int max_resp_len = WLC_IOCTL_MAXLEN;

	WL_DBG(("Enter:\n"));
	if (nan_buf->is_set) {
		ret = wldev_iovar_setbuf(ndev, "nan", nan_buf, nan_buf_size,
			resp_buf, resp_buf_size, NULL);
		p_resp = (bcm_iov_batch_buf_t *)(resp_buf + strlen(iov) + 1);
	} else {
		ret = wldev_iovar_getbuf(ndev, "nan", nan_buf, nan_buf_size,
			resp_buf, resp_buf_size, NULL);
		p_resp = (bcm_iov_batch_buf_t *)(resp_buf);
	}
	if (unlikely(ret)) {
		WL_ERR((" nan execute ioctl failed, error = %d \n", ret));
		goto fail;
	}

	p_resp->is_set = nan_buf->is_set;
	tlvs_len = max_resp_len - OFFSETOF(bcm_iov_batch_buf_t, cmds[0]);

	/* Extract the tlvs and print their resp in cb fn */
	res = bcm_unpack_xtlv_buf((void *)p_resp, (const uint8 *)&p_resp->cmds[0],
		tlvs_len, BCM_IOV_CMD_OPT_ALIGN32, wl_cfgnan_get_iovars_status);

	if (res == BCME_IOV_LAST_CMD) {
		res = BCME_OK;
	}
fail:
	*status = res;
	WL_DBG((" nan ioctl ret %d status %d \n", ret, *status));
	return ret;

}

static int
wl_cfgnan_if_addr_handler(void *p_buf, uint16 *nan_buf_size,
		struct ether_addr *if_addr)
{
	/* nan enable */
	s32 ret = BCME_OK;
	uint16 subcmd_len;

	NAN_DBG_ENTER();

	if (p_buf != NULL) {
		bcm_iov_batch_subcmd_t *sub_cmd = (bcm_iov_batch_subcmd_t*)(p_buf);

		ret = wl_cfg_nan_check_cmd_len(*nan_buf_size,
				sizeof(*if_addr), &subcmd_len);
		if (unlikely(ret)) {
			WL_ERR(("nan_sub_cmd check failed\n"));
			goto fail;
		}

		/* Fill the sub_command block */
		sub_cmd->id = htod16(WL_NAN_CMD_CFG_IF_ADDR);
		sub_cmd->len = sizeof(sub_cmd->u.options) + sizeof(*if_addr);
		sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);
		ret = memcpy_s(sub_cmd->data, sizeof(*if_addr),
				(uint8 *)if_addr, sizeof(*if_addr));
		if (ret != BCME_OK) {
			WL_ERR(("Failed to copy if addr\n"));
			goto fail;
		}

		*nan_buf_size -= subcmd_len;
	} else {
		WL_ERR(("nan_iov_buf is NULL\n"));
		ret = BCME_ERROR;
		goto fail;
	}

fail:
	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_get_ver(struct net_device *ndev, struct bcm_cfg80211 *cfg)
{
	bcm_iov_batch_buf_t *nan_buf = NULL;
	s32 ret = BCME_OK;
	uint16 nan_buf_size = NAN_IOCTL_BUF_SIZE;
	wl_nan_ver_t *nan_ver = NULL;
	uint16 subcmd_len;
	uint32 status;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	bcm_iov_batch_subcmd_t *sub_cmd_resp = NULL;
	uint8 resp_buf[NAN_IOCTL_BUF_SIZE];

	NAN_DBG_ENTER();
	nan_buf = MALLOCZ(cfg->osh, nan_buf_size);
	if (!nan_buf) {
		WL_ERR(("%s: memory allocation failed\n", __func__));
		ret = BCME_NOMEM;
		goto fail;
	}

	nan_buf->version = htol16(WL_NAN_IOV_BATCH_VERSION);
	nan_buf->count = 0;
	nan_buf_size -= OFFSETOF(bcm_iov_batch_buf_t, cmds[0]);
	sub_cmd = (bcm_iov_batch_subcmd_t*)(uint8 *)(&nan_buf->cmds[0]);

	ret = wl_cfg_nan_check_cmd_len(nan_buf_size,
			sizeof(*nan_ver), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		goto fail;
	}

	nan_ver = (wl_nan_ver_t *)sub_cmd->data;
	sub_cmd->id = htod16(WL_NAN_CMD_GLB_NAN_VER);
	sub_cmd->len = sizeof(sub_cmd->u.options) + sizeof(*nan_ver);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);
	nan_buf_size -= subcmd_len;
	nan_buf->count = 1;

	nan_buf->is_set = false;
	bzero(resp_buf, sizeof(resp_buf));
	nan_buf_size = NAN_IOCTL_BUF_SIZE - nan_buf_size;

	ret = wl_cfgnan_execute_ioctl(ndev, cfg, nan_buf, nan_buf_size, &status,
			(void*)resp_buf, NAN_IOCTL_BUF_SIZE);
	if (unlikely(ret) || unlikely(status)) {
		WL_ERR(("get nan ver failed ret %d status %d \n",
				ret, status));
		goto fail;
	}

	sub_cmd_resp = &((bcm_iov_batch_buf_t *)(resp_buf))->cmds[0];
	nan_ver = ((wl_nan_ver_t *)&sub_cmd_resp->data[0]);
	if (!nan_ver) {
		ret = BCME_NOTFOUND;
		WL_ERR(("nan_ver not found: err = %d\n", ret));
		goto fail;
	}
	cfg->nancfg.version = *nan_ver;
	WL_INFORM_MEM(("Nan Version is %d\n", cfg->nancfg.version));

fail:
	if (nan_buf) {
		MFREE(cfg->osh, nan_buf, NAN_IOCTL_BUF_SIZE);
	}
	NAN_DBG_EXIT();
	return ret;

}

static int
wl_cfgnan_set_if_addr(struct bcm_cfg80211 *cfg)
{
	s32 ret = BCME_OK;
	uint16 nan_buf_size = NAN_IOCTL_BUF_SIZE;
	uint32 status;
	uint8 resp_buf[NAN_IOCTL_BUF_SIZE];
	struct ether_addr if_addr;
	uint8 buf[NAN_IOCTL_BUF_SIZE];
	bcm_iov_batch_buf_t *nan_buf = (bcm_iov_batch_buf_t*)buf;
	bool rand_mac = cfg->nancfg.mac_rand;

	nan_buf->version = htol16(WL_NAN_IOV_BATCH_VERSION);
	nan_buf->count = 0;
	nan_buf_size -= OFFSETOF(bcm_iov_batch_buf_t, cmds[0]);
	if (rand_mac) {
		RANDOM_BYTES(if_addr.octet, 6);
		/* restore mcast and local admin bits to 0 and 1 */
		ETHER_SET_UNICAST(if_addr.octet);
		ETHER_SET_LOCALADDR(if_addr.octet);
	} else {
		/* Use primary MAC with the locally administered bit for the
		 * NAN NMI I/F
		 */
		if (wl_get_vif_macaddr(cfg, WL_IF_TYPE_NAN_NMI,
				if_addr.octet) != BCME_OK) {
			ret = -EINVAL;
			WL_ERR(("Failed to get mac addr for NMI\n"));
			goto fail;
		}
	}
	WL_INFORM_MEM(("%s: NMI " MACDBG "\n",
			__FUNCTION__, MAC2STRDBG(if_addr.octet)));
	ret = wl_cfgnan_if_addr_handler(&nan_buf->cmds[0],
			&nan_buf_size, &if_addr);
	if (unlikely(ret)) {
		WL_ERR(("Nan if addr handler sub_cmd set failed\n"));
		goto fail;
	}
	nan_buf->count++;
	nan_buf->is_set = true;
	nan_buf_size = NAN_IOCTL_BUF_SIZE - nan_buf_size;
	memset_s(resp_buf, sizeof(resp_buf), 0, sizeof(resp_buf));
	ret = wl_cfgnan_execute_ioctl(bcmcfg_to_prmry_ndev(cfg), cfg,
			nan_buf, nan_buf_size, &status,
			(void*)resp_buf, NAN_IOCTL_BUF_SIZE);
	if (unlikely(ret) || unlikely(status)) {
		WL_ERR(("nan if addr handler failed ret %d status %d\n",
				ret, status));
		goto fail;
	}
	ret = memcpy_s(cfg->nan_nmi_mac, ETH_ALEN,
			if_addr.octet, ETH_ALEN);
	if (ret != BCME_OK) {
		WL_ERR(("Failed to copy nmi addr\n"));
		goto fail;
	}
	return ret;
fail:
	if (!rand_mac) {
		wl_release_vif_macaddr(cfg, if_addr.octet, WL_IF_TYPE_NAN_NMI);
	}

	return ret;
}

static int
wl_cfgnan_init_handler(void *p_buf, uint16 *nan_buf_size, bool val)
{
	/* nan enable */
	s32 ret = BCME_OK;
	uint16 subcmd_len;

	NAN_DBG_ENTER();

	if (p_buf != NULL) {
		bcm_iov_batch_subcmd_t *sub_cmd = (bcm_iov_batch_subcmd_t*)(p_buf);

		ret = wl_cfg_nan_check_cmd_len(*nan_buf_size,
				sizeof(val), &subcmd_len);
		if (unlikely(ret)) {
			WL_ERR(("nan_sub_cmd check failed\n"));
			goto fail;
		}

		/* Fill the sub_command block */
		sub_cmd->id = htod16(WL_NAN_CMD_CFG_NAN_INIT);
		sub_cmd->len = sizeof(sub_cmd->u.options) + sizeof(uint8);
		sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);
		ret = memcpy_s(sub_cmd->data, sizeof(uint8),
				(uint8*)&val, sizeof(uint8));
		if (ret != BCME_OK) {
			WL_ERR(("Failed to copy init value\n"));
			goto fail;
		}

		*nan_buf_size -= subcmd_len;
	} else {
		WL_ERR(("nan_iov_buf is NULL\n"));
		ret = BCME_ERROR;
		goto fail;
	}

fail:
	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_enable_handler(wl_nan_iov_t *nan_iov_data, bool val)
{
	/* nan enable */
	s32 ret = BCME_OK;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	uint16 subcmd_len;

	NAN_DBG_ENTER();

	sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);

	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(val), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		return ret;
	}

	/* Fill the sub_command block */
	sub_cmd->id = htod16(WL_NAN_CMD_CFG_NAN_ENAB);
	sub_cmd->len = sizeof(sub_cmd->u.options) + sizeof(uint8);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);
	ret = memcpy_s(sub_cmd->data, sizeof(uint8),
			(uint8*)&val, sizeof(uint8));
	if (ret != BCME_OK) {
		WL_ERR(("Failed to copy enab value\n"));
		return ret;
	}

	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_data->nan_iov_buf += subcmd_len;
	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_warmup_time_handler(nan_config_cmd_data_t *cmd_data,
		wl_nan_iov_t *nan_iov_data)
{
	/* wl nan warm_up_time */
	s32 ret = BCME_OK;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	wl_nan_warmup_time_ticks_t *wup_ticks = NULL;
	uint16 subcmd_len;
	NAN_DBG_ENTER();

	sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);
	wup_ticks = (wl_nan_warmup_time_ticks_t *)sub_cmd->data;

	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(*wup_ticks), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		return ret;
	}
	/* Fill the sub_command block */
	sub_cmd->id = htod16(WL_NAN_CMD_CFG_WARMUP_TIME);
	sub_cmd->len = sizeof(sub_cmd->u.options) +
		sizeof(*wup_ticks);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);
	*wup_ticks = cmd_data->warmup_time;

	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_data->nan_iov_buf += subcmd_len;

	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_set_election_metric(nan_config_cmd_data_t *cmd_data,
		wl_nan_iov_t *nan_iov_data, uint32 nan_attr_mask)
{
	s32 ret = BCME_OK;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	wl_nan_election_metric_config_t *metrics = NULL;
	uint16 subcmd_len;
	NAN_DBG_ENTER();

	sub_cmd =
		(bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);
	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(*metrics), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		goto fail;
	}

	metrics = (wl_nan_election_metric_config_t *)sub_cmd->data;

	if (nan_attr_mask & NAN_ATTR_RAND_FACTOR_CONFIG) {
		metrics->random_factor = (uint8)cmd_data->metrics.random_factor;
	}

	if ((!cmd_data->metrics.master_pref) ||
		(cmd_data->metrics.master_pref > NAN_MAXIMUM_MASTER_PREFERENCE)) {
		WL_TRACE(("Master Pref is 0 or greater than 254, hence sending random value\n"));
		/* Master pref for mobile devices can be from 1 - 127 as per Spec AppendixC */
		metrics->master_pref = (RANDOM32()%(NAN_MAXIMUM_MASTER_PREFERENCE/2)) + 1;
	} else {
		metrics->master_pref = (uint8)cmd_data->metrics.master_pref;
	}
	sub_cmd->id = htod16(WL_NAN_CMD_ELECTION_METRICS_CONFIG);
	sub_cmd->len = sizeof(sub_cmd->u.options) +
		sizeof(*metrics);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);

	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_data->nan_iov_buf += subcmd_len;

fail:
	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_set_rssi_proximity(nan_config_cmd_data_t *cmd_data,
		wl_nan_iov_t *nan_iov_data, uint32 nan_attr_mask)
{
	s32 ret = BCME_OK;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	wl_nan_rssi_notif_thld_t *rssi_notif_thld = NULL;
	uint16 subcmd_len;

	NAN_DBG_ENTER();
	sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);

	rssi_notif_thld = (wl_nan_rssi_notif_thld_t *)sub_cmd->data;

	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(*rssi_notif_thld), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		return ret;
	}
	if (nan_attr_mask & NAN_ATTR_RSSI_PROXIMITY_2G_CONFIG) {
		rssi_notif_thld->bcn_rssi_2g =
			cmd_data->rssi_attr.rssi_proximity_2dot4g_val;
	} else {
		/* Keeping RSSI threshold value to be -70dBm */
		rssi_notif_thld->bcn_rssi_2g = NAN_DEF_RSSI_NOTIF_THRESH;
	}

	if (nan_attr_mask & NAN_ATTR_RSSI_PROXIMITY_5G_CONFIG) {
		rssi_notif_thld->bcn_rssi_5g =
			cmd_data->rssi_attr.rssi_proximity_5g_val;
	} else {
		/* Keeping RSSI threshold value to be -70dBm */
		rssi_notif_thld->bcn_rssi_5g = NAN_DEF_RSSI_NOTIF_THRESH;
	}

	sub_cmd->id = htod16(WL_NAN_CMD_SYNC_BCN_RSSI_NOTIF_THRESHOLD);
	sub_cmd->len = htod16(sizeof(sub_cmd->u.options) + sizeof(*rssi_notif_thld));
	sub_cmd->u.options = htod32(BCM_XTLV_OPTION_ALIGN32);

	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_data->nan_iov_buf += subcmd_len;

	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_set_rssi_mid_or_close(nan_config_cmd_data_t *cmd_data,
		wl_nan_iov_t *nan_iov_data, uint32 nan_attr_mask)
{
	s32 ret = BCME_OK;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	wl_nan_rssi_thld_t *rssi_thld = NULL;
	uint16 subcmd_len;

	NAN_DBG_ENTER();
	sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);
	rssi_thld = (wl_nan_rssi_thld_t *)sub_cmd->data;

	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(*rssi_thld), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		return ret;
	}

	/*
	 * Keeping RSSI mid value -75dBm for both 2G and 5G
	 * Keeping RSSI close value -60dBm for both 2G and 5G
	 */
	if (nan_attr_mask & NAN_ATTR_RSSI_MIDDLE_2G_CONFIG) {
		rssi_thld->rssi_mid_2g =
			cmd_data->rssi_attr.rssi_middle_2dot4g_val;
	} else {
		rssi_thld->rssi_mid_2g = NAN_DEF_RSSI_MID;
	}

	if (nan_attr_mask & NAN_ATTR_RSSI_MIDDLE_5G_CONFIG) {
		rssi_thld->rssi_mid_5g =
			cmd_data->rssi_attr.rssi_middle_5g_val;
	} else {
		rssi_thld->rssi_mid_5g = NAN_DEF_RSSI_MID;
	}

	if (nan_attr_mask & NAN_ATTR_RSSI_CLOSE_CONFIG) {
		rssi_thld->rssi_close_2g =
			cmd_data->rssi_attr.rssi_close_2dot4g_val;
	} else {
		rssi_thld->rssi_close_2g = NAN_DEF_RSSI_CLOSE;
	}

	if (nan_attr_mask & NAN_ATTR_RSSI_CLOSE_5G_CONFIG) {
		rssi_thld->rssi_close_5g =
			cmd_data->rssi_attr.rssi_close_5g_val;
	} else {
		rssi_thld->rssi_close_5g = NAN_DEF_RSSI_CLOSE;
	}

	sub_cmd->id = htod16(WL_NAN_CMD_ELECTION_RSSI_THRESHOLD);
	sub_cmd->len = htod16(sizeof(sub_cmd->u.options) + sizeof(*rssi_thld));
	sub_cmd->u.options = htod32(BCM_XTLV_OPTION_ALIGN32);

	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_data->nan_iov_buf += subcmd_len;

	NAN_DBG_EXIT();
	return ret;
}

static int
check_for_valid_5gchan(struct net_device *ndev, uint8 chan)
{
	s32 ret = BCME_OK;
	uint bitmap;
	u8 ioctl_buf[WLC_IOCTL_SMLEN];
	uint32 chanspec_arg;
	NAN_DBG_ENTER();

	chanspec_arg = CH20MHZ_CHSPEC(chan);
	chanspec_arg = wl_chspec_host_to_driver(chanspec_arg);
	memset_s(ioctl_buf, WLC_IOCTL_SMLEN, 0, WLC_IOCTL_SMLEN);
	ret = wldev_iovar_getbuf(ndev, "per_chan_info",
			(void *)&chanspec_arg, sizeof(chanspec_arg),
			ioctl_buf, WLC_IOCTL_SMLEN, NULL);
	if (ret != BCME_OK) {
		WL_ERR(("Chaninfo for channel = %d, error %d\n", chan, ret));
		goto exit;
	}

	bitmap = dtoh32(*(uint *)ioctl_buf);
	if (!(bitmap & WL_CHAN_VALID_HW)) {
		WL_ERR(("Invalid channel\n"));
		ret = BCME_BADCHAN;
		goto exit;
	}

	if (!(bitmap & WL_CHAN_VALID_SW)) {
		WL_ERR(("Not supported in current locale\n"));
		ret = BCME_BADCHAN;
		goto exit;
	}
exit:
	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_set_nan_soc_chans(struct net_device *ndev, nan_config_cmd_data_t *cmd_data,
	wl_nan_iov_t *nan_iov_data, uint32 nan_attr_mask)
{
	s32 ret = BCME_OK;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	wl_nan_social_channels_t *soc_chans = NULL;
	uint16 subcmd_len;

	NAN_DBG_ENTER();

	sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);
	soc_chans =
		(wl_nan_social_channels_t *)sub_cmd->data;

	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(*soc_chans), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		return ret;
	}

	sub_cmd->id = htod16(WL_NAN_CMD_SYNC_SOCIAL_CHAN);
	sub_cmd->len = sizeof(sub_cmd->u.options) +
		sizeof(*soc_chans);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);
	if (nan_attr_mask & NAN_ATTR_2G_CHAN_CONFIG) {
		soc_chans->soc_chan_2g = cmd_data->chanspec[1];
	} else {
		soc_chans->soc_chan_2g = NAN_DEF_SOCIAL_CHAN_2G;
	}

	if (cmd_data->support_5g) {
		if (nan_attr_mask & NAN_ATTR_5G_CHAN_CONFIG) {
			soc_chans->soc_chan_5g = cmd_data->chanspec[2];
		} else {
			soc_chans->soc_chan_5g = NAN_DEF_SOCIAL_CHAN_5G;
		}
		ret = check_for_valid_5gchan(ndev, soc_chans->soc_chan_5g);
		if (ret != BCME_OK) {
			ret = check_for_valid_5gchan(ndev, NAN_DEF_SEC_SOCIAL_CHAN_5G);
			if (ret == BCME_OK) {
				soc_chans->soc_chan_5g = NAN_DEF_SEC_SOCIAL_CHAN_5G;
			} else {
				soc_chans->soc_chan_5g = 0;
				ret = BCME_OK;
				WL_ERR(("Current locale doesn't support 5G op"
					"continuing with 2G only operation\n"));
			}
		}
	} else {
		WL_DBG(("5G support is disabled\n"));
	}
	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_data->nan_iov_buf += subcmd_len;

	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_set_nan_scan_params(struct net_device *ndev, struct bcm_cfg80211 *cfg,
	nan_config_cmd_data_t *cmd_data, uint8 band_index, uint32 nan_attr_mask)
{
	bcm_iov_batch_buf_t *nan_buf = NULL;
	s32 ret = BCME_OK;
	uint16 nan_iov_start, nan_iov_end;
	uint16 nan_buf_size = NAN_IOCTL_BUF_SIZE;
	uint16 subcmd_len;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	wl_nan_iov_t *nan_iov_data = NULL;
	uint8 resp_buf[NAN_IOCTL_BUF_SIZE];
	wl_nan_scan_params_t *scan_params = NULL;
	uint32 status;

	NAN_DBG_ENTER();

	nan_buf = MALLOCZ(cfg->osh, nan_buf_size);
	if (!nan_buf) {
		WL_ERR(("%s: memory allocation failed\n", __func__));
		ret = BCME_NOMEM;
		goto fail;
	}

	nan_iov_data = MALLOCZ(cfg->osh, sizeof(*nan_iov_data));
	if (!nan_iov_data) {
		WL_ERR(("%s: memory allocation failed\n", __func__));
		ret = BCME_NOMEM;
		goto fail;
	}

	nan_iov_data->nan_iov_len = nan_iov_start = NAN_IOCTL_BUF_SIZE;
	nan_buf->version = htol16(WL_NAN_IOV_BATCH_VERSION);
	nan_buf->count = 0;
	nan_iov_data->nan_iov_buf = (uint8 *)(&nan_buf->cmds[0]);
	nan_iov_data->nan_iov_len -= OFFSETOF(bcm_iov_batch_buf_t, cmds[0]);
	sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);

	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(*scan_params), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		goto fail;
	}
	scan_params = (wl_nan_scan_params_t *)sub_cmd->data;

	sub_cmd->id = htod16(WL_NAN_CMD_CFG_SCAN_PARAMS);
	sub_cmd->len = sizeof(sub_cmd->u.options) + sizeof(*scan_params);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);

	if (!band_index) {
		/* Fw default: Dwell time for 2G is 210 */
		if ((nan_attr_mask & NAN_ATTR_2G_DWELL_TIME_CONFIG) &&
			cmd_data->dwell_time[0]) {
			scan_params->dwell_time = cmd_data->dwell_time[0] +
				NAN_SCAN_DWELL_TIME_DELTA_MS;
		}
		/* Fw default: Scan period for 2G is 10 */
		if (nan_attr_mask & NAN_ATTR_2G_SCAN_PERIOD_CONFIG) {
			scan_params->scan_period = cmd_data->scan_period[0];
		}
	} else {
		if ((nan_attr_mask & NAN_ATTR_5G_DWELL_TIME_CONFIG) &&
			cmd_data->dwell_time[1]) {
			scan_params->dwell_time = cmd_data->dwell_time[1] +
				NAN_SCAN_DWELL_TIME_DELTA_MS;
		}
		if (nan_attr_mask & NAN_ATTR_5G_SCAN_PERIOD_CONFIG) {
			scan_params->scan_period = cmd_data->scan_period[1];
		}
	}
	scan_params->band_index = band_index;
	nan_buf->is_set = true;
	nan_buf->count++;

	/* Reduce the iov_len size by subcmd_len */
	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_end = nan_iov_data->nan_iov_len;
	nan_buf_size = (nan_iov_start - nan_iov_end);

	memset_s(resp_buf, sizeof(resp_buf), 0, sizeof(resp_buf));
	ret = wl_cfgnan_execute_ioctl(ndev, cfg, nan_buf, nan_buf_size, &status,
			(void*)resp_buf, NAN_IOCTL_BUF_SIZE);
	if (unlikely(ret) || unlikely(status)) {
		WL_ERR(("set nan scan params failed ret %d status %d \n", ret, status));
		goto fail;
	}
	WL_DBG(("set nan scan params successfull\n"));
fail:
	if (nan_buf) {
		MFREE(cfg->osh, nan_buf, NAN_IOCTL_BUF_SIZE);
	}
	if (nan_iov_data) {
		MFREE(cfg->osh, nan_iov_data, sizeof(*nan_iov_data));
	}

	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_set_cluster_id(nan_config_cmd_data_t *cmd_data,
		wl_nan_iov_t *nan_iov_data)
{
	s32 ret = BCME_OK;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	uint16 subcmd_len;

	NAN_DBG_ENTER();

	sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);

	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			(sizeof(cmd_data->clus_id) - sizeof(uint8)), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		return ret;
	}

	cmd_data->clus_id.octet[0] = 0x50;
	cmd_data->clus_id.octet[1] = 0x6F;
	cmd_data->clus_id.octet[2] = 0x9A;
	cmd_data->clus_id.octet[3] = 0x01;
	WL_TRACE(("cluster_id = " MACDBG "\n", MAC2STRDBG(cmd_data->clus_id.octet)));

	sub_cmd->id = htod16(WL_NAN_CMD_CFG_CID);
	sub_cmd->len = sizeof(sub_cmd->u.options) + sizeof(cmd_data->clus_id);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);
	ret = memcpy_s(sub_cmd->data, sizeof(cmd_data->clus_id),
			(uint8 *)&cmd_data->clus_id,
			sizeof(cmd_data->clus_id));
	if (ret != BCME_OK) {
		WL_ERR(("Failed to copy clus id\n"));
		return ret;
	}

	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_data->nan_iov_buf += subcmd_len;

	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_set_hop_count_limit(nan_config_cmd_data_t *cmd_data,
		wl_nan_iov_t *nan_iov_data)
{
	s32 ret = BCME_OK;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	wl_nan_hop_count_t *hop_limit = NULL;
	uint16 subcmd_len;

	NAN_DBG_ENTER();

	sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);
	hop_limit = (wl_nan_hop_count_t *)sub_cmd->data;

	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(*hop_limit), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		return ret;
	}

	*hop_limit = cmd_data->hop_count_limit;
	sub_cmd->id = htod16(WL_NAN_CMD_CFG_HOP_LIMIT);
	sub_cmd->len = sizeof(sub_cmd->u.options) + sizeof(*hop_limit);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);

	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_data->nan_iov_buf += subcmd_len;

	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_set_sid_beacon_val(nan_config_cmd_data_t *cmd_data,
	wl_nan_iov_t *nan_iov_data, uint32 nan_attr_mask)
{
	s32 ret = BCME_OK;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	wl_nan_sid_beacon_control_t *sid_beacon = NULL;
	uint16 subcmd_len;

	NAN_DBG_ENTER();

	sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);

	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(*sid_beacon), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		return ret;
	}

	sid_beacon = (wl_nan_sid_beacon_control_t *)sub_cmd->data;
	sid_beacon->sid_enable = cmd_data->sid_beacon.sid_enable;
	/* Need to have separate flag for sub beacons
	 * sid_beacon->sub_sid_enable = cmd_data->sid_beacon.sub_sid_enable;
	 */
	if (nan_attr_mask & NAN_ATTR_SID_BEACON_CONFIG) {
		/* Limit for number of publish SIDs to be included in Beacons */
		sid_beacon->sid_count = cmd_data->sid_beacon.sid_count;
	}
	if (nan_attr_mask & NAN_ATTR_SUB_SID_BEACON_CONFIG) {
		/* Limit for number of subscribe SIDs to be included in Beacons */
		sid_beacon->sub_sid_count = cmd_data->sid_beacon.sub_sid_count;
	}
	sub_cmd->id = htod16(WL_NAN_CMD_CFG_SID_BEACON);
	sub_cmd->len = sizeof(sub_cmd->u.options) +
		sizeof(*sid_beacon);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);

	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_data->nan_iov_buf += subcmd_len;
	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_set_nan_oui(nan_config_cmd_data_t *cmd_data,
		wl_nan_iov_t *nan_iov_data)
{
	s32 ret = BCME_OK;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	uint16 subcmd_len;

	NAN_DBG_ENTER();

	sub_cmd = (bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);

	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(cmd_data->nan_oui), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		return ret;
	}

	sub_cmd->id = htod16(WL_NAN_CMD_CFG_OUI);
	sub_cmd->len = sizeof(sub_cmd->u.options) + sizeof(cmd_data->nan_oui);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);
	ret = memcpy_s(sub_cmd->data, sizeof(cmd_data->nan_oui),
			(uint32 *)&cmd_data->nan_oui,
			sizeof(cmd_data->nan_oui));
	if (ret != BCME_OK) {
		WL_ERR(("Failed to copy nan oui\n"));
		return ret;
	}

	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_data->nan_iov_buf += subcmd_len;
	NAN_DBG_EXIT();
	return ret;
}

static int
wl_cfgnan_set_awake_dws(struct net_device *ndev, nan_config_cmd_data_t *cmd_data,
		wl_nan_iov_t *nan_iov_data, struct bcm_cfg80211 *cfg, uint32 nan_attr_mask)
{
	s32 ret = BCME_OK;
	bcm_iov_batch_subcmd_t *sub_cmd = NULL;
	wl_nan_awake_dws_t *awake_dws = NULL;
	uint16 subcmd_len;
	NAN_DBG_ENTER();

	sub_cmd =
		(bcm_iov_batch_subcmd_t*)(nan_iov_data->nan_iov_buf);
	ret = wl_cfg_nan_check_cmd_len(nan_iov_data->nan_iov_len,
			sizeof(*awake_dws), &subcmd_len);
	if (unlikely(ret)) {
		WL_ERR(("nan_sub_cmd check failed\n"));
		return ret;
	}

	awake_dws = (wl_nan_awake_dws_t *)sub_cmd->data;

	if (nan_attr_mask & NAN_ATTR_2G_DW_CONFIG) {
		awake_dws->dw_interval_2g = cmd_data->awake_dws.dw_interval_2g;
		if (!awake_dws->dw_interval_2g) {
			/* Set 2G awake dw value to fw default value 1 */
			awake_dws->dw_interval_2g = NAN_SYNC_DEF_AWAKE_DW;
		}
	} else {
		/* Set 2G awake dw value to fw default value 1 */
		awake_dws->dw_interval_2g = NAN_SYNC_DEF_AWAKE_DW;
	}

	if (cfg->support_5g) {
		if (nan_attr_mask & NAN_ATTR_5G_DW_CONFIG) {
			awake_dws->dw_interval_5g = cmd_data->awake_dws.dw_interval_5g;
			if (!awake_dws->dw_interval_5g) {
				/* disable 5g beacon ctrls */
				ret = wl_cfgnan_config_control_flag(ndev, cfg,
						WL_NAN_CTRL_DISC_BEACON_TX_5G,
						&(cmd_data->status), 0);
				if (unlikely(ret) || unlikely(cmd_data->status)) {
					WL_ERR((" nan control set config handler,"
							" ret = %d status = %d \n",
							ret, cmd_data->status));
					goto fail;
				}
				ret = wl_cfgnan_config_control_flag(ndev, cfg,
						WL_NAN_CTRL_SYNC_BEACON_TX_5G,
						&(cmd_data->status), 0);
				if (unlikely(ret) || unlikely(cmd_data->status)) {
					WL_ERR((" nan control set config handler,"
							" ret = %d status = %d \n",
							ret, cmd_data->status));
					goto fail;
				}
			}
		} else {
			/* Set 5G awake dw value to fw default value 1 */
			awake_dws->dw_interval_5g = NAN_SYNC_DEF_AWAKE_DW;
			ret = wl_cfgnan_config_control_flag(ndev, cfg,
					WL_NAN_CTRL_DISC_BEACON_TX_5G |
					WL_NAN_CTRL_SYNC_BEACON_TX_5G,
					&(cmd_data->status), TRUE);
			if (unlikely(ret) || unlikely(cmd_data->status)) {
				WL_ERR((" nan control set config handler, ret = %d"
					" status = %d \n", ret, cmd_data->status));
				goto fail;
			}
		}
	}

	sub_cmd->id = htod16(WL_NAN_CMD_SYNC_AWAKE_DWS);
	sub_cmd->len = sizeof(sub_cmd->u.options) +
		sizeof(*awake_dws);
	sub_cmd->u.options = htol32(BCM_XTLV_OPTION_ALIGN32);

	nan_iov_data->nan_iov_len -= subcmd_len;
	nan_iov_data->nan_iov_buf += subcmd_len;

fail:
	NAN_DBG_EXIT();
	return ret;
}

int
wl_cfgnan_start_handler(struct net_device *ndev, struct bcm_cfg80211 *cfg,
	nan_config_cmd_data_t *cmd_data, uint32 nan_attr_mask)
{
	s32 ret = BCME_OK;
	uint16 nan_buf_size = NAN_IOCTL_BUF_SIZE;
	bcm_iov_batch_buf_t *nan_buf = NULL;
	wl_nan_iov_t *nan_iov_data = NULL;
	dhd_pub_t *dhdp = wl_cfg80211_get_dhdp(ndev);
	uint8 resp_buf[NAN_IOCTL_BUF_SIZE];
	int i;
	s32 timeout = 0;
	nan_hal_capabilities_t capabilities;

	NAN_DBG_ENTER();

	/* Protect discovery creation. Ensure proper mutex precedence.
	 * If if_sync & nan_mutex comes together in same context, nan_mutex
	 * should follow if_sync.
	 */
	mutex_lock(&cfg->if_sync);
	NAN_MUTEX_LOCK();

	if (!dhdp->up) {
		WL_ERR(("bus is already down, hence blocking nan start\n"));
		ret = BCME_ERROR;
		NAN_MUTEX_UNLOCK();
		mutex_unlock(&cfg->if_sync);
		goto fail;
	}

#ifdef WL_IFACE_MGMT
	if ((ret = wl_cfg80211_handle_if_role_conflict(cfg, WL_IF_TYPE_NAN_NMI)) != BCME_OK) {
		WL_ERR(("Conflicting iface is present, cant support nan\n"));
		NAN_MUTEX_UNLOCK();
		mutex_unlock(&cfg->if_sync);
		goto fail;
	}
#endif /* WL_IFACE_MGMT */

	WL_INFORM_MEM(("Initializing NAN\n"));
	ret = wl_cfgnan_init(cfg);
	if (ret != BCME_OK) {
		WL_ERR(("failed to initialize NAN[%d]\n", ret));
		NAN_MUTEX_UNLOCK();
		mutex_unlock(&cfg->if_sync);
		goto fail;
	}

	ret = wl_cfgnan_get_ver(ndev, cfg);
	if (ret != BCME_OK) {
		WL_ERR(("failed to Nan IOV version[%d]\n", ret));
		NAN_MUTEX_UNLOCK();
		mutex_unlock(&cfg->if_sync);
		goto fail;
	}

	/* set nmi addr */
	ret = wl_cfgnan_set_if_addr(cfg);
	if (ret != BCME_OK) {
		WL_ERR(("Failed to set nmi address \n"));
		NAN_MUTEX_UNLOCK();
		mutex_unlock(&cfg->if_sync);
		goto fail;
	}
	cfg->nancfg.nan_event_recvd = false;
	NAN_MUTEX_UNLOCK();
	mutex_unlock(&cfg->if_sync);

	for (i = 0; i < NAN_MAX_NDI; i++) {
		/* Create NDI using the information provided by user space */
		if (cfg->nancfg.ndi[i].in_use && !cfg->nancfg.ndi[i].created) {
			ret = wl_cfgnan_data_path_iface_create_delete_handler(ndev, cfg,
				cfg->nancfg.ndi[i].ifname,
				NAN_WIFI_SUBCMD_DATA_PATH_IFACE_CREATE, dhdp->up);
			if (ret) {
				WL_ERR(("failed to create ndp interface [%d]\n", ret));
				goto fail;
			}
			cfg->nancfg.ndi[i].created = true;
		}
	}

	nan_buf = MALLOCZ(cfg->osh, nan_buf_size);
	if (!nan_buf) {
		WL_ERR(("%s: memory allocation failed\n", __func__));
		ret = BCME_NOMEM;
		goto fail;
	}

	nan_iov_data = MALLOCZ(cfg->osh, sizeof(*nan_iov_data));
	if (!nan_iov_data) {
		WL_ERR(("%s: memory allocation failed\n", __func__));
		ret = BCME_NOMEM;
		goto fail;
	}

	nan_iov_data->nan_iov_len = NAN_IOCTL_BUF_SIZE;
	nan_buf->version = htol16(WL_NAN_IOV_BATCH_VERSION);
	nan_buf->count = 0;
	nan_iov_data->nan_iov_buf = (uint8 *)(&nan_buf->cmds[0]);
	nan_iov_data->nan_iov_len -= OFFSETOF(bcm_iov_batch_buf_t, cmds[0]);

	if (nan_attr_mask & NAN_ATTR_SYNC_DISC_2G_BEACON_CONFIG) {
		/* config sync/discovery beacons on 2G band */
		/* 2g is mandatory */
		if (!cmd_data->beacon_2g_val) {
			WL_ERR(("Invalid NAN config...2G is mandatory\n"));
			ret = BCME_BADARG;
		}
		ret = wl_cfgnan_config_control_flag(ndev, cfg,
			WL_NAN_CTRL_DISC_BEACON_TX_2G | WL_NAN_CTRL_SYNC_BEACON_TX_2G,
			&(cmd_data->status), TRUE);
		if (unlikely(ret) || unlikely(cmd_data->status)) {
			WL_ERR((" nan control set config handler, ret = %d status = %d \n",
					ret, cmd_data->status));
			goto fail;
		}
	}
	if (nan_attr_mask & NAN_ATTR_SYNC_DISC_5G_BEACON_CONFIG) {
		/* config sync/discovery beacons on 5G band */
		ret = wl_cfgnan_config_control_flag(ndev, cfg,
			WL_NAN_CTRL_DISC_BEACON_TX_5G | WL_NAN_CTRL_SYNC_BEACON_TX_5G,
			&(cmd_data->status), cmd_data->beacon_5g_val);
		if (unlikely(ret) || unlikely(cmd_data->status)) {
			WL_ERR((" nan control set config handler, ret = %d status = %d \n",
					ret, cmd_data->status));
			goto fail;
		}
	}
	/* Setting warm up time */
	cmd_data->warmup_time = 1;
	if (cmd_data->warmup_time) {
		ret = wl_cfgnan_warmup_time_handler(cmd_data, nan_iov_data);
		if (unlikely(ret)) {
			WL_ERR(("warm up time handler sub_cmd set failed\n"));
			goto fail;
		}
		nan_buf->count++;
	}
	/* setting master preference and random factor */
	ret = wl_cfgnan_set_election_metric(cmd_data, nan_iov_data, nan_attr_mask);
	if (unlikely(ret)) {
		WL_ERR(("election_metric sub_cmd set failed\n"));
		goto fail;
	} else {
		nan_buf->count++;
	}

	/* setting nan social channels */
	ret = wl_cfgnan_set_nan_soc_chans(ndev, cmd_data, nan_iov_data, nan_attr_mask);
	if (unlikely(ret)) {
		WL_ERR(("nan social channels set failed\n"));
		goto fail;
	} else {
		/* Storing 5g capability which is reqd for avail chan config. */
		cfg->support_5g = cmd_data->support_5g;
		nan_buf->count++;
	}

	if ((cmd_data->support_2g) && ((cmd_data->dwell_time[0]) ||
			(cmd_data->scan_period[0]))) {
		/* setting scan params */
		ret = wl_cfgnan_set_nan_scan_params(ndev, cfg, cmd_data, 0, nan_attr_mask);
		if (unlikely(ret)) {
			WL_ERR(("scan params set failed for 2g\n"));
			goto fail;
		}
	}

	if ((cmd_data->support_5g) && ((cmd_data->dwell_time[1]) ||
			(cmd_data->scan_period[1]))) {
		/* setting scan params */
		ret = wl_cfgnan_set_nan_scan_params(ndev, cfg, cmd_data,
			cmd_data->support_5g, nan_attr_mask);
		if (unlikely(ret)) {
			WL_ERR(("scan params set failed for 5g\n"));
			goto fail;
		}
	}

	/*
	 * A cluster_low value matching cluster_high indicates a request
	 * to join a cluster with that value.
	 * If the requested cluster is not found the
	 * device will start its own cluster
	 */
	/* For Debug purpose, using clust id compulsion */
	if (!ETHER_ISNULLADDR(&cmd_data->clus_id.octet)) {
		if (cmd_data->clus_id.octet[4] == cmd_data->clus_id.octet[5]) {
			/* device will merge to configured CID only */
			ret = wl_cfgnan_config_control_flag(ndev, cfg,
					WL_NAN_CTRL_MERGE_CONF_CID_ONLY, &(cmd_data->status), true);
			if (unlikely(ret) || unlikely(cmd_data->status)) {
				WL_ERR((" nan control set config handler, ret = %d status = %d \n",
					ret, cmd_data->status));
				goto fail;
			}
		}
		/* setting cluster ID */
		ret = wl_cfgnan_set_cluster_id(cmd_data, nan_iov_data);
		if (unlikely(ret)) {
			WL_ERR(("cluster_id sub_cmd set failed\n"));
			goto fail;
		}
		nan_buf->count++;
	}

	/* setting rssi proximaty values for 2.4GHz and 5GHz */
	ret = wl_cfgnan_set_rssi_proximity(cmd_data, nan_iov_data, nan_attr_mask);
	if (unlikely(ret)) {
		WL_ERR(("2.4GHz/5GHz rssi proximity threshold set failed\n"));
		goto fail;
	} else {
		nan_buf->count++;
	}

	/* setting rssi middle/close values for 2.4GHz and 5GHz */
	ret = wl_cfgnan_set_rssi_mid_or_close(cmd_data, nan_iov_data, nan_attr_mask);
	if (unlikely(ret)) {
		WL_ERR(("2.4GHz/5GHz rssi middle and close set failed\n"));
		goto fail;
	} else {
		nan_buf->count++;
	}

	/* setting hop count limit or threshold */
	if (nan_attr_mask & NAN_ATTR_HOP_COUNT_LIMIT_CONFIG) {
		ret = wl_cfgnan_set_hop_count_limit(cmd_data, nan_iov_data);
		if (unlikely(ret)) {
			WL_ERR(("hop_count_limit sub_cmd set failed\n"));
			goto fail;
		}
		nan_buf->count++;
	}

	/* setting sid beacon val */
	if ((nan_attr_mask & NAN_ATTR_SID_BEACON_CONFIG) ||
		(nan_attr_mask & NAN_ATTR_SUB_SID_BEACON_CONFIG)) {
		ret = wl_cfgnan_set_sid_beacon_val(cmd_data, nan_iov_data, nan_attr_mask);
		if (unlikely(ret)) {
			WL_ERR(("sid_beacon sub_cmd set failed\n"));
			goto fail;
		}
		nan_buf->count++;
	}

	/* setting nan oui */
	if (nan_attr_mask & NAN_ATTR_OUI_CONFIG) {
		ret = wl_cfgnan_set_nan_oui(cmd_data, nan_iov_data);
		if (unlikely(ret)) {
			WL_ERR(("nan_oui sub_cmd set failed\n"));
			goto fail;
		}
		nan_buf->count++;
	}

	/* setting nan awake dws */
	ret = wl_cfgnan_set_awake_dws(ndev, cmd_data,
			nan_iov_data, cfg, nan_attr_mask);
	if (unlikely(ret)) {
		WL_ERR(("nan awake dws set failed\n"));
		goto fail;
	} else {
		nan_buf->count++;
	}

	/* enable events */
	ret = wl_cfgnan_config_eventmask(ndev, cfg, cmd_data->disc_ind_cfg, false);
	if (unlikely(ret)) {
		WL_ERR(("Failed to config disc ind flag in event_mask, ret = %d\n", ret));
		goto fail;
	}

	/* setting nan enable sub_cmd */
	ret = wl_cfgnan_enable_handler(nan_iov_data, true);
	if (unlikely(ret)) {
		WL_ERR(("enable handler sub_cmd set failed\n"));
		goto fail;
	}
	nan_buf->count++;
	nan_buf->is_set = true;

	nan_buf_size -= nan_iov_data->nan_iov_len;
	memset(resp_buf, 0, sizeof(resp_buf));
	/* Reset conditon variable */
	ret = wl_cfgnan_execute_ioctl(ndev, cfg, nan_buf, nan_buf_size,
			&(cmd_data->status), (void*)resp_buf, NAN_IOCTL_BUF_SIZE);
	if (unlikely(ret) || unlikely(cmd_data->status)) {
		WL_ERR((" nan start handler, enable failed, ret = %d status = %d \n",
				ret, cmd_data->status));
		goto fail;
	}

	timeout = wait_event_timeout(cfg->nancfg.nan_event_wait,
		cfg->nancfg.nan_event_recvd, msecs_to_jiffies(NAN_START_STOP_TIMEOUT));
	if (!timeout) {
		WL_ERR(("Timed out while Waiting for WL_NAN_EVENT_START event !!!\n"));
		ret = BCME_ERROR;
		goto fail;
	}

	/* If set, auto datapath confirms will be sent by FW */
	ret = wl_cfgnan_config_control_flag(ndev, cfg, WL_NAN_CTRL_AUTO_DPCONF,
		&(cmd_data->status), true);
	if (unlikely(ret) || unlikely(cmd_data->status)) {
		WL_ERR((" nan control set config handler, ret = %d status = %d \n",
				ret, cmd_data->status));
		goto fail;
	}

	/* By default set NAN proprietary rates */
	ret = wl_cfgnan_config_control_flag(ndev, cfg, WL_NAN_CTRL_PROP_RATE,
		&(cmd_data->status), true);
	if (unlikely(ret) || unlikely(cmd_data->status)) {
		WL_ERR((" nan proprietary rate set failed, ret = %d status = %d \n",
				ret, cmd_data->status));
		goto fail;
	}

	/* malloc for ndp peer list */
	if ((ret = wl_cfgnan_get_capablities_handler(ndev, cfg, &capabilities))
			== BCME_OK) {
		cfg->nancfg.max_ndp_count = capabilities.max_ndp_sessions;
		cfg->nancfg.nan_ndp_peer_info = MALLOCZ(cfg->osh,
				cfg->nancfg.max_ndp_count * sizeof(nan_ndp_peer_t));
		if (!cfg->nancfg.nan_ndp_peer_info) {
			WL_ERR(("%s: memory allocation failed\n", __func__));
			ret = BCME_NOMEM;
			goto fail;
		}

	} else {
		WL_ERR(("wl_cfgnan_get_capablities_handler failed, ret = %d\n", ret));
		goto fail;
	}

#ifdef RTT_SUPPORT
	/* Initialize geofence cfg */
	dhd_rtt_initialize_geofence_cfg(cfg->pub);
#endif /* RTT_SUPPORT */

	cfg->nan_enable = true;
	WL_INFORM_MEM(("[NAN] Enable successfull \n"));
	/* disable TDLS on NAN NMI IF create  */
	wl_cfg80211_tdls_config(cfg, TDLS_STATE_NMI_CREATE, false);

fail:
	/* reset conditon variable */
	cfg->nancfg.nan_event_recvd = false;
	if (unlikely(ret) || unlikely(cmd_data->status)) {
		cfg->nan_enable = false;
		mutex_lock(&cfg->if_sync);
		ret = wl_cfg80211_delete_iface(cfg, WL_IF_TYPE_NAN);
		if (ret != BCME_OK) {
			WL_ERR(("failed to delete NDI[%d]\n", ret));
		}
		mutex_unlock(&cfg->if_sync);
	}
	if (nan_buf) {
		MFREE(cfg->osh, nan_buf, NAN_IOCTL_BUF_SIZE);
	}
	if (nan_iov_data) {
		MFREE(cfg->osh, nan_iov_data, sizeof(*nan_iov_data));
	}

	NAN_DBG_EXIT();
	return ret;
}

int
wl_cfgnan_disable(struct bcm_cfg80211 *cfg)
{
	s32 ret = BCME_OK;
	dhd_pub_t *dhdp = (dhd_pub_t *)(cfg->pub);

	NAN_DBG_ENTER();
	if ((cfg->nan_init_state == TRUE) &&
			(cfg->nan_enable == TRUE)) {
		struct net_device *ndev;
		ndev = bcmcfg_to_prmry_ndev(cfg);

		/* We have to remove NDIs so that P2P/Softap can work */
		ret = wl_cfg80211_delete_iface(cfg, WL_IF_TYPE_NAN);
		if (ret != BCME_OK) {
			WL_ERR(("failed to delete NDI[%d]\n", ret));
		}

		WL_INFORM_MEM(("Nan Disable Req, reason = %d\n", cfg->nancfg.disable_reason));
		ret = wl_cfgnan_stop_handler(ndev, cfg);
		if (ret == -ENODEV) {
			WL_ERR(("Bus is down, no need to proceed\n"));
		} else if (ret != BCME_OK) {
			WL_ERR(("failed to stop nan, error[%d]\n", ret));
		}
		ret = wl_cfgnan_deinit(cfg, dhdp->up);
		if (ret != BCME_OK) {
			WL_ERR(("failed to de-initialize NAN[%d]\n", ret));
			if (!dhd_query_bus_erros(dhdp)) {
				ASSERT(0);
			}
		}
		wl_cfgnan_disable_cleanup(cfg);
	}
	NAN_DBG_EXIT();
	return ret;
}

static void
wl_cfgnan_send_stop_event(struct bcm_cfg80211 *cfg)
{
	s32 ret = BCME_OK;
	nan_event_data_t *nan_event_data = NULL;

	NAN_DBG_ENTER();

	if (cfg->nancfg.disable_reason == NAN_USER_INITIATED) {
	    /* do not event to host if command is from host */
	    goto exit;
	}
	nan_event_data = MALLOCZ(cfg->osh, sizeof(nan_event_data_t));
	if (!nan_event_data) {
		WL_ERR(("%s: memory allocation failed\n", __func__));
		ret = BCME_NOMEM;
		goto exit;
	}
	bzero(nan_event_data, sizeof(nan_event_data_t));

	if (cfg->nancfg.disable_reason == NAN_CONCURRENCY_CONFLICT) {
	   nan_event_data->status = NAN_STATUS_UNSUPPORTED_CONCURRENCY_NAN_DISABLED;
	} else {
	   nan_event_data->status = NAN_STATUS_SUCCESS;
	}

	nan_event_data->status = NAN_STATUS_SUCCESS;
	ret = memcpy_s(nan_event_data->nan_reason, NAN_ERROR_STR_LEN,
			"NAN_STATUS_SUCCESS", strlen("NAN_STATUS_SUCCESS"));
	if (ret != BCME_OK) {
		WL_ERR(("Failed to copy nan reason string, ret = %d\n", ret));
		goto exit;
	}
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 13, 0)) || defined(WL_VENDOR_EXT_SUPPORT)
	ret = wl_cfgvendor_send_nan_event(cfg->wdev->wiphy, bcmcfg_to_prmry_ndev(cfg),
			GOOGLE_NAN_EVENT_DISABLED, nan_event_data);
	if (ret != BCME_OK) {
		WL_ERR(("Failed to send event to nan hal, (%d)\n",
				GOOGLE_NAN_EVENT_DISABLED));
	}
#endif /* (LINUX_VERSION_CODE > KERNEL_VERSION(3, 13, 0)) || defined(WL_VENDOR_EXT_SUPPORT) */
exit:
	if (nan_event_data) {
		MFREE(cfg->osh, nan_event_data, sizeof(nan_event_data_t));
	}
	NAN_DBG_EXIT();
	return;
}

void wl_cfgnan_disable_cleanup(struct bcm_cfg80211 *cfg)
{
	int i = 0;
#ifdef RTT_SUPPORT
	dhd_pub_t *dhdp = (dhd_pub_t *)(cfg->pub);
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhdp);
	rtt_target_info_t *target_info = NULL;

	/* Delete the geofence rtt target list */
	dhd_rtt_delete_geofence_target_list(dhdp);
	/* Cancel pending retry timer if any */
	if (delayed_work_pending(&rtt_status->rtt_retry_timer)) {
		cancel_delayed_work_sync(&rtt_status->rtt_retry_timer);
	}
	/* Remove if any pending proxd timeout for nan-rtt */
	target_info = &rtt_status->rtt_config.target_info[rtt_status->cur_idx];
	if (target_info && target_info->peer == RTT_PEER_NAN) {
		/* Cancel pending proxd timeout work if any */
		if (delayed_work_pending(&rtt_status->proxd_timeout)) {
			cancel_delayed_work_sync(&rtt_status->proxd_timeout);
		}
	}
	/* Delete if any directed nan rtt session */
	dhd_rtt_delete_nan_session(dhdp);
#endif /* RTT_SUPPORT */
	/* Clear the NDP ID array and dp count */
	for (i = 0; i < NAN_MAX_NDP_PEER; i++) {
		cfg->nancfg.ndp_id[i] = 0;
	}
	cfg->nan_dp_count = 0;
	if (cfg->nancfg.nan_ndp_peer_info) {
		MFREE(cfg->osh, cfg->nancfg.nan_ndp_peer_info,
			cfg->nancfg.max_ndp_count * sizeof(nan_ndp_peer_t));
		cfg->nancfg.nan_ndp_peer_info = NULL;
	}
	return;
}

/*
 * Deferred nan disable work,
 * scheduled with 3sec delay in order to remove any active nan dps
 */
void
wl_cfgnan_delayed_disable(struct work_struct *work)
{
	struct bcm_cfg80211 *cfg = NULL;

	BCM_SET_CONTAINER_OF(cfg, work, struct bcm_cfg80211, nan_disable.work);

	rtnl_lock();
	wl_cfgnan_disable(cfg);
	rtnl_unlock();
}

int
wl_cfgnan_stop_handler(struct net_device *ndev,
	struct bcm_cfg80211 *cfg)
{
	bcm_iov_batch_buf_t *nan_buf = NULL;
	s32 ret = BCME_OK;
	uint16 nan_buf_size = NAN_IOCTL_BUF_SIZE;
	wl_nan_iov_t *nan_iov_data = NULL;
	uint32 status;
	uint8 resp_buf[NAN_IOCTL_BUF_SIZE];

	NAN_DBG_ENTER();
	NAN_MUTEX_LOCK();

	if (!cfg->nan_enable) {
		WL_INFORM(("Nan is not enabled\n"));
		ret = BCME_OK;
		goto fail;
	}

	if (cfg->nancfg.disable_reason != NAN_BUS_IS_DOWN) {
		/*
		 * Framework doing cleanup(iface remove) on disable command,
		 * so avoiding event to prevent iface delete calls again
		 */
		WL_INFORM_MEM(("[NAN] Disabling Nan events\n"));
		wl_cfgnan_config_eventmask(ndev, cfg, 0, true);

		nan_buf = MALLOCZ(cfg->osh, nan_buf_size);
		if (!nan_buf) {
			WL_ERR(("%s: memory allocation failed\n", __func__));
			ret = BCME_NOMEM;
			goto fail;
		}

		nan_iov_data = MALLOCZ(cfg->osh, sizeof(*nan_iov_data));
		if (!nan_iov_data) {
			WL_ERR(("%s: memory allocation failed\n", __func__));
			ret = BCME_NOMEM;
			goto fail;
		}

		nan_iov_data->nan_iov_len = NAN_IOCTL_BUF_SIZE;
		nan_buf->version = htol16(WL_NAN_IOV_BATCH_VERSION);
		nan_buf->count = 0;
		nan_iov_data->nan_iov_buf = (uint8 *)(&nan_buf->cmds[0]);
		nan_iov_data->nan_iov_len -= OFFSETOF(bcm_iov_batch_buf_t, cmds[0]);

		ret = wl_cfgnan_enable_handler(nan_iov_data, false);
		if (unlikely(ret)) {
			WL_ERR(("nan disable handler failed\n"));
			goto fail;
		}
		nan_buf->count++;
		nan_buf->is_set = true;
		nan_buf_size -= nan_iov_data->nan_iov_len;
		memset_s(resp_buf, sizeof(resp_buf),
				0, sizeof(resp_buf));
		ret = wl_cfgnan_execute_ioctl(ndev, cfg, nan_buf, nan_buf_size, &status,
				(void*)resp_buf, NAN_IOCTL_BUF_SIZE);
		if (unlikely(ret) || unlikely(status)) {
			WL_ERR(("nan disable failed ret = %d status = %d\n", ret, status));
			goto fail;
		}
		/* Enable back TDLS if connected interface is <= 1 */
		wl_cfg80211_tdls_config(cfg, TDLS_STATE_IF_DELETE, false);
	}

	wl_cfgnan_send_stop_event(cfg);

fail:
	/* Resetting instance ID mask */
	cfg->nancfg.inst_id_start = 0;
	memset(cfg->nancfg.svc_inst_id_mask, 0, sizeof(cfg->nancfg.svc_inst_id_mask));
	memset(cfg->svc_info, 0, NAN_MAX_SVC_INST * sizeof(nan_svc_info_t));
	cfg->nan_enable = false;

	if (nan_buf) {
		MFREE(cfg->osh, nan_buf, NAN_IOCTL_BUF_SIZE);
	}
	if (nan_iov_data) {
		MFREE(cfg->osh, nan_iov_data, sizeof(*nan_iov_data));
	}

	NAN_MUTEX_UNLOCK();
	NAN_DBG_EXIT();
	return ret;
}
