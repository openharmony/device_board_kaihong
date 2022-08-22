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

