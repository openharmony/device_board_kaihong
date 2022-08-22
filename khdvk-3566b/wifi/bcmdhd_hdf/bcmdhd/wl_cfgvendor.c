/*
 * Linux cfg80211 Vendor Extension Code
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
 * $Id: wl_cfgvendor.c 825970 2019-06-18 05:28:31Z $
 */

/*
 * New vendor interface additon to nl80211/cfg80211 to allow vendors
 * to implement proprietary features over the cfg80211 stack.
*/

#include <typedefs.h>
#include <linuxver.h>
#include <osl.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>

#include <bcmutils.h>
#include <bcmwifi_channels.h>
#include <bcmendian.h>
#include <ethernet.h>
#include <802.11.h>
#include <linux/if_arp.h>
#include <asm/uaccess.h>

#include <dngl_stats.h>
#include <dhd.h>
#include <dhd_debug.h>
#include <dhdioctl.h>
#include <wlioctl.h>
#include <wlioctl_utils.h>
#include <dhd_cfg80211.h>
#ifdef PNO_SUPPORT
#include <dhd_pno.h>
#endif /* PNO_SUPPORT */
#ifdef RTT_SUPPORT
#include <dhd_rtt.h>
#endif /* RTT_SUPPORT */

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
#include <wldev_common.h>
#include <wl_cfg80211.h>
#include <wl_cfgp2p.h>
#ifdef WL_NAN
#include <wl_cfgnan.h>
#endif /* WL_NAN */
#include <wl_android.h>
#include <wl_cfgvendor.h>
#ifdef PROP_TXSTATUS
#include <dhd_wlfc.h>
#endif // endif
#include <brcm_nl80211.h>

char*
wl_get_kernel_timestamp(void)
{
	static char buf[32];
	u64 ts_nsec;
	unsigned long rem_nsec;

	ts_nsec = local_clock();
	rem_nsec = DIV_AND_MOD_U64_BY_U32(ts_nsec, NSEC_PER_SEC);
	snprintf(buf, sizeof(buf), "%5lu.%06lu",
		(unsigned long)ts_nsec, rem_nsec / NSEC_PER_USEC);

	return buf;
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 13, 0)) || defined(WL_VENDOR_EXT_SUPPORT)
#if defined(WL_SUPP_EVENT)
int
wl_cfgvendor_send_supp_eventstring(const char *func_name, const char *fmt, ...)
{
	char buf[SUPP_LOG_LEN] = {0};
	struct bcm_cfg80211 *cfg;
	struct wiphy *wiphy;
	va_list args;
	int len;
	int prefix_len;
	int rem_len;

	cfg = wl_cfg80211_get_bcmcfg();
	if (!cfg || !cfg->wdev) {
		WL_DBG(("supp evt invalid arg\n"));
		return BCME_OK;
	}

	wiphy = cfg->wdev->wiphy;
	prefix_len = snprintf(buf, SUPP_LOG_LEN, "[DHD]<%s> %s: ",
		wl_get_kernel_timestamp(), __func__);
	/* Remaining buffer len */
	rem_len = SUPP_LOG_LEN - (prefix_len + 1);
	/* Print the arg list on to the remaining part of the buffer */
	va_start(args, fmt);
	len = vsnprintf((buf + prefix_len), rem_len, fmt, args);
	va_end(args);
	if (len < 0) {
		return -EINVAL;
	}

	if (len > rem_len) {
		/* If return length is greater than buffer len,
		 * then its truncated buffer case.
		 */
		len = rem_len;
	}

	/* Ensure the buffer is null terminated */
	len += prefix_len;
	buf[len] = '\0';
	len++;

	return wl_cfgvendor_send_async_event(wiphy,
		bcmcfg_to_prmry_ndev(cfg), BRCM_VENDOR_EVENT_PRIV_STR, buf, len);
}

int
wl_cfgvendor_notify_supp_event_str(const char *evt_name, const char *fmt, ...)
{
	char buf[SUPP_LOG_LEN] = {0};
	struct bcm_cfg80211 *cfg;
	struct wiphy *wiphy;
	va_list args;
	int len;
	int prefix_len;
	int rem_len;

	cfg = wl_cfg80211_get_bcmcfg();
	if (!cfg || !cfg->wdev) {
		WL_DBG(("supp evt invalid arg\n"));
		return BCME_OK;
	}
	wiphy = cfg->wdev->wiphy;
	prefix_len = snprintf(buf, SUPP_LOG_LEN, "%s ", evt_name);
	/* Remaining buffer len */
	rem_len = SUPP_LOG_LEN - (prefix_len + 1);
	/* Print the arg list on to the remaining part of the buffer */
	va_start(args, fmt);
	len = vsnprintf((buf + prefix_len), rem_len, fmt, args);
	va_end(args);
	if (len < 0) {
		return -EINVAL;
	}

	if (len > rem_len) {
		/* If return length is greater than buffer len,
		 * then its truncated buffer case.
		 */
		len = rem_len;
	}

	/* Ensure the buffer is null terminated */
	len += prefix_len;
	buf[len] = '\0';
	len++;

	return wl_cfgvendor_send_async_event(wiphy,
		bcmcfg_to_prmry_ndev(cfg), BRCM_VENDOR_EVENT_PRIV_STR, buf, len);
}
#endif /* WL_SUPP_EVENT */

/*
 * This API is to be used for asynchronous vendor events. This
 * shouldn't be used in response to a vendor command from its
 * do_it handler context (instead wl_cfgvendor_send_cmd_reply should
 * be used).
 */
int wl_cfgvendor_send_async_event(struct wiphy *wiphy,
	struct net_device *dev, int event_id, const void  *data, int len)
{
	gfp_t kflags;
	struct sk_buff *skb;

	kflags = in_atomic() ? GFP_ATOMIC : GFP_KERNEL;

	/* Alloc the SKB for vendor_event */
#if (defined(CONFIG_ARCH_MSM) && defined(SUPPORT_WDEV_CFG80211_VENDOR_EVENT_ALLOC)) || \
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	skb = cfg80211_vendor_event_alloc(wiphy, ndev_to_wdev(dev), len, event_id, kflags);
#else
	skb = cfg80211_vendor_event_alloc(wiphy, len, event_id, kflags);
#endif /* (defined(CONFIG_ARCH_MSM) && defined(SUPPORT_WDEV_CFG80211_VENDOR_EVENT_ALLOC)) || */
		/* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0) */
	if (!skb) {
		WL_ERR(("skb alloc failed"));
		return -ENOMEM;
	}

	/* Push the data to the skb */
	nla_put_nohdr(skb, len, data);

	cfg80211_vendor_event(skb, kflags);

	return 0;
}

static int
wl_cfgvendor_send_cmd_reply(struct wiphy *wiphy,
	const void  *data, int len)
{
	struct sk_buff *skb;
	int err;

	/* Alloc the SKB for vendor_event */
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, len);
	if (unlikely(!skb)) {
		WL_ERR(("skb alloc failed"));
		err = -ENOMEM;
		goto exit;
	}

	/* Push the data to the skb */
	nla_put_nohdr(skb, len, data);
	err = cfg80211_vendor_cmd_reply(skb);
exit:
	WL_DBG(("wl_cfgvendor_send_cmd_reply status %d", err));
	return err;
}

static int
wl_cfgvendor_get_feature_set(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	int reply;

	reply = dhd_dev_get_feature_set(bcmcfg_to_prmry_ndev(cfg));

	err =  wl_cfgvendor_send_cmd_reply(wiphy, &reply, sizeof(int));
	if (unlikely(err))
		WL_ERR(("Vendor Command reply failed ret:%d \n", err));

	return err;
}

static int
wl_cfgvendor_get_feature_set_matrix(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	struct sk_buff *skb;
	int reply;
	int mem_needed, i;

	mem_needed = VENDOR_REPLY_OVERHEAD +
		(ATTRIBUTE_U32_LEN * MAX_FEATURE_SET_CONCURRRENT_GROUPS) + ATTRIBUTE_U32_LEN;

	/* Alloc the SKB for vendor_event */
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, mem_needed);
	if (unlikely(!skb)) {
		WL_ERR(("skb alloc failed"));
		err = -ENOMEM;
		goto exit;
	}

	err = nla_put_u32(skb, ANDR_WIFI_ATTRIBUTE_NUM_FEATURE_SET,
		MAX_FEATURE_SET_CONCURRRENT_GROUPS);
	if (unlikely(err)) {
		kfree_skb(skb);
		goto exit;
	}
	for (i = 0; i < MAX_FEATURE_SET_CONCURRRENT_GROUPS; i++) {
		reply = dhd_dev_get_feature_set_matrix(bcmcfg_to_prmry_ndev(cfg), i);
		if (reply != WIFI_FEATURE_INVALID) {
			err = nla_put_u32(skb, ANDR_WIFI_ATTRIBUTE_FEATURE_SET,
				reply);
			if (unlikely(err)) {
				kfree_skb(skb);
				goto exit;
			}
		}
	}

	err =  cfg80211_vendor_cmd_reply(skb);

	if (unlikely(err)) {
		WL_ERR(("Vendor Command reply failed ret:%d \n", err));
	}
exit:
	return err;
}

static int
wl_cfgvendor_set_rand_mac_oui(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = -EINVAL;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	int type;

	if (!data) {
		WL_ERR(("data is not available\n"));
		goto exit;
	}

	if (len <= 0) {
		WL_ERR(("invalid len %d\n", len));
		goto exit;
	}

	type = nla_type(data);

	if (type == ANDR_WIFI_ATTRIBUTE_RANDOM_MAC_OUI) {
		if (nla_len(data) != DOT11_OUI_LEN) {
			WL_ERR(("nla_len not matched.\n"));
			goto exit;
		}
		err = dhd_dev_cfg_rand_mac_oui(bcmcfg_to_prmry_ndev(cfg), nla_data(data));

		if (unlikely(err))
			WL_ERR(("Bad OUI, could not set:%d \n", err));
	}
exit:
	return err;
}
#ifdef CUSTOM_FORCE_NODFS_FLAG
static int
wl_cfgvendor_set_nodfs_flag(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void *data, int len)
{
	int err = -EINVAL;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	int type;
	u32 nodfs;

	if (!data) {
		WL_ERR(("data is not available\n"));
		return -EINVAL;
	}

	if (len <= 0) {
		WL_ERR(("invalid len %d\n", len));
		return -EINVAL;
	}

	type = nla_type(data);
	if (type == ANDR_WIFI_ATTRIBUTE_NODFS_SET) {
		nodfs = nla_get_u32(data);
		err = dhd_dev_set_nodfs(bcmcfg_to_prmry_ndev(cfg), nodfs);
	}

	return err;
}
#endif /* CUSTOM_FORCE_NODFS_FLAG */

static int
wl_cfgvendor_set_country(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void *data, int len)
{
	int err = BCME_ERROR, rem, type;
	char country_code[WLC_CNTRY_BUF_SZ] = {0};
	const struct nlattr *iter;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	struct net_device *primary_ndev = bcmcfg_to_prmry_ndev(cfg);

	nla_for_each_attr(iter, data, len, rem) {
		type = nla_type(iter);
		switch (type) {
			case ANDR_WIFI_ATTRIBUTE_COUNTRY:
				err = memcpy_s(country_code, WLC_CNTRY_BUF_SZ,
					nla_data(iter), nla_len(iter));
				if (err) {
					WL_ERR(("Failed to copy country code: %d\n", err));
					return err;
				}
				break;
			default:
				WL_ERR(("Unknown type: %d\n", type));
				return err;
		}
	}
	/* country code is unique for dongle..hence using primary interface. */
	err = wl_cfg80211_set_country_code(primary_ndev, country_code, true, true, -1);
	if (err < 0) {
		WL_ERR(("Set country failed ret:%d\n", err));
	}

	return err;
}

#ifdef GSCAN_SUPPORT
int
wl_cfgvendor_send_hotlist_event(struct wiphy *wiphy,
	struct net_device *dev, void  *data, int len, wl_vendor_event_t event)
{
	gfp_t kflags;
	const void *ptr;
	struct sk_buff *skb;
	int malloc_len, total, iter_cnt_to_send, cnt;
	gscan_results_cache_t *cache = (gscan_results_cache_t *)data;

	total = len/sizeof(wifi_gscan_result_t);
	while (total > 0) {
		malloc_len = (total * sizeof(wifi_gscan_result_t)) + VENDOR_DATA_OVERHEAD;
		if (malloc_len > NLMSG_DEFAULT_SIZE) {
			malloc_len = NLMSG_DEFAULT_SIZE;
		}
		iter_cnt_to_send =
		   (malloc_len - VENDOR_DATA_OVERHEAD)/sizeof(wifi_gscan_result_t);
		total = total - iter_cnt_to_send;

		kflags = in_atomic() ? GFP_ATOMIC : GFP_KERNEL;

		/* Alloc the SKB for vendor_event */
#if (defined(CONFIG_ARCH_MSM) && defined(SUPPORT_WDEV_CFG80211_VENDOR_EVENT_ALLOC)) || \
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
		skb = cfg80211_vendor_event_alloc(wiphy, ndev_to_wdev(dev),
		malloc_len, event, kflags);
#else
		skb = cfg80211_vendor_event_alloc(wiphy, malloc_len, event, kflags);
#endif /* (defined(CONFIG_ARCH_MSM) && defined(SUPPORT_WDEV_CFG80211_VENDOR_EVENT_ALLOC)) || */
		/* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0) */
		if (!skb) {
			WL_ERR(("skb alloc failed"));
			return -ENOMEM;
		}

		while (cache && iter_cnt_to_send) {
			ptr = (const void *) &cache->results[cache->tot_consumed];

			if (iter_cnt_to_send < (cache->tot_count - cache->tot_consumed)) {
				cnt = iter_cnt_to_send;
			} else {
				cnt = (cache->tot_count - cache->tot_consumed);
			}

			iter_cnt_to_send -= cnt;
			cache->tot_consumed += cnt;
			/* Push the data to the skb */
			nla_append(skb, cnt * sizeof(wifi_gscan_result_t), ptr);
			if (cache->tot_consumed == cache->tot_count) {
				cache = cache->next;
			}

		}

		cfg80211_vendor_event(skb, kflags);
	}

	return 0;
}

static int
wl_cfgvendor_gscan_get_capabilities(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	dhd_pno_gscan_capabilities_t *reply = NULL;
	uint32 reply_len = 0;

	reply = dhd_dev_pno_get_gscan(bcmcfg_to_prmry_ndev(cfg),
	   DHD_PNO_GET_CAPABILITIES, NULL, &reply_len);
	if (!reply) {
		WL_ERR(("Could not get capabilities\n"));
		err = -EINVAL;
		return err;
	}

	err =  wl_cfgvendor_send_cmd_reply(wiphy, reply, reply_len);
	if (unlikely(err)) {
		WL_ERR(("Vendor Command reply failed ret:%d \n", err));
	}

	MFREE(cfg->osh, reply, reply_len);
	return err;
}

static int
wl_cfgvendor_gscan_get_batch_results(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	gscan_results_cache_t *results, *iter;
	uint32 reply_len, is_done = 1;
	int32 mem_needed, num_results_iter;
	wifi_gscan_result_t *ptr;
	uint16 num_scan_ids, num_results;
	struct sk_buff *skb;
	struct nlattr *scan_hdr, *complete_flag;

	err = dhd_dev_wait_batch_results_complete(bcmcfg_to_prmry_ndev(cfg));
	if (err != BCME_OK)
		return -EBUSY;

	err = dhd_dev_pno_lock_access_batch_results(bcmcfg_to_prmry_ndev(cfg));
	if (err != BCME_OK) {
		WL_ERR(("Can't obtain lock to access batch results %d\n", err));
		return -EBUSY;
	}
	results = dhd_dev_pno_get_gscan(bcmcfg_to_prmry_ndev(cfg),
	             DHD_PNO_GET_BATCH_RESULTS, NULL, &reply_len);

	if (!results) {
		WL_ERR(("No results to send %d\n", err));
		err =  wl_cfgvendor_send_cmd_reply(wiphy, results, 0);

		if (unlikely(err))
			WL_ERR(("Vendor Command reply failed ret:%d \n", err));
		dhd_dev_pno_unlock_access_batch_results(bcmcfg_to_prmry_ndev(cfg));
		return err;
	}
	num_scan_ids = reply_len & 0xFFFF;
	num_results = (reply_len & 0xFFFF0000) >> 16;
	mem_needed = (num_results * sizeof(wifi_gscan_result_t)) +
	             (num_scan_ids * GSCAN_BATCH_RESULT_HDR_LEN) +
	             VENDOR_REPLY_OVERHEAD + SCAN_RESULTS_COMPLETE_FLAG_LEN;

	if (mem_needed > (int32)NLMSG_DEFAULT_SIZE) {
		mem_needed = (int32)NLMSG_DEFAULT_SIZE;
	}

	WL_TRACE(("is_done %d mem_needed %d max_mem %d\n", is_done, mem_needed,
		(int)NLMSG_DEFAULT_SIZE));
	/* Alloc the SKB for vendor_event */
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, mem_needed);
	if (unlikely(!skb)) {
		WL_ERR(("skb alloc failed"));
		dhd_dev_pno_unlock_access_batch_results(bcmcfg_to_prmry_ndev(cfg));
		return -ENOMEM;
	}
	iter = results;
	complete_flag = nla_reserve(skb, GSCAN_ATTRIBUTE_SCAN_RESULTS_COMPLETE,
	                    sizeof(is_done));

	if (unlikely(!complete_flag)) {
		WL_ERR(("complete_flag could not be reserved"));
		kfree_skb(skb);
		dhd_dev_pno_unlock_access_batch_results(bcmcfg_to_prmry_ndev(cfg));
		return -ENOMEM;
	}
	mem_needed = mem_needed - (SCAN_RESULTS_COMPLETE_FLAG_LEN + VENDOR_REPLY_OVERHEAD);

	while (iter) {
		num_results_iter = (mem_needed - (int32)GSCAN_BATCH_RESULT_HDR_LEN);
		num_results_iter /= (int32)sizeof(wifi_gscan_result_t);
		if (num_results_iter <= 0 ||
		    ((iter->tot_count - iter->tot_consumed) > num_results_iter)) {
			break;
		}
		scan_hdr = nla_nest_start(skb, GSCAN_ATTRIBUTE_SCAN_RESULTS);
		/* no more room? we are done then (for now) */
		if (scan_hdr == NULL) {
			is_done = 0;
			break;
		}
		err = nla_put_u32(skb, GSCAN_ATTRIBUTE_SCAN_ID, iter->scan_id);
		if (unlikely(err)) {
			goto fail;
		}
		err = nla_put_u8(skb, GSCAN_ATTRIBUTE_SCAN_FLAGS, iter->flag);
		if (unlikely(err)) {
			goto fail;
		}
		err = nla_put_u32(skb, GSCAN_ATTRIBUTE_CH_BUCKET_BITMASK, iter->scan_ch_bucket);
		if (unlikely(err)) {
			goto fail;
		}
		num_results_iter = iter->tot_count - iter->tot_consumed;

		err = nla_put_u32(skb, GSCAN_ATTRIBUTE_NUM_OF_RESULTS, num_results_iter);
		if (unlikely(err)) {
			goto fail;
		}
		if (num_results_iter) {
			ptr = &iter->results[iter->tot_consumed];
			err = nla_put(skb, GSCAN_ATTRIBUTE_SCAN_RESULTS,
			 num_results_iter * sizeof(wifi_gscan_result_t), ptr);
			if (unlikely(err)) {
				goto fail;
			}
			iter->tot_consumed += num_results_iter;
		}
		nla_nest_end(skb, scan_hdr);
		mem_needed -= GSCAN_BATCH_RESULT_HDR_LEN +
		    (num_results_iter * sizeof(wifi_gscan_result_t));
		iter = iter->next;
	}
	/* Cleans up consumed results and returns TRUE if all results are consumed */
	is_done = dhd_dev_gscan_batch_cache_cleanup(bcmcfg_to_prmry_ndev(cfg));
	memcpy(nla_data(complete_flag), &is_done, sizeof(is_done));
	dhd_dev_pno_unlock_access_batch_results(bcmcfg_to_prmry_ndev(cfg));
	return cfg80211_vendor_cmd_reply(skb);
fail:
	/* Free up consumed results which will now not be sent */
	(void)dhd_dev_gscan_batch_cache_cleanup(bcmcfg_to_prmry_ndev(cfg));
	kfree_skb(skb);
	dhd_dev_pno_unlock_access_batch_results(bcmcfg_to_prmry_ndev(cfg));
	return err;
}

static int
wl_cfgvendor_initiate_gscan(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	int type, tmp = len;
	int run = 0xFF;
	int flush = 0;
	const struct nlattr *iter;

	nla_for_each_attr(iter, data, len, tmp) {
		type = nla_type(iter);
		if (type == GSCAN_ATTRIBUTE_ENABLE_FEATURE)
			run = nla_get_u32(iter);
		else if (type == GSCAN_ATTRIBUTE_FLUSH_FEATURE)
			flush = nla_get_u32(iter);
	}

	if (run != 0xFF) {
		err = dhd_dev_pno_run_gscan(bcmcfg_to_prmry_ndev(cfg), run, flush);

		if (unlikely(err)) {
			WL_ERR(("Could not run gscan:%d \n", err));
		}
		return err;
	} else {
		return -EINVAL;
	}

}

static int
wl_cfgvendor_enable_full_scan_result(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	int type;
	bool real_time = FALSE;

	if (!data) {
		WL_ERR(("data is not available\n"));
		return -EINVAL;
	}

	if (len <= 0) {
		WL_ERR(("invalid len %d\n", len));
		return -EINVAL;
	}

	type = nla_type(data);

	if (type == GSCAN_ATTRIBUTE_ENABLE_FULL_SCAN_RESULTS) {
		real_time = nla_get_u32(data);

		err = dhd_dev_pno_enable_full_scan_result(bcmcfg_to_prmry_ndev(cfg), real_time);

		if (unlikely(err)) {
			WL_ERR(("Could not run gscan:%d \n", err));
		}

	} else {
		err = -EINVAL;
	}

	return err;
}

static int
wl_cfgvendor_set_scan_cfg_bucket(const struct nlattr *prev,
	gscan_scan_params_t *scan_param, int num)
{
	struct dhd_pno_gscan_channel_bucket  *ch_bucket;
	int k = 0;
	int type, err = 0, rem;
	const struct nlattr *cur, *next;

	nla_for_each_nested(cur, prev, rem) {
		type = nla_type(cur);
		ch_bucket = scan_param->channel_bucket;
		switch (type) {
		case GSCAN_ATTRIBUTE_BUCKET_ID:
			break;
		case GSCAN_ATTRIBUTE_BUCKET_PERIOD:
			if (nla_len(cur) != sizeof(uint32)) {
				err = -EINVAL;
				goto exit;
			}

			ch_bucket[num].bucket_freq_multiple =
				nla_get_u32(cur) / MSEC_PER_SEC;
			break;
		case GSCAN_ATTRIBUTE_BUCKET_NUM_CHANNELS:
			if (nla_len(cur) != sizeof(uint32)) {
				err = -EINVAL;
				goto exit;
			}
			ch_bucket[num].num_channels = nla_get_u32(cur);
			if (ch_bucket[num].num_channels >
				GSCAN_MAX_CHANNELS_IN_BUCKET) {
				WL_ERR(("channel range:%d,bucket:%d\n",
					ch_bucket[num].num_channels,
					num));
				err = -EINVAL;
				goto exit;
			}
			break;
		case GSCAN_ATTRIBUTE_BUCKET_CHANNELS:
			nla_for_each_nested(next, cur, rem) {
				if (k >= GSCAN_MAX_CHANNELS_IN_BUCKET)
					break;
				if (nla_len(next) != sizeof(uint32)) {
					err = -EINVAL;
					goto exit;
				}
				ch_bucket[num].chan_list[k] = nla_get_u32(next);
				k++;
			}
			break;
		case GSCAN_ATTRIBUTE_BUCKETS_BAND:
			if (nla_len(cur) != sizeof(uint32)) {
				err = -EINVAL;
				goto exit;
			}
			ch_bucket[num].band = (uint16)nla_get_u32(cur);
			break;
		case GSCAN_ATTRIBUTE_REPORT_EVENTS:
			if (nla_len(cur) != sizeof(uint32)) {
				err = -EINVAL;
				goto exit;
			}
			ch_bucket[num].report_flag = (uint8)nla_get_u32(cur);
			break;
		case GSCAN_ATTRIBUTE_BUCKET_STEP_COUNT:
			if (nla_len(cur) != sizeof(uint32)) {
				err = -EINVAL;
				goto exit;
			}
			ch_bucket[num].repeat = (uint16)nla_get_u32(cur);
			break;
		case GSCAN_ATTRIBUTE_BUCKET_MAX_PERIOD:
			if (nla_len(cur) != sizeof(uint32)) {
				err = -EINVAL;
				goto exit;
			}
			ch_bucket[num].bucket_max_multiple =
				nla_get_u32(cur) / MSEC_PER_SEC;
			break;
		default:
			WL_ERR(("unknown attr type:%d\n", type));
			err = -EINVAL;
			goto exit;
		}
	}

exit:
	return err;
}

static int
wl_cfgvendor_set_scan_cfg(struct wiphy *wiphy, struct wireless_dev *wdev,
	const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	gscan_scan_params_t *scan_param;
	int j = 0;
	int type, tmp;
	const struct nlattr *iter;

	scan_param = (gscan_scan_params_t *)MALLOCZ(cfg->osh,
		sizeof(gscan_scan_params_t));
	if (!scan_param) {
		WL_ERR(("Could not set GSCAN scan cfg, mem alloc failure\n"));
		err = -EINVAL;
		return err;

	}

	scan_param->scan_fr = PNO_SCAN_MIN_FW_SEC;
	nla_for_each_attr(iter, data, len, tmp) {
		type = nla_type(iter);

		if (j >= GSCAN_MAX_CH_BUCKETS) {
			break;
		}

		switch (type) {
			case GSCAN_ATTRIBUTE_BASE_PERIOD:
				if (nla_len(iter) != sizeof(uint32)) {
					err = -EINVAL;
					goto exit;
				}
				scan_param->scan_fr = nla_get_u32(iter) / MSEC_PER_SEC;
				break;
			case GSCAN_ATTRIBUTE_NUM_BUCKETS:
				if (nla_len(iter) != sizeof(uint32)) {
					err = -EINVAL;
					goto exit;
				}
				scan_param->nchannel_buckets = nla_get_u32(iter);
				if (scan_param->nchannel_buckets >=
				    GSCAN_MAX_CH_BUCKETS) {
					WL_ERR(("ncha_buck out of range %d\n",
					scan_param->nchannel_buckets));
					err = -EINVAL;
					goto exit;
				}
				break;
			case GSCAN_ATTRIBUTE_CH_BUCKET_1:
			case GSCAN_ATTRIBUTE_CH_BUCKET_2:
			case GSCAN_ATTRIBUTE_CH_BUCKET_3:
			case GSCAN_ATTRIBUTE_CH_BUCKET_4:
			case GSCAN_ATTRIBUTE_CH_BUCKET_5:
			case GSCAN_ATTRIBUTE_CH_BUCKET_6:
			case GSCAN_ATTRIBUTE_CH_BUCKET_7:
				err = wl_cfgvendor_set_scan_cfg_bucket(iter, scan_param, j);
				if (err < 0) {
					WL_ERR(("set_scan_cfg_buck error:%d\n", err));
					goto exit;
				}
				j++;
				break;
			default:
				WL_ERR(("Unknown type %d\n", type));
				err = -EINVAL;
				goto exit;
		}
	}

	err = dhd_dev_pno_set_cfg_gscan(bcmcfg_to_prmry_ndev(cfg),
	     DHD_PNO_SCAN_CFG_ID, scan_param, FALSE);

	if (err < 0) {
		WL_ERR(("Could not set GSCAN scan cfg\n"));
		err = -EINVAL;
	}

exit:
	MFREE(cfg->osh, scan_param, sizeof(gscan_scan_params_t));
	return err;

}

static int
wl_cfgvendor_hotlist_cfg(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	gscan_hotlist_scan_params_t *hotlist_params;
	int tmp, tmp1, tmp2, type, j = 0, dummy;
	const struct nlattr *outer, *inner = NULL, *iter;
	bool flush = FALSE;
	struct bssid_t *pbssid;

	BCM_REFERENCE(dummy);

	if (len < sizeof(*hotlist_params) || len >= WLC_IOCTL_MAXLEN) {
		WL_ERR(("buffer length :%d wrong - bail out.\n", len));
		return -EINVAL;
	}

	hotlist_params = (gscan_hotlist_scan_params_t *)MALLOCZ(cfg->osh,
		sizeof(*hotlist_params)
		+ (sizeof(struct bssid_t) * (PFN_SWC_MAX_NUM_APS - 1)));

	if (!hotlist_params) {
		WL_ERR(("Cannot Malloc memory.\n"));
		return -ENOMEM;
	}

	hotlist_params->lost_ap_window = GSCAN_LOST_AP_WINDOW_DEFAULT;

	nla_for_each_attr(iter, data, len, tmp2) {
		type = nla_type(iter);
		switch (type) {
		case GSCAN_ATTRIBUTE_HOTLIST_BSSID_COUNT:
			if (nla_len(iter) != sizeof(uint32)) {
				WL_DBG(("type:%d length:%d not matching.\n",
					type, nla_len(iter)));
				err = -EINVAL;
				goto exit;
			}
			hotlist_params->nbssid = (uint16)nla_get_u32(iter);
			if ((hotlist_params->nbssid == 0) ||
			    (hotlist_params->nbssid > PFN_SWC_MAX_NUM_APS)) {
				WL_ERR(("nbssid:%d exceed limit.\n",
					hotlist_params->nbssid));
				err = -EINVAL;
				goto exit;
			}
			break;
		case GSCAN_ATTRIBUTE_HOTLIST_BSSIDS:
			if (hotlist_params->nbssid == 0) {
				WL_ERR(("nbssid not retrieved.\n"));
				err = -EINVAL;
				goto exit;
			}
			pbssid = hotlist_params->bssid;
			nla_for_each_nested(outer, iter, tmp) {
				if (j >= hotlist_params->nbssid)
					break;
				nla_for_each_nested(inner, outer, tmp1) {
					type = nla_type(inner);

					switch (type) {
					case GSCAN_ATTRIBUTE_BSSID:
						if (nla_len(inner) != sizeof(pbssid[j].macaddr)) {
							WL_ERR(("type:%d length:%d not matching.\n",
								type, nla_len(inner)));
							err = -EINVAL;
							goto exit;
						}
						memcpy(
							&(pbssid[j].macaddr),
							nla_data(inner),
							sizeof(pbssid[j].macaddr));
						break;
					case GSCAN_ATTRIBUTE_RSSI_LOW:
						if (nla_len(inner) != sizeof(uint8)) {
							WL_ERR(("type:%d length:%d not matching.\n",
								type, nla_len(inner)));
							err = -EINVAL;
							goto exit;
						}
						pbssid[j].rssi_reporting_threshold =
							(int8)nla_get_u8(inner);
						break;
					case GSCAN_ATTRIBUTE_RSSI_HIGH:
						if (nla_len(inner) != sizeof(uint8)) {
							WL_ERR(("type:%d length:%d not matching.\n",
								type, nla_len(inner)));
							err = -EINVAL;
							goto exit;
						}
						dummy = (int8)nla_get_u8(inner);
						WL_DBG(("dummy %d\n", dummy));
						break;
					default:
						WL_ERR(("ATTR unknown %d\n", type));
						err = -EINVAL;
						goto exit;
					}
				}
				j++;
			}
			if (j != hotlist_params->nbssid) {
				WL_ERR(("bssid_cnt:%d != nbssid:%d.\n", j,
					hotlist_params->nbssid));
				err = -EINVAL;
				goto exit;
			}
			break;
		case GSCAN_ATTRIBUTE_HOTLIST_FLUSH:
			if (nla_len(iter) != sizeof(uint8)) {
				WL_ERR(("type:%d length:%d not matching.\n",
					type, nla_len(iter)));
				err = -EINVAL;
				goto exit;
			}
			flush = nla_get_u8(iter);
			break;
		case GSCAN_ATTRIBUTE_LOST_AP_SAMPLE_SIZE:
			if (nla_len(iter) != sizeof(uint32)) {
				WL_ERR(("type:%d length:%d not matching.\n",
					type, nla_len(iter)));
				err = -EINVAL;
				goto exit;
			}
			hotlist_params->lost_ap_window = (uint16)nla_get_u32(iter);
			break;
		default:
			WL_ERR(("Unknown type %d\n", type));
			err = -EINVAL;
			goto exit;
		}

	}

	if (dhd_dev_pno_set_cfg_gscan(bcmcfg_to_prmry_ndev(cfg),
	      DHD_PNO_GEOFENCE_SCAN_CFG_ID, hotlist_params, flush) < 0) {
		WL_ERR(("Could not set GSCAN HOTLIST cfg error: %d\n", err));
		err = -EINVAL;
		goto exit;
	}
exit:
	MFREE(cfg->osh, hotlist_params, sizeof(*hotlist_params)
		+ (sizeof(struct bssid_t) * (PFN_SWC_MAX_NUM_APS - 1)));
	return err;
}

static int wl_cfgvendor_epno_cfg(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	dhd_pno_ssid_t *ssid_elem = NULL;
	int tmp, tmp1, tmp2, type = 0, num = 0;
	const struct nlattr *outer, *inner, *iter;
	uint8 flush = FALSE, i = 0;
	wl_ssid_ext_params_t params;

	nla_for_each_attr(iter, data, len, tmp2) {
		type = nla_type(iter);
		switch (type) {
			case GSCAN_ATTRIBUTE_EPNO_SSID_LIST:
				nla_for_each_nested(outer, iter, tmp) {
					ssid_elem = (dhd_pno_ssid_t *)
						dhd_dev_pno_get_gscan(bcmcfg_to_prmry_ndev(cfg),
						DHD_PNO_GET_NEW_EPNO_SSID_ELEM,
						NULL, &num);
					if (!ssid_elem) {
						WL_ERR(("Failed to get SSID LIST buffer\n"));
						err = -ENOMEM;
						goto exit;
					}
					i++;
					nla_for_each_nested(inner, outer, tmp1) {
						type = nla_type(inner);

						switch (type) {
							case GSCAN_ATTRIBUTE_EPNO_SSID:
								memcpy(ssid_elem->SSID,
								  nla_data(inner),
								  DOT11_MAX_SSID_LEN);
								break;
							case GSCAN_ATTRIBUTE_EPNO_SSID_LEN:
								ssid_elem->SSID_len =
									nla_get_u32(inner);
								if (ssid_elem->SSID_len >
									DOT11_MAX_SSID_LEN) {
									WL_ERR(("SSID too"
									"long %d\n",
									ssid_elem->SSID_len));
									err = -EINVAL;
									MFREE(cfg->osh, ssid_elem,
										num);
									goto exit;
								}
								break;
							case GSCAN_ATTRIBUTE_EPNO_FLAGS:
								ssid_elem->flags =
									nla_get_u32(inner);
								ssid_elem->hidden =
									((ssid_elem->flags &
									DHD_EPNO_HIDDEN_SSID) != 0);
								break;
							case GSCAN_ATTRIBUTE_EPNO_AUTH:
								ssid_elem->wpa_auth =
								        nla_get_u32(inner);
								break;
						}
					}
					if (!ssid_elem->SSID_len) {
						WL_ERR(("Broadcast SSID is illegal for ePNO\n"));
						err = -EINVAL;
						MFREE(cfg->osh, ssid_elem, num);
						goto exit;
					}
					dhd_pno_translate_epno_fw_flags(&ssid_elem->flags);
					dhd_pno_set_epno_auth_flag(&ssid_elem->wpa_auth);
					MFREE(cfg->osh, ssid_elem, num);
				}
				break;
			case GSCAN_ATTRIBUTE_EPNO_SSID_NUM:
				num = nla_get_u8(iter);
				break;
			case GSCAN_ATTRIBUTE_EPNO_FLUSH:
				flush = (bool)nla_get_u32(iter);
				/* Flush attribute is expected before any ssid attribute */
				if (i && flush) {
					WL_ERR(("Bad attributes\n"));
					err = -EINVAL;
					goto exit;
				}
				/* Need to flush driver and FW cfg */
				dhd_dev_pno_set_cfg_gscan(bcmcfg_to_prmry_ndev(cfg),
				DHD_PNO_EPNO_CFG_ID, NULL, flush);
				dhd_dev_flush_fw_epno(bcmcfg_to_prmry_ndev(cfg));
				break;
			case GSCAN_ATTRIBUTE_EPNO_5G_RSSI_THR:
				params.min5G_rssi = nla_get_s8(iter);
				break;
			case GSCAN_ATTRIBUTE_EPNO_2G_RSSI_THR:
				params.min2G_rssi = nla_get_s8(iter);
				break;
			case GSCAN_ATTRIBUTE_EPNO_INIT_SCORE_MAX:
				params.init_score_max = nla_get_s16(iter);
				break;
			case GSCAN_ATTRIBUTE_EPNO_CUR_CONN_BONUS:
				params.cur_bssid_bonus = nla_get_s16(iter);
				break;
			case GSCAN_ATTRIBUTE_EPNO_SAME_NETWORK_BONUS:
				params.same_ssid_bonus = nla_get_s16(iter);
				break;
			case GSCAN_ATTRIBUTE_EPNO_SECURE_BONUS:
				params.secure_bonus = nla_get_s16(iter);
				break;
			case GSCAN_ATTRIBUTE_EPNO_5G_BONUS:
				params.band_5g_bonus = nla_get_s16(iter);
				break;
			default:
				WL_ERR(("%s: No such attribute %d\n", __FUNCTION__, type));
				err = -EINVAL;
				goto exit;
			}
	}
	if (i != num) {
		WL_ERR(("%s: num_ssid %d does not match ssids sent %d\n", __FUNCTION__,
		     num, i));
		err = -EINVAL;
	}
exit:
	/* Flush all configs if error condition */
	if (err < 0) {
		dhd_dev_pno_set_cfg_gscan(bcmcfg_to_prmry_ndev(cfg),
		   DHD_PNO_EPNO_CFG_ID, NULL, TRUE);
		dhd_dev_flush_fw_epno(bcmcfg_to_prmry_ndev(cfg));
	} else if (type != GSCAN_ATTRIBUTE_EPNO_FLUSH) {
		/* If the last attribute was FLUSH, nothing else to do */
		dhd_dev_pno_set_cfg_gscan(bcmcfg_to_prmry_ndev(cfg),
		DHD_PNO_EPNO_PARAMS_ID, &params, FALSE);
		err = dhd_dev_set_epno(bcmcfg_to_prmry_ndev(cfg));
	}
	return err;
}

static int
wl_cfgvendor_set_batch_scan_cfg(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0, tmp, type;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	gscan_batch_params_t batch_param;
	const struct nlattr *iter;

	batch_param.mscan = batch_param.bestn = 0;
	batch_param.buffer_threshold = GSCAN_BATCH_NO_THR_SET;

	nla_for_each_attr(iter, data, len, tmp) {
		type = nla_type(iter);

		switch (type) {
			case GSCAN_ATTRIBUTE_NUM_AP_PER_SCAN:
				batch_param.bestn = nla_get_u32(iter);
				break;
			case GSCAN_ATTRIBUTE_NUM_SCANS_TO_CACHE:
				batch_param.mscan = nla_get_u32(iter);
				break;
			case GSCAN_ATTRIBUTE_REPORT_THRESHOLD:
				batch_param.buffer_threshold = nla_get_u32(iter);
				break;
			default:
				WL_ERR(("Unknown type %d\n", type));
				break;
		}
	}

	if (dhd_dev_pno_set_cfg_gscan(bcmcfg_to_prmry_ndev(cfg),
	       DHD_PNO_BATCH_SCAN_CFG_ID, &batch_param, FALSE) < 0) {
		WL_ERR(("Could not set batch cfg\n"));
		err = -EINVAL;
		return err;
	}

	return err;
}

#endif /* GSCAN_SUPPORT */
#if defined(GSCAN_SUPPORT) || defined(DHD_GET_VALID_CHANNELS)
static int
wl_cfgvendor_gscan_get_channel_list(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0, type, band;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	uint16 *reply = NULL;
	uint32 reply_len = 0, num_channels, mem_needed;
	struct sk_buff *skb;
	dhd_pub_t *dhdp;
	struct net_device *ndev = wdev->netdev;

	if (!ndev) {
		WL_ERR(("ndev null\n"));
		return -EINVAL;
	}

	dhdp = wl_cfg80211_get_dhdp(ndev);
	if (!dhdp) {
		WL_ERR(("dhdp null\n"));
		return -EINVAL;
	}

	if (!data) {
		WL_ERR(("data is not available\n"));
		return -EINVAL;
	}

	if (len <= 0) {
		WL_ERR(("invalid len %d\n", len));
		return -EINVAL;
	}

	type = nla_type(data);
	if (type == GSCAN_ATTRIBUTE_BAND) {
		band = nla_get_u32(data);
	} else {
		return -EINVAL;
	}

	reply = dhd_pno_get_gscan(dhdp,
	   DHD_PNO_GET_CHANNEL_LIST, &band, &reply_len);
	if (!reply) {
		WL_ERR(("Could not get channel list\n"));
		err = -EINVAL;
		return err;
	}
	num_channels =  reply_len/ sizeof(uint32);
	mem_needed = reply_len + VENDOR_REPLY_OVERHEAD + (ATTRIBUTE_U32_LEN * 2);

	/* Alloc the SKB for vendor_event */
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, mem_needed);
	if (unlikely(!skb)) {
		WL_ERR(("skb alloc failed"));
		err = -ENOMEM;
		goto exit;
	}

	nla_put_u32(skb, GSCAN_ATTRIBUTE_NUM_CHANNELS, num_channels);
	nla_put(skb, GSCAN_ATTRIBUTE_CHANNEL_LIST, reply_len, reply);

	err =  cfg80211_vendor_cmd_reply(skb);

	if (unlikely(err)) {
		WL_ERR(("Vendor Command reply failed ret:%d \n", err));
	}
exit:
	MFREE(cfg->osh, reply, reply_len);
	return err;
}
#endif	/* GSCAN_SUPPORT || DHD_GET_VALID_CHANNELS */

#ifdef RSSI_MONITOR_SUPPORT
static int wl_cfgvendor_set_rssi_monitor(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0, tmp, type, start = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	int8 max_rssi = 0, min_rssi = 0;
	const struct nlattr *iter;

	if (!wl_get_drv_status(cfg, CONNECTED, wdev_to_ndev(wdev))) {
		WL_ERR(("STA is not connected to an AP, rssi monitoring is not allowed\n"));
		return -EINVAL;
	}

	nla_for_each_attr(iter, data, len, tmp) {
		type = nla_type(iter);
		switch (type) {
			case RSSI_MONITOR_ATTRIBUTE_MAX_RSSI:
				max_rssi = (int8) nla_get_u32(iter);
				break;
			case RSSI_MONITOR_ATTRIBUTE_MIN_RSSI:
				min_rssi = (int8) nla_get_u32(iter);
				break;
			case RSSI_MONITOR_ATTRIBUTE_START:
				start = nla_get_u32(iter);
		}
	}

	if (dhd_dev_set_rssi_monitor_cfg(bcmcfg_to_prmry_ndev(cfg),
	       start, max_rssi, min_rssi) < 0) {
		WL_ERR(("Could not set rssi monitor cfg\n"));
		err = -EINVAL;
	}
	return err;
}
#endif /* RSSI_MONITOR_SUPPORT */

#ifdef DHD_WAKE_STATUS
static int
wl_cfgvendor_get_wake_reason_stats(struct wiphy *wiphy,
        struct wireless_dev *wdev, const void *data, int len)
{
	struct net_device *ndev = wdev_to_ndev(wdev);
	wake_counts_t *pwake_count_info;
	int ret, mem_needed;
#if defined(DHD_DEBUG) && defined(DHD_WAKE_EVENT_STATUS)
	int flowid;
#endif /* DHD_DEBUG && DHD_WAKE_EVENT_STATUS */
	struct sk_buff *skb = NULL;
	dhd_pub_t *dhdp = wl_cfg80211_get_dhdp(ndev);

	WL_DBG(("Recv get wake status info cmd.\n"));

	pwake_count_info = dhd_get_wakecount(dhdp);
	mem_needed =  VENDOR_REPLY_OVERHEAD + (ATTRIBUTE_U32_LEN * 20) +
		(WLC_E_LAST * sizeof(uint));

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, mem_needed);
	if (unlikely(!skb)) {
		WL_ERR(("%s: can't allocate %d bytes\n", __FUNCTION__, mem_needed));
		ret = -ENOMEM;
		goto exit;
	}
#ifdef DHD_WAKE_EVENT_STATUS
	WL_ERR(("pwake_count_info->rcwake %d\n", pwake_count_info->rcwake));
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_TOTAL_CMD_EVENT, pwake_count_info->rcwake);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total count of CMD event, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_CMD_EVENT_COUNT_USED, WLC_E_LAST);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Max count of event used, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put(skb, WAKE_STAT_ATTRIBUTE_CMD_EVENT_WAKE, (WLC_E_LAST * sizeof(uint)),
		pwake_count_info->rc_event);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Event wake data, ret=%d\n", ret));
		goto exit;
	}
#ifdef DHD_DEBUG
	for (flowid = 0; flowid < WLC_E_LAST; flowid++) {
		if (pwake_count_info->rc_event[flowid] != 0) {
			WL_ERR((" %s = %u\n", bcmevent_get_name(flowid),
				pwake_count_info->rc_event[flowid]));
		}
	}
#endif /* DHD_DEBUG */
#endif /* DHD_WAKE_EVENT_STATUS */
#ifdef DHD_WAKE_RX_STATUS
	WL_ERR(("pwake_count_info->rxwake %d\n", pwake_count_info->rxwake));
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_TOTAL_RX_DATA_WAKE, pwake_count_info->rxwake);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total Wake due RX data, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_RX_UNICAST_COUNT, pwake_count_info->rx_ucast);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total wake due to RX unicast, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_RX_MULTICAST_COUNT, pwake_count_info->rx_mcast);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total wake due RX multicast, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_RX_BROADCAST_COUNT, pwake_count_info->rx_bcast);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total wake due to RX broadcast, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_RX_ICMP_PKT, pwake_count_info->rx_arp);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total wake due to ICMP pkt, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_RX_ICMP6_PKT, pwake_count_info->rx_icmpv6);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total wake due ICMPV6 pkt, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_RX_ICMP6_RA, pwake_count_info->rx_icmpv6_ra);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total wake due to ICMPV6_RA, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_RX_ICMP6_NA, pwake_count_info->rx_icmpv6_na);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total wake due to ICMPV6_NA, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_RX_ICMP6_NS, pwake_count_info->rx_icmpv6_ns);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total wake due to ICMPV6_NS, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_IPV4_RX_MULTICAST_ADD_CNT,
		pwake_count_info->rx_multi_ipv4);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total wake due to RX IPV4 MULTICAST, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_IPV6_RX_MULTICAST_ADD_CNT,
		pwake_count_info->rx_multi_ipv6);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total wake due to RX IPV6 MULTICAST, ret=%d\n", ret));
		goto exit;
	}
	ret = nla_put_u32(skb, WAKE_STAT_ATTRIBUTE_OTHER_RX_MULTICAST_ADD_CNT,
		pwake_count_info->rx_multi_other);
	if (unlikely(ret)) {
		WL_ERR(("Failed to put Total wake due to Other RX Multicast, ret=%d\n", ret));
		goto exit;
	}
#endif /* #ifdef DHD_WAKE_RX_STATUS */
	ret = cfg80211_vendor_cmd_reply(skb);
	if (unlikely(ret)) {
		WL_ERR(("Vendor cmd reply for -get wake status failed:%d \n", ret));
	}
	/* On cfg80211_vendor_cmd_reply() skb is consumed and freed in case of success or failure */
	return ret;

exit:
	/* Free skb memory */
	if (skb) {
		kfree_skb(skb);
	}
	return ret;
}
#endif /* DHD_WAKE_STATUS */
