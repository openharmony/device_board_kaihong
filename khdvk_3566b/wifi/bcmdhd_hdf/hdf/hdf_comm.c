/*
 * hdf_comm.c
 *
 * hdf driver
 *
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#include <net/cfg80211.h>
#include <net/regulatory.h>
#include <securec.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/in6.h>
#include <linux/wireless.h>

#include "wifi_module.h"
#include "wifi_mac80211_ops.h"
#include "hdf_wlan_utils.h"
#include "net_bdh_adpater.h"
#include "hdf_wl_interface.h"
#include "hdf_public_ap6256.h"

#include <typedefs.h>
#include <ethernet.h>
#include <bcmutils.h>

#include "osal_mem.h"
#include "hdf_log.h"

#include "net_device.h"
#include "net_device_impl.h"
#include "net_device_adapter.h"
#include "hdf_wifi_cmd.h"
#include "hdf_wifi_event.h"
#include "hdf_mac80211_sta_event.h"
#include "hdf_mac80211_sta.h"
#include <net/netlink.h>

#include <uapi/linux/nl80211.h>
#include <asm/byteorder.h>
#include <linux/kernel.h>

#include "hdf_wifi_product.h"
#define HDF_LOG_TAG BDH6Driver
#define WIFI_SCAN_EXTRA_IE_LEN_MAX (512)
#define BDH6_POINT_CHANNEL_SIZE (8)
int dhd_module_init(void);
struct bcm_cfg80211;
s32 wl_get_vif_macaddr(struct bcm_cfg80211 *cfg, u16 wl_iftype, u8 *mac_addr);
extern struct cfg80211_ap_settings g_ap_setting_info;

static void HdfInfMapInit(void)
{
    int32_t i = 0;

    memset_s(g_hdf_infmap, sizeof(g_hdf_infmap), 0, sizeof(g_hdf_infmap));
    for (i = 0; i < HDF_INF_MAX; i++) {
        INIT_WORK(&g_hdf_infmap[i].eapolEvent.eapol_report,
                  eapol_report_handler);
        NetBufQueueInit(&g_hdf_infmap[i].eapolEvent.eapolQueue);
        g_hdf_infmap[i].eapolEvent.idx = i;
    }
    g_hdf_ifidx = HDF_INF_WLAN0; // master interface
}

int32_t Bdh6Fband(NetDevice *hnetDev, int32_t band, int32_t *freqs,
                  uint32_t *num)
{
    uint32_t freqIndex = 0;
    uint32_t channelNumber;
    uint32_t freqTmp;
    uint32_t minFreq;
    uint32_t maxFreq;

    struct wiphy *wiphy = NULL;
    struct NetDevice *netDev = NULL;
    struct ieee80211_supported_band *band5g = NULL;
    int32_t max5GChNum = 0;
    const struct ieee80211_regdomain *regdom = bdh6_get_regdomain();
    if (regdom == NULL) {
        HDF_LOGE("%s: wal_get_cfg_regdb failed!", __func__);
        return HDF_FAILURE;
    }

    netDev = get_real_netdev(hnetDev);
    wiphy = get_linux_wiphy_hdfdev(netDev);
    if (!wiphy) {
        HDF_LOGE("%s: wiphy is NULL", __func__);
        return -1;
    }

    (void)netDev;
    HDF_LOGE("%s: start..., band=%d", __func__, band);

    minFreq = regdom->reg_rules[0].freq_range.start_freq_khz / MHZ_TO_KHZ(1);
    maxFreq = regdom->reg_rules[0].freq_range.end_freq_khz / MHZ_TO_KHZ(1);
    switch (band) {
        case WLAN_BAND_2G:
            for (channelNumber = 1; channelNumber <= WIFI_24G_CHANNEL_NUMS;
                 channelNumber++) {
                if (channelNumber < WAL_MAX_CHANNEL_2G) {
                    freqTmp = WAL_MIN_FREQ_2G +
                              (channelNumber - 1) * WAL_FREQ_2G_INTERVAL;
                } else if (channelNumber == WAL_MAX_CHANNEL_2G) {
                    freqTmp = WAL_MAX_FREQ_2G;
                }
                if (freqTmp < minFreq || freqTmp > maxFreq) {
                    continue;
                }

                HDF_LOGE("bdh6 2G %u: freq=%u\n", freqIndex, freqTmp);
                freqs[freqIndex] = freqTmp;
                freqIndex++;
            }
            *num = freqIndex;
            break;

        case WLAN_BAND_5G:
            band5g = wiphy->bands[IEEE80211_BAND_5GHZ];
            if (band5g == NULL) {
                return HDF_ERR_NOT_SUPPORT;
            }

            max5GChNum = min(band5g->n_channels, WIFI_24G_CHANNEL_NUMS);
            for (freqIndex = 0; freqIndex < max5GChNum; freqIndex++) {
                freqs[freqIndex] = band5g->channels[freqIndex].center_freq;
                HDF_LOGE("bdh6 5G %u: freq=%u\n", freqIndex, freqs[freqIndex]);
            }
            *num = freqIndex;
            break;
        default:
            HDF_LOGE("%s: no support band!", __func__);
            return HDF_ERR_NOT_SUPPORT;
    }
    return HDF_SUCCESS;
}

int32_t Bdh6Ghcap(struct NetDevice *hnetDev,
                  struct WlanHwCapability **capability)
{
    uint8_t loop = 0;
    struct wiphy *wiphy = NULL;
    struct NetDevice *netDev = NULL;
    struct ieee80211_supported_band *band = NULL;
    struct ieee80211_supported_band *band5g = NULL;
    struct WlanHwCapability *hwCapability = NULL;
    uint16_t supportedRateCount = 0;
    netDev = get_real_netdev(hnetDev);

    wiphy = get_linux_wiphy_hdfdev(netDev);
    if (!wiphy) {
        HDF_LOGE("%s: wiphy is NULL", __func__);
        return -1;
    }

    HDF_LOGE("%s: start...", __func__);
    band = wiphy->bands[IEEE80211_BAND_2GHZ];
    hwCapability = (struct WlanHwCapability *)OsalMemCalloc(
        sizeof(struct WlanHwCapability));
    if (hwCapability == NULL) {
        HDF_LOGE("%s: oom!\n", __func__);
        return HDF_FAILURE;
    }
    hwCapability->Release = BDH6WalReleaseHwCapability;

    if (hwCapability->bands[IEEE80211_BAND_2GHZ] == NULL) {
        hwCapability->bands[IEEE80211_BAND_2GHZ] =
            OsalMemCalloc(sizeof(struct WlanBand) +
                          (sizeof(struct WlanChannel) * band->n_channels));
        if (hwCapability->bands[IEEE80211_BAND_2GHZ] == NULL) {
            BDH6WalReleaseHwCapability(hwCapability);
            return HDF_FAILURE;
        }
    }

    hwCapability->htCapability = band->ht_cap.cap;
    supportedRateCount = band->n_bitrates;

    hwCapability->bands[IEEE80211_BAND_2GHZ]->channelCount = band->n_channels;
    for (loop = 0; loop < band->n_channels; loop++) {
        hwCapability->bands[IEEE80211_BAND_2GHZ]->channels[loop].centerFreq =
            band->channels[loop].center_freq;
        hwCapability->bands[IEEE80211_BAND_2GHZ]->channels[loop].flags =
            band->channels[loop].flags;
        hwCapability->bands[IEEE80211_BAND_2GHZ]->channels[loop].channelId =
            band->channels[loop].hw_value;
        HDF_LOGE(
            "bdh6 2G band %u: centerFreq=%u, channelId=%u, flags=0x%08x\n",
            loop,
            hwCapability->bands[IEEE80211_BAND_2GHZ]->channels[loop].centerFreq,
            hwCapability->bands[IEEE80211_BAND_2GHZ]->channels[loop].channelId,
            hwCapability->bands[IEEE80211_BAND_2GHZ]->channels[loop].flags);
    }

    if (wiphy->bands[IEEE80211_BAND_5GHZ]) { // Fill 5Ghz band
        band5g = wiphy->bands[IEEE80211_BAND_5GHZ];
        hwCapability->bands[IEEE80211_BAND_5GHZ] =
            OsalMemCalloc(sizeof(struct WlanBand) +
                          (sizeof(struct WlanChannel) * band5g->n_channels));
        if (hwCapability->bands[IEEE80211_BAND_5GHZ] == NULL) {
            HDF_LOGE("%s: oom!\n", __func__);
            BDH6WalReleaseHwCapability(hwCapability);
            return HDF_FAILURE;
        }

        hwCapability->bands[IEEE80211_BAND_5GHZ]->channelCount =
            band5g->n_channels;
        for (loop = 0; loop < band5g->n_channels; loop++) {
            hwCapability->bands[IEEE80211_BAND_5GHZ]
                ->channels[loop]
                .centerFreq = band5g->channels[loop].center_freq;
            hwCapability->bands[IEEE80211_BAND_5GHZ]->channels[loop].flags =
                band5g->channels[loop].flags;
            hwCapability->bands[IEEE80211_BAND_5GHZ]->channels[loop].channelId =
                band5g->channels[loop].hw_value;
        }

        supportedRateCount += band5g->n_bitrates;
    }
    HDF_LOGE("bdh6 htCapability= %u,%u; supportedRateCount= %u,%u,%u\n",
             hwCapability->htCapability, band5g->ht_cap.cap, supportedRateCount,
             band->n_bitrates, band5g->n_bitrates);

    hwCapability->supportedRateCount = supportedRateCount;
    hwCapability->supportedRates =
        OsalMemCalloc(sizeof(uint16_t) * supportedRateCount);
    if (hwCapability->supportedRates == NULL) {
        HDF_LOGE("%s: oom!\n", __func__);
        BDH6WalReleaseHwCapability(hwCapability);
        return HDF_FAILURE;
    }

    for (loop = 0; loop < band->n_bitrates; loop++) {
        hwCapability->supportedRates[loop] = band->bitrates[loop].bitrate;
        HDF_LOGE("bdh6 2G supportedRates %u: %u\n", loop,
                 hwCapability->supportedRates[loop]);
    }

    if (band5g) {
        for (loop = band->n_bitrates; loop < supportedRateCount; loop++) {
            hwCapability->supportedRates[loop] = band5g->bitrates[loop].bitrate;
            HDF_LOGE("bdh6 5G supportedRates %u: %u\n", loop,
                     hwCapability->supportedRates[loop]);
        }
    }

    if (hwCapability->supportedRateCount > MAX_SUPPORTED_RATE) {
        hwCapability->supportedRateCount = MAX_SUPPORTED_RATE;
    }

    *capability = hwCapability;
    return HDF_SUCCESS;
}

int32_t Bdh6SAction(struct NetDevice *hhnetDev, WifiActionData *actionData)
{
    int retVal = 0;
    struct NetDevice *hnetdev = NULL;
    struct net_device *netdev = NULL;
    struct NetDevice *netDev = NULL;
    struct wiphy *wiphy = NULL;
    struct wireless_dev *wdev = NULL;
    static u64 action_cookie = 0;
    struct cfg80211_mgmt_tx_params params;
    u32 center_freq = 0;
    u8 *action_buf = NULL;
    struct ieee80211_mgmt *mgmt = NULL;
    u8 *srcMac = NULL;
    hnetdev = hhnetDev; // backup it

    g_mgmt_tx_event_ifidx = get_scan_ifidx(hnetdev->name);
    HDF_LOGE("%s: start %s... ifidx=%d", __func__, hnetdev->name,
             g_mgmt_tx_event_ifidx);

    netDev = get_real_netdev(hhnetDev);
    netdev = GetLinuxInfByNetDevice(netDev);
    if (!netdev) {
        HDF_LOGE("%s: net_device is NULL", __func__);
        return -1;
    }
    wiphy = get_linux_wiphy_ndev(netdev);
    if (!wiphy) {
        HDF_LOGE("%s: wiphy is NULL", __func__);
        return -1;
    }

    if (strcmp(hnetdev->name, "p2p0") == 0) {
        wdev = g_hdf_infmap[HDF_INF_P2P0].wdev;
        if (g_hdf_infmap[HDF_INF_P2P1].netdev) {
            srcMac = wdev->address;
        } else {
            srcMac = actionData->src;
        }
    } else {
        wdev = netdev->ieee80211_ptr;
        srcMac = actionData->src;
    }
    memset_s(&params, sizeof(params), 0, sizeof(params));
    params.wait = actionData->wait;
    params.no_cck = (bool)actionData->noCck;
    center_freq = actionData->freq;
    params.chan = ieee80211_get_channel_khz(wiphy, MHZ_TO_KHZ(center_freq));
    if (params.chan == NULL) {
        HDF_LOGE("%s: get center_freq %u faild", __func__, center_freq);
        return -1;
    }

    // build 802.11 action header
    action_buf = (u8 *)OsalMemCalloc(MAC_80211_FRAME_LEN + actionData->dataLen);
    mgmt = (struct ieee80211_mgmt *)action_buf;
    mgmt->frame_control =
        cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION);
    memcpy_s(mgmt->da, ETH_ALEN, actionData->dst, ETH_ALEN);
    memcpy_s(mgmt->sa, ETH_ALEN, srcMac, ETH_ALEN);
    memcpy_s(mgmt->bssid, ETH_ALEN, actionData->bssid, ETH_ALEN);

    /* 填充payload信息 */
    if (actionData->dataLen > 0) {
        memcpy_s(action_buf + MAC_80211_FRAME_LEN, actionData->dataLen,
                 actionData->data, actionData->dataLen);
    }
    params.buf = action_buf;
    params.len = (MAC_80211_FRAME_LEN + actionData->dataLen);
    retVal =
        (int32_t)wl_cfg80211_ops.mgmt_tx(wiphy, wdev, &params, &action_cookie);
    OsalMemFree(action_buf);
    return retVal;
}

static void InitCfg80211BeaconDataInfo(struct cfg80211_beacon_data *pInfo,
                                       const struct WlanBeaconConf *param)
{
    memset_s(pInfo, sizeof(struct cfg80211_beacon_data), 0x00,
             sizeof(struct cfg80211_beacon_data));
    pInfo->head = param->headIEs;
    pInfo->head_len = (size_t)param->headIEsLength;
    pInfo->tail = param->tailIEs;
    pInfo->tail_len = (size_t)param->tailIEsLength;

    pInfo->beacon_ies = NULL;
    pInfo->proberesp_ies = NULL;
    pInfo->assocresp_ies = NULL;
    pInfo->probe_resp = NULL;
    pInfo->beacon_ies_len = 0X00;
    pInfo->proberesp_ies_len = 0X00;
    pInfo->assocresp_ies_len = 0X00;
    pInfo->probe_resp_len = 0X00;
}

static void InitCfg80211ApSettingInfo(const struct WlanBeaconConf *param)
{
    if (g_ap_setting_info.beacon.head != NULL) {
        OsalMemFree((uint8_t *)g_ap_setting_info.beacon.head);
        g_ap_setting_info.beacon.head = NULL;
    }
    if (g_ap_setting_info.beacon.tail != NULL) {
        OsalMemFree((uint8_t *)g_ap_setting_info.beacon.tail);
        g_ap_setting_info.beacon.tail = NULL;
    }

    if (param->headIEs && param->headIEsLength > 0) {
        g_ap_setting_info.beacon.head = OsalMemCalloc(param->headIEsLength);
        memcpy_s((uint8_t *)g_ap_setting_info.beacon.head, param->headIEsLength,
                 param->headIEs, param->headIEsLength);
        g_ap_setting_info.beacon.head_len = param->headIEsLength;
    }

    if (param->tailIEs && param->tailIEsLength > 0) {
        g_ap_setting_info.beacon.tail = OsalMemCalloc(param->tailIEsLength);
        memcpy_s((uint8_t *)g_ap_setting_info.beacon.tail, param->tailIEsLength,
                 param->tailIEs, param->tailIEsLength);
        g_ap_setting_info.beacon.tail_len = param->tailIEsLength;
    }

    /* add beacon data for start ap */
    g_ap_setting_info.dtim_period = param->DTIMPeriod;
    g_ap_setting_info.hidden_ssid = param->hiddenSSID;
    g_ap_setting_info.beacon_interval = param->interval;
    HDF_LOGE("%s: dtim_period:%d---hidden_ssid:%d---beacon_interval:%d!",
             __func__, g_ap_setting_info.dtim_period,
             g_ap_setting_info.hidden_ssid, g_ap_setting_info.beacon_interval);

    g_ap_setting_info.beacon.beacon_ies = NULL;
    g_ap_setting_info.beacon.proberesp_ies = NULL;
    g_ap_setting_info.beacon.assocresp_ies = NULL;
    g_ap_setting_info.beacon.probe_resp = NULL;
    g_ap_setting_info.beacon.beacon_ies_len = 0X00;
    g_ap_setting_info.beacon.proberesp_ies_len = 0X00;
    g_ap_setting_info.beacon.assocresp_ies_len = 0X00;
    g_ap_setting_info.beacon.probe_resp_len = 0X00;

    bdh6_nl80211_calculate_ap_params(&g_ap_setting_info);
}

int32_t WalChangeBeacon(NetDevice *hnetDev, struct WlanBeaconConf *param)
{
    int32_t ret = 0;
    struct cfg80211_beacon_data info;
    struct net_device *netdev = NULL;
    struct wiphy *wiphy = NULL;
    struct NetDevice *netDev = NULL;
    netDev = get_real_netdev(hnetDev);
    netdev = GetLinuxInfByNetDevice(netDev);
    if (!netdev) {
        HDF_LOGE("%s: net_device is NULL", __func__);
        return -1;
    }

    wiphy = get_linux_wiphy_ndev(netdev);
    if (!wiphy) {
        HDF_LOGE("%s: wiphy is NULL", __func__);
        return -1;
    }

    HDF_LOGE("%s: start...", __func__);
    if ((int)param->interval <= 0) {
        HDF_LOGE("%s: invalid beacon interval=%d, %d,%d", __func__,
                 (int)param->interval, param->DTIMPeriod,
                 (int)param->hiddenSSID);
        return 0;
    }

    InitCfg80211BeaconDataInfo(&info, param);
    InitCfg80211ApSettingInfo(param);

    HDF_LOGE("%s: headIEsLen:%d---tailIEsLen:%d!", __func__,
             param->headIEsLength, param->tailIEsLength);
    ret = WalStartAp(netDev);
    HDF_LOGE("call start_ap ret=%d", ret);
    ret = (int32_t)wl_cfg80211_ops.change_beacon(wiphy, netdev, &info);
    if (ret < 0) {
        HDF_LOGE("%s: change_beacon failed!", __func__);
    }

    return HDF_SUCCESS;
}

static int32_t __HdfConnect(NetDevice *hnetDev, WlanConnectParams *param)
{
    int32_t ret = 0;
    struct net_device *ndev = NULL;
    struct wiphy *wiphy = NULL;
    struct NetDevice *netDev = NULL;
    struct cfg80211_connect_params cfg80211_params = {0};
    g_conn_event_ifidx = get_scan_ifidx(hnetDev->name);
    netDev = get_real_netdev(hnetDev);
    if (netDev == NULL || param == NULL) {
        HDF_LOGE("%s:NULL ptr!", __func__);
        return HDF_FAILURE;
    }
    ndev = GetLinuxInfByNetDevice(netDev);
    if (ndev == NULL) {
        HDF_LOGE("%s:NULL ptr!", __func__);
        return HDF_FAILURE;
    }

    wiphy = get_linux_wiphy_ndev(ndev);
    if (!wiphy) {
        HDF_LOGE("%s: wiphy is NULL", __func__);
        return -1;
    }

    if (param->centerFreq != WLAN_FREQ_NOT_SPECFIED) {
        cfg80211_params.channel = WalGetChannel(wiphy, param->centerFreq);
        if ((cfg80211_params.channel == NULL) ||
            (cfg80211_params.channel->flags & WIFI_CHAN_DISABLED)) {
            HDF_LOGE("%s:illegal channel.flags=%u", __func__,
                     (cfg80211_params.channel == NULL)
                         ? 0
                         : cfg80211_params.channel->flags);
            return HDF_FAILURE;
        }
    }

    cfg80211_params.bssid = param->bssid;
    cfg80211_params.ssid = param->ssid;
    cfg80211_params.ie = param->ie;
    cfg80211_params.ssid_len = param->ssidLen;
    cfg80211_params.ie_len = param->ieLen;

    cfg80211_params.crypto.wpa_versions = param->crypto.wpaVersions;
    cfg80211_params.crypto.cipher_group = param->crypto.cipherGroup;
    cfg80211_params.crypto.n_ciphers_pairwise = param->crypto.n_ciphersPairwise;

    memcpy_s(cfg80211_params.crypto.ciphers_pairwise,
             NL80211_MAX_NR_CIPHER_SUITES *
                 sizeof(cfg80211_params.crypto.ciphers_pairwise[0]),
             param->crypto.ciphersPairwise,
             NL80211_MAX_NR_CIPHER_SUITES *
                 sizeof(param->crypto.ciphersPairwise[0]));

    memcpy_s(cfg80211_params.crypto.akm_suites,
             NL80211_MAX_NR_AKM_SUITES *
                 sizeof(cfg80211_params.crypto.akm_suites[0]),
             param->crypto.akmSuites,
             NL80211_MAX_NR_AKM_SUITES * sizeof(param->crypto.akmSuites[0]));

    cfg80211_params.crypto.n_akm_suites = param->crypto.n_akmSuites;

    if (param->crypto.controlPort) {
        cfg80211_params.crypto.control_port = true;
    } else {
        cfg80211_params.crypto.control_port = false;
    }

    cfg80211_params.crypto.control_port_ethertype =
        param->crypto.controlPortEthertype;
    cfg80211_params.crypto.control_port_no_encrypt =
        param->crypto.controlPortNoEncrypt;

    cfg80211_params.key = param->key;
    cfg80211_params.auth_type = (unsigned char)param->authType;
    cfg80211_params.privacy = param->privacy;
    cfg80211_params.key_len = param->keyLen;
    cfg80211_params.key_idx = param->keyIdx;
    cfg80211_params.mfp = (unsigned char)param->mfp;

    HDF_LOGE("%s: %s connect ssid: %s", __func__, netDev->name,
             cfg80211_params.ssid);
    HDF_LOGE("%s: cfg80211_params "
             "auth_type:%d--channelId:%d--centerFreq:%d--Mac:%02x:%02x:%02x:%"
             "02x:%02x:%02x",
             __func__, cfg80211_params.auth_type, cfg80211_params.channel->band,
             param->centerFreq, cfg80211_params.bssid[0],
             cfg80211_params.bssid[1], cfg80211_params.bssid[0x2],
             cfg80211_params.bssid[0x3], cfg80211_params.bssid[0x4],
             cfg80211_params.bssid[0x5]);

    ret = wl_cfg80211_ops.connect(wiphy, ndev, &cfg80211_params);
    if (ret < 0) {
        HDF_LOGE("%s: connect failed!\n", __func__);
    }

    return ret;
}

int32_t HdfConnect(NetDevice *hnetDev, WlanConnectParams *param)
{
    int32_t ret = 0;
    mutex_lock(&bdh6_reset_driver_lock);
    rtnl_lock();
    ret = __HdfConnect(hnetDev, param);
    rtnl_unlock();
    mutex_unlock(&bdh6_reset_driver_lock);
    return ret;
}

static int32_t __HdfStartScan(NetDevice *hhnetDev,
                              struct WlanScanRequest *scanParam)
{
    int32_t ret = 0;
    struct net_device *ndev = NULL;
    struct wiphy *wiphy = NULL;
    NetDevice *hnetdev = hhnetDev;
    int32_t channelTotal;
    struct NetDevice *netDev = NULL;

    netDev = get_real_netdev(hhnetDev);
    ndev = GetLinuxInfByNetDevice(netDev);
    wiphy = get_linux_wiphy_ndev(ndev);
    channelTotal = ieee80211_get_num_supported_channels(wiphy);
    g_scan_event_ifidx = get_scan_ifidx(hnetdev->name);

    struct cfg80211_scan_request *request =
        (struct cfg80211_scan_request *)OsalMemCalloc(
            sizeof(struct cfg80211_scan_request) +
            sizeof(struct ieeee80211_channel *) * channelTotal);

    HDF_LOGE("%s: enter hdfStartScan %s, channelTotal: %d, for %u", __func__,
             ndev->name, channelTotal, sizeof(struct ieeee80211_channel *));

    if (request == NULL) {
        return HDF_FAILURE;
    }
    if (WifiScanSetRequest(netDev, scanParam, request) != HDF_SUCCESS) {
        WifiScanFree(&request);
        return HDF_FAILURE;
    }
    if (g_scan_event_ifidx == HDF_INF_P2P0 && g_hdf_infmap[HDF_INF_P2P0].wdev) {
        request->wdev = g_hdf_infmap[HDF_INF_P2P0].wdev;
    }

    HDF_LOGE("%s: enter cfg80211_scan, n_ssids=%d !", __func__,
             request->n_ssids);
    ret = wl_cfg80211_ops.scan(wiphy, request);
    HDF_LOGE("%s: left cfg80211_scan %d!", __func__, ret);

    if (ret != HDF_SUCCESS) {
        WifiScanFree(&request);
    }

    return ret;
}

int32_t HdfStartScan(NetDevice *hhnetDev, struct WlanScanRequest *scanParam)
{
    int32_t ret = 0;
    mutex_lock(&bdh6_reset_driver_lock);
    rtnl_lock();
    ret = __HdfStartScan(hhnetDev, scanParam);
    rtnl_unlock();
    mutex_unlock(&bdh6_reset_driver_lock);
    return ret;
}

int32_t WifiScanSetUserIe(const struct WlanScanRequest *params,
                          struct cfg80211_scan_request *request)
{
    if (params->extraIEsLen > WIFI_SCAN_EXTRA_IE_LEN_MAX) {
        HDF_LOGE("%s:unexpected extra len!extraIesLen=%d", __func__,
                 params->extraIEsLen);
        return HDF_FAILURE;
    }
    if ((params->extraIEs != NULL) && (params->extraIEsLen != 0)) {
        request->ie = (uint8_t *)OsalMemCalloc(params->extraIEsLen);
        if (request->ie == NULL) {
            HDF_LOGE("%s: calloc request->ie null", __func__);
            goto fail;
        }
        (void)memcpy_s((void *)request->ie, params->extraIEsLen,
                       params->extraIEs, params->extraIEsLen);
        request->ie_len = params->extraIEsLen;
    }

    return HDF_SUCCESS;

fail:
    if (request->ie != NULL) {
        OsalMemFree((void *)request->ie);
        request->ie = NULL;
    }

    return HDF_FAILURE;
}

int32_t WifiScanSetChannel(const struct wiphy *wiphy,
                           const struct WlanScanRequest *params,
                           struct cfg80211_scan_request *request)
{
    int32_t loop;
    int32_t count = 0;
    enum Ieee80211Band band = IEEE80211_BAND_2GHZ;
    struct ieee80211_channel *chan = NULL;

    int32_t channelTotal =
        ieee80211_get_num_supported_channels((struct wiphy *)wiphy);

    if ((params->freqs == NULL) || (params->freqsCount == 0)) {
        for (band = IEEE80211_BAND_2GHZ; band <= IEEE80211_BAND_5GHZ; band++) {
            if (wiphy->bands[band] == NULL) {
                HDF_LOGE("%s: wiphy->bands[band] = NULL!\n", __func__);
                continue;
            }

            for (loop = 0; loop < (int32_t)wiphy->bands[band]->n_channels;
                 loop++) {
                if (count >= channelTotal) {
                    break;
                }

                chan = &wiphy->bands[band]->channels[loop];
                if ((chan->flags & WIFI_CHAN_DISABLED) != 0) {
                    continue;
                }

                request->channels[count++] = chan;
            }
        }
    } else {
        for (loop = 0; loop < params->freqsCount; loop++) {
            chan = GetChannelByFreq(wiphy, (uint16_t)(params->freqs[loop]));
            if (chan == NULL) {
                HDF_LOGE("%s: freq not found!freq=%d!\n", __func__,
                         params->freqs[loop]);
                continue;
            }

            if (count >= channelTotal) {
                break;
            }

            request->channels[count++] = chan;
        }
    }

    if (count == 0) {
        HDF_LOGE("%s: invalid freq info!\n", __func__);
        return HDF_FAILURE;
    }
    request->n_channels = count;

    return HDF_SUCCESS;
}

#define HDF_ETHER_ADDR_LEN (6)
int32_t HdfConnectResultEventCallback(struct net_device *ndev, uint8_t *bssid,
                                      uint8_t *reqIe, uint8_t *rspIe,
                                      uint32_t reqIeLen, uint32_t rspIeLen,
                                      uint16_t connectStatus, uint16_t freq)
{
    int32_t retVal = 0;
    NetDevice *netDev = GetHdfNetDeviceByLinuxInf(ndev);
    struct ConnetResult connResult;
    // for check p2p0 report
    netDev = get_hdf_netdev(g_conn_event_ifidx);

    HDF_LOGE("%s: enter", __func__);

    if (netDev == NULL || bssid == NULL || rspIe == NULL || reqIe == NULL) {
        HDF_LOGE("%s: netDev / bssid / rspIe / reqIe  null!", __func__);
        return -1;
    }

    memcpy_s(&connResult.bssid[0], HDF_ETHER_ADDR_LEN, bssid,
             HDF_ETHER_ADDR_LEN);

    connResult.rspIe = rspIe;
    connResult.rspIeLen = rspIeLen;
    connResult.reqIe = reqIe;
    connResult.reqIeLen = reqIeLen;
    connResult.connectStatus = connectStatus;
    connResult.freq = freq;
    connResult.statusCode = connectStatus;

    retVal = HdfWifiEventConnectResult(netDev, &connResult);
    if (retVal < 0) {
        HDF_LOGE("%s: hdf wifi event inform connect result failed!", __func__);
    }
    return retVal;
}

void HdfInformBssFrameEventCallback(struct net_device *ndev,
                                    struct ieee80211_channel *channel,
                                    int32_t signal, int16_t freq,
                                    struct ieee80211_mgmt *mgmt,
                                    uint32_t mgmtLen)
{
    int32_t retVal = 0;
    NetDevice *netDev = GetHdfNetDeviceByLinuxInf(ndev);
    struct ScannedBssInfo bssInfo;
    struct WlanChannel hdfchannel;

    if (channel == NULL || netDev == NULL || mgmt == NULL) {
        HDF_LOGE("%s: inform_bss_frame channel = null or netDev = null!",
                 __func__);
        return;
    }
    netDev = get_hdf_netdev(g_scan_event_ifidx);
    bssInfo.signal = signal;
    bssInfo.freq = freq;
    bssInfo.mgmtLen = mgmtLen;
    bssInfo.mgmt = (struct Ieee80211Mgmt *)mgmt;

    hdfchannel.flags = channel->flags;
    hdfchannel.channelId = channel->hw_value;
    hdfchannel.centerFreq = channel->center_freq;
    retVal = HdfWifiEventInformBssFrame(netDev, &hdfchannel, &bssInfo);
    if (retVal < 0) {
        HDF_LOGE("%s: hdf wifi event inform bss frame failed!", __func__);
    }
}

int32_t BDH6Init(struct HdfChipDriver *chipDriver, struct NetDevice *netDevice)
{
    int32_t ret = 0;
    struct HdfWifiNetDeviceData *data = NULL;
    struct net_device *netdev = NULL;
    int private_data_size = 0;
    struct wiphy *wiphy = NULL;
    struct net_device *p2p_netdev = NULL;
    struct NetDevice *p2p_hnetdev = NULL;
    struct bcm_cfg80211 *cfg = NULL;

    (void)chipDriver;
    HDF_LOGW("bdh6: call BDH6Init");
    HdfInfMapInit();

    if (netDevice == NULL) {
        HDF_LOGE("%s netdevice is null!", __func__);
        return HDF_FAILURE;
    }

    netdev = GetLinuxInfByNetDevice(netDevice);
    if (netdev == NULL) {
        HDF_LOGE("%s net_device is null!", __func__);
        return HDF_FAILURE;
    }

    data = GetPlatformData(netDevice);
    if (data == NULL) {
        HDF_LOGE("%s:netdevice data null!", __func__);
        return HDF_FAILURE;
    }

    hdf_bdh6_netdev_init(netDevice);
    netDevice->classDriverPriv = data;
    private_data_size = get_dhd_priv_data_size(); // create bdh6 private object
    netDevice->mlPriv = kzalloc(private_data_size, GFP_KERNEL);
    if (netDevice->mlPriv == NULL) {
        HDF_LOGE("%s:kzalloc mlPriv failed", __func__);
        return HDF_FAILURE;
    }

    set_krn_netdev(netDevice, netdev, g_hdf_ifidx);
    dhd_module_init();
    ret = hdf_bdh6_netdev_open(netDevice);
    if (ret != 0) {
        HDF_LOGE("%s:open netdev %s failed", __func__, netDevice->name);
    }

    ret = BDH6InitNetdev(netDevice, sizeof(void *), NL80211_IFTYPE_P2P_DEVICE,
                         HDF_INF_P2P0);
    if (ret != 0) {
        HDF_LOGE("%s:BDH6InitNetdev p2p0 failed", __func__);
        return HDF_FAILURE;
    }
    wiphy = get_linux_wiphy_ndev(netdev);
    if (wiphy == NULL) {
        HDF_LOGE("%s:get wlan0 wiphy failed", __func__);
        return HDF_FAILURE;
    }
    p2p_hnetdev = get_hdf_netdev(g_hdf_ifidx);
    p2p_netdev = get_krn_netdev(g_hdf_ifidx);
    p2p_netdev->ieee80211_ptr = NULL;
    p2p_hnetdev->ieee80211Ptr = p2p_netdev->ieee80211_ptr;
    cfg = wiphy_priv(wiphy); // update mac from wdev address
    wl_get_vif_macaddr(cfg, 7, p2p_hnetdev->macAddr); // WL_IF_TYPE_P2P_DISC = 7
    memcpy_s(p2p_netdev->dev_addr, p2p_netdev->addr_len, p2p_hnetdev->macAddr,
             MAC_ADDR_SIZE);
    p2p_hnetdev->netDeviceIf = wal_get_net_p2p_ops(); // reset netdev_ops
    hdf_cfgp2p_register_ndev(p2p_netdev, netdev, wiphy);
    ret = NetDeviceAdd(p2p_hnetdev); // Call linux register_netdev()
    HDF_LOGE("NetDeviceAdd %s ret = %d", p2p_hnetdev->name, ret);

    if (bdh6_reset_driver_flag) {
        p2p_hnetdev->netDeviceIf->open(p2p_hnetdev);
        rtnl_lock();
        dev_open(netdev, NULL);
        rtnl_unlock();
        rtnl_lock();
        dev_open(p2p_netdev, NULL);
        rtnl_unlock();
        if (start_p2p_completed) {
            start_p2p_completed = 0;
            hdf_start_p2p_device();
        }
        bdh6_reset_driver_flag = 0;
        HDF_LOGE("%s: reset driver ok", __func__);
    }
    return HDF_SUCCESS;
}
