/*
 * hdf_bdh_mac80211.c
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

#include "wifi_module.h"
#include "wifi_mac80211_ops.h"
#include "hdf_wlan_utils.h"
#include "net_bdh_adpater.h"
#include "hdf_wl_interface.h"
#include "hdf_public_ap6256.h"
#include "hdf_mac80211_sta.h"

#define HDF_LOG_TAG BDH6Driver

struct NetDevice *get_real_netdev(NetDevice *netDev);
int32_t WalStopAp(NetDevice *netDev);
struct wiphy *get_linux_wiphy_ndev(struct net_device *ndev)
{
    if (ndev == NULL || ndev->ieee80211_ptr == NULL) {
        return NULL;
    }

    return ndev->ieee80211_ptr->wiphy;
}

struct wiphy *get_linux_wiphy_hdfdev(NetDevice *netDev)
{
    struct net_device *ndev = GetLinuxInfByNetDevice(netDev);
    return get_linux_wiphy_ndev(ndev);
}

int32_t BDH6WalSetMode(NetDevice *hnetDev, enum WlanWorkMode iftype)
{
    int32_t retVal = 0;
    struct net_device *netdev = NULL;
    NetDevice *netDev = NULL;
    struct wiphy *wiphy = NULL;
    netDev = get_real_netdev(hnetDev);
    enum nl80211_iftype old_iftype = 0;
    
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
    old_iftype = netdev->ieee80211_ptr->iftype;

    HDF_LOGE("%s: start... iftype=%d, oldiftype=%d", __func__, iftype, old_iftype);
    if (old_iftype == NL80211_IFTYPE_AP && iftype != old_iftype) {
        WalStopAp(netDev);
    }

    if (iftype == NL80211_IFTYPE_P2P_GO && old_iftype == NL80211_IFTYPE_P2P_GO) {
        HDF_LOGE("%s: p2p go don't change mode", __func__);
        return retVal;
    }
    
    retVal = (int32_t)wl_cfg80211_ops.change_virtual_intf(wiphy, netdev,
        (enum nl80211_iftype)iftype, NULL);
    if (retVal < 0) {
        HDF_LOGE("%s: set mode failed!", __func__);
    }

    return retVal;
}

int32_t BDH6WalAddKey(struct NetDevice *hnetDev, uint8_t keyIndex, bool pairwise, const uint8_t *macAddr,
    struct KeyParams *params)
{
    int32_t retVal = 0;
    struct NetDevice *netDev = NULL;
    struct net_device *netdev = NULL;
    struct wiphy *wiphy = NULL;
    netDev = get_real_netdev(hnetDev);

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5, 10, 0))
    struct key_params keypm;
#endif

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
    
    HDF_LOGE("%s: start..., mac = %p, keyIndex = %u,pairwise = %d, cipher = 0x%x, seqlen = %d, keylen = %d",
        __func__, macAddr, keyIndex, pairwise, params->cipher, params->seqLen, params->keyLen);
    (void)netDev;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(5, 10, 0))
    memset_s(&keypm, sizeof(struct key_params), 0, sizeof(struct key_params));
    keypm.key = params->key;
    keypm.seq = params->seq;
    keypm.key_len = params->keyLen;
    keypm.seq_len = params->seqLen;
    keypm.cipher = params->cipher;
    keypm.vlan_id = 0;
    retVal = (int32_t)wl_cfg80211_ops.add_key(wiphy, netdev, keyIndex, pairwise, macAddr, &keypm);
#else
    retVal = (int32_t)wl_cfg80211_ops.add_key(wiphy, netdev, keyIndex, pairwise, macAddr, (struct key_params *)params);
#endif
    if (retVal < 0) {
        HDF_LOGE("%s: add key failed!", __func__);
    }

    return retVal;
}

int32_t BDH6WalDelKey(struct NetDevice *hnetDev, uint8_t keyIndex, bool pairwise, const uint8_t *macAddr)
{
    int32_t retVal = 0;
    struct NetDevice *netDev = NULL;
    struct net_device *netdev = NULL;
    struct wiphy *wiphy = NULL;
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

    HDF_LOGE("%s: start..., mac=%p, keyIndex=%u,pairwise=%d", __func__, macAddr, keyIndex, pairwise);

    (void)netDev;
    retVal = (int32_t)wl_cfg80211_ops.del_key(wiphy, netdev, keyIndex, pairwise, macAddr);
    if (retVal < 0) {
        HDF_LOGE("%s: delete key failed!", __func__);
    }

    return retVal;
}

int32_t BDH6WalSetDefaultKey(struct NetDevice *hnetDev, uint8_t keyIndex, bool unicast, bool multicas)
{
    int32_t retVal = 0;
    struct NetDevice *netDev = NULL;
    struct net_device *netdev = NULL;
    struct wiphy *wiphy = NULL;
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
    HDF_LOGE("%s: start..., keyIndex=%u,unicast=%d, multicas=%d", __func__, keyIndex, unicast, multicas);
    retVal = (int32_t)wl_cfg80211_ops.set_default_key(wiphy, netdev, keyIndex, unicast, multicas);
    if (retVal < 0) {
        HDF_LOGE("%s: set default key failed!", __func__);
    }

    return retVal;
}

int32_t BDH6WalGetDeviceMacAddr(NetDevice *hnetDev, int32_t type, uint8_t *mac, uint8_t len)
{
    struct NetDevice *netDev = NULL;
    netDev = get_real_netdev(hnetDev);
    struct net_device *netdev = GetLinuxInfByNetDevice(netDev);
    if (!netdev) {
        HDF_LOGE("%s: net_device is NULL", __func__);
        return -1;
    }

    (void)len;
    (void)type;
    (void)netDev;
    HDF_LOGE("%s: start...", __func__);
    
    memcpy_s(mac, len, netdev->dev_addr, netdev->addr_len);

    return HDF_SUCCESS;
}

int32_t BDH6WalSetMacAddr(NetDevice *hnetDev, uint8_t *mac, uint8_t len)
{
    int32_t retVal = 0;
    struct NetDevice *netDev = NULL;
    struct sockaddr sa;
    netDev = get_real_netdev(hnetDev);
    struct net_device *netdev = GetLinuxInfByNetDevice(netDev);
    if (!netdev) {
        HDF_LOGE("%s: net_device is NULL", __func__);
        return -1;
    }

    HDF_LOGE("%s: start...", __func__);
    if (mac == NULL || len != ETH_ALEN) {
        HDF_LOGE("%s: mac is error, len=%u", __func__, len);
        return -1;
    }
    if (!is_valid_ether_addr(mac)) {
        HDF_LOGE("%s: mac is invalid %02x:%02x:%02x:%02x:%02x:%02x", __func__,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return -1;
    }
    
    memcpy_s(sa.sa_data, ETH_ALEN, mac, len);

    retVal = (int32_t)dhd_ops_pri.ndo_set_mac_address(netdev, (void *)&sa);
    if (retVal < 0) {
        HDF_LOGE("%s: set mac address failed!", __func__);
    }

    return retVal;
}

int32_t BDH6WalSetTxPower(NetDevice *hnetDev, int32_t power)
{
    int retVal = 0;
    struct wiphy *wiphy = NULL;
    struct NetDevice *netDev = NULL;
    netDev = get_real_netdev(hnetDev);

    // sync from net_device->ieee80211_ptr
    struct wireless_dev *wdev = GET_NET_DEV_CFG80211_WIRELESS(netDev);

    wiphy = get_linux_wiphy_hdfdev(netDev);
    if (!wiphy) {
        HDF_LOGE("%s: wiphy is NULL", __func__);
        return -1;
    }

    HDF_LOGE("%s: start...", __func__);
    retVal = (int32_t)wl_cfg80211_ops.set_tx_power(wiphy, wdev, NL80211_TX_POWER_FIXED, power);
    if (retVal < 0) {
        HDF_LOGE("%s: set_tx_power failed!", __func__);
    }
        
    return HDF_SUCCESS;
}

void BDH6WalReleaseHwCapability(struct WlanHwCapability *self)
{
    uint8_t i;
    if (self == NULL) {
        return;
    }
    for (i = 0; i < IEEE80211_NUM_BANDS; i++) {
        if (self->bands[i] != NULL) {
            OsalMemFree(self->bands[i]);
            self->bands[i] = NULL;
        }
    }
    if (self->supportedRates != NULL) {
        OsalMemFree(self->supportedRates);
        self->supportedRates = NULL;
    }
    OsalMemFree(self);
}

int32_t BDH6WalGetIftype(struct NetDevice *hnetDev, uint8_t *iftype)
{
    struct NetDevice *netDev = NULL;
    netDev = get_real_netdev(hnetDev);
    iftype = (uint8_t *)(&(GET_NET_DEV_CFG80211_WIRELESS(netDev)->iftype));
    HDF_LOGE("%s: start...", __func__);
    return HDF_SUCCESS;
}

static struct HdfMac80211BaseOps g_bdh6_baseOps = {
    .SetMode = BDH6WalSetMode,
    .AddKey = BDH6WalAddKey,
    .DelKey = BDH6WalDelKey,
    .SetDefaultKey = BDH6WalSetDefaultKey,
    
    .GetDeviceMacAddr = BDH6WalGetDeviceMacAddr,
    .SetMacAddr = BDH6WalSetMacAddr,
    .SetTxPower = BDH6WalSetTxPower,
    .GetValidFreqsWithBand = Bdh6Fband,
    
    .GetHwCapability = Bdh6Ghcap,
    .SendAction = Bdh6SAction,
    .GetIftype = BDH6WalGetIftype,
    
};

void BDH6Mac80211Init(struct HdfChipDriver *chipDriver)
{
    HDF_LOGE("%s: start...", __func__);

    if (chipDriver == NULL) {
        HDF_LOGE("%s: input is NULL", __func__);
        return;
    }
    
    chipDriver->ops = &g_bdh6_baseOps;
    chipDriver->staOps = &g_bdh6_staOps;
    chipDriver->apOps = &g_bdh6_apOps;
    chipDriver->p2pOps = &g_bdh6_p2pOps;
}

