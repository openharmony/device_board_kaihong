/*
 * Copyright (c) 2022 Shenzhen KaiHong Digital Industry Development Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "wifi_mac80211_ops.h"
#include "hdf_wlan_utils.h"
#include "wifi_module.h"
#include <net/cfg80211.h>
#include <net/regulatory.h>
#include "osal_mem.h"
#include "hdf_wifi_event.h"
#include "hdf_log.h"
#include "osl.h"



#include <typedefs.h>
#include <ethernet.h>
#include <bcmutils.h>
#include <wl_cfgp2p.h>
#include "net_device_adapter.h"
#include "hdf_wl_interface.h"
#include <securec.h>
#include "eapol.h"

//#include "hdf_wifi_cmd.h"
//#include "wl_cfg80211.h"



enum wl_management_type {
	WL_BEACON = 0x1,
	WL_PROBE_RESP = 0x2,
	WL_ASSOC_RESP = 0x4
};

#define HDF_LOG_TAG BDH6Driver
#define HISI_DRIVER_FLAGS_AP                         0x00000040
#define HISI_DRIVER_FLAGS_P2P_DEDICATED_INTERFACE    0x00000400
#define HISI_DRIVER_FLAGS_P2P_CONCURRENT             0x00000200
#define HISI_DRIVER_FLAGS_P2P_CAPABLE                0x00000800
#define WLAN_WPS_IE_MAX_SIZE                352

#if defined(WL_CFG80211_P2P_DEV_IF)
#define ndev_to_cfg(ndev) ((ndev)->ieee80211_ptr)
#else
#define ndev_to_cfg(ndev)	(ndev)
#endif
#ifndef errno_t
typedef int errno_t;
#endif
extern struct net_device_ops dhd_ops_pri;
extern struct cfg80211_ops wl_cfg80211_ops;
extern struct hdf_inf_map g_hdf_infmap[HDF_INF_MAX];
extern int g_hdf_ifidx;
extern int g_event_ifidx;

extern struct net_device * GetLinuxInfByNetDevice(const struct NetDevice *netDevice);
extern struct wiphy * get_linux_wiphy_ndev(struct net_device *ndev);
extern struct wiphy * get_linux_wiphy_hdfdev(NetDevice *netDev);
int BDH6InitNetdev(struct NetDevice *netDevice, int private_data_size, int type, int ifidx);
int get_dhd_priv_data_size(void);
struct NetDevice * get_hdf_netdev(int ifidx);
int get_scan_ifidx(const char *ifname);


extern s32 wl_cfg80211_set_wps_p2p_ie(struct net_device *net, char *buf, int len,
	enum wl_management_type type);
	

struct net_device * get_krn_netdev(int ifidx);
struct NetDevice * get_real_netdev(NetDevice *netDev);
extern void rtnl_lock(void);
extern void rtnl_unlock(void);


static u64 p2p_cookie = 0;
u32 p2p_remain_freq = 0;
int start_p2p_completed = 0;

int32_t WalRemainOnChannel(struct NetDevice *netDev, WifiOnChannel *onChannel)
{
	struct net_device *netdev = NULL;
	struct wiphy *wiphy = NULL;
	bcm_struct_cfgdev *cfgdev = NULL;
	struct ieee80211_channel *channel = NULL;
	unsigned int duration;
    struct NetDevice *hnetdev = netDev;
    int ret = 0;
    
    netDev = get_real_netdev(netDev);
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
    HDF_LOGE("%s: ifname=%s, freq=%u, duration=%u", __func__, hnetdev->name, onChannel->freq, onChannel->duration);

	channel = OsalMemCalloc(sizeof(struct ieee80211_channel));
	cfgdev = ndev_to_cfg(netdev);
	channel->center_freq = onChannel->freq;    //remain_on_channel函数需要的参数
	duration = (unsigned int)onChannel->duration;
    p2p_remain_freq = channel->center_freq;
    
    ret = wl_cfg80211_ops.remain_on_channel(wiphy, cfgdev, channel, duration, &p2p_cookie);
    OsalMemFree(channel);
    return ret;
}



int32_t WalCancelRemainOnChannel(struct NetDevice *netDev)

{
    struct net_device *netdev = NULL;
    bcm_struct_cfgdev *cfgdev = NULL;
    struct wiphy *wiphy = NULL;
    struct NetDevice *hnetdev = netDev;
    
    netDev = get_real_netdev(netDev);
    netdev = GetLinuxInfByNetDevice(netDev);
    wiphy = get_linux_wiphy_ndev(netdev);
    if (!wiphy) {
        HDF_LOGE("%s: wiphy is NULL", __func__);
        return -1;
	}

    HDF_LOGE("%s: ifname = %s", __func__, hnetdev->name);
    if (!netdev) {
        HDF_LOGE("%s: net_device is NULL", __func__);
        return -1;
    }

    cfgdev =  ndev_to_cfg(netdev);

    return wl_cfg80211_ops.cancel_remain_on_channel(wiphy, cfgdev, p2p_cookie);
}

int32_t WalProbeReqReport(struct NetDevice *netDev, int32_t report)

{
    (void)report;

    HDF_LOGE("%s: ifname = %s, report=%d", __func__, netDev->name, report);

    return HDF_SUCCESS;

}
//extern int wl_cfgp2p_start_p2p_device(struct wiphy *wiphy, struct wireless_dev *wdev);
int32_t WalAddIf(struct NetDevice *netDev, WifiIfAdd *ifAdd)
{
    struct wiphy *wiphy = NULL;
    struct wireless_dev *wdev = NULL;
    int ret = 0;
    struct net_device *p2p_netdev = NULL;
    struct NetDevice *p2p_hnetdev = NULL;
    
    if (netDev == NULL || ifAdd == NULL) {
        HDF_LOGE("%s:NULL ptr!", __func__);
        return -1;
    }
    
    HDF_LOGE("%s: ifname = %s, type=%u", __func__, netDev->name, ifAdd->type);
    netDev = get_real_netdev(netDev);
    if (g_hdf_infmap[HDF_INF_P2P1].hnetdev != NULL) {
        HDF_LOGE("%s: ifidx=%d was used, failed add if", __func__, HDF_INF_P2P1);
        return -1;
    }

    ret = BDH6InitNetdev(netDev, get_dhd_priv_data_size(), ifAdd->type, HDF_INF_P2P1);
    if (ret != 0) {
        HDF_LOGE("%s:BDH6InitNetdev p2p-p2p0-0 failed", __func__);
        return HDF_FAILURE;
    }

    wiphy = get_linux_wiphy_hdfdev(netDev);
    if (wiphy == NULL) {
        HDF_LOGE("%s:get wlan0 wiphy failed", __func__);
        return HDF_FAILURE;
    }

    p2p_hnetdev = get_hdf_netdev(g_hdf_ifidx);
    p2p_netdev = get_krn_netdev(g_hdf_ifidx);
    
    wdev = wl_cfg80211_ops.add_virtual_intf(wiphy, p2p_hnetdev->name, NET_NAME_USER, ifAdd->type, NULL);
    if (wdev == NULL || wdev == ERR_PTR(-ENODEV)) {
        HDF_LOGE("%s:create wdev for %s %d failed", __func__, p2p_hnetdev->name, ifAdd->type);
        return HDF_FAILURE;
    }
	HDF_LOGE("%s:%s wdev->netdev=%p, %p", __func__, p2p_hnetdev->name, wdev->netdev, p2p_netdev);
    p2p_hnetdev->ieee80211Ptr = p2p_netdev->ieee80211_ptr;
    
    // update mac addr to NetDevice object
    memcpy_s(p2p_hnetdev->macAddr, MAC_ADDR_SIZE, p2p_netdev->dev_addr, p2p_netdev->addr_len);
    HDF_LOGE("%s: %s mac: %02x:%02x:%02x:%02x:%02x:%02x", __func__, p2p_hnetdev->name, 
        p2p_hnetdev->macAddr[0],
        p2p_hnetdev->macAddr[1],
        p2p_hnetdev->macAddr[2],
        p2p_hnetdev->macAddr[3],
        p2p_hnetdev->macAddr[4],
        p2p_hnetdev->macAddr[5]
    );
    
    //g_event_ifidx = HDF_INF_P2P1;
    //hdf_bdh6_netdev_open(p2p_hnetdev);
    
    return HDF_SUCCESS;
}

int32_t WalRemoveIf(struct NetDevice *netDev, WifiIfRemove *ifRemove)
{
    int i = HDF_INF_WLAN0;
    struct wiphy *wiphy = NULL;
    struct wireless_dev *wdev = NULL;
    struct NetDevice *p2p_hnetdev = NULL;
    int ret = 0;
    struct NetDevice *hnetdev = netDev;
    netDev = get_real_netdev(netDev);

    wiphy = get_linux_wiphy_hdfdev(netDev);
    if (wiphy == NULL) {
        HDF_LOGE("%s:get wlan0 wiphy failed", __func__);
        return HDF_FAILURE;
    }
    
    HDF_LOGE("%s: ifname=%s, primary netdev %s, remove ifname=%s", __func__, hnetdev->name, netDev->name, ifRemove->ifname);
    for (; i < HDF_INF_MAX; i ++) {
        p2p_hnetdev = g_hdf_infmap[i].hnetdev;
        if (p2p_hnetdev == NULL) {
            continue;
        }
        
        if (strcmp(p2p_hnetdev->name, ifRemove->ifname) == 0) {
            // check safely
            if (i == HDF_INF_WLAN0) {
                HDF_LOGE("%s: don't remove master interface %s", __func__, ifRemove->ifname);
                continue;
            }
            if (i != HDF_INF_P2P1) {
                HDF_LOGE("%s: remove %s is not p2p interface (%d %d)", __func__, ifRemove->ifname, i, HDF_INF_P2P1);
                //return HDF_FAILURE;
            }

			wdev = (struct wireless_dev *)p2p_hnetdev->ieee80211Ptr;
            ret = (int32_t)wl_cfg80211_ops.change_virtual_intf(wiphy, g_hdf_infmap[i].netdev, NL80211_IFTYPE_STATION, NULL);
            HDF_LOGE("%s: change %s mode %d --> %d, ret=%d", __func__, g_hdf_infmap[i].netdev->name, wdev->iftype, NL80211_IFTYPE_STATION, ret);
            
            //g_hdf_ifidx = HDF_INF_P2P0;  // delete p2p-p2p0-0 interface

			rtnl_lock();
            // clear private object
            DestroyEapolData(p2p_hnetdev);
            p2p_hnetdev->ieee80211Ptr = NULL;
            // This func free wdev object and call unregister_netdevice() and NetDeviceDeInit()
            ret = wl_cfg80211_ops.del_virtual_intf(wiphy, wdev);

            g_hdf_infmap[i].hnetdev = NULL;
            g_hdf_infmap[i].netdev = NULL;
            g_hdf_infmap[i].wdev = NULL;
            g_hdf_ifidx = HDF_INF_WLAN0;
            g_event_ifidx = HDF_INF_P2P0;
			rtnl_unlock();
            break;
        }
    }
    
    return ret;
}

int32_t WalSetApWpsP2pIe(struct NetDevice *netDev, WifiAppIe *appIe)
{
	struct net_device *netdev = NULL;
    enum wl_management_type type;
    
    netDev = get_real_netdev(netDev);
	netdev = GetLinuxInfByNetDevice(netDev);
    type = appIe->appIeType;

    HDF_LOGE("%s: primary netdev %s, type=%d", __func__, netDev->name, type);
    if (!netdev) {
        HDF_LOGE("%s: net_device is NULL", __func__);
        return -1;
    }
	
    if (appIe->ieLen > WLAN_WPS_IE_MAX_SIZE) {
        //oam_error_log0(0, 0, "app ie length is too large!");
        return -1;
    }

	return wl_cfg80211_set_wps_p2p_ie(netdev, appIe->ie, appIe->ieLen, type);
}

void cfg80211_init_wdev(struct wireless_dev *wdev);

int hdf_start_p2p_device(void)
{
    int ret = HDF_SUCCESS;
    struct wiphy *wiphy = NULL;
    struct wireless_dev *wdev = NULL;
    struct net_device *netdev = get_krn_netdev(HDF_INF_WLAN0);

    if (start_p2p_completed == 1) {
        HDF_LOGE("%s:start p2p completed already", __func__);
        return 0;
    }

    // create wdev object for p2p-dev-wlan0 device, refer nl80211_new_interface()
    wiphy = get_linux_wiphy_ndev(netdev);
    if (wiphy == NULL) {
        HDF_LOGE("%s:get wlan0 wiphy failed", __func__);
        return HDF_FAILURE;
    }

    wdev = wl_cfg80211_ops.add_virtual_intf(wiphy, "p2p-dev-wlan0", NET_NAME_USER, NL80211_IFTYPE_P2P_DEVICE, NULL);
    if (wdev == NULL) {
        HDF_LOGE("%s:create wdev for p2p-dev-wlan0 %d failed", __func__, NL80211_IFTYPE_P2P_DEVICE);
        return HDF_FAILURE;
    }
    cfg80211_init_wdev(wdev);
	HDF_LOGE("%s:p2p-dev-wlan0 wdev->netdev=%p", __func__, wdev->netdev);

    g_hdf_infmap[HDF_INF_P2P0].wdev = wdev;  // free it for module released !!

    ret = wl_cfg80211_ops.start_p2p_device(wiphy, NULL);
    HDF_LOGE("call start_p2p_device ret = %d", ret);
    g_event_ifidx = HDF_INF_P2P0;
    start_p2p_completed = 1;
    
    return ret;
}

int32_t WalGetDriverFlag(struct NetDevice *netDev, WifiGetDrvFlags **params)
{
    struct wireless_dev *wdev = NULL;
    WifiGetDrvFlags *getDrvFlag = NULL;
    int iftype = 0;
    int ifidx = 0;

    HDF_LOGE("%s: primary netdev %s", __func__, netDev->name);
    if (netDev == NULL || params == NULL) {
        HDF_LOGE("%s:NULL ptr!", __func__);
        return -1;
    }
    wdev = (struct wireless_dev*)((netDev)->ieee80211Ptr);
    getDrvFlag = (WifiGetDrvFlags *)OsalMemCalloc(sizeof(WifiGetDrvFlags));
    if (wdev) {
        iftype = wdev->iftype;
    } else {
        ifidx = get_scan_ifidx(netDev->name);
        if (ifidx == HDF_INF_P2P0)
            iftype = NL80211_IFTYPE_P2P_DEVICE;
    }
        
    switch (iftype) {
        case NL80211_IFTYPE_P2P_CLIENT:
             /* fall-through */
        case NL80211_IFTYPE_P2P_GO:
            getDrvFlag->drvFlags = (unsigned int)(HISI_DRIVER_FLAGS_AP);
            g_event_ifidx = HDF_INF_P2P1;
            break;
        case NL80211_IFTYPE_P2P_DEVICE:
            getDrvFlag->drvFlags = (unsigned int)(HISI_DRIVER_FLAGS_P2P_DEDICATED_INTERFACE |
                                            HISI_DRIVER_FLAGS_P2P_CONCURRENT |
                                            HISI_DRIVER_FLAGS_P2P_CAPABLE);
            //getDrvFlag->drvFlags = (unsigned int)0xBA0CFEC0;
            hdf_start_p2p_device();
            break;
        default:
            getDrvFlag->drvFlags = 0;
    }

    *params = getDrvFlag;

    HDF_LOGE("%s: %s iftype=%d, drvflag=%lu", __func__, netDev->name, iftype, getDrvFlag->drvFlags);
    return HDF_SUCCESS;
}

struct HdfMac80211P2POps g_bdh6_p2pOps = {
    .RemainOnChannel = WalRemainOnChannel,
    .CancelRemainOnChannel = WalCancelRemainOnChannel,
    .ProbeReqReport = WalProbeReqReport,
    .AddIf = WalAddIf,
    .RemoveIf = WalRemoveIf,
    .SetApWpsP2pIe = WalSetApWpsP2pIe,
    .GetDriverFlag = WalGetDriverFlag,
};


