/*
 * hdfinit_bdh.c
 *
 * hdf driver
 *
 * Copyright (c) 2022 Shenzhen KaiHong Digital Industry Development Co., Ltd.
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
#include <uapi/linux/nl80211.h>
#include <securec.h>
#include <asm/byteorder.h>
#include <linux/kernel.h>

#include "hdf_wifi_product.h"
#include "wifi_mac80211_ops.h"
#include "hdf_wlan_utils.h"
#include "hdf_wl_interface.h"
#include "net_bdh_adpater.h"
#include "hdf_public_ap6275s.h"
#include "eapol.h"

#define HDF_LOG_TAG BDH6Driver
int hdf_cfgp2p_register_ndev(struct net_device *p2p_netdev, struct net_device *primary_netdev, struct wiphy *wiphy);
void dhd_module_exit(void);
struct NetDeviceInterFace *wal_get_net_p2p_ops(void);
struct hdf_inf_map g_hdf_infmap[HDF_INF_MAX];

int g_hdf_ifidx = HDF_INF_WLAN0;
int g_event_ifidx = HDF_INF_WLAN0;
int g_scan_event_ifidx = HDF_INF_WLAN0;
int g_conn_event_ifidx = HDF_INF_WLAN0;
int g_mgmt_tx_event_ifidx = HDF_INF_P2P0;
int bdh6_reset_driver_flag = 0;

// BDH Wifi6 chip driver init
int32_t InitBDH6Chip(struct HdfWlanDevice *device)
{
    (void)device;
    HDF_LOGW("bdh6: call InitBDH6Chip");
    return HDF_SUCCESS;
}

int32_t DeinitBDH6Chip(struct HdfWlanDevice *device)
{
    int32_t ret = HDF_SUCCESS;
    (void)device;
    if (ret != 0) {
        HDF_LOGE("%s:Deinit failed!ret=%d", __func__, ret);
    }
    return ret;
}

int32_t BDH6Deinit(struct HdfChipDriver *chipDriver, struct NetDevice *netDevice)
{
    // free p2p0
    int32_t i = 0;
    struct NetDevice *p2p_hnetdev = get_hdf_netdev(HDF_INF_P2P0);

    (void)chipDriver;
    kfree(p2p_hnetdev->mlPriv);
    p2p_hnetdev->mlPriv = NULL;
    DestroyEapolData(p2p_hnetdev);
    if (NetDeviceDelete(p2p_hnetdev) != 0) {
        return HDF_FAILURE;
    }
    if (NetDeviceDeInit(p2p_hnetdev) != 0) {
        return HDF_FAILURE;
    }
	
    hdf_bdh6_netdev_stop(netDevice);
    dhd_module_exit();

    // free primary wlan0
    kfree(netDevice->mlPriv);
    netDevice->mlPriv = NULL;
    DestroyEapolData(netDevice);

    for (i = 0; i < HDF_INF_MAX; i ++) {
        cancel_work_sync(&g_hdf_infmap[i].eapolEvent.eapol_report);
        NetBufQueueClear(&g_hdf_infmap[i].eapolEvent.eapolQueue);
    }

    bdh6_reset_driver_flag = 1;
    HDF_LOGE("%s: ok", __func__);
    
    return HDF_SUCCESS;
}

struct NetDevice *get_real_netdev(NetDevice *netDev)
{
    if (strcmp(netDev->name, "p2p0") == 0) {
        return get_hdf_netdev(HDF_INF_WLAN0);
    } else {
        return netDev;
    }
}
