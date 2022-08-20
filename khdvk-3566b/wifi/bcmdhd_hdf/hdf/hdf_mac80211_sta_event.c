/*
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
#include <net/netlink.h>
#include <net/cfg80211.h>
#include <securec.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/in6.h>
#include <linux/wireless.h>

#include "osal_mem.h"
#include "net_device.h"
#include "net_device_impl.h"
#include "net_device_adapter.h"
#include "wifi_mac80211_ops.h"
#include "hdf_wifi_cmd.h"
#include "hdf_wifi_event.h"
#include "hdf_wl_interface.h"
#include "hdf_public_ap6275s.h"
#include "hdf_mac80211_sta_event.h"

#define HDF_LOG_TAG BDH6Driver
#define WIFI_SCAN_EXTRA_IE_LEN_MAX      (512)

int32_t HdfScanEventCallback(struct net_device *ndev, HdfWifiScanStatus _status)
{
    int32_t ret = 0;

    NetDevice *netDev = GetHdfNetDeviceByLinuxInf(ndev);
    WifiScanStatus status = _status;
    netDev = get_hdf_netdev(g_scan_event_ifidx);
    HDF_LOGE("%s: %d, scandone!", __func__, _status);
    ret = HdfWifiEventScanDone(netDev, status);

    return ret;
}

int32_t HdfDisconnectedEventCallback(struct net_device *ndev, uint16_t reason, uint8_t *ie, uint32_t len)
{
    int32_t ret = 0;

    NetDevice *netDev = GetHdfNetDeviceByLinuxInf(ndev);
    netDev = get_hdf_netdev(g_conn_event_ifidx);
    HDF_LOGE("%s: leave", __func__);

    ret = HdfWifiEventDisconnected(netDev, reason, ie, len);
    return ret;
}
