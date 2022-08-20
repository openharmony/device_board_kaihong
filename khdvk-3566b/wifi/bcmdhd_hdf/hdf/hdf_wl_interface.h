/*
 * hdf_wl_interface.h
 *
 * ap6275s driver header
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
#ifndef HDF_WL_INTERFACE_H
#define HDF_WL_INTERFACE_H
#include <net/cfg80211.h>
#include <linux/netdevice.h>
#include "net_device.h"

enum hdf_inf_type {
    HDF_INF_WLAN0 = 0,
    HDF_INF_P2P0,
    HDF_INF_P2P1,
    HDF_INF_AP0,
    HDF_INF_MAX
};

struct hdf_eapol_event_s {
    struct work_struct eapol_report;
    NetBufQueue eapolQueue;
    int32_t idx;
};

struct hdf_inf_map {
    struct NetDevice  *hnetdev;
    struct net_device *netdev;
    struct wireless_dev *wdev;
    u8 macaddr[ETH_ALEN];
    struct hdf_eapol_event_s eapolEvent;
};

void eapol_report_handler(struct work_struct *work_data);
#endif
