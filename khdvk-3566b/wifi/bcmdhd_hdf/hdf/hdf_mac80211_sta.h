/*
 * hdf_mac80211_sta.h
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
#ifndef WAL_MAC80211_STA_H_
#define WAL_MAC80211_STA_H_

#include "wifi_mac80211_ops.h"

int32_t HdfStartScan(NetDevice *netdev, struct WlanScanRequest *scanParam);
int32_t HdfAbortScan(NetDevice *hnetDev);
int32_t HdfConnect(NetDevice *netDev, WlanConnectParams *param);
int32_t HdfDisconnect(NetDevice *netDev, uint16_t reasonCode);
int32_t HdfSetScanningMacAddress(NetDevice *netDev, unsigned char *mac, uint32_t len);
extern int32_t  wl_cfg80211_connect(struct wiphy *wiphy, struct net_device *dev,
    struct cfg80211_connect_params *sme);

extern int32_t wl_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *dev,
    u16 reason_code);
extern int32_t wl_cfg80211_abort_scan(struct wiphy *wiphy, struct wireless_dev *wdev);
#endif
