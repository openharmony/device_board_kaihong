/*
 * net_bdh_adpater.h
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
#ifndef NET_BDH_ADAPTER_H
#define NET_BDH_ADAPTER_H

#include <linux/netdevice.h>
#include "net_device.h"


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

void set_krn_netdev(struct NetDevice *hnetdev, struct net_device *netdev, int ifidx);
struct wiphy *get_krn_wiphy(void);

int32_t hdf_bdh6_netdev_init(struct NetDevice *netDev);
int32_t hdf_bdh6_netdev_open(struct NetDevice *netDev);
int32_t hdf_bdh6_netdev_stop(struct NetDevice *netDev);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
