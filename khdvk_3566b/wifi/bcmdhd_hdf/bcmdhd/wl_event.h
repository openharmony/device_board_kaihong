/*
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _wl_event_
#define _wl_event_
typedef enum WL_EVENT_PRIO {
	PRIO_EVENT_IAPSTA,
	PRIO_EVENT_ESCAN,
	PRIO_EVENT_WEXT
}wl_event_prio_t;
s32 wl_ext_event_attach(struct net_device *net);
void wl_ext_event_dettach(dhd_pub_t *dhdp);
int wl_ext_event_attach_netdev(struct net_device *net, int ifidx, uint8 bssidx);
int wl_ext_event_dettach_netdev(struct net_device *net, int ifidx);
int wl_ext_event_register(struct net_device *dev, dhd_pub_t *dhd,
	uint32 event, void *cb_func, void *data, wl_event_prio_t prio);
void wl_ext_event_deregister(struct net_device *dev, dhd_pub_t *dhd,
	uint32 event, void *cb_func);
void wl_ext_event_send(void *params, const wl_event_msg_t * e, void *data);
#endif

