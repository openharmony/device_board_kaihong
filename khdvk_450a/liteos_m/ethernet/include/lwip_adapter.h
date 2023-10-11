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

#ifndef LWIP_ADAPTER_H
#define LWIP_ADAPTER_H

#include "gd32f4xx.h"
#include "stdint.h"

void lwip_stack_init(void);
#define DHCP_TIMEOUT_S 30
#define ETH_THREAD_PRIORITY 5
#define ENET_TASK_STACK_SIZE 1024
#define ENET_TASK_PRIORITY 30
#define DHCP_TASK_STACK_SIZE 1024
#define DHCP_TASK_PRIORITY 29

#define USE_ENET_INTERRUPT
#define MAC_ADDR0 2
#define MAC_ADDR1 0xA
#define MAC_ADDR2 0xF
#define MAC_ADDR3 0xE
#define MAC_ADDR4 0xD
#define MAC_ADDR5 6

/* static IP address: IP_ADDR0.IP_ADDR1.IP_ADDR2.IP_ADDR3 */
#define IP_ADDR0 192
#define IP_ADDR1 168
#define IP_ADDR2 100
#define IP_ADDR3 2

/* remote IP address: IP_S_ADDR0.IP_S_ADDR1.IP_S_ADDR2.IP_S_ADDR3 */
#define IP_S_ADDR0 192
#define IP_S_ADDR1 168
#define IP_S_ADDR2 100
#define IP_S_ADDR3 3

/* net mask */
#define NETMASK_ADDR0 255
#define NETMASK_ADDR1 255
#define NETMASK_ADDR2 255
#define NETMASK_ADDR3 0

/* gateway address */
#define GW_ADDR0 192
#define GW_ADDR1 168
#define GW_ADDR2 100
#define GW_ADDR3 1

#define RMII_MODE // user have to provide the 50 MHz clock by soldering a 50 MHz oscillator

/* clock the PHY from external 25MHz crystal (only for MII mode) */
#ifdef MII_MODE
#define PHY_CLOCK_MCO
#endif

typedef union {
    UINT32 u32_addr;
    UINT8 u8_addr[4];
} IPUnion;

typedef struct {
    unsigned char useStaticIp;
    IPUnion ipaddr;
    IPUnion netmask;
    IPUnion gw;
    unsigned char useStaticMac;
    unsigned char macAddr[6];
} EthLinkInfo;

typedef enum {
    STATE_UPDATE_LINK_DOWN = 0,
    STATE_UPDATE_LINK_UP = 1,
} EthLinkState;

typedef void (*net_state_callBack)(EthLinkState state);

#define PHY_STATUS_CALLBACK(func, val)                                                                                 \
    {                                                                                                                  \
        do {                                                                                                           \
            if ((func) != NULL) {                                                                                      \
                (func)(val);                                                                                           \
            }                                                                                                          \
        } while (0);                                                                                                   \
    }

extern void enet_gpio_config(void);

#endif // end of #ifndef LWIP_ADAPTER_H