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

#include <stdio.h>
#include "stdint.h"
#include "los_config.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "netif/etharp.h"
#include "lwip/dhcp.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/timeouts.h"
#include "lwip/netif.h"
#include "lwip/ip4_addr.h"
#include "lwip/sockets.h"
#include "gd32f4xx.h"
#include "gd32f4xx_enet_eval.h"
#include "gd32f4xx_enet.h"
#include "cmsis_os2.h"
#include "los_interrupt.h"
#include "ethernetif.h"
#include "lwip_adapter.h"

err_t ethernetif_init(struct netif *netif);
#define MAX_DHCP_TRIES 4
#define DELAY250_MS 250
#define DELAY1000_MS 1000
#define IRQ_PRIORITY 2
#define CREATE_IRQ_MODE 5
static EthLinkInfo gEthLinkInfo = {.useStaticIp = 1, .useStaticMac = 1};

typedef enum { DHCP_START = 0, DHCP_WAIT_ADDRESS, DHCP_ADDRESS_ASSIGNED, DHCP_TIMEOUT } dhcp_state_enum;

#ifdef USE_DHCP
dhcp_state_enum dhcp_state = DHCP_START;
#endif

struct netif g_mynetif;
unsigned int tcp_timer = 0;
unsigned int arp_timer = 0;
ip_addr_t ip_address = {0};

void lwip_dhcp_process_handle(void);

void lwip_stack_init(void)
{
    ip_addr_t ipaddr;
    ip_addr_t netmask;
    ip_addr_t gw;

    tcpip_init(NULL, NULL);

#ifdef TIMEOUT_CHECK_USE_LWIP
    sys_timeouts_init();
#endif

#ifdef USE_DHCP
    ipaddr.addr = 0;
    netmask.addr = 0;
    gw.addr = 0;
#else
    IP_ADDR4(&ipaddr, IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
    IP_ADDR4(&netmask, NETMASK_ADDR0, NETMASK_ADDR1, NETMASK_ADDR2, NETMASK_ADDR3);
    IP_ADDR4(&gw, GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);

#endif /* USE_DHCP */

    netif_add(&g_mynetif, &ipaddr, &netmask, &gw, NULL, &ethernetif_init, &tcpip_input);
    /* registers the default network interface */
    netif_set_default(&g_mynetif);

    /* when the netif is fully configured this function must be called */
    netif_set_up(&g_mynetif);
}

#ifdef USE_DHCP
void dhcp_task(void *pvParameters)
{
    ip_addr_t ipaddr;
    ip_addr_t netmask;
    ip_addr_t gw;
    struct dhcp *dhcp_client;

    for (;;) {
        switch (dhcp_state) {
            case DHCP_START:
                dhcp_start(&g_mynetif);
                /* IP address should be set to 0 every time we want to assign a new DHCP address */
                dhcp_state = DHCP_WAIT_ADDRESS;
                printf("dhcp start\n");
                break;

            case DHCP_WAIT_ADDRESS:
                /* read the new IP address */
                ip_address.addr = g_mynetif.ip_addr.addr;
                printf("dhcp wait addr\n");
                if (ip_address.addr != 0) {
                    dhcp_state = DHCP_ADDRESS_ASSIGNED;
                    printf("\r\nDHCP -- eval board ip address: %d.%d.%d.%d \r\n", ip4_addr1_16(&ip_address),
                           ip4_addr2_16(&ip_address), ip4_addr3_16(&ip_address), ip4_addr4_16(&ip_address));
                } else {
                    /* DHCP timeout */
                    dhcp_client = netif_dhcp_data(&g_mynetif);
                    if (dhcp_client->tries > MAX_DHCP_TRIES) {
                        dhcp_state = DHCP_TIMEOUT;
                        /* stop DHCP */
                        dhcp_stop(&g_mynetif);
                        printf("dhcp set static addr\n");
                        /* static address used */
                        IP4_ADDR(&ipaddr, IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
                        IP4_ADDR(&netmask, NETMASK_ADDR0, NETMASK_ADDR1, NETMASK_ADDR2, NETMASK_ADDR3);
                        IP4_ADDR(&gw, GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);
                        netif_set_addr(&g_mynetif, &ipaddr, &netmask, &gw);
                    }
                }
                break;

            default:
                break;
        }
        osDelay(DELAY250_MS);
    }
}
#endif

#ifdef USE_ENET_INTERRUPT
static void nvic_configuration(void)
{
    nvic_irq_enable(ENET_IRQn, IRQ_PRIORITY, 0);
}
#endif

static __IO UINT32 enet_init_status = 0;

void enet_taskEntery(void *param)
{
    ErrStatus reval_state = ERROR;

#ifdef USE_ENET_INTERRUPT
    nvic_configuration();
#endif /* USE_ENET_INTERRUPT */

    /* configure the GPIO ports for ethernet pins */
    enet_gpio_config();

    /* enable ethernet clock  */
    rcu_periph_clock_enable(RCU_ENET);
    rcu_periph_clock_enable(RCU_ENETTX);
    rcu_periph_clock_enable(RCU_ENETRX);

    /* reset ethernet on AHB bus */
    enet_deinit();
    reval_state = enet_software_reset();
    while (ERROR == reval_state) {
        printf("enet reset \n");
        osDelay(DELAY1000_MS);
    }

#ifdef USE_ENET_INTERRUPT
    enet_interrupt_enable(ENET_DMA_INT_NIE);
    enet_interrupt_enable(ENET_DMA_INT_RIE);
#endif /* USE_ENET_INTERRUPT */

    lwip_stack_init();
    LOS_HwiCreate(ENET_IRQn, 0, CREATE_IRQ_MODE, (HWI_PROC_FUNC)ENET_IRQHandler_CB, 0);

    net_state_callBack callback = (net_state_callBack)param;
    uint16_t phy_value;
    uint16_t status = 0;
    while (1) {
        enet_phy_write_read(ENET_PHY_READ, PHY_ADDRESS, PHY_REG_BSR, &phy_value);
        if (status == (phy_value & PHY_LINKED_STATUS)) {
            osDelay(DELAY1000_MS);
            continue;
        }
        status = phy_value & PHY_LINKED_STATUS;
        if (status != RESET) {           /* link status changes from down to up */
            if (enet_init_status == 0) { /* init phy once */
#ifdef CHECKSUM_BY_HARDWARE
                enet_init_status =
                    enet_init(ENET_AUTO_NEGOTIATION, ENET_AUTOCHECKSUM_DROP_FAILFRAMES, ENET_BROADCAST_FRAMES_PASS);
#else
                enet_init_status =
                    enet_init(ENET_AUTO_NEGOTIATION, ENET_NO_AUTOCHECKSUM, ENET_BROADCAST_FRAMES_PASS);
#endif
            }
            PHY_STATUS_CALLBACK(callback, STATE_UPDATE_LINK_DOWN);
        } else {
            /* link status changes from up to down */
            PHY_STATUS_CALLBACK(callback, STATE_UPDATE_LINK_UP);
        }
        osDelay(DELAY1000_MS);
    }
}

void enet_adapter_init(net_state_callBack callBack)
{
    osThreadAttr_t attr = {.name = "net_init",
                           .attr_bits = 0U,
                           .cb_mem = NULL,
                           .stack_mem = NULL,
                           .stack_size = ENET_TASK_STACK_SIZE,
                           .priority = ENET_TASK_PRIORITY};
    if (osThreadNew((osThreadFunc_t)enet_taskEntery, (void *)callBack, &attr) == NULL) {
        printf("Create net task failed! \n");
    }

#ifdef USE_DHCP
    /* start DHCP client */
    osThreadAttr_t attr1 = {
        .name = "DHCP", .attr_bits = 0U, .cb_mem = NULL, .stack_mem = NULL, .stack_size = 1024, .priority = 29};
    if (osThreadNew((osThreadFunc_t)dhcp_task, NULL, &attr1) == NULL) {
        printf("Create DHCP task failed! \n");
    }
#endif
}
