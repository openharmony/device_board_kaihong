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

#include <string.h>
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/timeouts.h"
#include "netif/etharp.h"
#include "lwip/err.h"
#include "lwip_adapter.h"
#include "gd32f4xx_enet.h"
#include "cmsis_os2.h"
#include "los_interrupt.h"
#include "ethernetif.h"

#define ETHERNETIF_INPUT_TASK_STACK_SIZE (1024)
#define ETHERNETIF_INPUT_TASK_PRIO (5)
#define LOWLEVEL_OUTPUT_WAITING_TIME (250)
/* The time to block waiting for input */
#define LOWLEVEL_INPUT_WAITING_TIME ((uint32_t)100)
#define ENET_MTU (1500)

/* define those to better describe your network interface */
#define IFNAME0 'G'
#define IFNAME1 'D'

/* preserve another ENET RxDMA/TxDMA ptp descriptor for normal mode */
enet_descriptors_struct ptp_txstructure[ENET_TXBUF_NUM];
enet_descriptors_struct ptp_rxstructure[ENET_RXBUF_NUM];

void ethernetif_input(void *pvParameters);

static struct netif *low_netif = NULL;
osSemaphoreId_t g_rx_semaphore = NULL;

static void low_level_init(struct netif *netif)
{
    uint32_t i;

    /* set netif MAC hardware address length */
    netif->hwaddr_len = ETHARP_HWADDR_LEN;

    /* set netif MAC hardware address */
    int index = 0;
    netif->hwaddr[index++] = MAC_ADDR0;
    netif->hwaddr[index++] = MAC_ADDR1;
    netif->hwaddr[index++] = MAC_ADDR2;
    netif->hwaddr[index++] = MAC_ADDR3;
    netif->hwaddr[index++] = MAC_ADDR4;
    netif->hwaddr[index++] = MAC_ADDR5;

    /* set netif maximum transfer unit */
    netif->mtu = ENET_MTU;

    /* accept broadcast address and ARP traffic */
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

    low_netif = netif;

    /* create binary semaphore used for informing ethernetif of frame reception */
    if (g_rx_semaphore == NULL) {
        g_rx_semaphore = osSemaphoreNew(1, 1, g_rx_semaphore);
        osSemaphoreAcquire(g_rx_semaphore, 0);
    }

    /* initialize MAC address in ethernet MAC */
    enet_mac_address_set(ENET_MAC_ADDRESS0, netif->hwaddr);

    /* initialize descriptors list: chain/ring mode */
#ifdef SELECT_DESCRIPTORS_ENHANCED_MODE
    enet_ptp_enhanced_descriptors_chain_init(ENET_DMA_TX);
    enet_ptp_enhanced_descriptors_chain_init(ENET_DMA_RX);
#else
    enet_descriptors_chain_init(ENET_DMA_TX);
    enet_descriptors_chain_init(ENET_DMA_RX);
#endif

    for (i = 0; i < ENET_RXBUF_NUM; i++) {
        enet_rx_desc_immediate_receive_complete_interrupt(&rxdesc_tab[i]);
    }

#ifdef CHECKSUM_BY_HARDWARE
    /* enable the TCP, UDP and ICMP checksum insertion for the Tx frames */
    for (i = 0; i < ENET_TXBUF_NUM; i++) {
        enet_transmit_checksum_config(&txdesc_tab[i], ENET_CHECKSUM_TCPUDPICMP_FULL);
    }
#endif

    /* create the task that handles the ETH_MAC */
    osThreadAttr_t attr = {.name = "ETHERNETIF_INPUT",
                           .attr_bits = 0U,
                           .cb_mem = NULL,
                           .stack_mem = NULL,
                           .stack_size = ETHERNETIF_INPUT_TASK_STACK_SIZE,
                           .priority = ETHERNETIF_INPUT_TASK_PRIO};
    osThreadNew((osThreadFunc_t)ethernetif_input, (void *)netif, &attr);

    /* enable MAC and DMA transmission and reception */
    enet_enable();
}

static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
    static osSemaphoreId_t s_tx_semaphore = NULL;
    struct pbuf *q;
    uint8_t *buffer;
    uint16_t framelength = 0;
    ErrStatus reval = ERROR;

    SYS_ARCH_DECL_PROTECT(sr);

    if (s_tx_semaphore == NULL) {
        s_tx_semaphore = osSemaphoreNew(1, 1, NULL);
    }

    if (osOK == osSemaphoreAcquire(s_tx_semaphore, LOWLEVEL_OUTPUT_WAITING_TIME)) {
        sr = LOS_IntLock();
        while ((uint32_t)RESET != (dma_current_txdesc->status & ENET_TDES0_DAV)) { }
        buffer = (uint8_t *)(enet_desc_information_get(dma_current_txdesc, TXDESC_BUFFER_1_ADDR));

        for (q = p; q != NULL; q = q->next) {
            memcpy_s((uint8_t *)&buffer[framelength], q->len, q->payload, q->len);
            framelength = framelength + q->len;
        }

        /* transmit descriptors to give to DMA */
#ifdef SELECT_DESCRIPTORS_ENHANCED_MODE
        reval = ENET_NOCOPY_PTPFRAME_TRANSMIT_ENHANCED_MODE(framelength, NULL);
#else
        reval = ENET_NOCOPY_FRAME_TRANSMIT(framelength);
#endif

        LOS_IntRestore(sr);

        osSemaphoreRelease(s_tx_semaphore);
    }

    if (SUCCESS == reval) {
        return ERR_OK;
    } else {
        while (1) { }
    }
}

static struct pbuf *low_level_input(struct netif *netif)
{
    struct pbuf *p = NULL, *q;
    uint32_t l = 0;
    u16_t len;
    uint8_t *buffer;

    /* obtain the size of the packet and put it into the "len" variable. */
    len = enet_desc_information_get(dma_current_rxdesc, RXDESC_FRAME_LENGTH);
    buffer = (uint8_t *)(enet_desc_information_get(dma_current_rxdesc, RXDESC_BUFFER_1_ADDR));

    if (len > 0) {
        p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    }
    if (p != NULL) {
        for (q = p; q != NULL; q = q->next) {
            memcpy_s((uint8_t *)q->payload, q->len, (u8_t *)&buffer[l], q->len);
            l = l + q->len;
        }
    }
#ifdef SELECT_DESCRIPTORS_ENHANCED_MODE
    ENET_NOCOPY_PTPFRAME_RECEIVE_ENHANCED_MODE(NULL);
#else
    ENET_NOCOPY_FRAME_RECEIVE();
#endif

    return p;
}

void ethernetif_input(void *pvParameters)
{
    struct pbuf *p;
    SYS_ARCH_DECL_PROTECT(sr);

    for (;;) {
        if (osOK != osSemaphoreAcquire(g_rx_semaphore, LOWLEVEL_INPUT_WAITING_TIME)) {
            continue;
        }
        while (1) {
            sr = LOS_IntLock();
            p = low_level_input(low_netif);
            LOS_IntRestore(sr);

            if (p == NULL) {
                break;
            }
            if (ERR_OK != low_netif->input(p, low_netif)) {
                pbuf_free(p);
                break;
            }
        }
    }
}

err_t ethernetif_init(struct netif *netif)
{
    LWIP_ASSERT("netif != NULL", (netif != NULL));

    netif->name[0] = IFNAME0;
    netif->name[1] = IFNAME1;

    netif->output = etharp_output;
    netif->linkoutput = low_level_output;

    /* initialize the hardware */
    low_level_init(netif);

    return ERR_OK;
}

void ENET_IRQHandler_CB(void)
{
    /* frame received */
    if (SET == enet_interrupt_flag_get(ENET_DMA_INT_FLAG_RS)) {
        /* give the semaphore to wakeup LwIP task */
        osSemaphoreRelease(g_rx_semaphore);
    }
    enet_interrupt_flag_clear(ENET_DMA_INT_FLAG_RS_CLR);
    enet_interrupt_flag_clear(ENET_DMA_INT_FLAG_NI_CLR);
}