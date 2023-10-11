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

#ifndef ETHERNET_H_
#define ETHERNET_H_
#include <string.h>
#include "gd32f4xx_enet.h"
#include "cmsis_os2.h"

/* ENET RxDMA/TxDMA descriptor */
extern enet_descriptors_struct rxdesc_tab[ENET_RXBUF_NUM], txdesc_tab[ENET_TXBUF_NUM];

/* ENET receive buffer  */
extern uint8_t rx_buff[ENET_RXBUF_NUM][ENET_RXBUF_SIZE];

/* ENET transmit buffer */
extern uint8_t tx_buff[ENET_TXBUF_NUM][ENET_TXBUF_SIZE];

/* global transmit and receive descriptors pointers */
extern enet_descriptors_struct *dma_current_txdesc;
extern enet_descriptors_struct *dma_current_rxdesc;
extern void ENET_IRQHandler_CB(void);
#endif