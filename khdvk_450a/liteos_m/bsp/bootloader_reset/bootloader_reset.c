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
#include "uart_if.h"
#include "cmsis_os2.h"
#include "ohos_init.h"
#include "los_task.h"

#define UART_BUFFER_LEN_RX 64
#define UART_RX_IDLE0 0
#define UART_RX_IDLE1 1
#define UART_RX_IDLE2 2
#define UART_RX_IDLE3 3
#define UART_RX_IDLE4 4
#define UART_RX_IDLE5 5
#define UART_RX_IDLE6 6
#define UART_RX_IDLE7 7
#define OFFSET 8
#define DELAY_TIME  10
#define TASK_PRIORITY 6

typedef struct {
    uint32_t rxLen;
    uint8_t rxStat;
    uint8_t rsv[3];
    uint8_t *rxPtr;
    uint8_t rxBuffer[UART_BUFFER_LEN_RX];
} UART_INFO;
static UART_INFO uart0;
static uint32_t restLen;
uint8_t usart_get_crc(void)
{
    uint32_t i;
    uint8_t crc = 0;

    for (i = 0; i < uart0.rxLen; i++) {
        crc += uart0.rxBuffer[i];
    }

    return ~crc;
}
void uart_buff_init(void)
{
    uart0.rxLen = 0;
    uart0.rxPtr = uart0.rxBuffer;
    uart0.rxStat = 0;
    memset_s(&uart0.rxBuffer, UART_BUFFER_LEN_RX, 0, UART_BUFFER_LEN_RX);
}

static int32_t Uart0Add(char uChar)
{
    uart0.rxStat++;
    *uart0.rxPtr = uChar;
    uart0.rxPtr++;
    uart0.rxLen++;
    return uart0.rxStat;
}

static void HandleByOrder(char uChar)
{
    switch (uart0.rxStat) {
        case UART_RX_IDLE0:
            if (uChar == 0x5) {
                uart0.rxLen = 0;
                uart0.rxPtr = uart0.rxBuffer;
                Uart0Add(uChar);
            }
            break;
        case UART_RX_IDLE1:
            uart0.rxStat = (uChar == 0x5) ? Uart0Add(uChar) : 0;
            break;
        case UART_RX_IDLE2:
        case UART_RX_IDLE3:
            uart0.rxStat = (uChar == 0xa) ? Uart0Add(uChar) : 0;
            break;
        case UART_RX_IDLE4:
            uart0.rxStat = (uChar == 0) ? Uart0Add(uChar) : 0;
            break;
        case UART_RX_IDLE5:
            Uart0Add(uChar);
            restLen = uChar;
            break;
        case UART_RX_IDLE6:
            Uart0Add(uChar);
            restLen = (restLen << OFFSET) | uChar;
            if (restLen == OFFSET) {
                restLen = 1;
            } else {
                uart0.rxStat = 0;
            }
            break;
        case UART_RX_IDLE7:
            if (uart0.rxLen >= UART_BUFFER_LEN_RX) {
                uart0.rxStat = 0;
                break;
            }
            Uart0Add(uChar);
            uart0.rxStat--;
            restLen--;
            if (restLen != 0) {
                break;
            }
            if (usart_get_crc() == 0) {
                NVIC_SystemReset();
            } else {
                uart0.rxStat = 0;
            }
        default:
            break;
    }
}
void StartResetBootloader(void)
{
    uint32_t port = 0;
    int32_t ret;
    uint32_t baudRate;
    uint8_t uChar;
    DevHandle handle = NULL;
    handle = UartOpen(port);
    if (handle == NULL) {
        printf("UartOpen %u: failed!\n", port);
        return NULL;
    }
    ret = UartSetTransMode(handle, UART_MODE_RD_BLOCK);
    if (ret != 0) {
        return;
    }
    uart_buff_init();
    int t = 1;
    while (t > 0) {
        ret = UartRead(handle, &uChar, 1);
        if (ret < 0) {
            printf("UartRead: failed, ret %d\n", ret);
            UartClose(handle);
            return;
        }
        HandleByOrder(uChar);
    }
}

static void ResetBootloader(void)
{
    uint32_t uwRet;
    uint32_t taskID;
    TSK_INIT_PARAM_S stTask = {0};

    stTask.pfnTaskEntry = (TSK_ENTRY_FUNC)StartResetBootloader;
    stTask.uwStackSize = 0x1000;
    stTask.pcName = "StartResetBootloader";
    stTask.usTaskPrio = TASK_PRIORITY;
    uwRet = LOS_TaskCreate(&taskID, &stTask);
    if (uwRet != LOS_OK) {
        printf("ResetBootloader Task create failed\r\n");
    }
}

SYS_RUN(ResetBootloader);
