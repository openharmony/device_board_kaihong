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

#include "iot_errno.h"
#include "iot_uart.h"
#include "los_sem.h"
#define DEFAULT_BAUDRATE (115200U)
typedef struct {
    unsigned int uartID; /* data */
    rcu_periph_enum gpioTxClock;
    rcu_periph_enum gpioRxClock;
    rcu_periph_enum uartClock;
    unsigned int af;
    unsigned int txGpio;
    unsigned int txPin;
    unsigned int rxGpio;
    unsigned int rxPin;
} UartSt;

UartSt gdUart[] = {
    {USART0, RCU_GPIOA, RCU_GPIOA, RCU_USART0, GPIO_AF_7, GPIOA, GPIO_PIN_9, GPIOA, GPIO_PIN_10},
    {USART1, RCU_GPIOD, RCU_GPIOD, RCU_USART1, GPIO_AF_7, GPIOD, GPIO_PIN_5, GPIOD, GPIO_PIN_6},
    {USART2, RCU_GPIOB, RCU_GPIOB, RCU_USART2, GPIO_AF_7, GPIOB, GPIO_PIN_10, GPIOB, GPIO_PIN_11},
    {UART3, RCU_GPIOC, RCU_GPIOC, RCU_UART3, GPIO_AF_8, GPIOC, GPIO_PIN_10, GPIOC, GPIO_PIN_11},
    {UART4, RCU_GPIOC, RCU_GPIOD, RCU_UART4, GPIO_AF_8, GPIOC, GPIO_PIN_12, GPIOD, GPIO_PIN_2},
    {USART5, RCU_GPIOC, RCU_GPIOC, RCU_USART5, GPIO_AF_8, GPIOC, GPIO_PIN_6, GPIOC, GPIO_PIN_7},
};

unsigned int IoTUartInit(unsigned int id, const IotUartAttribute *param)
{
    if (id >= sizeof(gdUart) / sizeof(*gdUart)) {
        return IOT_FAILURE;
    }

    // 使能 GPIO 时钟源
    rcu_periph_clock_enable(gdUart[id].gpioTxClock);
    if (gdUart[id].gpioTxClock != gdUart[id].gpioRxClock) {
        rcu_periph_clock_enable(gdUart[id].gpioRxClock);
    }
    // 使能 USART0 时钟源
    rcu_periph_clock_enable(gdUart[id].uartClock);

    /* 复用引脚为 USARTx_Tx */
    gpio_af_set(gdUart[id].txGpio, gdUart[id].af, gdUart[id].txPin);

    /* 复用引脚为 USARTx_Rx */
    gpio_af_set(gdUart[id].rxGpio, gdUart[id].af, gdUart[id].rxPin);

    /* 设置引脚为上拉复用 */
    gpio_mode_set(gdUart[id].txGpio, GPIO_MODE_AF, GPIO_PUPD_PULLUP, gdUart[id].txPin);
    gpio_output_options_set(gdUart[id].txGpio, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, gdUart[id].txPin);

    /* 设置引脚为上拉复用 */
    gpio_mode_set(gdUart[id].rxGpio, GPIO_MODE_AF, GPIO_PUPD_PULLUP, gdUart[id].rxPin);
    gpio_output_options_set(gdUart[id].rxGpio, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, gdUart[id].rxPin);

    /* USART 配置 */
    usart_deinit(gdUart[id].uartID);
    if (param != NULL) {
        usart_baudrate_set(gdUart[id].uartID, param->baudRate);
    } else {
        usart_baudrate_set(gdUart[id].uartID, DEFAULT_BAUDRATE);
    }
    usart_receive_config(gdUart[id].uartID, USART_RECEIVE_ENABLE);
    usart_transmit_config(gdUart[id].uartID, USART_TRANSMIT_ENABLE);
    usart_flag_clear(gdUart[id].uartID, USART_FLAG_TC | USART_FLAG_TBE);
    usart_enable(gdUart[id].uartID);
    return IOT_SUCCESS;
}

int IoTUartRead(unsigned int id, unsigned char *data, unsigned int dataLen)
{
    if (id >= sizeof(gdUart) / sizeof(*gdUart)) {
        return IOT_FAILURE;
    }

    for (int i = 0; i < sizeof(dataLen); i++) {
        while (usart_flag_get(gdUart[id].uartID, USART_FLAG_RBNE) == RESET) { };
        data[i] = usart_data_receive(gdUart[id].uartID);
    }
    return IOT_SUCCESS;
}

int IoTUartWrite(unsigned int id, const unsigned char *data, unsigned int dataLen)
{
    if (id >= sizeof(gdUart) / sizeof(*gdUart)) {
        return IOT_FAILURE;
    }
    for (int i = 0; i < sizeof(dataLen); i++) {
        usart_data_transmit(gdUart[id].uartID, (uint8_t)data[i]);
        while (RESET == usart_flag_get(gdUart[id].uartID, USART_FLAG_TBE)) { };
    }
    return IOT_SUCCESS;
}

unsigned int IoTUartDeinit(unsigned int id)
{
    if (id >= sizeof(gdUart) / sizeof(*gdUart)) {
        return IOT_FAILURE;
    }
    usart_deinit(gdUart[id].uartID);
    return IOT_SUCCESS;
}

unsigned int IoTUartSetFlowCtrl(unsigned int id, IotFlowCtrl flowCtrl)
{
    if (id >= sizeof(gdUart) / sizeof(*gdUart)) {
        return IOT_FAILURE;
    }
    uint32_t rtsConfig;
    uint32_t ctsConfig;
    switch (flowCtrl) {
        case IOT_FLOW_CTRL_NONE:
            rtsConfig = USART_RTS_DISABLE;
            ctsConfig = USART_CTS_DISABLE;
            break;
        case IOT_FLOW_CTRL_RTS_CTS:
            rtsConfig = USART_RTS_ENABLE;
            ctsConfig = USART_CTS_ENABLE;
            break;
        case IOT_FLOW_CTRL_RTS_ONLY:
            rtsConfig = USART_RTS_ENABLE;
            ctsConfig = USART_CTS_DISABLE;
            break;
        case IOT_FLOW_CTRL_CTS_ONLY:
            rtsConfig = USART_RTS_DISABLE;
            ctsConfig = USART_CTS_ENABLE;
            break;
        default:
            return IOT_FAILURE;
    }
    usart_hardware_flow_rts_config(gdUart[id].uartID, rtsConfig);
    usart_hardware_flow_cts_config(gdUart[id].uartID, ctsConfig);
    return IOT_SUCCESS;
}
