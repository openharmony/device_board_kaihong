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

#include "hdf_device_desc.h"

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
#include "hcs_macro.h"
#include "hdf_config_macro.h"
#else
#include "device_resource_if.h"
#endif
#include "hdf_log.h"
#include "osal.h"
#include "los_mux.h"
#include "los_queue.h"

#include "uart_if.h"
#include "uart_core.h"
#include "gd32f4xx_usart.h"

#define HDF_LOG_TAG uart_gd32f4xx
#define UART_HWI_PRIO (0U)
#define UART_HWI_MODE (1U)
#define CLOCK_APB (2)
#define UART_BUS_NUMS (8)
#define GPIO_REG_BASE 0x40020000
#define GPIO_REG_STEP 0x00000400
#define GPIO_BIT_PER_GROUP 16

struct UartCtrl {
    uint32_t num;
    uint32_t regBase;
    uint32_t irqNum;
    OSAL_DECLARE_SPINLOCK(lock);
    uint32_t baudRate;
    enum UartTransMode mode;
    uint32_t openCount;
    uint32_t af;
    uint32_t txPin;
    uint32_t rxPin;
    uint32_t fifoSize;
    void *priv;
};

static int32_t g_regBase;
static UINT32 g_queue;

static inline uint32_t ToGpioPin(uint16_t local)
{
    uint32_t pinNum = 0;

    pinNum = local % GPIO_BIT_PER_GROUP;

    return (BIT(pinNum));
}

static inline uint32_t ToGpioPeriph(uint16_t local)
{
    uint32_t gpioPeriph = 0;

    gpioPeriph = GPIO_REG_BASE + (local / GPIO_BIT_PER_GROUP) * GPIO_REG_STEP;

    return gpioPeriph;
}

static rcu_periph_enum GpioRcuEnumFind(uint32_t gpioGroup)
{
    uint32_t gpioClockOffset;
    gpioClockOffset = gpioGroup / GPIO_BIT_PER_GROUP;
    return RCU_REGIDX_BIT(AHB1EN_REG_OFFSET, gpioClockOffset);
}

static rcu_periph_enum UartRcuEnumFind(struct UartCtrl *uart)
{
    rcu_periph_enum usartRcus[UART_BUS_NUMS] = {
        RCU_USART0, RCU_USART1, RCU_USART2, RCU_UART3, RCU_UART4, RCU_USART5, RCU_UART6, RCU_UART7,
    };
    return usartRcus[uart->num];
}

static uint32_t UartRegBaseFind(struct UartCtrl *uart)
{
    uint32_t usarts[UART_BUS_NUMS] = {
        USART0, USART1, USART2, UART3, UART4, USART5, UART6, UART7,
    };
    return usarts[uart->num];
}

// enable uart, and enable tx/rx mode
static int32_t UartEnable(struct UartCtrl *uart, int enable)
{
    if (enable) {
        int32_t gpioGroup;
        int32_t gpioTxPin;
        int32_t gpioRxPin;
        gpioGroup = ToGpioPeriph(uart->txPin);
        gpioTxPin = ToGpioPin(uart->txPin);
        gpioRxPin = ToGpioPin(uart->rxPin);
        rcu_periph_clock_enable(GpioRcuEnumFind(uart->txPin));
        rcu_periph_clock_enable(UartRcuEnumFind(uart));

        gpio_af_set(gpioGroup, AF(uart->af), gpioTxPin);
        gpio_af_set(gpioGroup, AF(uart->af), gpioRxPin);

        gpio_mode_set(gpioGroup, GPIO_MODE_AF, GPIO_PUPD_PULLUP, gpioTxPin);
        gpio_output_options_set(gpioGroup, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, gpioTxPin);

        gpio_mode_set(gpioGroup, GPIO_MODE_AF, GPIO_PUPD_PULLUP, gpioRxPin);
        gpio_output_options_set(gpioGroup, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, gpioRxPin);

        usart_deinit(uart->regBase);

        usart_baudrate_set(uart->regBase, uart->baudRate);
        usart_word_length_set(uart->regBase, USART_WL_8BIT);
        usart_stop_bit_set(uart->regBase, USART_STB_1BIT);
        usart_parity_config(uart->regBase, USART_PM_NONE);

        usart_hardware_flow_rts_config(uart->regBase, USART_RTS_DISABLE);
        usart_hardware_flow_cts_config(uart->regBase, USART_CTS_DISABLE);

        usart_receive_config(uart->regBase, USART_RECEIVE_ENABLE);
        usart_transmit_config(uart->regBase, USART_TRANSMIT_ENABLE);

        usart_flag_clear(uart->regBase, USART_FLAG_TC | USART_FLAG_TBE);

        usart_enable(uart->regBase);

        nvic_irq_enable(uart->irqNum, 2U, 0U);

        usart_interrupt_enable(uart->regBase, USART_INT_RBNE);
    } else {
        usart_deinit(uart->regBase);

        usart_receive_config(uart->regBase, USART_RECEIVE_DISABLE);
        usart_transmit_config(uart->regBase, USART_TRANSMIT_DISABLE);

        usart_flag_clear(uart->regBase, USART_FLAG_TC | USART_FLAG_TBE);

        usart_interrupt_disable(uart->regBase, USART_INT_RBNE);

        nvic_irq_disable(uart->irqNum);

        usart_disable(uart->regBase);
    }
    return 0;
}

static int32_t UartDataBits(struct UartCtrl *uart, uint32_t bits)
{
    switch (bits) {
        case UART_ATTR_DATABIT_8:
            usart_word_length_set(uart->regBase, USART_WL_8BIT);
            break;
        default:
            HDF_LOGE("%s: not support parameter.\r\n", __func__);
            return HDF_ERR_INVALID_PARAM;
    }

    return 0;
}

static int32_t UartStopBits(struct UartCtrl *uart, uint32_t bits)
{
    switch (bits) {
        case UART_ATTR_STOPBIT_1:
            usart_stop_bit_set(uart->regBase, USART_STB_1BIT);
            break;
        case UART_ATTR_STOPBIT_1P5:
            usart_stop_bit_set(uart->regBase, USART_STB_1_5BIT);
            break;
        case UART_ATTR_STOPBIT_2:
            usart_stop_bit_set(uart->regBase, USART_STB_2BIT);
            break;
        default:
            HDF_LOGE("%s: not support parameter.\r\n", __func__);
            return HDF_ERR_INVALID_PARAM;
    }

    return 0;
}

static int32_t UartParity(struct UartCtrl *uart, uint32_t parity)
{
    switch (parity) {
        case UART_ATTR_PARITY_NONE:
            usart_parity_config(uart->regBase, USART_PM_NONE);
            break;
        case UART_ATTR_PARITY_ODD:
            usart_parity_config(uart->regBase, USART_PM_ODD);
            break;
        case UART_ATTR_PARITY_EVEN:
            usart_parity_config(uart->regBase, USART_PM_EVEN);
            break;
        default:
            HDF_LOGE("%s: not support parameter.\r\n", __func__);
            return HDF_ERR_INVALID_PARAM;
    }

    return 0;
}

static int32_t UartRts(struct UartCtrl *uart, uint32_t rts)
{
    switch (rts) {
        case UART_ATTR_RTS_DIS:
            usart_hardware_flow_rts_config(uart->regBase, USART_RTS_DISABLE);
            break;
        case UART_ATTR_RTS_EN:
            usart_hardware_flow_rts_config(uart->regBase, USART_RTS_ENABLE);
            break;
        default:
            HDF_LOGE("%s: not support parameter.\r\n", __func__);
            return HDF_ERR_INVALID_PARAM;
    }

    return 0;
}

static int32_t UartCts(struct UartCtrl *uart, uint32_t cts)
{
    switch (cts) {
        case UART_ATTR_CTS_DIS:
            usart_hardware_flow_cts_config(uart->regBase, USART_CTS_DISABLE);
            break;
        case UART_ATTR_CTS_EN:
            usart_hardware_flow_cts_config(uart->regBase, USART_CTS_ENABLE);
            break;
        default:
            HDF_LOGE("%s: not support parameter.\r\n", __func__);
            return HDF_ERR_INVALID_PARAM;
    }

    return 0;
}

static int32_t UartBaudrate(struct UartCtrl *uart, uint32_t baudRate)
{
    usart_baudrate_set(uart->regBase, baudRate);
    return 0;
}

static int32_t UartConfig(struct UartCtrl *uart)
{
    int32_t ret;
    struct UartAttribute *attr = (struct UartAttribute *)uart->priv;

    ret = UartDataBits(uart, attr->dataBits);
    ret |= UartStopBits(uart, attr->stopBits);
    ret |= UartParity(uart, attr->parity);
    ret |= UartRts(uart, attr->rts);
    ret |= UartCts(uart, attr->cts);

    return ret;
}

static int32_t UartDevOpen(struct UartHost *host)
{
    int32_t ret = HDF_SUCCESS;

    struct UartCtrl *uart = (struct UartCtrl *)host->priv;

    OsalSpinLock(&(uart->lock));

    struct UartAttribute *attr = (struct UartAttribute *)uart->priv;

    attr->dataBits = UART_ATTR_DATABIT_8;
    attr->parity = UART_ATTR_PARITY_NONE;
    attr->stopBits = UART_ATTR_STOPBIT_1;
    attr->rts = UART_ATTR_RTS_DIS;
    attr->cts = UART_ATTR_CTS_DIS;

    UartConfig(uart);
    UartEnable(uart, true);
    ret = LOS_QueueCreate("queue", uart->fifoSize, &g_queue, 0, 1);
    if (ret != LOS_OK) {
        HDF_LOGE("create queue failure, error: %x\n", ret);
    }
    uart->openCount++;

    OsalSpinUnlock(&(uart->lock));
    return ret;
}

static int32_t UartDevClose(struct UartHost *host)
{
    struct UartCtrl *uart = (struct UartCtrl *)host->priv;

    if (--uart->openCount > 0) {
        return HDF_FAILURE;
    }

    OsalSpinLock(&(uart->lock));

    UartEnable(uart, false);

    OsalSpinUnlock(&(uart->lock));

    return HDF_SUCCESS;
}

static int32_t UartDevRead(struct UartHost *host, uint8_t *data, uint32_t size)
{
    if (host == NULL || host->priv == NULL) {
        HDF_LOGE("%s: invalid parameter.\r\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = 0;
    int32_t recvSize = 0;
    int32_t readLen = 1;
    int32_t timeOut = 0;

    struct UartCtrl *uart = (struct UartCtrl *)host->priv;

    OsalSpinLock(&(uart->lock));

    if (uart->mode == UART_MODE_RD_BLOCK) {
        timeOut = LOS_WAIT_FOREVER;
    } else if (uart->mode == UART_MODE_RD_NONBLOCK) {
        timeOut = 0;
    } else {
        HDF_LOGE("mode not support");
    }
    while (recvSize < size) {
        ret = LOS_QueueReadCopy(g_queue, data + recvSize, &readLen, timeOut);
        if (ret == LOS_ERRNO_QUEUE_ISEMPTY) {
            break;
        }
        recvSize++;
    }

    OsalSpinUnlock(&(uart->lock));
    return recvSize;
}

static int32_t UartDevWrite(struct UartHost *host, uint8_t *data, uint32_t size)
{
    int32_t ret = HDF_SUCCESS;
    if (host == NULL || host->priv == NULL || data == NULL) {
        HDF_LOGE("%s: invalid parameter.\r\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UartCtrl *uart = (struct UartCtrl *)host->priv;

    OsalSpinLock(&(uart->lock));

    for (int i = 0; i < size; i++) {
        if (data[i] == '\n') {
            usart_data_transmit(uart->regBase, '\r');
            while (RESET == usart_flag_get(uart->regBase, USART_FLAG_TBE)) { };
            usart_data_transmit(uart->regBase, '\n');
        } else {
            usart_data_transmit(uart->regBase, data[i]);
        }
        while (RESET == usart_flag_get(uart->regBase, USART_FLAG_TBE)) { };
    }

    OsalSpinUnlock(&(uart->lock));

    return ret;
}

static int32_t UartDevGetBaud(struct UartHost *host, uint32_t *baudRate)
{
    int32_t ret = HDF_SUCCESS;
    if (host == NULL || host->priv == NULL || baudRate == NULL) {
        HDF_LOGE("%s: invalid parameter", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UartCtrl *uart = (struct UartCtrl *)host->priv;

    OsalSpinLock(&(uart->lock));

    *baudRate = uart->baudRate;

    OsalSpinUnlock(&(uart->lock));
    return ret;
}

static int32_t UartDevSetBaud(struct UartHost *host, uint32_t baudRate)
{
    int32_t ret = HDF_SUCCESS;
    if (host == NULL || host->priv == NULL || baudRate == 0) {
        HDF_LOGE("%s: invalid parameter", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UartCtrl *uart = (struct UartCtrl *)host->priv;

    OsalSpinLock(&(uart->lock));

    if (uart->baudRate != baudRate) {
        UartBaudrate(uart, baudRate);
        uart->baudRate = baudRate;
    }

    OsalSpinUnlock(&(uart->lock));
    return ret;
}

static int32_t UartDevGetAttribute(struct UartHost *host, struct UartAttribute *attribute)
{
    int32_t ret = HDF_SUCCESS;
    struct UartCtrl *uart = NULL;
    struct UartAttribute *attr = NULL;
    if (host == NULL || host->priv == NULL || attribute == NULL) {
        HDF_LOGE("%s: invalid parameter", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    uart = (struct UartCtrl *)host->priv;
    attr = (struct UartAttribute *)uart->priv;

    OsalSpinLock(&(uart->lock));

    memcpy_s(attribute, sizeof(struct UartAttribute), attr, sizeof(struct UartAttribute));

    OsalSpinUnlock(&(uart->lock));

    return ret;
}

static int32_t UartDevSetAttribute(struct UartHost *host, struct UartAttribute *attribute)
{
    HDF_LOGE("func: %s, UartSetAttribute ok\r\n", __func__);
    int32_t ret = HDF_SUCCESS;
    struct UartCtrl *uart = NULL;
    struct UartAttribute *attr = NULL;
    if (host == NULL || host->priv == NULL || attribute == NULL) {
        HDF_LOGE("%s: invalid parameter", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    uart = (struct UartCtrl *)host->priv;
    attr = (struct UartAttribute *)uart->priv;

    OsalSpinLock(&(uart->lock));

    // 保存新配置
    memcpy_s(attr, sizeof(struct UartAttribute), attribute, sizeof(struct UartAttribute));

    // 根据新配置，更新寄存器
    ret = UartConfig(uart);

    OsalSpinUnlock(&(uart->lock));
    return ret;
}

static int32_t UartDevSetTransMode(struct UartHost *host, enum UartTransMode mode)
{
    int32_t ret = HDF_SUCCESS;
    struct UartCtrl *uart = (struct UartCtrl *)host->priv;

    OsalSpinLock(&(uart->lock));

    switch (mode) {
        case UART_MODE_RD_BLOCK:
            uart->mode = UART_MODE_RD_BLOCK;
            break;
        case UART_MODE_RD_NONBLOCK:
            uart->mode = UART_MODE_RD_NONBLOCK;
            break;
        default:
            HDF_LOGE("%s: unsupport mode %#x.\r\n", __func__, mode);
            break;
    }

    OsalSpinUnlock(&(uart->lock));

    return ret;
}

struct UartHostMethod g_uartOps = {.Init = UartDevOpen,
                                   .Deinit = UartDevClose,
                                   .Read = UartDevRead,
                                   .Write = UartDevWrite,
                                   .GetBaud = UartDevGetBaud,
                                   .SetBaud = UartDevSetBaud,
                                   .GetAttribute = UartDevGetAttribute,
                                   .SetAttribute = UartDevSetAttribute,
                                   .SetTransMode = UartDevSetTransMode,
                                   .pollEvent = NULL};

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
#define UART_FIND_CONFIG(node, name, uart)                                                                             \
    do {                                                                                                               \
        if (strcmp(HCS_PROP(node, match_attr), name) == 0) {                                                           \
            uint32_t devNum = HCS_PROP(node, num);                                                                     \
            uint16_t baudRate = HCS_PROP(node, baudrate);                                                              \
            uint16_t mode = HCS_PROP(node, mode);                                                                      \
            uint32_t interrupt = HCS_PROP(node, interrupt);                                                            \
            uint32_t fifoSize = HCS_PROP(node, fifo_size);                                                             \
            uint32_t af = HCS_PROP(node, af);                                                                          \
            uint32_t txPin = HCS_PROP(node, tx_pin);                                                                   \
            uint32_t rxPin = HCS_PROP(node, rx_pin);                                                                   \
            uart->num = devNum;                                                                                        \
            uart->baudRate = baudRate;                                                                                 \
            uart->mode = mode;                                                                                         \
            uart->irqNum = interrupt;                                                                                  \
            uart->fifoSize = fifoSize;                                                                                 \
            uart->af = af;                                                                                             \
            uart->txPin = txPin;                                                                                       \
            uart->rxPin = rxPin;                                                                                       \
            result = HDF_SUCCESS;                                                                                      \
        }                                                                                                              \
    } while (0)
#define PLATFORM_CONFIG HCS_NODE(HCS_ROOT, platform)
#define PLATFORM_UART_CONFIG HCS_NODE(HCS_NODE(HCS_ROOT, platform), controller_0x40011000)
static int32_t ReadUartHcsSource(struct UartCtrl *uart, const char *deviceMatchAttr)
{
    int32_t result = HDF_FAILURE;
    if (uart == NULL || deviceMatchAttr == NULL) {
        HDF_LOGE("%s: uart resource or deviceMatchAttr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

#if HCS_NODE_HAS_PROP(PLATFORM_CONFIG, controller_0x40011000)
    HCS_FOREACH_CHILD_VARGS(PLATFORM_UART_CONFIG, UART_FIND_CONFIG, deviceMatchAttr, uart);
#endif
    if (result != HDF_SUCCESS) {
        HDF_LOGE("resourceNode %s is NULL\r\n", deviceMatchAttr);
    }

    return result;
}
#else
static int32_t ReadUartHcsSource(struct UartCtrl *uart, const struct DeviceResourceNode *node)
{
    int32_t ret;
    struct DeviceResourceIface *drsOps = NULL;

    drsOps = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (drsOps == NULL || drsOps->GetUint32 == NULL) {
        HDF_LOGE("%s: invalid drs ops!\r\n", __func__);
        return HDF_FAILURE;
    }

    ret = drsOps->GetUint32(node, "num", &uart->num, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read num fail!\r\n", __func__);
        return ret;
    }

    ret = drsOps->GetUint32(node, "mode", &uart->mode, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read mode fail!\r\n", __func__);
        return ret;
    }

    ret = drsOps->GetUint32(node, "baudrate", &uart->baudRate, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read baud_rate fail!\r\n", __func__);
        return ret;
    }

    ret = drsOps->GetUint32(node, "interrupt", &uart->irqNum, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read interrupt fail!\r\n", __func__);
        return ret;
    }

    ret = drsOps->GetUint32(node, "fifo_size", &uart->fifoSize, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read fifoSize fail!\r\n", __func__);
        return ret;
    }

    ret = drsOps->GetUint32(node, "af", &uart->af, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read af fail!\r\n", __func__);
        return ret;
    }

    ret = drsOps->GetUint32(node, "tx_pin", &uart->txPin, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read tx_pin fail!\r\n", __func__);
        return ret;
    }

    ret = drsOps->GetUint32(node, "rx_pin", &uart->rxPin, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read rx_pin fail!\r\n", __func__);
        return ret;
    }

    return HDF_SUCCESS;
}
#endif

static int32_t UartDevBind(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct UartHost *host = NULL;
    struct UartCtrl *uart = NULL;
    struct UartAttribute *attr = NULL;
    HDF_LOGI("%s: Enter", __func__);

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    if (device == NULL) {
#else
    if (device == NULL || device->property == NULL) {
#endif
        HDF_LOGE("%s: device or property is null!.\r\n", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    host = UartHostCreate(device);
    if (host == NULL) {
        HDF_LOGE("%s: UartHostCreate fail!.\r\n", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    // 申请内存空间
    uart = (struct UartCtrl *)OsalMemCalloc(sizeof(struct UartCtrl));
    if (uart == NULL) {
        HDF_LOGE("%s: malloc uart fail!.\r\n", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    // attr
    attr = (struct UartAttribute *)OsalMemCalloc(sizeof(struct UartAttribute));
    if (uart == NULL) {
        HDF_LOGE("%s: malloc attr fail!.\r\n", __func__);
        OsalMemFree(uart);
        return HDF_ERR_MALLOC_FAIL;
    }
    uart->priv = (void *)attr;
#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    ret = ReadUartHcsSource(uart, device->deviceMatchAttr);
#else
    ret = ReadUartHcsSource(uart, device->property);
#endif
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read drs fail:%d.\r\n", __func__, ret);
        OsalMemFree(attr);
        OsalMemFree(uart);
        return ret;
    }

    uart->regBase = UartRegBaseFind(uart);
    host->method = &g_uartOps;
    host->priv = uart;
    host->num = uart->num;
    HDF_LOGI("%s: Bind sucess", __func__);
    return HDF_SUCCESS;
}

static void UsartIrq(void)
{
    char ch;
    char recvCh = 0;
    UINT32 recvSize = 1;
    uint32_t ret;

    while (RESET != usart_interrupt_flag_get(g_regBase, USART_INT_FLAG_RBNE)) {
        ch = usart_data_receive(g_regBase);
        ret = LOS_QueueWriteCopy(g_queue, &ch, 1, 0);
        if (ret == LOS_ERRNO_QUEUE_ISFULL) {
            LOS_QueueReadCopy(g_queue, &recvCh, &recvSize, 0);
            LOS_QueueWriteCopy(g_queue, &ch, 1, 0);
        }
    }
}

static int32_t UartDevInit(struct HdfDeviceObject *device)
{
    int32_t ret = HDF_SUCCESS;
    struct UartHost *host = NULL;
    struct UartCtrl *uart = NULL;

    HDF_LOGI("%s: Enter", __func__);

    if (device == NULL) {
        HDF_LOGE("%s: device is null.\r\n", __func__);
        return HDF_FAILURE;
    }

    host = UartHostFromDevice(device);
    if (host == NULL) {
        HDF_LOGE("%s: host is null.\r\n", __func__);
        return HDF_FAILURE;
    }

    uart = (struct UartCtrl *)host->priv;
    if (uart == NULL) {
        HDF_LOGE("%s: uart is null.\r\n", __func__);
        return HDF_FAILURE;
    }

    g_regBase = uart->regBase;

    LOS_HwiCreate(uart->irqNum, UART_HWI_PRIO, UART_HWI_MODE, (HWI_PROC_FUNC)UsartIrq, NULL);

    ret = OsalSpinInit(&(uart->lock));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: OsalSpinInit fail.\r\n", __func__);
        return HDF_FAILURE;
    }

    OsalSpinLock(&(uart->lock));

    UartEnable(uart, true);

    OsalSpinUnlock(&(uart->lock));
    HDF_LOGI("%s: init uart%d sucess", __func__, uart->num);
    return ret;
}

static void UartDevRelease(struct HdfDeviceObject *device)
{
    struct UartHost *host = NULL;
    struct UartCtrl *uart = NULL;
    HDF_LOGD("%s::enter, deviceObject=%p", __func__, device);
    if (device == NULL) {
        HDF_LOGE("%s: device is null.\r\n", __func__);
        return;
    }

    host = UartHostFromDevice(device);
    if (host == NULL) {
        HDF_LOGE("%s: host is null.\r\n", __func__);
        return;
    }

    uart = (struct UartCtrl *)host->priv;
    if (uart == NULL) {
        HDF_LOGE("%s: uart is null.\r\n", __func__);
        return;
    }

    OsalSpinLock(&(uart->lock));

    LOS_HwiDelete(uart->irqNum, NULL);

    UartEnable(uart, false);

    OsalSpinUnlock(&(uart->lock));

    OsalSpinDestroy(&(uart->lock));

    OsalMemFree(uart->priv);
    OsalMemFree(uart);

    UartHostDestroy(host);
}

struct HdfDriverEntry g_hdf_driver_uart_entry = {
    .moduleVersion = 1,
    .Bind = UartDevBind,
    .Init = UartDevInit,
    .Release = UartDevRelease,
    .moduleName = "GD_UART_MODULE_HDF",
};
HDF_INIT(g_hdf_driver_uart_entry);
