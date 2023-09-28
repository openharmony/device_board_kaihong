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

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
#include "hcs_macro.h"
#include "hdf_config_macro.h"
#else
#include "device_resource_if.h"
#endif
#include "hdf_device_desc.h"
#include "hdf_log.h"
#include "i2c_core.h"
#include "i2c_if.h"
#include "osal_mem.h"
#include "osal_mutex.h"
#include "osal_time.h"

#include "gd32f4xx.h"
#include "gd32f4xx_i2c.h"

#define HDF_LOG_TAG i2c_gd32f4xx

#define DELAY_MS 1
#define TIMEOUT_MS 0xfff

#define GPIO_PIN_TOTAL 140
#define GPIO_REG_STEP 0x00000400
#define GPIO_REG_BASE 0x40020000
#define GPIO_REG_STEP 0x00000400
#define GPIO_BIT_PER_GROUP 16

#define I2C_BUS_0 0
#define I2C_BUS_1 1
#define I2C_BUS_2 2
#define I2C_FLAG_WRITE 0
#define MESSAGE_LAST_SECOND 2
#define MESSAGE_LAST_THIRD 3
#define US_TO_MS_CONV (1000)

static void I2cMDelay(uint32_t timeOut)
{
    OsalTimespec startTick = {0, 0};
    OsalTimespec endTick = {0, 0};
    OsalTimespec diffTick = {0, 0};

    OsalGetTime(&startTick);
    do {
        OsalMSleep(1);
        /* time out break */
        OsalGetTime(&endTick);
        OsalDiffTime(&startTick, &endTick, &diffTick);
        if ((uint32_t)(diffTick.sec * US_TO_MS_CONV + diffTick.usec / US_TO_MS_CONV) >= timeOut) {
            break;
        }
    } while (true);
}

static inline int32_t I2cTimeOutCheck(void)
{
    static int16_t iTmp = 0;
    I2cMDelay(DELAY_MS);
    iTmp++;
    if (iTmp > TIMEOUT_MS) {
        iTmp = 0;
        return HDF_ERR_TIMEOUT;
    }
    return HDF_SUCCESS;
}

struct I2cDevResource {
    uint16_t bus;
    uint16_t scl;
    uint16_t sda;
    uint32_t speed;
    uint32_t regBasePhy;
    uint32_t rcuGpio;
    uint32_t rcuI2c;
    struct OsalMutex mutex;
};

static inline uint32_t ToGpioPeriph(uint16_t local)
{
    uint32_t gpioPeriph = 0;

    gpioPeriph = GPIO_REG_BASE + (local / GPIO_BIT_PER_GROUP) * GPIO_REG_STEP;

    return gpioPeriph;
}

static inline uint32_t ToGpioPin(uint16_t local)
{
    uint32_t pinNum = 0;

    pinNum = local % GPIO_BIT_PER_GROUP;

    return (BIT(pinNum));
}

static inline uint32_t ToGpioRcu(uint16_t local)
{
    uint32_t Periph = 0;

    Periph = local / GPIO_BIT_PER_GROUP;

    return (RCU_GPIOA + Periph);
}

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
#define I2C_FIND_CONFIG(node, name, resource)                                                                          \
    do {                                                                                                               \
        if (strcmp(HCS_PROP(node, match_attr), name) == 0) {                                                           \
            resource->bus = HCS_PROP(node, bus);                                                                       \
            resource->speed = HCS_PROP(node, speed);                                                                   \
            resource->scl = HCS_PROP(node, scl);                                                                       \
            resource->sda = HCS_PROP(node, sda);                                                                       \
            result = HDF_SUCCESS;                                                                                      \
        }                                                                                                              \
    } while (0)
#define PLATFORM_CONFIG HCS_NODE(HCS_ROOT, platform)
#define PLATFORM_I2C_CONFIG HCS_NODE(HCS_NODE(HCS_ROOT, platform), i2c_config)
static int32_t GetI2cDeviceResource(struct I2cDevResource *i2cResource, const char *deviceMatchAttr)
{
    int32_t result = HDF_FAILURE;
    struct I2cDevResource *resource = NULL;
    if (i2cResource == NULL || deviceMatchAttr == NULL) {
        HDF_LOGE("device or deviceMatchAttr is NULL\r\n");
        return HDF_ERR_INVALID_PARAM;
    }
    resource = i2cResource;
#if HCS_NODE_HAS_PROP(PLATFORM_CONFIG, i2c_config)
    HCS_FOREACH_CHILD_VARGS(PLATFORM_I2C_CONFIG, I2C_FIND_CONFIG, deviceMatchAttr, resource);
#endif
    if (result != HDF_SUCCESS) {
        HDF_LOGE("resourceNode %s is NULL\r\n", deviceMatchAttr);
    }

    return result;
}
#else
static int32_t GetI2cDeviceResource(struct I2cDevResource *i2cResource, const struct DeviceResourceNode *resourceNode)
{
    if (i2cResource == NULL || resourceNode == NULL) {
        HDF_LOGE("[%s]: param is NULL\r\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct DeviceResourceIface *ops = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (ops == NULL || ops->GetUint32 == NULL || ops->GetUint16 == NULL || ops->GetUint16Array == NULL) {
        HDF_LOGE("DeviceResourceIface is invalid\r\n");
        return HDF_ERR_INVALID_OBJECT;
    }

    if (ops->GetUint32(resourceNode, "speed", &i2cResource->speed, 0) != HDF_SUCCESS) {
        HDF_LOGE("%s: read i2c speed fail!", __func__);
        return HDF_FAILURE;
    }

    if (ops->GetUint16(resourceNode, "bus", &i2cResource->bus, 0) != HDF_SUCCESS) {
        HDF_LOGE("%s: read i2c bus fail!", __func__);
        return HDF_FAILURE;
    }

    if (ops->GetUint16(resourceNode, "scl", &i2cResource->scl, 0) != HDF_SUCCESS) {
        HDF_LOGE("%s: read i2c scl fail!", __func__);
        return HDF_FAILURE;
    }

    if (ops->GetUint16(resourceNode, "sda", &i2cResource->sda, 0) != HDF_SUCCESS) {
        HDF_LOGE("%s: read i2c sda fail!", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}
#endif

static uint32_t I2cParaCheck(struct I2cDevResource *i2cResource)
{
    if (i2cResource->bus != I2C_BUS_0 && i2cResource->bus != I2C_BUS_1 && i2cResource->bus != I2C_BUS_2) {
        HDF_LOGE("%s: I2c(%d) bus is invalid!", __func__, i2cResource->bus);
        return HDF_ERR_INVALID_PARAM;
    }

    if (i2cResource->scl > GPIO_PIN_TOTAL || i2cResource->sda > GPIO_PIN_TOTAL) {
        HDF_LOGE("%s: I2c(%d) gpio port is invalid!", __func__, i2cResource->bus);
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

static void I2cConfigCompletion(struct I2cDevResource *i2cResource)
{
    switch (i2cResource->bus) {
        case I2C_BUS_0:
            i2cResource->regBasePhy = I2C0;
            i2cResource->rcuGpio = ToGpioRcu(i2cResource->scl);
            i2cResource->rcuI2c = RCU_I2C0;
            break;
        case I2C_BUS_1:
            i2cResource->regBasePhy = I2C1;
            i2cResource->rcuGpio = ToGpioRcu(i2cResource->scl);
            i2cResource->rcuI2c = RCU_I2C1;
            break;
        case I2C_BUS_2:
            i2cResource->regBasePhy = I2C2;
            i2cResource->rcuGpio = ToGpioRcu(i2cResource->scl);
            i2cResource->rcuI2c = RCU_I2C2;
            break;
        default:
            break;
    }

    return;
}

static int32_t AttachI2cDevice(struct I2cCntlr *host, const struct HdfDeviceObject *device)
{
    int32_t ret = HDF_FAILURE;

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    if (device == NULL || host == NULL) {
#else
    if (device == NULL || device->property == NULL || host == NULL) {
#endif
        HDF_LOGE("[%s]: param is NULL\r\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct I2cDevResource *i2cResource = (struct I2cDevResource *)OsalMemCalloc(sizeof(struct I2cDevResource));
    if (i2cResource == NULL) {
        HDF_LOGE("[%s]: OsalMemCalloc I2cDevResource fail\r\n", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    ret = GetI2cDeviceResource(i2cResource, device->deviceMatchAttr);
#else
    ret = GetI2cDeviceResource(i2cResource, device->property);
#endif
    if (ret != HDF_SUCCESS || I2cParaCheck(i2cResource) != HDF_SUCCESS) {
        OsalMemFree(i2cResource);
        return HDF_FAILURE;
    }
    I2cConfigCompletion(i2cResource);

    host->busId = i2cResource->bus;
    host->priv = i2cResource;

    return HDF_SUCCESS;
}

static void I2cGpioConfig(struct I2cDevResource *i2cResource)
{
    /* enable GPIOB clock */
    rcu_periph_clock_enable(i2cResource->rcuGpio);
    /* enable I2C0 clock */
    rcu_periph_clock_enable(i2cResource->rcuI2c);

    /* connect PB6 to I2C0_SCL */
    gpio_af_set(ToGpioPeriph(i2cResource->scl), GPIO_AF_4, ToGpioPin(i2cResource->scl));
    /* connect PB7 to I2C0_SDA */
    gpio_af_set(ToGpioPeriph(i2cResource->sda), GPIO_AF_4, ToGpioPin(i2cResource->sda));

    gpio_mode_set(ToGpioPeriph(i2cResource->scl), GPIO_MODE_AF, GPIO_PUPD_PULLUP, ToGpioPin(i2cResource->scl));
    gpio_output_options_set(ToGpioPeriph(i2cResource->scl), GPIO_OTYPE_OD, GPIO_OSPEED_50MHZ,
                            ToGpioPin(i2cResource->scl));
    gpio_mode_set(ToGpioPeriph(i2cResource->sda), GPIO_MODE_AF, GPIO_PUPD_PULLUP, ToGpioPin(i2cResource->sda));
    gpio_output_options_set(ToGpioPeriph(i2cResource->sda), GPIO_OTYPE_OD, GPIO_OSPEED_50MHZ,
                            ToGpioPin(i2cResource->sda));
}

static void I2cConfig(struct I2cDevResource *i2cResource)
{
    /* configure I2C clock */
    i2c_clock_config(i2cResource->regBasePhy, i2cResource->speed, I2C_DTCY_2);
    /* enable I2C0 */
    i2c_enable(i2cResource->regBasePhy);
    /* enable acknowledge */
    i2c_ack_config(i2cResource->regBasePhy, I2C_ACK_ENABLE);
}

static uint32_t Gd32f4xxI2cWrite(struct I2cDevResource *device, struct I2cMsg *msg)
{
    uint16_t bufIdx = 0;
    uint8_t val;
    /* 等待总线空闲 */
    while (i2c_flag_get(device->regBasePhy, I2C_FLAG_I2CBSY) && !I2cTimeOutCheck()) { }
    if (!(msg->flags & I2C_FLAG_NO_START)) {
        /* 发送start信号 */
        i2c_start_on_bus(device->regBasePhy);
        while (!i2c_flag_get(device->regBasePhy, I2C_FLAG_SBSEND) && !I2cTimeOutCheck()) { }
    }
    /* 设置从机地址操作 */
    i2c_master_addressing(device->regBasePhy, msg->addr, I2C_TRANSMITTER);
    /* 等待从机地址发送标志 */
    while (!i2c_flag_get(device->regBasePhy, I2C_FLAG_ADDSEND) && !I2cTimeOutCheck()) { }
    /* 清除从机地址发送标志 */
    i2c_flag_clear(device->regBasePhy, I2C_FLAG_ADDSEND);
    while (!i2c_flag_get(device->regBasePhy, I2C_FLAG_TBE) && !I2cTimeOutCheck()) { }
    while (bufIdx < msg->len) {
        val = msg->buf[bufIdx];
        i2c_data_transmit(device->regBasePhy, val);
        bufIdx++;
        /* 等待数据寄存器空 */
        while (!i2c_flag_get(device->regBasePhy, I2C_FLAG_BTC) && !I2cTimeOutCheck()) { }
    }

    if (msg->flags & I2C_FLAG_STOP) {
        /* 发送stop信号 */
        i2c_stop_on_bus(device->regBasePhy);
        while ((I2C_CTL0(device->regBasePhy) & I2C_CTL0_STOP)  && !I2cTimeOutCheck()) { }
    }

    return HDF_SUCCESS;
}

static int Gd32f4xxI2cRead(struct I2cDevResource *device, struct I2cMsg *msg)
{
    uint16_t bufIdx = 0;
    uint8_t val;
    /* 等待总线空闲 */
    while (i2c_flag_get(device->regBasePhy, I2C_FLAG_I2CBSY) && !I2cTimeOutCheck()) { }
    if (msg->len == MESSAGE_LAST_SECOND) {
        /* 接收数据长度等于2时,首先将POAP置1 */
        i2c_ackpos_config(device->regBasePhy, I2C_ACKPOS_NEXT);
    }

    if (!(msg->flags & I2C_FLAG_NO_START)) {
        i2c_start_on_bus(device->regBasePhy);
        /* 等待SBSEND标志 */
        while (!i2c_flag_get(device->regBasePhy, I2C_FLAG_SBSEND) && !I2cTimeOutCheck()) { }
    }

    i2c_master_addressing(device->regBasePhy, msg->addr, I2C_RECEIVER);
    if (msg->len < MESSAGE_LAST_THIRD) {
        /* 接收数据长度小于3时,需先清除ACK */
        i2c_ack_config(device->regBasePhy, I2C_ACK_DISABLE);
    }
    /* 等待从机地址发送标志 */
    while (!i2c_flag_get(device->regBasePhy, I2C_FLAG_ADDSEND) && !I2cTimeOutCheck()) { }
    /* 清除从机地址发送标志 */
    i2c_flag_clear(device->regBasePhy, I2C_FLAG_ADDSEND);
    while (bufIdx < msg->len) {
        /* 等待倒数第二个数据被接收到寄存器 */
        if (msg->len - bufIdx == MESSAGE_LAST_THIRD) {
            while (!i2c_flag_get(device->regBasePhy, I2C_FLAG_BTC) && !I2cTimeOutCheck()) { }
            /* 清除ACK */
            i2c_ack_config(device->regBasePhy, I2C_ACK_DISABLE);
        }
        if (msg->len - bufIdx == MESSAGE_LAST_SECOND) {
            while (!i2c_flag_get(device->regBasePhy, I2C_FLAG_BTC) && !I2cTimeOutCheck()) { }
            if (msg->flags & I2C_FLAG_STOP) {
                i2c_stop_on_bus(device->regBasePhy);
            }
        }
        /* 等待RBNE位被设置 */
        if (i2c_flag_get(device->regBasePhy, I2C_FLAG_RBNE)) {
            /* 从I2C总线读取数据 */
            val = i2c_data_receive(device->regBasePhy);
            msg->buf[bufIdx] = val;
            bufIdx++;
        }
    }

    if (msg->flags & I2C_FLAG_STOP) {
        while ((I2C_CTL0(device->regBasePhy) & I2C_CTL0_STOP) && !I2cTimeOutCheck()) { }
    }

    i2c_ack_config(device->regBasePhy, I2C_ACK_ENABLE);
    return HDF_SUCCESS;
}

static int32_t I2cDataTransfer(struct I2cCntlr *cntlr, struct I2cMsg *msgs, int16_t count)
{
    int32_t i = 0;
    int32_t ret;

    if (cntlr == NULL || msgs == NULL || cntlr->priv == NULL) {
        HDF_LOGE("[%s]: I2cDataTransfer param is NULL!\r\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (count <= 0) {
        HDF_LOGE("[%s]: I2c msg count err\r\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct I2cDevResource *device = (struct I2cDevResource *)cntlr->priv;
    if (device == NULL) {
        HDF_LOGE("%s: I2c device is NULL\r\n", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    struct I2cMsg *msg = NULL;
    if (HDF_SUCCESS != OsalMutexLock(&device->mutex)) {
        HDF_LOGE("[%s]: OsalMutexLock fail\r\n", __func__);
        return HDF_ERR_TIMEOUT;
    }

    for (i = 0; i < count; i++) {
        msg = &msgs[i];
        if (msg->flags & (I2C_FLAG_ADDR_10BIT | I2C_FLAG_READ_NO_ACK | I2C_FLAG_IGNORE_NO_ACK | I2C_FLAG_NO_START)) {
            HDF_LOGE("%s: flag %d is not support", __func__, msg->flags);
        } else if (msg->flags == (I2C_FLAG_READ | I2C_FLAG_STOP)) {
            ret = Gd32f4xxI2cRead(device, msg);
        } else if (msg->flags == I2C_FLAG_STOP) {
            ret = Gd32f4xxI2cWrite(device, msg);
        }
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: I2c transfer fail!,flag :%d", __func__, msg->flags);
            break;
        }
    }
    OsalMutexUnlock(&device->mutex);

    return i;
}

static const struct I2cMethod g_I2cMethod = {
    .transfer = I2cDataTransfer,
};

static int32_t I2cDriverBind(struct HdfDeviceObject *device)
{
    if (device == NULL) {
        HDF_LOGE("[%s]: I2c device is NULL\r\n", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static void I2cDriverRelease(struct HdfDeviceObject *device)
{
    struct I2cCntlr *i2cCntrl = NULL;
    struct I2cDevResource *i2cDevice = NULL;

    HDF_LOGI("%s: enter", __func__);

    if (device == NULL) {
        HDF_LOGE("%s: device is NULL", __func__);
        return;
    }

    i2cCntrl = device->priv;
    if (i2cCntrl == NULL || i2cCntrl->priv == NULL) {
        HDF_LOGE("%s: i2cCntrl is NULL\r\n", __func__);
        return;
    }
    i2cCntrl->ops = NULL;

    i2cDevice = (struct I2cDevResource *)i2cCntrl->priv;

    if (i2cDevice != NULL) {
        OsalMutexDestroy(&i2cDevice->mutex);
        OsalMemFree(i2cDevice);
    }
    OsalMemFree(i2cCntrl);

    return;
}

static int32_t I2cDriverInit(struct HdfDeviceObject *device)
{
    int32_t ret = HDF_FAILURE;
    struct I2cCntlr *host = NULL;

    if (device == NULL) {
        HDF_LOGE("%s: device or property is NULL", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    HDF_LOGI("%s: Enter", __func__);

    host = (struct I2cCntlr *)OsalMemCalloc(sizeof(struct I2cCntlr));
    if (host == NULL) {
        HDF_LOGE("[%s]: malloc host is NULL\r\n", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    host->ops = &g_I2cMethod;
    device->priv = (void *)host;

    ret = AttachI2cDevice(host, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("[%s]: AttachI2cDevice error, ret = %d\r\n", __func__, ret);
        I2cDriverRelease(device);
        return HDF_DEV_ERR_ATTACHDEV_FAIL;
    }

    /* configure GPIO */
    I2cGpioConfig((struct I2cDevResource *)host->priv);

    /* configure I2C */
    I2cConfig((struct I2cDevResource *)host->priv);

    ret = I2cCntlrAdd(host);
    if (ret != HDF_SUCCESS) {
        I2cDriverRelease(device);
        return HDF_FAILURE;
    }
    HDF_LOGI("%s: i2c%d init success", __func__, host->busId);
    return HDF_SUCCESS;
}

struct HdfDriverEntry g_i2cDriverEntry = {
    .moduleVersion = 1,
    .Bind = I2cDriverBind,
    .Init = I2cDriverInit,
    .Release = I2cDriverRelease,
    .moduleName = "GD_I2C_MODULE_HDF",
};
HDF_INIT(g_i2cDriverEntry);
