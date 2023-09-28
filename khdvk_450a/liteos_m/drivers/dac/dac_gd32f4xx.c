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
#include "dac_core.h"
#include "gd32f4xx_dac.h"

#define ALIGN_NUM 3
#define MAX_CHANNEL_NUM 2
#define MAX_VAL 4096
#define GPIO_PIN_TOTAL 140
#define GPIO_REG_BASE 0x40020000
#define GPIO_REG_STEP 0x00000400
#define GPIO_BIT_PER_GROUP 16

struct DacCntrl {
    struct DacDevice device;
    uint32_t deviceNum;
    uint32_t validChannel;
    uint32_t outputPinNum;
    uint32_t alignment;
};

static uint32_t g_alignedList[ALIGN_NUM] = {
    DAC_ALIGN_12B_R,
    DAC_ALIGN_12B_L,
    DAC_ALIGN_8B_R,
};

typedef enum {
    PORT_NUM_0 = 0,
    PORT_NUM_1,
    PORT_NUM_2,
} Port;

static inline struct DacCntrl *ToDacDev(struct DacDevice *device)
{
    return (struct DacCntrl *)device;
}

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

static inline rcu_periph_enum ToGpioRcuPeriphNum(uint16_t local)
{
    rcu_periph_enum rcuPeriph;

    rcuPeriph = (rcu_periph_enum)(RCU_REGIDX_BIT(AHB1EN_REG_OFFSET, local / GPIO_BIT_PER_GROUP));

    return rcuPeriph;
}

static int32_t DacDevWrite(struct DacDevice *device, uint32_t channel, uint32_t val)
{
    struct DacCntrl *dacCntrl = NULL;
#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    if (device == NULL)
#else
    if (device == NULL || device->priv == NULL)
#endif
    {
        HDF_LOGE("%s: device or priv is NULL", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    dacCntrl = ToDacDev(device);
    if (dacCntrl == NULL) {
        HDF_LOGE("%s: dacCntrl is NULL", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    if ((dacCntrl->validChannel != 0) || (channel != dacCntrl->validChannel)) {
        HDF_LOGE("%s: channel is invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (val > MAX_VAL) {
        HDF_LOGE("%s, val = (%d) is invalid!", __func__, val);
        return HDF_ERR_INVALID_PARAM;
    }

    dac_data_set(channel, g_alignedList[dacCntrl->alignment], (uint16_t)val);

    return HDF_SUCCESS;
}

static int32_t DacDevStop(struct DacDevice *device)
{
    struct DacCntrl *dacCntrl = NULL;

    if (device == NULL || device->priv == NULL) {
        HDF_LOGE("%s: device or priv is NULL", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    dacCntrl = ToDacDev(device);
    dac_disable(dacCntrl->deviceNum);

    return HDF_SUCCESS;
}

static int32_t DacDevStart(struct DacDevice *device)
{
    struct DacCntrl *dacCntrl = NULL;
#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    if (device == NULL)
#else
    if (device == NULL || device->priv == NULL)
#endif
    {
        HDF_LOGE("%s: device or priv is NULL", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    dacCntrl = ToDacDev(device);

    dac_deinit();
    dac_trigger_disable(dacCntrl->deviceNum);
    dac_wave_mode_config(dacCntrl->deviceNum, DAC_WAVE_DISABLE);
    dac_enable(dacCntrl->deviceNum);

    return HDF_SUCCESS;
}

static const struct DacMethod g_DacDeviceMethod = {
    .write = DacDevWrite,
    .stop = DacDevStop,
    .start = DacDevStart,
};

static void DacDevConfig(uint32_t port, uint32_t outputPinNum)
{
    rcu_periph_clock_enable(RCU_DAC);

    rcu_periph_clock_enable(ToGpioRcuPeriphNum(outputPinNum));
    gpio_mode_set(ToGpioPeriph(outputPinNum), GPIO_MODE_ANALOG, GPIO_PUPD_NONE, ToGpioPin(outputPinNum));
}

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
#define DAC_FIND_CONFIG(node, name)                                                                                    \
    do {                                                                                                               \
        HDF_LOGI("%s: Enter", __func__);                                                                               \
        resource = (struct DacCntrl *)OsalMemCalloc(sizeof(*resource));                                                \
        if (resource == NULL) {                                                                                        \
            HDF_LOGE("%s: Malloc resource fail!", __func__);                                                           \
            result = HDF_ERR_MALLOC_FAIL;                                                                              \
        }                                                                                                              \
        if (HCS_PROP(node, exists) == 1) {                                                                             \
            resource->deviceNum = HCS_PROP(node, deviceNum);                                                           \
            resource->validChannel = HCS_PROP(node, validChannel);                                                     \
            resource->outputPinNum = HCS_PROP(node, outputPinNum);                                                     \
            resource->alignment = HCS_PROP(node, alignment);                                                           \
            result = HDF_SUCCESS;                                                                                      \
        }                                                                                                              \
        if (result != HDF_SUCCESS) {                                                                                   \
            HDF_LOGE("%s: Read drs fail! ret:%d", __func__, result);                                                   \
            OsalMemFree(resource);                                                                                     \
            resource = NULL;                                                                                           \
        }                                                                                                              \
        if (result == HDF_SUCCESS) {                                                                                   \
            DacDevConfig(resource->deviceNum, resource->outputPinNum);                                                 \
            resource->device.priv = NULL;                                                                              \
            resource->device.devNum = resource->deviceNum;                                                             \
            resource->device.chanNum = resource->validChannel;                                                         \
            resource->device.ops = &g_DacDeviceMethod;                                                                 \
            result = DacDeviceAdd(&resource->device);                                                                  \
        }                                                                                                              \
        if (result != HDF_SUCCESS) {                                                                                   \
            HDF_LOGE("%s: add Dac controller failed! ret = %d", __func__, result);                                     \
            if (resource != NULL) {                                                                                    \
                OsalMemFree(resource);                                                                                 \
                resource = NULL;                                                                                       \
            }                                                                                                          \
        }                                                                                                              \
        HDF_LOGI("%s: DAC%d init success", __func__, resource->deviceNum);                                             \
    } while (0)
#define PLATFORM_CONFIG HCS_NODE(HCS_ROOT, platform)
#define PLATFORM_DAC_CONFIG HCS_NODE(HCS_NODE(HCS_ROOT, platform), dac_config)
static int32_t DacDevReadDrs(void)
{
    int32_t result = HDF_FAILURE;
    struct DacCntrl *resource = NULL;
#if HCS_NODE_HAS_PROP(PLATFORM_CONFIG, dac_config)
    HCS_FOREACH_CHILD_VARGS(PLATFORM_DAC_CONFIG, DAC_FIND_CONFIG, 1);
#endif
    if (result != HDF_SUCCESS) {
        HDF_LOGE("resourceNode is NULL\r\n");
    }
    return result;
}
#else
static int32_t DacDevReadDrs(struct DacCntrl *resource, const struct DeviceResourceNode *node)
{
    int32_t ret;
    struct DeviceResourceIface *drsOps = NULL;

    drsOps = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (drsOps == NULL || drsOps->GetUint32 == NULL) {
        HDF_LOGE("%s: invalid drs ops fail!", __func__);
        return HDF_FAILURE;
    }

    ret = drsOps->GetUint32(node, "deviceNum", &resource->deviceNum, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read deviceNum fail!", __func__);
        return ret;
    }

    ret = drsOps->GetUint32(node, "validChannel", &resource->validChannel, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read validChannel fail!", __func__);
        return ret;
    }

    ret = drsOps->GetUint32(node, "outputPinNum", &resource->outputPinNum, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read validChannel fail!", __func__);
        return ret;
    }

    ret = drsOps->GetUint32(node, "alignment", &resource->alignment, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read alignment fail!", __func__);
        return ret;
    }

    return HDF_SUCCESS;
}
#endif

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
static int32_t DacDevParseAndInit(struct HdfDeviceObject *device, const char *deviceMatchAttr)
{
    (void)device;
    int32_t ret;
    if (device == NULL) {
        HDF_LOGE("%s: param is NULL\r\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = DacDevReadDrs();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: dac device init fail! ret:%d", __func__, ret);
        return ret;
    }

    return HDF_SUCCESS;
}
#else
static int32_t DacDevParseAndInit(struct HdfDeviceObject *device, const struct DeviceResourceNode *node)
{
    (void)device;
    int32_t ret;
    struct DacCntrl *dacCntrl = NULL;

    if (device == NULL || device->property == NULL || node == NULL) {
        HDF_LOGE("%s: param is NULL\r\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%s: Enter", __func__);
    dacCntrl = (struct DacCntrl *)OsalMemCalloc(sizeof(*dacCntrl));
    if (dacCntrl == NULL) {
        HDF_LOGE("%s: Malloc dacCntrl fail!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    ret = DacDevReadDrs(dacCntrl, node);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Read drs fail! ret:%d", __func__, ret);
        OsalMemFree(dacCntrl);
        dacCntrl = NULL;
        return ret;
    }

    DacDevConfig(dacCntrl->validChannel, dacCntrl->outputPinNum);

    dacCntrl->device.priv = (void *)node;
    dacCntrl->device.devNum = dacCntrl->deviceNum;
    dacCntrl->device.chanNum = dacCntrl->validChannel;
    dacCntrl->device.ops = &g_DacDeviceMethod;

    ret = DacDeviceAdd(&dacCntrl->device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: add Dac controller failed! ret = %d", __func__, ret);
        if (dacCntrl != NULL) {
            OsalMemFree(dacCntrl);
            dacCntrl = NULL;
        }
        return ret;
    }
    HDF_LOGI("%s: DAC%d init success", __func__, dacCntrl->deviceNum);
    return HDF_SUCCESS;
}
#endif

static int32_t DacDevInit(struct HdfDeviceObject *device)
{
    int32_t ret;
    const struct DeviceResourceNode *childNode = NULL;
#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    if (device == NULL)
#else
    if (device == NULL || device->property == NULL)
#endif
    {
        HDF_LOGE("%s: device or property is NULL", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    ret = HDF_SUCCESS;

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    ret = DacDevParseAndInit(device, device->deviceMatchAttr);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
#else
    DEV_RES_NODE_FOR_EACH_CHILD_NODE(device->property, childNode)
    {
        ret = DacDevParseAndInit(device, childNode);
        if (ret != HDF_SUCCESS) {
            break;
        }
    }
#endif
    return ret;
}

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO

#else
static void DacDevRemoveByNode(const struct DeviceResourceNode *node)
{
    int32_t ret;
    int16_t devNum;

    struct DacDevice *device = NULL;
    struct DacCntrl *dacCntrl = NULL;
    struct DeviceResourceIface *drsOps = NULL;

    drsOps = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (drsOps == NULL || drsOps->GetUint32 == NULL) {
        HDF_LOGE("%s: invalid drs ops fail!", __func__);
        return;
    }

    ret = drsOps->GetUint16(node, "devNum", (uint16_t *)&devNum, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read devNum fail!", __func__);
        return;
    }

    device = DacDeviceGet(devNum);
    if (device != NULL && device->priv == node) {
        DacDevicePut(device);
        DacDeviceRemove(device);
        dacCntrl = (struct DacCntrl *)device;
        OsalMemFree(dacCntrl);
    }

    return;
}
#endif

static void DacDevRelease(struct HdfDeviceObject *device)
{
#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO

#else
    const struct DeviceResourceNode *childNode = NULL;
    if (device == NULL || device->property == NULL) {
        HDF_LOGE("%s: device or property is NULL", __func__);
        return;
    }

    DEV_RES_NODE_FOR_EACH_CHILD_NODE(device->property, childNode)
    {
        DacDevRemoveByNode(childNode);
    }
#endif
}

static struct HdfDriverEntry g_dacDriverEntry = {
    .moduleVersion = 1,
    .Init = DacDevInit,
    .Release = DacDevRelease,
    .moduleName = "GD_DAC_MODULE_HDF",
};

HDF_INIT(g_dacDriverEntry);