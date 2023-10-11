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
#include "adc_core.h"
#include "osal_mem.h"
#include "osal_time.h"
#include "gd32f4xx_adc.h"

#define HDF_LOG_TAG GD_ADC_MODULE_HDF

#define CHANNEL_GROUP 0U
#define CHANNEL_LENGTH 1U
#define TIME_OUT 5000
#define BEGIN_TIMES 0
#define GPIO_REG_BASE 0x40020000
#define GPIO_BIT_PER_GROUP 16
#define GPIO_REG_STEP 0x400
#define DELAY_TIME_MS 1
#define ADC_REG_STEP 0x100

struct AdcDeviceCntlr {
    struct AdcDevice device;
    uint32_t regBasePhy;
    uint32_t deviceNum;
    uint8_t channelNums;
    uint8_t validChannels[16];
    uint32_t outputPinNums[16];
    uint8_t currentChannel;
    uint32_t currentPinNum;
};
#define US_TO_MS_CONV (1000)

static void AdcMDelay(uint32_t timeOut)
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
static uint32_t g_times = BEGIN_TIMES;

static inline uint32_t ToGpioPeriph(uint32_t local)
{
    uint32_t gpioPeriph = 0;

    gpioPeriph = GPIO_REG_BASE + (local / GPIO_BIT_PER_GROUP) * GPIO_REG_STEP;

    return gpioPeriph;
}

static inline uint32_t ToGpioPin(uint32_t local)
{
    uint32_t pinNum = 0;

    pinNum = local % GPIO_BIT_PER_GROUP;

    return (BIT(pinNum));
}

static inline uint32_t Adc(uint32_t devNum)
{
    return ADC0 + devNum * ADC_REG_STEP;
}

static inline uint32_t RcuAdc(uint32_t devNum)
{
    return RCU_ADC0 + devNum;
}

static uint16_t AdcGetData(struct AdcDeviceCntlr *adc)
{
    if (adc == NULL) {
        HDF_LOGE("%s %d: invalid param adc!", __func__, __LINE__);
        return 0;
    }
    /* enable GPIOX clock */
    rcu_periph_clock_enable(ToGpioPeriph(adc->currentPinNum));
    /* config the GPIO as analog mode */
    gpio_mode_set(ToGpioPeriph(adc->currentPinNum), GPIO_MODE_ANALOG, GPIO_PUPD_NONE, ToGpioPin(adc->currentPinNum));
    /* ADC regular channel config */
    adc_regular_channel_config(adc->regBasePhy, CHANNEL_GROUP, adc->currentChannel, ADC_SAMPLETIME_480);
    /* ADC software trigger enable */
    adc_software_trigger_enable(adc->regBasePhy, ADC_REGULAR_CHANNEL);
    g_times = BEGIN_TIMES;
    /* wait the end of conversion flag */
    while (!adc_flag_get(adc->regBasePhy, ADC_FLAG_EOC) && g_times < TIME_OUT) {
        g_times++;
    };
    /* clear the end of conversion flag */
    adc_flag_clear(adc->regBasePhy, ADC_FLAG_EOC);
    /* return regular channel sample value */
    return adc_regular_data_read(adc->regBasePhy);
}

static int32_t AdcDevRead(struct AdcDevice *device, uint8_t channel, uint32_t *val)
{
    int ret = HDF_FAILURE;
    struct AdcDeviceCntlr *adc = NULL;

    if (device == NULL) {
        HDF_LOGE("%s %d: device is null!", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    adc = (struct AdcDeviceCntlr *)device;
    for (int i = 0; i < adc->channelNums; i++) {
        if (channel == adc->validChannels[i]) {
            adc->currentChannel = adc->validChannels[i];
            adc->currentPinNum = adc->outputPinNums[i];
            ret = HDF_SUCCESS;
            break;
        }
    }
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s %d: invalid channel number:%d", __func__, __LINE__, channel);
        return HDF_ERR_INVALID_PARAM;
    }

    *val = (uint32_t)AdcGetData(adc);
    if (g_times == TIME_OUT) {
        HDF_LOGE("%s %d:data read out of time!", __func__, __LINE__);
        return HDF_ERR_TIMEOUT;
    }

    return HDF_SUCCESS;
}

static int32_t AdcDevStop(struct AdcDevice *device)
{
    if (device == NULL) {
        HDF_LOGE("%s %d: device is null!", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    /* reset ADC */
    adc_deinit();

    return HDF_SUCCESS;
}

static int32_t AdcDevStart(struct AdcDevice *device)
{
    if (device == NULL) {
        HDF_LOGE("%s %d: device is null!", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct AdcDeviceCntlr *adc = NULL;
    adc = (struct AdcDeviceCntlr *)device;
    /* enable ADC clock */
    rcu_periph_clock_enable(RcuAdc(adc->deviceNum));
    /* config ADC clock */
    adc_clock_config(ADC_ADCCK_PCLK2_DIV8);
    /* reset ADC */
    adc_deinit();
    /* ADC mode config */
    adc_sync_mode_config(ADC_SYNC_MODE_INDEPENDENT);
    /* ADC contineous function disable */
    adc_special_function_config(adc->regBasePhy, ADC_CONTINUOUS_MODE, DISABLE);
    /* ADC scan mode disable */
    adc_special_function_config(adc->regBasePhy, ADC_SCAN_MODE, DISABLE);
    /* ADC data alignment config */
    adc_data_alignment_config(adc->regBasePhy, ADC_DATAALIGN_RIGHT);
    /* ADC channel length config */
    adc_channel_length_config(adc->regBasePhy, ADC_REGULAR_CHANNEL, CHANNEL_LENGTH);
    /* ADC trigger config */
    adc_external_trigger_source_config(adc->regBasePhy, ADC_REGULAR_CHANNEL, ADC_EXTTRIG_REGULAR_T0_CH0);
    adc_external_trigger_config(adc->regBasePhy, ADC_REGULAR_CHANNEL, EXTERNAL_TRIGGER_DISABLE);
    /* enable ADC interface */
    adc_enable(adc->regBasePhy);
    AdcMDelay(DELAY_TIME_MS);
    /* ADC calibration and reset calibration */
    adc_calibration_enable(adc->regBasePhy);
    return HDF_SUCCESS;
}

static const struct AdcMethod g_method = {
    .read = AdcDevRead,
    .stop = AdcDevStop,
    .start = AdcDevStart,
};

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
#define ADC_FIND_CONFIG(node, name, adc)                                                                               \
    do {                                                                                                               \
        if (strcmp(HCS_PROP(node, match_attr), name) == 0) {                                                           \
            uint32_t deviceNum = HCS_PROP(node, deviceNum);                                                            \
            uint8_t channelNums = HCS_PROP(node, channelNums);                                                         \
            uint8_t validChannels[] = HCS_ARRAYS(HCS_NODE(node, validChannels));                                       \
            uint32_t outputPinNums[] = HCS_ARRAYS(HCS_NODE(node, outputPinNums));                                      \
            adc->deviceNum = deviceNum;                                                                                \
            adc->channelNums = channelNums;                                                                            \
            for (int i = 0; i < channelNums; i++) {                                                                    \
                adc->validChannels[i] = validChannels[i];                                                              \
                adc->outputPinNums[i] = outputPinNums[i];                                                              \
            }                                                                                                          \
            result = HDF_SUCCESS;                                                                                      \
        }                                                                                                              \
    } while (0)
#define PLATFORM_CONFIG HCS_NODE(HCS_ROOT, platform)
#define PLATFORM_ADC_CONFIG HCS_NODE(HCS_NODE(HCS_ROOT, platform), adc_config)
static int32_t AdcReadDrs(struct AdcDeviceCntlr *adc, const char *deviceMatchAttr)
{
    int32_t result = HDF_FAILURE;
    if (adc == NULL || deviceMatchAttr == NULL) {
        HDF_LOGE("%s %d: device or deviceMatchAttr is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

#if HCS_NODE_HAS_PROP(PLATFORM_CONFIG, adc_config)
    HCS_FOREACH_CHILD_VARGS(PLATFORM_ADC_CONFIG, ADC_FIND_CONFIG, deviceMatchAttr, adc);
#endif
    if (result != HDF_SUCCESS) {
        HDF_LOGE("resourceNode %s is NULL\r\n", deviceMatchAttr);
    }
    return result;
}
#else
static int32_t AdcReadDrs(struct AdcDeviceCntlr *adc, struct DeviceResourceNode *node)
{
    int32_t ret = HDF_SUCCESS;
    struct DeviceResourceIface *drsOps = NULL;
    if (adc == NULL || node == NULL) {
        HDF_LOGE("%s %d: AdcDeviceCntlr or DeviceResourceNode is null!", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    drsOps = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (drsOps == NULL || drsOps->GetUint32 == NULL) {
        HDF_LOGE("%s %d: invalid drs ops fail!", __func__, __LINE__);
        return HDF_FAILURE;
    }

    ret = drsOps->GetUint32(node, "deviceNum", &adc->deviceNum, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s %d: read deviceNum fail!", __func__, __LINE__);
        return ret;
    }

    ret = drsOps->GetUint8(node, "channelNums", &adc->channelNums, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s %d: read channelNums fail!", __func__, __LINE__);
        return ret;
    }

    ret = drsOps->GetUint8Array(node, "validChannels", adc->validChannels, adc->channelNums, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s %d: read validChannels fail!", __func__, __LINE__);
        return ret;
    }

    ret = drsOps->GetUint32Array(node, "outputPinNums", &adc->outputPinNums, adc->channelNums, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s %d: read outputPinNums fail!", __func__, __LINE__);
        return ret;
    }
    adc->currentChannel = 0;
    adc->currentPinNum = 0;
    return HDF_SUCCESS;
}
#endif

static int32_t AdcParseInit(struct HdfDeviceObject *device)
{
    int32_t ret = HDF_SUCCESS;
    struct AdcDeviceCntlr *adc = NULL;
    adc = (struct AdcDeviceCntlr *)OsalMemCalloc(sizeof(*adc));
    do {
        if (adc == NULL) {
            HDF_LOGE("%s %d: malloc AdcDeviceCntlr failed!", __func__, __LINE__);
            ret = HDF_ERR_MALLOC_FAIL;
            break;
        }
        HDF_LOGI("%s: Enter", __func__);

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
        if (device == NULL || device->deviceMatchAttr == NULL) {
            HDF_LOGE("%s %d: device or device->deviceMatchAttr is null !", __func__, __LINE__);
            ret = HDF_ERR_INVALID_OBJECT;
            break;
        }
        ret = AdcReadDrs(adc, device->deviceMatchAttr);
#else
        if (device == NULL || device->property == NULL) {
            HDF_LOGE("%s %d: device or device->property is null !", __func__, __LINE__);
            ret = HDF_ERR_INVALID_OBJECT;
            break;
        }
        ret = AdcReadDrs(adc, device->property);
#endif
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s %d: adc read failed!", __func__, __LINE__);
            break;
        }
        adc->regBasePhy = Adc(adc->deviceNum);
        adc->device.priv = (void *)adc;
        adc->device.devNum = adc->deviceNum;
        adc->device.ops = &g_method;
        ret = AdcDeviceAdd(&adc->device);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s %d: adc device add failed!", __func__, __LINE__);
            break;
        }
        HDF_LOGI("%s: adc%d init success", __func__, adc->deviceNum);
        return HDF_SUCCESS;
    } while (0);

    if (adc != NULL) {
        AdcDeviceRemove(&adc->device);
        OsalMemFree(adc);
        OsalMemFree(adc->validChannels);
        OsalMemFree(adc->outputPinNums);
    }
    return ret;
}

static int32_t AdcInit(struct HdfDeviceObject *device)
{
    int32_t ret;
    if (device == NULL) {
        HDF_LOGE("%s %d: device node is null!", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = AdcParseInit(device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s %d: adc parse init failed!", __func__, __LINE__);
    }
    return ret;
}

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
static void AdcRemoveByObject(const struct HdfDeviceObject *device)
{
    struct AdcDevice *adcDev = NULL;
    struct AdcDeviceCntlr *adc = NULL;

    if (device == NULL) {
        HDF_LOGE("%s %d: device is NULL", __func__, __LINE__);
        return;
    }

    adcDev = device->priv;
    if (adcDev == NULL) {
        HDF_LOGE("%s %d: device priv is NULL\r\n", __func__, __LINE__);
        return;
    }

    AdcDevicePut(adcDev);
    AdcDeviceRemove(adcDev);
    adc = (struct AdcDeviceCntlr *)adcDev;
    OsalMemFree(adcDev);
}
#else
static void AdcRemoveByNode(const struct DeviceResourceNode *node)
{
    int32_t ret;
    int32_t deviceNum;
    struct AdcDevice *device = NULL;
    struct AdcDeviceCntlr *adc = NULL;
    struct DeviceResourceIface *drsOps = NULL;

    drsOps = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);

    ret = drsOps->GetUint32(node, "deviceNum", (uint32_t *)&deviceNum, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s %d: get resouce failed!", __func__, __LINE__);
        return ret;
    }
    device = AdcDeviceGet(deviceNum);
    if (device != NULL && device->priv == node) {
        AdcDevicePut(device);
        AdcDeviceRemove(device);
        adc = (struct AdcDeviceCntlr *)device;
        OsalMemFree(adc);
    }
}
#endif

static void AdcRelease(struct HdfDeviceObject *device)
{
#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    AdcRemoveByObject(device);
#else
    AdcRemoveByNode(device->property);
#endif
}

static struct HdfDriverEntry g_AdcDriverEntry = {
    .moduleVersion = 1,
    .Init = AdcInit,
    .Release = AdcRelease,
    .moduleName = "GD_ADC_MODULE_HDF",
};

HDF_INIT(g_AdcDriverEntry);