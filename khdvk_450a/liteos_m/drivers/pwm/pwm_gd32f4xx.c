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

#include <stdlib.h>
#include <stdio.h>
#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
#include "hcs_macro.h"
#include "hdf_config_macro.h"
#else
#include "device_resource_if.h"
#endif
#include "hdf_device_desc.h"
#include "pwm_core.h"
#include "hdf_log.h"
#include "osal_mem.h"

#include "gd32f4xx_timer.h"
#include "gd32f4xx_gpio.h"

#define HDF_LOG_TAG pwm_gd32f4xx

#define SYS_CORE_CLK 120000000 // 120MHz
#define PER_SEC_NSEC 1000000000

#define GPIO_PORT_MAX 8
#define GPIO_PIN_MAX 15
#define GPIO_PORT_IDX 0
#define GPIO_PIN_IDX 1
#define GPIO_ARRY_SIZE 2
#define GPIO_REG_STEP 0x00000400
#define PRESCALER_MAX 65535
#define PWM_TIMER_0 0
#define PWM_TIMER_1 1
#define PWM_TIMER_2 2
#define PWM_TIMER_3 3
#define PWM_TIMER_4 4
#define PWM_TIMER_7 7
#define PWM_TIMER_8 8
#define PWM_TIMER_11 11

#define PWM_TIMER_ROW_SIZE 8
#define PWM_TIMER_COL_SIZE 3
#define PWM_TIMER_KEY 0
#define PWM_TIMER_VALUE_TIMER 1
#define PWM_TIMER_VALUE_RCU 2

static uint32_t g_gdTimerMap[PWM_TIMER_ROW_SIZE][PWM_TIMER_COL_SIZE] = {
    PWM_TIMER_0, TIMER0,      RCU_TIMER0,  PWM_TIMER_1, TIMER1,      RCU_TIMER1,   PWM_TIMER_2, TIMER2,
    RCU_TIMER2,  PWM_TIMER_3, TIMER3,      RCU_TIMER3,  PWM_TIMER_4, TIMER4,       RCU_TIMER4,  PWM_TIMER_7,
    TIMER7,      RCU_TIMER7,  PWM_TIMER_8, TIMER8,      RCU_TIMER8,  PWM_TIMER_11, TIMER11,     RCU_TIMER11,
};

typedef struct {
    uint16_t timerId;
    uint16_t pwmCh;
    uint32_t pwmTm;
    uint16_t pwmId;
    uint32_t rcuTimer;
    uint16_t chGpio[GPIO_ARRY_SIZE];
} PwmResource;

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
#define PWM_FIND_CONFIG(node, name, resource)                                                                          \
    do {                                                                                                               \
        if (strcmp(HCS_PROP(node, match_attr), name) == 0) {                                                           \
            uint16_t channel = HCS_PROP(node, pwm_ch);                                                                 \
            uint16_t id = HCS_PROP(node, pwm_id);                                                                      \
            uint16_t timerId = HCS_PROP(node, timer_id);                                                               \
            uint16_t chGpio[] = HCS_ARRAYS(HCS_NODE(node, ch_gpio));                                                   \
            resource->pwmCh = channel;                                                                                 \
            resource->pwmId = id;                                                                                      \
            resource->timerId = timerId;                                                                               \
            for (uint16_t i = 0; i < GPIO_ARRY_SIZE; i++) {                                                            \
                resource->chGpio[i] = chGpio[i];                                                                       \
            }                                                                                                          \
            result = HDF_SUCCESS;                                                                                      \
        }                                                                                                              \
    } while (0)
#define PLATFORM_CONFIG HCS_NODE(HCS_ROOT, platform)
#define PLATFORM_PWM_CONFIG HCS_NODE(HCS_NODE(HCS_ROOT, platform), pwm_config)
static int32_t GetPwmDeviceResource(PwmResource *resource, const char *deviceMatchAttr)
{
    int32_t result = HDF_FAILURE;
    if (resource == NULL || deviceMatchAttr == NULL) {
        HDF_LOGE("%s: resource or deviceMatchAttr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

#if HCS_NODE_HAS_PROP(PLATFORM_CONFIG, pwm_config)
    HCS_FOREACH_CHILD_VARGS(PLATFORM_PWM_CONFIG, PWM_FIND_CONFIG, deviceMatchAttr, resource);
#endif
    if (result != HDF_SUCCESS) {
        HDF_LOGE("resourceNode %s is NULL\r\n", deviceMatchAttr);
    }

    return result;
}
#else
static int32_t GetPwmDeviceResource(PwmResource *resource, const struct DeviceResourceNode *resourceNode)
{
    struct DeviceResourceIface *dri = NULL;

    if (resource == NULL || resourceNode == NULL) {
        HDF_LOGE("resource or device is NULL\r\n");
        return HDF_ERR_INVALID_PARAM;
    }

    dri = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (dri == NULL || dri->GetUint16 == NULL || dri->GetUint32 == NULL || dri->GetUint16Array == NULL) {
        HDF_LOGE("DeviceResourceIface is invalid\r\n");
        return HDF_ERR_INVALID_PARAM;
    }

    if (dri->GetUint16(resourceNode, "pwm_ch", &resource->pwmCh, 0) != HDF_SUCCESS) {
        HDF_LOGE("read pwm_ch fail\r\n");
        return HDF_FAILURE;
    }

    if (dri->GetUint16(resourceNode, "pwm_id", &resource->pwmId, 0) != HDF_SUCCESS) {
        HDF_LOGE("read pwm_id fail\r\n");
        return HDF_FAILURE;
    }

    if (dri->GetUint16(resourceNode, "timer_id", &resource->timerId, 0) != HDF_SUCCESS) {
        HDF_LOGE("read timer_id fail\r\n");
        return HDF_FAILURE;
    }

    if (dri->GetUint16Array(resourceNode, "ch_gpio", &resource->chGpio, GPIO_ARRY_SIZE, 0) != HDF_SUCCESS) {
        HDF_LOGE("read ch_gpio fail!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}
#endif

static int32_t PwmTimerCheck(PwmResource *dev)
{
    int16_t i = 0;

    if (dev->chGpio[GPIO_PORT_IDX] > GPIO_PORT_MAX || dev->chGpio[GPIO_PIN_IDX] > GPIO_PIN_MAX) {
        HDF_LOGE("%s: pwm(%d) gpio ch is invalid!", __func__, dev->pwmId);
        return HDF_ERR_INVALID_PARAM;
    }

    for (; i < PWM_TIMER_ROW_SIZE; i++) {
        if (dev->timerId == g_gdTimerMap[i][PWM_TIMER_KEY]) {
            return HDF_SUCCESS;
        }
    }
    HDF_LOGE("%s: pwm(%d) timer is invalid!", __func__, dev->pwmId);

    return HDF_FAILURE;
}

static void PwmConfigCompletion(PwmResource *dev)
{
    int16_t i = 0;

    for (; i < PWM_TIMER_ROW_SIZE; i++) {
        if (dev->timerId == g_gdTimerMap[i][PWM_TIMER_KEY]) {
            dev->pwmTm = g_gdTimerMap[i][PWM_TIMER_VALUE_TIMER];
            dev->rcuTimer = g_gdTimerMap[i][PWM_TIMER_VALUE_RCU];
        }
    }

    return;
}

static int32_t AttachPwmDevice(struct PwmDev *host, const struct HdfDeviceObject *device)
{
    int32_t ret;
    PwmResource *pwmDevice = NULL;
#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    if (device == NULL || host == NULL) {
#else
    if (device == NULL || device->property == NULL || host == NULL) {
#endif
        HDF_LOGE("%s: param is NULL\r\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pwmDevice = (PwmResource *)OsalMemCalloc(sizeof(PwmResource));
    if (pwmDevice == NULL) {
        HDF_LOGE("%s: OsalMemAlloc pwmDevice error\r\n", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    ret = GetPwmDeviceResource(pwmDevice, device->deviceMatchAttr);
#else
    ret = GetPwmDeviceResource(pwmDevice, device->property);
#endif
    if (ret != HDF_SUCCESS || PwmTimerCheck(pwmDevice) != HDF_SUCCESS) {
        (void)OsalMemFree(pwmDevice);
        return HDF_FAILURE;
    }

    PwmConfigCompletion(pwmDevice);
    host->priv = pwmDevice;
    host->num = pwmDevice->pwmId;

    return HDF_SUCCESS;
}

static void ChannelGpioConfig(PwmResource *dev)
{
    rcu_periph_clock_enable(RCU_GPIOB);

    /* Configure PB10(TIMER1_CH2) as alternate function */
    gpio_mode_set(dev->chGpio[GPIO_PORT_IDX] * GPIO_REG_STEP + GPIO_BASE, GPIO_MODE_AF, GPIO_PUPD_NONE,
                  BIT(dev->chGpio[GPIO_PIN_IDX]));
    gpio_output_options_set(dev->chGpio[GPIO_PORT_IDX] * GPIO_REG_STEP + GPIO_BASE, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ,
                            BIT(dev->chGpio[GPIO_PIN_IDX]));

    gpio_af_set(dev->chGpio[GPIO_PORT_IDX] * GPIO_REG_STEP + GPIO_BASE, GPIO_AF_1, BIT(dev->chGpio[GPIO_PIN_IDX]));
}

static int32_t PwmTimerConfig(PwmResource *resource, struct PwmConfig *config)
{
    /* TIMER1 configuration: generate PWM signals with different duty cycles:
       TIMER1CLK = SystemCoreClock / 120 = 1MHz */
    timer_oc_parameter_struct timer_ocintpara;
    timer_parameter_struct timer_initpara;

    rcu_periph_clock_enable(resource->rcuTimer);
    rcu_timer_clock_prescaler_config(RCU_TIMER_PSC_MUL4);
    timer_struct_para_init(&timer_initpara);
    timer_deinit(resource->pwmTm);

    /* TIMER1 configuration */
    timer_initpara.prescaler = config->period / PER_SEC_NSEC * SYS_CORE_CLK - 1;
    if (timer_initpara.prescaler < 0 || timer_initpara.prescaler > PRESCALER_MAX) {
        HDF_LOGE("%s: prescaler must be 0~65535! ", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    timer_initpara.alignedmode = TIMER_COUNTER_EDGE;
    timer_initpara.counterdirection = TIMER_COUNTER_UP;
    timer_initpara.period = config->period;
    timer_initpara.clockdivision = TIMER_CKDIV_DIV1;
    timer_initpara.repetitioncounter = 0;
    timer_init(resource->pwmTm, &timer_initpara);

    /* CH2 configuration in PWM mode 0 */
    timer_channel_output_struct_para_init(&timer_ocintpara);
    if (config->polarity == PWM_NORMAL_POLARITY) {
        timer_ocintpara.ocpolarity = TIMER_OC_POLARITY_HIGH;
        timer_ocintpara.ocnpolarity = TIMER_OCN_POLARITY_HIGH;
    } else {
        timer_ocintpara.ocpolarity = TIMER_OC_POLARITY_LOW;
        timer_ocintpara.ocnpolarity = TIMER_OCN_POLARITY_LOW;
    }
    timer_ocintpara.outputstate = TIMER_CCX_ENABLE;
    timer_ocintpara.outputnstate = TIMER_CCXN_DISABLE;
    timer_ocintpara.ocidlestate = TIMER_OC_IDLE_STATE_LOW;
    timer_ocintpara.ocnidlestate = TIMER_OCN_IDLE_STATE_LOW;

    timer_channel_output_config(resource->pwmTm, resource->pwmCh, &timer_ocintpara);

    /* CH2 configuration duty cycle */
    timer_channel_output_pulse_value_config(resource->pwmTm, resource->pwmCh, config->duty);
    timer_channel_output_mode_config(resource->pwmTm, resource->pwmCh, TIMER_OC_MODE_PWM0);
    timer_channel_output_shadow_config(resource->pwmTm, resource->pwmCh, TIMER_OC_SHADOW_DISABLE);

    /* auto-reload preload enable */
    timer_auto_reload_shadow_enable(resource->pwmTm);
    /* TIMER1 enable */
    timer_enable(resource->pwmTm);

    return HDF_SUCCESS;
}

void PwmTimerStop(PwmResource *dev)
{
    timer_channel_output_pulse_value_config(dev->pwmTm, dev->pwmCh, 0);
    timer_disable(dev->pwmTm);
}

static int32_t PwmDevSetConfig(struct PwmDev *pwm, struct PwmConfig *config)
{
    PwmResource *prvPwm = NULL;

    if (pwm == NULL || config == NULL || (config->period > PER_SEC_NSEC)) {
        HDF_LOGE("%s\r\n", __FUNCTION__);
        return HDF_ERR_INVALID_PARAM;
    }

    prvPwm = (PwmResource *)PwmGetPriv(pwm);
    if (prvPwm == NULL) {
        return HDF_DEV_ERR_NO_DEVICE;
    }

    if (config->status == PWM_ENABLE_STATUS) {
        if (PwmTimerConfig(prvPwm, config) != HDF_SUCCESS) {
            HDF_LOGE("set timer config failed!\r\n");
            return HDF_FAILURE;
        }
    } else {
        PwmTimerStop(prvPwm);
    }

    return HDF_SUCCESS;
}

static int32_t PwmDevOpen(struct PwmDev *pwm)
{
    if (pwm == NULL) {
        HDF_LOGE("%s\r\n", __FUNCTION__);
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

static int32_t PwmDevClose(struct PwmDev *pwm)
{
    PwmResource *prvPwm = NULL;

    if (pwm == NULL) {
        HDF_LOGE("%s\r\n", __FUNCTION__);
        return HDF_ERR_INVALID_PARAM;
    }
    prvPwm = (PwmResource *)PwmGetPriv(pwm);
    if (prvPwm == NULL) {
        HDF_LOGE("%s\r\n", __FUNCTION__);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    PwmTimerStop(prvPwm);

    return HDF_SUCCESS;
}

struct PwmMethod g_pwmmethod = {
    .setConfig = PwmDevSetConfig,
    .open = PwmDevOpen,
    .close = PwmDevClose,
};

static int32_t PwmDriverBind(struct HdfDeviceObject *device)
{
    struct PwmDev *devService = NULL;
    if (device == NULL) {
        HDF_LOGE("hdfDevice object is null!\r\n");
        return HDF_ERR_INVALID_OBJECT;
    }

    devService = (struct PwmDev *)OsalMemCalloc(sizeof(struct PwmDev));
    if (devService == NULL) {
        HDF_LOGE("malloc pwmDev failed\n");
        return HDF_ERR_MALLOC_FAIL;
    }
    device->service = &devService->service;
    devService->device = device;

    return HDF_SUCCESS;
}

static int32_t PwmDriverInit(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct PwmDev *host = NULL;

    if (device == NULL) {
        HDF_LOGE("%s: device is NULL\r\n", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    HDF_LOGI("%s: Enter", __func__);

    host = (struct PwmDev *)device->service;
    if (host == NULL) {
        HDF_LOGE("%s: host is NULL\r\n", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    ret = AttachPwmDevice(host, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s:attach error\r\n", __func__);
        return HDF_DEV_ERR_ATTACHDEV_FAIL;
    }

    ChannelGpioConfig((PwmResource *)host->priv);

    host->method = &g_pwmmethod;
    ret = PwmDeviceAdd(device, host);
    if (ret != HDF_SUCCESS) {
        PwmDeviceRemove(device, host);
        OsalMemFree(host->device);
        OsalMemFree(host);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    HDF_LOGI("%s: PWM%d init success", __func__, host->num);
    return HDF_SUCCESS;
}

static void PwmDriverRelease(struct HdfDeviceObject *device)
{
    struct PwmDev *host = NULL;

    if (device == NULL || device->service == NULL) {
        HDF_LOGE("device is null\r\n");
        return;
    }

    host = (struct PwmDev *)device->service;
    if (host != NULL && host->device != NULL) {
        host->method = NULL;
        OsalMemFree(host->device);
        OsalMemFree(host);
        host->device = NULL;
        host = NULL;
    }

    device->service = NULL;
    host = NULL;

    return;
}

struct HdfDriverEntry g_pwmDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "GD_PWM_MODULE_HDF",
    .Bind = PwmDriverBind,
    .Init = PwmDriverInit,
    .Release = PwmDriverRelease,
};
HDF_INIT(g_pwmDriverEntry);