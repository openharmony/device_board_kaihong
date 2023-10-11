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
#include "hdf_log.h"
#include "los_interrupt.h"
#include "gpio_core.h"
#include "gd32f4xx.h"

#define HDF_LOG_TAG gpio_gd32f450

#define GPIO_PIN_TOTAL 140
#define GPIO_REG_BASE 0x40020000
#define GPIO_REG_STEP 0x00000400
#define GPIO_BIT_PER_GROUP 16

#define DEFAULT_PRE_PRIORITY 2U
#define DEFAULT_SUB_PRIORITY 0U
#define EXIT_PIN_SOURCE_MAX GPIO_BIT_PER_GROUP
#define GPIO_MODE_DATA_LENGTH 2
#define EXTI5_9_IRQ_START_NUM 5
#define EXTI5_9_IRQ_END_NUM 9
#define EXTI10_15_IRQ_START_NUM 10
#define EXTI10_15_IRQ_END_NUM 15
#define EXTI5_9_IRQ_PARAM_NUM 5
#define EXTI10_15_IRQ_PARAM_NUM 6

typedef enum {
    PIN_EXTI0 = 0,
    PIN_EXTI1 = 1,
    PIN_EXTI2 = 2,
    PIN_EXTI3 = 3,
    PIN_EXTI4 = 4,
    PIN_EXTI5 = 5,
    PIN_EXTI6 = 6,
    PIN_EXTI7 = 7,
    PIN_EXTI8 = 8,
    PIN_EXTI9 = 9,
    PIN_EXTI10 = 10,
    PIN_EXTI11 = 11,
    PIN_EXTI12 = 12,
    PIN_EXTI13 = 13,
    PIN_EXTI14 = 14,
    PIN_EXTI15 = 15,
} EXTI0_NUM;

typedef enum {
    PIN_NUM0 = 0,
    PIN_NUM1 = 1,
    PIN_NUM2 = 2,
    PIN_NUM3 = 3,
    PIN_NUM4 = 4,
    PIN_NUM5 = 5,
    PIN_NUM6 = 6,
    PIN_NUM7 = 7,
    PIN_NUM8 = 8,
    PIN_NUM9 = 9,
    PIN_NUM10 = 10,
    PIN_NUM11 = 11,
    PIN_NUM12 = 12,
    PIN_NUM13 = 13,
    PIN_NUM14 = 14,
    PIN_NUM15 = 15,
} PIN_NUM;
/* GPIO 分组 */
// PA0 ~ PA15, 0-15
// PB0 ~ PB15, 16-31
// PC0 ~ PC15, 32-47
// PD0 ~ PD15, 48-63
// PE0 ~ PE15, 64-79
// PF0 ~ PF15, 80-95
// PG0 ~ PG15, 96-111
// PH0 ~ PH15, 112-117
// PI0 ~ PI11. 118-139

/* 一个中断线仅支持一个端口触发 */
// EXTILineNumber  Source
// 0                PA0/PB0/PC0/PD0/PE0/PF0/PG0/PH0/PI0
// 1                PA1/PB1/PC1/PD1/PE1/PF1/PG1/PH1/PI1
// 2                PA2/PB2/PC2/PD2/PE2/PF2/PG2/PH2/PI2
// 3                PA3/PB3/PC3/PD3/PE3/PF3/PG3/PH3/PI3
// 4                PA4/PB4/PC4/PD4/PE4/PF4/PG4/PH4/PI4
// 5                PA5/PB5/PC5/PD5/PE5/PF5/PG5/PH5/PI5
// 6                PA6/PB6/PC6/PD6/PE6/PF6/PG6/PH6/PI6
// 7                PA7/PB7/PC7/PD7/PE7/PF7/PG7/PH7/PI7
// 8                PA8/PB8/PC8/PD8/PE8/PF8/PG8/PH8/PI8
// 9                PA9/PB9/PC9/PD9/PE9/PF9/PG9/PH9/PI9
// 10               PA10/PB10/PC10/PD10/PE10/PF10/PG10/PH10/PI10
// 11               PA11/PB11/PC11/PD11/PE11/PF11/PG11/PH11/PI11
// 12               PA12/PB12/PC12/PD12/PE12/PF12/PG12/PH12
// 13               PA13/PB13/PC13/PD13/PE13/PF13/PG13/PH13
// 14               PA14/PB14/PC14/PD14/PE14/PF14/PG14/PH14
// 15               PA15/PB15/PC15/PD15/PE15/PF15/PG15/PH15

struct GpioDevCntlr {
    struct GpioCntlr cntlr;

    uint32_t irqSave;
    OsalSpinlock lock;

    uint32_t start;
    uint32_t count;
};

struct DevIrqInfo {
    uint8_t isRegistered;
    struct GpioCntlr *cntlr;
    uint16_t sourceLocal;
};
static struct DevIrqInfo g_DevIrqInfo[EXIT_PIN_SOURCE_MAX] = {0};

struct IrqFuncParam {
    uint8_t startExti;
    uint8_t endExti;
    uint8_t irqRcu;
};
static struct IrqFuncParam g_Exti[7];

static inline struct GpioDevCntlr *ToGpioDevCntlr(struct GpioCntlr *cntlr)
{
    if (cntlr == NULL) {
        HDF_LOGE("%s, cntlr is NULL", __func__);
        return NULL;
    }
    return (struct GpioDevCntlr *)cntlr;
}

static inline uint32_t ToGpioPeriph(struct GpioCntlr *cntlr, uint16_t local)
{
    uint32_t gpioPeriph = 0;

    gpioPeriph = GPIO_REG_BASE + (local / GPIO_BIT_PER_GROUP) * GPIO_REG_STEP;

    return gpioPeriph;
}

static inline uint32_t ToGpioPin(struct GpioCntlr *cntlr, uint16_t local)
{
    uint32_t pinNum = 0;

    pinNum = local % GPIO_BIT_PER_GROUP;

    return (BIT(pinNum));
}

static inline uint8_t ToGpioExitSourceIndex(struct GpioCntlr *cntlr, uint16_t local)
{
    return (local % GPIO_BIT_PER_GROUP);
}

static inline exti_line_enum ToGpioExtiLineNum(struct GpioCntlr *cntlr, uint16_t local)
{
    uint32_t pinNum = 0;

    pinNum = local % GPIO_BIT_PER_GROUP;

    return (BIT(pinNum));
}

static inline rcu_periph_enum ToGpioRcuPeriphNum(struct GpioCntlr *cntlr, uint16_t local)
{
    rcu_periph_enum rcuPeriph;

    rcuPeriph = (rcu_periph_enum)(RCU_REGIDX_BIT(AHB1EN_REG_OFFSET, local / GPIO_BIT_PER_GROUP));

    return rcuPeriph;
}

static uint8_t ToGpioRcuIndex(uint16_t local)
{
    uint16_t pinNum = 0;
    uint8_t index = 0;
    pinNum = local % GPIO_BIT_PER_GROUP;
    if (pinNum < EXTI5_9_IRQ_START_NUM) {
        index = pinNum;
    } else if (pinNum < EXTI10_15_IRQ_START_NUM) {
        index = EXTI5_9_IRQ_PARAM_NUM;
    } else {
        index = EXTI10_15_IRQ_PARAM_NUM;
    }
    return index;
}
static void InitExti(void)
{
    static uint8_t single = 0;
    if (single == 0) {
        for (int i = 0; i < EXTI5_9_IRQ_PARAM_NUM; i++) {
            g_Exti[i].startExti = i;
            g_Exti[i].endExti = i;
            g_Exti[i].irqRcu = EXTI0_IRQn + i;
        }
        g_Exti[EXTI5_9_IRQ_PARAM_NUM].startExti = EXTI5_9_IRQ_START_NUM;
        g_Exti[EXTI5_9_IRQ_PARAM_NUM].endExti = EXTI5_9_IRQ_END_NUM;
        g_Exti[EXTI5_9_IRQ_PARAM_NUM].irqRcu = EXTI5_9_IRQn;
        g_Exti[EXTI10_15_IRQ_PARAM_NUM].startExti = EXTI10_15_IRQ_START_NUM;
        g_Exti[EXTI10_15_IRQ_PARAM_NUM].endExti = EXTI10_15_IRQ_END_NUM;
        g_Exti[EXTI10_15_IRQ_PARAM_NUM].irqRcu = EXTI10_15_IRQn;
        single = 1;
    }
}

static inline uint8_t ToGpioIrqNum(struct GpioCntlr *cntlr, uint16_t local)
{
    uint8_t index;
    index = ToGpioRcuIndex(local);
    return g_Exti[index].irqRcu;
}

static inline uint8_t ToGpioExtiSourcePort(struct GpioCntlr *cntlr, uint16_t local)
{
    uint8_t groupNum = 0;

    groupNum = local / GPIO_BIT_PER_GROUP;

    return ((uint8_t)groupNum);
}

static inline uint8_t ToGpioExtiSourcePin(struct GpioCntlr *cntlr, uint16_t local)
{
    uint8_t pinNum = 0;

    pinNum = local % GPIO_BIT_PER_GROUP;

    return ((uint8_t)pinNum);
}

static int32_t GpioDevSetDir(struct GpioCntlr *cntlr, uint16_t local, uint16_t dir)
{
    uint32_t gpioPeriph;
    uint32_t mode;
    uint32_t pull;
    uint32_t pin;
    struct GpioDevCntlr *p = NULL;

    if (cntlr == NULL) {
        HDF_LOGE("%s, cntlr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (local >= GPIO_PIN_TOTAL) {
        HDF_LOGE("%s, local(%d) is out of range", __func__, local);
        return HDF_ERR_INVALID_PARAM;
    }

    if ((dir != GPIO_DIR_IN) && (dir != GPIO_DIR_OUT)) {
        HDF_LOGE("%s, dir(%d) is not right", __func__, dir);
        return HDF_ERR_INVALID_PARAM;
    }

    p = ToGpioDevCntlr(cntlr);
    gpioPeriph = ToGpioPeriph(cntlr, local);
    if (dir == GPIO_DIR_IN) {
        mode = GPIO_MODE_INPUT;
    } else {
        mode = GPIO_MODE_OUTPUT;
    }
    pull = GPIO_PUPD_NONE;
    pin = ToGpioPin(cntlr, local);

    if (OsalSpinLockIrqSave(&p->lock, &p->irqSave) != HDF_SUCCESS) {
        HDF_LOGE("in %s:%s %d: get spinLock failed", __FILE__, __FUNCTION__, __LINE__);
        return HDF_ERR_DEVICE_BUSY;
    }

    gpio_mode_set(gpioPeriph, mode, pull, pin);

    (void)OsalSpinUnlockIrqRestore(&p->lock, &p->irqSave);

    return HDF_SUCCESS;
}

static int32_t GpioDevGetDir(struct GpioCntlr *cntlr, uint16_t local, uint16_t *dir)
{
    uint32_t gpioPeriph;
    uint32_t ctl;
    uint32_t pin;
    uint32_t readDir;

    if (cntlr == NULL) {
        HDF_LOGE("%s, cntlr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (local >= GPIO_PIN_TOTAL) {
        HDF_LOGE("%s, local(%d) is out of range", __func__, local);
        return HDF_ERR_INVALID_PARAM;
    }

    if (dir == NULL) {
        HDF_LOGE("%s, dir is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    gpioPeriph = ToGpioPeriph(cntlr, local);
    pin = ToGpioPin(cntlr, local);
    ctl = GPIO_CTL(gpioPeriph);
    readDir = (ctl >> (GPIO_MODE_DATA_LENGTH * pin)) & 0x03;

    if (readDir == GPIO_MODE_OUTPUT) {
        *dir = GPIO_DIR_OUT;
    } else if (readDir == GPIO_MODE_INPUT) {
        *dir = GPIO_DIR_IN;
    } else { // default direction
        HDF_LOGE("invalid gpio mode input/output!");
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

static int32_t GpioDevWrite(struct GpioCntlr *cntlr, uint16_t local, uint16_t val)
{
    uint32_t gpioPeriph;
    uint32_t pin;
    bit_status bitValue;
    struct GpioDevCntlr *p = NULL;

    if (cntlr == NULL) {
        HDF_LOGE("%s, cntlr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (local >= GPIO_PIN_TOTAL) {
        HDF_LOGE("%s, local(%d) is out of range", __func__, local);
        return HDF_ERR_INVALID_PARAM;
    }
    p = ToGpioDevCntlr(cntlr);
    gpioPeriph = ToGpioPeriph(cntlr, local);
    pin = ToGpioPin(cntlr, local);
    if (val == 1) {
        bitValue = SET;
    } else {
        bitValue = RESET;
    }

    if (OsalSpinLockIrqSave(&p->lock, &p->irqSave) != HDF_SUCCESS) {
        HDF_LOGE("in %s:%s %d: get spinLock failed", __FILE__, __FUNCTION__, __LINE__);
        return HDF_ERR_DEVICE_BUSY;
    }

    gpio_bit_write(gpioPeriph, pin, bitValue);

    (void)OsalSpinUnlockIrqRestore(&p->lock, &p->irqSave);

    return HDF_SUCCESS;
}

static int32_t GpioDevRead(struct GpioCntlr *cntlr, uint16_t local, uint16_t *val)
{
    uint32_t gpioPeriph;
    uint32_t pin;
    bit_status bitValue;

    if (cntlr == NULL) {
        HDF_LOGE("%s, cntlr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (local >= GPIO_PIN_TOTAL) {
        HDF_LOGE("%s, local(%d) is out of range", __func__, local);
        return HDF_ERR_INVALID_PARAM;
    }

    gpioPeriph = ToGpioPeriph(cntlr, local);
    pin = ToGpioPin(cntlr, local);

    bitValue = gpio_input_bit_get(gpioPeriph, pin);
    if (bitValue == SET) {
        *val = GPIO_VAL_HIGH;
    } else {
        *val = GPIO_VAL_LOW;
    }

    return HDF_SUCCESS;
}

static void GpioDevClearIrqUnsafe(struct GpioCntlr *cntlr, uint16_t local)
{
    exti_line_enum lineX;
    lineX = ToGpioExtiLineNum(cntlr, local);

    exti_interrupt_flag_clear(lineX);
}

static void GpioDevSetIrqEnableUnsafe(struct GpioCntlr *cntlr, uint16_t local, int flag)
{
    exti_line_enum lineX;

    lineX = ToGpioExtiLineNum(cntlr, local);

    if (flag == 0) {
        exti_interrupt_disable(lineX);
    } else {
        exti_interrupt_enable(lineX);
    }
}

static int32_t GpioDevEnableIrq(struct GpioCntlr *cntlr, uint16_t local)
{
    struct GpioDevCntlr *p = NULL;

    static int isFirstEnterFlag = 1;
    if (isFirstEnterFlag == 1) {
        rcu_periph_clock_enable(RCU_SYSCFG);
        isFirstEnterFlag = 0;
    }

    if (cntlr == NULL) {
        HDF_LOGE("%s, cntlr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (local >= GPIO_PIN_TOTAL) {
        HDF_LOGE("%s, local(%d) is out of range", __func__, local);
        return HDF_ERR_INVALID_PARAM;
    }

    p = ToGpioDevCntlr(cntlr);
    if (OsalSpinLockIrqSave(&p->lock, &p->irqSave) != HDF_SUCCESS) {
        HDF_LOGE("in %s:%s %d: get spinLock failed", __FILE__, __FUNCTION__, __LINE__);
        return HDF_ERR_DEVICE_BUSY;
    }

    GpioDevSetIrqEnableUnsafe(cntlr, local, 1);

    nvic_irq_enable(ToGpioIrqNum(cntlr, local), DEFAULT_PRE_PRIORITY, DEFAULT_SUB_PRIORITY);
    syscfg_exti_line_config(ToGpioExtiSourcePort(cntlr, local), ToGpioExtiSourcePin(cntlr, local));

    (void)OsalSpinUnlockIrqRestore(&p->lock, &p->irqSave);
    return HDF_SUCCESS;
}

static int32_t GpioDevDisableIrq(struct GpioCntlr *cntlr, uint16_t local)
{
    struct GpioDevCntlr *p = NULL;

    if (cntlr == NULL) {
        HDF_LOGE("%s, cntlr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (local >= GPIO_PIN_TOTAL) {
        HDF_LOGE("%s, local(%d) is out of range", __func__, local);
        return HDF_ERR_INVALID_PARAM;
    }

    p = ToGpioDevCntlr(cntlr);
    if (OsalSpinLockIrqSave(&p->lock, &p->irqSave) != HDF_SUCCESS) {
        HDF_LOGE("in %s:%s %d: get spinLock failed", __FILE__, __FUNCTION__, __LINE__);
        return HDF_ERR_DEVICE_BUSY;
    }

    GpioDevSetIrqEnableUnsafe(cntlr, local, 0);

    (void)OsalSpinUnlockIrqRestore(&p->lock, &p->irqSave);
    return HDF_SUCCESS;
}

/* 中断处理方式仅支持沿触发 */
static int32_t GpioDevSetIrqTypeUnsafe(struct GpioCntlr *cntlr, uint16_t local, uint16_t mode)
{
    exti_line_enum lineNum;
    exti_trig_type_enum trigType;

    lineNum = ToGpioExtiLineNum(cntlr, local);

    switch (mode) {
        case OSAL_IRQF_TRIGGER_RISING:
            trigType = EXTI_TRIG_RISING;
            break;
        case OSAL_IRQF_TRIGGER_FALLING:
            trigType = EXTI_TRIG_FALLING;
            break;
        case OSAL_IRQF_TRIGGER_HIGH:
        case OSAL_IRQF_TRIGGER_LOW:
        case OSAL_IRQF_TRIGGER_NONE:
        default:
            HDF_LOGE("%s:irq mode(%x) not support", __func__, mode);
            return HDF_ERR_INVALID_PARAM;
    }

    exti_init(lineNum, EXTI_INTERRUPT, trigType);
    exti_interrupt_flag_clear(lineNum);

    return HDF_SUCCESS;
}

static void DevExitIrqHandler(struct IrqFuncParam *para)
{
    HDF_LOGI("===================== INTERRUPT:%s %d id addr=%0x para add=%0x", __FUNCTION__, __LINE__, para);
    struct DevIrqInfo *p_info;
    for (uint8_t i = para->startExti; i <= para->endExti; i++) {
        exti_line_enum linex = BIT(i);
        if (RESET != exti_interrupt_flag_get(linex)) {
            exti_interrupt_flag_clear(linex);
            p_info = &g_DevIrqInfo[i];
            if (p_info->isRegistered == 1) {
                GpioCntlrIrqCallback(p_info->cntlr, p_info->sourceLocal);
            }
        }
    }
}

static UINT32 DevHwiCreate(struct GpioCntlr *cntlr, uint16_t local)
{
    HwiIrqParam irqParam;
    uint8_t index;

    index = ToGpioRcuIndex(local);
    irqParam.pDevId = &g_Exti[index];
    return LOS_HwiCreate(ToGpioIrqNum(cntlr, local), 0, 0, (HWI_PROC_FUNC)DevExitIrqHandler, &irqParam);
}

static UINT32 DevHwiDelete(struct GpioCntlr *cntlr, uint16_t local)
{
    uint8_t i;
    uint8_t index;

    index = ToGpioRcuIndex(local);
    for (i = g_Exti[index].startExti; i <= g_Exti[index].endExti; i++) {
        if (g_DevIrqInfo[index].isRegistered == 1) {
            break;
        }
    }

    if (i > g_Exti[index].endExti) {
        return LOS_HwiDelete(ToGpioIrqNum(cntlr, local), NULL);
    }

    return HDF_SUCCESS;
}

static int32_t GpioDevSetIrq(struct GpioCntlr *cntlr, uint16_t local, uint16_t mode)
{
    struct GpioDevCntlr *p = NULL;
    uint8_t index;

    if (cntlr == NULL) {
        HDF_LOGE("%s, cntlr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (local >= GPIO_PIN_TOTAL) {
        HDF_LOGE("%s, local(%d) is out of range", __func__, local);
        return HDF_ERR_INVALID_PARAM;
    }

    p = ToGpioDevCntlr(cntlr);
    if (OsalSpinLockIrqSave(&p->lock, &p->irqSave) != HDF_SUCCESS) {
        HDF_LOGE("in %s:%s %d: get spinLock failed", __FILE__, __FUNCTION__, __LINE__);
        return HDF_ERR_DEVICE_BUSY;
    }

    InitExti();
    gpio_mode_set(ToGpioPeriph(cntlr, local), GPIO_MODE_INPUT, GPIO_PUPD_NONE, ToGpioPin(cntlr, local));
    GpioDevSetIrqTypeUnsafe(cntlr, local, mode);
    GpioDevSetIrqEnableUnsafe(cntlr, local, 0); // disable irq when set
    GpioDevClearIrqUnsafe(cntlr, local);

    index = ToGpioExitSourceIndex(cntlr, local);
    if (g_DevIrqInfo[index].isRegistered == 1) {
        HDF_LOGE("%s: exitSourceIndex [%d] has already been registered! You need to unset it", index);
        (void)OsalSpinUnlockIrqRestore(&p->lock, &p->irqSave);
        return HDF_FAILURE;
    }

    g_DevIrqInfo[index].isRegistered = 1;
    g_DevIrqInfo[index].cntlr = cntlr;
    g_DevIrqInfo[index].sourceLocal = local;

    (void)DevHwiCreate(cntlr, local);

    (void)OsalSpinUnlockIrqRestore(&p->lock, &p->irqSave);

    return HDF_SUCCESS;
}

static int32_t GpioDevUnsetIrq(struct GpioCntlr *cntlr, uint16_t local)
{
    struct GpioDevCntlr *p = NULL;
    uint8_t index;
    if (cntlr == NULL) {
        HDF_LOGE("%s, cntlr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (local >= GPIO_PIN_TOTAL) {
        HDF_LOGE("%s, local(%d) is out of range", __func__, local);
        return HDF_ERR_INVALID_PARAM;
    }

    p = ToGpioDevCntlr(cntlr);
    if (OsalSpinLockIrqSave(&p->lock, &p->irqSave) != HDF_SUCCESS) {
        HDF_LOGE("in %s:%s %d: get spinLock failed", __FILE__, __FUNCTION__, __LINE__);
        return HDF_ERR_DEVICE_BUSY;
    }

    index = ToGpioExitSourceIndex(cntlr, local);
    g_DevIrqInfo[index].isRegistered = 0;

    GpioDevSetIrqEnableUnsafe(cntlr, local, 0);
    GpioDevClearIrqUnsafe(cntlr, local);
    (void)DevHwiDelete(cntlr, local);

    (void)OsalSpinUnlockIrqRestore(&p->lock, &p->irqSave);

    return HDF_SUCCESS;
}

static struct GpioMethod g_Method = {
    .request = NULL,
    .release = NULL,
    .write = GpioDevWrite,
    .read = GpioDevRead,
    .setDir = GpioDevSetDir,
    .getDir = GpioDevGetDir,
    .toIrq = NULL,
    .setIrq = GpioDevSetIrq,
    .unsetIrq = GpioDevUnsetIrq,
    .enableIrq = GpioDevEnableIrq,
    .disableIrq = GpioDevDisableIrq,
};

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
#define GPIO_FIND_CONFIG(node, name, resource)                                                                         \
    do {                                                                                                               \
        if (strcmp(HCS_PROP(node, match_attr), name) == 0) {                                                           \
            uint32_t start = HCS_PROP(node, start);                                                                    \
            uint32_t count = HCS_PROP(node, count);                                                                    \
            resource->start = start;                                                                                   \
            resource->count = count;                                                                                   \
            result = HDF_SUCCESS;                                                                                      \
        }                                                                                                              \
    } while (0)
#define PLATFORM_CONFIG HCS_NODE(HCS_ROOT, platform)
#define PLATFORM_GPIO_CONFIG HCS_NODE(HCS_NODE(HCS_ROOT, platform), gpio_config)
static int32_t DevGetGpioDeviceResource(struct GpioDevCntlr *resource, const char *deviceMatchAttr)
{
    int32_t result = HDF_FAILURE;
    if (resource == NULL || deviceMatchAttr == NULL) {
        HDF_LOGE("%s: resource or deviceMatchAttr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

#if HCS_NODE_HAS_PROP(PLATFORM_CONFIG, gpio_config)
    HCS_FOREACH_CHILD_VARGS(PLATFORM_GPIO_CONFIG, GPIO_FIND_CONFIG, deviceMatchAttr, resource);
#endif
    if (result != HDF_SUCCESS) {
        HDF_LOGE("resourceNode %s is NULL\r\n", deviceMatchAttr);
    }

    return result;
}
#else
static int32_t DevGetGpioDeviceResource(struct GpioDevCntlr *p, const struct DeviceResourceNode *node)
{
    int32_t ret = 0;

    if (node == NULL) {
        HDF_LOGE("%s, device resource node is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct DeviceResourceIface *drsOps = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (drsOps == NULL || drsOps->GetUint16 == NULL || drsOps->GetUint32 == NULL) {
        HDF_LOGE("%s: invalid drs ops fail!", __func__);
        return HDF_FAILURE;
    }

    ret = drsOps->GetUint32(node, "start", &p->start, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read regBase fail!", __func__);
        return ret;
    }

    ret = drsOps->GetUint32(node, "count", &p->count, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read regStep fail!", __func__);
        return ret;
    }

    if ((p->start < 0) || (p->start >= GPIO_PIN_TOTAL)) {
        HDF_LOGE("%s: start(%d) is out of range", __func__, p->start);
        return HDF_ERR_INVALID_PARAM;
    }

    if ((p->count <= 0) || ((p->start + p->count - 1) >= GPIO_PIN_TOTAL)) {
        HDF_LOGE("%s start(%d): count(%d) is out of range", __func__, p->start, p->count);
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}
#endif

static int32_t GpioDevBind(struct HdfDeviceObject *device)
{
    HDF_LOGI("%s: Enter %d", __FILE__, __FUNCTION__, __LINE__);
    (void)device;
    return HDF_SUCCESS;
}
static void GpioRcuInit(struct GpioDevCntlr *p)
{
    rcu_periph_enum rcuPeriph = RCU_GPIOA;
    if (p == NULL) {
        HDF_LOGE("%s: GpioDevCntlr null!", __func__);
        return;
    }
    rcu_periph_clock_enable(RCU_SYSCFG);
    for (int32_t i = 0; i < p->count; i++) {
        rcuPeriph = ToGpioRcuPeriphNum(&p->cntlr, (p->start + i));
        rcu_periph_clock_enable(rcuPeriph);
    }
}
static int32_t GpioDevInit(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct GpioDevCntlr *p = NULL;

    HDF_LOGI("%s: Enter", __FUNCTION__);

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    if (device == NULL)
#else
    if (device == NULL || device->property == NULL)
#endif
    {
        HDF_LOGE("%s: device or property null!", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    p = (struct GpioDevCntlr *)OsalMemCalloc(sizeof(struct GpioDevCntlr));
    if (p == NULL) {
        HDF_LOGE("%s: malloc memory failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    memset_s(p, sizeof(struct GpioDevCntlr), 0, sizeof(struct GpioDevCntlr));

    if (OsalSpinInit(&p->lock) != HDF_SUCCESS) {
        HDF_LOGE("%s: OsalSpinInit failed!", __func__);
        OsalSpinDestroy(&p->lock);
        return HDF_FAILURE;
    }
#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    ret = DevGetGpioDeviceResource(p, device->deviceMatchAttr);
#else
    ret = DevGetGpioDeviceResource(p, device->property);
#endif
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read drs fail:%x", __func__, ret);
        return ret;
    }

    p->cntlr.start = p->start;
    p->cntlr.count = p->count;
#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    p->cntlr.priv = NULL;
#else
    p->cntlr.priv = (void *)device->property;
#endif
    p->cntlr.ops = &g_Method;

    GpioRcuInit(p);

    ret = GpioCntlrAdd(&p->cntlr);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: err add controller: %x", __func__, ret);
        return ret;
    }

    device->priv = p;
    HDF_LOGI("%s: gpio init success", __func__);
    return HDF_SUCCESS;
}

static void GpioDevRelease(struct HdfDeviceObject *device)
{
    struct GpioDevCntlr *p = NULL;

    if (device->priv != NULL) {
        p = (struct GpioDevCntlr *)device->priv;
        OsalMemFree(p);

        device->priv = NULL;
    }

    return;
}

struct HdfDriverEntry g_gpioDriverEntry = {
    .moduleVersion = 1,
    .Bind = GpioDevBind,
    .Init = GpioDevInit,
    .Release = GpioDevRelease,
    .moduleName = "GD_GPIO_MODULE_HDF",
};
HDF_INIT(g_gpioDriverEntry);
