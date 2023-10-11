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

#ifndef WATCHDOG_H
#define WATCHDOG_H
#include "device_resource_if.h"
#include "hdf_device_desc.h"
#include "hdf_log.h"
#include "gpio_core.h"
#include "gd32f4xx_gpio.h"
#include "watchdog_if.h"
#include "watchdog_core.h"

#define HDF_LOG_TAG GD450wdg

#define BITS_PER_LONG 32

#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

/* IWDG registers */
#define IWDG_KR 0x00   /* Key register */
#define IWDG_PR 0x04   /* Prescaler Register */
#define IWDG_RLR 0x08  /* ReLoad Register */
#define IWDG_SR 0x0C   /* Status Register */
#define IWDG_WINR 0x10 /* Windows Register */

/* IWDG_KR register bit mask */
#define KR_KEY_RELOAD 0xAAAA /* reload counter enable */
#define KR_KEY_ENABLE 0xCCCC /* peripheral enable */
#define KR_KEY_EWA 0x5555    /* write access enable */
#define KR_KEY_DWA 0x0000    /* write access disable */

/* IWDG_PR register */
#define PR_SHIFT 2
#define PR_MIN BIT(PR_SHIFT)

/* IWDG_RLR register values */
#define RLR_MIN 0x2            /* min value recommended */
#define RLR_MAX GENMASK(11, 0) /* max value of reload register */

/* IWDG_SR register bit mask */
#define SR_PVU BIT(0) /* Watchdog prescaler value update */
#define SR_RVU BIT(1) /* Watchdog counter reload value update */

/* set timeout to 100000 us */
#define TIMEOUT_US 100000
#define SLEEP_US 1000

#define DEFAULT_TIMEOUT (32)
#define DEFAULT_TASK_STACK_SIZE (0x800)
#define DEFAULT_CLOCK_RATE (32000)

#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))

struct GD450wdg {
    struct WatchdogCntlr wdt;     // 控制器
    uint32_t num;                 // 当前独立看门狗编号
    void volatile *base;          // 虚拟地址
    uint32_t phy_base;            // 物理地址
    uint32_t reg_step;            // 映射大小
    uint32_t seconds;             // 当前设置的超时值(s)
    bool start;                   // 当前iwdg是否已经启动
    uint32_t rate;                // 时钟源频率
    char *clock_source;           // 时钟源名称
    uint32_t min_timeout;         // 最小超时时间
    uint32_t max_hw_heartbeat_ms; // 最大超时时间
};

#endif