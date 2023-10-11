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
#include "lowpower.h"
#include "iot_errno.h"
#include "gd32f4xx_pmu.h"
#include "core_cm4.h"

unsigned int LpcInit(void)
{
    rcu_periph_clock_enable(RCU_PMU);
    return IOT_SUCCESS;
}

unsigned int LpcSetType(LpcType type)
{
    switch (type) {
        case NO_SLEEP:
            pmu_to_standbymode();
            break;
        case LIGHT_SLEEP:
            pmu_to_sleepmode(WFI_CMD);
            break;
        case DEEP_SLEEP:
            pmu_to_deepsleepmode(PMU_LDO_LOWPOWER, PMU_LOWDRIVER_DISABLE, WFI_CMD);
            break;
        default:
            return IOT_FAILURE;
    }
    return IOT_SUCCESS;
}