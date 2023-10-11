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
#include "iot_pwm.h"
#include "gd32f4xx.h"

// GPIOx[0:4] TIMEx[5:7] PINx[8:15]

// GPIOx  =  (PX & 0xF000) >> 12
// TIMEx  =  (PX & 0x0F00) >> 8
// AFmode =  (PX & 0x2F00) >> 4
// PIN    =  (PX & 0x200F) >> 0

#define GPIO(x) ((((x)&0xF000) >> 12))
#define TIME(x) ((((x)&0x0F00) >> 8))
#define TIME_CH(x) ((((x)&0x00F0) >> 4))
#define PINx(x) ((((x)&0x000F) >> 0))

#define BIT(x) ((uint32_t)((uint32_t)0x01U << (x)))
#define BITS(start, end) ((0xFFFFFFFFUL << (start)) & (0xFFFFFFFFUL >> (31U - (uint32_t)(end))))
#define TIMER_NUM (14)
#define TIMER_CHN_NUM (4)
#define GPIO_NUM (9)
#define ZERO_PULSE (0)
#define SYS_CLK (200000000)
#define CLK_PRESCALER (200 - 1)
#define PWM_CLK (SYS_CLK / ((CLK_PRESCALER) + 1))
#define PERCENTAGE 100

#define INVALID_TIME5 5
#define INVALID_TIME6 6
#define INVALID_GPIO_GROUP 6
#define INVALID_GPIO_GROUPS_START 8
const unsigned int time_arr[TIMER_NUM] = {
    TIMER0, TIMER1, TIMER2, TIMER3, TIMER4, TIMER5, TIMER6, TIMER7, TIMER8, TIMER9, TIMER10, TIMER11, TIMER12, TIMER13,
};
const unsigned int rcu_time_arr[TIMER_NUM] = {
    RCU_TIMER0, RCU_TIMER1, RCU_TIMER2, RCU_TIMER3,  RCU_TIMER4,  RCU_TIMER5,  RCU_TIMER6,
    RCU_TIMER7, RCU_TIMER8, RCU_TIMER9, RCU_TIMER10, RCU_TIMER11, RCU_TIMER12, RCU_TIMER13,
};
const unsigned int gpio_arr[GPIO_NUM] = {
    GPIOA, GPIOB, GPIOC, GPIOD, GPIOE, GPIOF, GPIOG, GPIOH, GPIOI,
};
const unsigned int rcu_gpio_arr[GPIO_NUM] = {
    RCU_GPIOA, RCU_GPIOB, RCU_GPIOC, RCU_GPIOD, RCU_GPIOE, RCU_GPIOF, RCU_GPIOG, RCU_GPIOH, RCU_GPIOI,
};
const unsigned int af_mode_arr[TIMER_NUM] = {
    GPIO_AF_1,  /* 0 */
    GPIO_AF_1,  /* 1 */
    GPIO_AF_2,  /* 2 */
    GPIO_AF_2,  /* 3 */
    GPIO_AF_2,  /* 4 */
    0,          /* 5 */
    0,          /* 6 */
    GPIO_AF_3,  /* 7 */
    GPIO_AF_3,  /* 8 */
    GPIO_AF_3,  /* 9 */
    GPIO_AF_3,  /* 10 */
    RCU_TIMER9, /* 11 */
    RCU_TIMER9, /* 12 */
    RCU_TIMER9, /* 13 */
};
const unsigned int time_ch_arr[TIMER_CHN_NUM] = {
    TIMER_CH_0, /* 0 */
    TIMER_CH_1, /* 1 */
    TIMER_CH_2, /* 2 */
    TIMER_CH_3, /* 3 */
};

unsigned int GpioConfigInit(unsigned int data)
{
    unsigned char gpiox = GPIO(data);
    unsigned char pin = PINx(data);
    unsigned char time = TIME(data);
    if (time == INVALID_TIME5 || time == INVALID_TIME6 || gpiox == INVALID_GPIO_GROUP ||
        gpiox > INVALID_GPIO_GROUPS_START) {
        return IOT_FAILURE;
    } else {
        rcu_periph_clock_enable(rcu_gpio_arr[gpiox]);                                         // RCU_GPIOB
        gpio_mode_set(gpio_arr[gpiox], GPIO_MODE_AF, GPIO_PUPD_NONE, BIT(pin));               // GPIOB  GPIO_PIN_3
        gpio_output_options_set(gpio_arr[gpiox], GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, BIT(pin)); // GPIOB GPIO_PIN_3
        gpio_af_set(gpio_arr[gpiox], af_mode_arr[time], BIT(pin)); // GPIOB GPIO_AF_1 GPIO_PIN_3
        rcu_periph_clock_enable(rcu_time_arr[time]);               // 选择开启的RCC RCU_TIMER1
        rcu_timer_clock_prescaler_config(RCU_TIMER_PSC_MUL4);      // 固定
    }
    return IOT_SUCCESS;
}

unsigned int GpioConfigDeinit(unsigned int data)
{
    unsigned char gpiox = GPIO(data);
    unsigned char pin = PINx(data);
    unsigned char time = TIME(data);
    if (time == INVALID_TIME5 || time == INVALID_TIME6 || gpiox == INVALID_GPIO_GROUP ||
        gpiox > INVALID_GPIO_GROUPS_START) {
        return IOT_FAILURE;
    } else {
        gpio_bit_reset(gpio_arr[gpiox], BIT(pin));
        rcu_periph_clock_disable(rcu_gpio_arr[gpiox]);
        rcu_periph_clock_disable(rcu_time_arr[time]);
    }
    return IOT_SUCCESS;
}

unsigned int IoTPwmInit(unsigned int port)
{
    int ret = GpioConfigInit(port);
    if (!ret) {
        return IOT_FAILURE;
    }
    return IOT_SUCCESS;
}

unsigned int IoTPwmDeinit(unsigned int port)
{
    int ret = GpioConfigDeinit(port);
    if (!ret) {
        return IOT_FAILURE;
    }
    return IOT_SUCCESS;
}

unsigned int IoTPwmStart(unsigned int port, unsigned short duty, unsigned int freq)
{
    unsigned char gpiox = GPIO(port);
    unsigned char pin = PINx(port);
    unsigned char ch = TIME_CH(port);
    unsigned char time = TIME(port);
    timer_parameter_struct timer_initpara;
    timer_oc_parameter_struct timer_ocintpara;

    if (time == INVALID_TIME5 || time == INVALID_TIME6 || gpiox == INVALID_GPIO_GROUP ||
        gpiox > INVALID_GPIO_GROUPS_START || freq == 0) {
        return IOT_FAILURE;
    }

    unsigned int period = PWM_CLK / freq;
    unsigned int val = (PWM_CLK / period) * duty / PERCENTAGE;

    /* TIMER1 configuration */
    timer_initpara.prescaler = CLK_PRESCALER;           // 分频 SystemCoreClock / 199+1 = 1MHz 1000000hz = 1Mhz
    timer_initpara.alignedmode = TIMER_COUNTER_EDGE;    // 触发方式设置根据边沿决定
    timer_initpara.counterdirection = TIMER_COUNTER_UP; // 设置为上升沿触发
    timer_initpara.period = period;
    timer_initpara.clockdivision = TIMER_CKDIV_DIV1; // clock division value is 1,fDTS=fTIMER_CK
    timer_initpara.repetitioncounter = 0;
    timer_init(time_arr[time], &timer_initpara);

    timer_ocintpara.ocpolarity = TIMER_OC_POLARITY_HIGH;     // 通道输出极性
    timer_ocintpara.outputstate = TIMER_CCX_ENABLE;          // 通道输出状态
    timer_ocintpara.ocnpolarity = TIMER_OCN_POLARITY_HIGH;   // 通道处于空闲时的输出
    timer_ocintpara.outputnstate = TIMER_CCXN_DISABLE;       // 互补通道输出极性
    timer_ocintpara.ocidlestate = TIMER_OC_IDLE_STATE_LOW;   // 互补通道输出状态
    timer_ocintpara.ocnidlestate = TIMER_OCN_IDLE_STATE_LOW; // 互补通道处于空闲时的输出
    timer_channel_output_config(time_arr[time], time_ch_arr[ch], &timer_ocintpara);

    timer_channel_output_pulse_value_config(time_arr[time], time_ch_arr[ch], val);
    timer_channel_output_mode_config(time_arr[time], time_ch_arr[ch], TIMER_OC_MODE_PWM0);
    timer_channel_output_shadow_config(time_arr[time], time_ch_arr[ch], TIMER_OC_SHADOW_DISABLE);
    timer_auto_reload_shadow_enable(time_arr[time]);
    timer_enable(time_arr[time]);

    return IOT_SUCCESS;
}

unsigned int IoTPwmStop(unsigned int port)
{
    unsigned char ch = TIME_CH(port);
    unsigned char time = TIME(port);
    timer_channel_output_pulse_value_config(time_arr[time], time_ch_arr[ch], ZERO_PULSE);
    timer_disable(time_arr[time]);
}