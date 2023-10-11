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
#include "iot_gpio.h"
#include "stdbool.h"
#include "gd32f4xx_rcu.h"

#define GPIO_PERIPH(x) (((x)&0xF0) >> 4)
#define GPIO_PIN(x) ((x)&0x0F)
#define RCU_PERIPH(x) (((x)&0xF0) >> 4)
#define PRE_PRIORITY (2U)
#define SUB_PRIORITY (0U)
#define INPUT_MODE_BYTE (2U)

static unsigned int port_id = 0;
static unsigned int pin_id = 0;
static unsigned int rcu_port_id = 0;
static unsigned int exti5_9_pin_id = 0;
static unsigned int exti10_15_pin_id = 0;

const unsigned int gpio_port_arr[9] = {
    GPIOA, GPIOB, GPIOC, GPIOD, GPIOE, GPIOF, GPIOG, GPIOH, GPIOI,
};

const unsigned int rcu_port_arr[9] = {
    RCU_GPIOA, RCU_GPIOB, RCU_GPIOC, RCU_GPIOD, RCU_GPIOE, RCU_GPIOF, RCU_GPIOG, RCU_GPIOH, RCU_GPIOI,
};

const unsigned int exti_port_arr[9] = {
    EXTI_SOURCE_GPIOA, EXTI_SOURCE_GPIOB, EXTI_SOURCE_GPIOC, EXTI_SOURCE_GPIOD, EXTI_SOURCE_GPIOE,
    EXTI_SOURCE_GPIOF, EXTI_SOURCE_GPIOG, EXTI_SOURCE_GPIOH, EXTI_SOURCE_GPIOI,
};

const unsigned int exti_pin_arr[16] = {
    EXTI_SOURCE_PIN0,  EXTI_SOURCE_PIN1,  EXTI_SOURCE_PIN2,  EXTI_SOURCE_PIN3,  EXTI_SOURCE_PIN4,  EXTI_SOURCE_PIN5,
    EXTI_SOURCE_PIN6,  EXTI_SOURCE_PIN7,  EXTI_SOURCE_PIN8,  EXTI_SOURCE_PIN9,  EXTI_SOURCE_PIN10, EXTI_SOURCE_PIN11,
    EXTI_SOURCE_PIN12, EXTI_SOURCE_PIN13, EXTI_SOURCE_PIN14, EXTI_SOURCE_PIN15,
};

unsigned int IoTGpioInit(unsigned int id)
{
    rcu_port_id = RCU_PERIPH(id);
    rcu_periph_clock_enable(rcu_port_arr[rcu_port_id]);
    return IOT_SUCCESS;
}

unsigned int IoTGpioSetDir(unsigned int id, IotGpioDir dir)
{
    port_id = GPIO_PERIPH(id);
    pin_id = GPIO_PIN(id);
    if (IOT_GPIO_DIR_IN == dir) {
        gpio_mode_set(gpio_port_arr[port_id], GPIO_MODE_INPUT, GPIO_PUPD_NONE, BIT(pin_id));
    } else if (IOT_GPIO_DIR_OUT == dir) {
        gpio_mode_set(gpio_port_arr[port_id], GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, BIT(pin_id));
        gpio_output_options_set(gpio_port_arr[port_id], GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, BIT(pin_id));
    }
    return IOT_SUCCESS;
}

unsigned int IoTGpioGetDir(unsigned int id, IotGpioDir *dir)
{
    port_id = GPIO_PERIPH(id);
    pin_id = GPIO_PIN(id);
    unsigned int reg_ctl_val = GPIO_CTL(gpio_port_arr[port_id]);
    *dir = (uint8_t)((reg_ctl_val >> (INPUT_MODE_BYTE * pin_id)) & 0xff);
    return IOT_SUCCESS;
}

unsigned int IoTGpioSetOutputVal(unsigned int id, IotGpioValue val)
{
    port_id = GPIO_PERIPH(id);
    pin_id = GPIO_PIN(id);
    if (IOT_GPIO_VALUE0 == val) {
        gpio_bit_reset(gpio_port_arr[port_id], BIT(pin_id));
    } else if (IOT_GPIO_VALUE1 == val) {
        gpio_bit_set(gpio_port_arr[port_id], BIT(pin_id));
    }
    return IOT_SUCCESS;
}

unsigned int IoTGpioGetOutputVal(unsigned int id, IotGpioValue *val)
{
    port_id = GPIO_PERIPH(id);
    pin_id = GPIO_PIN(id);
    *val = gpio_output_bit_get(gpio_port_arr[port_id], pin_id);
    return IOT_SUCCESS;
}

unsigned int IoTGpioGetInputVal(unsigned int id, IotGpioValue *val)
{
    port_id = GPIO_PERIPH(id);
    pin_id = GPIO_PIN(id);
    *val = gpio_input_bit_get(gpio_port_arr[port_id], pin_id);
    return IOT_SUCCESS;
}

unsigned int IoTGpioRegisterIsrFunc(unsigned int id, IotGpioIntType intType, IotGpioIntPolarity intPolarity,
                                    GpioIsrCallbackFunc func, char *arg)
{
    if (intType != IOT_INT_TYPE_LEVEL && intType != IOT_INT_TYPE_LEVEL) {
        return IOT_FAILURE;
    }
    if (intPolarity != IOT_GPIO_EDGE_FALL_LEVEL_LOW && intPolarity != IOT_GPIO_EDGE_RISE_LEVEL_HIGH) {
        return IOT_FAILURE;
    }
    port_id = GPIO_PERIPH(id);
    pin_id = GPIO_PIN(id);
    rcu_port_id = RCU_PERIPH(id);

    rcu_periph_clock_enable(rcu_port_arr[rcu_port_id]);
    rcu_periph_clock_enable(RCU_SYSCFG);

    gpio_mode_set(gpio_port_arr[port_id], GPIO_MODE_INPUT, GPIO_PUPD_NONE, BIT(pin_id));
    /* enable and set EXTI interrupt to the lowest priority */
    nvic_irq_enable(EXTI0_IRQn, PRE_PRIORITY, SUB_PRIORITY);
    syscfg_exti_line_config(exti_port_arr[port_id], exti_pin_arr[pin_id]);

    if (IOT_GPIO_EDGE_FALL_LEVEL_LOW == intPolarity) {
        exti_init(BIT(pin_id), EXTI_INTERRUPT, EXTI_TRIG_FALLING);
    } else {
        exti_init(BIT(pin_id), EXTI_INTERRUPT, EXTI_TRIG_RISING);
    }
    exti_interrupt_flag_clear(BIT(pin_id));
    return IOT_SUCCESS;
}

unsigned int IoTGpioUnregisterIsrFunc(unsigned int id)
{
    port_id = GPIO_PERIPH(id);
    gpio_deinit(gpio_port_arr[port_id]);
    return IOT_SUCCESS;
}

unsigned int IoTGpioSetIsrMask(unsigned int id, unsigned char mask)
{
    pin_id = GPIO_PIN(id);
    exti_interrupt_flag_clear(BIT(pin_id));
    return IOT_SUCCESS;
}

unsigned int IoTGpioSetIsrMode(unsigned int id, IotGpioIntType intType, IotGpioIntPolarity intPolarity)
{
    if (intType != IOT_INT_TYPE_LEVEL && intType != IOT_INT_TYPE_LEVEL) {
        return IOT_FAILURE;
    }
    if (intPolarity != IOT_GPIO_EDGE_FALL_LEVEL_LOW && intPolarity != IOT_GPIO_EDGE_RISE_LEVEL_HIGH) {
        return IOT_FAILURE;
    }
    port_id = GPIO_PERIPH(id);
    pin_id = GPIO_PIN(id);
    rcu_port_id = RCU_PERIPH(id);
    rcu_periph_clock_enable(rcu_port_arr[rcu_port_id]);
    rcu_periph_clock_enable(RCU_SYSCFG);
    gpio_mode_set(gpio_port_arr[port_id], GPIO_MODE_INPUT, GPIO_PUPD_NONE, BIT(pin_id));
    /* enable and set EXTI interrupt to the lowest priority */
    nvic_irq_enable(EXTI0_IRQn, PRE_PRIORITY, SUB_PRIORITY);
    syscfg_exti_line_config(exti_port_arr[port_id], exti_pin_arr[pin_id]);
    if (IOT_GPIO_EDGE_FALL_LEVEL_LOW == intPolarity) {
        exti_init(BIT(pin_id), EXTI_INTERRUPT, EXTI_TRIG_FALLING);
    } else {
        exti_init(BIT(pin_id), EXTI_INTERRUPT, EXTI_TRIG_RISING);
    }
    exti_interrupt_flag_clear(BIT(pin_id));
    return IOT_SUCCESS;
}

unsigned int IoTGpioDeinit(unsigned int id)
{
    port_id = GPIO_PERIPH(id);
    pin_id = GPIO_PIN(id);
    rcu_port_id = RCU_PERIPH(id);
    if (IOT_SUCCESS == IoTGpioUnregisterIsrFunc(id)) {
        rcu_periph_clock_disable(rcu_port_arr[rcu_port_id]);
    }
    gpio_mode_set(gpio_port_arr[port_id], GPIO_MODE_INPUT, GPIO_PUPD_NONE, BIT(pin_id));
    return IOT_SUCCESS;
}