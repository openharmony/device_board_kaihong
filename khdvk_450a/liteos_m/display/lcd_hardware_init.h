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

#ifndef LCD_HARDWARE_INIT_H_
#define LCD_HARDWARE_INIT_H_

#include "gd32f4xx.h"

#define LCD_CS_PIN GPIO_PIN_11
#define LCD_CS_GPIO_PORT GPIOD
#define LCD_CS_GPIO_CLK RCU_GPIOD

#define LCD_RS_PIN GPIO_PIN_3
#define LCD_RS_GPIO_PORT GPIOE
#define LCD_RS_GPIO_CLK RCU_GPIOE

#define LCD_SPI_SCK_PIN GPIO_PIN_13
#define LCD_SPI_SCK_GPIO_PORT GPIOG
#define LCD_SPI_SCK_GPIO_CLK RCU_GPIOG

#define LCD_SPI_MOSI_PIN GPIO_PIN_14
#define LCD_SPI_MOSI_GPIO_PORT GPIOG
#define LCD_SPI_MOSI_GPIO_CLK RCU_GPIOG

#define LCD_SPI SPI5
#define LCD_SPI_CLK RCU_SPI5

#define LCD_PIXEL_WIDTH ((uint16_t)320)
#define LCD_PIXEL_HEIGHT ((uint16_t)480)

/* choose only one of them based on the version of LCD */
// #define USE_LCD_VERSION_1_1                /* LCD V1.1 or earlier */
// #define USE_LCD_VERSION_1_2                /* LCD V1.2 */
// #define USE_LCD_VERSION_1_3                /* LCD V1.3 (TK035F3296) */
#define USE_LCD_VERSION_1_4 /* LCD V1.4 (3LINE SPI + RGB) */

/* enable the LCD */
void lcdEnable(void);
/* disable the LCD */
void lcdDisable(void);
/* configure the LCD control line */
void lcdCtrlGpioConfig(void);
/* set the LCD control line */
void lcdCtrlLineSet(uint32_t gpiox, uint16_t gpiopin);
/* reset the LCD control line */
void lcdCtrlLineReset(uint32_t gpiox, uint16_t gpiopin);
/* configure the LCD SPI and it's GPIOs */
void InitLcdSpiGpio(void);
/* write command to select LCD register */
void lcdCommandWrite(uint8_t lcd_register);
/* write data to select LCD register */
void lcdDateWrite(uint8_t value);
/* configure the LCD based on the power on sequence 3(for V1.4 LCD, inanbo) */
void InitLcdRegister(void);

#endif /* _LCD_CONFIG_H_ */
