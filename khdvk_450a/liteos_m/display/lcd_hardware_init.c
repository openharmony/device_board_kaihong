/*
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http:// www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lcd_hardware_init.h"

#define LCD_SPI_CS(a)                                                                                                  \
    do {                                                                                                               \
        if (a) {                                                                                                       \
            gpio_bit_set(LCD_CS_GPIO_PORT, LCD_CS_PIN);                                                                \
        } else {                                                                                                       \
            gpio_bit_reset(LCD_CS_GPIO_PORT, LCD_CS_PIN);                                                              \
        }                                                                                                              \
    } while (0)
#define SPI_DCLK(a)                                                                                                    \
    do {                                                                                                               \
        if (a) {                                                                                                       \
            gpio_bit_set(LCD_SPI_SCK_GPIO_PORT, LCD_SPI_SCK_PIN);                                                      \
        } else {                                                                                                       \
            gpio_bit_reset(LCD_SPI_SCK_GPIO_PORT, LCD_SPI_SCK_PIN);                                                    \
        }                                                                                                              \
    } while (0)
#define SPI_SDA(a)                                                                                                     \
    do {                                                                                                               \
        if (a) {                                                                                                       \
            gpio_bit_set(LCD_SPI_MOSI_GPIO_PORT, LCD_SPI_MOSI_PIN);                                                    \
        } else {                                                                                                       \
            gpio_bit_reset(LCD_SPI_MOSI_GPIO_PORT, LCD_SPI_MOSI_PIN);                                                  \
        }                                                                                                              \
    } while (0)

#define DELAY_120_MS 120
#define DELAY_20_MS 20
#define WRITE_OFFSET 8
static void delay(uint32_t count);

/*!
    \brief      enable the LCD
    \param[in]  none
    \param[out] none
    \retval     none
*/
void lcdEnable(void)
{
    gpio_bit_set(LCD_CS_GPIO_PORT, LCD_CS_PIN);
}

/*!
    \brief      disable the LCD
    \param[in]  none
    \param[out] none
    \retval     none
*/
void lcdDisable(void)
{
    gpio_bit_reset(LCD_CS_GPIO_PORT, LCD_CS_PIN);
}

/*!
    \brief      configure the LCD control line
    \param[in]  none
    \param[out] none
    \retval     none
*/
void lcdCtrlGpioConfig(void)
{
    /* enable GPIOs clock */
    rcu_periph_clock_enable(LCD_CS_GPIO_CLK);
    rcu_periph_clock_enable(LCD_RS_GPIO_CLK);

    /* configure LCD_CS_GPIO_PORT(PD11) and LCD_RS_GPIO_PORT(PE3) */
    gpio_mode_set(LCD_CS_GPIO_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, LCD_CS_PIN);
    gpio_output_options_set(LCD_CS_GPIO_PORT, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, LCD_CS_PIN);

    gpio_mode_set(LCD_RS_GPIO_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, LCD_RS_PIN);
    gpio_output_options_set(LCD_RS_GPIO_PORT, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, LCD_RS_PIN);

    /* set the chip select pin */
    lcdCtrlLineSet(LCD_CS_GPIO_PORT, LCD_CS_PIN);
}

/*!
    \brief      set the LCD control line
    \param[in]  gpiox: control line GPIO
      \arg        LCD_CS_GPIO_PORT: LCD chip select GPIO
      \arg        LCD_RS_GPIO_PORT: LCD register/RAM selection GPIO
    \param[in]  gpiopin: control line pin
      \arg        LCD_CS_PIN: LCD chip select pin
      \arg        LCD_RS_PIN: LCD register/RAM selection pin
    \param[out] none
    \retval     none
*/
void lcdCtrlLineSet(uint32_t gpiox, uint16_t gpiopin)
{
    gpio_bit_set(gpiox, gpiopin);
}

/*!
    \brief      reset the LCD control line
    \param[in]  gpiox: control line GPIO
      \arg        LCD_CS_GPIO_PORT: LCD chip select GPIO
      \arg        LCD_RS_GPIO_PORT: LCD register/RAM selection GPIO
    \param[in]  gpiopin: control line pin
      \arg        LCD_CS_PIN: LCD chip select pin
      \arg        LCD_RS_PIN: LCD register/RAM selection pin
    \param[out] none
    \retval     none
*/
void lcdCtrlLineReset(uint32_t gpiox, uint16_t gpiopin)
{
    gpio_bit_reset(gpiox, gpiopin);
}

/*!
    \brief      configure the LCD SPI and it's GPIOs
    \param[in]  none
    \param[out] none
    \retval     none
*/
void InitLcdSpiGpio(void)
{
    /* GPIO clock enable */
    rcu_periph_clock_enable(LCD_SPI_SCK_GPIO_CLK);
    rcu_periph_clock_enable(LCD_SPI_MOSI_GPIO_CLK);

    /* configure the LCD SPI pins */
    gpio_mode_set(LCD_SPI_SCK_GPIO_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, LCD_SPI_SCK_PIN);
    gpio_output_options_set(LCD_SPI_SCK_GPIO_PORT, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, LCD_SPI_SCK_PIN);
    gpio_mode_set(LCD_SPI_MOSI_GPIO_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, LCD_SPI_MOSI_PIN);
    gpio_output_options_set(LCD_SPI_MOSI_GPIO_PORT, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, LCD_SPI_MOSI_PIN);
}

/*!
    \brief      write command to select LCD register
    \param[in]  lcd_register: the address of the selected register
    \param[out] none
    \retval     none
*/
void lcdCommandWrite(uint8_t lcd_register)
{
    /* reset LCD_RS to send command */
    lcdCtrlLineReset(LCD_RS_GPIO_PORT, LCD_RS_PIN);

    /* reset LCD control line and send command */
    lcdDisable();
    while (RESET == spi_i2s_flag_get(LCD_SPI, SPI_FLAG_TBE)) { }
    spi_i2s_data_transmit(LCD_SPI, lcd_register);

    /* wait until a data is sent */
    while (RESET != spi_i2s_flag_get(LCD_SPI, SPI_FLAG_TRANS)) { }

    lcdEnable();
}

/*!
    \brief      write data to select LCD register
    \param[in]  value: the value that will be written to the selected register
    \param[out] none
    \retval     none
*/
void lcdDateWrite(uint8_t value)
{
    /* set LCD_RS to send data */
    lcdCtrlLineSet(LCD_RS_GPIO_PORT, LCD_RS_PIN);

    /* reset LCD control line and send data */
    lcdDisable();
    while (RESET == spi_i2s_flag_get(LCD_SPI, SPI_FLAG_TBE)) { }

    spi_i2s_data_transmit(LCD_SPI, value);

    /* wait until a data is sent */
    while (RESET != spi_i2s_flag_get(LCD_SPI, SPI_FLAG_TRANS)) { }

    lcdEnable();
}

/*!
    \brief      GPIO emulated SPI byte write
    \param[in]  byte: data to be sent
    \param[out] none
    \retval     none
*/
void spiIOByteWrite(unsigned char byteIn)
{
    unsigned char n;
    unsigned char byte = byteIn;
    for (n = 0; n < WRITE_OFFSET; n++) {
        if (byte & 0x80) {
            SPI_SDA(1);
        } else {
            SPI_SDA(0);
        }
        byte <<= 1;

        SPI_DCLK(0);
        SPI_DCLK(1);
    }
}

/*!
    \brief      GPIO emulated SPI write command
    \param[in]  cmd: command to be sent
    \param[out] none
    \retval     none
*/
void spiIOCommandWrite(uint8_t cmd)
{
    LCD_SPI_CS(0);
    SPI_SDA(0);
    SPI_DCLK(0);
    SPI_DCLK(1);
    spiIOByteWrite(cmd);

    LCD_SPI_CS(1);
}

/*!
    \brief      GPIO emulated SPI write data
    \param[in]  tem_data: data to be sent
    \param[out] none
    \retval     none
*/
void spiIODateWrite(uint8_t tem_data)
{
    LCD_SPI_CS(0);
    SPI_SDA(1);
    SPI_DCLK(0);
    SPI_DCLK(1);
    spiIOByteWrite(tem_data);
    LCD_SPI_CS(1);
}

void InitLcdRegisterBefore(void)
{
    delay(DELAY_120_MS);

    LCD_SPI_CS(1);
    delay(DELAY_20_MS);
    LCD_SPI_CS(0);

    spiIOCommandWrite(0xE0); // P-Gamma
    spiIODateWrite(0x00);
    spiIODateWrite(0x10);
    spiIODateWrite(0x14);
    spiIODateWrite(0x03);
    spiIODateWrite(0x0E);
    spiIODateWrite(0x04);
    spiIODateWrite(0x36);
    spiIODateWrite(0x56);
    spiIODateWrite(0x4B);
    spiIODateWrite(0x04);
    spiIODateWrite(0x0C);
    spiIODateWrite(0x0A);
    spiIODateWrite(0x30);
    spiIODateWrite(0x34);
    spiIODateWrite(0x0F);

    spiIOCommandWrite(0XE1); // N-Gamma
    spiIODateWrite(0x00);
    spiIODateWrite(0x0E);
    spiIODateWrite(0x13);
    spiIODateWrite(0x03);
    spiIODateWrite(0x10);
    spiIODateWrite(0x06);
    spiIODateWrite(0x3E);
    spiIODateWrite(0x34);
    spiIODateWrite(0x55);
    spiIODateWrite(0x05);
    spiIODateWrite(0x0F);
    spiIODateWrite(0x0E);
    spiIODateWrite(0x3A);
    spiIODateWrite(0x3E);
    spiIODateWrite(0x0F);
}
void InitLcdRegister(void)
{
    InitLcdRegisterBefore();
    spiIOCommandWrite(0XC0); // Power Control 1
    spiIODateWrite(0x0F);    // Vreg1out
    spiIODateWrite(0x0C);    // Verg2out

    spiIOCommandWrite(0xC1); // Power Control 2
    spiIODateWrite(0x41);    // VGH,VGL

    spiIOCommandWrite(0xC5); // Power Control 3
    spiIODateWrite(0x00);
    spiIODateWrite(0x21); // Vcom
    spiIODateWrite(0x80);

    spiIOCommandWrite(0x2a);
    spiIODateWrite(0 >> WRITE_OFFSET);
    spiIODateWrite(0);
    spiIODateWrite(LCD_PIXEL_WIDTH >> WRITE_OFFSET);
    spiIODateWrite((uint8_t)LCD_PIXEL_WIDTH);

    spiIOCommandWrite(0x2b);
    spiIODateWrite(0 >> WRITE_OFFSET);
    spiIODateWrite(0);
    spiIODateWrite(LCD_PIXEL_HEIGHT >> WRITE_OFFSET);
    spiIODateWrite((uint8_t)LCD_PIXEL_HEIGHT);

    spiIOCommandWrite(0x36); // Memory Access
    spiIODateWrite(0x48);

    spiIOCommandWrite(0x3A); //  Interface Pixel Format
    spiIODateWrite(0x66);    // 18bit
    // spiIODateWrite(0x55);    // 16bit

    spiIOCommandWrite(0XB0); //  Interface Mode Control
    spiIODateWrite(0x00);

    spiIOCommandWrite(0xB1); // Frame rate
    spiIODateWrite(0xA0);    // 60Hz

    spiIOCommandWrite(0xB4); // Display Inversion Control
    spiIODateWrite(0x02);    // 2-dot

    spiIOCommandWrite(0XB6); // RGB/MCU Interface Control
    spiIODateWrite(0x22);    // MCU
    spiIODateWrite(0x02);    // Source,Gate scan dieection

    spiIOCommandWrite(0XE9); //  Set Image Function
    spiIODateWrite(0x00);    // disable 24 bit data input

    spiIOCommandWrite(0xF7); // Adjust Control
    spiIODateWrite(0xA9);
    spiIODateWrite(0x51);
    spiIODateWrite(0x2C);
    spiIODateWrite(0x82); // D7 stream, loose

    spiIOCommandWrite(0x21); // Normal Black

    spiIOCommandWrite(0x11); // Sleep out
    delay(DELAY_120_MS);
    spiIOCommandWrite(0x29); // Display on

    delay(DELAY_120_MS);
}

/*!
    \brief      insert a delay time
    \param[in]  count: delay time
    \param[out] none
    \retval     none
*/
static void delay(__IO uint32_t count)
{
    __IO uint32_t index = 0;
    for (index = count; index != 0; index--) { }
}
