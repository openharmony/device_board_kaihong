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
#include "hdf_log.h"
#include "los_task.h"
#include "gd32f4xx.h"
#include "lcd_hardware_init.h"
#include "tli_ipa_config.h"

#define HORIZONTAL_SYNCHRONOUS_PULSE 10
#define HORIZONTAL_BACK_PORCH 20
#define ACTIVE_WIDTH 320
#define HORIZONTAL_FRONT_PORCH 40

#define VERTICAL_SYNCHRONOUS_PULSE 2
#define VERTICAL_BACK_PORCH 2
#define ACTIVE_HEIGHT 480
#define VERTICAL_FRONT_PORCH 4
#define PLLSAI_N 108
#define PLLSAI_P 2
#define PLLSAI_R 3
#define WIDTH_DOUBLE 2
#define WIDTH_OFFSET 3
/*!
    \brief      LCD configuration
    \param[in]  none
    \param[out] none
    \retval     none
*/
void InitLcdGpio(void)
{
    /* configure the LCD control line */
    lcdCtrlGpioConfig();
    lcdDisable();
    lcdEnable();

    /* configure the GPIO of TLI */
    InitTliGpio();

    /* configure the LCD_SPI */
    InitLcdSpiGpio();
}

void SetLcdBackgroundLayer(void)
{
    tli_parameter_struct tli_init_struct;

    /* initialize the parameters of structure */
    tli_struct_para_init(&tli_init_struct);

    /* TLI initialization */
    tli_init_struct.signalpolarity_hs = TLI_HSYN_ACTLIVE_LOW;
    tli_init_struct.signalpolarity_vs = TLI_VSYN_ACTLIVE_LOW;
    tli_init_struct.signalpolarity_de = TLI_DE_ACTLIVE_LOW;
    tli_init_struct.signalpolarity_pixelck = TLI_PIXEL_CLOCK_INVERTEDTLI;

    tli_init_struct.synpsz_hpsz = HORIZONTAL_SYNCHRONOUS_PULSE - 1;
    tli_init_struct.synpsz_vpsz = VERTICAL_SYNCHRONOUS_PULSE - 1;
    tli_init_struct.backpsz_hbpsz = HORIZONTAL_SYNCHRONOUS_PULSE + HORIZONTAL_BACK_PORCH - 1;
    tli_init_struct.backpsz_vbpsz = VERTICAL_SYNCHRONOUS_PULSE + VERTICAL_BACK_PORCH - 1;
    tli_init_struct.activesz_hasz = HORIZONTAL_SYNCHRONOUS_PULSE + HORIZONTAL_BACK_PORCH + ACTIVE_WIDTH - 1;
    tli_init_struct.activesz_vasz = VERTICAL_SYNCHRONOUS_PULSE + VERTICAL_BACK_PORCH + ACTIVE_HEIGHT - 1;
    tli_init_struct.totalsz_htsz =
        HORIZONTAL_SYNCHRONOUS_PULSE + HORIZONTAL_BACK_PORCH + ACTIVE_WIDTH + HORIZONTAL_FRONT_PORCH - 1;
    tli_init_struct.totalsz_vtsz =
        VERTICAL_SYNCHRONOUS_PULSE + VERTICAL_BACK_PORCH + ACTIVE_HEIGHT + VERTICAL_FRONT_PORCH - 1;

    /* LCD background color configure */
    tli_init_struct.backcolor_red = 0xFF;
    tli_init_struct.backcolor_green = 0xFF;
    tli_init_struct.backcolor_blue = 0xFF;
    tli_init(&tli_init_struct);
}

int32_t SetLcdFrontLayer(uint32_t layerId, uint32_t left, uint32_t top, uint32_t pictureWidth, uint32_t pictureHeight,
                         uint32_t pictureBuffer)
{
    uint32_t layerX;
    tli_layer_parameter_struct tli_layer_init_struct;
    /* initialize the parameters of structure */
    tli_layer_struct_para_init(&tli_layer_init_struct);

    if (layerId > 1) {
        HDF_LOGE("layerId(%d) is more than 1\n", layerId);
        return -1;
    }

    if ((left + pictureWidth) > ACTIVE_WIDTH) {
        HDF_LOGE("total width is out of range [0, %d]\n", ACTIVE_WIDTH);
        return -1;
    }

    if ((top + pictureHeight) > ACTIVE_HEIGHT) {
        HDF_LOGE("total height is out of range [0, %d]\n", ACTIVE_HEIGHT);
        return -1;
    }

    if (layerId == 0) {
        layerX = LAYER0;
    } else {
        layerX = LAYER1;
    }

    tli_layer_init_struct.layer_window_leftpos = (0 + left + HORIZONTAL_SYNCHRONOUS_PULSE + HORIZONTAL_BACK_PORCH);
    tli_layer_init_struct.layer_window_rightpos =
        (pictureWidth + left + HORIZONTAL_SYNCHRONOUS_PULSE + HORIZONTAL_BACK_PORCH - 1);
    tli_layer_init_struct.layer_window_toppos = (0 + top + VERTICAL_SYNCHRONOUS_PULSE + VERTICAL_BACK_PORCH);
    tli_layer_init_struct.layer_window_bottompos =
        (pictureHeight + top + VERTICAL_SYNCHRONOUS_PULSE + VERTICAL_BACK_PORCH - 1);

    tli_layer_init_struct.layer_ppf = LAYER_PPF_RGB565;
    tli_layer_init_struct.layer_sa = 0xFF;
    tli_layer_init_struct.layer_acf1 = LAYER_ACF1_PASA;
    tli_layer_init_struct.layer_acf2 = LAYER_ACF2_PASA;
    tli_layer_init_struct.layer_default_alpha = 0;
    tli_layer_init_struct.layer_default_blue = 0;
    tli_layer_init_struct.layer_default_green = 0;
    tli_layer_init_struct.layer_default_red = 0;
    tli_layer_init_struct.layer_frame_bufaddr = pictureBuffer;
    tli_layer_init_struct.layer_frame_line_length = ((pictureWidth * WIDTH_DOUBLE) + WIDTH_OFFSET);
    tli_layer_init_struct.layer_frame_buf_stride_offset = (pictureWidth * WIDTH_DOUBLE);
    tli_layer_init_struct.layer_frame_total_line_number = pictureHeight;
    tli_layer_init(layerX, &tli_layer_init_struct);

    return 0;
}

/*!
    \brief      configure TLI peripheral
    \param[in]  none
    \param[out] none
    \retval     none
*/
void ConfigTli(void)
{
    tli_parameter_struct tli_init_struct;
    tli_layer_parameter_struct tli_layer_init_struct;

    /* initialize the parameters of structure */
    tli_struct_para_init(&tli_init_struct);
    tli_layer_struct_para_init(&tli_layer_init_struct);

    rcu_periph_clock_enable(RCU_TLI);

    /* configure the PLLSAI clock to generate lcd clock */
    if (ERROR == rcu_pllsai_config(PLLSAI_N, PLLSAI_P, PLLSAI_R)) {
        while (1) { }
    }
    rcu_tli_clock_div_config(RCU_PLLSAIR_DIV4);
    rcu_osci_on(RCU_PLLSAI_CK);
    if (ERROR == rcu_osci_stab_wait(RCU_PLLSAI_CK)) {
        while (1) { }
    }
}

/*!
    \brief      IPA initialize and configuration
    \param[in]  none
    \param[out] none
    \retval     none
*/
int32_t ipaConfig(uint32_t width, uint32_t height, uint32_t srcAddr, uint32_t desAddr)
{
    ipa_destination_parameter_struct ipa_destination_init_struct;
    ipa_foreground_parameter_struct ipa_fg_init_struct;

    /* 如果目标层像素格式是ARGB8888，这些位必须是32位对齐，如果目标层像素格式是
    RGB565, ARGB1555或ARGB4444,这些位必须是16位对齐，如果违背以上对齐规
    则，当传输使能的时候，将检测到一个配置错误。 */
    ipa_foreground_struct_para_init(&ipa_fg_init_struct);
    ipa_destination_struct_para_init(&ipa_destination_init_struct);

    rcu_periph_clock_enable(RCU_IPA);

    ipa_deinit();
    /* IPA pixel format convert mode configure */
    ipa_pixel_format_convert_mode_set(IPA_FGTODE);
    /* destination pixel format configure */
    ipa_destination_init_struct.destination_pf = IPA_DPF_RGB565;
    /* destination memory base address configure */
    ipa_destination_init_struct.destination_memaddr = desAddr;
    /* destination pre-defined alpha value RGB configure */
    ipa_destination_init_struct.destination_pregreen = 0;
    ipa_destination_init_struct.destination_preblue = 0;
    ipa_destination_init_struct.destination_prered = 0;
    ipa_destination_init_struct.destination_prealpha = 0;
    /* destination line offset configure */
    ipa_destination_init_struct.destination_lineoff = 0;
    /* height of the image to be processed configure */
    ipa_destination_init_struct.image_height = height;
    /* width of the image to be processed configure */
    ipa_destination_init_struct.image_width = width;
    /* IPA destination initialization */
    ipa_destination_init(&ipa_destination_init_struct);

    /* IPA foreground configure */
    ipa_fg_init_struct.foreground_memaddr = srcAddr;
    ipa_fg_init_struct.foreground_pf = FOREGROUND_PPF_RGB565;
    ipa_fg_init_struct.foreground_alpha_algorithm = IPA_FG_ALPHA_MODE_0;
    ipa_fg_init_struct.foreground_prealpha = 0;
    ipa_fg_init_struct.foreground_lineoff = 0;
    ipa_fg_init_struct.foreground_preblue = 0;
    ipa_fg_init_struct.foreground_pregreen = 0;
    ipa_fg_init_struct.foreground_prered = 0;
    /* foreground initialization */
    ipa_foreground_init(&ipa_fg_init_struct);
}

/*!
    \brief      configure TLI peripheral and display blend image
    \param[in]  none
    \param[out] none
    \retval     none
*/
int32_t tliBlendConfig(uint32_t left, uint32_t top, uint32_t pictureWidth, uint32_t pictureHeight,
                       uint32_t pictureBuffer)
{
    SetLcdFrontLayer(1, left, top, pictureWidth, pictureHeight, pictureBuffer);

    return 0;
}
/*!
    \brief      configure TLI GPIO
    \param[in]  none
    \param[out] none
    \retval     none
*/
void InitTliGpio(void)
{
    /* enable the periphral clock */
    rcu_periph_clock_enable(RCU_GPIOA);
    rcu_periph_clock_enable(RCU_GPIOB);
    rcu_periph_clock_enable(RCU_GPIOC);
    rcu_periph_clock_enable(RCU_GPIOD);
    rcu_periph_clock_enable(RCU_GPIOF);
    rcu_periph_clock_enable(RCU_GPIOG);

    /* configure HSYNC(PC6), VSYNC(PA4), PCLK(PG7), DE(PF10) */
    /* configure LCD_R7(PG6), LCD_R6(PA8), LCD_R5(PA12), LCD_R4(PA11), LCD_R3(PB0),
                 LCD_G7(PD3), LCD_G6(PC7), LCD_G5(PB11), LCD_G4(PB10), LCD_G3(PG10), LCD_G2(PA6),
                 LCD_B7(PB9), LCD_B6(PB8), LCD_B5(PA3), LCD_B4(PG12), LCD_B3(PG11) */
    gpio_af_set(GPIOA, GPIO_AF_14, GPIO_PIN_3);
    gpio_af_set(GPIOA, GPIO_AF_14, GPIO_PIN_4);
    gpio_af_set(GPIOA, GPIO_AF_14, GPIO_PIN_6);
    gpio_af_set(GPIOA, GPIO_AF_14, GPIO_PIN_8);
    gpio_af_set(GPIOA, GPIO_AF_14, GPIO_PIN_11);
    gpio_af_set(GPIOA, GPIO_AF_14, GPIO_PIN_12);

    gpio_af_set(GPIOB, GPIO_AF_9, GPIO_PIN_0);
    gpio_af_set(GPIOB, GPIO_AF_14, GPIO_PIN_8);
    gpio_af_set(GPIOB, GPIO_AF_14, GPIO_PIN_9);
    gpio_af_set(GPIOB, GPIO_AF_14, GPIO_PIN_10);
    gpio_af_set(GPIOB, GPIO_AF_14, GPIO_PIN_11);

    gpio_af_set(GPIOC, GPIO_AF_14, GPIO_PIN_6);
    gpio_af_set(GPIOC, GPIO_AF_14, GPIO_PIN_7);

    gpio_af_set(GPIOD, GPIO_AF_14, GPIO_PIN_3);

    gpio_af_set(GPIOF, GPIO_AF_14, GPIO_PIN_10);

    gpio_af_set(GPIOG, GPIO_AF_14, GPIO_PIN_6);
    gpio_af_set(GPIOG, GPIO_AF_14, GPIO_PIN_7);
    gpio_af_set(GPIOG, GPIO_AF_9, GPIO_PIN_10);
    gpio_af_set(GPIOG, GPIO_AF_14, GPIO_PIN_11);
    gpio_af_set(GPIOG, GPIO_AF_9, GPIO_PIN_12);

    gpio_mode_set(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE,
                  GPIO_PIN_3 | GPIO_PIN_4 | GPIO_PIN_6 | GPIO_PIN_8 | GPIO_PIN_11 | GPIO_PIN_12);
    gpio_output_options_set(GPIOA, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ,
                            GPIO_PIN_3 | GPIO_PIN_4 | GPIO_PIN_6 | GPIO_PIN_8 | GPIO_PIN_11 | GPIO_PIN_12);

    gpio_mode_set(GPIOB, GPIO_MODE_AF, GPIO_PUPD_NONE,
                  GPIO_PIN_0 | GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10 | GPIO_PIN_11);
    gpio_output_options_set(GPIOB, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ,
                            GPIO_PIN_0 | GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10 | GPIO_PIN_11);

    gpio_mode_set(GPIOC, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO_PIN_6 | GPIO_PIN_7);
    gpio_output_options_set(GPIOC, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, GPIO_PIN_6 | GPIO_PIN_7);

    gpio_mode_set(GPIOD, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO_PIN_3);
    gpio_output_options_set(GPIOD, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, GPIO_PIN_3);

    gpio_mode_set(GPIOF, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO_PIN_10);
    gpio_output_options_set(GPIOF, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, GPIO_PIN_10);

    gpio_mode_set(GPIOG, GPIO_MODE_AF, GPIO_PUPD_NONE,
                  GPIO_PIN_6 | GPIO_PIN_7 | GPIO_PIN_10 | GPIO_PIN_11 | GPIO_PIN_12);
    gpio_output_options_set(GPIOG, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ,
                            GPIO_PIN_6 | GPIO_PIN_7 | GPIO_PIN_10 | GPIO_PIN_11 | GPIO_PIN_12);
}
