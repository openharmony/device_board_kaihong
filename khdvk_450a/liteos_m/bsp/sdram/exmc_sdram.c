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

#include "gd32f4xx.h"
#include "gd32f4xx_systick.h"
#include "exmc_sdram.h"

/* define mode register content */
/* burst length */
#define SDRAM_MODEREG_BURST_LENGTH_1 ((uint16_t)0x0000)
#define SDRAM_MODEREG_BURST_LENGTH_2 ((uint16_t)0x0001)
#define SDRAM_MODEREG_BURST_LENGTH_4 ((uint16_t)0x0002)
#define SDRAM_MODEREG_BURST_LENGTH_8 ((uint16_t)0x0003)

/* burst type */
#define SDRAM_MODEREG_BURST_TYPE_SEQUENTIAL ((uint16_t)0x0000)
#define SDRAM_MODEREG_BURST_TYPE_INTERLEAVED ((uint16_t)0x0008)

/* CAS latency */
#define SDRAM_MODEREG_CAS_LATENCY_2 ((uint16_t)0x0020)
#define SDRAM_MODEREG_CAS_LATENCY_3 ((uint16_t)0x0030)

/* write mode */
#define SDRAM_MODEREG_WRITEBURST_MODE_PROGRAMMED ((uint16_t)0x0000)
#define SDRAM_MODEREG_WRITEBURST_MODE_SINGLE ((uint16_t)0x0200)

#define SDRAM_MODEREG_OPERATING_MODE_STANDARD ((uint16_t)0x0000)

#define SDRAM_TIMEOUT ((uint32_t)0x0000FFFF)
#define ADDR_STEP ((uint16_t)2)
void clean_bss(void)
{
    volatile unsigned int *start = (volatile unsigned int *)&__bss_start__;
    volatile unsigned int *end = (volatile unsigned int *)&__bss_end__;

    printf("bss start is %p %p\n", __bss_start__, &__bss_start__);
    printf("bss end is %p %p\n", __bss_end__, &__bss_end__);
    while (start <= end) {
        *start++ = 0;
    }
}

/*!
    \brief      initialize sdram peripheral
    \param[in]  sdram_device: specify the SDRAM device
    \param[out] none
    \retval     none
*/
void sdram_rcu_periph_clock_enable(void)
{
    /* enable EXMC clock */
    rcu_periph_clock_enable(RCU_EXMC);
    rcu_periph_clock_enable(RCU_GPIOB);
    rcu_periph_clock_enable(RCU_GPIOC);
    rcu_periph_clock_enable(RCU_GPIOD);
    rcu_periph_clock_enable(RCU_GPIOE);
    rcu_periph_clock_enable(RCU_GPIOF);
    rcu_periph_clock_enable(RCU_GPIOG);
    rcu_periph_clock_enable(RCU_GPIOH);
}
void sdram_gpio_init(void)
{
    /* common GPIO configuration */
    /* SDNWE(PC0),SDNE0(PC2),SDCKE0(PC3) pin configuration */
    gpio_af_set(GPIOC, GPIO_AF_12, GPIO_PIN_0 | GPIO_PIN_2 | GPIO_PIN_3);
    gpio_mode_set(GPIOC, GPIO_MODE_AF, GPIO_PUPD_PULLUP, GPIO_PIN_0 | GPIO_PIN_2 | GPIO_PIN_3);
    gpio_output_options_set(GPIOC, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, GPIO_PIN_0 | GPIO_PIN_2 | GPIO_PIN_3);

    /* D2(PD0),D3(PD1),D13(PD8),D14(PD9),D15(PD10),D0(PD14),D1(PD15) pin configuration */
    gpio_af_set(GPIOD, GPIO_AF_12,
                GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10 | GPIO_PIN_14 | GPIO_PIN_15);
    gpio_mode_set(GPIOD, GPIO_MODE_AF, GPIO_PUPD_PULLUP,
                  GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10 | GPIO_PIN_14 | GPIO_PIN_15);
    gpio_output_options_set(GPIOD, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ,
                            GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10 | GPIO_PIN_14 |
                                GPIO_PIN_15);

    /* NBL0(PE0),NBL1(PE1),D4(PE7),D5(PE8),D6(PE9),D7(PE10),D8(PE11),
    D9(PE12),D10(PE13),D11(PE14),D12(PE15) pin configuration */
    gpio_af_set(GPIOE, GPIO_AF_12,
                GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_7 | GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10 | GPIO_PIN_11 |
                    GPIO_PIN_12 | GPIO_PIN_13 | GPIO_PIN_14 | GPIO_PIN_15);
    gpio_mode_set(GPIOE, GPIO_MODE_AF, GPIO_PUPD_PULLUP,
                  GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_7 | GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10 | GPIO_PIN_11 |
                      GPIO_PIN_12 | GPIO_PIN_13 | GPIO_PIN_14 | GPIO_PIN_15);
    gpio_output_options_set(GPIOE, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ,
                            GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_7 | GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10 | GPIO_PIN_11 |
                                GPIO_PIN_12 | GPIO_PIN_13 | GPIO_PIN_14 | GPIO_PIN_15);

    /* A0(PF0),A1(PF1),A2(PF2),A3(PF3),A4(PF4),A5(PF5),NRAS(PF11),
    A6(PF12),A7(PF13),A8(PF14),A9(PF15) pin configuration */
    gpio_af_set(GPIOF, GPIO_AF_12,
                GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3 | GPIO_PIN_4 | GPIO_PIN_5 | GPIO_PIN_11 |
                    GPIO_PIN_12 | GPIO_PIN_13 | GPIO_PIN_14 | GPIO_PIN_15);
    gpio_mode_set(GPIOF, GPIO_MODE_AF, GPIO_PUPD_PULLUP,
                  GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3 | GPIO_PIN_4 | GPIO_PIN_5 | GPIO_PIN_11 |
                      GPIO_PIN_12 | GPIO_PIN_13 | GPIO_PIN_14 | GPIO_PIN_15);
    gpio_output_options_set(GPIOF, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ,
                            GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3 | GPIO_PIN_4 | GPIO_PIN_5 | GPIO_PIN_11 |
                                GPIO_PIN_12 | GPIO_PIN_13 | GPIO_PIN_14 | GPIO_PIN_15);

    /* A10(PG0),A11(PG1),A12(PG2),A14(PG4),A15(PG5),SDCLK(PG8),NCAS(PG15) pin configuration */
    gpio_af_set(GPIOG, GPIO_AF_12,
                GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_4 | GPIO_PIN_5 | GPIO_PIN_8 | GPIO_PIN_15);
    gpio_mode_set(GPIOG, GPIO_MODE_AF, GPIO_PUPD_PULLUP,
                  GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_4 | GPIO_PIN_5 | GPIO_PIN_8 | GPIO_PIN_15);
    gpio_output_options_set(GPIOG, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ,
                            GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_4 | GPIO_PIN_5 | GPIO_PIN_8 | GPIO_PIN_15);
}

void sdram_timing_init_struct_configure(exmc_sdram_timing_parameter_struct *sdram_timing_init_struct)
{
     /* LMRD: 2 clock cycles */
    int16_t delay_t1 = 2;
    sdram_timing_init_struct->load_mode_register_delay = delay_t1;
    /* XSRD: min = 75ns */
    int16_t delay_t2 = 8;
    sdram_timing_init_struct->exit_selfrefresh_delay = delay_t2;
    /* RASD: min=44ns , max=120k (ns) */
    int16_t delay_t3 = 5;
    sdram_timing_init_struct->row_address_select_delay = delay_t3;
    /* ARFD: min=66ns */
    int16_t delay_t4 = 7;
    sdram_timing_init_struct->auto_refresh_delay = delay_t4;
    /* WRD:  min=1 Clock cycles +7.5ns */
    int16_t delay_t5 = 2;
    sdram_timing_init_struct->write_recovery_delay = delay_t5;
    /* RPD:  min=20ns */
    int16_t delay_t6 = 3;
    sdram_timing_init_struct->row_precharge_delay = delay_t6;
    /* RCD:  min=20ns */
    int16_t delay_t7 = 3;
    sdram_timing_init_struct->row_to_column_delay = delay_t7;
}
void sdram_init_struct_config(uint32_t sdram_device, exmc_sdram_parameter_struct *sdram_init_struct,
                              exmc_sdram_timing_parameter_struct *sdram_timing_init_struct)
{
    sdram_init_struct->sdram_device = sdram_device;
    sdram_init_struct->column_address_width = EXMC_SDRAM_COW_ADDRESS_9;
    sdram_init_struct->row_address_width = EXMC_SDRAM_ROW_ADDRESS_13;
    sdram_init_struct->data_width = EXMC_SDRAM_DATABUS_WIDTH_16B;
    sdram_init_struct->internal_bank_number = EXMC_SDRAM_4_INTER_BANK;
    sdram_init_struct->cas_latency = EXMC_CAS_LATENCY_3_SDCLK;
    sdram_init_struct->write_protection = DISABLE;
    sdram_init_struct->sdclock_config = EXMC_SDCLK_PERIODS_2_HCLK;
    sdram_init_struct->burst_read_switch = ENABLE;
    sdram_init_struct->pipeline_read_delay = EXMC_PIPELINE_DELAY_1_HCLK;
    sdram_init_struct->timing = sdram_timing_init_struct;
}
void sdram_command_init_struct_config(int step, uint32_t bank_select, uint32_t command_content,
                                      exmc_sdram_command_parameter_struct *sdram_command_init_struct)
{
    switch (step) {
        case 0x3:
            sdram_command_init_struct->command = EXMC_SDRAM_CLOCK_ENABLE;
            sdram_command_init_struct->bank_select = bank_select;
            sdram_command_init_struct->auto_refresh_number = EXMC_SDRAM_AUTO_REFLESH_1_SDCLK;
            sdram_command_init_struct->mode_register_content = 0;
            break;
        case 0x5:
            sdram_command_init_struct->command = EXMC_SDRAM_PRECHARGE_ALL;
            sdram_command_init_struct->bank_select = bank_select;
            sdram_command_init_struct->auto_refresh_number = EXMC_SDRAM_AUTO_REFLESH_1_SDCLK;
            sdram_command_init_struct->mode_register_content = 0;
            break;
        case 0x6:
            sdram_command_init_struct->command = EXMC_SDRAM_AUTO_REFRESH;
            sdram_command_init_struct->bank_select = bank_select;
            sdram_command_init_struct->auto_refresh_number = EXMC_SDRAM_AUTO_REFLESH_8_SDCLK;
            sdram_command_init_struct->mode_register_content = 0;
            break;
        case 0x7:
            sdram_command_init_struct->command = EXMC_SDRAM_LOAD_MODE_REGISTER;
            sdram_command_init_struct->bank_select = bank_select;
            sdram_command_init_struct->auto_refresh_number = EXMC_SDRAM_AUTO_REFLESH_1_SDCLK;
            sdram_command_init_struct->mode_register_content = command_content;
            break;
        default :
            break;
    }
}
ErrStatus time_out_check(uint32_t sdram_device)
{
    uint32_t timeout = SDRAM_TIMEOUT;
    while ((exmc_flag_get(sdram_device, EXMC_SDRAM_FLAG_NREADY) != RESET) && (timeout > 0)) {
        timeout--;
    }
    if (timeout == 0) {
        printf("in %s %s:%d timeout\n", __FILE__, __FUNCTION__, __LINE__);
        return ERROR;
    }
    return SUCCESS;
}
ErrStatus exmc_synchronous_dynamic_ram_init(uint32_t sdram_device)
{
    exmc_sdram_parameter_struct sdram_init_struct;
    exmc_sdram_timing_parameter_struct sdram_timing_init_struct;
    exmc_sdram_command_parameter_struct sdram_command_init_struct;
    uint32_t command_content = 0, bank_select;

    sdram_rcu_periph_clock_enable();

    sdram_gpio_init();
    /* specify which SDRAM to read and write */
    if (EXMC_SDRAM_DEVICE0 == sdram_device) {
        bank_select = EXMC_SDRAM_DEVICE0_SELECT;
    } else {
        bank_select = EXMC_SDRAM_DEVICE1_SELECT;
    }

    /* EXMC SDRAM device initialization sequence --------------------------------*/
    /* Step 1 : configure SDRAM timing registers --------------------------------*/
    sdram_timing_init_struct_configure(&sdram_timing_init_struct);

    /* step 2 : configure SDRAM control registers ---------------------------------*/
    sdram_init_struct_config(sdram_device, &sdram_init_struct, &sdram_timing_init_struct);
    /* EXMC SDRAM bank initialization */
    exmc_sdram_init(&sdram_init_struct);

    /* step 3 : configure CKE high command---------------------------------------*/
    sdram_command_init_struct_config(0x3, bank_select, command_content, &sdram_command_init_struct);
    /* wait until the SDRAM controller is ready */
    if (time_out_check(sdram_device) != SUCCESS) {
        return ERROR;
    }
    /* send the command */
    exmc_sdram_command_config(&sdram_command_init_struct);

    /* step 4 : insert 10ms delay----------------------------------------------*/
    int16_t delay_t8 = 10;
    Gd32f4xxDelay1ms(delay_t8);

    /* step 5 : configure precharge all command----------------------------------*/
    sdram_command_init_struct_config(0x5, bank_select, command_content, &sdram_command_init_struct);
    /* wait until the SDRAM controller is ready */
    if (time_out_check(sdram_device) != SUCCESS) {
        return ERROR;
    }
    /* send the command */
    exmc_sdram_command_config(&sdram_command_init_struct);

    /* step 6 : configure Auto-Refresh command-----------------------------------*/
    sdram_command_init_struct_config(0x6, bank_select, command_content, &sdram_command_init_struct);
    /* wait until the SDRAM controller is ready */
    if (time_out_check(sdram_device) != SUCCESS) {
        return ERROR;
    }
    /* send the command */
    exmc_sdram_command_config(&sdram_command_init_struct);

    /* step 7 : configure load mode register command-----------------------------*/
    /* program mode register */
    command_content = (uint32_t)SDRAM_MODEREG_BURST_LENGTH_1 | SDRAM_MODEREG_BURST_TYPE_SEQUENTIAL |
                      SDRAM_MODEREG_CAS_LATENCY_3 | SDRAM_MODEREG_OPERATING_MODE_STANDARD |
                      SDRAM_MODEREG_WRITEBURST_MODE_SINGLE;

    sdram_command_init_struct_config(0x7, bank_select, command_content, &sdram_command_init_struct);

    /* wait until the SDRAM controller is ready */
    if (time_out_check(sdram_device) != SUCCESS) {
        return ERROR;
    }
    /* send the command */
    exmc_sdram_command_config(&sdram_command_init_struct);

    /* step 8 : set the auto-refresh rate counter--------------------------------*/
    /* 64ms, 8192-cycle refresh, 64ms/8192=7.81us */
    /* SDCLK_Freq = SYS_Freq/2 */
    /* (7.81 us * SDCLK_Freq) - 20 */
    int16_t auto_refresh_iterval = 761;
    exmc_sdram_refresh_count_set(auto_refresh_iterval);

    /* wait until the SDRAM controller is ready */
    if (time_out_check(sdram_device) != SUCCESS) {
        return ERROR;
    }
    int16_t delay_t9 = 500;
    Gd32f4xxDelay1ms(delay_t9);

    printf("*********************clean_bss\n");
    clean_bss();
    return SUCCESS;
}

/*!
    \brief      fill the buffer with specified value
    \param[in]  pbuffer: pointer on the buffer to fill
    \param[in]  buffer_lengh: size of the buffer to fill
    \param[in]  offset: the initial value to fill in the buffer
    \param[out] none
    \retval     none
*/
void fill_buffer(uint8_t *pbuffer, uint16_t buffer_lengh, uint16_t offset)
{
    uint16_t index = 0;

    /* fill the buffer with specified values */
    for (index = 0; index < buffer_lengh; index++) {
        pbuffer[index] = 0x10 + index + offset;
    }
}

/*!
    \brief      write a byte buffer(data is 8 bits) to the EXMC SDRAM memory
    \param[in]  sdram_device: specify which a SDRAM memory block is written
    \param[in]  pbuffer: pointer to buffer
    \param[in]  writeaddr: SDRAM memory internal address from which the data will be written
    \param[in]  numbytetowrite: number of bytes to write
    \param[out] none
    \retval     none
*/
void sdram_writebuffer_8(uint32_t sdram_device, uint8_t *pbuffer, uint32_t writeaddr, uint32_t numbytetowrite)
{
    uint32_t temp_addr;

    /* Select the base address according to EXMC_Bank */
    if (sdram_device == EXMC_SDRAM_DEVICE0) {
        temp_addr = SDRAM_DEVICE0_ADDR;
    } else {
        temp_addr = SDRAM_DEVICE1_ADDR;
    }

    /* While there is data to write */
    for (; numbytetowrite != 0; numbytetowrite--) {
        /* Transfer data to the memory */
        *(uint8_t *)(temp_addr + writeaddr) = *pbuffer++;

        /* Increment the address */
        writeaddr += 1;
    }
}

/*!
    \brief      read a block of 8-bit data from the EXMC SDRAM memory
    \param[in]  sdram_device: specify which a SDRAM memory block is written
    \param[in]  pbuffer: pointer to buffer
    \param[in]  readaddr: SDRAM memory internal address to read from
    \param[in]  numbytetoread: number of bytes to read
    \param[out] none
    \retval     none
*/
void sdram_readbuffer_8(uint32_t sdram_device, uint8_t *pbuffer, uint32_t readaddr, uint32_t numbytetoread)
{
    uint32_t temp_addr;

    /* select the base address according to EXMC_Bank */
    if (sdram_device == EXMC_SDRAM_DEVICE0) {
        temp_addr = SDRAM_DEVICE0_ADDR;
    } else {
        temp_addr = SDRAM_DEVICE1_ADDR;
    }

    /* while there is data to read */
    for (; numbytetoread != 0; numbytetoread--) {
        /* read a byte from the memory */
        *pbuffer++ = *(uint8_t *)(temp_addr + readaddr);

        /* increment the address */
        readaddr += 1;
    }
}

/*!
    \brief      write a half-word buffer(data is 16 bits) to the EXMC SDRAM memory
    \param[in]  sdram_device: specify which a SDRAM memory block is written
    \param[in]  pbuffer: pointer to buffer
    \param[in]  writeaddr: SDRAM memory internal address from which the data will be written
    \param[in]  numbytetowrite: number of half-word to write
    \param[out] none
    \retval     none
*/
void sdram_writebuffer_16(uint32_t sdram_device, uint16_t *pbuffer, uint32_t writeaddr, uint32_t numtowrite)
{
    uint32_t temp_addr;
    __IO uint32_t write_addr_prt = writeaddr;

    /* Select the base address according to EXMC_Bank */
    if (sdram_device == EXMC_SDRAM_DEVICE0) {
        temp_addr = SDRAM_DEVICE0_ADDR;
    } else {
        temp_addr = SDRAM_DEVICE1_ADDR;
    }

    /* While there is data to write */
    for (; numtowrite != 0; numtowrite--) {
        /* Transfer data to the memory */
        *(uint16_t *)(temp_addr + write_addr_prt) = *pbuffer++;

        /* Increment the address */
        write_addr_prt += ADDR_STEP;
    }
}

/*!
    \brief      read a block of 16-bit data from the EXMC SDRAM memory
    \param[in]  sdram_device: specify which a SDRAM memory block is written
    \param[in]  pbuffer: pointer to buffer
    \param[in]  readaddr: SDRAM memory internal address to read from
    \param[in]  numtowrite: number of half-word to read
    \param[out] none
    \retval     none
*/
void sdram_readbuffer_16(uint32_t sdram_device, uint16_t *pbuffer, uint32_t readaddr, uint32_t numtowrite)
{
    uint32_t temp_addr;
    __IO uint32_t write_addr_prt = readaddr;

    /* select the base address according to EXMC_Bank */
    if (sdram_device == EXMC_SDRAM_DEVICE0) {
        temp_addr = SDRAM_DEVICE0_ADDR;
    } else {
        temp_addr = SDRAM_DEVICE1_ADDR;
    }

    /* while there is data to read */
    for (; numtowrite != 0; numtowrite--) {
        /* read a byte from the memory */
        *pbuffer++ = *(uint16_t *)(temp_addr + write_addr_prt);

        /* increment the address */
        write_addr_prt += ADDR_STEP;
    }
}
