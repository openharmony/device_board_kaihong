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

#include "ohos_init.h"
#include "cmsis_os2.h"
#include "logo_interface.h"
#include "gd32f4xx.h"
#include "gd32f4xx_systick.h"
#include "exmc_sdram.h"
#include "hilog/log.h"

#define APP_ADDR_OFF ((uint32_t)0x10000) // 应用程序起始地址偏移
#define LOG_DOMAIN 0x00201
#define LOG_TAG "main"
#define TIME_PEROID 5000
#define DELAY_TIME 1000
#define STACK_SIZE 0x1000
#define PRIORITY 32
#define BUFFER_START_LEN 2

static void SysInit(void)
{
    OHOS_SystemInit();
}

static void DeadWhile(void)
{
    while (1) {
        osDelay(DELAY_TIME);
        HILOG_ERROR(0, "enter in DeadWhile");
    }
}

static void MainBoot(void)
{
    /*
    CMSIS Highest priority 34
    CMSIS Norbal  priority 24
    CMSIS Lowest  priority 3
    CMSIS_PRI = 34 - LOS_PRI
    */
    osThreadId_t threadId = NULL;
    osThreadAttr_t attr = {0};
    attr.name = "MainBoot";
    attr.stack_size = STACK_SIZE;
    attr.priority = PRIORITY;
    threadId = osThreadNew(SysInit, NULL, &attr);
    if (threadId == NULL) {
        HILOG_ERROR(0, "MainBoot task create failed!!!");
    }

    osThreadDetach(threadId);
}

int HiLogWriteInternal(const char *buffer, size_t bufLen)
{
    if (!buffer) {
        return -1;
    }

    // because it's called as HiLogWriteInternal(buf, strlen(buf) + 1)
    if (bufLen < BUFFER_START_LEN) {
        return 0;
    }

    if (buffer[bufLen - BUFFER_START_LEN] != '\n') {
        *((char *)buffer + bufLen - 1) = '\n';
    } else {
        bufLen--;
    }

    printf("%s", buffer);

    return 0;
}

static void InitBoardBefore(void)
{
    nvic_vector_table_set(NVIC_VECTTAB_FLASH, APP_ADDR_OFF);           // 中断向量重映射
    gpio_mode_set(GPIOD, GPIO_MODE_INPUT, GPIO_PUPD_NONE, GPIO_PIN_4); // reset led2
}

static void InitBoard(void)
{
    ErrStatus init_state;

    USART0_UART_Init();
    Gd32f4xxSystickConfig();

    init_state = exmc_synchronous_dynamic_ram_init(EXMC_SDRAM_DEVICE0);
    if (ERROR == init_state) {
        HILOG_ERROR(0, "SDRAM initialize fail!");
        while (1) { }
    }

    HILOG_INFO(0, "SDRAM initialized success!\n");
}

static void Gif_Init(void)
{
    int reval = 0;
    while (!reval) {
        reval = GifLoad("/data/cartoon_logo.gif");
        HILOG_INFO(0, "GifLoad try again ...\n\n");
    }
    HILOG_INFO(0, "GifLoad ok ...\n\n");
}

/**
 * @brief  The application entry point.
 * @retval int
 */
int main(void)
{
    osStatus_t status = osError;

    InitBoardBefore();
    InitBoard();
    HILOG_INFO(0, "build time is %s:%s\n\n", __DATE__, __TIME__);

    status = osKernelInitialize();
    if (status != osOK) {
        HILOG_ERROR(0, "osKernelInitialize fail!");
        while (1) { }
    }
    HILOG_INFO(0, "Open Harmony 3.1 Release start ...\n\n");

    lfs_init();
#ifdef LOSCFG_DRIVERS_HDF_USER_LCD
    Gif_Init();
#endif
    DeviceManagerStart();
    enet_adapter_init(NULL);

    InitUartMutex();
    MainBoot();

    status = osKernelStart();
    if (status != osOK) {
        HILOG_ERROR(0, "osKernelStart fail!");
    }
    while (1) { }
}