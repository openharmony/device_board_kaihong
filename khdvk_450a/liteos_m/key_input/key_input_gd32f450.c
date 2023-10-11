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

#include "cmsis_os2.h"
#include "los_compiler.h"
#include "osal_mem.h"
#include "gpio_if.h"
#include "key_input_gd32f450.h"

#define WAKEUP_KEY_GPIO_NUM 0  // PA0
#define TAMPER_KEY_GPIO_NUM 45 // PC13
#define USER_KEY_GPIO_NUM 30   // PB14
#define DELAY_10_MS 10
#define DELAY_20_MS 20
#define KEY_INDEX_0 0
#define KEY_INDEX_1 1
#define KEY_INDEX_2 2
#define STACK_SIZE 0x1000
#define INPUT_TASK_PRIORITY 29

static AllKeyCond *g_allKeyCond;
static UINT32 g_allKeyGpioNum[MAX_KEY_NUM];

static void Gd32f450GetKeyInputDeviceResource(void)
{
    g_allKeyGpioNum[KEY_INDEX_0] = WAKEUP_KEY_GPIO_NUM;

    g_allKeyGpioNum[KEY_INDEX_1] = TAMPER_KEY_GPIO_NUM;

    g_allKeyGpioNum[KEY_INDEX_2] = USER_KEY_GPIO_NUM;
}

static void GpioPinScan(int32_t key)
{
    uint16_t ret = 0;
    int isPressed = 0;
    GpioRead(g_allKeyGpioNum[key], &ret);
    if (ret == 0) {
        osDelay(DELAY_10_MS);
        GpioRead(g_allKeyGpioNum[key], &ret);
    }
    if (ret) {
        isPressed = 0;
    } else {
        isPressed = 1;
    }
    g_allKeyCond->isPressed[key] = isPressed;
}

static void KeyInputScanCallback(void)
{
    while (1) {
        for (int32_t i = 0; i < MAX_KEY_NUM; i++) {
            GpioPinScan(i);
        }
        osDelay(DELAY_20_MS);
    }
}

static void Gd32f450KeyInputTaskCreate(void)
{
    osThreadId_t threadId = NULL;
    osThreadAttr_t attr = {0};
    memset_s(&attr, sizeof(osThreadAttr_t), 0, sizeof(osThreadAttr_t));
    attr.name = "KeyInputScanCallback";
    attr.stack_size = STACK_SIZE;
    attr.priority = (INPUT_TASK_PRIORITY);
    threadId = osThreadNew(KeyInputScanCallback, NULL, &attr);
    if (threadId == NULL) {
        printf("KeyInputScanCallback task create failed.\n");
        return -1;
    }
}

int32_t Gd32f450KeyInputInit()
{
    if (g_allKeyCond != NULL) {
        printf("%s: Malloc g_allKeyCond fail!\r\n", __func__);
        return HDF_FAILURE;
    }
    int ret = 0;
    printf("enter in %s:%s %d\r\n", __FILE__, __FUNCTION__, __LINE__);
    g_allKeyCond = (AllKeyCond *)OsalMemCalloc(sizeof(*g_allKeyCond));
    if (g_allKeyCond == NULL) {
        printf("%s: Malloc g_allKeyCond fail!\r\n", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    memset_s(g_allKeyCond, sizeof(*g_allKeyCond), 0, sizeof(*g_allKeyCond));
    Gd32f450GetKeyInputDeviceResource();

    for (int32_t i = 0; i < MAX_KEY_NUM; i++) {
        ret = GpioSetDir(g_allKeyGpioNum[i], GPIO_DIR_IN);
        if (ret != 0) {
            printf("GpioSetDir: failed, ret %d\n", ret);
            OsalMemFree(g_allKeyCond);
            g_allKeyCond = NULL;
            return HDF_FAILURE;
        }
    }

    g_allKeyCond->keyType[KEY_INDEX_0] = KEY_WAKEUP;
    g_allKeyCond->keyType[KEY_INDEX_1] = KEY_TAMPER;
    g_allKeyCond->keyType[KEY_INDEX_2] = KEY_USER;

    Gd32f450KeyInputTaskCreate();

    return HDF_SUCCESS;
}

int32_t Gd32f450KeyInputRelease()
{
    printf("enter in %s:%s %d\r\n", __FILE__, __FUNCTION__, __LINE__);
    OsalMemFree(g_allKeyCond);
    g_allKeyCond = NULL;
    return HDF_SUCCESS;
}

AllKeyCond *Gd32f450ALLKeyInputRead(void)
{
    return g_allKeyCond;
}

int Gd32f450SingleKeyInputRead(KEY_TYPE keyId)
{
    return g_allKeyCond->isPressed[keyId];
}
