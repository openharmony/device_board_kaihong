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
#include "ui_main.h"
#include "cmsis_os.h"
#include "pthread.h"
#include "core/render_manager.h"
#include "common/graphic_startup.h"
#include "common/image_decode_ability.h"
#include "common/input_device_manager.h"
#include "common/task_manager.h"
#include "display_device.h"
#include "engines/gfx/gfx_engine_manager.h"
#include "font/ui_font.h"
#include "font/ui_font_header.h"
#include "font/ui_font_vector.h"
#include "gfx_utils/graphic_log.h"
#include "graphic_config.h"
#include "hal_tick.h"
#include "key_input.h"
#define ENABLE_FPS
#ifdef ENABLE_ACE
#include "product_adapter.h"
#endif

static const int32_t FONT_MEM_LEN = 40 * 1024;
static uint8_t g_fontMemBaseAddr[FONT_MEM_LEN];
#if ENABLE_ICU
static uint8_t g_icuMemBaseAddr[SHAPING_WORD_DICT_LENGTH];
#endif

using namespace OHOS;

static void InitFontEngine()
{
#if ENABLE_VECTOR_FONT
    GraphicStartUp::InitFontEngine(reinterpret_cast<uintptr_t>(g_fontMemBaseAddr), FONT_MEM_LEN, VECTOR_FONT_DIR,
                                   DEFAULT_VECTOR_FONT_FILENAME);
#endif

#if ENABLE_ICU
    GraphicStartUp::InitLineBreakEngine(reinterpret_cast<uintptr_t>(g_icuMemBaseAddr), SHAPING_WORD_DICT_LENGTH,
                                        VECTOR_FONT_DIR, DEFAULT_LINE_BREAK_RULE_FILENAME);
#endif
}

static void InitImageDecodeAbility()
{
    uint32_t imageType = IMG_SUPPORT_BITMAP | OHOS::IMG_SUPPORT_JPEG | OHOS::IMG_SUPPORT_PNG;
    ImageDecodeAbility::GetInstance().SetImageDecodeAbility(imageType);
}

static void InitHal()
{
    DisplayDevice *display = DisplayDevice::GetInstance();
    BaseGfxEngine::InitGfxEngine(display);
#ifdef LOSCFG_DRIVERS_USER_KEY_INPUT
    KeyInput *key = KeyInput::GetInstance();
    InputDeviceManager::GetInstance()->Add(key);
#endif
}

void InitUiKit(void)
{
    GraphicStartUp::Init();
    // init display/input device
    InitHal();
    // init font engine
    InitFontEngine();
    // init suppot image format
    InitImageDecodeAbility();
}

__attribute__((weak)) void RunApp(void)
{
    GRAPHIC_LOGI("RunApp default");
}

#ifdef ENABLE_ACE
static void RenderTEHandler()
{
}
#endif

static void UiMainTask(void *arg)
{
    (void)arg;
    // init ui kit (hal/fontengine/imagedecode/...)
    InitUiKit();

    // run user app
    RunApp();

#ifdef ENABLE_ACE
    const ACELite::TEHandlingHooks hooks = {RenderTEHandler, NULL};
    ACELite::ProductAdapter::RegTEHandlers(hooks);
#endif
#ifdef ENABLE_FPS
    uint32_t cnt = 0;
    uint32_t start = HALTick::GetInstance().GetTime();
#endif
    while (1) {
#ifdef ENABLE_ACE
        // Here render all js app in the same task.
        ACELite::ProductAdapter::DispatchTEMessage();
#endif

        DisplayDevice::GetInstance()->UpdateFBBuffer();
        uint32_t temp = HALTick::GetInstance().GetTime();
        TaskManager::GetInstance()->TaskHandler();
        uint32_t time = HALTick::GetInstance().GetElapseTime(temp);
        if (time < DEFAULT_TASK_PERIOD) {
            osDelay(DEFAULT_TASK_PERIOD - time);
        }
#ifdef ENABLE_FPS
        cnt++;
        time = HALTick::GetInstance().GetElapseTime(start);
        int16_t timeout = 1000;
        if (time >= timeout) {
            GRAPHIC_LOGD("uitest time=%u, cnt=%u", time, cnt);
            if (time == 0) {
                return;
            }
            GRAPHIC_LOGD("uitest %u fps", timeout * cnt / time);
            start = HALTick::GetInstance().GetTime();
            cnt = 0;
        }
#endif
    }
}
static const int32_t UI_THREAD_STACK_SIZE = 1024 * 32;

void UiMain(void)
{
    osThreadAttr_t attr;

    attr.name = "display-demo";
    attr.attr_bits = 0U;
    attr.cb_mem = NULL;
    attr.cb_size = 0U;
    attr.stack_mem = NULL;
    attr.stack_size = UI_THREAD_STACK_SIZE;
    attr.priority = osPriorityNormal;

    if (osThreadNew((osThreadFunc_t)UiMainTask, NULL, &attr) == NULL) {
        GRAPHIC_LOGE("Failed to create UiMainTask");
    }
}
