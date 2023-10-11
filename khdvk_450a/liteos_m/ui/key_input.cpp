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

#include "events/key_event.h"
#include "gfx_utils/graphic_log.h"
#include "key_input_gd32f450.h"
#include "key_input.h"

namespace OHOS {
    namespace {
        static uint16_t g_lastKeyId = 0;
    } // namespace

    KeyInput::KeyInput()
    {
        Gd32f450KeyInputInit();
    }

    KeyInput *KeyInput::GetInstance()
    {
        static KeyInput keyInput;
        return &keyInput;
    }

    bool KeyInput::Read(DeviceData &data)
    {
        data.keyId = g_lastKeyId;
        data.state = (uint16_t)Gd32f450SingleKeyInputRead((KEY_TYPE)g_lastKeyId);

        if (g_lastKeyId < MAX_KEY_NUM - 1) {
            g_lastKeyId++;
            return true;
        } else {
            g_lastKeyId = 0;
            return false;
        }

        return false;
    }
} // namespace OHOS
