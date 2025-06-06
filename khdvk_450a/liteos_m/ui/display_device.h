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

#ifndef DISPLAY_DEVICE_H
#define DISPLAY_DEVICE_H

#include "engines/gfx/soft_engine.h"

namespace OHOS {
    class DisplayDevice : public SoftEngine {
    public:
        DisplayDevice()
        {
        }
        virtual ~DisplayDevice()
        {
        }
        static DisplayDevice *GetInstance();

        void Flush(const Rect &flushRect);
        BufferInfo *GetFBBufferInfo() override;
        void UpdateFBBuffer();

    private:
        bool isRegister_ = false;
        void *fbAddr = nullptr;
    };
} // namespace OHOS

#endif // DISPLAY_DEVICE_H
