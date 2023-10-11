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

#ifndef GD32F4XX_KEY_INPUT_H_
#define GD32F4XX_KEY_INPUT_H_
#ifdef __cplusplus
extern "C" {
#endif

#define MAX_KEY_NUM (KEY_LIMIT + 1)
typedef enum {
    KEY_WAKEUP = 0,
    KEY_TAMPER,
    KEY_USER,
    KEY_LIMIT = KEY_USER,
} KEY_TYPE;

typedef struct {
    KEY_TYPE keyType[MAX_KEY_NUM];
    int isPressed[MAX_KEY_NUM];
} AllKeyCond;

extern int32_t Gd32f450KeyInputInit(void);
extern int32_t Gd32f450KeyInputRelease(void);
extern AllKeyCond *Gd32f450ALLKeyInputRead(void);
extern int Gd32f450SingleKeyInputRead(KEY_TYPE keyId);

#ifdef __cplusplus
}
#endif

#endif