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

#ifndef TLI_IPA_CONFIG_H_
#define TLI_IPA_CONFIG_H_

extern void InitLcdGpio(void);
extern int32_t ipaConfig(uint32_t width, uint32_t height, uint32_t srcAddr, uint32_t desAddr);
extern int32_t tliBlendConfig(uint32_t left, uint32_t top, uint32_t pictureWidth, uint32_t pictureHeight,
                              uint32_t pictureBuffer);
extern void InitTliGpio(void);
extern void SetLcdBackgroundLayer(void);
extern int32_t SetLcdFrontLayer(uint32_t layerId, uint32_t left, uint32_t top, uint32_t pictureWidth,
                                uint32_t pictureHeight, uint32_t pictureBuffer);
#endif