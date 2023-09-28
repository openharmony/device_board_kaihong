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

#ifndef LCD_ABS_IF_H
#define LCD_ABS_IF_H

#include "disp_hal.h"

/* support max panel number */
#define PANEL_MAX 1
#define LCD_PANEL_DEV_ID 0

struct BlkDesc {
    uint32_t type;
    uint32_t minLevel;
    uint32_t maxLevel;
    uint32_t defLevel;
};

struct PanelInfo {
    uint32_t width;
    uint32_t height;
    uint32_t hbp;
    uint32_t hfp;
    uint32_t hsw;
    uint32_t vbp;
    uint32_t vfp;
    uint32_t vsw;
    uint32_t frameRate;
    uint32_t dev_id;
    uint32_t intfType;
    enum IntfSync intfSync;
    struct BlkDesc blk;
};

struct PanelStatus {
    uint32_t currLevel;
};

struct PanelData {
    struct HdfDeviceObject *object;
    int32_t (*init)(struct PanelData *panel);
    int32_t (*on)(struct PanelData *panel);
    int32_t (*off)(struct PanelData *panel);
    int32_t (*setBacklight)(struct PanelData *panel, uint32_t level);
    int32_t (*dispFlush)(uint16_t disWidth, uint16_t disHeight, uint16_t *dataBuffer);
    struct PanelInfo *info;
    struct PanelStatus status;
};

struct PanelManager {
    struct PanelData *panel[PANEL_MAX];
    uint32_t panelNum;
};

int32_t RegisterPanel(struct PanelData *data);
struct PanelManager *GetPanelManager(void);
struct PanelData *GetPanel(int32_t index);

#endif /* LCD_ABS_IF_H */
