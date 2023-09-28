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

#include "lcd_abs_if.h"
#include "hdf_log.h"

#define TRANSFORM_KILO 1000
#define TRANSFORM_MILL 1000000

static struct PanelManager g_panelManager = {0};

#define LCD_HDF_SUCCESS (0)            /* < The operation is successful. */
#define LCD_HDF_FAILURE (-1)           /* < Failed to invoke the OS underlying function. */
#define LCD_HDF_ERR_INVALID_PARAM (-3) /* < Invalid parameter. */

int32_t RegisterPanel(struct PanelData *data)
{
    HDF_LOGI("enter in %s\n", __FUNCTION__);

    int32_t panelNum;
    if (data == NULL) {
        HDF_LOGE("%s: panel data is null", __func__);
        return LCD_HDF_ERR_INVALID_PARAM;
    }
    panelNum = g_panelManager.panelNum;
    if (panelNum >= PANEL_MAX) {
        HDF_LOGE("%s registered panel up PANEL_MAX", __func__);
        return LCD_HDF_FAILURE;
    }
    g_panelManager.panel[panelNum] = data;
    g_panelManager.panelNum++;

    return LCD_HDF_SUCCESS;
}

struct PanelManager *GetPanelManager(void)
{
    if (g_panelManager.panelNum == 0) {
        return NULL;
    } else {
        return &g_panelManager;
    }
}

struct PanelData *GetPanel(int32_t index)
{
    struct PanelManager *panelManager = NULL;

    panelManager = GetPanelManager();
    if (panelManager == NULL) {
        HDF_LOGE("%s panelManager is null", __func__);
        return NULL;
    }
    if (index >= g_panelManager.panelNum) {
        HDF_LOGE("%s index is greater than g_panelManager.panelNum", __func__);
        return NULL;
    }

    return panelManager->panel[index];
}