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
#include "hdf_base.h"

#define LCD_MAX_SUPPORT 1

static int32_t lcdInit[LCD_MAX_SUPPORT] = {0};
static int8_t *sDispFrameBuffer = NULL;

int32_t DispInit(uint32_t devId)
{
    struct PanelData *panelData = GetPanel(devId);
    HDF_LOGI("enter in %s\n", __FUNCTION__);

    if (devId >= LCD_MAX_SUPPORT) {
        HDF_LOGE("DispInit->devId = %d fail to <= LCD_MAX_SUPPORT! ", devId);
        return HDF_ERR_INVALID_PARAM;
    }

    if (lcdInit[devId] == 1) {
        HDF_LOGI("DispInit: lcdInit[%d] == 1", devId);
        return HDF_SUCCESS;
    }

    if (panelData == NULL) {
        HDF_LOGE("%s: GetPanelData failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (panelData->init) {
        /* panel driver init */
        if (panelData->init(panelData) != HDF_SUCCESS) {
            HDF_LOGE("%s: panelData->init failed", __func__);
            return HDF_FAILURE;
        }
    }

    lcdInit[devId] = 1;

    return HDF_SUCCESS;
}

int32_t DispGetInfo(uint32_t devId, struct DispInfo *info)
{
    if (info == NULL) {
        HDF_LOGE("DispGetInfo: info == NULL !");
        return HDF_FAILURE;
    }
    struct PanelData *panelData = GetPanel(devId);
    if (panelData == NULL) {
        HDF_LOGE("%s: GetPanelData failed", __func__);
        return HDF_FAILURE;
    }
    struct PanelInfo *panelInfo = panelData->info;
    if (panelInfo == NULL) {
        HDF_LOGE("%s: GetPanelInfo failed", __func__);
        return HDF_FAILURE;
    }
    info->width = panelInfo->width;
    info->height = panelInfo->height;
    info->intfSync = OUTPUT_USER;
    info->intfType = (uint32_t)panelInfo->intfType;
    info->frameRate = panelInfo->frameRate;

    return HDF_SUCCESS;
}

int32_t DispOn(uint32_t devId, uint32_t fbSize)
{
    struct PanelData *panelData = GetPanel(devId);
    if (panelData == NULL) {
        HDF_LOGE("%s: GetPanelData failed", __func__);
        return HDF_FAILURE;
    }
    if (panelData->on) {
        /* panel driver on */
        if (panelData->on(panelData) != HDF_SUCCESS) {
            HDF_LOGE("%s: panelData->on failed", __func__);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

void DispUmap(uint32_t size)
{
    if (sDispFrameBuffer != NULL) {
        OsalMemFree(sDispFrameBuffer);
        sDispFrameBuffer = NULL;
    }
}

void *DispMmap(uint32_t size)
{
    if (sDispFrameBuffer) {
        return sDispFrameBuffer;
    } else {
        sDispFrameBuffer = OsalMemCalloc(size);
        return sDispFrameBuffer;
    }

    return NULL;
}

int32_t DispOff(uint32_t devId)
{
    struct PanelData *panelData = GetPanel(devId);
    if (panelData == NULL) {
        HDF_LOGE("%s: GetPanelData failed", __func__);
        return HDF_FAILURE;
    }
    if (panelData->off) {
        /* panel driver off */
        if (panelData->off(panelData) != HDF_SUCCESS) {
            HDF_LOGE("%s: panelData->off failed", __func__);
            return HDF_FAILURE;
        }
    }

    if (sDispFrameBuffer) {
        free(sDispFrameBuffer);
        sDispFrameBuffer = NULL;
    }

    return HDF_SUCCESS;
}

int32_t DispSetBacklight(uint32_t devId, uint32_t level)
{
    struct PanelData *panelData = GetPanel(devId);
    if (panelData == NULL) {
        HDF_LOGE("%s: GetPanelData failed", __func__);
        return HDF_FAILURE;
    }
    if (panelData->setBacklight) {
        /* panel driver set backlight */
        if (panelData->setBacklight(panelData, level) != HDF_SUCCESS) {
            HDF_LOGE("%s: panelData->setBacklight failed", __func__);
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

void DispFlush(uint32_t devId, LayerBuffer *buffer)
{
    struct PanelData *panelData = GetPanel(devId);
    if (panelData == NULL) {
        HDF_LOGE("%s: GetPanelData failed", __func__);
        return HDF_FAILURE;
    }

    if (panelData->dispFlush) {
        if (panelData->dispFlush(buffer->width, buffer->height, (uint16_t *)(buffer->data.virAddr)) != HDF_SUCCESS) {
            HDF_LOGE("%s: panelData->dispFlush failed", __func__);
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}
