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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "gif_lib.h"
#define ARGB_SKIP_INDEX (4)
#define OPA_OPAQUE (255)

static uint8_t *gifImageData = NULL;
static uint8_t imageIndex = 0;
static uint32_t gifDataSize = 0;
static GifFileType *gifFileType = NULL;

static void DealGifImageData(GifFileType *gifFileType, GifImageDesc *gifImageDesc,

                             SavedImage *savedImage, GraphicsControlBlock gcb, ColorMapObject *colorMap)
{
    uint8_t colorIndex = 0;
    GifColorType *gifColorType = NULL;
    uint32_t index = 0;
    bool transparentColor = true;
    int32_t loc = 0;
    for (int32_t x = 0; x < gifFileType->SHeight; x++) {
        for (int32_t y = 0; y < gifFileType->SWidth; y++) {
            transparentColor = true;
            if ((x >= gifImageDesc->Top) && (x < gifImageDesc->Top + gifImageDesc->Height) &&
                (y >= gifImageDesc->Left) && (y < gifImageDesc->Left + gifImageDesc->Width)) {
                loc = (x - gifImageDesc->Top) * gifImageDesc->Width + (y - gifImageDesc->Left);
                colorIndex = savedImage->RasterBits[loc];

                if ((gcb.DisposalMode != DISPOSE_DO_NOT) || (gcb.TransparentColor == NO_TRANSPARENT_COLOR) ||
                    (colorIndex != gcb.TransparentColor)) {
                    transparentColor = false;
                }
            }
            if (transparentColor) {
                index += ARGB_SKIP_INDEX;
            } else {
                gifColorType = &colorMap->Colors[colorIndex];
                gifImageData[index++] = gifColorType->Blue;
                gifImageData[index++] = gifColorType->Green;
                gifImageData[index++] = gifColorType->Red;
                gifImageData[index++] = OPA_OPAQUE;
            }
        }
    }
}

static void SetGifFrame(GifFileType *gifFileType, int32_t imageIndex)
{
    SavedImage *savedImage = &(gifFileType->SavedImages[imageIndex]);

    GifImageDesc *gifImageDesc = &(savedImage->ImageDesc);

    GraphicsControlBlock gcb;
    DGifSavedExtensionToGCB(gifFileType, imageIndex, &gcb);

    ColorMapObject *colorMap = NULL;
    if (gifImageDesc->ColorMap != NULL) {
        colorMap = gifImageDesc->ColorMap;
    } else {
        colorMap = gifFileType->SColorMap;
    }

    DealGifImageData(gifFileType, gifImageDesc, savedImage, gcb, colorMap);
}

int GetGifImgCnt(void)
{
    return gifFileType->ImageCount;
}

uint8_t *GetGifData(uint8_t imageIndex)
{
    SetGifFrame(gifFileType, imageIndex);
    return gifImageData;
}

int GifLoad(const char *src)
{
    int error = D_GIF_SUCCEEDED;
    gifFileType = DGifOpenFileName(src, &error);
    if (gifFileType == NULL) {
        return GIF_ERROR;
    }
    if (error != D_GIF_SUCCEEDED) {
        return GIF_ERROR;
    }
    if (GIF_ERROR == DGifSlurp(gifFileType)) {
        return GIF_ERROR;
    }
    gifDataSize = gifFileType->SWidth * gifFileType->SHeight * ARGB_SKIP_INDEX;

    gifImageData = (uint8_t *)malloc(gifDataSize);
    if (gifImageData == NULL) {
        DGifCloseFile(gifFileType, NULL);
    }
    return GIF_OK;
}