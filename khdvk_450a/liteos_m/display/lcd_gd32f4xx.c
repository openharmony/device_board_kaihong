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

#include "hdf_log.h"
#include "hdf_device_desc.h"
#include "device_resource_if.h"
#include "osal_time.h"
#include "lcd_abs_if.h"
#include "tli_ipa_config.h"
#include "lcd_hardware_init.h"

#define HDF_LOG_TAG gd_lcd

#define WIDTH (320)
#define HEIGHT (480)
#define PICTURE_DEFAULT_POSITION_X 0
#define PICTURE_DEFAULT_POSITION_Y 0
#define PICTURE_WIDTH 162
#define PICTURE_HEIGHT 320
#define DELAY_500_MS 500
#define DELAY_50_MS 50
#define DISWIDTH 137
#define DISHEIGHT 160
#define DISHEIGHT_STANDARD 310
#define DISHEIGHT_STEP 10
static int32_t PanelReadId(uint32_t *p_dev_id);
struct PanelDevice {
    struct PanelData panelData;
    struct PanelInfo panelInfo;
};

static struct PanelDevice priv = {
    .panelInfo =
        {
            .width = WIDTH,
            .height = HEIGHT,
            .frameRate = 60,
            .intfSync = OUTPUT_USER,
        },
};
#define US_TO_MS_CONV (1000)

static void LcdMDelay(uint32_t timeOut)
{
    OsalTimespec startTick = {0, 0};
    OsalTimespec endTick = {0, 0};
    OsalTimespec diffTick = {0, 0};

    OsalGetTime(&startTick);
    do {
        OsalMSleep(1);

        /* time out break */
        OsalGetTime(&endTick);
        OsalDiffTime(&startTick, &endTick, &diffTick);
        if ((uint32_t)(diffTick.sec * US_TO_MS_CONV + diffTick.usec / US_TO_MS_CONV) >= timeOut) {
            break;
        }
    } while (true);
}
#define RGB565_DATA_BUFF_SIZE 307200 // 320*480*2=307200 137*320*2=87680
static uint8_t *g_blended_address_buffer = NULL;

static int32_t PanelInit(struct PanelData *panel)
{
    HDF_LOGI("enter in %s\n", __FUNCTION__);
    static const unsigned char gImageLogo[32] = {0};
    if (panel == NULL) {
        HDF_LOGE("in %s: panel == NULL", __FUNCTION__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_blended_address_buffer == NULL) {
        g_blended_address_buffer = (uint8_t *)OsalMemCalloc(RGB565_DATA_BUFF_SIZE);
        if (g_blended_address_buffer == NULL) {
            HDF_LOGE("in %s:%s %d: mallc g_blended_address_buffer failed\n", __FILE__, __FUNCTION__, __LINE__);
            return;
        }

        memset_s(&g_blended_address_buffer[0], RGB565_DATA_BUFF_SIZE, 0, RGB565_DATA_BUFF_SIZE);
    }

    LcdMDelay(DELAY_500_MS);

    InitLcdGpio();

    InitLcdRegister(); // init lcd register

    ConfigTli();
    SetLcdBackgroundLayer();
    SetLcdFrontLayer(0, PICTURE_DEFAULT_POSITION_X, PICTURE_DEFAULT_POSITION_Y, 1, 1,
                     (uint32_t)gImageLogo); // set layer0
    tli_layer_enable(LAYER0);
    tli_layer_enable(LAYER1);
    tli_reload_config(TLI_FRAME_BLANK_RELOAD_EN);
    tli_enable();

    SetLcdFrontLayer(1, PICTURE_DEFAULT_POSITION_X, PICTURE_DEFAULT_POSITION_Y, WIDTH, HEIGHT,
                     (uint32_t)&g_blended_address_buffer[0]); // set layer1

    tli_reload_config(TLI_REQUEST_RELOAD_EN);

    return HDF_SUCCESS;
}

static int32_t PanelReadId(uint32_t *p_dev_id)
{
    return HDF_SUCCESS;
}

static int32_t PanelOn(struct PanelData *panel)
{
    return HDF_SUCCESS;
}

static int32_t PanelOff(struct PanelData *panel)
{
    return HDF_SUCCESS;
}

static int32_t PanelSetBacklight(struct PanelData *panel, uint32_t level)
{
    return HDF_SUCCESS;
}

static int32_t PanelFlush(uint16_t disWidth, uint16_t disHeight, uint16_t *dataBuffer)
{
    if ((disWidth <= 0) || (disHeight <= 0) || (dataBuffer == NULL)) {
        HDF_LOGE("input para is wrong: disWidth(%d) disHeight(%d) dataBuffer(%p)", disWidth, disHeight, dataBuffer);
        return HDF_ERR_INVALID_PARAM;
    }

    SetLcdFrontLayer(1, PICTURE_DEFAULT_POSITION_X, PICTURE_DEFAULT_POSITION_X, disWidth, disHeight,
                     (uint32_t)&g_blended_address_buffer[0]);
    tli_reload_config(TLI_REQUEST_RELOAD_EN); // make layer_settings in work

#ifdef USE_IPA
    ipaConfig(disWidth, disHeight, (uint32_t)dataBuffer, (uint32_t)&g_blended_address_buffer[0]);
    ipa_transfer_enable();
    while (RESET == ipa_interrupt_flag_get(IPA_INT_FLAG_FTF)) { }
#else
    uint16_t area_multip = 2;
    memcpy_s(&g_blended_address_buffer[0], (disWidth * disHeight * area_multip), dataBuffer,
             (disWidth * disHeight * area_multip));
#endif

    return HDF_SUCCESS;
}

static int32_t PanelDriverInit(struct HdfDeviceObject *object)
{
    HDF_LOGI("enter in %s\n", __FUNCTION__);

    if (object == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }

    priv.panelData.info = &priv.panelInfo;
    priv.panelData.init = PanelInit;
    priv.panelData.on = PanelOn;
    priv.panelData.off = PanelOff;
    priv.panelData.setBacklight = PanelSetBacklight;
    priv.panelData.dispFlush = PanelFlush;
    priv.panelData.object = object;
    if (RegisterPanel(&priv.panelData) != HDF_SUCCESS) {
        HDF_LOGE("%s: RegisterPanel failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t PanelDriverBind(struct HdfDeviceObject *device)
{
    (void)device;
    return HDF_SUCCESS;
}

static void PanelDriverRelease(struct HdfDeviceObject *device)
{
    (void)device;
}

static struct HdfDriverEntry g_lcdDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "GD_LCD_MODULE_HDF",
    .Bind = PanelDriverBind,
    .Init = PanelDriverInit,
    .Release = PanelDriverRelease,
};

HDF_INIT(g_lcdDriverEntry);