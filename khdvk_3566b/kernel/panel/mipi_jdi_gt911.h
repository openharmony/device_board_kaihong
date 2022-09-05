/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef MIPI_JDI_GT911_H
#define MIPI_JDI_GT911_H

#include <drm/drm_mipi_dsi.h>
#include <uapi/drm/drm_mode.h>
#include <drm/drm_modes.h>
#include <linux/backlight.h>
#include <linux/of.h>
#include <linux/regulator/consumer.h>
#include <linux/gpio/consumer.h>
#include "hdf_disp.h"

struct panel_hw_delay {
    uint32_t prepare_delay;
    uint32_t hpd_absent_delay;
    uint32_t enable_delay;
    uint32_t disable_delay;
    uint32_t unprepare_delay;
    uint32_t reset_delay;
    uint32_t init_delay;
};

struct panel_jdi_gt911_dev {
    bool power_invert;
    struct PanelData panel;
    struct mipi_dsi_device *dsiDev;
    struct regulator *supply;
    struct gpio_desc *enable_gpio;
    struct gpio_desc *reset_gpio;
    struct gpio_desc *hpd_gpio;
    struct panel_hw_delay hw_delay;
};

/* panel on command payload */
static uint8_t g_payLoad0[] = { 0x11 };
static uint8_t g_payLoad1[] = { 0x29 };

static struct DsiCmdDesc g_panelOnCode[] = {
    { 0x05, 0x78, sizeof(g_payLoad0), g_payLoad0 },
    { 0x05, 0x05, sizeof(g_payLoad1), g_payLoad1 },
};

/* panel off command payload */
static uint8_t g_offpayLoad0[] = { 0x28 };
static uint8_t g_offpayLoad1[] = { 0x10 };

static struct DsiCmdDesc g_panelOffCode[] = {
    { 0x05, 0x00, sizeof(g_offpayLoad0), g_offpayLoad0 },
    { 0x05, 0x78, sizeof(g_offpayLoad1), g_offpayLoad1 },
};

#endif