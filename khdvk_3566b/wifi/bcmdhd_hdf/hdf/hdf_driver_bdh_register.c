/*
 * hdf_driver_bdh_register.c
 *
 * hdf driver
 *
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */
#include "hdf_device_desc.h"
#include "hdf_wifi_product.h"
#include "hdf_log.h"
#include "osal_mem.h"
#include "hdf_wlan_chipdriver_manager.h"
#include "securec.h"
#include "wifi_module.h"
#include "hdf_wifi_core.h"
#include "hdf_public_ap6256.h"

#define HDF_LOG_TAG BDH6Driver
#define BDH6_MAX_WLAN_DEVICE 3

int32_t InitBDH6Chip(struct HdfWlanDevice *device);
int32_t DeinitBDH6Chip(struct HdfWlanDevice *device);
int32_t BDH6Deinit(struct HdfChipDriver *chipDriver, struct NetDevice *netDevice);
int32_t BDH6Init(struct HdfChipDriver *chipDriver, struct NetDevice *netDevice);
void BDH6Mac80211Init(struct HdfChipDriver *chipDriver);
static const char * const BDH6_DRIVER_NAME = "ap6256";
DEFINE_MUTEX(bdh6_reset_driver_lock);

void BDH6_ResetDriver(void)
{
    uint8_t i;
    int32_t ret;
    struct HdfWlanDevice *wlanDevice = NULL;
    mutex_lock(&bdh6_reset_driver_lock);
    
    for (i = 0; i < BDH6_MAX_WLAN_DEVICE; i++) {
        wlanDevice = HdfWlanGetWlanDevice(i);
        if (wlanDevice && strcmp(wlanDevice->driverName, BDH6_DRIVER_NAME) == 0 && wlanDevice->reset) {
            ret = HdfWifiDeinitDevice(wlanDevice);
            if (ret != HDF_SUCCESS) {
                continue;
            }

            ret = wlanDevice->reset->Reset(wlanDevice->reset);
            if (ret != HDF_SUCCESS) {
                continue;
            }

            ret = HdfWifiInitDevice(wlanDevice);
        }
    }
    mutex_unlock(&bdh6_reset_driver_lock);
}

static struct HdfChipDriver *BuildBDH6Driver(struct HdfWlanDevice *device, uint8_t ifIndex)
{
    struct HdfChipDriver *specificDriver = NULL;
    if (device == NULL) {
        HDF_LOGE("%s fail : channel is NULL", __func__);
        return NULL;
    }
    (void)device;
    (void)ifIndex;
    specificDriver = (struct HdfChipDriver *)OsalMemCalloc(sizeof(struct HdfChipDriver));
    if (specificDriver == NULL) {
        HDF_LOGE("%s fail: OsalMemCalloc fail!", __func__);
        return NULL;
    }
    if (memset_s(specificDriver, sizeof(struct HdfChipDriver), 0, sizeof(struct HdfChipDriver)) != EOK) {
        HDF_LOGE("%s fail: memset_s fail!", __func__);
        OsalMemFree(specificDriver);
        return NULL;
    }

    if (strcpy_s(specificDriver->name, MAX_WIFI_COMPONENT_NAME_LEN, BDH6_DRIVER_NAME) != EOK) {
        HDF_LOGE("%s fail : strcpy_s fail", __func__);
        OsalMemFree(specificDriver);
        return NULL;
    }
    specificDriver->init = BDH6Init;
    specificDriver->deinit = BDH6Deinit;

    HDF_LOGW("bdh6: call BuildBDH6Driver %p", specificDriver);

    BDH6Mac80211Init(specificDriver);

    return specificDriver;
}

static void ReleaseBDH6Driver(struct HdfChipDriver *chipDriver)
{
    if (chipDriver == NULL) {
        return;
    }
    if (strcmp(chipDriver->name, BDH6_DRIVER_NAME) != 0) {
        HDF_LOGE("%s:Not my driver!", __func__);
        return;
    }
    OsalMemFree(chipDriver);
}

static uint8_t GetBDH6GetMaxIFCount(struct HdfChipDriverFactory *factory)
{
    (void)factory;
    return 1;
}

/* bdh wifi6's chip driver register */
static int32_t HDFWlanRegBDH6DriverFactory(void)
{
    static struct HdfChipDriverFactory BDH6Factory = { 0 };  // WiFi device chip driver
    struct HdfChipDriverManager *driverMgr = NULL;
    driverMgr = HdfWlanGetChipDriverMgr();
    if (driverMgr == NULL) {
        HDF_LOGE("%s fail: driverMgr is NULL!", __func__);
        return HDF_FAILURE;
    }
    BDH6Factory.driverName = BDH6_DRIVER_NAME;
    BDH6Factory.GetMaxIFCount = GetBDH6GetMaxIFCount;
    BDH6Factory.InitChip = InitBDH6Chip;
    BDH6Factory.DeinitChip = DeinitBDH6Chip;
    BDH6Factory.Build = BuildBDH6Driver;
    BDH6Factory.Release = ReleaseBDH6Driver;
    BDH6Factory.ReleaseFactory = NULL;
    if (driverMgr->RegChipDriver(&BDH6Factory) != HDF_SUCCESS) {
        HDF_LOGE("%s fail: driverMgr is NULL!", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}


static int32_t HdfWlanBDH6ChipDriverInit(struct HdfDeviceObject *device)
{
    (void)device;
    HDF_LOGW("bdh6: call HdfWlanBDH6ChipDriverInit");
    return HDFWlanRegBDH6DriverFactory();
}

static int HdfWlanBDH6DriverBind(struct HdfDeviceObject *dev)
{
    (void)dev;
    HDF_LOGW("bdh6: call HdfWlanBDH6DriverBind");
    return HDF_SUCCESS;
}

static void HdfWlanBDH6ChipRelease(struct HdfDeviceObject *object)
{
    (void)object;
    HDF_LOGW("bdh6: call HdfWlanBDH6ChipRelease");
}

int32_t HdfWlanConfigSDIO(uint8_t busId)
{
    return HDF_SUCCESS;
}

struct HdfDriverEntry g_hdfBdh6ChipEntry = {
    .moduleVersion = 1,
    .Bind = HdfWlanBDH6DriverBind,
    .Init = HdfWlanBDH6ChipDriverInit,
    .Release = HdfWlanBDH6ChipRelease,
    .moduleName = "HDF_WLAN_CHIPS_AP6256"
};

HDF_INIT(g_hdfBdh6ChipEntry);
