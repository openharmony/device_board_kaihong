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

#include "watchdog.h"

/**
 * fls - find last (most-significant) bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */
#define START_FLS 32
#define OFFSET16 16
#define OFFSET8 8
#define OFFSET4 4
#define OFFSET2 2
#define OFFSET1 1
#define BORDER_MULTIPLE 1000
#define TWO_TO_TENTH 1024
static int generic_fls(int t)
{
    int r = START_FLS;
    int x = t;
    if (!x) {
        return 0;
    }
    if (!(x & 0xffff0000u)) {
        x <<= OFFSET16;
        r -= OFFSET16;
    }
    if (!(x & 0xff000000u)) {
        x <<= OFFSET8;
        r -= OFFSET8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= OFFSET4;
        r -= OFFSET4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= OFFSET2;
        r -= OFFSET2;
    }
    if (!(x & 0x80000000u)) {
        x <<= OFFSET1;
        r -= OFFSET1;
    }
    return r;
}

static inline int ilog2(unsigned int x)
{
    return generic_fls(x) - 1;
}

unsigned long roundup_pow_of_two(unsigned long n)
{
    return 1UL << generic_fls(n - 1);
}

static inline uint32_t reg_read(void volatile *base, uint32_t reg)
{
    return OSAL_READL((uintptr_t)base + reg);
}

static inline void reg_write(void volatile *base, uint32_t reg, uint32_t val)
{
    OSAL_WRITEL(val, (uintptr_t)base + reg);
}

// get clock source real rate
static inline int32_t GD450wdgGetClockRate(struct GD450wdg *iwdg)
{
    int ret = HDF_SUCCESS;

    /*
        if "clock_source" is set, use the real rate of clock source
        otherwise, use the default clock rate
    */
    if (iwdg->clock_source != NULL) {
        // get clock source real rate.
        // ...
        ret = HDF_SUCCESS;
    }

    return ret;
}

static inline uint32_t GD450wdgGetSr(struct GD450wdg *iwdg)
{
    return reg_read(iwdg->base, IWDG_SR);
}

int32_t GD450wdgStart(struct WatchdogCntlr *wdt)
{
    struct GD450wdg *iwdg = NULL;
    uint32_t tout, presc, iwdg_pr, iwdg_rlr, iwdg_sr;
    uint32_t i = 10;

    if (wdt == NULL) {
        return HDF_ERR_INVALID_OBJECT;
    }
    iwdg = (struct GD450wdg *)wdt->priv;

    // 计算装载值
    tout = iwdg->seconds; // 超时秒数

    // 计算边界
    if (tout > (iwdg->max_hw_heartbeat_ms * BORDER_MULTIPLE)) {
        tout = iwdg->max_hw_heartbeat_ms * BORDER_MULTIPLE;
    }
    if (tout < iwdg->min_timeout) {
        tout = iwdg->min_timeout;
    }

    presc = DIV_ROUND_UP(tout * iwdg->rate, RLR_MAX + 1);

    /* The prescaler is align on power of 2 and start at 2 ^ PR_SHIFT. */
    presc = roundup_pow_of_two(presc);
    iwdg_pr = (presc <= (1 << PR_SHIFT)) ? 0 : ilog2(presc) - PR_SHIFT;
    if (presc == 0) {
        return HDF_FAILURE;
    }
    iwdg_rlr = ((tout * iwdg->rate) / presc) - 1;

    /* enable write access */
    reg_write(iwdg->base, IWDG_KR, KR_KEY_EWA);

    /* set prescaler & reload registers */
    reg_write(iwdg->base, IWDG_PR, iwdg_pr);
    reg_write(iwdg->base, IWDG_RLR, iwdg_rlr);
    reg_write(iwdg->base, IWDG_KR, KR_KEY_ENABLE);

    // 等待状态寄存器 SR_PVU | SR_RVU 复位
    while ((iwdg_sr = GD450wdgGetSr(iwdg)) & (SR_PVU | SR_RVU)) {
        if (!(--i)) {
            HDF_LOGE("Fail to set prescaler, reload regs.");
            return HDF_FAILURE;
        }
    }

    /* reload watchdog */
    reg_write(iwdg->base, IWDG_KR, KR_KEY_RELOAD);

    /* iwdg start */
    iwdg->start = true;

    return HDF_SUCCESS;
}

int32_t GD450wdgSetTimeout(struct WatchdogCntlr *wdt, uint32_t seconds)
{
    struct GD450wdg *iwdg = NULL;

    if (wdt == NULL) {
        return HDF_ERR_INVALID_OBJECT;
    }

    iwdg = (struct GD450wdg *)wdt->priv;
    iwdg->seconds = seconds;

    // 如果iwdg已经是启动状态, 需要重新装载超时值并继续喂狗操作
    if (iwdg->start) {
        return GD450wdgStart(wdt);
    }

    return HDF_SUCCESS;
}

int32_t GD450wdgGetTimeout(struct WatchdogCntlr *wdt, uint32_t *seconds)
{
    struct GD450wdg *iwdg = NULL;
    if (wdt == NULL || seconds == NULL) {
        return HDF_ERR_INVALID_OBJECT;
    }
    iwdg = (struct GD450wdg *)wdt->priv;

    *seconds = iwdg->seconds;

    return HDF_SUCCESS;
}

static int32_t GD450wdgFeed(struct WatchdogCntlr *wdt)
{
    struct GD450wdg *iwdg = NULL;

    if (wdt == NULL) {
        return HDF_ERR_INVALID_OBJECT;
    }
    iwdg = (struct GD450wdg *)wdt->priv;

    /* reload watchdog */
    reg_write(iwdg->base, IWDG_KR, KR_KEY_RELOAD);

    return HDF_SUCCESS;
}

static int32_t GD450wdgGetStatus(struct WatchdogCntlr *wdt, int32_t *status)
{
    (void)status;
    int32_t ret = WATCHDOG_STOP;
    struct GD450wdg *iwdg = NULL;

    if (wdt == NULL) {
        return HDF_ERR_INVALID_OBJECT;
    }
    iwdg = (struct GD450wdg *)wdt->priv;

    if (iwdg->start) {
        ret = WATCHDOG_START;
    }
    return ret;
}

/* WatchdogOpen 的时候被调用 */
static int32_t GD450wdgGetPriv(struct WatchdogCntlr *wdt)
{
    int32_t ret;
    struct GD450wdg *iwdg = NULL;

    if (wdt == NULL) {
        return HDF_ERR_INVALID_OBJECT;
    }
    iwdg = (struct GD450wdg *)wdt->priv;

    // 获取当前时钟源频率
    ret = GD450wdgGetClockRate(iwdg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("GD450wdgGetClockRate fail, ret : %#x.", ret);
        return HDF_FAILURE;
    }

    // 计算最大最小的超时时间
    iwdg->min_timeout = DIV_ROUND_UP((RLR_MIN + 1) * PR_MIN, iwdg->rate);
    iwdg->max_hw_heartbeat_ms = ((RLR_MAX + 1) * TWO_TO_TENTH * BORDER_MULTIPLE) / iwdg->rate;

    return ret;
}

/* WatchdogClose 的时候被调用 */
static void GD450wdgReleasePriv(struct WatchdogCntlr *wdt)
{
    (void)wdt;
}

static struct WatchdogMethod g_gd450_iwdg_ops = {.feed = GD450wdgFeed,
                                                 .getPriv = GD450wdgGetPriv,
                                                 .getStatus = GD450wdgGetStatus,
                                                 .getTimeout = GD450wdgGetTimeout,
                                                 .releasePriv = GD450wdgReleasePriv,
                                                 .setTimeout = GD450wdgSetTimeout,
                                                 .start = GD450wdgStart,
                                                 // iwdg不支持软件停止
                                                 .stop = NULL};

static int32_t GD450wdgReadDrs(struct GD450wdg *iwdg, const struct DeviceResourceNode *node)
{
    int32_t ret;
    struct DeviceResourceIface *drsOps = NULL;

    drsOps = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (drsOps == NULL || drsOps->GetUint32 == NULL) {
        HDF_LOGE("%s: invalid drs ops!", __func__);
        return HDF_FAILURE;
    }

    // num
    ret = drsOps->GetUint32(node, "num", &iwdg->num, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read num fail!", __func__);
        return ret;
    }

    // reg_base
    ret = drsOps->GetUint32(node, "reg_base", &iwdg->phy_base, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read regBase fail!", __func__);
        return ret;
    }

    // reg_step
    ret = drsOps->GetUint32(node, "reg_step", &iwdg->reg_step, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read regStep fail!", __func__);
        return ret;
    }

    // default timeout
    ret = drsOps->GetUint32(node, "timeout_sec", &iwdg->seconds, DEFAULT_TIMEOUT);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read timeout fail!", __func__);
        return ret;
    }

    // default source rate
    ret = drsOps->GetUint32(node, "clock_rate", &iwdg->rate, DEFAULT_CLOCK_RATE);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read clock_rate fail!", __func__);
        return ret;
    }

    // start
    iwdg->start = drsOps->GetBool(node, "start");

    return HDF_SUCCESS;
}

static int32_t GD450wdgBind(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct GD450wdg *iwdg = NULL;

    if (device == NULL || device->property == NULL) {
        HDF_LOGE("%s: device or property is null!", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    // 申请内存空间
    iwdg = (struct GD450wdg *)OsalMemCalloc(sizeof(struct GD450wdg));
    if (iwdg == NULL) {
        HDF_LOGE("%s: malloc iwdg fail!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    // 解析配置
    ret = GD450wdgReadDrs(iwdg, device->property);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read drs fail:%d", __func__, ret);
        OsalMemFree(iwdg);
        return ret;
    }

    // 寄存器映射
    iwdg->base = OsalIoRemap(iwdg->phy_base, iwdg->reg_step);
    if (iwdg->base == NULL) {
        HDF_LOGE("%s: ioremap regbase fail!", __func__);
        OsalMemFree(iwdg);
        return HDF_ERR_IO;
    }

    // 填充操作符
    iwdg->wdt.priv = (void *)iwdg;
    iwdg->wdt.ops = &g_gd450_iwdg_ops;
    iwdg->wdt.device = device;
    iwdg->wdt.wdtId = iwdg->num;

    // add device
    ret = WatchdogCntlrAdd(&iwdg->wdt);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: err add watchdog:%d.", __func__, ret);
        OsalIoUnmap((void *)iwdg->base);
        OsalMemFree(iwdg);
        return ret;
    }

    return HDF_SUCCESS;
}

static int32_t GD450wdgInit(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct WatchdogCntlr *wdt = NULL;
    struct GD450wdg *iwdg = NULL;

    // get WatchdogCntlr
    wdt = WatchdogCntlrFromDevice(device);
    if (wdt == NULL) {
        return HDF_FAILURE;
    }
    iwdg = (struct GD450wdg *)wdt->priv;

    // get priv data(get clock source)
    ret = GD450wdgGetPriv(wdt);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("GD450wdgGetPriv fail.");
        return HDF_FAILURE;
    }

    // set default timeout
    ret = GD450wdgSetTimeout(wdt, iwdg->seconds);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("GD450wdgSetTimeout fail.");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void GD450wdgRelease(struct HdfDeviceObject *device)
{
    struct WatchdogCntlr *wdt = NULL;
    struct GD450wdg *iwdg = NULL;

    if (device == NULL) {
        return;
    }

    wdt = WatchdogCntlrFromDevice(device);
    if (wdt == NULL) {
        return;
    }
    WatchdogCntlrRemove(wdt);

    iwdg = (struct GD450wdg *)wdt->priv;
    if (iwdg->base != NULL) {
        OsalIoUnmap((void *)iwdg->base);
        iwdg->base = NULL;
    }
    OsalMemFree(iwdg);
}

struct HdfDriverEntry g_hdf_driver_iwdg_entry = {
    .moduleVersion = 1,
    .Bind = GD450wdgBind,
    .Init = GD450wdgInit,
    .Release = GD450wdgRelease,
    .moduleName = "gd450_iwdg",
};
HDF_INIT(g_hdf_driver_iwdg_entry);
