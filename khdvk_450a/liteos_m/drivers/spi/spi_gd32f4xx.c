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

#include "hdf_device_desc.h"
#include "hdf_log.h"
#include "spi_core.h"
#include "gd32f4xx_spi.h"
#include "spi_if.h"
#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
#include "hcs_macro.h"
#include "hdf_config_macro.h"
#else
#include "device_resource_if.h"
#endif

#define BITWORD_EIGHT 8
#define BITWORD_SIXTEEN 16
#define PER_MS_IN_SEC 1000
#define SPI_CLK 100000000
#define WAIT_TIME_MAX 10000
#define SPICFG_MODE 0x0000
#define SPI_SOFT 0

#define GPIO_REG_BASE 0x40020000
#define GPIO_REG_STEP 0x00000400
#define GPIO_BIT_PER_GROUP 16

typedef enum {
    BAUD_RATE_DIV2 = 2,
    BAUD_RATE_DIV4 = 4,
    BAUD_RATE_DIV8 = 8,
    BAUD_RATE_DIV16 = 16,
    BAUD_RATE_DIV32 = 32,
    BAUD_RATE_DIV64 = 64,
    BAUD_RATE_DIV128 = 128,
    BAUD_RATE_DIV256 = 256,
} SPI_BAUD_RATE;

typedef enum {
    SPI_PORT1 = 0,
    SPI_PORT2,
    SPI_PORT3,
    SPI_PORT4,
    SPI_PORT5,
    SPI_PORT6,
    SPI_PORT_MAX,
} SPI_GROUPS;

typedef struct {
    uint32_t speed;
    uint8_t num;
    uint8_t csPin;
    uint8_t dataSize;
    uint8_t misoPin;
    uint8_t mosiPin;
    uint8_t clkPin;
    uint8_t csSoft;
    uint8_t transMode;
    uint8_t mode;
    uint8_t afPin;
    uint8_t enableQuad;
} SpiResource;

typedef struct {
    uint32_t spiId;
    SpiResource resource;
} SpiDevice;

static uint32_t g_spiGroupMaps[SPI_PORT_MAX] = {
    SPI0, SPI1, SPI2, SPI3, SPI4, SPI5,
};

static uint32_t g_rcuSpiGroupMaps[SPI_PORT_MAX] = {
    RCU_SPI0, RCU_SPI1, RCU_SPI2, RCU_SPI3, RCU_SPI4, RCU_SPI5,
};

static inline uint32_t ToGpioPeriph(uint16_t local)
{
    uint32_t gpioPeriph = 0;

    gpioPeriph = GPIO_REG_BASE + (local / GPIO_BIT_PER_GROUP) * GPIO_REG_STEP;

    return gpioPeriph;
}

static inline uint32_t ToGpioPin(uint16_t local)
{
    uint32_t pinNum = 0;

    pinNum = local % GPIO_BIT_PER_GROUP;

    return (BIT(pinNum));
}

static inline rcu_periph_enum ToGpioRcuPeriphNum(uint16_t local)
{
    rcu_periph_enum rcuPeriph;

    rcuPeriph = (rcu_periph_enum)(RCU_REGIDX_BIT(AHB1EN_REG_OFFSET, local / GPIO_BIT_PER_GROUP));

    return rcuPeriph;
}

static void EnableSpiClock(uint32_t spiNum)
{
    switch (spiNum) {
        case SPI_PORT1:
            spi_enable(SPI0);
        case SPI_PORT2:
            spi_enable(SPI1);
        case SPI_PORT3:
            spi_enable(SPI2);
        case SPI_PORT4:
            spi_enable(SPI3);
        case SPI_PORT5:
            spi_enable(SPI4);
        case SPI_PORT6:
            spi_enable(SPI5);
        default:
            break;
    }
}

static void InitSpiRcu(const SpiResource *resource)
{
    rcu_periph_clock_enable(ToGpioRcuPeriphNum(resource->csPin));
    rcu_periph_clock_enable(g_rcuSpiGroupMaps[resource->csPin % GPIO_BIT_PER_GROUP]);
}

static void InitSpiGpio(const SpiResource *resource)
{
    gpio_af_set(ToGpioPeriph(resource->misoPin), AF(resource->afPin), ToGpioPin(resource->misoPin));
    gpio_af_set(ToGpioPeriph(resource->mosiPin), AF(resource->afPin), ToGpioPin(resource->mosiPin));
    gpio_af_set(ToGpioPeriph(resource->clkPin), AF(resource->afPin), ToGpioPin(resource->clkPin));

    if (resource->enableQuad == TRUE) {
        gpio_af_set(GPIOG, AF(resource->afPin), GPIO_PIN_10);
        gpio_af_set(GPIOG, AF(resource->afPin), GPIO_PIN_11);
    }

    gpio_mode_set(ToGpioPeriph(resource->misoPin), GPIO_MODE_AF, GPIO_PUPD_NONE, ToGpioPin(resource->misoPin));
    gpio_mode_set(ToGpioPeriph(resource->mosiPin), GPIO_MODE_AF, GPIO_PUPD_NONE, ToGpioPin(resource->mosiPin));
    gpio_mode_set(ToGpioPeriph(resource->clkPin), GPIO_MODE_AF, GPIO_PUPD_NONE, ToGpioPin(resource->clkPin));
    if (resource->enableQuad == TRUE) {
        gpio_output_options_set(GPIOG, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO_PIN_10);
        gpio_output_options_set(GPIOG, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO_PIN_11);
    }

    gpio_output_options_set(ToGpioPeriph(resource->misoPin), GPIO_OTYPE_PP, GPIO_OSPEED_25MHZ,
                            ToGpioPin(resource->misoPin));
    gpio_output_options_set(ToGpioPeriph(resource->mosiPin), GPIO_OTYPE_PP, GPIO_OSPEED_25MHZ,
                            ToGpioPin(resource->mosiPin));
    gpio_output_options_set(ToGpioPeriph(resource->clkPin), GPIO_OTYPE_PP, GPIO_OSPEED_25MHZ,
                            ToGpioPin(resource->clkPin));
    if (resource->enableQuad == TRUE) {
        gpio_output_options_set(GPIOG, GPIO_OTYPE_PP, GPIO_OSPEED_25MHZ, GPIO_PIN_10);
        gpio_output_options_set(GPIOG, GPIO_OTYPE_PP, GPIO_OSPEED_25MHZ, GPIO_PIN_11);
    }

    gpio_mode_set(ToGpioPeriph(resource->csPin), GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, ToGpioPin(resource->csPin));
    gpio_output_options_set(ToGpioPeriph(resource->csPin), GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ,
                            ToGpioPin(resource->csPin));
}

static int32_t SpiSendRecv(const SpiDevice *spiDevice, uint8_t *txData, uint8_t *rxData, uint16_t len)
{
    uint32_t spiId;
    uint32_t time = 0;
    SpiResource *resource = NULL;
    if (spiDevice == NULL || len == 0) {
        HDF_LOGE("spi input para err");
        return HDF_ERR_INVALID_PARAM;
    }
    spiId = spiDevice->spiId;
    resource = &spiDevice->resource;

    if ((resource->transMode == SPI_INTERRUPT_TRANSFER) || (resource->transMode == SPI_DMA_TRANSFER)) {
        HDF_LOGE("%s: transfer mode is not support!", __func__);
        return HDF_ERR_INVALID_PARAM;
    } else if (resource->transMode != SPI_POLLING_TRANSFER) {
        HDF_LOGE("%s: error transfer mode!", __func__);
    }

    while (len--) {
        if (txData != NULL) {
            time = 0;
            while ((RESET == spi_i2s_flag_get(g_spiGroupMaps[spiId], SPI_FLAG_TBE)) && (time <= WAIT_TIME_MAX)) {
                time++;
            }
            if (time > WAIT_TIME_MAX) {
                return HDF_FAILURE;
            }
            spi_i2s_data_transmit(g_spiGroupMaps[spiId], *txData);
            txData++;
        }

        if (rxData != NULL) {
            time = 0;
            while ((RESET == spi_i2s_flag_get(g_spiGroupMaps[spiId], SPI_FLAG_RBNE)) && (time <= WAIT_TIME_MAX)) {
                time++;
            }
            if (time > WAIT_TIME_MAX) {
                return HDF_FAILURE;
            }
            *rxData = spi_i2s_data_receive(g_spiGroupMaps[spiId]);
            rxData++;
        }
    }

    return HDF_SUCCESS;
}
static void SpiClkInit(spi_parameter_struct *spi, const SpiResource *resource)
{
    if (SPI_CLK / resource->speed <= BAUD_RATE_DIV2) {
        spi->prescale = SPI_PSC_2;
    } else if (SPI_CLK / resource->speed <= BAUD_RATE_DIV4) {
        spi->prescale = SPI_PSC_4;
    } else if (SPI_CLK / resource->speed <= BAUD_RATE_DIV8) {
        spi->prescale = SPI_PSC_8;
    } else if (SPI_CLK / resource->speed <= BAUD_RATE_DIV16) {
        spi->prescale = SPI_PSC_16;
    } else if (SPI_CLK / resource->speed <= BAUD_RATE_DIV32) {
        spi->prescale = SPI_PSC_32;
    } else if (SPI_CLK / resource->speed <= BAUD_RATE_DIV64) {
        spi->prescale = SPI_PSC_64;
    } else if (SPI_CLK / resource->speed <= BAUD_RATE_DIV128) {
        spi->prescale = SPI_PSC_128;
    } else if (SPI_CLK / resource->speed > BAUD_RATE_DIV128) {
        spi->prescale = SPI_PSC_256;
    }
}
static void SpiStructInit(spi_parameter_struct *spi, const SpiResource *resource)
{
    uint32_t temp = 0;
    spi->device_mode = SPI_MASTER;
    spi->trans_mode = SPI_TRANSMODE_FULLDUPLEX;
    if (resource->dataSize == BITWORD_EIGHT) {
        spi->frame_size = SPI_FRAMESIZE_8BIT;
    } else {
        spi->frame_size = SPI_FRAMESIZE_16BIT;
    }
    temp = (resource->mode & (SPI_CLK_PHASE | SPI_CLK_POLARITY));
    switch (temp) {
        case (SPI_CLK_PHASE | SPI_CLK_POLARITY):
            spi->clock_polarity_phase = SPI_CK_PL_HIGH_PH_2EDGE;
            break;
        case SPI_CLK_PHASE:
            spi->clock_polarity_phase = SPI_CK_PL_LOW_PH_2EDGE;
            break;
        case SPI_CLK_POLARITY:
            spi->clock_polarity_phase = SPI_CK_PL_HIGH_PH_1EDGE;
            break;
        default:
            spi->clock_polarity_phase = SPI_CK_PL_LOW_PH_1EDGE;
            break;
    }
    if (resource->mode & SPI_MODE_LSBFE) {
        spi->endian = SPI_ENDIAN_LSB;
    } else {
        spi->endian = SPI_ENDIAN_MSB;
    }
    if (resource->csSoft == SPI_SOFT) {
        spi->nss = SPI_NSS_SOFT;
    } else {
        spi->nss = SPI_NSS_HARD;
    }
    SpiClkInit(spi, resource);
    return;
}

static int32_t InitSpiDevice(const SpiDevice *spiDevice)
{
    SpiResource *resource = NULL;
    spi_parameter_struct spiInitStruct = {0};
    uint32_t spix;

    if (spiDevice == NULL) {
        HDF_LOGE("%s: invalid parameter", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    resource = &spiDevice->resource;
    spix = g_spiGroupMaps[resource->num];

    SpiStructInit(&spiInitStruct, resource);
    spi_init(spix, &spiInitStruct);

    if (resource->enableQuad == TRUE) {
        /* quad wire SPI_IO2 and SPI_IO3 pin output enable */
        spi_quad_io23_output_enable(spix);
    }

    spi_enable(spix);

    return HDF_SUCCESS;
}

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
#define SPI_FIND_CONFIG(node, name, resource, spiDevice)                                                               \
    do {                                                                                                               \
        if (strcmp(HCS_PROP(node, match_attr), name) == 0) {                                                           \
            resource->speed = HCS_PROP(node, speed);                                                                   \
            resource->num = HCS_PROP(node, num);                                                                       \
            resource->csPin = HCS_PROP(node, csPin);                                                                   \
            resource->dataSize = HCS_PROP(node, dataSize);                                                             \
            resource->clkPin = HCS_PROP(node, clkPin);                                                                 \
            resource->mosiPin = HCS_PROP(node, mosiPin);                                                               \
            resource->misoPin = HCS_PROP(node, misoPin);                                                               \
            resource->afPin = HCS_PROP(node, afPin);                                                                   \
            resource->enableQuad = HCS_PROP(node, enableQuad);                                                         \
            resource->csSoft = HCS_PROP(node, csSoft);                                                                 \
            resource->transMode = HCS_PROP(node, transMode);                                                           \
            resource->mode = HCS_PROP(node, mode);                                                                     \
            spiDevice->spiId = resource->num;                                                                          \
            result = HDF_SUCCESS;                                                                                      \
        }                                                                                                              \
    } while (0)

#define PLATFORM_CONFIG HCS_NODE(HCS_ROOT, platform)
#define PLATFORM_SPI_CONFIG HCS_NODE(HCS_NODE(HCS_ROOT, platform), spi_config)
static int32_t GetSpiDeviceResource(SpiDevice *spiDevice, const char *deviceMatchAttr)
{
    int32_t result = HDF_FAILURE;
    SpiResource *resource = NULL;
    if (spiDevice == NULL || deviceMatchAttr == NULL) {
        HDF_LOGE("device or deviceMatchAttr is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    resource = &spiDevice->resource;
#if HCS_NODE_HAS_PROP(PLATFORM_CONFIG, spi_config)
    HCS_FOREACH_CHILD_VARGS(PLATFORM_SPI_CONFIG, SPI_FIND_CONFIG, deviceMatchAttr, resource, spiDevice);
#endif
    if (result != HDF_SUCCESS) {
        HDF_LOGE("resourceNode %s is NULL", deviceMatchAttr);
    }
    return result;
}
#else
static int32_t GetSpiDeviceResource(SpiDevice *spiDevice, const struct DeviceResourceNode *resourceNode)
{
    struct DeviceResourceIface *dri = NULL;
    SpiResource *resource = NULL;

    if (spiDevice == NULL || resourceNode == NULL) {
        HDF_LOGE("%s: PARAM is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    resource = &spiDevice->resource;
    if (resource == NULL) {
        HDF_LOGE("%s: resource is NULL", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    dri = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (dri == NULL || dri->GetUint16 == NULL || dri->GetUint8 == NULL || dri->GetUint32 == NULL) {
        HDF_LOGE("DeviceResourceIface is invalid");
        return HDF_ERR_INVALID_PARAM;
    }

    if (dri->GetUint8(resourceNode, "num", &resource->num, 0) != HDF_SUCCESS) {
        HDF_LOGE("get config num failed");
        return HDF_FAILURE;
    }
    if (dri->GetUint8(resourceNode, "csPin", &resource->csPin, 0) != HDF_SUCCESS) {
        HDF_LOGE("get config csPin failed");
        return HDF_FAILURE;
    }
    if (dri->GetUint32(resourceNode, "speed", &resource->speed, 0) != HDF_SUCCESS) {
        HDF_LOGE("get config speed failed");
        return HDF_FAILURE;
    }
    if (dri->GetUint32(resourceNode, "dataSize", &resource->dataSize, 0) != HDF_SUCCESS) {
        HDF_LOGE("get config dataSize failed");
        return HDF_FAILURE;
    }
    if (dri->GetUint32(resourceNode, "clkPin", &resource->clkPin, 0) != HDF_SUCCESS) {
        HDF_LOGE("get config spiClkPin failed");
        return HDF_FAILURE;
    }
    if (dri->GetUint32(resourceNode, "mosiPin", &resource->mosiPin, 0) != HDF_SUCCESS) {
        HDF_LOGE("get config spiMosiPin failed");
        return HDF_FAILURE;
    }
    if (dri->GetUint32(resourceNode, "misoPin", &resource->misoPin, 0) != HDF_SUCCESS) {
        HDF_LOGE("get config spiMisoPin failed");
        return HDF_FAILURE;
    }
    if (dri->GetUint32(resourceNode, "csSoft", &resource->csSoft, 0) != HDF_SUCCESS) {
        HDF_LOGE("get config spiCsSoft failed");
        return HDF_FAILURE;
    }
    if (dri->GetUint32(resourceNode, "transMode", &resource->transMode, 0) != HDF_SUCCESS) {
        HDF_LOGE("get config transMode failed");
        return HDF_FAILURE;
    }
    if (dri->GetUint32(resourceNode, "mode", &resource->mode, 0) != HDF_SUCCESS) {
        HDF_LOGE("get config mode failed");
        return HDF_FAILURE;
    }
    if (dri->GetUint32(resourceNode, "afPin", &resource->afPin, 0) != HDF_SUCCESS) {
        HDF_LOGE("get config afPin failed");
        return HDF_FAILURE;
    }
    if (dri->GetUint32(resourceNode, "enableQuad", &resource->enableQuad, 0) != HDF_SUCCESS) {
        HDF_LOGE("get config enableQuad failed");
        return HDF_FAILURE;
    }

    spiDevice->spiId = resource->num;

    return HDF_SUCCESS;
}
#endif

static int32_t AttachSpiDevice(struct SpiCntlr *spiCntlr, const struct HdfDeviceObject *device)
{
    int32_t ret;
    SpiDevice *spiDevice = NULL;

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    if (spiCntlr == NULL || device == NULL) {
#else
    if (spiCntlr == NULL || device == NULL || device->property == NULL) {
#endif
        HDF_LOGE("%s: param is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    spiDevice = (struct SpiDevice *)OsalMemAlloc(sizeof(*spiDevice));
    if (spiDevice == NULL) {
        HDF_LOGE("%s: OsalMemAlloc spiDevice error", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

#ifdef LOSCFG_DRIVERS_HDF_CONFIG_MACRO
    ret = GetSpiDeviceResource(spiDevice, device->deviceMatchAttr);
#else
    ret = GetSpiDeviceResource(spiDevice, device->property);
#endif
    if (ret != HDF_SUCCESS) {
        (void)OsalMemFree(spiDevice);
        return HDF_FAILURE;
    }

    spiCntlr->priv = spiDevice;
    spiCntlr->busNum = spiDevice->spiId;

    InitSpiRcu(&spiDevice->resource);
    InitSpiGpio(&spiDevice->resource);
    InitSpiDevice(spiDevice);

    return HDF_SUCCESS;
}

static int32_t SpiDevOpen(struct SpiCntlr *spiCntlr)
{
    HDF_LOGI("Enter %s", __func__);
    if (spiCntlr == NULL) {
        HDF_LOGE("spiCntlr is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    SpiDevice *spiDevice = NULL;
    spiDevice = (SpiDevice *)spiCntlr->priv;
    uint32_t spix = g_spiGroupMaps[spiDevice->resource.num];
    spi_enable(spix);

    return HDF_SUCCESS;
}

static int32_t SpiDevClose(struct SpiCntlr *spiCntlr)
{
    HDF_LOGI("Enter %s", __func__);
    if (spiCntlr == NULL) {
        HDF_LOGE("spiCntlr is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    SpiDevice *spiDevice = NULL;
    spiDevice = (SpiDevice *)spiCntlr->priv;
    uint32_t spix = g_spiGroupMaps[spiDevice->resource.num];
    spi_disable(spix);

    return HDF_SUCCESS;
}

static int32_t SpiDevGetCfg(struct SpiCntlr *spiCntlr, struct SpiCfg *spiCfg)
{
    SpiDevice *spiDevice = NULL;
    if (spiCntlr == NULL || spiCfg == NULL || spiCntlr->priv == NULL) {
        HDF_LOGE("%s: spiCntlr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    spiDevice = (SpiDevice *)spiCntlr->priv;
    if (spiDevice == NULL) {
        return HDF_DEV_ERR_NO_DEVICE;
    }

    spiCfg->maxSpeedHz = spiDevice->resource.speed;
    spiCfg->mode = spiDevice->resource.mode;
    spiCfg->transferMode = spiDevice->resource.transMode;
    spiCfg->bitsPerWord = spiDevice->resource.dataSize;

    return HDF_SUCCESS;
}

static int32_t SpiDevSetCfg(struct SpiCntlr *spiCntlr, struct SpiCfg *spiCfg)
{
    SpiDevice *spiDevice = NULL;
    if (spiCntlr == NULL || spiCfg == NULL || spiCntlr->priv == NULL) {
        HDF_LOGE("%s: spiCntlr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    spiDevice = (SpiDevice *)spiCntlr->priv;
    if (spiDevice == NULL) {
        HDF_LOGE("%s: spiDevice is NULL", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    if ((spiDevice->resource.speed == spiCfg->maxSpeedHz) && (spiDevice->resource.dataSize == spiCfg->bitsPerWord) &&
        (spiDevice->resource.transMode == spiCfg->transferMode) && (spiDevice->resource.mode == spiCfg->mode)) {
        return HDF_SUCCESS;
    }

    spiDevice->resource.speed = spiCfg->maxSpeedHz;
    spiDevice->resource.dataSize = spiCfg->bitsPerWord;
    spiDevice->resource.transMode = spiCfg->transferMode;
    spiDevice->resource.mode = spiCfg->mode;

    return InitSpiDevice(spiDevice);
}

static int32_t SpiDevTransfer(struct SpiCntlr *spiCntlr, struct SpiMsg *spiMsg, uint32_t count)
{
    SpiDevice *spiDevice = NULL;
    uint32_t ticks = 0;
    int32_t ret = 0;
    uint8_t singleCsChange = 0;
    struct SpiMsg *msg = NULL;
    msg = (struct SpiMsg *)OsalMemAlloc(sizeof(*msg));
    if (spiCntlr == NULL || spiCntlr->priv == NULL) {
        HDF_LOGE("%s: spiCntlr is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    spiDevice = (SpiDevice *)spiCntlr->priv;
    InitSpiDevice(spiDevice);

    for (size_t i = 0; i < count; i++) {
        msg = &spiMsg[i];
        gpio_bit_reset(ToGpioPeriph((spiDevice->resource).csPin), ToGpioPin((spiDevice->resource).csPin));

        ret = SpiSendRecv(spiDevice, msg->wbuf, msg->rbuf, msg->len);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: SpiSendRecv failed: ret is %x", __func__, ret);
        }

        if (msg->keepCs == 0 || singleCsChange) {
            gpio_bit_reset(ToGpioPeriph((spiDevice->resource).csPin), ToGpioPin((spiDevice->resource).csPin));
        }
        if (msg->delayUs > 0) {
            ticks = (msg->delayUs / PER_MS_IN_SEC);
            osDelay(ticks);
        }
    }

    HDF_LOGD("%s success\n", __func__);
    return HDF_SUCCESS;
}

struct SpiCntlrMethod g_method = {
    .Transfer = SpiDevTransfer,
    .SetCfg = SpiDevSetCfg,
    .GetCfg = SpiDevGetCfg,
    .Open = SpiDevOpen,
    .Close = SpiDevClose,
};

static int32_t SpiDriverBind(struct HdfDeviceObject *device)
{
    struct SpiCntrl *spiCntlr = NULL;

    HDF_LOGI("%s: Enter ", __func__);

    if (device == NULL) {
        HDF_LOGE("device object is null!");
        return HDF_ERR_INVALID_PARAM;
    }

    spiCntlr = SpiCntlrCreate(device);
    if (spiCntlr == NULL) {
        HDF_LOGE("SpiCntrlCreate object failed!");
        return HDF_FAILURE;
    }
    HDF_LOGI("%s spi bind success\n", __func__);

    return HDF_SUCCESS;
}

static int32_t SpiDriverInit(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct SpiCntlr *spiCntlr = NULL;

    if (device == NULL) {
        HDF_LOGE("device object is null!");
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%s: Enter", __func__);

    spiCntlr = SpiCntlrFromDevice(device);
    if (spiCntlr == NULL) {
        HDF_LOGE("%s: spiCntlr is NULL", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    ret = AttachSpiDevice(spiCntlr, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: attach error", __func__);
        return HDF_DEV_ERR_ATTACHDEV_FAIL;
    }

    spiCntlr->method = &g_method;
    HDF_LOGI("%s spi%d init success\n", __func__, spiCntlr->busNum);

    return HDF_SUCCESS;
}

static void SpiDriverRelease(struct HdfDeviceObject *device)
{
    struct SpiCntlr *spiCntlr = NULL;
    SpiDevice *spiDevice = NULL;
    if (device == NULL) {
        HDF_LOGE("%s: device is NULL", __func__);
        return;
    }

    spiCntlr = SpiCntlrFromDevice(device);
    if (spiCntlr == NULL || spiCntlr->priv == NULL) {
        HDF_LOGE("%s: spiCntlr is NULL", __func__);
        return;
    }

    spiDevice = (SpiDevice *)spiCntlr->priv;
    OsalMemFree(spiDevice);

    HDF_LOGD("%s success", __func__);
}

struct HdfDriverEntry g_hdfSpiDevice = {
    .moduleVersion = 1,
    .moduleName = "GD_SPI_MODULE_HDF",
    .Bind = SpiDriverBind,
    .Init = SpiDriverInit,
    .Release = SpiDriverRelease,
};
HDF_INIT(g_hdfSpiDevice);