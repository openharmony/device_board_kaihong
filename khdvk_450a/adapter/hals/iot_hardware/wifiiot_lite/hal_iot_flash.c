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

#include <stdbool.h>
#include <stdint.h>
#include "iot_errno.h"
#include "iot_flash.h"
#include "fmc_operation.h"

#define ADDR_FMC_SECTOR_0 ((uint32_t)0x08000000)  /*!< base address of sector 0, 16 kbytes */
#define ADDR_FMC_SECTOR_1 ((uint32_t)0x08004000)  /*!< base address of sector 1, 16 kbytes */
#define ADDR_FMC_SECTOR_2 ((uint32_t)0x08008000)  /*!< base address of sector 2, 16 kbytes */
#define ADDR_FMC_SECTOR_3 ((uint32_t)0x0800C000)  /*!< base address of sector 3, 16 kbytes */
#define ADDR_FMC_SECTOR_4 ((uint32_t)0x08010000)  /*!< base address of sector 4, 64 kbytes */
#define ADDR_FMC_SECTOR_5 ((uint32_t)0x08020000)  /*!< base address of sector 5, 64 kbytes */
#define ADDR_FMC_SECTOR_6 ((uint32_t)0x08040000)  /*!< base address of sector 6, 64 kbytes */
#define ADDR_FMC_SECTOR_7 ((uint32_t)0x08060000)  /*!< base address of sector 7, 64 kbytes */
#define ADDR_FMC_SECTOR_8 ((uint32_t)0x08080000)  /*!< base address of sector 8, 64 kbytes */
#define ADDR_FMC_SECTOR_9 ((uint32_t)0x080A0000)  /*!< base address of sector 9, 64 kbytes */
#define ADDR_FMC_SECTOR_10 ((uint32_t)0x080C0000) /*!< base address of sector 10, 64 kbytes */
#define ADDR_FMC_SECTOR_11 ((uint32_t)0x080E0000) /*!< base address of sector 11, 64 kbytes */

static uint32_t g_startAddr = 0;

static int32_t IoTFmcWrite8Bit(uint32_t addr, uint16_t length, int8_t *data_8)
{
    uint32_t address = addr;
    fmc_state_enum fmcState;
    fmc_unlock();
    fmc_flag_clear(FMC_FLAG_END | FMC_FLAG_OPERR | FMC_FLAG_WPERR | FMC_FLAG_PGMERR | FMC_FLAG_PGSERR);
    for (uint32_t i = 0; i < length; i++) {
        fmcState = fmc_byte_program(address, data_8[i]);
        if (FMC_READY == fmcState) {
            address++;
        } else if (FMC_BUSY == fmcState) {
            while (1) { }
        } else {
            return IOT_FAILURE;
        }
    }
    fmc_lock();
    return IOT_SUCCESS;
}

unsigned int IoTFlashRead(unsigned int flashOffset, unsigned int size, unsigned char *ramData)
{
    if (!size || !ramData || !g_startAddr) {
        return IOT_FAILURE;
    }
    unsigned int addr = g_startAddr + flashOffset;
    fmc_read_8bit_data(addr, size, ramData);
    return IOT_SUCCESS;
}

unsigned int IoTFlashWrite(unsigned int flashOffset, unsigned int size, const unsigned char *ramData,
                           unsigned char doErase)
{
    if (!size || !ramData || !g_startAddr) {
        return IOT_FAILURE;
    }
    unsigned int addr = g_startAddr + flashOffset;
    if (doErase) {
        fmc_erase_sector_by_address(addr);
    }
    if (IoTFmcWrite8Bit(addr, size, ramData)) {
        return IOT_FAILURE;
    }
    return IOT_SUCCESS;
}

unsigned int IoTFlashErase(unsigned int flashOffset, unsigned int size)
{
    unsigned int addr = g_startAddr + flashOffset;
    fmc_erase_sector_by_address(addr);
    return IOT_SUCCESS;
}

unsigned int IoTFlashInit(void)
{
    g_startAddr = ADDR_FMC_SECTOR_1;
    return IOT_SUCCESS;
}

unsigned int IoTFlashDeinit(void)
{
    g_startAddr = 0;
    return IOT_SUCCESS;
}
