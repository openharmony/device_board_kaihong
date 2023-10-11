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

#ifndef EXMC_SDRAM_H
#define EXMC_SDRAM_H

#include "gd32f4xx.h"

#define SDRAM_DEVICE0_ADDR ((uint32_t)0xC0000000)
#define SDRAM_DEVICE1_ADDR ((uint32_t)0xD0000000)

extern int __bss_start__;
extern int __bss_end__;

/* initialize sdram peripheral */
ErrStatus exmc_synchronous_dynamic_ram_init(uint32_t sdram_device);
/* fill the buffer with specified value */
void fill_buffer(uint8_t *pbuffer, uint16_t buffer_lengh, uint16_t offset);
/* write a byte buffer(data is 8 bits) to the EXMC SDRAM memory */
void sdram_writebuffer_8(uint32_t sdram_device, uint8_t *pbuffer, uint32_t writeaddr, uint32_t numbytetowrite);
/* read a block of 8-bit data from the EXMC SDRAM memory */
void sdram_readbuffer_8(uint32_t sdram_device, uint8_t *pbuffer, uint32_t readaddr, uint32_t numbytetoread);
/* write a half-word buffer(data is 16 bits) to the EXMC SDRAM memory */
void sdram_writebuffer_16(uint32_t sdram_device, uint16_t *pbuffer, uint32_t writeaddr, uint32_t numtowrite);
/* read a block of 16-bit data from the EXMC SDRAM memory */
void sdram_readbuffer_16(uint32_t sdram_device, uint16_t *pbuffer, uint32_t readaddr, uint32_t numtowrite);

#endif /* EXMC_SDRAM_H */
