/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 Rockchip Inc.
 */

#ifndef _RK_SDMMC_OPS_H_
#define _RK_SDMMC_OPS_H_

int rk_emmc_transfer(u8 *buffer, unsigned int addr, unsigned int blksz, int write);

#endif
