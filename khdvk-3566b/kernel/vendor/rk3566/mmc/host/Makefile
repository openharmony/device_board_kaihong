# SPDX-License-Identifier: GPL-2.0
VENDOR_DRIVER_MMC_CORE := -I$(srctree)/drivers/mmc
EXTRA_CFLAGS += -Wno-error -Wno-implicit-function-declaration
EXTRA_CFLAGS += -Wno-unused-variable -Wno-unused-function -Wno-unused
EXTRA_CFLAGS += -Wno-date-time
EXTRA_CFLAGS += $(VENDOR_DRIVER_MMC_CORE)

obj-$(CONFIG_VENDOR_RK3566_MMC_HOST_RK_SDMMC_OPS)	+= rk_sdmmc_ops.o
