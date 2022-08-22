# SPDX-License-Identifier: GPL-2.0-only
#
# Rockchip Soc drivers
#
VENDOR_RK3566_DRIVER_CPUFINFO_INCLUDE := -I$(srctree)/drivers
EXTRA_CFLAGS += -Wno-error -Wno-implicit-function-declaration
EXTRA_CFLAGS += -Wno-unused-variable -Wno-unused-function -Wno-unused
EXTRA_CFLAGS += -Wno-date-time
EXTRA_CFLAGS += $(VENDOR_RK3566_DRIVER_CPUFINFO_INCLUDE)

obj-$(CONFIG_ROCKCHIP_CPUINFO) += rockchip-cpuinfo.o
obj-$(CONFIG_ROCKCHIP_HW_DECOMPRESS) += rockchip_decompress.o
obj-$(CONFIG_ROCKCHIP_FIQ_DEBUGGER) += rk_fiq_debugger.o
obj-$(CONFIG_ROCKCHIP_VENDOR_STORAGE) += rk_vendor_storage.o
obj-$(CONFIG_ROCKCHIP_MMC_VENDOR_STORAGE) += sdmmc_vendor_storage.o
obj-$(CONFIG_ROCKCHIP_FLASH_VENDOR_STORAGE) += flash_vendor_storage.o
obj-$(CONFIG_ROCKCHIP_MTD_VENDOR_STORAGE) += mtd_vendor_storage.o
obj-$(CONFIG_ROCKCHIP_IPA) += rockchip_ipa.o
obj-$(CONFIG_ROCKCHIP_OPP) += rockchip_opp_select.o
obj-$(CONFIG_ROCKCHIP_PVTM) += rockchip_pvtm.o
obj-$(CONFIG_ROCKCHIP_SUSPEND_MODE) += rockchip_pm_config.o
obj-$(CONFIG_ROCKCHIP_SYSTEM_MONITOR) += rockchip_system_monitor.o
obj-$(CONFIG_ROCKCHIP_THUNDER_BOOT_SFC) += rockchip_thunderboot_sfc.o
obj-$(CONFIG_ROCKCHIP_DEBUG) += rockchip_debug.o
