# SPDX-License-Identifier: GPL-2.0

VENDOR_RK3566_DRIVER_DEVFREQ_INCLUDE := -I$(srctree)/drivers/devfreq
EXTRA_CFLAGS += -Wno-error -Wno-implicit-function-declaration
EXTRA_CFLAGS += -Wno-unused-variable -Wno-unused-function -Wno-unused
EXTRA_CFLAGS += -Wno-date-time
EXTRA_CFLAGS += $(VENDOR_RK3566_DRIVER_DEVFREQ_INCLUDE)

obj-$(CONFIG_ARM_ROCKCHIP_BUS_DEVFREQ)	+= rockchip_bus.o
obj-$(CONFIG_ARM_ROCKCHIP_DMC_DEVFREQ)	+= rockchip_dmc.o rockchip_dmc_common.o
# DEVFREQ Event Drivers
obj-$(CONFIG_PM_DEVFREQ_EVENT)		    += event/
