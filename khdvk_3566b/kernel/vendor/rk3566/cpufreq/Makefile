# SPDX-License-Identifier: GPL-2.0
VENDOR_RK3566_DRIVER_CPUFRQ_INCLUDE := -I$(srctree)/drivers/cpufreq
EXTRA_CFLAGS += -Wno-error -Wno-implicit-function-declaration
EXTRA_CFLAGS += -Wno-unused-variable -Wno-unused-function -Wno-unused
EXTRA_CFLAGS += -Wno-date-time
EXTRA_CFLAGS += $(VENDOR_RK3566_DRIVER_CPUFRQ_INCLUDE)

obj-$(CONFIG_ARM_ROCKCHIP_CPUFREQ)	+= rockchip-cpufreq.o
