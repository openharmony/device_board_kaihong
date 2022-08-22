# SPDX-License-Identifier: GPL-2.0
#
# Rockchip Clock specific Makefile
#
VENDOR_RK3566_DRIVER_CLK_INCLUDE := -I$(srctree)/drivers/clk/rockchip
EXTRA_CFLAGS += -Wno-error -Wno-implicit-function-declaration
EXTRA_CFLAGS += -Wno-unused-variable -Wno-unused-function -Wno-unused
EXTRA_CFLAGS += -Wno-date-time
EXTRA_CFLAGS += $(VENDOR_RK3566_DRIVER_CLK_INCLUDE)

obj-$(CONFIG_VENDOR_RK3566_DRIVER_CLK) += clk-vendor.o
clk-vendor-y += clk-dclk-divider.o
clk-vendor-y += clk-pvtm.o
obj-$(CONFIG_CLK_RK1808)        += clk-rk1808.o
obj-$(CONFIG_CLK_RK3568)        += clk-rk3568.o

