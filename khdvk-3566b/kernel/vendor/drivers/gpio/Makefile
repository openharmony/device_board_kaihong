# SPDX-License-Identifier: GPL-2.0
# generic gpio support: platform drivers, dedicated expander chips, etc

VENDOR_BOARD_GPIO_INCLUDE := -I$(srctree)/drivers/pinctrl
EXTRA_CFLAGS += -Wno-error -Wno-implicit-function-declaration
EXTRA_CFLAGS += -Wno-unused-variable -Wno-unused-function -Wno-unused
EXTRA_CFLAGS += -Wno-date-time
EXTRA_CFLAGS += $(VENDOR_BOARD_GPIO_INCLUDE)

obj-$(CONFIG_VENDOR_GPIO_ROCKCHIP)		+= gpio-rockchip.o