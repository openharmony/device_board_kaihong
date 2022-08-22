# SPDX-License-Identifier: GPL-2.0

VENDOR_KHDVK_3566B_DRIVER_NET_TOOL_INCLUDE := -I$(srctree)/drivers/net/ethernet/stmicro/stmmac
EXTRA_CFLAGS += -Wno-error -Wno-implicit-function-declaration
EXTRA_CFLAGS += -Wno-unused-variable -Wno-unused-function -Wno-unused
EXTRA_CFLAGS += -Wno-date-time
EXTRA_CFLAGS += $(VENDOR_KHDVK_3566B_DRIVER_NET_TOOL_INCLUDE)

obj-$(CONFIG_VENDOR_KHDVK_3566B_DRIVER_NET_TOOL)	+= dwmac-rk-tool.o
