
VENDOR_RK3566_DRIVER_STAGING_INCLUDE := -I$(srctree)/vendor/rk3566
EXTRA_CFLAGS += -Wno-error -Wno-implicit-function-declaration
EXTRA_CFLAGS += -Wno-unused-variable -Wno-unused-function -Wno-unused
EXTRA_CFLAGS += -Wno-date-time
EXTRA_CFLAGS += $(VENDOR_RK3566_DRIVER_STAGING_INCLUDE)

obj-$(CONFIG_FIQ_DEBUGGER)	+= fiq_debugger.o
obj-$(CONFIG_FIQ_WATCHDOG)	+= fiq_watchdog.o
