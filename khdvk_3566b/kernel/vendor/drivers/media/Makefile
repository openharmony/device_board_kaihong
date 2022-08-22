# SPDX-License-Identifier: GPL-2.0
# Makefile for the kernel vendor  multimedia device drivers.
#
#

# I2C drivers should come before other drivers, otherwise they'll fail
# when compiled as builtin drivers
obj-y += i2c/ 

# Finally, merge the drivers that require the core
obj-y += platform/


