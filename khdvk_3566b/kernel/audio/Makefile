#
# Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
#
# This software is licensed under the terms of the GNU General Public
# License version 2, as published by the Free Software Foundation, and
# may be copied, distributed, and modified under those terms.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
#

KHDF_AUDIO_KHDF_ROOT_DIR = drivers/hdf/khdf
KHDF_FRAMEWORK_ROOT_DIR = drivers/hdf/framework
KHDF_AUDIO_RK3566_INC_DIR = drivers/hdf/framework/../../../device/board/kaihong/khdvk_3566b/kernel/audio

obj-$(CONFIG_DRIVERS_HDF_AUDIO_RK3566) += \
        codec/rk809_codec/src/rk809_codec_adapter.o \
        codec/rk809_codec/src/rk809_codec_impl.o \
        codec/rk809_codec/src/rk809_codec_linux_driver.o \
        dsp/src/rk3568_dsp_adapter.o \
        dsp/src/rk3568_dsp_ops.o \
        dai/src/rk3568_dai_adapter.o \
        dai/src/rk3568_dai_ops.o \
        dai/src/rk3568_dai_linux_driver.o \
        soc/src/rk3568_dma_adapter.o \
        soc/src/rk3568_dma_ops.o

ccflags-$(CONFIG_DRIVERS_HDF_AUDIO_RK3566) += \
        -I$(srctree)/$(KHDF_AUDIO_KHDF_ROOT_DIR)/osal/include \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/include/core \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/include/utils \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/include/osal \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/include/platform \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/include/config \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/include/audio \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/ability/sbuf/include \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/core/common/include/host \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/core/host/include \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/model/audio/core/include \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/model/audio/sapm/include \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/model/audio/dispatch/include \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/model/audio/common/include \
        -I$(srctree)/bounds_checking_function/include \
        -I$(srctree)/$(KHDF_AUDIO_RK3566_INC_DIR)/soc/include \
        -I$(srctree)/$(KHDF_AUDIO_RK3566_INC_DIR)/dai/include \
        -I$(srctree)/$(KHDF_AUDIO_RK3566_INC_DIR)/dsp/include \
        -I$(srctree)/$(KHDF_AUDIO_RK3566_INC_DIR)/codec/rk809_codec/include \
        -I$(srctree)/$(KHDF_AUDIO_RK3566_INC_DIR)/include

obj-$(CONFIG_DRIVERS_HDF_AUDIO_ANA_HEADSET_3566) += \
        headset_monitor/src/analog_headset_base.o \
        headset_monitor/src/analog_headset_core.o \
        headset_monitor/src/analog_headset_gpio.o \
        headset_monitor/src/analog_headset_adc.o

ccflags-$(CONFIG_DRIVERS_HDF_AUDIO_ANA_HEADSET_3566) += \
        -I$(srctree)/$(KHDF_FRAMEWORK_ROOT_DIR)/model/input/driver \
        -I$(srctree)/drivers/hdf/evdev \
        -I$(srctree)/$(KHDF_AUDIO_RK3566_INC_DIR)/headset_monitor/include
