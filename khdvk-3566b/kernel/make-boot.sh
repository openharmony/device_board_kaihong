#!/bin/bash
# Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
BUILD_OUT_DIR=`realpath ${1}`
CURRENT_DIR=$(cd `dirname $0`; pwd)

BOOT_LINUX=$BUILD_OUT_DIR/KERNEL_OBJ/OBJ
export IMAGES_OUT_PATH=$CURRENT_DIR/images/
export PRODUCT_PATH=vendor/kaihong/khdvk-3566b
echo "make-boot.sh PRODUCT_PATH =$PRODUCT_PATH"

cp $CURRENT_DIR/images/ramdisk.img ${BOOT_LINUX}/kernel/ramdisk.img
cd ${BOOT_LINUX}
#bash ./build.sh rp-rk3566-ramdisk.mk
source ../khdvk-3566b/device/rockchip/.BoardConfig.mk
if [ -f "../khdvk-3566b/device/rockchip/$RK_TARGET_PRODUCT/$RK_KERNEL_FIT_ITS" ]; then
	../khdvk-3566b/device/rockchip/common/mk-fitimage.sh ./kernel/$RK_BOOT_IMG \
		../khdvk-3566b/device/rockchip/$RK_TARGET_PRODUCT/$RK_KERNEL_FIT_ITS \
		${BOOT_LINUX}/kernel/ramdisk.img
fi
#bash ./build.sh kernel
cp -arfpL ${BOOT_LINUX}/../khdvk-3566b/kernel/boot.img ${IMAGES_OUT_PATH}
cp -arfpL ${BOOT_LINUX}/kernel/resource.img ${IMAGES_OUT_PATH}

cd -
