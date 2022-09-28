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

#$1 - kernel source root dir                    //kernel/linux/linux-5.10
#$2 - kernel build script stage dir             //out/KERNEL_OBJ 
#$3 - GN target output dir image output dir     //out/khdvk_3566b/packages/phone/images
#$4 - device build script work dir              //device/board/kaihong/khdvk_3566b
#$5 - device_name                               khdvk_3566b

KERNEL_DIR=`realpath ${1}`
KERNEL_BUILD_OBJ=${2}
export IMAGES_OUT_PATH=$3
DEVICE_DIR=$4
export DEVICE_NAME=$5
export PRODUCT_PATH=$6
export PRODUCT_COMPANY=$7

KERNEL_BUILD_ROOT_DIR=$KERNEL_BUILD_OBJ/$DEVICE_NAME
KERNEL_OBJ_TMP_PATH=$KERNEL_BUILD_OBJ/OBJ/kernel

echo "+++++++++++++++++++BUILD KERNEL CONFIG AS:+++++++++++++++++"
echo "KERNEL_DIR=${KERNEL_DIR}"
echo "KERNEL_BUILD_OBJ=$KERNEL_BUILD_OBJ"
echo "{IMAGES_OUT_PATH}=${IMAGES_OUT_PATH}"
echo "DEVICE_DIR=$DEVICE_DIR"
echo "DEVICE_NAME=$DEVICE_NAME"
echo "+++++++++++++++++++BUILD KERNEL CONFIG END+++++++++++++++++"

if [ ! -d "${IMAGES_OUT_PATH}" ];then
	mkdir -p ${IMAGES_OUT_PATH}
fi

ROOT_DIR=`realpath ${KERNEL_DIR}/../../..`
KERNEL_SRC_TMP_PATH=$KERNEL_BUILD_ROOT_DIR/kernel/
BORAD_DIR=$DEVICE_DIR
KERNEL_PATCH_PATH=${ROOT_DIR}/kernel/linux/patches/linux-5.10

rm -rf ${KERNEL_BUILD_ROOT_DIR}

# Copy kernel source code
if [ ! -d "${KERNEL_SRC_TMP_PATH}" ];then
	mkdir -p ${KERNEL_SRC_TMP_PATH}   
fi

cp -arfp $KERNEL_DIR/* ${KERNEL_SRC_TMP_PATH}

pushd ${KERNEL_SRC_TMP_PATH}
#HDF patch
bash ${ROOT_DIR}/drivers/hdf_core/adapter/khdf/linux/patch_hdf.sh ${ROOT_DIR} ${KERNEL_SRC_TMP_PATH} ${KERNEL_PATCH_PATH} ${DEVICE_NAME}
popd

#copy logo、dts、defconfig、sh、parameter.txt
cp -rf ${BORAD_DIR}/resource/logo* ${KERNEL_SRC_TMP_PATH}/
cp -arfpL $BORAD_DIR/kernel/*defconfig  $KERNEL_BUILD_ROOT_DIR/kernel/arch/arm64/configs/
cp -arfpL $BORAD_DIR/kernel/*.dts*   $KERNEL_BUILD_ROOT_DIR/kernel/arch/arm64/boot/dts/rockchip/
cp -arfpL $BORAD_DIR/kernel/make_ohos.sh ${KERNEL_SRC_TMP_PATH}
cp -arfpL $BORAD_DIR/loader/parameter-fit.txt ${IMAGES_OUT_PATH}/parameter.txt

#拷贝kernel patch 删减
cp -arfp $BORAD_DIR/../../../soc/rockchip/common/sdk_linux/*  $KERNEL_BUILD_ROOT_DIR/kernel/
cp -arfp $BORAD_DIR/../../../soc/rockchip/common/vendor  $KERNEL_BUILD_ROOT_DIR/kernel/
cp -arfp $BORAD_DIR/../../../soc/rockchip/rk3566/sdk_linux/*  $KERNEL_BUILD_ROOT_DIR/kernel/
cp -arfp $BORAD_DIR/../../../soc/rockchip/rk3566/vendor  $KERNEL_BUILD_ROOT_DIR/kernel/


cp -arfp $BORAD_DIR/kernel/modem/option.c  $KERNEL_BUILD_ROOT_DIR/kernel/drivers/usb/serial

cp -arfp $BORAD_DIR/kernel/touchscreen/touch* ${ROOT_DIR}/drivers/hdf_core/framework/model/input/driver/touchscreen/
cp -arfp $BORAD_DIR/kernel/touchscreen/Makefile ${ROOT_DIR}/drivers/hdf_core/adapter/khdf/linux/model/input/
cp -arfp $BORAD_DIR/kernel/touchscreen/Kconfig  ${ROOT_DIR}/drivers/hdf_core/adapter/khdf/linux/model/input/
cp -arfp $BORAD_DIR/kernel/panel/mipi* ${ROOT_DIR}/drivers/hdf_core/framework/model/display/driver/panel/
cp -arfp $BORAD_DIR/kernel/panel/Makefile ${ROOT_DIR}/drivers/hdf_core/adapter/khdf/linux/model/display/
cp -arfp $BORAD_DIR/kernel/panel/Kconfig ${ROOT_DIR}/drivers/hdf_core/adapter/khdf/linux/model/display/

pushd $KERNEL_BUILD_ROOT_DIR
rm -rf ${KERNEL_OBJ_TMP_PATH}
mkdir -p ${KERNEL_OBJ_TMP_PATH}
export KBUILD_OUTPUT=${KERNEL_OBJ_TMP_PATH}

cd ${KERNEL_SRC_TMP_PATH}
./make_ohos.sh TB-RK3566X0
cd -

#cp boot.img resource.img
cp -arfpL ${KERNEL_SRC_TMP_PATH}/boot_linux.img ${IMAGES_OUT_PATH}/boot.img
cp -arfpL ${KERNEL_OBJ_TMP_PATH}/resource.img ${IMAGES_OUT_PATH}

# Copy loader images(Miniloader.bin and uboot.img) to $OUT
# uboot 获取参考 //khdvk_3566b/README_zh.md 文档
#cp -arfpL ${DEVICE_DIR}/loader/uboot.img ${IMAGES_OUT_PATH}
cp -arfpL ${DEVICE_DIR}/loader/MiniLoaderAll.bin ${IMAGES_OUT_PATH}
popd

touch $DEVICE_DIR/kernel/build_kernel.sh
