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
#$3 - GN target output dir image output dir     //out/ohos-riscv64-release/packages/phone/images
#$4 - device build script work dir              //device/kaihong/chip_rk356x
#$5 - product path                              //vendor/kaihong/RK3566-Firefly
#$6 - product mk config file name               roc-rk3566-pc-ubuntu.mk
#$7 - device_name                               rk3568-khdvk

KERNEL_DIR=`realpath ${1}`
KERNEL_BUILD_OBJ=${2}
export PRODUCT_PATH=$5
export IMAGES_OUT_PATH=$3
DEVICE_DIR=$4
CONFIG_FILE=$6
export DEVICE_NAME=$7
export ENABLE_RAMDISK=$8
export PRODUCT_COMPANY=$9
# $1 $KERNEL_DIR :         /home/openharmony/kernel/linux/linux-5.10
# $2 $KERNEL_BUILD_OBJ :   /home/openharmony/out/KERNEL_OBJ
# $3 $IMAGES_OUT_PATH :  /home/openharmony/out/ohos-arm-release/packages/phone/images
# $4 $DEVICE_DIR :         /home/openharmony/device/kaihong/chip_rk356x
# $5 $PRODUCT_PATH :       vendor/kaihong/RK3566-Firefly
# $6 $CONFIG_FILE :        khdvk-rk3568-ubuntu.mk

KERNEL_BUILD_ROOT_DIR=$KERNEL_BUILD_OBJ/$DEVICE_NAME
KERNEL_OBJ_TMP_PATH=$KERNEL_BUILD_OBJ/OBJ/kernel

echo "+++++++++++++++++++BUILD KERNEL CONFIG AS:+++++++++++++++++"
echo "KERNEL_DIR=${KERNEL_DIR}"
echo "KERNEL_BUILD_OBJ=$KERNEL_BUILD_OBJ"
echo "{IMAGES_OUT_PATH}=${IMAGES_OUT_PATH}"
echo "DEVICE_DIR=$DEVICE_DIR"
echo "PRODUCT_PATH=$PRODUCT_PATH"
echo "CONFIG_FILE=$CONFIG_FILE"
echo "DEVICE_NAME=$DEVICE_NAME"
echo "ENABLE_RAMDISK=$ENABLE_RAMDISK"
echo "PRODUCT_COMPANY=$PRODUCT_COMPANY"
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

if [ ! -d "$KERNEL_BUILD_ROOT_DIR/tools/linux/Linux_Pack_Firmware/rockdev" ];then
	mkdir -p $KERNEL_BUILD_ROOT_DIR/tools/linux/Linux_Pack_Firmware/rockdev
    cp -arfp  $DEVICE_DIR/loader/afptool $KERNEL_BUILD_ROOT_DIR/tools/linux/Linux_Pack_Firmware/rockdev/
	cp -arfp  $DEVICE_DIR/loader/rkImageMaker $KERNEL_BUILD_ROOT_DIR/tools/linux/Linux_Pack_Firmware/rockdev/
fi

if [ ! -d "$KERNEL_BUILD_ROOT_DIR/device/rockchip" ];then
	mkdir -p $KERNEL_BUILD_ROOT_DIR/device/rockchip/common
	mkdir -p $KERNEL_BUILD_ROOT_DIR/device/rockchip/rk356x
    cp -arfpL $DEVICE_DIR/package_script/build.sh $KERNEL_BUILD_ROOT_DIR/device/rockchip/common
    cp -arfpL $DEVICE_DIR/package_script/mk-fitimage.sh $KERNEL_BUILD_ROOT_DIR/device/rockchip/common
    cp -arfpL $DEVICE_DIR/package_script/Version.mk $KERNEL_BUILD_ROOT_DIR/device/rockchip/common
    cp -arfpL $DEVICE_DIR/package_script/BoardConfig.mk $KERNEL_BUILD_ROOT_DIR/device/rockchip/rk356x
    cp -arfpL $DEVICE_DIR/package_script/bootramdisk.its $KERNEL_BUILD_ROOT_DIR/device/rockchip/rk356x
    cp -arfpL $DEVICE_DIR/package_script/rp-rk3566-ramdisk.mk $KERNEL_BUILD_ROOT_DIR/device/rockchip/rk356x
    cp -arfp  $DEVICE_DIR/loader/mkimage $KERNEL_BUILD_ROOT_DIR/device/rockchip/
fi

pushd ${KERNEL_SRC_TMP_PATH}

#HDF patch
bash ${ROOT_DIR}/drivers/hdf_core/adapter/khdf/linux/patch_hdf.sh ${ROOT_DIR} ${KERNEL_SRC_TMP_PATH} ${KERNEL_PATCH_PATH} ${DEVICE_NAME}

popd

cp -rf ${BORAD_DIR}/kernel/config/logo* ${KERNEL_SRC_TMP_PATH}/

cp -arfpL $BORAD_DIR/package_script/package.sh $KERNEL_BUILD_ROOT_DIR
cp -arfpL $BORAD_DIR/package_script/rk356x-mkupdate.sh $KERNEL_BUILD_ROOT_DIR/tools/linux/Linux_Pack_Firmware/rockdev/rk356x-mkupdate.sh
cp -arfpL $BORAD_DIR/package_script/rk3566-rp-package-file $KERNEL_BUILD_ROOT_DIR/tools/linux/Linux_Pack_Firmware/rockdev/rk3566-rp-package-file

#拷贝config、dts、ramdisk.img、parameter.txt
cp -arfpL $BORAD_DIR/kernel/config/*defconfig  $KERNEL_BUILD_ROOT_DIR/kernel/arch/arm64/configs/
cp -arfpL $BORAD_DIR/kernel/config/*.dts*   $KERNEL_BUILD_ROOT_DIR/kernel/arch/arm64/boot/dts/rockchip/


#拷贝kernel patch 删减
cp -arfp $BORAD_DIR/kernel/sdk-linux/*  $KERNEL_BUILD_ROOT_DIR/kernel/
cp -arfp $BORAD_DIR/kernel/vendor  $KERNEL_BUILD_ROOT_DIR/kernel/

cp -arfpL $BORAD_DIR/kernel/make-boot.sh  $KERNEL_BUILD_ROOT_DIR/../../khdvk-3566b/packages/phone
cp -arfpL $BORAD_DIR/loader/parameter-ubuntu-fit.txt $KERNEL_BUILD_ROOT_DIR/device/rockchip/rk356x/parameter-ubuntu-fit.txt

pushd $KERNEL_BUILD_ROOT_DIR

ln -rsf $KERNEL_BUILD_ROOT_DIR/device/rockchip/common/build.sh $KERNEL_BUILD_ROOT_DIR
ln -sf  $KERNEL_BUILD_ROOT_DIR/package.sh ${IMAGES_OUT_PATH}
ln -sf  $KERNEL_BUILD_ROOT_DIR/device/rockchip/common/build.sh ${IMAGES_OUT_PATH}

# config product dts
bash ./build.sh $CONFIG_FILE

#link pack img path
ln -snf ${IMAGES_OUT_PATH} $KERNEL_BUILD_ROOT_DIR/tools/linux/Linux_Pack_Firmware/rockdev/Image

rm -rf ${KERNEL_OBJ_TMP_PATH}
mkdir -p ${KERNEL_OBJ_TMP_PATH}
export KBUILD_OUTPUT=${KERNEL_OBJ_TMP_PATH}

cp -arfpL ${DEVICE_DIR}/loader/ramdisk.img ${IMAGES_OUT_PATH}

bash ./build.sh kernel 
if [ "$ENABLE_RAMDISK" != "true" ];then
    echo "ENABLE_RAMDISK=$ENABLE_RAMDISK"
    cp -arfpL $KERNEL_BUILD_ROOT_DIR/kernel/boot.img ${IMAGES_OUT_PATH}
    cp -arfpL $KERNEL_BUILD_ROOT_DIR/kernel/resource.img ${IMAGES_OUT_PATH}
fi

bash ${IMAGES_OUT_PATH}/../make-boot.sh $KERNEL_BUILD_OBJ/../ ${IMAGES_OUT_PATH}/../

#cp uboot.img
cp -arfpL ${DEVICE_DIR}/loader/uboot.img ${IMAGES_OUT_PATH}

#need to use build target
# Copy loader images(Miniloader.bin and uboot.img) to $OUT
cp -arfpL ${DEVICE_DIR}/loader/MiniLoaderAll.bin ${IMAGES_OUT_PATH}

popd
touch $DEVICE_DIR/kernel/build_kernel.sh
