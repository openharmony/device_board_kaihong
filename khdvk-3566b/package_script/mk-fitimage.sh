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

SCRIPT_DIR=$(dirname $(realpath $BASH_SOURCE))
TOP_DIR=$(realpath $SCRIPT_DIR/../../..)
cd $TOP_DIR

source $TOP_DIR/device/rockchip/.BoardConfig.mk
ROCKDEV=$TOP_DIR/rockdev

fdt=0
kernel=0
ramdisk=0
resource=0
OUTPUT_TARGET_IMAGE="$1"
src_its_file="$2"
ramdisk_file_path="$3"
kernel_image="$4"
target_its_file="$ROCKDEV/.tmp_its"

if [ -z $kernel_image ]; then
	if [ -z $RK_KERNEL_ZIMG ]; then
		kernel_image=$TOP_DIR/../OBJ/$RK_KERNEL_IMG
	else
		kernel_image=$TOP_DIR/../OBJ/$RK_KERNEL_ZIMG
	fi
fi

if [ ! -f $src_its_file ]; then
	echo "Not Fount $src_its_file ..."
	exit -1
fi

if [ "$RK_ARCH" == "arm" ]; then
	kernel_dtb_file="../OBJ/kernel/arch/arm/boot/dts/$RK_KERNEL_DTS.dtb"
else
	kernel_dtb_file="../OBJ/kernel/arch/arm64/boot/dts/rockchip/$RK_KERNEL_DTS.dtb"
fi

rm -f $target_its_file
mkdir -p "`dirname $target_its_file`"

while read line
do
	############################# generate fdt path
	if [ $fdt -eq 1 ];then
		echo "data = /incbin/(\"$TOP_DIR/$kernel_dtb_file\");" >> $target_its_file
		fdt=0
		continue
	fi
	if echo $line | grep -w "^fdt" |grep -v ";"; then
		fdt=1
		echo "$line" >> $target_its_file
		continue
	fi

	############################# generate kernel image path
	if [ $kernel -eq 1 ];then
		echo "data = /incbin/(\"$kernel_image\");" >> $target_its_file
		kernel=0
		continue
	fi
	if echo $line | grep -w "^kernel" |grep -v ";"; then
		kernel=1
		echo "$line" >> $target_its_file
		continue
	fi

	############################# generate ramdisk path
	if [ -f $ramdisk_file_path ]; then
		if [ $ramdisk -eq 1 ];then
			echo "data = /incbin/(\"$ramdisk_file_path\");" >> $target_its_file
			ramdisk=0
			continue
		fi
		if echo $line | grep -w "^ramdisk" |grep -v ";"; then
			ramdisk=1
			echo "$line" >> $target_its_file
			continue
		fi
	fi

	############################# generate resource path
	if [ $resource -eq 1 ];then
		echo "data = /incbin/(\"$TOP_DIR/../OBJ/kernel/resource.img\");" >> $target_its_file
		resource=0
		continue
	fi
	if echo $line | grep -w "^resource" |grep -v ";"; then
		resource=1
		echo "$line" >> $target_its_file
		continue
	fi

	if [ "$RK_RAMDISK_SECURITY_BOOTUP" = "true" ];then
		if echo $line | grep -wq "uboot-ignore"; then
			echo "Enable Security boot, Skip uboot-ignore ..."
			continue
		fi
	fi

	echo "$line" >> $target_its_file
done < $src_its_file


#$TOP_DIR/rkbin/tools/mkimage -f $target_its_file  -E -p 0x800 $OUTPUT_TARGET_IMAGE
$TOP_DIR/device/rockchip/mkimage -f $target_its_file  -E -p 0x800 $OUTPUT_TARGET_IMAGE
rm -f $target_its_file
