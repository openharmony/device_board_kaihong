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

export LC_ALL=C
export LD_LIBRARY_PATH=
unset RK_CFG_TOOLCHAIN

err_handler() {
	ret=$?
	[ "$ret" -eq 0 ] && return

	echo "ERROR: Running ${FUNCNAME[1]} failed!"
	echo "ERROR: exit code $ret from line ${BASH_LINENO[0]}:"
	echo "    $BASH_COMMAND"
	exit $ret
}
trap 'err_handler' ERR
set -eE

function finish_build(){
	echo "Running ${FUNCNAME[1]} succeeded."
	cd $TOP_DIR
}

function check_config(){
	unset missing
	for var in $@; do
		eval [ \$$var ] && continue

		missing="$missing $var"
	done

	[ -z "$missing" ] && return 0

	echo "Skipping ${FUNCNAME[1]} for missing configs: $missing."
	return 1
}

function choose_target_board()
{
	echo
	echo "You're building on Linux"
	echo "Launch menu...pick a combo:"
	echo ""

	echo "0. default BoardConfig.mk"
	echo ${RK_TARGET_BOARD_ARRAY[@]} | xargs -n 1 | sed "=" | sed "N;s/\n/. /"

	local INDEX
	read -p "Which would you like? [0]: " INDEX
	INDEX=$((${INDEX:-0} - 1))

	if echo $INDEX | grep -vq [^0-9]; then
		RK_BUILD_TARGET_BOARD="${RK_TARGET_BOARD_ARRAY[$INDEX]}"
	else
		echo "Launching for Default BoardConfig.mk boards..."
		RK_BUILD_TARGET_BOARD=BoardConfig.mk
	fi
}

function build_select_board()
{
	RK_TARGET_BOARD_ARRAY=( $(cd ${TARGET_PRODUCT_DIR}/; ls *.mk | sort) )

	RK_TARGET_BOARD_ARRAY_LEN=${#RK_TARGET_BOARD_ARRAY[@]}
	if [ $RK_TARGET_BOARD_ARRAY_LEN -eq 0 ]; then
		echo "No available Board Config"
		return
	fi

	choose_target_board

	ln -rfs $TARGET_PRODUCT_DIR/$RK_BUILD_TARGET_BOARD device/rockchip/.BoardConfig.mk

	unset RK_PACKAGE_FILE
	source $TARGET_PRODUCT_DIR/$RK_BUILD_TARGET_BOARD
	if [[ x"$RK_PACKAGE_FILE" != x ]];then
		PACK_TOOL_DIR=$TOP_DIR/tools/linux/Linux_Pack_Firmware/rockdev/
		cd $PACK_TOOL_DIR
		rm -f package-file
		ln -sf $RK_PACKAGE_FILE package-file
	fi

	if [[ x"$RK_PARAMETER" != x ]];then
		PARAMETER=$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_PARAMETER
		ln -sf $PARAMETER $ROCKDEV/parameter.txt
	else
		echo -e "\e[31m error: $SD_PARAMETER not found! \e[0m"
	fi

    MKUPDATE_FILE=${RK_TARGET_PRODUCT}-mkupdate.sh
    if [[ x"$MKUPDATE_FILE" != x-mkupdate.sh ]];then
		PACK_TOOL_DIR=$TOP_DIR/tools/linux/Linux_Pack_Firmware/rockdev/
		cd $PACK_TOOL_DIR
		rm -f mkupdate.sh
		ln -sf $MKUPDATE_FILE mkupdate.sh
	fi

	echo "switching to board: `realpath $BOARD_CONFIG`"
}

function unset_board_config_all()
{
	local tmp_file=`mktemp`
	grep -o "^export.*RK_.*=" `find $TOP_DIR/device/rockchip -name "Board*.mk" -type f` -h | sort | uniq > $tmp_file
	source $tmp_file
	rm -f $tmp_file
}

CMD=`realpath $0`
COMMON_DIR=`dirname $CMD`
TOP_DIR=$(realpath $COMMON_DIR/../../..)
export ROOT_DIR=$(realpath $TOP_DIR/../../..)
MAKE="make CROSS_COMPILE=${ROOT_DIR}/prebuilts/gcc/linux-x86/aarch64/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-"
# $CMD        : /home/openharmony/out/KERNEL_OBJ/rk356x-4.19/src_tmp/chip_rk356x/borad_firefly_rk3566/device/rockchip/common/build.sh
# $COMMON_DIR : /home/openharmony/out/KERNEL_OBJ/rk356x-4.19/src_tmp/chip_rk356x/borad_firefly_rk3566/device/rockchip/common
# $TOP_DIR    : /home/openharmony/out/KERNEL_OBJ/rk356x-4.19/src_tmp/chip_rk356x/borad_firefly_rk3566
# $ROOT_DIR   : /home/openharmony 

echo "CMD        : $CMD"
echo "COMMON_DIR : $COMMON_DIR"
echo "TOP_DIR    : $TOP_DIR"
echo "ROOT_DIR   : $ROOT_DIR"

IMGNAME=

BOARD_CONFIG=$TOP_DIR/device/rockchip/.BoardConfig.mk
TARGET_PRODUCT="$TOP_DIR/device/rockchip/.target_product"
TARGET_PRODUCT_DIR=$(realpath ${TARGET_PRODUCT})

unset_board_config_all
[ -L "$BOARD_CONFIG" ] && source $BOARD_CONFIG
source $TOP_DIR/device/rockchip/common/Version.mk
CFG_DIR=$TOP_DIR/device/rockchip
#ROCKDEV=$ROOT_DIR/out/ohos-arm-release/packages/phone/images
ROCKDEV=${IMAGES_OUT_PATH}
PARAMETER=$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_PARAMETER
SD_PARAMETER=$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_SD_PARAMETER

NPROC=`nproc`
export RK_JOBS=$NPROC

if [ ! -d "$ROCKDEV/pack" ];then
	mkdir -p $ROCKDEV/pack
fi

function prebuild_uboot()
{
	UBOOT_COMPILE_COMMANDS="\
			${RK_TRUST_INI_CONFIG:+../rkbin/RKTRUST/$RK_TRUST_INI_CONFIG} \
			${RK_SPL_INI_CONFIG:+../rkbin/RKBOOT/$RK_SPL_INI_CONFIG} \
			${RK_UBOOT_SIZE_CONFIG:+--sz-uboot $RK_UBOOT_SIZE_CONFIG} \
			${RK_TRUST_SIZE_CONFIG:+--sz-trust $RK_TRUST_SIZE_CONFIG}"
	UBOOT_COMPILE_COMMANDS="$(echo $UBOOT_COMPILE_COMMANDS)"

	if [ "$RK_LOADER_UPDATE_SPL" = "true" ]; then
		UBOOT_COMPILE_COMMANDS="--spl-new $UBOOT_COMPILE_COMMANDS"
		UBOOT_COMPILE_COMMANDS="$(echo $UBOOT_COMPILE_COMMANDS)"
	fi

	if [ "$RK_RAMDISK_SECURITY_BOOTUP" = "true" ];then
		UBOOT_COMPILE_COMMANDS=" \
			--boot_img $(cd $TOP_DIR && realpath ./rockdev/boot.img) \
			--burn-key-hash $UBOOT_COMPILE_COMMANDS \
			${RK_ROLLBACK_INDEX_BOOT:+--rollback-index-boot $RK_ROLLBACK_INDEX_BOOT} \
			${RK_ROLLBACK_INDEX_UBOOT:+--rollback-index-uboot $RK_ROLLBACK_INDEX_UBOOT} "
		UBOOT_COMPILE_COMMANDS="$(echo $UBOOT_COMPILE_COMMANDS)"
	fi
}

function usagekernel()
{
	check_config RK_KERNEL_DTS RK_KERNEL_DEFCONFIG || return 0

	echo "cd kernel"
	echo "${MAKE} ARCH=$RK_ARCH $RK_KERNEL_DEFCONFIG $RK_KERNEL_DEFCONFIG_FRAGMENT"
	echo "${MAKE} ARCH=$RK_ARCH $RK_KERNEL_DTS.img -j$RK_JOBS"
}

function usageuboot()
{
	check_config RK_UBOOT_DEFCONFIG || return 0
	prebuild_uboot

	cd $TOP_DIR/uboot/
	echo "cd uboot"
	if [ -n "$RK_UBOOT_DEFCONFIG_FRAGMENT" ]; then
		if [ -f "configs/${RK_UBOOT_DEFCONFIG}_defconfig" ]; then
			echo "${MAKE} ${RK_UBOOT_DEFCONFIG}_defconfig $RK_UBOOT_DEFCONFIG_FRAGMENT"
		else
			echo "${MAKE} ${RK_UBOOT_DEFCONFIG}.config $RK_UBOOT_DEFCONFIG_FRAGMENT"
		fi
		echo "./make.sh $UBOOT_COMPILE_COMMANDS"
	else
		echo "./make.sh $RK_UBOOT_DEFCONFIG $UBOOT_COMPILE_COMMANDS"
	fi

	if [ "$RK_IDBLOCK_UPDATE_SPL" = "true" ]; then
		echo "./make.sh --idblock --spl"
	fi

	finish_build
}

function usagerootfs()
{
	check_config RK_ROOTFS_IMG || return 0

	if [ "${RK_CFG_BUILDROOT}x" != "x" ];then
		echo "source envsetup.sh $RK_CFG_BUILDROOT"
	else
		if [ "${RK_CFG_RAMBOOT}x" != "x" ];then
			echo "source envsetup.sh $RK_CFG_RAMBOOT"
		else
			echo "Not found config buildroot. Please Check !!!"
		fi
	fi

	case "${RK_ROOTFS_SYSTEM:-buildroot}" in
		yocto)
			;;
		debian)
			;;
		distro)
			;;
		*)
			echo "make"
			;;
	esac
}

function usagerecovery()
{
	check_config RK_CFG_RECOVERY || return 0

	echo "source envsetup.sh $RK_CFG_RECOVERY"
	echo "$COMMON_DIR/mk-ramdisk.sh recovery.img $RK_CFG_RECOVERY"
}

function usageramboot()
{
	check_config RK_CFG_RAMBOOT || return 0

	echo "source envsetup.sh $RK_CFG_RAMBOOT"
	echo "$COMMON_DIR/mk-ramdisk.sh ramboot.img $RK_CFG_RAMBOOT"
}

function usagemodules()
{
	check_config RK_KERNEL_DEFCONFIG || return 0

	echo "cd kernel"
	echo "${MAKE} ARCH=$RK_ARCH $RK_KERNEL_DEFCONFIG"
	echo "${MAKE} ARCH=$RK_ARCH modules -j$RK_JOBS"
}

function usage()
{
	echo "Usage: build.sh [OPTIONS]"
	echo "Available options:"
	echo "*.mk               -switch to specified board config"
	echo "launch              -list current SDK boards and switch to specified board config"
	echo "uboot              -build uboot"
	echo "spl                -build spl"
	echo "loader             -build loader"
	echo "kernel             -build kernel"
	echo "modules            -build kernel modules"
	echo "toolchain          -build toolchain"
	echo "extboot            -build extlinux boot.img, boot from EFI partition"
	echo "rootfs             -build default rootfs, currently build buildroot as default"
	echo "buildroot          -build buildroot rootfs"
	echo "ramboot            -build ramboot image"
	echo "multi-npu_boot     -build boot image for multi-npu board"
	echo "yocto              -build yocto rootfs"
	echo "debian             -build debian9 stretch rootfs"
	echo "distro             -build debian10 buster rootfs"
    echo "openwrt            -build openwrt rootfs"
	echo "pcba               -build pcba"
	echo "recovery           -build recovery"
	echo "all                -build uboot, kernel, rootfs, recovery image"
	echo "cleanall           -clean uboot, kernel, rootfs, recovery"
	echo "firmware           -pack all the image we need to boot up system"
	echo "updateimg          -pack update image"
	echo "rawimg             -pack raw image"
	echo "otapackage         -pack ab update otapackage image (update_ota.img)"
	echo "sdpackage          -pack update sdcard package image (update_sdcard.img)"
	echo "save               -save images, patches, commands used to debug"
	echo "allsave            -build all & firmware & updateimg & save"
	echo "check              -check the environment of building"
	echo "info               -see the current board building information"
	echo "app/<pkg>          -build packages in the dir of app/*"
	echo "external/<pkg>     -build packages in the dir of external/*"
	echo ""
	echo "Default option is 'allff'."
}

function build_info(){
	if [ ! -L $TARGET_PRODUCT_DIR ];then
		echo "No found target product!!!"
	fi
	if [ ! -L $BOARD_CONFIG ];then
		echo "No found target board config!!!"
	fi

	if [ -f .repo/manifest.xml ]; then
		local sdk_ver=""
		sdk_ver=`grep "include name"  .repo/manifest.xml | awk -F\" '{print $2}'`
		sdk_ver=`realpath .repo/manifests/${sdk_ver}`
		echo "Build SDK version: `basename ${sdk_ver}`"
	else
		echo "Not found .repo/manifest.xml [ignore] !!!"
	fi

	echo "Current Building Information:"
	echo "Target Product: $TARGET_PRODUCT_DIR"
	echo "Target BoardConfig: `realpath $BOARD_CONFIG`"
	echo "Target Misc config:"
	echo "`env |grep "^RK_" | grep -v "=$" | sort`"

	local kernel_file_dtb

	if [ "$RK_ARCH" == "arm" ]; then
		kernel_file_dtb="${TOP_DIR}/kernel/arch/arm/boot/dts/${RK_KERNEL_DTS}.dtb"
	else
		kernel_file_dtb="${TOP_DIR}/kernel/arch/arm64/boot/dts/rockchip/${RK_KERNEL_DTS}.dtb"
	fi

	rm -f $kernel_file_dtb

	cd kernel
	${MAKE} ARCH=$RK_ARCH dtbs -j$RK_JOBS
}

function build_check_power_domain(){
	local dump_kernel_dtb_file
	local tmp_phandle_file
	local tmp_io_domain_file
	local tmp_regulator_microvolt_file
	local tmp_final_target
	local tmp_none_item
	local kernel_file_dtb_dts

	if [ "$RK_ARCH" == "arm" ]; then
		kernel_file_dtb_dts="${TOP_DIR}/kernel/arch/arm/boot/dts/$RK_KERNEL_DTS"
	else
		kernel_file_dtb_dts="${TOP_DIR}/kernel/arch/arm64/boot/dts/rockchip/$RK_KERNEL_DTS"
	fi

	dump_kernel_dtb_file=${kernel_file_dtb_dts}.dump.dts
	tmp_phandle_file=`mktemp`
	tmp_io_domain_file=`mktemp`
	tmp_regulator_microvolt_file=`mktemp`
	tmp_final_target=`mktemp`
	tmp_grep_file=`mktemp`

	dtc -I dtb -O dts -o ${dump_kernel_dtb_file} ${kernel_file_dtb_dts}.dtb 2>/dev/null
	if ! grep -Pzo "io-domains\s*{(\n|\w|-|;|=|<|>|\"|_|\s|,)*};" $dump_kernel_dtb_file 1>$tmp_grep_file 2>/dev/null; then
		echo "Not Found io-domains in ${kernel_file_dtb_dts}.dts"
		rm -f $tmp_grep_file
		return 0
	fi
	grep -a supply $tmp_grep_file > $tmp_io_domain_file
	rm -f $tmp_grep_file
	awk '{print "phandle = " $3}' $tmp_io_domain_file > $tmp_phandle_file


	while IFS= read -r item_phandle && IFS= read -u 3 -r item_domain
	do
		echo "${item_domain% *}" >> $tmp_regulator_microvolt_file
		tmp_none_item=${item_domain% *}
		cmds="grep -Pzo \"{(\\n|\w|-|;|=|<|>|\\\"|_|\s)*"$item_phandle\"

		eval "$cmds $dump_kernel_dtb_file | strings | grep "regulator-m..-microvolt" >> $tmp_regulator_microvolt_file" || \
			eval "sed -i \"/${tmp_none_item}/d\" $tmp_regulator_microvolt_file" && continue

		echo >> $tmp_regulator_microvolt_file
	done < $tmp_phandle_file 3<$tmp_io_domain_file

	while read -r regulator_val
	do
		if echo ${regulator_val} | grep supply &>/dev/null; then
			echo -e "\n\n\e[1;33m${regulator_val%*=}\e[0m" >> $tmp_final_target
		else
			tmp_none_item=${regulator_val##*<}
			tmp_none_item=${tmp_none_item%%>*}
			echo -e "${regulator_val%%<*} \e[1;31m$(( $tmp_none_item / 1000 ))mV\e[0m" >> $tmp_final_target
		fi
	done < $tmp_regulator_microvolt_file

	echo -e "\e[41;1;30m PLEASE CHECK BOARD GPIO POWER DOMAIN CONFIGURATION !!!!!\e[0m"
	echo -e "\e[41;1;30m <<< ESPECIALLY Wi-Fi/Flash/Ethernet IO power domain >>> !!!!!\e[0m"
	echo -e "\e[41;1;30m Check Node [pmu_io_domains] in the file: ${kernel_file_dtb_dts}.dts \e[0m"
	echo
	echo -e "\e[41;1;30m 请再次确认板级的电源域配置！！！！！！\e[0m"
	echo -e "\e[41;1;30m <<< 特别是Wi-Fi，FLASH，以太网这几路IO电源的配置 >>> ！！！！！\e[0m"
	echo -e "\e[41;1;30m 检查内核文件 ${kernel_file_dtb_dts}.dts 的节点 [pmu_io_domains] \e[0m"
	cat $tmp_final_target

	rm -f $tmp_phandle_file
	rm -f $tmp_regulator_microvolt_file
	rm -f $tmp_io_domain_file
	rm -f $tmp_final_target
	rm -f $dump_kernel_dtb_file
}

function build_check(){
	local build_depend_cfg="build-depend-tools.txt"
	common_product_build_tools="$TOP_DIR/device/rockchip/common/$build_depend_cfg"
	target_product_build_tools="$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$build_depend_cfg"
	cat $common_product_build_tools $target_product_build_tools 2>/dev/null | while read chk_item
		do
			chk_item=${chk_item###*}
			echo $chk_item
			if [ -z "$chk_item" ]; then
				continue
			fi

			dst=${chk_item%%,*}
			src=${chk_item##*,}
			echo "**************************************"
			if eval $dst &>/dev/null;then
				echo "Check [OK]: $dst"
			else
				echo "Please install ${dst%% *} first"
				echo "    sudo apt-get install $src"
			fi
		done
}

function build_pkg() {
	check_config RK_CFG_BUILDROOT || check_config RK_CFG_RAMBOOT || check_config RK_CFG_RECOVERY || check_config RK_CFG_PCBA || return 0

	local target_pkg=$1
	target_pkg=${target_pkg%*/}

	if [ ! -d $target_pkg ];then
		echo "build pkg: error: not found package $target_pkg"
		return 1
	fi

	if ! eval [ $rk_package_mk_arrry ];then
		rk_package_mk_arrry=( $(find buildroot/package/rockchip/ -name "*.mk" | sort) )
	fi

	local pkg_mk pkg_config_in pkg_br pkg_final_target pkg_final_target_upper pkg_cfg

	for it in ${rk_package_mk_arrry[@]}
	do
		pkg_final_target=$(basename $it)
		pkg_final_target=${pkg_final_target%%.mk*}
		pkg_final_target_upper=${pkg_final_target^^}
		pkg_final_target_upper=${pkg_final_target_upper//-/_}
		if grep "${pkg_final_target_upper}_SITE.*$target_pkg" $it &>/dev/null; then
			pkg_mk=$it
			pkg_config_in=$(dirname $pkg_mk)/Config.in
			pkg_br=BR2_PACKAGE_$pkg_final_target_upper

			for cfg in RK_CFG_BUILDROOT RK_CFG_RAMBOOT RK_CFG_RECOVERY RK_CFG_PCBA
			do
				if eval [ \$$cfg ] ;then
					pkg_cfg=$( eval "echo \$$cfg" )
					if grep -wq ${pkg_br}=y buildroot/output/$pkg_cfg/.config; then
						echo "Found $pkg_br in buildroot/output/$pkg_cfg/.config "
						${MAKE} -C buildroot/output/$pkg_cfg ${pkg_final_target}-dirclean O=buildroot/output/$pkg_cfg
						${MAKE} -C buildroot/output/$pkg_cfg ${pkg_final_target}-rebuild O=buildroot/output/$pkg_cfg
					else
						echo "[SKIP BUILD $target_pkg] NOT Found ${pkg_br}=y in buildroot/output/$pkg_cfg/.config"
					fi
				fi
			done
		fi
	done

	finish_build
}

function build_uboot(){
	check_config RK_UBOOT_DEFCONFIG || return 0
	prebuild_uboot

	echo "============Start building uboot============"
	echo "TOP_DIR=$TOP_DIR"
	echo "TARGET_UBOOT_CONFIG=$RK_UBOOT_DEFCONFIG"
	echo "RK_UBOOT_DEFCONFIG_FRAGMENT=$RK_UBOOT_DEFCONFIG_FRAGMENT"
	echo "========================================="

	cd $TOP_DIR/uboot/
	rm -f *_loader_*.bin
	if [ "$RK_LOADER_UPDATE_SPL" = "true" ]; then
		rm -f *spl.bin
	fi
	if [ "$RK_RAMDISK_SECURITY_BOOTUP" = "true" ];then
		rm -f $TOP_DIR/uboot/boot.img
	fi

	if [ -n "$RK_UBOOT_DEFCONFIG_FRAGMENT" ]; then
		if [ -f "configs/${RK_UBOOT_DEFCONFIG}_defconfig" ]; then
			${MAKE} ${RK_UBOOT_DEFCONFIG}_defconfig $RK_UBOOT_DEFCONFIG_FRAGMENT
		else
			${MAKE} ${RK_UBOOT_DEFCONFIG}.config $RK_UBOOT_DEFCONFIG_FRAGMENT
		fi
		./make.sh $UBOOT_COMPILE_COMMANDS
	else
		./make.sh $RK_UBOOT_DEFCONFIG \
			$UBOOT_COMPILE_COMMANDS
	fi
	
	if [ "$RK_IDBLOCK_UPDATE" = "true" ]; then
		./make.sh --idblock
	fi

	if [ "$RK_LOADER_UPDATE_TPL" = "true" ]; then
		./make.sh --tpl
	fi
	
	if [ "$RK_IDBLOCK_UPDATE_SPL" = "true" ]; then
		./make.sh --idblock --spl
	fi

	#if [ "$RK_RAMDISK_SECURITY_BOOTUP" = "true" ];then
	#	ln -rsf $TOP_DIR/u-boot/boot.img $TOP_DIR/rockdev/
	#fi

	finish_build
}

# TODO: build_spl can be replaced by build_uboot with define RK_LOADER_UPDATE_SPL
function build_spl(){
	check_config RK_SPL_DEFCONFIG || return 0

	echo "============Start building spl============"
	echo "TARGET_SPL_CONFIG=$RK_SPL_DEFCONFIG"
	echo "========================================="
	if [ -f uboot/*spl.bin ]; then
		rm uboot/*spl.bin
	fi
	cd $TOP_DIR/uboot/ && ./make.sh $RK_SPL_DEFCONFIG && ./make.sh spl-s && cd -
	if [ $? -eq 0 ]; then
		echo "====Build spl ok!===="
	else
		echo "====Build spl failed!===="
		exit 1
	fi

	finish_build
}

function build_loader(){
	check_config RK_LOADER_BUILD_TARGET || return 0

	echo "============Start building loader============"
	echo "RK_LOADER_BUILD_TARGET=$RK_LOADER_BUILD_TARGET"
	echo "=========================================="
	cd loader && ./build.sh $RK_LOADER_BUILD_TARGET && cd -
	if [ $? -eq 0 ]; then
		echo "====Build loader ok!===="
	else
		echo "====Build loader failed!===="
		exit 1
	fi

	finish_build
}

function build_kernel(){
	check_config RK_KERNEL_DTS RK_KERNEL_DEFCONFIG || return 0

	echo "============Start building kernel============"
	echo "TARGET_ARCH          =$RK_ARCH"
	echo "TARGET_KERNEL_CONFIG =$RK_KERNEL_DEFCONFIG"
	echo "TARGET_KERNEL_DTS    =$RK_KERNEL_DTS"
	echo "TARGET_KERNEL_CONFIG_FRAGMENT =$RK_KERNEL_DEFCONFIG_FRAGMENT"
	echo "RK_KERNEL_FIT_ITS =$RK_KERNEL_FIT_ITS"
	echo "RK_TARGET_PRODUCT =$RK_TARGET_PRODUCT"
	echo "ENABLE_RAMDISK =$ENABLE_RAMDISK"
	echo "=========================================="
	pwd
	cd kernel
	${MAKE} ARCH=$RK_ARCH $RK_KERNEL_DEFCONFIG $RK_KERNEL_DEFCONFIG_FRAGMENT
	${MAKE} ARCH=$RK_ARCH $RK_KERNEL_DTS.img -j$RK_JOBS
	if [ "$ENABLE_RAMDISK" != "true" ];then
		if [ -f "$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_KERNEL_FIT_ITS" ]; then
			$COMMON_DIR/mk-fitimage.sh $TOP_DIR/kernel/$RK_BOOT_IMG \
				$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_KERNEL_FIT_ITS \
				$TOP_DIR/kernel/ramdisk.img
		fi
	fi

	finish_build
}

function build_kerneldeb(){
	check_config RK_KERNEL_DTS RK_KERNEL_DEFCONFIG || return 0

	echo "============Start building kernel deb============"
	echo "TARGET_ARCH          =$RK_ARCH"
	echo "TARGET_KERNEL_CONFIG =$RK_KERNEL_DEFCONFIG"
	echo "TARGET_KERNEL_DTS    =$RK_KERNEL_DTS"
	echo "TARGET_KERNEL_CONFIG_FRAGMENT =$RK_KERNEL_DEFCONFIG_FRAGMENT"
	echo "=========================================="
	pwd
	cd kernel
	${MAKE} ARCH=$RK_ARCH $RK_KERNEL_DEFCONFIG $RK_KERNEL_DEFCONFIG_FRAGMENT
	${MAKE} ARCH=$RK_ARCH bindeb-pkg RK_KERNEL_DTS=$RK_KERNEL_DTS -j$RK_JOBS
	finish_build
}


function build_extboot(){
	check_config RK_KERNEL_DTS RK_KERNEL_DEFCONFIG || return 0

	echo "============Start building kernel============"
	echo "TARGET_ARCH          =$RK_ARCH"
	echo "TARGET_KERNEL_CONFIG =$RK_KERNEL_DEFCONFIG"
	echo "TARGET_KERNEL_DTS    =$RK_KERNEL_DTS"
	echo "TARGET_KERNEL_CONFIG_FRAGMENT =$RK_KERNEL_DEFCONFIG_FRAGMENT"
	echo "=========================================="
	pwd
	cd kernel
	${MAKE} ARCH=$RK_ARCH $RK_KERNEL_DEFCONFIG $RK_KERNEL_DEFCONFIG_FRAGMENT
	${MAKE} ARCH=$RK_ARCH $RK_KERNEL_DTS.img -j$RK_JOBS
	if [ "$ENABLE_RAMDISK" != "true" ];then
		if [ -f "$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_KERNEL_FIT_ITS" ]; then
			$COMMON_DIR/mk-fitimage.sh $TOP_DIR/kernel/$RK_BOOT_IMG \
				$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_KERNEL_FIT_ITS \
				$TOP_DIR/kernel/ramdisk.img
		fi
	fi

	echo -e "\e[36m Generate extLinuxBoot image start\e[0m"

	EXTBOOT_IMG=${TOP_DIR}/kernel/extboot.img
	EXTBOOT_DIR=${TOP_DIR}/kernel/extboot
	rm -rf ${EXTBOOT_DIR} && mkdir -p ${EXTBOOT_DIR}/extlinux

    KERNEL_VERSION=$(cat $TOP_DIR/kernel/include/config/kernel.release)
	echo "label $RK_KERNEL_DTS linux-$KERNEL_VERSION" > $EXTBOOT_DIR/extlinux/extlinux.conf

    cp ${TOP_DIR}/$RK_KERNEL_IMG $EXTBOOT_DIR/Image-$KERNEL_VERSION
	echo -e "\tkernel /Image-$KERNEL_VERSION" >> $EXTBOOT_DIR/extlinux/extlinux.conf

    cp ${TOP_DIR}/kernel/arch/${RK_ARCH}/boot/dts/rockchip/${RK_KERNEL_DTS}.dtb $EXTBOOT_DIR
	echo -e "\tfdt /${RK_KERNEL_DTS}.dtb" >> $EXTBOOT_DIR/extlinux/extlinux.conf

    if [[ -e ${TOP_DIR}/kernel/ramdisk.img ]]; then
        cp ${TOP_DIR}/kernel/ramdisk.img $EXTBOOT_DIR/initrd-$KERNEL_VERSION
        echo -e "\tinitrd /initrd-$KERNEL_VERSION" >> $EXTBOOT_DIR/extlinux/extlinux.conf
    fi

    cp ${TOP_DIR}/kernel/.config $EXTBOOT_DIR/config-$KERNEL_VERSION
    cp ${TOP_DIR}/kernel/System.map $EXTBOOT_DIR/System.map-$KERNEL_VERSION

    rm -rf $EXTBOOT_IMG && truncate -s 100M $EXTBOOT_IMG
    fakeroot mkfs.ext4 -Fq -L "boot" -d $EXTBOOT_DIR $EXTBOOT_IMG

	finish_build
}

function build_modules(){
	check_config RK_KERNEL_DEFCONFIG || return 0

	echo "============Start building kernel modules============"
	echo "TARGET_ARCH          =$RK_ARCH"
	echo "TARGET_KERNEL_CONFIG =$RK_KERNEL_DEFCONFIG"
	echo "TARGET_KERNEL_CONFIG_FRAGMENT =$RK_KERNEL_DEFCONFIG_FRAGMENT"
	echo "=================================================="
	cd $TOP_DIR/kernel && ${MAKE} ARCH=$RK_ARCH $RK_KERNEL_DEFCONFIG $RK_KERNEL_DEFCONFIG_FRAGMENT && ${MAKE} ARCH=$RK_ARCH modules -j$RK_JOBS && cd -
	if [ $? -eq 0 ]; then
		echo "====Build kernel ok!===="
	else
		echo "====Build kernel failed!===="
		exit 1
	fi
}

function build_toolchain(){
	check_config RK_CFG_TOOLCHAIN || return 0

	echo "==========Start building toolchain =========="
	echo "TARGET_TOOLCHAIN_CONFIG=$RK_CFG_TOOLCHAIN"
	echo "========================================="
	[[ $RK_CFG_TOOLCHAIN ]] \
		&& /usr/bin/time -f "you take %E to build toolchain" $COMMON_DIR/mk-toolchain.sh $BOARD_CONFIG \
		|| echo "No toolchain step, skip!"
	if [ $? -eq 0 ]; then
		echo "====Build toolchain ok!===="
	else
		echo "====Build toolchain failed!===="
		exit 1
	fi

	finish_build
}

function build_buildroot(){
	check_config RK_CFG_BUILDROOT || return 0

	echo "==========Start building buildroot=========="
	echo "TARGET_BUILDROOT_CONFIG=$RK_CFG_BUILDROOT"
	echo "========================================="
	if [ -z ${RK_CFG_BUILDROOT} ];then
		echo "====No Found config on `realpath $BOARD_CONFIG`. Just exit ..."
		return
	fi
	/usr/bin/time -f "you take %E to build builroot" $COMMON_DIR/mk-buildroot.sh $BOARD_CONFIG
	if [ $? -eq 0 ]; then
		echo "====Build buildroot ok!===="
	else
		echo "====Build buildroot failed!===="
		exit 1
	fi
}

function build_ramboot(){
	check_config RK_CFG_RAMBOOT || return 0

	echo "=========Start building ramboot========="
	echo "TARGET_RAMBOOT_CONFIG=$RK_CFG_RAMBOOT"
	echo "====================================="
	if [ -z ${RK_CFG_RAMBOOT} ];then
		echo "====No Found config on `realpath $BOARD_CONFIG`. Just exit ..."
		return
	fi
	/usr/bin/time -f "you take %E to build ramboot" $COMMON_DIR/mk-ramdisk.sh ramboot.img $RK_CFG_RAMBOOT
	if [ $? -eq 0 ]; then
		rm $TOP_DIR/rockdev/boot.img
		ln -rfs $TOP_DIR/buildroot/output/$RK_CFG_RAMBOOT/images/ramboot.img $TOP_DIR/rockdev/boot.img
		echo "====Build ramboot ok!===="
	else
		echo "====Build ramboot failed!===="
		exit 1
	fi


	finish_build
}

function build_multi-npu_boot(){
	check_config RK_MULTINPU_BOOT || return 0

	echo "=========Start building multi-npu boot========="
	echo "TARGET_RAMBOOT_CONFIG=$RK_CFG_RAMBOOT"
	echo "====================================="
	/usr/bin/time -f "you take %E to build multi-npu boot" $COMMON_DIR/mk-multi-npu_boot.sh
	if [ $? -eq 0 ]; then
		echo "====Build multi-npu boot ok!===="
	else
		echo "====Build multi-npu boot failed!===="
		exit 1
	fi
}

function build_yocto(){
	check_config RK_YOCTO_MACHINE || return 0

	echo "=========Start build ramboot========="
	echo "TARGET_MACHINE=$RK_YOCTO_MACHINE"
	echo "====================================="

	export LANG=en_US.UTF-8 LANGUAGE=en_US.en LC_ALL=en_US.UTF-8

	cd yocto
	ln -sf $RK_YOCTO_MACHINE.conf build/conf/local.conf
	source oe-init-build-env
	cd ..
	bitbake core-image-minimal -r conf/include/rksdk.conf

	if [ $? -eq 0 ]; then
		echo "====Build yocto ok!===="
	else
		echo "====Build yocto failed!===="
		exit 1
	fi
}

function build_debian(){
	ARCH=${RK_DEBIAN_ARCH:-${RK_ARCH}}
	case $ARCH in
		arm|armhf) ARCH=armhf ;;
		*) ARCH=arm64 ;;
	esac

	echo "=========Start building debian for $ARCH========="

	cd debian
	if [ ! -e linaro-buster-$ARCH.tar.gz ]; then
		RELEASE=buster TARGET=desktop ARCH=$ARCH ./mk-base-debian.sh
		ln -rsf linaro-buster-alip-*.tar.gz linaro-buster-$ARCH.tar.gz
	fi

	VERSION=debug ARCH=$ARCH ./mk-rootfs-stretch.sh

	./mk-image.sh
	cd ..
	if [ $? -eq 0 ]; then
		echo "====Build Debian9 ok!===="
	else
		echo "====Build Debian9 failed!===="
		exit 1
	fi
}

function build_distro(){
	check_config RK_DISTRO_DEFCONFIG || return 0

	echo "===========Start building distro==========="
	echo "TARGET_ARCH=$RK_ARCH"
	echo "RK_DISTRO_DEFCONFIG=$RK_DISTRO_DEFCONFIG"
	echo "========================================"
	cd distro && ${MAKE} $RK_DISTRO_DEFCONFIG && /usr/bin/time -f "you take %E to build debian" $TOP_DIR/distro/make.sh && cd -
	if [ $? -eq 0 ]; then
		echo "====Build debian ok!===="
	else
		echo "====Build debian failed!===="
		exit 1
	fi
}

function build_openwrt(){
    check_config RK_OPENWRT_DEFCONFIG || return 0
    check_config RK_OPENWRT_VERSION_SELECT || return 0

	echo "===========Start building $RK_OPENWRT_VERSION_SELECT==========="
	echo "RK_OPENWRT_DEFCONFIG=$RK_OPENWRT_DEFCONFIG"
	echo "========================================"

	/usr/bin/time -f "you take %E to build $RK_OPENWRT_VERSION_SELECT" $COMMON_DIR/mk-openwrt.sh $RK_OPENWRT_VERSION_SELECT $RK_OPENWRT_DEFCONFIG 
	if [ $? -eq 0 ]; then
		echo "====Build $RK_OPENWRT_VERSION_SELECT ok!===="
	else
		echo "====Build $RK_OPENWRT_VERSION_SELECT failed!===="
		exit 1
	fi
}

function build_rootfs(){
	check_config RK_ROOTFS_IMG || return 0

	RK_ROOTFS_DIR=.rootfs
	ROOTFS_IMG=${RK_ROOTFS_IMG##*/}

	if [ "$RK_ROOTFS_SYSTEM" != "ubuntu" ]; then
		rm -rf $RK_ROOTFS_IMG $RK_ROOTFS_DIR
		mkdir -p ${RK_ROOTFS_IMG%/*} $RK_ROOTFS_DIR
	fi

	case "$1" in
		yocto)
			build_yocto
			ROOTFS_IMG=yocto/build/tmp/deploy/images/$RK_YOCTO_MACHINE/rootfs.img
			;;
		debian)
			build_debian
			ROOTFS_IMG=debian/linaro-rootfs.img
			;;
		distro)
			build_distro
			ROOTFS_IMG=distro/output/images/rootfs.$RK_ROOTFS_TYPE
			;;
		openwrt)
			build_openwrt
			ROOTFS_IMG=openwrt_sdk/$RK_OPENWRT_VERSION_SELECT/build_dir/target-aarch64_generic_musl/linux-firefly_armv8/root.ext4
			;;
		*)
			if [ -n $RK_CFG_BUILDROOT ];then
				build_buildroot
				ROOTFS_IMG=buildroot/output/$RK_CFG_BUILDROOT/images/rootfs.$RK_ROOTFS_TYPE
			fi
			;;
	esac

	[ -z "$ROOTFS_IMG" ] && return

	if [ ! -f "$ROOTFS_IMG" ]; then
		echo "$ROOTFS_IMG not generated?"
	else
		mkdir -p ${RK_ROOTFS_IMG%/*}
		rm -f $RK_ROOTFS_IMG
		ln -rsf $TOP_DIR/$ROOTFS_IMG $RK_ROOTFS_IMG
	fi


	finish_build
}

function build_recovery(){

	if [ "$RK_UPDATE_SDCARD_ENABLE_FOR_AB" = "true" ] ;then
		RK_CFG_RECOVERY=$RK_UPDATE_SDCARD_CFG_RECOVERY
	fi

	echo "==========Start building recovery=========="
	echo "TARGET_RECOVERY_CONFIG=$RK_CFG_RECOVERY"
	echo "========================================"
	/usr/bin/time -f "you take %E to build recovery" $COMMON_DIR/mk-ramdisk.sh recovery.img $RK_CFG_RECOVERY
	if [ $? -eq 0 ]; then
		echo "====Build recovery ok!===="
	else
		echo "====Build recovery failed!===="
		exit 1
	fi


	finish_build
}

function build_pcba(){
	check_config RK_CFG_PCBA || return 0

	echo "==========Start building pcba=========="
	echo "TARGET_PCBA_CONFIG=$RK_CFG_PCBA"
	echo "===================================="
	if [ -z ${RK_CFG_PCBA} ];then
		echo "====No Found config on `realpath $BOARD_CONFIG`. Just exit ..."
		return
	fi
	/usr/bin/time -f "you take %E to build pcba" $COMMON_DIR/mk-ramdisk.sh pcba.img $RK_CFG_PCBA
	if [ $? -eq 0 ]; then
		echo "====Build pcba ok!===="
	else
		echo "====Build pcba failed!===="
		exit 1
	fi
}

function build_all(){
	echo "============================================"
	echo "TARGET_ARCH=$RK_ARCH"
	echo "TARGET_PLATFORM=$RK_TARGET_PRODUCT"
	echo "TARGET_UBOOT_CONFIG=$RK_UBOOT_DEFCONFIG"
	echo "TARGET_SPL_CONFIG=$RK_SPL_DEFCONFIG"
	echo "TARGET_KERNEL_CONFIG=$RK_KERNEL_DEFCONFIG"
	echo "TARGET_KERNEL_DTS=$RK_KERNEL_DTS"
	echo "TARGET_TOOLCHAIN_CONFIG=$RK_CFG_TOOLCHAIN"
	echo "TARGET_BUILDROOT_CONFIG=$RK_CFG_BUILDROOT"
	echo "TARGET_RECOVERY_CONFIG=$RK_CFG_RECOVERY"
	echo "TARGET_PCBA_CONFIG=$RK_CFG_PCBA"
	echo "TARGET_RAMBOOT_CONFIG=$RK_CFG_RAMBOOT"
	echo "============================================"

	# NOTE: On secure boot-up world, if the images build with fit(flattened image tree)
	#       we will build kernel and ramboot firstly,
	#       and then copy images into u-boot to sign the images.
	if [ "$RK_RAMDISK_SECURITY_BOOTUP" != "true" ];then
		#note: if build spl, it will delete loader.bin in uboot directory,
		# so can not build uboot and spl at the same time.
		if [ -z $RK_SPL_DEFCONFIG ]; then
			build_uboot
		else
			build_spl
		fi
	fi

	build_loader
	build_kernel
	build_toolchain && \
	build_rootfs ${RK_ROOTFS_SYSTEM:-buildroot}
	build_recovery
	build_ramboot

	if [ "$RK_RAMDISK_SECURITY_BOOTUP" = "true" ];then
		#note: if build spl, it will delete loader.bin in uboot directory,
		# so can not build uboot and spl at the same time.
		if [ -z $RK_SPL_DEFCONFIG ]; then
			build_uboot
		else
			build_spl
		fi
	fi

	finish_build
}

function build_cleanall(){
	echo "clean uboot, kernel, rootfs, recovery"
	cd $TOP_DIR/uboot/ && ${MAKE} distclean && cd -
	cd $TOP_DIR/kernel && ${MAKE} distclean && cd -
	rm -rf $TOP_DIR/buildroot/output
	rm -rf $TOP_DIR/yocto/build/tmp
	rm -rf $TOP_DIR/distro/output
	rm -rf $TOP_DIR/debian/binary
}

function build_firmware(){
	./mkfirmware.sh $BOARD_CONFIG
	if [ $? -eq 0 ]; then
		echo "Make image ok!"
	else
		echo "Make image failed!"
		exit 1
	fi
}


function gen_file_name() {
	day=$(date +%Y%m%d)
	time=$(date +%H%M)

	typeset -u board
	board=$(basename $(readlink ${BOARD_CONFIG}))
	board=${board%%.MK}
	rootfs=$(ls -l $ROCKDEV/ | grep system.img | awk -F '/' '{print $(NF)}'|awk -F '_' '{print $2}')
	board=${board}${rootfs}-GPT

	if [ -n "$1" ];then
		board=$board-$1
	fi

	echo -e "File name is \e[36m $board \e[0m"
	read -t 10 -e -p "Rename the file? [N|y]" ANS || :
	ANS=${ANS:-n}
	
	case $ANS in
			Y|y|yes|YES|Yes) rename=1;;
			N|n|no|NO|No) rename=0;;
			*) rename=0;;
	esac
	if [[ ${rename} == "1" ]]; then
		read -e -p "Enter new file name: " IMGNAME
		IMGNAME=$IMGNAME
	fi
	IMGNAME=${IMGNAME:-$board}
	IMGNAME=${IMGNAME}-${day}-${time}.img
}


function build_rawimg(){
	packm="unpack"
	[[ -n "$1" ]] && [[ $1 != "-p" ]] && usage 
	[[ -n "$1" ]] && packm="pack"

	gen_file_name RAW

	if [ $packm == "pack" ];then
		cd rockdev && ./version.sh $IMGNAME init && cd -
	fi

	if [ -n "$RK_RECOVERY_RAMDISK_RAW" ]; then
		local mk_path=$(realpath $BOARD_CONFIG)
		sed -i '$a\'"export RK_RECOVERY_RAMDISK=$RK_RECOVERY_RAMDISK_RAW" $mk_path
		sed -i '$a\'"export RK_CFG_RECOVERY=" $mk_path
		if [ -n "$TOP_DIR/rockdev/recovery.img" ]; then
			mv $TOP_DIR/rockdev/recovery.img $TOP_DIR/rockdev/recovery.img_bk
		fi
		build_recovery
		sed -i "/export RK_RECOVERY_RAMDISK=$RK_RECOVERY_RAMDISK_RAW/d" $mk_path
		sed -i "/export RK_CFG_RECOVERY=/d" $mk_path
	else
		echo "Not found RK_RECOVERY_RAMDISK_RAW!"
		exit 1
	fi

	# IMAGE_PATH=$ROOT_DIR/out/ohos-arm-release/packages/phone/images
	IMAGE_PATH=${IMAGES_OUT_PATH}
	PACK_TOOL_DIR=$TOP_DIR/tools/linux/Linux_Pack_Firmware

	cd $PACK_TOOL_DIR/rockdev

	if [ -f "$RK_PACKAGE_FILE_AB" ]; then
		build_sdcard_package
		build_otapackage

		cd $PACK_TOOL_DIR/rockdev
		echo "Make Linux a/b update_ab.img."
		source_package_file_name=`ls -lh package-file | awk -F ' ' '{print $NF}'`
		ln -fs "$RK_PACKAGE_FILE_AB" package-file
		./mkupdate.sh
		mv update.img $IMAGE_PATH/update_ab.img
		ln -fs $source_package_file_name package-file
	else
		echo "Make raw.img"

		if [ -f "$RK_PACKAGE_FILE" ]; then
			source_package_file_name=`ls -lh package-file | awk -F ' ' '{print $NF}'`
			ln -fs "$RK_PACKAGE_FILE" package-file
			./mkrawimg.sh
			ln -fs $source_package_file_name package-file
		else
			cd $PACK_TOOL_DIR/rockdev && ./mkrawimg.sh && cd -
		fi
	mv $PACK_TOOL_DIR/rockdev/raw.img $IMAGE_PATH/pack/$IMGNAME
	rm -rf $IMAGE_PATH/raw.img
	if [ -n "$TOP_DIR/rockdev/recovery.img_bk" ]; then
		mv $TOP_DIR/rockdev/recovery.img_bk $TOP_DIR/rockdev/recovery.img
	fi

	if [ $? -eq 0 ]; then
	   echo "Make raw image ok!"
	   echo -e "\e[36m $IMAGE_PATH/pack/$IMGNAME \e[0m"
	else
	   echo "Make raw image failed!"
	   exit 1
	fi

	if [ $packm == "pack" ];then
		cd $TOP_DIR/rockdev && ./version.sh $IMGNAME pack && cd -
	fi
    fi
}

function build_sdupdateimg(){

	gen_file_name sdupdate

	# IMAGE_PATH=$ROOT_DIR/out/ohos-arm-release/packages/phone/images
	IMAGE_PATH=${IMAGES_OUT_PATH}
	PACK_TOOL_DIR=$TOP_DIR/tools/linux/Linux_Pack_Firmware

	echo "Make sdupdate.img"
	if [ -f $SD_PARAMETER ]
	then
		echo -n "create parameter..."
		ln -s -f $SD_PARAMETER $ROCKDEV/parameter.txt
		echo "done."
	else
		echo -e "\e[31m error: $SD_PARAMETER not found! \e[0m"
		exit 1
	fi

	if [[ x"$RK_SD_PACKAGE_FILE" != x ]];then
		RK_PACK_TOOL_DIR=$TOP_DIR/tools/linux/Linux_Pack_Firmware/rockdev/
		cd $RK_PACK_TOOL_DIR
		rm -f package-file
		ln -sf $RK_SD_PACKAGE_FILE package-file
	fi

	cd $PACK_TOOL_DIR/rockdev && ./mkupdate.sh && cd -
	mv $PACK_TOOL_DIR/rockdev/update.img $IMAGE_PATH/pack/$IMGNAME
	rm -rf $IMAGE_PATH/update.img

	if [ $? -eq 0 ]; then
	   echo "Make sdupdate image ok!"
	   echo -e "\e[36m $IMAGE_PATH/pack/$IMGNAME \e[0m"
	else
	   echo "Make sdupdate image failed!"
	fi

	if [ -f $PARAMETER ]
	then
		ln -s -f $PARAMETER $ROCKDEV/parameter.txt
	fi

	if [[ x"$RK_PACKAGE_FILE" != x ]];then
		RK_PACK_TOOL_DIR=$TOP_DIR/tools/linux/Linux_Pack_Firmware/rockdev/
		cd $RK_PACK_TOOL_DIR
		rm -f package-file
		ln -sf $RK_PACKAGE_FILE package-file
	fi
}

function build_otapackage(){
	# IMAGE_PATH=$ROOT_DIR/out/ohos-arm-release/packages/phone/images
	IMAGE_PATH=${IMAGES_OUT_PATH}
	PACK_TOOL_DIR=$TOP_DIR/tools/linux/Linux_Pack_Firmware

	echo "Make ota ab update_ota.img"
	cd $PACK_TOOL_DIR/rockdev
	if [ -f "$RK_PACKAGE_FILE_OTA" ]; then
		source_package_file_name=`ls -lh $PACK_TOOL_DIR/rockdev/package-file | awk -F ' ' '{print $NF}'`
		ln -fs "$RK_PACKAGE_FILE_OTA" package-file
		./mkupdate.sh
		mv update.img $IMAGE_PATH/update_ota.img
		ln -fs $source_package_file_name package-file
	fi

	finish_build
}

function build_sdcard_package(){

	check_config RK_UPDATE_SDCARD_ENABLE_FOR_AB || return 0

	local image_path=$TOP_DIR/rockdev
	local pack_tool_dir=$TOP_DIR/tools/linux/Linux_Pack_Firmware
	local rk_sdupdate_ab_misc=${RK_SDUPDATE_AB_MISC:=sdupdate-ab-misc.img}
	local rk_parameter_sdupdate=${RK_PARAMETER_SDUPDATE:=parameter-sdupdate.txt}
	local rk_package_file_sdcard_update=${RK_PACKAGE_FILE_SDCARD_UPDATE:=sdcard-update-package-file}
	local sdupdate_ab_misc_img=$TOP_DIR/device/rockchip/rockimg/$rk_sdupdate_ab_misc
	local parameter_sdupdate=$TOP_DIR/device/rockchip/rockimg/$rk_parameter_sdupdate
	local recovery_img=$TOP_DIR/buildroot/output/$RK_UPDATE_SDCARD_CFG_RECOVERY/images/recovery.img

	if [ $RK_UPDATE_SDCARD_CFG_RECOVERY ]; then
		if [ -f $recovery_img ]; then
			echo -n "create recovery.img..."
			ln -rsf $recovery_img $image_path/recovery.img
		else
			echo "error: $recovery_img not found!"
			return 1
		fi
	fi


	echo "Make sdcard update update_sdcard.img"
	cd $pack_tool_dir/rockdev
	if [ -f "$rk_package_file_sdcard_update" ]; then

		if [ $rk_parameter_sdupdate ]; then
			if [ -f $parameter_sdupdate ]; then
				echo -n "create sdcard update image parameter..."
				ln -rsf $parameter_sdupdate $image_path/
			fi
		fi

		if [ $rk_sdupdate_ab_misc ]; then
			if [ -f $sdupdate_ab_misc_img ]; then
				echo -n "create sdupdate ab misc.img..."
				ln -rsf $sdupdate_ab_misc_img $image_path/
			fi
		fi

		source_package_file_name=`ls -lh $pack_tool_dir/rockdev/package-file | awk -F ' ' '{print $NF}'`
		ln -fs "$rk_package_file_sdcard_update" package-file
		./mkupdate.sh
		mv update.img $image_path/update_sdcard.img
		ln -fs $source_package_file_name package-file
		rm -f $image_path/$rk_sdupdate_ab_misc $image_path/$rk_parameter_sdupdate $image_path/recovery.img
	fi

	finish_build
}

function build_save(){
	# IMAGE_PATH=$ROOT_DIR/out/ohos-arm-release/packages/phone/images
	IMAGE_PATH=${IMAGES_OUT_PATH}
	DATE=$(date  +%Y%m%d.%H%M)
	STUB_PATH=Image/"$RK_KERNEL_DTS"_"$DATE"_RELEASE_TEST
	STUB_PATH="$(echo $STUB_PATH | tr '[:lower:]' '[:upper:]')"
	export STUB_PATH=$TOP_DIR/$STUB_PATH
	export STUB_PATCH_PATH=$STUB_PATH/PATCHES
	mkdir -p $STUB_PATH

	#Generate patches
	$TOP_DIR/.repo/repo/repo forall -c "$TOP_DIR/device/rockchip/common/gen_patches_body.sh"

	#Copy stubs
	$TOP_DIR/.repo/repo/repo manifest -r -o $STUB_PATH/manifest_${DATE}.xml
	mkdir -p $STUB_PATCH_PATH/kernel
	cp $TOP_DIR/kernel/.config $STUB_PATCH_PATH/kernel
	cp $TOP_DIR/kernel/vmlinux $STUB_PATCH_PATH/kernel
	mkdir -p $STUB_PATH/IMAGES/
	cp $IMAGE_PATH/* $STUB_PATH/IMAGES/

	#Save build command info
	echo "UBOOT:  defconfig: $RK_UBOOT_DEFCONFIG" >> $STUB_PATH/build_cmd_info
	echo "KERNEL: defconfig: $RK_KERNEL_DEFCONFIG, dts: $RK_KERNEL_DTS" >> $STUB_PATH/build_cmd_info
	echo "BUILDROOT: $RK_CFG_BUILDROOT" >> $STUB_PATH/build_cmd_info

}

function build_updateimg(){
	packm="unpack"
	[[ -n "$1" ]] && [[ $1 != "-p" ]] && usage 
	[[ -n "$1" ]] && packm="pack"

	gen_file_name 

	if [ $packm == "pack" ];then
		echo "IMAGES_OUT_PATH-${IMAGES_OUT_PATH}"
		cd ${IMAGES_OUT_PATH} \
		&& rm -rf $IMGNAME \
		&& ./version.sh $IMGNAME init $2 && cd -
	fi
		
	#IMAGE_PATH=$ROOT_DIR/out/rk3568-khdvk/packages/phone/images
	IMAGE_PATH=${IMAGES_OUT_PATH}
	PACK_TOOL_DIR=$TOP_DIR/tools/linux/Linux_Pack_Firmware
	echo "IMAGE_PATH is $IMAGE_PATH"

	cd $PACK_TOOL_DIR/rockdev

	if [ -f "$RK_PACKAGE_FILE_AB" ]; then
		build_sdcard_package
		build_otapackage

		cd $PACK_TOOL_DIR/rockdev
		echo "Make Linux a/b update_ab.img."
		source_package_file_name=`ls -lh package-file | awk -F ' ' '{print $NF}'`
		ln -fs "$RK_PACKAGE_FILE_AB" package-file
		./mkupdate.sh
		mv update.img $IMAGE_PATH/update_ab.img
		ln -fs $source_package_file_name package-file
	else
		echo "Make update.img"

		if [ -f "$RK_PACKAGE_FILE" ]; then
			source_package_file_name=`ls -lh package-file | awk -F ' ' '{print $NF}'`
			ln -fs "$RK_PACKAGE_FILE" package-file
			./mkupdate.sh
			ln -fs $source_package_file_name package-file
		else
			./mkupdate.sh
		fi
		mv update.img $IMAGE_PATH
	fi
	
	mv $IMAGE_PATH/update.img $IMAGE_PATH/pack/$IMGNAME
	rm -rf $IMAGE_PATH/update.img
	if [ $? -eq 0 ]; then
	   echo "Make update image ok!"
	   echo -e "\e[36m $IMAGE_PATH/pack/$IMGNAME \e[0m"
	else
	   echo "Make update image failed!"
	   exit 1
	fi

    [ -z "$RK_PRODUCT_MODEL" ] && RK_PRODUCT_MODEL=${RK_KERNEL_DTS}
    [ -z "$RK_DRM_VERSION" ] && RK_DRM_VERSION=1
    [[ "${RK_TARGET_PRODUCT^^}" == RK356* ]]  && RK_DRM_VERSION=100
    command -v ffgenswv.bin > /dev/null 2>&1 && \
    ffgenswv.bin -b ${RK_TARGET_PRODUCT^^} \
                -m ${RK_PRODUCT_MODEL^^} \
                -V ${RK_DRM_VERSION} \
                -u $IMAGE_PATH/pack/$IMGNAME \
                -o $IMAGE_PATH/ffimage.swv

	finish_build
}


function build_allff(){
	build_all
	build_firmware
	build_updateimg
}

function build_allsave(){
	rm -fr $TOP_DIR/rockdev
	build_all
	build_firmware
	build_updateimg
	build_save

	finish_build
}

#=========================
# build targets
#=========================

if echo $@|grep -wqE "help|-h"; then
	if [ -n "$2" -a "$(type -t usage$2)" == function ]; then
		echo "###Current SDK Default [ $2 ] Build Command###"
		eval usage$2
	else
		usage
	fi
	exit 0
fi

OPTIONS="${@:-allff}"

[ -f "$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_BOARD_PRE_BUILD_SCRIPT" ] \
	&& source "$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_BOARD_PRE_BUILD_SCRIPT"  # board hooks

for option in ${OPTIONS}; do
	echo "processing option: $option"
	case $option in
		*.mk)
			if [ -f $option ]; then
				CONF=${option}
			else
				CONF=$(find $CFG_DIR -name $option)
				echo "switching to board: $CONF"
				if [ ! -f $CONF ]; then
					echo "not exist!"
					exit 1
				fi
			fi

		    ln -rsf $CONF $BOARD_CONFIG

			unset RK_PACKAGE_FILE
			source $CONF
			if [[ x"$RK_PACKAGE_FILE" != x ]];then
				PACK_TOOL_DIR=$TOP_DIR/tools/linux/Linux_Pack_Firmware/rockdev/
				cd $PACK_TOOL_DIR
				rm -f package-file
				ln -sf $RK_PACKAGE_FILE package-file
			fi

			if [[ x"$RK_PARAMETER" != x ]];then
				PARAMETER=$TOP_DIR/device/rockchip/$RK_TARGET_PRODUCT/$RK_PARAMETER
				cp -arpf $PARAMETER $ROCKDEV/parameter.txt
			else
				echo -e "\e[31m error: $SD_PARAMETER not found! \e[0m"
			fi
    
		    MKUPDATE_FILE=${RK_TARGET_PRODUCT}-mkupdate.sh 
		    if [[ x"$MKUPDATE_FILE" != x-mkupdate.sh ]];then
				PACK_TOOL_DIR=$TOP_DIR/tools/linux/Linux_Pack_Firmware/rockdev/
				cd $PACK_TOOL_DIR
				rm -f mkupdate.sh
				ln -sf $MKUPDATE_FILE mkupdate.sh
			fi
			;;
		launch) build_select_board ;;
		all) build_all ;;
		save) build_save ;;
		allsave) build_allsave ;;
		allff) build_allff ;;
		check) build_check ;;
		cleanall) build_cleanall ;;
		firmware) build_firmware ;;
		updateimg) build_updateimg ;;
		rawimg) build_rawimg ;;
		otapackage) build_otapackage ;;
		sdpackage) build_sdcard_package ;;
		toolchain) build_toolchain ;;
		spl) build_spl ;;
		uboot) build_uboot ;;
		loader) build_loader ;;
		kernel) build_kernel ;;
		extboot) build_extboot ;;
		kerneldeb) build_kerneldeb ;;
		modules) build_modules ;;
		rootfs|buildroot|debian|distro|yocto|openwrt) build_rootfs $option ;;
		pcba) build_pcba ;;
		ramboot) build_ramboot ;;
		recovery) build_recovery ;;
		multi-npu_boot) build_multi-npu_boot ;;
		info) build_info ;;
		app/*|external/*) build_pkg $option ;;
		*) usage ;;
	esac
done
