#!/bin/bash

CMD=`realpath $BASH_SOURCE`
CUR_DIR=`dirname $CMD`

source $CUR_DIR/BoardConfig.mk

# Uboot defconfig
export RK_UBOOT_DEFCONFIG=firefly-rk3568
# Kernel defconfig
export RK_KERNEL_DEFCONFIG=rk3566_rp_linux_defconfig
# Kernel dts
export RK_KERNEL_DTS=rk3566-rp-kh
# parameter for GPT table
export RK_PARAMETER=parameter-ubuntu-fit.txt
# packagefile for make update image
export RK_PACKAGE_FILE=rk3566-rp-package-file

# Set rootfs type, including ext2 ext4 squashfs
export RK_ROOTFS_TYPE=ext4
# rootfs image path
export RK_ROOTFS_IMG=ubuntu_rootfs/rk356x_ubuntu_rootfs.img
# recovery ramdisk
export RK_RECOVERY_RAMDISK=rk356x-recovery-arm64.cpio.gz
# Set userdata partition type
export RK_USERDATA_FS_TYPE=ext4
# kernel image format type: fit(flattened image tree)
export RK_KERNEL_FIT_ITS=bootramdisk.its

# Buildroot config
export RK_CFG_BUILDROOT=
# Recovery config
export RK_CFG_RECOVERY=
#OEM config
export RK_OEM_DIR=
#userdata config
export RK_USERDATA_DIR=
# rootfs_system
export RK_ROOTFS_SYSTEM=ubuntu
# PRODUCT MODEL
export RK_PRODUCT_MODEL=ROC_RK3566_PC

