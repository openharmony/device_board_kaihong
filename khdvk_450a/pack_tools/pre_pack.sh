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

#!/bin/bash
set -e

OUT_DIR="$1"
DEST_PATH="$2"
PACKTOOL_PATH=${OUT_DIR}/kh_packtool
echo "=========>>kh pre build:DEST_PATH=${DEST_PATH},PACKTOOL_PATH=${PACKTOOL_PATH}" >&2

if [ ! -f ${DEST_PATH}/gd32_uart_bootloader.bin ]; then
    echo "=========>>kh pre build:${DEST_PATH}/gd32_uart_bootloader.bin does not exist." >&2
    if [ -d ${PACKTOOL_PATH} ]; then
        rm -rf ${PACKTOOL_PATH}
    fi
    mkdir -p ${PACKTOOL_PATH}
    cd ${PACKTOOL_PATH}
    git clone https://gitee.com/download_tools/khdvk_450a.git
    cp -af khdvk_450a/bootloader/gd32_uart_bootloader.bin ${DEST_PATH}
    cd -
fi

if [ ! -f ${OUT_DIR}/mklfs ]; then
    echo "=========>>kh pre build:${OUT_DIR}/mklfs does not exist." >&2
    cd ${DEST_PATH}/../../third_party/
    # gcc -std=gnu99 -Os -Wall -Ilfs -I. -D__NO_INLINE__ -I../../../../third_party/littlefs -o mklfs mklfs.c ../../../../third_party/littlefs/lfs.c ../../../../third_party/littlefs/lfs_util.c 
    # mv ${DEST_PATH}/../../third_party/mklfs ${OUT_DIR}
    ../../../../prebuilts/build-tools/linux-x86/bin/gn gen out  && ../../../../prebuilts/build-tools/linux-x86/bin/ninja -C out && mv out/mklfs ${OUT_DIR} && rm -rf out
    cd -
fi