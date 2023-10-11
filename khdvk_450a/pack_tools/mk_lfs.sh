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

SCRIPT_PATH=$(dirname $0)
SRC_PATH="$1"
NO_APP_DATA_FLAG="$2"
OUT_DIR=${SRC_PATH}/..
echo "=========>>gd32f4xx file system make:src path=$SRC_PATH,SCRIPT_PATH=${SCRIPT_PATH},OUT_DIR=${OUT_DIR}" >&2


if [[ $NO_APP_DATA_FLAG == "no_app_data" ]]; then 
    python3 ${SCRIPT_PATH}/combination.py --bootloader_path ${SCRIPT_PATH}/gd32_uart_bootloader.bin --kernel_path ${OUT_DIR}/OHOS_Image.bin --image_path ${OUT_DIR}/gd32f4xx.bin
else 
    #cd ${SRC_PATH}/..
    # ${SCRIPT_PATH}/mklfs -c $SRC_PATH -b 4096 -r 128 -p 128 -s 1048576 -n 1 -l 32 -e 128 -k 500 -i ${OUT_DIR}/lfs.img
    ${OUT_DIR}/mklfs -c $SRC_PATH -b 4096 -r 1 -p 1 -s 1048576 -n 1 -l 16 -e 128 -k 500 -i ${OUT_DIR}/lfs.img
    #cd -
    python3 ${SCRIPT_PATH}/combination.py --bootloader_path ${SCRIPT_PATH}/gd32_uart_bootloader.bin --kernel_path ${OUT_DIR}/OHOS_Image.bin --file_path ${OUT_DIR}/lfs.img --image_path ${OUT_DIR}/gd32f4xx.bin
fi

