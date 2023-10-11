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

import os
import argparse

# src: src_file_path
# dst: dst_file_path
# memory_size: malloced memory size, unit: byte
def append_file_data(src, dst, memory_size):
    src_file_size = os.stat(src).st_size

    if(memory_size < 0):
        raise Exception("memory_size < 0")

    if(memory_size < src_file_size):
        raise Exception("memory_size is too small to hold src_file_data")

    src_fd = open(src, 'rb')
    dst_fd = open(dst, 'ab')

    # append src_file_data to dst file
    buf = src_fd.read(1024)
    while buf:
        dst_fd.write(buf)
        buf = src_fd.read(1024)

    # fill free space with 0xff
    buf = bytes([0xff])
    for i in range(memory_size - src_file_size):      
        dst_fd.write(buf)

    src_fd.close()
    dst_fd.close() 

def cmd_parse():
    parser=argparse.ArgumentParser()
    parser.add_argument('--bootloader_path',help='bootloader_path', required=True)
    parser.add_argument('--kernel_path',help='kernel_path', required=True)
    parser.add_argument('--file_path',help='file_path')
    parser.add_argument('--image_path',help='image_path', required=True)
    parser.add_argument('--bootloader_zone_size', help='bootloader_zone_size,Unit: KB',type=int,default=64)
    parser.add_argument('--kernel_zone_size', help='kernel_zone_size,Unit: KB',type=int,default=1984)
    parser.add_argument('--file_zone_size', help='file_zone_size,Unit: KB',type=int,default=1024)
    #parser.print_help()
    args = parser.parse_args()
    return args

args = cmd_parse()

# ensure image_file existing and set image_file empty
image_fd = open(args.image_path, 'wb')
image_fd.close()

#add file to image
append_file_data(args.bootloader_path, args.image_path, args.bootloader_zone_size * 1024)
append_file_data(args.kernel_path,  args.image_path, args.kernel_zone_size * 1024)
if(args.file_path):
    append_file_data(args.file_path,  args.image_path, args.file_zone_size * 1024)
