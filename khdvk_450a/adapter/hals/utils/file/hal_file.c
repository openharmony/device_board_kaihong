/*
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <securec.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <utils_file.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <hal_file.h>
#include "los_fs.h"
#include "errno.h"
#include "lfs.h"
#include "los_task.h"
#include "fmc_operation.h"
#include "exmc_sdram.h"
#include "utils_file.h"

#define GD32F450ZIT6_FLASH_BANK1_SECTOR17_ADDR 0x08200000
#ifndef GD32F450ZIT6_FLASH_SECTOR_SIZE
#define GD32F450ZIT6_FLASH_SECTOR_SIZE (4 * 1024)
#endif

#define SLOT_AVAILABLE (-1)
#define HAL_ERROR (-1)

#define RD_WR_FIELD_MASK 0x000f
#define CREAT_EXCL_FIELD_MASK 0x00f0
#define TRUNC_FILED_MASK 0x0f00

#define ADDITIONAL_LEN 2
#define MAX_PATH_LEN 40
#define MAX_OPEN_FILE_NUM 32
#define FLASH_ROOT_PATH "/data"
#define DIR_SEPARATOR "/"
#define RAM_ROOT_PATH "/ram"              

#define FLASH_READ_SIZE 1 // 128   /* 最小读取字节数，所有的读取操作字节数必须是它的倍数（影响内存消耗） */
#define FLASH_PROG_SIZE 1 // 128   /* 最小写入字节数，所有的写入操作字节数必须是它的倍数（影响内存消耗） */
#define FLASH_BLOCK_SIZE \
    GD32F450ZIT6_FLASH_SECTOR_SIZE /* 擦除块字节数，不会影响内存消耗，每个文件至少占用一个块，必须是READ_SIZE/PROG_SIZE的倍数 \
                                    */
#define FLASH_CACHE_SIZE \
    128 /* 块缓存的大小，缓存越大磁盘访问越小，性能越高，必须是READ_SIZE/PROG_SIZE的倍数，且是BLOCK_SIZE的因数 */
#define FLASH_LOOKAHEAD_SIZE 16 /* 块分配预测深度，分配块时每次步进多少个块，必须为8的整数倍，对于内存消耗影响不大 */
#define FLASH_BLOCK_CYCLES \
    500 /* 逐出元数据日志并将元数据移动到另一个块之前的擦除周期数，值越大性能越好，但磨损越不均匀，-1将禁用块级磨损均衡 \
         */
#define FLASH_BLOCK_COUNT (1024 * 1024 / FLASH_BLOCK_SIZE)

#define DEVICE_SDRAM_NAME EXMC_SDRAM_DEVICE0        
#define SDRAM_OFFSET_ADDRESS  0x01000000    
#define SDRAM_BLOCK_ADDRESS   0xC0000000  
#define SDRAM_READ_SIZE 1 //128   /* 最小读取字节数，所有的读取操作字节数必须是它的倍数（影响内存消耗） */
#define SDRAM_PROG_SIZE 1 //128   /* 最小写入字节数，所有的写入操作字节数必须是它的倍数（影响内存消耗） */
#define SDRAM_BLOCK_COUNT 2048      
#define SDRAM_BLOCK_SIZE  256     /* 擦除块字节数，不会影响内存消耗，每个文件至少占用一个块，必须是READ_SIZE/PROG_SIZE的倍数 */
#define SDRAM_CACHE_SIZE  128     /* 块缓存的大小，缓存越大磁盘访问越小，性能越高，必须是READ_SIZE/PROG_SIZE的倍数，且是BLOCK_SIZE的因数 */
#define SDRAM_LOOKAHEAD_SIZE 64   /* 块分配预测深度，分配块时每次步进多少个块，必须为8的整数倍，对于内存消耗影响不大 */
#define SDRAM_BLOCK_CYCLES 500    /* 逐出元数据日志并将元数据移动到另一个块之前的擦除周期数，值越大性能越好，但磨损越不均匀，-1将禁用块级磨损均衡 */

#define MAX_PATH_LEN         40

int littlefs_block_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size);
int littlefs_block_write(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer,
                         lfs_size_t size);
int littlefs_block_erase(const struct lfs_config *c, lfs_block_t block);
int littlefs_block_sync(const struct lfs_config *c);

struct fs_cfg {
    char *mount_point;
    struct lfs_config lfs_cfg;
};
static struct fs_cfg fs[LOSCFG_LFS_MAX_MOUNT_SIZE] = {0};

static struct PartitionCfg part_cfg[LOSCFG_LFS_MAX_MOUNT_SIZE] ={ 
    {
        .readFunc = NULL,
        .writeFunc = NULL,
        .eraseFunc = NULL,
        .readSize = FLASH_READ_SIZE,   // 读闪存 以字节为单位读取的块的最小大小。所有读操作都是该值的倍数。
        .writeSize = FLASH_PROG_SIZE,  // 写闪存 以字节为单位的块程序的最小大小。所有程序操作都是该值的倍数。
        .blockSize = GD32F450ZIT6_FLASH_SECTOR_SIZE, // 块大小 可擦块的大小(以字节为单位),必须是读取大小和程序大小的倍数。
        .blockCount = FLASH_BLOCK_COUNT,       // 块个数 设备上可擦的块数。
        .cacheSize = FLASH_CACHE_SIZE,         // 系统缓存必须是读写缓存的倍数 块大小的因数
        .lookaheadSize = FLASH_LOOKAHEAD_SIZE, // 类似目录缓存  必须是8的倍数
        .blockCycles = FLASH_BLOCK_CYCLES,     // 每500次磨损来一次均衡
        .partNo = 1,          // 用来判断底层操作函数的标志num
    }, 
    {
        .readFunc = NULL,
        .writeFunc = NULL,
        .eraseFunc = NULL,
        .readSize = SDRAM_READ_SIZE,  // 读闪存 以字节为单位读取的块的最小大小。所有读操作都是该值的倍数。
        .writeSize = SDRAM_PROG_SIZE, // 写闪存 以字节为单位的块程序的最小大小。所有程序操作都是该值的倍数。
        .blockSize = SDRAM_BLOCK_SIZE,  // 块大小 可擦块的大小(以字节为单位),必须是读取大小和程序大小的倍数。
        .blockCount = SDRAM_BLOCK_COUNT,       // 块个数 设备上可擦的块数。
        .cacheSize = SDRAM_CACHE_SIZE,         // 系统缓存必须是读写缓存的倍数 块大小的因数
        .lookaheadSize = SDRAM_LOOKAHEAD_SIZE, // 类似目录缓存  必须是8的倍数
        .blockCycles = SDRAM_BLOCK_CYCLES,     // 每500次磨损来一次均衡
        .partNo = 2,        // 用来判断底层操作函数的标志num
    }
};

int lfs_init(void)
{
    DIR *dir = NULL;
    fs[0].mount_point = FLASH_ROOT_PATH;  
    fs[1].mount_point = RAM_ROOT_PATH;
    for (int i = 0; i < sizeof(fs) / sizeof(fs[0]); i++) {
        if (fs[i].mount_point == NULL) {
            continue;
        }

        int ret = mount(NULL, fs[i].mount_point, "littlefs", 0, &part_cfg[i]);
        printf("%s: mount fs on '%s' %s\n", __func__, fs[i].mount_point, (ret == 0) ? "succeed" : "failed");
        if ((dir = opendir(fs[i].mount_point)) == NULL) {
            printf("first time create file %s\n", fs[i].mount_point);
            ret = mkdir(fs[i].mount_point, S_IRUSR | S_IWUSR);
            if (ret != LOS_OK) {
                printf("Mkdir failed %d[%d]\n", ret, errno);
                return ret;
            } else {
                printf("mkdir success %d\n", ret);
            }
        } else {
            printf("open dir success!\n");
            closedir(dir);
        }
    }
    return LFS_ERR_OK;
}

int littlefs_block_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size)
{
    uint32_t intlock;
    intlock = LOS_IntLock();
    uint32_t addr;
    int partNum = (int) c->context;
    switch (partNum) {
        case 1:
            addr =
                ((uint32_t)((uint32_t)block * GD32F450ZIT6_FLASH_SECTOR_SIZE) + GD32F450ZIT6_FLASH_BANK1_SECTOR17_ADDR + off);
            fmc_read_8bit_data(addr, size, buffer);
            break;
        case 2:
            addr =
                ((uint32_t)((uint32_t)block * SDRAM_BLOCK_SIZE) + SDRAM_OFFSET_ADDRESS + off + SDRAM_BLOCK_ADDRESS);
            int ret = memcpy_s(buffer, size, (void*)addr, size);
            if (ret != 0) {
                printf("The read sdram address 0x%x is failed ret = %d",addr,ret);
                LOS_IntRestore(intlock);
                return LOS_NOK;
            }
            break;
        default:
            printf("partNum(%d) is out of range \n", partNum);
            LOS_IntRestore(intlock);
            return LOS_NOK;
    }
    LOS_IntRestore(intlock);
    return LFS_ERR_OK;
}

int littlefs_block_write(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer,
                         lfs_size_t size)
{
    uint32_t intlock;
    intlock = LOS_IntLock();
    uint32_t addr;
    int partNum = (int) c->context;
    switch (partNum) {
        case 1:
            addr =
                ((uint32_t)((uint32_t)block * GD32F450ZIT6_FLASH_SECTOR_SIZE) + GD32F450ZIT6_FLASH_BANK1_SECTOR17_ADDR + off);
            fmc_write_8bit_data(addr, size, buffer);
            break;
        case 2:
            addr =
                ((uint32_t)((uint32_t)block * SDRAM_BLOCK_SIZE) + SDRAM_OFFSET_ADDRESS + off + SDRAM_BLOCK_ADDRESS);
            int ret = memcpy_s((void*)addr, size, buffer, size);
            if (ret != 0) {
                printf("The write sdram address 0x%x is failed ret = %d",addr,ret);
                LOS_IntRestore(intlock);
                return LOS_NOK;
            }
            break;
        default:
            printf("partNum(%d) is out of range \n", partNum);
            LOS_IntRestore(intlock);
            return LOS_NOK;
    }
    LOS_IntRestore(intlock);
    return LFS_ERR_OK;
}

int littlefs_block_erase(const struct lfs_config *c, lfs_block_t block)
{
    uint32_t intlock;
    intlock = LOS_IntLock();
    uint32_t addr;
    int partNum = (int) c->context;
    switch (partNum) {
        case 1:
            addr = 
                (uint32_t)(GD32F450ZIT6_FLASH_BANK1_SECTOR17_ADDR + (block * GD32F450ZIT6_FLASH_SECTOR_SIZE));
            fmc_erase_sector_by_address(addr);
            break;
        case 2:
            addr = 
                ((uint32_t)((uint32_t)block * SDRAM_BLOCK_SIZE) + SDRAM_OFFSET_ADDRESS + SDRAM_BLOCK_ADDRESS);
            int ret = memset_s((void *)addr,SDRAM_BLOCK_SIZE , 0xff, SDRAM_BLOCK_SIZE);
            if (ret != 0) {
                printf("The earse sdram address 0x%x is failed ret = %d",addr,ret);
                LOS_IntRestore(intlock);
                return LOS_NOK;
            }
            break;
        default:
            printf("partNum(%d) is out of range \n", partNum);
            LOS_IntRestore(intlock);
            return LOS_NOK;
    }
    LOS_IntRestore(intlock);
    return LFS_ERR_OK;
}

int littlefs_block_sync(const struct lfs_config *c)
{
    return LFS_ERR_OK;
}

static int g_FileHandlerArray[MAX_OPEN_FILE_NUM] = {
    SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE,
    SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE,
    SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE,
    SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE,
    SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE, SLOT_AVAILABLE
};

static int GetAvailableFileHandlerIndex(void)
{
    int i = MAX_OPEN_FILE_NUM;

    for (; i > 0; i--) {
        if (g_FileHandlerArray[i - 1] == SLOT_AVAILABLE) {
            break;
        }
    }

    return i;
}
static int ConvertFlags(int oflag)
{
    int ret = 0;
    int buffer = 0;

    buffer = (oflag & RD_WR_FIELD_MASK);
    if (buffer == O_RDONLY_FS) {
        ret = O_RDONLY;
    } else if (buffer == O_WRONLY_FS) {
        ret = O_WRONLY;
    } else if (buffer == O_RDWR_FS) {
        ret = O_RDWR;
    }

    buffer = (oflag & CREAT_EXCL_FIELD_MASK);
    if ((buffer & O_CREAT_FS) != 0) {
        ret |= O_CREAT;
    }

    if ((buffer & O_EXCL_FS) != 0) {
        ret |= O_EXCL;
    }

    buffer = (oflag & TRUNC_FILED_MASK);
    if ((buffer & O_TRUNC_FS) != 0) {
        ret |= O_TRUNC;
    }

    if ((buffer & O_APPEND_FS) != 0) {
        ret |= O_APPEND;
    }

    return ret;
}

static char *GetActualFilePath(const char *path)
{
    int len;
    char *file_path = NULL;

    len = strnlen(path, MAX_PATH_LEN);
    if (len >= MAX_PATH_LEN) {
        printf("path is too long!\r\n");
        return NULL;
    }

    len += (strlen(RAM_ROOT_PATH) + ADDITIONAL_LEN);
    file_path = (char *)malloc(len);
    if (file_path == NULL) {
        printf("malloc failed!\r\n");
        return NULL;
    }

    strcpy_s(file_path, len, RAM_ROOT_PATH);
    strcat_s(file_path, len, DIR_SEPARATOR);
    strcat_s(file_path, len, path);

    return file_path;
}

int HalFileOpen(const char *path, int oflag, int mode)
{
    int index;
    int fd;
    char *file_path;

    index = GetAvailableFileHandlerIndex();
    if (index == 0) {
        printf("error: can not find index available!\n");
        return HAL_ERROR;
    }

    file_path = GetActualFilePath(path);
    if (file_path == NULL) {
        return HAL_ERROR;
    }

    fd = open(file_path, ConvertFlags(oflag));
    if (fd < 0) {
        printf("error:failed to open file : errno = %d\n", errno);
        free(file_path);
        return HAL_ERROR;
    }

    g_FileHandlerArray[index - 1] = fd;
    free(file_path);

    return index;
}

int HalFileClose(int fd)
{
    int ret;

    /* make sure fd is within the allowed range, which is 1 to MAX_OPEN_FILE_NUM */
    if ((fd > MAX_OPEN_FILE_NUM) || (fd <= 0)) {
        printf("error: close: fd(%d) is out of range!\n", fd);
        return HAL_ERROR;
    }

    ret = close(g_FileHandlerArray[fd - 1]);
    if (ret != 0) {
        printf("error: failed to close ret = %d!\n", ret);
        return HAL_ERROR;
    }
    LOS_MDelay(0x0A);       

    g_FileHandlerArray[fd - 1] = SLOT_AVAILABLE;

    return ret;
}

int HalFileRead(int fd, char *buf, unsigned int len)
{
    /* make sure fd is within the allowed range, which is 1 to MAX_OPEN_FILE_NUM */
    if ((fd > MAX_OPEN_FILE_NUM) || (fd <= 0)) {
        printf("error: read: fd(%d) is out of range!\n", fd);
        return HAL_ERROR;
    }

    return read(g_FileHandlerArray[fd - 1], buf, len);
}

int HalFileWrite(int fd, const char *buf, unsigned int len)
{
    /* make sure fd is within the allowed range, which is 1 to MAX_OPEN_FILE_NUM */
    if ((fd > MAX_OPEN_FILE_NUM) || (fd <= 0)) {
        printf("error: write: fd(%d) is out of range!\n", fd);
        return HAL_ERROR;
    }

    return write(g_FileHandlerArray[fd - 1], buf, len);
}

int HalFileDelete(const char *path)
{
    char *file_path;
    int ret;

    file_path = GetActualFilePath(path);
    if (file_path == NULL) {
        printf("error: delete: file_path == NULL\n");
        return HAL_ERROR;
    }

    ret = unlink(file_path);
    free(file_path);
    LOS_MDelay(0x0A);        
    return ret;
}

int HalFileStat(const char *path, unsigned int *fileSize)
{
    char *file_path;
    struct stat f_info;
    int ret;

    file_path = GetActualFilePath(path);
    if (file_path == NULL) {
        printf("error: stat: file_path == NULL\n");
        return HAL_ERROR;
    }

    ret = stat(file_path, &f_info);
    *fileSize = f_info.st_size;
    free(file_path);

    return ret;
}

int HalFileSeek(int fd, int offset, unsigned int whence)
{
    int ret = 0;
    struct stat f_info;

    /* make sure fd is within the allowed range, which is 1 to MAX_OPEN_FILE_NUM */
    if ((fd > MAX_OPEN_FILE_NUM) || (fd <= 0)) {
        printf("error: seek: fd(%d) is out of range!\n", fd);
        return HAL_ERROR;
    }

    ret = fstat(g_FileHandlerArray[fd - 1], &f_info);
    if (ret != 0) {
        printf("error: fail to fstat!\n");
        return HAL_ERROR;
    }

    if (whence == SEEK_SET_FS) {
        if (offset > f_info.st_size) {
            printf("error: seek offset is more than st_size %d vs %d!\n", offset, f_info.st_size);
            ret = HAL_ERROR;
        }
    }

    ret = lseek(g_FileHandlerArray[fd - 1], offset, whence);
    if ((ret > f_info.st_size) || (ret < 0)) {
        printf("error: lseek ret:f_info.st_size %d vs %d\n", ret, f_info.st_size);
        return HAL_ERROR;
    }

    return ret;
}