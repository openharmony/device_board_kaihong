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

#include "iot_errno.h"
#include "iot_i2c.h"
#include "los_sem.h"
#include "gd32f4xx.h"
#include "gd32f4xx_i2c.h"

#define MAX_I2C_ID_NUM (2) // 最大I2C ID数
#define I2C_OWN_ADDRESS7 (0x72)
#define I2C0_BUS_ID 0
#define I2C1_BUS_ID 1
#define I2C2_BUS_ID 2
#define MESSAGE_LAST_SECOND 2
#define MESSAGE_LAST_THIRD 3
static uint32_t get_i2c_chn(unsigned int id)
{
    switch (id) {
        case I2C0_BUS_ID:
            return I2C0;
        case I2C1_BUS_ID:
            return I2C1;
        case I2C2_BUS_ID:
            return I2C2;
        default:
            break;
    }
}

static uint32_t get_i2c_rcu_chn(unsigned int id)
{
    switch (id) {
        case I2C0_BUS_ID:
            return RCU_I2C0;
        case I2C1_BUS_ID:
            return RCU_I2C1;
        case I2C2_BUS_ID:
            return RCU_I2C2;
        default:
            break;
    }
}

unsigned int IoTI2cWrite(unsigned int id, unsigned short deviceAddr, const unsigned char *data, unsigned int dataLen)
{
    if (id > MAX_I2C_ID_NUM) {
        return IOT_FAILURE;
    }
    uint32_t chn = get_i2c_chn(id);
    while (i2c_flag_get(chn, I2C_FLAG_I2CBSY)) { }; // 等待总线空闲
    i2c_start_on_bus(chn);                          // 发送start信号
    while (!i2c_flag_get(chn, I2C_FLAG_SBSEND)) { };
    i2c_master_addressing(chn, deviceAddr, I2C_TRANSMITTER); // 设置从机地址操作
    while (!i2c_flag_get(chn, I2C_FLAG_ADDSEND)) { };        // 等待从机地址发送标志
    i2c_flag_clear(chn, I2C_FLAG_ADDSEND);                   // 清除从机地址发送标志
    while (!i2c_flag_get(chn, I2C_FLAG_TBE)) { };
    for (uint8_t i = 0; i < dataLen; i++) {
        i2c_data_transmit(chn, data[i]);
        while (!i2c_flag_get(chn, I2C_FLAG_BTC)) { }; // 等待数据寄存器空
    }
    i2c_stop_on_bus(chn); // 发送stop信号
    while (I2C_CTL0(chn) & I2C_CTL0_STOP) { };
    return IOT_SUCCESS;
}

unsigned int IoTI2cRead(unsigned int id, unsigned short deviceAddr, unsigned char *dataIn, unsigned int len)
{
    unsigned char *data = dataIn;
    unsigned int dataLen = len;
    if (id > MAX_I2C_ID_NUM) {
        return IOT_FAILURE;
    }
    uint32_t chn = get_i2c_chn(id);
    while (i2c_flag_get(chn, I2C_FLAG_I2CBSY)) { }; // 等待总线空闲
    if (dataLen == MESSAGE_LAST_SECOND) {
        i2c_ackpos_config(chn, I2C_ACKPOS_NEXT);
    }                                                     // 接收数据长度等于2时,首先将POAP置1
    i2c_start_on_bus(chn);                                // 发送start信号
    while (!i2c_flag_get(chn, I2C_FLAG_SBSEND)) { };      // 等待SBSEND标志
    i2c_master_addressing(chn, deviceAddr, I2C_RECEIVER); // 设置从机地址操作
    if (dataLen < MESSAGE_LAST_THIRD) {
        i2c_ack_config(chn, I2C_ACK_DISABLE);
    }                                                 // 接收数据长度小于3时,需先清除ACK
    while (!i2c_flag_get(chn, I2C_FLAG_ADDSEND)) { }; // 等待从机地址发送标志
    i2c_flag_clear(chn, I2C_FLAG_ADDSEND);            // 清除从机地址发送标志
    while (dataLen) {
        if (dataLen == MESSAGE_LAST_THIRD) {
            while (!i2c_flag_get(chn, I2C_FLAG_BTC)) { }; // 等待倒数第二个数据被接收到寄存器
            i2c_ack_config(chn, I2C_ACK_DISABLE);         // 清除ACK
        }
        if (dataLen == MESSAGE_LAST_SECOND) {
            while (!i2c_flag_get(chn, I2C_FLAG_BTC)) { };
            i2c_stop_on_bus(chn); // 发送stop信号
        }
        if (i2c_flag_get(chn, I2C_FLAG_RBNE)) { // 等待RBNE位被设置
            *data = i2c_data_receive(chn);      // 从I2C总线读取数据
            data++;
            dataLen--;
        }
    }
    while (I2C_CTL0(chn) & I2C_CTL0_STOP) { };
    i2c_ack_config(chn, I2C_ACK_ENABLE);
    return IOT_SUCCESS;
}

unsigned int IoTI2cInit(unsigned int id, unsigned int baudrate)
{
    if (id > MAX_I2C_ID_NUM) {
        return IOT_FAILURE;
    }
    uint32_t chn = get_i2c_chn(id);
    rcu_periph_clock_enable(get_i2c_rcu_chn(id));
    i2c_clock_config(chn, baudrate, I2C_DTCY_2);
    i2c_mode_addr_config(chn, I2C_I2CMODE_ENABLE, I2C_ADDFORMAT_7BITS, I2C_OWN_ADDRESS7);
    i2c_enable(chn);
    i2c_ack_config(chn, I2C_ACK_ENABLE);
    return IOT_SUCCESS;
}

unsigned int IoTI2cDeinit(unsigned int id)
{
    if (id > MAX_I2C_ID_NUM) {
        return IOT_FAILURE;
    }
    uint32_t chn = get_i2c_chn(id);
    i2c_deinit(chn);
    i2c_disable(chn);
    return IOT_SUCCESS;
}

unsigned int IoTI2cSetBaudrate(unsigned int id, unsigned int baudrate)
{
    if (id > MAX_I2C_ID_NUM) {
        return IOT_FAILURE;
    }
    i2c_clock_config(get_i2c_chn(id), baudrate, I2C_DTCY_2);
    return IOT_SUCCESS;
}
