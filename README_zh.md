# device_board_kaihong

## 简介

深开鸿致力于实现更大范围的以软件定义硬件，引领智慧基建、智慧康养、智慧能源、智慧交通、智慧制造、智慧政务、智慧金融、智慧教育等多个行业变革，赋能、赋智、赋值千行百业的数智化转型。目前基于openharmony操作系统适配了多款开发板，本仓用于托管相关智能硬件。

### 开发板简介

**深开鸿【金星】系列智慧屏khdvk_3566b开发板**

基于OpenHarmony内嵌KaihongOS的智慧屏开发板，采用ROCKCHIP RK3566 Cortex-A55 四核处理器，提供多路通用显示屏接口，接口类型丰富，支持外设拓展，满足多种人机交互场景的需求，适用于平板电脑，学习机，人脸别相关，主要产品有匝机通道，刷脸支付，工业机器人，医疗检测设备，车牌识别，广告机、数字标牌、智能自助终端、智能零售终端等相关产品。

**深开鸿khdvk_450a开发板**

khdvk_450a开发板使用GD32F450ZKT6作为主控制器，使用Mini USB接口或者DC-005连接器提供5V电源，提供包括扩展引脚在内的SWD、Reset、Boot、User button key、LED、CAN、I2C、I2S、USART、RTC、LCD、SPI、ADC、DAC、EXMC、CTC、SDIO、ENET、USBFS、USBHS等外设资源。

开发板支持OpenHarmony 轻量系统，并支持display、以太网通讯等能力，可广泛应用于人工智能、工业控制、电机变频、图形显示、传感器网络、无人机、机器人、物联网等创新领域。

## 目录

```
device/board/kaihong
├── figures                          # 插图
├── khdvk_3566b                      # khdvk_3566b开发板
├── khdvk_450a                       # KHDVK-450A开发板
├── xxx                              # 其它开发板持续开发中
```

## 使用说明

khdvk_3566b参考：

- [khdvk_3566b](khdvk_3566b/README_zh.md)

khdvk_450a参考：

- [khdvk_450a](khdvk_450a/README_zh.md)

## 相关仓

- [vendor/kaihong](https://gitee.com/openharmony-sig/vendor_kaihong)
- [device/soc/rockchip](https://gitee.com/openharmony-sig/device_soc_rockchip)
- [device_soc_gigadevice](https://gitee.com/openharmony-sig/device_soc_gigadevice)