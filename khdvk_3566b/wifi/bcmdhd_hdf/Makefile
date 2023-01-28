# bcmdhd

BDH6_ROOT_DIR := ../../../..
#KERNEL_SRC_DIR := $(BDH6_ROOT_DIR)/out/kernel/src_tmp/linux-5.10
KERNEL_SRC_DIR := $(BDH6_ROOT_DIR)/out/KERNEL_OBJ/khdvk_3566b/kernel
#ORIG_PATH = $(KERNEL_SRC_DIR)/drivers/net/wireless/rockchip_wlan/rkwifi/bcmdhd
#CURR_PATH = $(BDH6_ROOT_DIR)/device/board/hihope/rk3568/wifi/bcmdhd_wifi6/
CURR_PATH = $(BDH6_ROOT_DIR)/device/board/kaihong/khdvk_3566b/wifi/bcmdhd_hdf
BCMDHD_PATH = $(CURR_PATH)/bcmdhd
# Execute Makefile in the kernel root directory
#include drivers/net/wireless/rockchip_wlan/rkwifi/bcmdhd_hdf/hdfwifi_bcmdhd.mk
include drivers/hdf/khdf/model/network/wifi/hdfwifi.mk

exist = $(shell if [ -d $(BCMDHD_PATH) ]; then echo "exist"; else echo "noexist"; fi)

$(info $(exist))

#ifeq ("$(exist)", "noexist")
    #$(shell mkdir -p $(BCMDHD_PATH))
#else
    #$(shell rm -rf $(BCMDHD_PATH)/*)
#endif

#$(shell cp -f $(ORIG_PATH) $(CURR_PATH))
#$(shell cp -f $(ORIG_PATH)/*.c $(CURR_PATH))
#$(shell cp -f $(ORIG_PATH)/*.h $(CURR_PATH))
#$(shell rm -fr $(CURR_PATH)/include)
#$(shell cp -fr $(ORIG_PATH)/include $(CURR_PATH)/include)

exist = $(shell if [ -d $(BCMDHD_PATH) ]; then echo "exist"; else echo "noexist"; fi)
#ifeq ("$(exist)", "exist")
    #$(shell cp -f $(ORIG_PATH)/*.c $(BCMDHD_PATH))
    #$(shell cp -f $(ORIG_PATH)/*.h $(BCMDHD_PATH))
    #$(shell rm -fr $(BCMDHD_PATH)/include)
    #$(shell cp -fr $(ORIG_PATH)/include $(BCMDHD_PATH)/include)
#endif

MODULE_NAME := bcmdhd
#CONFIG_BCMDHD := m

CONFIG_BCMDHD_SDIO := y
#CONFIG_BCMDHD_PCIE := y
#CONFIG_BCMDHD_USB := y

#CONFIG_BCMDHD_OOB := y
#CONFIG_BCMDHD_CUSB := y
#CONFIG_BCMDHD_NO_POWER_OFF := y
CONFIG_BCMDHD_PROPTXSTATUS := y
#CONFIG_DHD_USE_STATIC_BUF := y
#CONFIG_BCMDHD_STATIC_BUF_IN_DHD := y
#CONFIG_BCMDHD_VTS := y
CONFIG_BCMDHD_AUTO_SELECT := y
CONFIG_BCMDHD_DEBUG := y
#CONFIG_BCMDHD_WAPI := y
CONFIG_MACH_PLATFORM := y
#CONFIG_BCMDHD_DTS := y

HDF_BDH_WIFI_CFLAGS +=-D_PRE_OS_VERSION_LINUX=1
HDF_BDH_WIFI_CFLAGS +=-D_PRE_OS_VERSION=_PRE_OS_VERSION_LINUX
HDF_BDH_WIFI_CFLAGS +=-D_PRE_HDF_LINUX
HDF_BDH_WIFI_CFLAGS +=-DCONFIG_BCMDHD_FW_PATH=\"/vendor/etc/firmware/fw_bcmdhd.bin\"
HDF_BDH_WIFI_CFLAGS +=-DCONFIG_BCMDHD_NVRAM_PATH=\"/vendor/etc/firmware/nvram.txt\"
DHDCFLAGS = -Wall -Wstrict-prototypes -Wno-date-time -Dlinux -DBCMDRIVER  \
	-DBCMDONGLEHOST -DBCMDMA32 -DBCMFILEIMAGE                             \
	-DDHDTHREAD -DDHD_DEBUG -DSHOW_EVENTS -DBCMDBG -DGET_OTP_MAC_ENABLE   \
	-DWIFI_ACT_FRAME -DARP_OFFLOAD_SUPPORT -DSUPPORT_PM2_ONLY             \
	-DKEEP_ALIVE -DPKT_FILTER_SUPPORT -DDHDTCPACK_SUPPRESS                \
	-DDHD_DONOT_FORWARD_BCMEVENT_AS_NETWORK_PKT                           \
	-DMULTIPLE_SUPPLICANT -DTSQ_MULTIPLIER -DMFP -DDHD_8021X_DUMP         \
	-DPOWERUP_MAX_RETRY=0 -DIFACE_HANG_FORCE_DEV_CLOSE -DWAIT_DEQUEUE     \
	-DWL_EXT_IAPSTA -DWL_ESCAN -DCCODE_LIST -DSUSPEND_EVENT               \
	-DENABLE_INSMOD_NO_FW_LOAD -DBCMCRYPTO_COMPONENT

#DHDOFILES = aiutils.o siutils.o sbutils.o bcmutils.o bcmwifi_channels.o   \
	dhd_linux.o dhd_linux_platdev.o dhd_linux_sched.o dhd_pno.o           \
	dhd_common.o dhd_ip.o dhd_linux_wq.o dhd_custom_gpio.o                \
	bcmevent.o hndpmu.o linux_osl.o wldev_common.o wl_ohos.o           \
	dhd_debug_linux.o dhd_debug.o dhd_mschdbg.o dhd_dbg_ring.o            \
	hnd_pktq.o hnd_pktpool.o bcmxtlv.o linux_pkt.o bcmstdlib_s.o frag.o   \
	dhd_linux_exportfs.o dhd_linux_pktdump.o                              \
	dhd_config.o dhd_ccode.o wl_event.o wl_ohos_ext.o wl_iapsta.o wl_escan.o  \
	hdf/hdf_driver_bdh_register.o hdf/hdfinit_bdh.o \
	hdf/net_bdh_adpater.o hdf/hdf_bdh_mac80211.o hdf/hdf_mac80211_sta.o \
	hdf/hdf_mac80211_sta_event.o hdf/hdf_mac80211_ap.o hdf/hdf_mac80211_p2p.o \
	hdf/hdf_comm.o

DHDOFILES = bcmdhd/aiutils.o bcmdhd/siutils.o bcmdhd/sbutils.o bcmdhd/bcmutils.o \
	    bcmdhd/bcmwifi_channels.o bcmdhd/dhd_linux.o bcmdhd/dhd_linux_platdev.o \
	    bcmdhd/dhd_linux_sched.o bcmdhd/dhd_pno.o bcmdhd/dhd_common.o bcmdhd/dhd_ip.o \
	    bcmdhd/dhd_linux_wq.o bcmdhd/dhd_custom_gpio.o bcmdhd/bcmevent.o bcmdhd/hndpmu.o \
	    bcmdhd/linux_osl.o bcmdhd/wldev_common.o bcmdhd/wl_ohos.o bcmdhd/dhd_debug_linux.o \
	    bcmdhd/dhd_debug.o bcmdhd/dhd_mschdbg.o bcmdhd/dhd_dbg_ring.o bcmdhd/hnd_pktq.o \
	    bcmdhd/hnd_pktpool.o bcmdhd/bcmxtlv.o bcmdhd/linux_pkt.o bcmdhd/bcmstdlib_s.o bcmdhd/frag.o \
	    bcmdhd/dhd_linux_exportfs.o bcmdhd/dhd_linux_pktdump.o bcmdhd/dhd_config.o bcmdhd/dhd_ccode.o \
	    bcmdhd/wl_event.o bcmdhd/wl_ohos_ext.o bcmdhd/wl_iapsta.o bcmdhd/wl_escan.o \
	    hdf/hdf_driver_bdh_register.o hdf/hdfinit_bdh.o \
	    hdf/net_bdh_adpater.o hdf/hdf_bdh_mac80211.o hdf/hdf_mac80211_sta.o \
	    hdf/hdf_mac80211_sta_event.o hdf/hdf_mac80211_ap.o hdf/hdf_mac80211_p2p.o \
	    hdf/hdf_comm.o


ifneq ($(CONFIG_WIRELESS_EXT),)
	DHDOFILES += bcmdhd/wl_iw.o
	DHDCFLAGS += -DSOFTAP -DWL_WIRELESS_EXT -DUSE_IW
endif
ifneq ($(CONFIG_CFG80211),)
	DHDOFILES += bcmdhd/wl_cfg80211.o bcmdhd/wl_cfgscan.o bcmdhd/wl_cfgp2p.o
	DHDOFILES += bcmdhd/wl_linux_mon.o bcmdhd/wl_cfg_btcoex.o bcmdhd/wl_cfgvendor.o
	DHDOFILES += bcmdhd/dhd_cfg80211.o
	DHDCFLAGS += -DWL_CFG80211 -DWLP2P -DWL_CFG80211_STA_EVENT
	DHDCFLAGS += -DWL_IFACE_COMB_NUM_CHANNELS
	DHDCFLAGS += -DCUSTOM_PNO_EVENT_LOCK_xTIME=10
	DHDCFLAGS += -DWL_SUPPORT_AUTO_CHANNEL
	DHDCFLAGS += -DWL_SUPPORT_BACKPORTED_KPATCHES
	DHDCFLAGS += -DESCAN_RESULT_PATCH -DESCAN_BUF_OVERFLOW_MGMT
	DHDCFLAGS += -DVSDB -DWL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST
	DHDCFLAGS += -DWLTDLS -DMIRACAST_AMPDU_SIZE=8
	DHDCFLAGS += -DWL_VIRTUAL_APSTA -DSTA_MGMT
	DHDCFLAGS += -DPNO_SUPPORT -DEXPLICIT_DISCIF_CLEANUP
	DHDCFLAGS += -DDHD_USE_SCAN_WAKELOCK
	DHDCFLAGS += -DSPECIFIC_MAC_GEN_SCHEME
	DHDCFLAGS += -DWL_IFACE_MGMT
	DHDCFLAGS += -DWLFBT
	DHDCFLAGS += -DGTK_OFFLOAD_SUPPORT
#	DHDCFLAGS += -DWL_STATIC_IF
#	DHDCFLAGS += -DWL_CLIENT_SAE
endif

#BCMDHD_SDIO
ifneq ($(CONFIG_BCMDHD_SDIO),)
BUS_TYPE := "sdio"
DHDCFLAGS += -DBCMSDIO -DMMC_SDIO_ABORT -DBCMLXSDMMC       \
	-DUSE_SDIOFIFO_IOVAR -DSDTEST                                         \
	-DBDC -DDHD_USE_IDLECOUNT -DCUSTOM_SDIO_F2_BLKSIZE=256                \
	-DBCMSDIOH_TXGLOM -DBCMSDIOH_TXGLOM_EXT -DRXFRAME_THREAD              \
	-DDHDENABLE_TAILPAD -DSUPPORT_P2P_GO_PS                               \
	-DBCMSDIO_RXLIM_POST -DBCMSDIO_TXSEQ_SYNC -DCONSOLE_DPC               \
	-DBCMSDIO_INTSTATUS_WAR
ifeq ($(CONFIG_BCMDHD_OOB),y)
	DHDCFLAGS += -DOOB_INTR_ONLY -DCUSTOMER_OOB -DHW_OOB
ifeq ($(CONFIG_BCMDHD_DISABLE_WOWLAN),y)
	DHDCFLAGS += -DDISABLE_WOWLAN
endif
else
	DHDCFLAGS += -DSDIO_ISR_THREAD
endif
DHDOFILES += bcmdhd/bcmsdh.o bcmdhd/bcmsdh_linux.o bcmdhd/bcmsdh_sdmmc.o bcmdhd/bcmsdh_sdmmc_linux.o  \
	bcmdhd/dhd_sdio.o bcmdhd/dhd_cdc.o bcmdhd/dhd_wlfc.o
endif

#BCMDHD_PCIE
ifneq ($(CONFIG_BCMDHD_PCIE),)
BUS_TYPE := "pcie"
DHDCFLAGS += -DPCIE_FULL_DONGLE -DBCMPCIE -DCUSTOM_DPC_PRIO_SETTING=-1    \
	-DDONGLE_ENABLE_ISOLATION
DHDCFLAGS += -DDHD_LB -DDHD_LB_RXP -DDHD_LB_STATS -DDHD_LB_TXP
DHDCFLAGS += -DDHD_PKTID_AUDIT_ENABLED
DHDCFLAGS += -DINSMOD_FW_LOAD
ifeq ($(CONFIG_BCMDHD_OOB),y)
	DHDCFLAGS += -DCUSTOMER_OOB -DBCMPCIE_OOB_HOST_WAKE -DHW_OOB
endif
ifneq ($(CONFIG_PCI_MSI),)
	DHDCFLAGS += -DDHD_MSI_SUPPORT
endif
DHDOFILES += bcmdhd/dhd_pcie.o bcmdhd/dhd_pcie_linux.o bcmdhd/pcie_core.o bcmdhd/dhd_flowring.o       \
	bcmdhd/dhd_msgbuf.o bcmdhd/dhd_linux_lb.o
endif

#BCMDHD_USB
ifneq ($(CONFIG_BCMDHD_USB),)
BUS_TYPE := "usb"
DHDCFLAGS += -DUSBOS_TX_THREAD -DBCMDBUS -DBCMTRXV2 -DDBUS_USB_LOOPBACK   \
	-DBDC
DHDCFLAGS += -DBCM_REQUEST_FW -DEXTERNAL_FW_PATH
ifneq ($(CONFIG_BCMDHD_CUSB),)
	DHDCFLAGS += -DBCMUSBDEV_COMPOSITE
	CONFIG_BCMDHD_NO_POWER_OFF := y
endif
DHDOFILES += bcmdhd/dbus.o bcmdhd/dbus_usb.o bcmdhd/dbus_usb_linux.o bcmdhd/dhd_cdc.o bcmdhd/dhd_wlfc.o
endif

ifeq ($(CONFIG_BCMDHD_NO_POWER_OFF),y)
	DHDCFLAGS += -DENABLE_INSMOD_NO_FW_LOAD
	DHDCFLAGS += -DENABLE_INSMOD_NO_POWER_OFF -DNO_POWER_OFF_AFTER_OPEN
endif

ifeq ($(CONFIG_BCMDHD_MULTIPLE_DRIVER),y)
	DHDCFLAGS += -DBCMDHD_MDRIVER
	DHDCFLAGS += -DBUS_TYPE=\"-$(BUS_TYPE)\"
	DHDCFLAGS += -DDHD_LOG_PREFIX=\"[dhd-$(BUS_TYPE)]\"
	MODULE_NAME := dhd$(BUS_TYPE)
else
	DHDCFLAGS += -DBUS_TYPE=\"\"
endif

#PROPTXSTATUS
ifeq ($(CONFIG_BCMDHD_PROPTXSTATUS),y)
ifneq ($(CONFIG_BCMDHD_USB),)
	DHDCFLAGS += -DPROP_TXSTATUS
endif
ifneq ($(CONFIG_BCMDHD_SDIO),)
	DHDCFLAGS += -DPROP_TXSTATUS -DPROPTX_MAXCOUNT
endif
ifneq ($(CONFIG_CFG80211),)
	DHDCFLAGS += -DPROP_TXSTATUS_VSDB
endif
endif

ifeq ($(CONFIG_64BIT),y)
    DHDCFLAGS := $(filter-out -DBCMDMA32,$(DHDCFLAGS))
    DHDCFLAGS += -DBCMDMA64OSL
endif

# For Android VTS
ifeq ($(CONFIG_BCMDHD_VTS),y)
	DHDCFLAGS += -DDHD_NOTIFY_MAC_CHANGED
ifneq ($(CONFIG_CFG80211),)
	DHDCFLAGS += -DGSCAN_SUPPORT -DRTT_SUPPORT -DLINKSTAT_SUPPORT
	DHDCFLAGS += -DCUSTOM_COUNTRY_CODE -DDHD_GET_VALID_CHANNELS
	DHDCFLAGS += -DDEBUGABILITY -DDBG_PKT_MON
	DHDCFLAGS += -DDHD_LOG_DUMP -DDHD_FW_COREDUMP
	DHDCFLAGS += -DAPF -DNDO_CONFIG_SUPPORT -DRSSI_MONITOR_SUPPORT
	DHDCFLAGS += -DDHD_WAKE_STATUS
	DHDOFILES += bcmdhd/dhd_rtt.o bcmdhd/bcm_app_utils.o
endif
endif

ifeq ($(CONFIG_AP6XXX_WIFI6_HDF), y)
	DHDCFLAGS += -DDHD_LOG_DUMP -DDHD_FW_COREDUMP
endif

# For Debug
ifeq ($(CONFIG_BCMDHD_DEBUG),y)
	DHDCFLAGS += -DDHD_ARP_DUMP -DDHD_DHCP_DUMP -DDHD_ICMP_DUMP
	DHDCFLAGS += -DDHD_DNS_DUMP -DDHD_TRX_DUMP
	DHDCFLAGS += -DTPUT_MONITOR
#	DHDCFLAGS += -DSCAN_SUPPRESS -DBSSCACHE
	DHDCFLAGS += -DCHECK_DOWNLOAD_FW
	DHDCFLAGS += -DPKT_STATICS
	DHDCFLAGS += -DKSO_DEBUG
#	DHDCFLAGS += -DDHD_PKTDUMP_TOFW
endif

# For Debug2
ifeq ($(CONFIG_BCMDHD_DEBUG2),y)
	DHDCFLAGS += -DDEBUGFS_CFG80211
	DHDCFLAGS += -DSHOW_LOGTRACE -DDHD_LOG_DUMP -DDHD_FW_COREDUMP
	DHDCFLAGS += -DBCMASSERT_LOG -DSI_ERROR_ENFORCE
ifneq ($(CONFIG_BCMDHD_PCIE),)
	DHDCFLAGS += -DEWP_EDL
	DHDCFLAGS += -DDNGL_EVENT_SUPPORT
	DHDCFLAGS += -DDHD_SSSR_DUMP
endif
endif

# MESH support for kernel 3.10 later
ifeq ($(CONFIG_WL_MESH),y)
	DHDCFLAGS += -DWLMESH
ifneq ($(CONFIG_CFG80211),)
	DHDCFLAGS += -DWLMESH_CFG80211
endif
ifneq ($(CONFIG_BCMDHD_PCIE),)
	DHDCFLAGS += -DBCM_HOST_BUF -DDMA_HOST_BUFFER_LEN=0x80000
endif
	DHDCFLAGS += -DDHD_UPDATE_INTF_MAC
	DHDCFLAGS :=$(filter-out -DDHD_FW_COREDUMP,$(DHDCFLAGS))
	DHDCFLAGS :=$(filter-out -DWL_STATIC_IF,$(DHDCFLAGS))
endif

ifeq ($(CONFIG_BCMDHD_EASYMESH),y)
	DHDCFLAGS :=$(filter-out -DDHD_FW_COREDUMP,$(DHDCFLAGS))
	DHDCFLAGS :=$(filter-out -DDHD_LOG_DUMP,$(DHDCFLAGS))
	DHDCFLAGS += -DWLEASYMESH -DWL_STATIC_IF -DWLDWDS -DFOURADDR_AUTO_BRG
endif

#CSI_SUPPORT
ifeq ($(CONFIG_CSI_SUPPORT),y)
	DHDCFLAGS += -DCSI_SUPPORT
	DHDOFILES += bcmdhd/dhd_csi.o
endif

# For TPUT_IMPROVE
ifeq ($(CONFIG_BCMDHD_TPUT),y)
	DHDCFLAGS += -DDHD_TPUT_PATCH
ifneq ($(CONFIG_BCMDHD_SDIO),)
	DHDCFLAGS += -DDYNAMIC_MAX_HDR_READ
	DHDCFLAGS :=$(filter-out -DSDTEST,$(DHDCFLAGS))
endif
ifneq ($(CONFIG_BCMDHD_PCIE),)
	DHDCFLAGS += -DDHD_LB_TXP_DEFAULT_ENAB
	DHDCFLAGS += -DSET_RPS_CPUS -DSET_XPS_CPUS
	DHDCFLAGS += -DDHD_LB_PRIMARY_CPUS=0xF0 -DDHD_LB_SECONDARY_CPUS=0x0E
endif
endif

# For Zero configure
ifeq ($(CONFIG_BCMDHD_ZEROCONFIG),y)
	DHDCFLAGS += -DWL_EXT_GENL -DSENDPROB
	DHDOFILES += bcmdhd/wl_ext_genl.o
endif

# For WAPI
ifeq ($(CONFIG_BCMDHD_WAPI),y)
	DHDCFLAGS += -DBCMWAPI_WPI -DBCMWAPI_WAI
endif

# For Module auto-selection
ifeq ($(CONFIG_BCMDHD_AUTO_SELECT),y)
	DHDCFLAGS += -DUPDATE_MODULE_NAME
ifneq ($(CONFIG_BCMDHD_SDIO),)
	DHDCFLAGS += -DGET_OTP_MODULE_NAME -DCOMPAT_OLD_MODULE
endif
endif

ifeq ($(CONFIG_BCMDHD),m)
	DHDCFLAGS += -DBCMDHD_MODULAR
endif

ifeq ($(CONFIG_MACH_PLATFORM),y)
	DHDOFILES += bcmdhd/dhd_gpio.o
ifeq ($(CONFIG_BCMDHD_DTS),y)
	DHDCFLAGS += -DBCMDHD_DTS
endif
	DHDCFLAGS += -DCUSTOMER_HW -DDHD_OF_SUPPORT
	#DHDCFLAGS += -DCUSTOMER_HW_ALLWINNER
	DHDCFLAGS += -Iarch/arm/mach-sunxi/include
endif

ifeq ($(CONFIG_BCMDHD_AG),y)
	DHDCFLAGS += -DBAND_AG
endif

ifeq ($(CONFIG_DHD_USE_STATIC_BUF),y)
ifeq  ($(CONFIG_BCMDHD_STATIC_BUF_IN_DHD),y)
	DHDOFILES += bcmdhd/dhd_static_buf.o
	DHDCFLAGS += -DDHD_STATIC_IN_DRIVER
else
	obj-m += bcmdhd/dhd_static_buf.o
endif
	DHDCFLAGS += -DSTATIC_WL_PRIV_STRUCT -DENHANCED_STATIC_BUF
	DHDCFLAGS += -DCONFIG_DHD_USE_STATIC_BUF
	DHDCFLAGS += -DDHD_USE_STATIC_MEMDUMP
ifneq ($(CONFIG_BCMDHD_PCIE),)
	DHDCFLAGS += -DDHD_USE_STATIC_CTRLBUF
endif
endif

ARCH ?= arm64
#BCMDHD_ROOT = $(src)
BCMDHD_ROOT = $(CURR_PATH)
#$(warning "BCMDHD_ROOT=$(BCMDHD_ROOT)")
EXTRA_CFLAGS = $(DHDCFLAGS)
EXTRA_CFLAGS += -DDHD_COMPILED=\"$(BCMDHD_ROOT)\"
EXTRA_CFLAGS += -I$(BCMDHD_ROOT)/bcmdhd/include/ -I$(BCMDHD_ROOT)/bcmdhd -I$(BCMDHD_ROOT)/hdf/
EXTRA_CFLAGS += $(HDF_FRAMEWORKS_INC) \
	$(HDF_WIFI_FRAMEWORKS_INC) \
	$(HDF_WIFI_ADAPTER_INC) \
	$(HDF_WIFI_VENDOR_INC) \
	$(SECURE_LIB_INC)

ifeq ($(CONFIG_BCMDHD),m)
EXTRA_LDFLAGS += --strip-debug
endif

obj-y += $(MODULE_NAME).o
$(MODULE_NAME)-objs := $(DHDOFILES)

ccflags-y := $(EXTRA_CFLAGS) $(HDF_BDH_WIFI_CFLAGS)

all: bcmdhd_pcie bcmdhd_sdio bcmdhd_usb

bcmdhd_pcie:
	$(warning "building BCMDHD_PCIE..........")
	$(MAKE) -C $(LINUXDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules CONFIG_BCMDHD=m CONFIG_BCMDHD_PCIE=y

bcmdhd_sdio:
	$(warning "building BCMDHD_SDIO..........")
	$(MAKE) -C $(LINUXDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules CONFIG_BCMDHD=m CONFIG_BCMDHD_SDIO=y

bcmdhd_usb:
	$(warning "building BCMDHD_USB..........")
	$(MAKE) -C $(LINUXDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules CONFIG_BCMDHD=m CONFIG_BCMDHD_USB=y

.PHONY : clean
clean:
	-rm -rf bcmdhd modules.order built-in.a 
