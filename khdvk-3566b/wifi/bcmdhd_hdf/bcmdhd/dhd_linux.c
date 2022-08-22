/*
 * Broadcom Dongle Host Driver (DHD), Linux-specific network interface
 * Basically selected code segments from usb-cdc.c and usb-rndis.c
 *
 * Copyright (C) 2022 Broadcom.
 *
 *      Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2 (the "GPL"),
 * available at http://www.broadcom.com/licenses/GPLv2.php, with the
 * following added to such license:
 *
 *      As a special exception, the copyright holders of this software give you
 * permission to link this software with independent modules, and to copy and
 * distribute the resulting executable under terms of your choice, provided that
 * you also meet, for each linked independent module, the terms and conditions of
 * the license of that module.  An independent module is a module which is not
 * derived from this software.  The special exception does not apply to any
 * modifications of the software.
 *
 *      Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a license
 * other than the GPL, without Broadcom's express prior written consent.
 *
 *
 * <<Broadcom-WL-IPTag/Open:>>
 *
 * $Id: dhd_linux.c 822756 2019-05-30 13:20:26Z $
 */

#include <typedefs.h>
#include <linuxver.h>
#include <osl.h>
#include <bcmstdlib_s.h>
#ifdef SHOW_LOGTRACE
#include <linux/syscalls.h>
#include <event_log.h>
#endif /* SHOW_LOGTRACE */

#if defined(PCIE_FULL_DONGLE) || defined(SHOW_LOGTRACE)
#include <bcmmsgbuf.h>
#endif /* PCIE_FULL_DONGLE */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/ethtool.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/ip.h>
#include <linux/reboot.h>
#include <linux/notifier.h>
#include <linux/irq.h>
#include <net/addrconf.h>
#ifdef ENABLE_ADAPTIVE_SCHED
#include <linux/cpufreq.h>
#endif /* ENABLE_ADAPTIVE_SCHED */
#include <linux/rtc.h>
#include <linux/namei.h>
#include <asm/uaccess.h>
#include <asm/unaligned.h>
#include <dhd_linux_priv.h>

#include <epivers.h>
#include <bcmutils.h>
#include <bcmendian.h>
#include <bcmdevs.h>
#include <bcmiov.h>

#include <ethernet.h>
#include <bcmevent.h>
#include <vlan.h>
#include <802.3.h>

#include <dhd_linux_wq.h>
#include <dhd.h>
#include <dhd_linux.h>
#include <dhd_linux_pktdump.h>
#ifdef DHD_WET
#include <dhd_wet.h>
#endif /* DHD_WET */
#ifdef PCIE_FULL_DONGLE
#include <dhd_flowring.h>
#endif // endif
#include <dhd_bus.h>
#include <dhd_proto.h>
#include <dhd_config.h>
#ifdef WL_ESCAN
#include <wl_escan.h>
#endif
#include <dhd_dbg.h>
#include <dhd_dbg_ring.h>
#include <dhd_debug.h>
#ifdef CONFIG_HAS_WAKELOCK
#include <linux/wakelock.h>
#endif // endif
#if defined(WL_CFG80211)
#include <wl_cfg80211.h>
#endif	/* WL_CFG80211 */
#ifdef PNO_SUPPORT
#include <dhd_pno.h>
#endif // endif
#ifdef RTT_SUPPORT
#include <dhd_rtt.h>
#endif // endif

#ifdef CSI_SUPPORT
#include <dhd_csi.h>
#endif /* CSI_SUPPORT */

#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif // endif

#if defined(CONFIG_SOC_EXYNOS8895) || defined(CONFIG_SOC_EXYNOS9810) || \
	defined(CONFIG_SOC_EXYNOS9820)
#include <linux/exynos-pci-ctrl.h>
#endif /* CONFIG_SOC_EXYNOS8895 || CONFIG_SOC_EXYNOS9810 || CONFIG_SOC_EXYNOS9820 */

#ifdef DHD_L2_FILTER
#include <bcmicmp.h>
#include <bcm_l2_filter.h>
#include <dhd_l2_filter.h>
#endif /* DHD_L2_FILTER */

#ifdef DHD_PSTA
#include <dhd_psta.h>
#endif /* DHD_PSTA */

#ifdef AMPDU_VO_ENABLE
#include <802.1d.h>
#endif /* AMPDU_VO_ENABLE */

#if defined(DHDTCPACK_SUPPRESS) || defined(DHDTCPSYNC_FLOOD_BLK)
#include <dhd_ip.h>
#endif /* DHDTCPACK_SUPPRESS || DHDTCPSYNC_FLOOD_BLK */
#include <dhd_daemon.h>
#ifdef DHD_4WAYM4_FAIL_DISCONNECT
#include <dhd_eapol.h>
#endif /* DHD_4WAYM4_FAIL_DISCONNECT */
#ifdef DHD_DEBUG_PAGEALLOC
typedef void (*page_corrupt_cb_t)(void *handle, void *addr_corrupt, size_t len);
void dhd_page_corrupt_cb(void *handle, void *addr_corrupt, size_t len);
extern void register_page_corrupt_cb(page_corrupt_cb_t cb, void* handle);
#endif /* DHD_DEBUG_PAGEALLOC */

#define IP_PROT_RESERVED	0xFF

#ifdef DHD_4WAYM4_FAIL_DISCONNECT
static void dhd_m4_state_handler(struct work_struct * work);
#endif /* DHD_4WAYM4_FAIL_DISCONNECT */

#ifdef DHDTCPSYNC_FLOOD_BLK
static void dhd_blk_tsfl_handler(struct work_struct * work);
#endif /* DHDTCPSYNC_FLOOD_BLK */

#ifdef WL_NATOE
#include <dhd_linux_nfct.h>
#endif /* WL_NATOE */

#if defined(SOFTAP)
extern bool ap_cfg_running;
extern bool ap_fw_loaded;
#endif // endif

#ifdef FIX_CPU_MIN_CLOCK
#include <linux/pm_qos.h>
#endif /* FIX_CPU_MIN_CLOCK */

#ifdef SET_RANDOM_MAC_SOFTAP
#ifndef CONFIG_DHD_SET_RANDOM_MAC_VAL
#define CONFIG_DHD_SET_RANDOM_MAC_VAL	0x001A11
#endif // endif
static u32 vendor_oui = CONFIG_DHD_SET_RANDOM_MAC_VAL;
#endif /* SET_RANDOM_MAC_SOFTAP */

#ifdef ENABLE_ADAPTIVE_SCHED
#define DEFAULT_CPUFREQ_THRESH		1000000	/* threshold frequency : 1000000 = 1GHz */
#ifndef CUSTOM_CPUFREQ_THRESH
#define CUSTOM_CPUFREQ_THRESH	DEFAULT_CPUFREQ_THRESH
#endif /* CUSTOM_CPUFREQ_THRESH */
#endif /* ENABLE_ADAPTIVE_SCHED */

/* enable HOSTIP cache update from the host side when an eth0:N is up */
#define AOE_IP_ALIAS_SUPPORT 1

#ifdef PROP_TXSTATUS
#include <wlfc_proto.h>
#include <dhd_wlfc.h>
#endif // endif

#include <wl_android.h>

/* Maximum STA per radio */
#define DHD_MAX_STA     32

const uint8 wme_fifo2ac[] = { 0, 1, 2, 3, 1, 1 };
const uint8 prio2fifo[8] = { 1, 0, 0, 1, 2, 2, 3, 3 };
#define WME_PRIO2AC(prio)  wme_fifo2ac[prio2fifo[(prio)]]

#ifdef ARP_OFFLOAD_SUPPORT
void aoe_update_host_ipv4_table(dhd_pub_t *dhd_pub, u32 ipa, bool add, int idx);
static int dhd_inetaddr_notifier_call(struct notifier_block *this,
	unsigned long event, void *ptr);
static struct notifier_block dhd_inetaddr_notifier = {
	.notifier_call = dhd_inetaddr_notifier_call
};
/* to make sure we won't register the same notifier twice, otherwise a loop is likely to be
 * created in kernel notifier link list (with 'next' pointing to itself)
 */
static bool dhd_inetaddr_notifier_registered = FALSE;
#endif /* ARP_OFFLOAD_SUPPORT */

#if defined(CONFIG_IPV6) && defined(IPV6_NDO_SUPPORT)
int dhd_inet6addr_notifier_call(struct notifier_block *this,
	unsigned long event, void *ptr);
static struct notifier_block dhd_inet6addr_notifier = {
	.notifier_call = dhd_inet6addr_notifier_call
};
/* to make sure we won't register the same notifier twice, otherwise a loop is likely to be
 * created in kernel notifier link list (with 'next' pointing to itself)
 */
static bool dhd_inet6addr_notifier_registered = FALSE;
#endif /* CONFIG_IPV6 && IPV6_NDO_SUPPORT */

#if defined(CONFIG_PM_SLEEP)
#include <linux/suspend.h>
volatile bool dhd_mmc_suspend = FALSE;
DECLARE_WAIT_QUEUE_HEAD(dhd_dpc_wait);
#endif /* defined(CONFIG_PM_SLEEP) */

#if defined(OOB_INTR_ONLY) || defined(BCMSPI_ANDROID) || defined(FORCE_WOWLAN)
extern void dhd_enable_oob_intr(struct dhd_bus *bus, bool enable);
#endif /* defined(OOB_INTR_ONLY) || defined(BCMSPI_ANDROID) */
static void dhd_hang_process(struct work_struct *work_data);
MODULE_LICENSE("GPL and additional rights");

#if defined(MULTIPLE_SUPPLICANT)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25))
DEFINE_MUTEX(_dhd_mutex_lock_);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)) */
#endif
static int dhd_suspend_resume_helper(struct dhd_info *dhd, int val, int force);

#ifdef CONFIG_BCM_DETECT_CONSECUTIVE_HANG
#define MAX_CONSECUTIVE_HANG_COUNTS 5
#endif /* CONFIG_BCM_DETECT_CONSECUTIVE_HANG */

#include <dhd_bus.h>

#ifdef DHD_ULP
#include <dhd_ulp.h>
#endif /* DHD_ULP */

#ifndef PROP_TXSTATUS
#define DBUS_RX_BUFFER_SIZE_DHD(net)	(net->mtu + net->hard_header_len + dhd->pub.hdrlen)
#else
#define DBUS_RX_BUFFER_SIZE_DHD(net)	(net->mtu + net->hard_header_len + dhd->pub.hdrlen + 128)
#endif // endif

#ifdef PROP_TXSTATUS
extern bool dhd_wlfc_skip_fc(void * dhdp, uint8 idx);
extern void dhd_wlfc_plat_init(void *dhd);
extern void dhd_wlfc_plat_deinit(void *dhd);
#endif /* PROP_TXSTATUS */
#ifdef USE_DYNAMIC_F2_BLKSIZE
extern uint sd_f2_blocksize;
extern int dhdsdio_func_blocksize(dhd_pub_t *dhd, int function_num, int block_size);
#endif /* USE_DYNAMIC_F2_BLKSIZE */

/* Linux wireless extension support */
#if defined(WL_WIRELESS_EXT)
#include <wl_iw.h>
extern wl_iw_extra_params_t  g_wl_iw_params;
#endif /* defined(WL_WIRELESS_EXT) */

#ifdef CONFIG_PARTIALSUSPEND_SLP
#include <linux/partialsuspend_slp.h>
#define CONFIG_HAS_EARLYSUSPEND
#define DHD_USE_EARLYSUSPEND
#define register_early_suspend		register_pre_suspend
#define unregister_early_suspend	unregister_pre_suspend
#define early_suspend				pre_suspend
#define EARLY_SUSPEND_LEVEL_BLANK_SCREEN		50
#else
#if defined(CONFIG_HAS_EARLYSUSPEND) && defined(DHD_USE_EARLYSUSPEND)
#include <linux/earlysuspend.h>
#endif /* defined(CONFIG_HAS_EARLYSUSPEND) && defined(DHD_USE_EARLYSUSPEND) */
#endif /* CONFIG_PARTIALSUSPEND_SLP */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0))
#include <linux/nl80211.h>
#endif /* OEM_ANDROID && (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)) */

#if defined(PKT_FILTER_SUPPORT) && defined(APF)
static int __dhd_apf_add_filter(struct net_device *ndev, uint32 filter_id,
	u8* program, uint32 program_len);
static int __dhd_apf_config_filter(struct net_device *ndev, uint32 filter_id,
	uint32 mode, uint32 enable);
static int __dhd_apf_delete_filter(struct net_device *ndev, uint32 filter_id);
#endif /* PKT_FILTER_SUPPORT && APF */

#if defined(WL_CFG80211) && defined(DHD_FILE_DUMP_EVENT) && defined(DHD_FW_COREDUMP)
static int dhd_wait_for_file_dump(dhd_pub_t *dhdp);
#endif /* WL_CFG80211 && DHD_FILE_DUMP_EVENT && DHD_FW_COREDUMP */

#if defined(ARGOS_NOTIFY_CB)
/* ARGOS notifer data */
static struct notifier_block argos_wifi; /* STA */
static struct notifier_block argos_p2p; /* P2P */
argos_rps_ctrl argos_rps_ctrl_data;
#endif // endif

#ifdef DHD_FW_COREDUMP
static int dhd_mem_dump(void *dhd_info, void *event_info, u8 event);
#endif /* DHD_FW_COREDUMP */

#ifdef DHD_LOG_DUMP

struct dhd_log_dump_buf g_dld_buf[DLD_BUFFER_NUM];

/* Only header for log dump buffers is stored in array
 * header for sections like 'dhd dump', 'ext trap'
 * etc, is not in the array, because they are not log
 * ring buffers
 */
dld_hdr_t dld_hdrs[DLD_BUFFER_NUM] = {
		{GENERAL_LOG_HDR, LOG_DUMP_SECTION_GENERAL},
		{PRESERVE_LOG_HDR, LOG_DUMP_SECTION_PRESERVE},
		{SPECIAL_LOG_HDR, LOG_DUMP_SECTION_SPECIAL}
};

static int dld_buf_size[DLD_BUFFER_NUM] = {
		LOG_DUMP_GENERAL_MAX_BUFSIZE,	/* DLD_BUF_TYPE_GENERAL */
		LOG_DUMP_PRESERVE_MAX_BUFSIZE,	/* DLD_BUF_TYPE_PRESERVE */
		LOG_DUMP_SPECIAL_MAX_BUFSIZE,	/* DLD_BUF_TYPE_SPECIAL */
};

static void dhd_log_dump_init(dhd_pub_t *dhd);
static void dhd_log_dump_deinit(dhd_pub_t *dhd);
static void dhd_log_dump(void *handle, void *event_info, u8 event);
static int do_dhd_log_dump(dhd_pub_t *dhdp, log_dump_type_t *type);
static int dhd_log_flush(dhd_pub_t *dhdp, log_dump_type_t *type);
static void dhd_get_time_str(dhd_pub_t *dhdp, char *time_str, int size);
void dhd_get_debug_dump_len(void *handle, struct sk_buff *skb, void *event_info, u8 event);
void cfgvendor_log_dump_len(dhd_pub_t *dhdp, log_dump_type_t *type, struct sk_buff *skb);
static void dhd_print_buf_addr(dhd_pub_t *dhdp, char *name, void *buf, unsigned int size);
static void dhd_log_dump_buf_addr(dhd_pub_t *dhdp, log_dump_type_t *type);
#endif /* DHD_LOG_DUMP */

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
#include <linux/workqueue.h>
#include <linux/pm_runtime.h>
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

#ifdef DHD_DEBUG_UART
#include <linux/kmod.h>
#define DHD_DEBUG_UART_EXEC_PATH	"/system/bin/wldu"
static void dhd_debug_uart_exec_rd(void *handle, void *event_info, u8 event);
static void dhd_debug_uart_exec(dhd_pub_t *dhdp, char *cmd);
#endif	/* DHD_DEBUG_UART */

static int dhd_reboot_callback(struct notifier_block *this, unsigned long code, void *unused);
static struct notifier_block dhd_reboot_notifier = {
	.notifier_call = dhd_reboot_callback,
	.priority = 1,
};

#ifdef BCMPCIE
static int is_reboot = 0;
#endif /* BCMPCIE */

dhd_pub_t	*g_dhd_pub = NULL;

#if defined(BT_OVER_SDIO)
#include "dhd_bt_interface.h"
#endif /* defined (BT_OVER_SDIO) */

#ifdef WL_STATIC_IF
bool dhd_is_static_ndev(dhd_pub_t *dhdp, struct net_device *ndev);
#endif /* WL_STATIC_IF */

atomic_t exit_in_progress = ATOMIC_INIT(0);

static void dhd_process_daemon_msg(struct sk_buff *skb);
static void dhd_destroy_to_notifier_skt(void);
static int dhd_create_to_notifier_skt(void);
static struct sock *nl_to_event_sk = NULL;
int sender_pid = 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0))
struct netlink_kernel_cfg dhd_netlink_cfg = {
	.groups = 1,
	.input = dhd_process_daemon_msg,
};
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)) */

#if defined(BT_OVER_SDIO)
/* Flag to indicate if driver is initialized */
uint dhd_driver_init_done = TRUE;
#else
/* Flag to indicate if driver is initialized */
uint dhd_driver_init_done = FALSE;
#endif // endif
/* Flag to indicate if we should download firmware on driver load */
uint dhd_download_fw_on_driverload = TRUE;

/* Definitions to provide path to the firmware and nvram
 * example nvram_path[MOD_PARAM_PATHLEN]="/projects/wlan/nvram.txt"
 */
char firmware_path[MOD_PARAM_PATHLEN];
char nvram_path[MOD_PARAM_PATHLEN];
char clm_path[MOD_PARAM_PATHLEN];
char config_path[MOD_PARAM_PATHLEN];
#ifdef DHD_UCODE_DOWNLOAD
char ucode_path[MOD_PARAM_PATHLEN];
#endif /* DHD_UCODE_DOWNLOAD */

module_param_string(clm_path, clm_path, MOD_PARAM_PATHLEN, 0660);

/* backup buffer for firmware and nvram path */
char fw_bak_path[MOD_PARAM_PATHLEN];
char nv_bak_path[MOD_PARAM_PATHLEN];

/* information string to keep firmware, chio, cheip version info visiable from log */
char info_string[MOD_PARAM_INFOLEN];
module_param_string(info_string, info_string, MOD_PARAM_INFOLEN, 0444);
int op_mode = 0;
int disable_proptx = 0;
module_param(op_mode, int, 0644);
extern int wl_control_wl_start(struct net_device *dev);
#if defined(BCMLXSDMMC) || defined(BCMDBUS)
struct semaphore dhd_registration_sem;
#endif /* BCMXSDMMC */

#ifdef DHD_LOG_DUMP
int logdump_max_filesize = LOG_DUMP_MAX_FILESIZE;
module_param(logdump_max_filesize, int, 0644);
int logdump_max_bufsize = LOG_DUMP_GENERAL_MAX_BUFSIZE;
module_param(logdump_max_bufsize, int, 0644);
int logdump_prsrv_tailsize = DHD_LOG_DUMP_MAX_TAIL_FLUSH_SIZE;
int logdump_periodic_flush = FALSE;
module_param(logdump_periodic_flush, int, 0644);
#ifdef EWP_ECNTRS_LOGGING
int logdump_ecntr_enable = TRUE;
#else
int logdump_ecntr_enable = FALSE;
#endif /* EWP_ECNTRS_LOGGING */
module_param(logdump_ecntr_enable, int, 0644);
#ifdef EWP_RTT_LOGGING
int logdump_rtt_enable = TRUE;
#else
int logdump_rtt_enable = FALSE;
#endif /* EWP_RTT_LOGGING */
module_param(logdump_rtt_enable, int, 0644);
#endif /* DHD_LOG_DUMP */
#ifdef EWP_EDL
int host_edl_support = TRUE;
module_param(host_edl_support, int, 0644);
#endif // endif

/* deferred handlers */
static void dhd_ifadd_event_handler(void *handle, void *event_info, u8 event);
static void dhd_ifdel_event_handler(void *handle, void *event_info, u8 event);
static void dhd_set_mac_addr_handler(void *handle, void *event_info, u8 event);
static void dhd_set_mcast_list_handler(void *handle, void *event_info, u8 event);
#ifdef WL_NATOE
static void dhd_natoe_ct_event_hanlder(void *handle, void *event_info, u8 event);
static void dhd_natoe_ct_ioctl_handler(void *handle, void *event_info, uint8 event);
#endif /* WL_NATOE */

#ifdef DHD_UPDATE_INTF_MAC
static void dhd_ifupdate_event_handler(void *handle, void *event_info, u8 event);
#endif /* DHD_UPDATE_INTF_MAC */
#if defined(CONFIG_IPV6) && defined(IPV6_NDO_SUPPORT)
static void dhd_inet6_work_handler(void *dhd_info, void *event_data, u8 event);
#endif /* CONFIG_IPV6 && IPV6_NDO_SUPPORT */
#ifdef WL_CFG80211
extern void dhd_netdev_free(struct net_device *ndev);
#endif /* WL_CFG80211 */
static dhd_if_t * dhd_get_ifp_by_ndev(dhd_pub_t *dhdp, struct net_device *ndev);

#if defined(WLDWDS) && defined(FOURADDR_AUTO_BRG)
static void dhd_bridge_dev_set(dhd_info_t * dhd, int ifidx, struct net_device * dev);
#endif /* defiend(WLDWDS) && defined(FOURADDR_AUTO_BRG) */

#if (defined(DHD_WET) || defined(DHD_MCAST_REGEN) || defined(DHD_L2_FILTER))
/* update rx_pkt_chainable state of dhd interface */
static void dhd_update_rx_pkt_chainable_state(dhd_pub_t* dhdp, uint32 idx);
#endif /* DHD_WET || DHD_MCAST_REGEN || DHD_L2_FILTER */

/* Error bits */
module_param(dhd_msg_level, int, 0);
#if defined(WL_WIRELESS_EXT)
module_param(iw_msg_level, int, 0);
#endif
#ifdef WL_CFG80211
module_param(wl_dbg_level, int, 0);
#endif
module_param(android_msg_level, int, 0);
module_param(config_msg_level, int, 0);

#ifdef ARP_OFFLOAD_SUPPORT
/* ARP offload enable */
uint dhd_arp_enable = TRUE;
module_param(dhd_arp_enable, uint, 0);

/* ARP offload agent mode : Enable ARP Host Auto-Reply and ARP Peer Auto-Reply */

#ifdef ENABLE_ARP_SNOOP_MODE
uint dhd_arp_mode = (ARP_OL_AGENT | ARP_OL_PEER_AUTO_REPLY | ARP_OL_SNOOP | ARP_OL_HOST_AUTO_REPLY |
		ARP_OL_UPDATE_HOST_CACHE);
#else
uint dhd_arp_mode = ARP_OL_AGENT | ARP_OL_PEER_AUTO_REPLY | ARP_OL_UPDATE_HOST_CACHE;
#endif /* ENABLE_ARP_SNOOP_MODE */

module_param(dhd_arp_mode, uint, 0);
#endif /* ARP_OFFLOAD_SUPPORT */

/* Disable Prop tx */
module_param(disable_proptx, int, 0644);
/* load firmware and/or nvram values from the filesystem */
module_param_string(firmware_path, firmware_path, MOD_PARAM_PATHLEN, 0660);
module_param_string(nvram_path, nvram_path, MOD_PARAM_PATHLEN, 0660);
module_param_string(config_path, config_path, MOD_PARAM_PATHLEN, 0);
#ifdef DHD_UCODE_DOWNLOAD
module_param_string(ucode_path, ucode_path, MOD_PARAM_PATHLEN, 0660);
#endif /* DHD_UCODE_DOWNLOAD */

/* wl event forwarding */
#ifdef WL_EVENT_ENAB
uint wl_event_enable = true;
#else
uint wl_event_enable = false;
#endif /* WL_EVENT_ENAB */
module_param(wl_event_enable, uint, 0660);

/* wl event forwarding */
#ifdef LOGTRACE_PKT_SENDUP
uint logtrace_pkt_sendup = true;
#else
uint logtrace_pkt_sendup = false;
#endif /* LOGTRACE_PKT_SENDUP */
module_param(logtrace_pkt_sendup, uint, 0660);

/* Watchdog interval */
/* extend watchdog expiration to 2 seconds when DPC is running */
#define WATCHDOG_EXTEND_INTERVAL (2000)

uint dhd_watchdog_ms = CUSTOM_DHD_WATCHDOG_MS;
module_param(dhd_watchdog_ms, uint, 0);

#if defined(DHD_DEBUG)
/* Console poll interval */
uint dhd_console_ms = 0;
module_param(dhd_console_ms, uint, 0644);
#else
uint dhd_console_ms = 0;
#endif /* DHD_DEBUG */

uint dhd_slpauto = TRUE;
module_param(dhd_slpauto, uint, 0);

#ifdef PKT_FILTER_SUPPORT
/* Global Pkt filter enable control */
uint dhd_pkt_filter_enable = TRUE;
module_param(dhd_pkt_filter_enable, uint, 0);
#endif // endif

/* Pkt filter init setup */
uint dhd_pkt_filter_init = 0;
module_param(dhd_pkt_filter_init, uint, 0);

/* Pkt filter mode control */
#ifdef GAN_LITE_NAT_KEEPALIVE_FILTER
uint dhd_master_mode = FALSE;
#else
uint dhd_master_mode = FALSE;
#endif /* GAN_LITE_NAT_KEEPALIVE_FILTER */
module_param(dhd_master_mode, uint, 0);

int dhd_watchdog_prio = 0;
module_param(dhd_watchdog_prio, int, 0);

/* DPC thread priority */
int dhd_dpc_prio = CUSTOM_DPC_PRIO_SETTING;
module_param(dhd_dpc_prio, int, 0);

/* RX frame thread priority */
int dhd_rxf_prio = CUSTOM_RXF_PRIO_SETTING;
module_param(dhd_rxf_prio, int, 0);

#if !defined(BCMDBUS)
extern int dhd_dongle_ramsize;
module_param(dhd_dongle_ramsize, int, 0);
#endif /* !BCMDBUS */

#ifdef WL_CFG80211
int passive_channel_skip = 0;
module_param(passive_channel_skip, int, (S_IRUSR|S_IWUSR));
#endif /* WL_CFG80211 */

#ifdef DHD_MSI_SUPPORT
uint enable_msi = TRUE;
module_param(enable_msi, uint, 0);
#endif /* PCIE_FULL_DONGLE */

#ifdef DHD_SSSR_DUMP
int dhdpcie_sssr_dump_get_before_after_len(dhd_pub_t *dhd, uint32 *arr_len);
extern uint support_sssr_dump;
module_param(support_sssr_dump, uint, 0);
#endif /* DHD_SSSR_DUMP */

/* Keep track of number of instances */
static int dhd_found = 0;
static int instance_base = 0; /* Starting instance number */
module_param(instance_base, int, 0644);

#if defined(DHD_LB_RXP)
static int dhd_napi_weight = 32;
module_param(dhd_napi_weight, int, 0644);
#endif /* DHD_LB_RXP */

#ifdef PCIE_FULL_DONGLE
extern int h2d_max_txpost;
module_param(h2d_max_txpost, int, 0644);

extern uint dma_ring_indices;
module_param(dma_ring_indices, uint, 0644);

extern bool h2d_phase;
module_param(h2d_phase, bool, 0644);
extern bool force_trap_bad_h2d_phase;
module_param(force_trap_bad_h2d_phase, bool, 0644);
#endif /* PCIE_FULL_DONGLE */

#ifdef FORCE_TPOWERON
/*
 * On Fire's reference platform, coming out of L1.2,
 * there is a constant delay of 45us between CLKREQ# and stable REFCLK
 * Due to this delay, with tPowerOn < 50
 * there is a chance of the refclk sense to trigger on noise.
 *
 * 0x29 when written to L1SSControl2 translates to 50us.
 */
#define FORCE_TPOWERON_50US 0x29
uint32 tpoweron_scale = FORCE_TPOWERON_50US; /* default 50us */
module_param(tpoweron_scale, uint, 0644);
#endif /* FORCE_TPOWERON */

#ifdef SHOW_LOGTRACE
static char *logstrs_path = "/data/misc/wifi/logstrs.bin";
char *st_str_file_path = "/data/misc/wifi/rtecdc.bin";
static char *map_file_path = "/data/misc/wifi/rtecdc.map";
static char *rom_st_str_file_path = "/data/misc/wifi/roml.bin";
static char *rom_map_file_path = "/data/misc/wifi/roml.map";
static char *ram_file_str = "rtecdc";
static char *rom_file_str = "roml";

module_param(logstrs_path, charp, S_IRUGO);
module_param(st_str_file_path, charp, S_IRUGO);
module_param(map_file_path, charp, S_IRUGO);
module_param(rom_st_str_file_path, charp, S_IRUGO);
module_param(rom_map_file_path, charp, S_IRUGO);

static int dhd_init_logstrs_array(osl_t *osh, dhd_event_log_t *temp);
static int dhd_read_map(osl_t *osh, char *fname, uint32 *ramstart, uint32 *rodata_start,
	uint32 *rodata_end);
static int dhd_init_static_strs_array(osl_t *osh, dhd_event_log_t *temp, char *str_file,
	char *map_file);
#endif /* SHOW_LOGTRACE */

#ifdef USE_WFA_CERT_CONF
int g_frameburst = 1;
#endif /* USE_WFA_CERT_CONF */

static int dhd_get_pend_8021x_cnt(dhd_info_t *dhd);

/* DHD Perimiter lock only used in router with bypass forwarding. */
#define DHD_PERIM_RADIO_INIT()              do { /* noop */ } while (0)
#define DHD_PERIM_LOCK_TRY(unit, flag)      do { /* noop */ } while (0)
#define DHD_PERIM_UNLOCK_TRY(unit, flag)    do { /* noop */ } while (0)

#ifdef PCIE_FULL_DONGLE
#define DHD_IF_STA_LIST_LOCK_INIT(ifp) spin_lock_init(&(ifp)->sta_list_lock)
#define DHD_IF_STA_LIST_LOCK(ifp, flags) \
	spin_lock_irqsave(&(ifp)->sta_list_lock, (flags))
#define DHD_IF_STA_LIST_UNLOCK(ifp, flags) \
	spin_unlock_irqrestore(&(ifp)->sta_list_lock, (flags))

#if defined(DHD_IGMP_UCQUERY) || defined(DHD_UCAST_UPNP)
static struct list_head * dhd_sta_list_snapshot(dhd_info_t *dhd, dhd_if_t *ifp,
	struct list_head *snapshot_list);
static void dhd_sta_list_snapshot_free(dhd_info_t *dhd, struct list_head *snapshot_list);
#define DHD_IF_WMF_UCFORWARD_LOCK(dhd, ifp, slist) ({ dhd_sta_list_snapshot(dhd, ifp, slist); })
#define DHD_IF_WMF_UCFORWARD_UNLOCK(dhd, slist) ({ dhd_sta_list_snapshot_free(dhd, slist); })
#endif /* DHD_IGMP_UCQUERY || DHD_UCAST_UPNP */
#endif /* PCIE_FULL_DONGLE */

/* Control fw roaming */
#ifdef BCMCCX
uint dhd_roam_disable = 0;
#else
uint dhd_roam_disable = 0;
#endif /* BCMCCX */

#ifdef BCMDBGFS
extern void dhd_dbgfs_init(dhd_pub_t *dhdp);
extern void dhd_dbgfs_remove(void);
#endif // endif

static uint pcie_txs_metadata_enable = 0;	/* Enable TX status metadta report */
module_param(pcie_txs_metadata_enable, int, 0);

/* Control radio state */
uint dhd_radio_up = 1;

/* Network inteface name */
char iface_name[IFNAMSIZ] = {'\0'};
module_param_string(iface_name, iface_name, IFNAMSIZ, 0);

/* The following are specific to the SDIO dongle */

/* IOCTL response timeout */
int dhd_ioctl_timeout_msec = IOCTL_RESP_TIMEOUT;

/* DS Exit response timeout */
int ds_exit_timeout_msec = DS_EXIT_TIMEOUT;

/* Idle timeout for backplane clock */
int dhd_idletime = DHD_IDLETIME_TICKS;
module_param(dhd_idletime, int, 0);

/* Use polling */
uint dhd_poll = FALSE;
module_param(dhd_poll, uint, 0);

/* Use interrupts */
uint dhd_intr = TRUE;
module_param(dhd_intr, uint, 0);

/* SDIO Drive Strength (in milliamps) */
uint dhd_sdiod_drive_strength = 6;
module_param(dhd_sdiod_drive_strength, uint, 0);

#ifdef BCMSDIO
/* Tx/Rx bounds */
extern uint dhd_txbound;
extern uint dhd_rxbound;
module_param(dhd_txbound, uint, 0);
module_param(dhd_rxbound, uint, 0);

/* Deferred transmits */
extern uint dhd_deferred_tx;
module_param(dhd_deferred_tx, uint, 0);

#endif /* BCMSDIO */

#ifdef SDTEST
/* Echo packet generator (pkts/s) */
uint dhd_pktgen = 0;
module_param(dhd_pktgen, uint, 0);

/* Echo packet len (0 => sawtooth, max 2040) */
uint dhd_pktgen_len = 0;
module_param(dhd_pktgen_len, uint, 0);
#endif /* SDTEST */

#if defined(BCMSUP_4WAY_HANDSHAKE)
/* Use in dongle supplicant for 4-way handshake */
#if defined(WLFBT) || defined(WL_ENABLE_IDSUP)
/* Enable idsup by default (if supported in fw) */
uint dhd_use_idsup = 1;
#else
uint dhd_use_idsup = 0;
#endif /* WLFBT || WL_ENABLE_IDSUP */
module_param(dhd_use_idsup, uint, 0);
#endif /* BCMSUP_4WAY_HANDSHAKE */

#ifndef BCMDBUS
/* Allow delayed firmware download for debug purpose */
int allow_delay_fwdl = FALSE;
module_param(allow_delay_fwdl, int, 0);
#endif /* !BCMDBUS */

#ifdef ECOUNTER_PERIODIC_DISABLE
uint enable_ecounter = FALSE;
#else
uint enable_ecounter = TRUE;
#endif // endif
module_param(enable_ecounter, uint, 0);

/* TCM verification flag */
uint dhd_tcm_test_enable = FALSE;
module_param(dhd_tcm_test_enable, uint, 0644);

extern char dhd_version[];
extern char fw_version[];
extern char clm_version[];

int dhd_net_bus_devreset(struct net_device *dev, uint8 flag);
static void dhd_net_if_lock_local(dhd_info_t *dhd);
static void dhd_net_if_unlock_local(dhd_info_t *dhd);
static void dhd_suspend_lock(dhd_pub_t *dhdp);
static void dhd_suspend_unlock(dhd_pub_t *dhdp);

/* Monitor interface */
int dhd_monitor_init(void *dhd_pub);
int dhd_monitor_uninit(void);

#ifdef DHD_PM_CONTROL_FROM_FILE
bool g_pm_control;
#ifdef DHD_EXPORT_CNTL_FILE
int pmmode_val;
#endif /* DHD_EXPORT_CNTL_FILE */
void sec_control_pm(dhd_pub_t *dhd, uint *);
#endif /* DHD_PM_CONTROL_FROM_FILE */

#if defined(WL_WIRELESS_EXT)
struct iw_statistics *dhd_get_wireless_stats(struct net_device *dev);
#endif /* defined(WL_WIRELESS_EXT) */

#ifndef BCMDBUS
static void dhd_dpc(ulong data);
#endif /* !BCMDBUS */
/* forward decl */
extern int dhd_wait_pend8021x(struct net_device *dev);
void dhd_os_wd_timer_extend(void *bus, bool extend);

#ifdef TOE
#ifndef BDC
#error TOE requires BDC
#endif /* !BDC */
static int dhd_toe_get(dhd_info_t *dhd, int idx, uint32 *toe_ol);
static int dhd_toe_set(dhd_info_t *dhd, int idx, uint32 toe_ol);
#endif /* TOE */

static int dhd_wl_host_event(dhd_info_t *dhd, int ifidx, void *pktdata, uint16 pktlen,
		wl_event_msg_t *event_ptr, void **data_ptr);

#if defined(CONFIG_PM_SLEEP)
static int dhd_pm_callback(struct notifier_block *nfb, unsigned long action, void *ignored)
{
	int ret = NOTIFY_DONE;
	bool suspend = FALSE;

#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif // endif
	dhd_info_t *dhdinfo = (dhd_info_t*)container_of(nfb, struct dhd_info, pm_notifier);
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic pop
#endif // endif
	dhd_pub_t *dhd = &dhdinfo->pub;
	struct dhd_conf *conf = dhd->conf;
	int suspend_mode = conf->suspend_mode;

	BCM_REFERENCE(dhdinfo);
	BCM_REFERENCE(suspend);

	switch (action) {
	case PM_HIBERNATION_PREPARE:
	case PM_SUSPEND_PREPARE:
		suspend = TRUE;
		break;

	case PM_POST_HIBERNATION:
	case PM_POST_SUSPEND:
		suspend = FALSE;
		break;
	}

	if(!dhd->early_suspended && suspend_mode != PM_NOTIFIER) {
		suspend_mode = PM_NOTIFIER;
		conf->suspend_mode = PM_NOTIFIER;
		conf->insuspend |= (NO_TXDATA_IN_SUSPEND | NO_TXCTL_IN_SUSPEND);
		printf("%s: switch suspend_mode to %d\n", __FUNCTION__, suspend_mode);
	}
	printf("%s: action=%ld, suspend=%d, suspend_mode=%d\n",
		__FUNCTION__, action, suspend, suspend_mode);
	if (suspend) {
		DHD_OS_WAKE_LOCK_WAIVE(dhd);
		if (suspend_mode == PM_NOTIFIER)
			dhd_suspend_resume_helper(dhdinfo, suspend, 0);
#if defined(SUPPORT_P2P_GO_PS) && defined(PROP_TXSTATUS)
		dhd_wlfc_suspend(dhd);
#endif /* defined(SUPPORT_P2P_GO_PS) && defined(PROP_TXSTATUS) */
		if (suspend_mode == PM_NOTIFIER || suspend_mode == SUSPEND_MODE_2)
			dhd_conf_set_suspend_resume(dhd, suspend);
		DHD_OS_WAKE_LOCK_RESTORE(dhd);
	} else {
		if (suspend_mode == PM_NOTIFIER || suspend_mode == SUSPEND_MODE_2)
			dhd_conf_set_suspend_resume(dhd, suspend);
#if defined(SUPPORT_P2P_GO_PS) && defined(PROP_TXSTATUS)
		dhd_wlfc_resume(dhd);
#endif /* defined(SUPPORT_P2P_GO_PS) && defined(PROP_TXSTATUS) */
		if (suspend_mode == PM_NOTIFIER)
			dhd_suspend_resume_helper(dhdinfo, suspend, 0);
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)) && (LINUX_VERSION_CODE <= \
        KERNEL_VERSION(2, 6, 39))
	dhd_mmc_suspend = suspend;
	smp_mb();
#endif

	return ret;
}

/* to make sure we won't register the same notifier twice, otherwise a loop is likely to be
 * created in kernel notifier link list (with 'next' pointing to itself)
 */
static bool dhd_pm_notifier_registered = FALSE;

extern int register_pm_notifier(struct notifier_block *nb);
extern int unregister_pm_notifier(struct notifier_block *nb);
#endif /* CONFIG_PM_SLEEP */

/* Request scheduling of the bus rx frame */
static void dhd_sched_rxf(dhd_pub_t *dhdp, void *skb);
static void dhd_os_rxflock(dhd_pub_t *pub);
static void dhd_os_rxfunlock(dhd_pub_t *pub);

#if defined(DHD_H2D_LOG_TIME_SYNC)
static void
dhd_deferred_work_rte_log_time_sync(void *handle, void *event_info, u8 event);
#endif /* DHD_H2D_LOG_TIME_SYNC */

/** priv_link is the link between netdev and the dhdif and dhd_info structs. */
typedef struct dhd_dev_priv {
	dhd_info_t * dhd; /* cached pointer to dhd_info in netdevice priv */
	dhd_if_t   * ifp; /* cached pointer to dhd_if in netdevice priv */
	int          ifidx; /* interface index */
	void       * lkup;
} dhd_dev_priv_t;

#define DHD_DEV_PRIV_SIZE       (sizeof(dhd_dev_priv_t))

#ifdef CONFIG_AP6XXX_WIFI6_HDF
#include "net_device.h"

extern int g_hdf_ifidx;
//struct NetDevice * get_hdf_netdev(int ifidx);
void BDH6_ResetDriver(void);
struct NetDevice * GetHdfNetDeviceByLinuxInf(struct net_device *dev);

static inline dhd_dev_priv_t * DHD_DEV_PRIV(struct net_device *dev)
{
	dhd_dev_priv_t *__tmp_dhd_netpriv = NULL;
    struct NetDevice * hnetdev = GetHdfNetDeviceByLinuxInf(dev);
	if ( hnetdev != NULL) {
		__tmp_dhd_netpriv = ((dhd_dev_priv_t *)hnetdev->mlPriv);
	} else {
		__tmp_dhd_netpriv = NULL;
		DHD_ERROR(("HDF net_device %s is invalid\n", dev->name));
	}
	
	return (__tmp_dhd_netpriv);
}

void * VOID_DEV_PRIV(struct net_device *dev)
{
    return (void *)DHD_DEV_PRIV(dev);
}

#define DHD_DEV_INFO(dev)       (DHD_DEV_PRIV(dev)->dhd)
#define DHD_DEV_IFP(dev)        (DHD_DEV_PRIV(dev)->ifp)
#define DHD_DEV_IFIDX(dev)      (DHD_DEV_PRIV(dev)->ifidx)
#define DHD_DEV_LKUP(dev)		(DHD_DEV_PRIV(dev)->lkup)


#else
#define DHD_DEV_PRIV(dev)       ((dhd_dev_priv_t *)DEV_PRIV(dev))
#define DHD_DEV_INFO(dev)       (((dhd_dev_priv_t *)DEV_PRIV(dev))->dhd)
#define DHD_DEV_IFP(dev)        (((dhd_dev_priv_t *)DEV_PRIV(dev))->ifp)
#define DHD_DEV_IFIDX(dev)      (((dhd_dev_priv_t *)DEV_PRIV(dev))->ifidx)
#define DHD_DEV_LKUP(dev)		(((dhd_dev_priv_t *)DEV_PRIV(dev))->lkup)
#endif

/** Clear the dhd net_device's private structure. */
static inline void
dhd_dev_priv_clear(struct net_device * dev)
{
	dhd_dev_priv_t * dev_priv;
	ASSERT(dev != (struct net_device *)NULL);
	dev_priv = DHD_DEV_PRIV(dev);
	dev_priv->dhd = (dhd_info_t *)NULL;
	dev_priv->ifp = (dhd_if_t *)NULL;
	dev_priv->ifidx = DHD_BAD_IF;
	dev_priv->lkup = (void *)NULL;
}

/** Setup the dhd net_device's private structure. */
static inline void
dhd_dev_priv_save(struct net_device * dev, dhd_info_t * dhd, dhd_if_t * ifp,
                  int ifidx)
{
	dhd_dev_priv_t * dev_priv;
	ASSERT(dev != (struct net_device *)NULL);
	dev_priv = DHD_DEV_PRIV(dev);
	dev_priv->dhd = dhd;
	dev_priv->ifp = ifp;
	dev_priv->ifidx = ifidx;
}

/* Return interface pointer */
struct dhd_if * dhd_get_ifp(dhd_pub_t *dhdp, uint32 ifidx)
{
	ASSERT(ifidx < DHD_MAX_IFS);

	if (!dhdp || !dhdp->info || ifidx >= DHD_MAX_IFS)
		return NULL;

	return dhdp->info->iflist[ifidx];
}

#ifdef WLEASYMESH
int
dhd_set_1905_almac(dhd_pub_t *dhdp, uint8 ifidx, uint8* ea, bool mcast)
{
	dhd_if_t *ifp;

	ASSERT(ea != NULL);
	ifp = dhd_get_ifp(dhdp, ifidx);
	if (ifp == NULL) {
		return BCME_ERROR;
	}
	if (mcast) {
		memcpy(ifp->_1905_al_mcast, ea, ETHER_ADDR_LEN);
	} else {
		memcpy(ifp->_1905_al_ucast, ea, ETHER_ADDR_LEN);
	}
	return BCME_OK;
}
int
dhd_get_1905_almac(dhd_pub_t *dhdp, uint8 ifidx, uint8* ea, bool mcast)
{
	dhd_if_t *ifp;

	ASSERT(ea != NULL);
	ifp = dhd_get_ifp(dhdp, ifidx);
	if (ifp == NULL) {
		return BCME_ERROR;
	}
	if (mcast) {
		memcpy(ea, ifp->_1905_al_mcast, ETHER_ADDR_LEN);
	} else {
		memcpy(ea, ifp->_1905_al_ucast, ETHER_ADDR_LEN);
	}
	return BCME_OK;
}
#endif /* WLEASYMESH */

#ifdef PCIE_FULL_DONGLE

/** Dummy objects are defined with state representing bad|down.
 * Performance gains from reducing branch conditionals, instruction parallelism,
 * dual issue, reducing load shadows, avail of larger pipelines.
 * Use DHD_XXX_NULL instead of (dhd_xxx_t *)NULL, whenever an object pointer
 * is accessed via the dhd_sta_t.
 */

/* Dummy dhd_info object */
dhd_info_t dhd_info_null = {
	.pub = {
	         .info = &dhd_info_null,
#ifdef DHDTCPACK_SUPPRESS
	         .tcpack_sup_mode = TCPACK_SUP_REPLACE,
#endif /* DHDTCPACK_SUPPRESS */
	         .up = FALSE,
	         .busstate = DHD_BUS_DOWN
	}
};
#define DHD_INFO_NULL (&dhd_info_null)
#define DHD_PUB_NULL  (&dhd_info_null.pub)

/* Dummy netdevice object */
struct net_device dhd_net_dev_null = {
	.reg_state = NETREG_UNREGISTERED
};
#define DHD_NET_DEV_NULL (&dhd_net_dev_null)

/* Dummy dhd_if object */
dhd_if_t dhd_if_null = {
#ifdef WMF
	.wmf = { .wmf_enable = TRUE },
#endif // endif
	.info = DHD_INFO_NULL,
	.net = DHD_NET_DEV_NULL,
	.idx = DHD_BAD_IF
};
#define DHD_IF_NULL  (&dhd_if_null)

#define DHD_STA_NULL ((dhd_sta_t *)NULL)

/** Interface STA list management. */

/** Alloc/Free a dhd_sta object from the dhd instances' sta_pool. */
static void dhd_sta_free(dhd_pub_t *pub, dhd_sta_t *sta);
static dhd_sta_t * dhd_sta_alloc(dhd_pub_t * dhdp);

/* Delete a dhd_sta or flush all dhd_sta in an interface's sta_list. */
static void dhd_if_del_sta_list(dhd_if_t * ifp);
static void	dhd_if_flush_sta(dhd_if_t * ifp);

/* Construct/Destruct a sta pool. */
static int dhd_sta_pool_init(dhd_pub_t *dhdp, int max_sta);
static void dhd_sta_pool_fini(dhd_pub_t *dhdp, int max_sta);
/* Clear the pool of dhd_sta_t objects for built-in type driver */
static void dhd_sta_pool_clear(dhd_pub_t *dhdp, int max_sta);

/** Reset a dhd_sta object and free into the dhd pool. */
static void
dhd_sta_free(dhd_pub_t * dhdp, dhd_sta_t * sta)
{
	int prio;

	ASSERT((sta != DHD_STA_NULL) && (sta->idx != ID16_INVALID));

	ASSERT((dhdp->staid_allocator != NULL) && (dhdp->sta_pool != NULL));

	/*
	 * Flush and free all packets in all flowring's queues belonging to sta.
	 * Packets in flow ring will be flushed later.
	 */
	for (prio = 0; prio < (int)NUMPRIO; prio++) {
		uint16 flowid = sta->flowid[prio];

		if (flowid != FLOWID_INVALID) {
			unsigned long flags;
			flow_ring_node_t * flow_ring_node;

#ifdef DHDTCPACK_SUPPRESS
			/* Clean tcp_ack_info_tbl in order to prevent access to flushed pkt,
			 * when there is a newly coming packet from network stack.
			 */
			dhd_tcpack_info_tbl_clean(dhdp);
#endif /* DHDTCPACK_SUPPRESS */

			flow_ring_node = dhd_flow_ring_node(dhdp, flowid);
			if (flow_ring_node) {
				flow_queue_t *queue = &flow_ring_node->queue;

				DHD_FLOWRING_LOCK(flow_ring_node->lock, flags);
				flow_ring_node->status = FLOW_RING_STATUS_STA_FREEING;

				if (!DHD_FLOW_QUEUE_EMPTY(queue)) {
					void * pkt;
					while ((pkt = dhd_flow_queue_dequeue(dhdp, queue)) !=
						NULL) {
						PKTFREE(dhdp->osh, pkt, TRUE);
					}
				}

				DHD_FLOWRING_UNLOCK(flow_ring_node->lock, flags);
				ASSERT(DHD_FLOW_QUEUE_EMPTY(queue));
			}
		}

		sta->flowid[prio] = FLOWID_INVALID;
	}

	id16_map_free(dhdp->staid_allocator, sta->idx);
	DHD_CUMM_CTR_INIT(&sta->cumm_ctr);
	sta->ifp = DHD_IF_NULL; /* dummy dhd_if object */
	sta->ifidx = DHD_BAD_IF;
	bzero(sta->ea.octet, ETHER_ADDR_LEN);
	INIT_LIST_HEAD(&sta->list);
	sta->idx = ID16_INVALID; /* implying free */
}

/** Allocate a dhd_sta object from the dhd pool. */
static dhd_sta_t *
dhd_sta_alloc(dhd_pub_t * dhdp)
{
	uint16 idx;
	dhd_sta_t * sta;
	dhd_sta_pool_t * sta_pool;

	ASSERT((dhdp->staid_allocator != NULL) && (dhdp->sta_pool != NULL));

	idx = id16_map_alloc(dhdp->staid_allocator);
	if (idx == ID16_INVALID) {
		DHD_ERROR(("%s: cannot get free staid\n", __FUNCTION__));
		return DHD_STA_NULL;
	}

	sta_pool = (dhd_sta_pool_t *)(dhdp->sta_pool);
	sta = &sta_pool[idx];

	ASSERT((sta->idx == ID16_INVALID) &&
	       (sta->ifp == DHD_IF_NULL) && (sta->ifidx == DHD_BAD_IF));

	DHD_CUMM_CTR_INIT(&sta->cumm_ctr);

	sta->idx = idx; /* implying allocated */

	return sta;
}

/** Delete all STAs in an interface's STA list. */
static void
dhd_if_del_sta_list(dhd_if_t *ifp)
{
	dhd_sta_t *sta, *next;
	unsigned long flags;

	DHD_IF_STA_LIST_LOCK(ifp, flags);
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif // endif
	list_for_each_entry_safe(sta, next, &ifp->sta_list, list) {
		list_del(&sta->list);
		dhd_sta_free(&ifp->info->pub, sta);
	}
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic pop
#endif // endif
	DHD_IF_STA_LIST_UNLOCK(ifp, flags);

	return;
}

/** Router/GMAC3: Flush all station entries in the forwarder's WOFA database. */
static void
dhd_if_flush_sta(dhd_if_t * ifp)
{
}

/** Construct a pool of dhd_sta_t objects to be used by interfaces. */
static int
dhd_sta_pool_init(dhd_pub_t *dhdp, int max_sta)
{
	int idx, prio, sta_pool_memsz;
	dhd_sta_t * sta;
	dhd_sta_pool_t * sta_pool;
	void * staid_allocator;

	ASSERT(dhdp != (dhd_pub_t *)NULL);
	ASSERT((dhdp->staid_allocator == NULL) && (dhdp->sta_pool == NULL));

	/* dhd_sta objects per radio are managed in a table. id#0 reserved. */
	staid_allocator = id16_map_init(dhdp->osh, max_sta, 1);
	if (staid_allocator == NULL) {
		DHD_ERROR(("%s: sta id allocator init failure\n", __FUNCTION__));
		return BCME_ERROR;
	}

	/* Pre allocate a pool of dhd_sta objects (one extra). */
	sta_pool_memsz = ((max_sta + 1) * sizeof(dhd_sta_t)); /* skip idx 0 */
	sta_pool = (dhd_sta_pool_t *)MALLOC(dhdp->osh, sta_pool_memsz);
	if (sta_pool == NULL) {
		DHD_ERROR(("%s: sta table alloc failure\n", __FUNCTION__));
		id16_map_fini(dhdp->osh, staid_allocator);
		return BCME_ERROR;
	}

	dhdp->sta_pool = sta_pool;
	dhdp->staid_allocator = staid_allocator;

	/* Initialize all sta(s) for the pre-allocated free pool. */
	bzero((uchar *)sta_pool, sta_pool_memsz);
	for (idx = max_sta; idx >= 1; idx--) { /* skip sta_pool[0] */
		sta = &sta_pool[idx];
		sta->idx = id16_map_alloc(staid_allocator);
		ASSERT(sta->idx <= max_sta);
	}

	/* Now place them into the pre-allocated free pool. */
	for (idx = 1; idx <= max_sta; idx++) {
		sta = &sta_pool[idx];
		for (prio = 0; prio < (int)NUMPRIO; prio++) {
			sta->flowid[prio] = FLOWID_INVALID; /* Flow rings do not exist */
		}
		dhd_sta_free(dhdp, sta);
	}

	return BCME_OK;
}

/** Destruct the pool of dhd_sta_t objects.
 * Caller must ensure that no STA objects are currently associated with an if.
 */
static void
dhd_sta_pool_fini(dhd_pub_t *dhdp, int max_sta)
{
	dhd_sta_pool_t * sta_pool = (dhd_sta_pool_t *)dhdp->sta_pool;

	if (sta_pool) {
		int idx;
		int sta_pool_memsz = ((max_sta + 1) * sizeof(dhd_sta_t));
		for (idx = 1; idx <= max_sta; idx++) {
			ASSERT(sta_pool[idx].ifp == DHD_IF_NULL);
			ASSERT(sta_pool[idx].idx == ID16_INVALID);
		}
		MFREE(dhdp->osh, dhdp->sta_pool, sta_pool_memsz);
		dhdp->sta_pool = NULL;
	}

	id16_map_fini(dhdp->osh, dhdp->staid_allocator);
	dhdp->staid_allocator = NULL;
}

/* Clear the pool of dhd_sta_t objects for built-in type driver */
static void
dhd_sta_pool_clear(dhd_pub_t *dhdp, int max_sta)
{
	int idx, prio, sta_pool_memsz;
	dhd_sta_t * sta;
	dhd_sta_pool_t * sta_pool;
	void *staid_allocator;

	if (!dhdp) {
		DHD_ERROR(("%s: dhdp is NULL\n", __FUNCTION__));
		return;
	}

	sta_pool = (dhd_sta_pool_t *)dhdp->sta_pool;
	staid_allocator = dhdp->staid_allocator;

	if (!sta_pool) {
		DHD_ERROR(("%s: sta_pool is NULL\n", __FUNCTION__));
		return;
	}

	if (!staid_allocator) {
		DHD_ERROR(("%s: staid_allocator is NULL\n", __FUNCTION__));
		return;
	}

	/* clear free pool */
	sta_pool_memsz = ((max_sta + 1) * sizeof(dhd_sta_t));
	bzero((uchar *)sta_pool, sta_pool_memsz);

	/* dhd_sta objects per radio are managed in a table. id#0 reserved. */
	id16_map_clear(staid_allocator, max_sta, 1);

	/* Initialize all sta(s) for the pre-allocated free pool. */
	for (idx = max_sta; idx >= 1; idx--) { /* skip sta_pool[0] */
		sta = &sta_pool[idx];
		sta->idx = id16_map_alloc(staid_allocator);
		ASSERT(sta->idx <= max_sta);
	}
	/* Now place them into the pre-allocated free pool. */
	for (idx = 1; idx <= max_sta; idx++) {
		sta = &sta_pool[idx];
		for (prio = 0; prio < (int)NUMPRIO; prio++) {
			sta->flowid[prio] = FLOWID_INVALID; /* Flow rings do not exist */
		}
		dhd_sta_free(dhdp, sta);
	}
}

/** Find STA with MAC address ea in an interface's STA list. */
dhd_sta_t *
dhd_find_sta(void *pub, int ifidx, void *ea)
{
	dhd_sta_t *sta;
	dhd_if_t *ifp;
	unsigned long flags;

	ASSERT(ea != NULL);
	ifp = dhd_get_ifp((dhd_pub_t *)pub, ifidx);
	if (ifp == NULL)
		return DHD_STA_NULL;

	DHD_IF_STA_LIST_LOCK(ifp, flags);
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif // endif
	list_for_each_entry(sta, &ifp->sta_list, list) {
		if (!memcmp(sta->ea.octet, ea, ETHER_ADDR_LEN)) {
			DHD_INFO(("%s: Found STA " MACDBG "\n",
				__FUNCTION__, MAC2STRDBG((char *)ea)));
			DHD_IF_STA_LIST_UNLOCK(ifp, flags);
			return sta;
		}
	}
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic pop
#endif // endif
	DHD_IF_STA_LIST_UNLOCK(ifp, flags);

	return DHD_STA_NULL;
}

/** Add STA into the interface's STA list. */
dhd_sta_t *
dhd_add_sta(void *pub, int ifidx, void *ea)
{
	dhd_sta_t *sta;
	dhd_if_t *ifp;
	unsigned long flags;

	ASSERT(ea != NULL);
	ifp = dhd_get_ifp((dhd_pub_t *)pub, ifidx);
	if (ifp == NULL)
		return DHD_STA_NULL;

	if (!memcmp(ifp->net->dev_addr, ea, ETHER_ADDR_LEN)) {
		DHD_ERROR(("%s: Serious FAILURE, receive own MAC %pM !!\n", __FUNCTION__, ea));
		return DHD_STA_NULL;
	}

	sta = dhd_sta_alloc((dhd_pub_t *)pub);
	if (sta == DHD_STA_NULL) {
		DHD_ERROR(("%s: Alloc failed\n", __FUNCTION__));
		return DHD_STA_NULL;
	}

	memcpy(sta->ea.octet, ea, ETHER_ADDR_LEN);

	/* link the sta and the dhd interface */
	sta->ifp = ifp;
	sta->ifidx = ifidx;
	INIT_LIST_HEAD(&sta->list);

	DHD_IF_STA_LIST_LOCK(ifp, flags);

	list_add_tail(&sta->list, &ifp->sta_list);

	DHD_ERROR(("%s: Adding  STA " MACDBG "\n",
		__FUNCTION__, MAC2STRDBG((char *)ea)));

	DHD_IF_STA_LIST_UNLOCK(ifp, flags);

	return sta;
}

/** Delete all STAs from the interface's STA list. */
void
dhd_del_all_sta(void *pub, int ifidx)
{
	dhd_sta_t *sta, *next;
	dhd_if_t *ifp;
	unsigned long flags;

	ifp = dhd_get_ifp((dhd_pub_t *)pub, ifidx);
	if (ifp == NULL)
		return;

	DHD_IF_STA_LIST_LOCK(ifp, flags);
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif // endif
	list_for_each_entry_safe(sta, next, &ifp->sta_list, list) {

		list_del(&sta->list);
		dhd_sta_free(&ifp->info->pub, sta);
#ifdef DHD_L2_FILTER
		if (ifp->parp_enable) {
			/* clear Proxy ARP cache of specific Ethernet Address */
			bcm_l2_filter_arp_table_update(((dhd_pub_t*)pub)->osh,
					ifp->phnd_arp_table, FALSE,
					sta->ea.octet, FALSE, ((dhd_pub_t*)pub)->tickcnt);
		}
#endif /* DHD_L2_FILTER */
	}
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic pop
#endif // endif
	DHD_IF_STA_LIST_UNLOCK(ifp, flags);

	return;
}

/** Delete STA from the interface's STA list. */
void
dhd_del_sta(void *pub, int ifidx, void *ea)
{
	dhd_sta_t *sta, *next;
	dhd_if_t *ifp;
	unsigned long flags;

	ASSERT(ea != NULL);
	ifp = dhd_get_ifp((dhd_pub_t *)pub, ifidx);
	if (ifp == NULL)
		return;

	DHD_IF_STA_LIST_LOCK(ifp, flags);
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif // endif
	list_for_each_entry_safe(sta, next, &ifp->sta_list, list) {
		if (!memcmp(sta->ea.octet, ea, ETHER_ADDR_LEN)) {
			DHD_ERROR(("%s: Deleting STA " MACDBG "\n",
				__FUNCTION__, MAC2STRDBG(sta->ea.octet)));
			list_del(&sta->list);
			dhd_sta_free(&ifp->info->pub, sta);
		}
	}
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic pop
#endif // endif
	DHD_IF_STA_LIST_UNLOCK(ifp, flags);
#ifdef DHD_L2_FILTER
	if (ifp->parp_enable) {
		/* clear Proxy ARP cache of specific Ethernet Address */
		bcm_l2_filter_arp_table_update(((dhd_pub_t*)pub)->osh, ifp->phnd_arp_table, FALSE,
			ea, FALSE, ((dhd_pub_t*)pub)->tickcnt);
	}
#endif /* DHD_L2_FILTER */
	return;
}

/** Add STA if it doesn't exist. Not reentrant. */
dhd_sta_t*
dhd_findadd_sta(void *pub, int ifidx, void *ea)
{
	dhd_sta_t *sta;

	sta = dhd_find_sta(pub, ifidx, ea);

	if (!sta) {
		/* Add entry */
		sta = dhd_add_sta(pub, ifidx, ea);
	}

	return sta;
}

#if defined(DHD_IGMP_UCQUERY) || defined(DHD_UCAST_UPNP)
static struct list_head *
dhd_sta_list_snapshot(dhd_info_t *dhd, dhd_if_t *ifp, struct list_head *snapshot_list)
{
	unsigned long flags;
	dhd_sta_t *sta, *snapshot;

	INIT_LIST_HEAD(snapshot_list);

	DHD_IF_STA_LIST_LOCK(ifp, flags);

	list_for_each_entry(sta, &ifp->sta_list, list) {
		/* allocate one and add to snapshot */
		snapshot = (dhd_sta_t *)MALLOC(dhd->pub.osh, sizeof(dhd_sta_t));
		if (snapshot == NULL) {
			DHD_ERROR(("%s: Cannot allocate memory\n", __FUNCTION__));
			continue;
		}

		memcpy(snapshot->ea.octet, sta->ea.octet, ETHER_ADDR_LEN);

		INIT_LIST_HEAD(&snapshot->list);
		list_add_tail(&snapshot->list, snapshot_list);
	}

	DHD_IF_STA_LIST_UNLOCK(ifp, flags);

	return snapshot_list;
}

static void
dhd_sta_list_snapshot_free(dhd_info_t *dhd, struct list_head *snapshot_list)
{
	dhd_sta_t *sta, *next;

	list_for_each_entry_safe(sta, next, snapshot_list, list) {
		list_del(&sta->list);
		MFREE(dhd->pub.osh, sta, sizeof(dhd_sta_t));
	}
}
#endif /* DHD_IGMP_UCQUERY || DHD_UCAST_UPNP */

#else
static inline void dhd_if_flush_sta(dhd_if_t * ifp) { }
static inline void dhd_if_del_sta_list(dhd_if_t *ifp) {}
static inline int dhd_sta_pool_init(dhd_pub_t *dhdp, int max_sta) { return BCME_OK; }
static inline void dhd_sta_pool_fini(dhd_pub_t *dhdp, int max_sta) {}
static inline void dhd_sta_pool_clear(dhd_pub_t *dhdp, int max_sta) {}
dhd_sta_t *dhd_findadd_sta(void *pub, int ifidx, void *ea) { return NULL; }
dhd_sta_t *dhd_find_sta(void *pub, int ifidx, void *ea) { return NULL; }
void dhd_del_sta(void *pub, int ifidx, void *ea) {}
#endif /* PCIE_FULL_DONGLE */

#if defined(DNGL_AXI_ERROR_LOGGING) && defined(DHD_USE_WQ_FOR_DNGL_AXI_ERROR)
void
dhd_axi_error_dispatch(dhd_pub_t *dhdp)
{
	dhd_info_t *dhd = dhdp->info;
	schedule_work(&dhd->axi_error_dispatcher_work);
}

static void dhd_axi_error_dispatcher_fn(struct work_struct * work)
{
	struct dhd_info *dhd =
		container_of(work, struct dhd_info, axi_error_dispatcher_work);
	dhd_axi_error(&dhd->pub);
}
#endif /* DNGL_AXI_ERROR_LOGGING && DHD_USE_WQ_FOR_DNGL_AXI_ERROR */

/** Returns dhd iflist index corresponding the the bssidx provided by apps */
int dhd_bssidx2idx(dhd_pub_t *dhdp, uint32 bssidx)
{
	dhd_if_t *ifp;
	dhd_info_t *dhd = dhdp->info;
	int i;

	ASSERT(bssidx < DHD_MAX_IFS);
	ASSERT(dhdp);

	for (i = 0; i < DHD_MAX_IFS; i++) {
		ifp = dhd->iflist[i];
		if (ifp && (ifp->bssidx == bssidx)) {
			DHD_TRACE(("Index manipulated for %s from %d to %d\n",
				ifp->name, bssidx, i));
			break;
		}
	}
	return i;
}

static inline int dhd_rxf_enqueue(dhd_pub_t *dhdp, void* skb)
{
	uint32 store_idx;
	uint32 sent_idx;

	if (!skb) {
		DHD_ERROR(("dhd_rxf_enqueue: NULL skb!!!\n"));
		return BCME_ERROR;
	}

	dhd_os_rxflock(dhdp);
	store_idx = dhdp->store_idx;
	sent_idx = dhdp->sent_idx;
	if (dhdp->skbbuf[store_idx] != NULL) {
		/* Make sure the previous packets are processed */
		dhd_os_rxfunlock(dhdp);
		DHD_ERROR(("dhd_rxf_enqueue: pktbuf not consumed %p, store idx %d sent idx %d\n",
			skb, store_idx, sent_idx));
		/* removed msleep here, should use wait_event_timeout if we
		 * want to give rx frame thread a chance to run
		 */
#if defined(WAIT_DEQUEUE)
		OSL_SLEEP(1);
#endif // endif
		return BCME_ERROR;
	}
	DHD_TRACE(("dhd_rxf_enqueue: Store SKB %p. idx %d -> %d\n",
		skb, store_idx, (store_idx + 1) & (MAXSKBPEND - 1)));
	dhdp->skbbuf[store_idx] = skb;
	dhdp->store_idx = (store_idx + 1) & (MAXSKBPEND - 1);
	dhd_os_rxfunlock(dhdp);

	return BCME_OK;
}

static inline void* dhd_rxf_dequeue(dhd_pub_t *dhdp)
{
	uint32 store_idx;
	uint32 sent_idx;
	void *skb;

	dhd_os_rxflock(dhdp);

	store_idx = dhdp->store_idx;
	sent_idx = dhdp->sent_idx;
	skb = dhdp->skbbuf[sent_idx];

	if (skb == NULL) {
		dhd_os_rxfunlock(dhdp);
		DHD_ERROR(("dhd_rxf_dequeue: Dequeued packet is NULL, store idx %d sent idx %d\n",
			store_idx, sent_idx));
		return NULL;
	}

	dhdp->skbbuf[sent_idx] = NULL;
	dhdp->sent_idx = (sent_idx + 1) & (MAXSKBPEND - 1);

	DHD_TRACE(("dhd_rxf_dequeue: netif_rx_ni(%p), sent idx %d\n",
		skb, sent_idx));

	dhd_os_rxfunlock(dhdp);

	return skb;
}

int dhd_process_cid_mac(dhd_pub_t *dhdp, bool prepost)
{
	if (prepost) { /* pre process */
		dhd_read_cis(dhdp);
		dhd_check_module_cid(dhdp);
		dhd_check_module_mac(dhdp);
		dhd_set_macaddr_from_file(dhdp);
	} else { /* post process */
		dhd_write_macaddr(&dhdp->mac);
		dhd_clear_cis(dhdp);
	}

	return 0;
}

#if defined(WL_CFG80211) && defined(DHD_FILE_DUMP_EVENT) && defined(DHD_FW_COREDUMP)
static int dhd_wait_for_file_dump(dhd_pub_t *dhdp)
{
	struct net_device *primary_ndev;
	struct bcm_cfg80211 *cfg;
	unsigned long flags = 0;
	primary_ndev = dhd_linux_get_primary_netdev(dhdp);

	if (!primary_ndev) {
		DHD_ERROR(("%s: Cannot find primary netdev\n", __FUNCTION__));
		return BCME_ERROR;
	}
	cfg = wl_get_cfg(primary_ndev);

	if (!cfg) {
		DHD_ERROR(("%s: Cannot find cfg\n", __FUNCTION__));
		return BCME_ERROR;
	}

	DHD_GENERAL_LOCK(dhdp, flags);
	if (DHD_BUS_CHECK_DOWN_OR_DOWN_IN_PROGRESS(dhdp)) {
		DHD_BUS_BUSY_CLEAR_IN_HALDUMP(dhdp);
		dhd_os_busbusy_wake(dhdp);
		DHD_GENERAL_UNLOCK(dhdp, flags);
		DHD_ERROR(("%s: bus is down! can't collect log dump. \n", __FUNCTION__));
		return BCME_ERROR;
	}
	DHD_BUS_BUSY_SET_IN_HALDUMP(dhdp);
	DHD_GENERAL_UNLOCK(dhdp, flags);

	DHD_OS_WAKE_LOCK(dhdp);
	/* check for hal started and only then send event if not clear dump state here */
	if (wl_cfg80211_is_hal_started(cfg)) {
		int timeleft = 0;

		DHD_ERROR(("[DUMP] %s: HAL started. send urgent event\n", __FUNCTION__));
		dhd_dbg_send_urgent_evt(dhdp, NULL, 0);

		DHD_ERROR(("%s: wait to clear dhd_bus_busy_state: 0x%x\n",
			__FUNCTION__, dhdp->dhd_bus_busy_state));
		timeleft = dhd_os_busbusy_wait_bitmask(dhdp,
				&dhdp->dhd_bus_busy_state, DHD_BUS_BUSY_IN_HALDUMP, 0);
		if ((dhdp->dhd_bus_busy_state & DHD_BUS_BUSY_IN_HALDUMP) != 0) {
			DHD_ERROR(("%s: Timed out dhd_bus_busy_state=0x%x\n",
					__FUNCTION__, dhdp->dhd_bus_busy_state));
		}
	} else {
		DHD_ERROR(("[DUMP] %s: HAL Not started. skip urgent event\n", __FUNCTION__));
	}
	DHD_OS_WAKE_UNLOCK(dhdp);
	/* In case of dhd_os_busbusy_wait_bitmask() timeout,
	 * hal dump bit will not be cleared. Hence clearing it here.
	 */
	DHD_GENERAL_LOCK(dhdp, flags);
	DHD_BUS_BUSY_CLEAR_IN_HALDUMP(dhdp);
	dhd_os_busbusy_wake(dhdp);
	DHD_GENERAL_UNLOCK(dhdp, flags);

	return BCME_OK;
}
#endif /* WL_CFG80211 && DHD_FILE_DUMP_EVENT && DHD_FW_CORE_DUMP */

// terence 20160615: fix building error if ARP_OFFLOAD_SUPPORT removed
#if defined(PKT_FILTER_SUPPORT)
#if defined(ARP_OFFLOAD_SUPPORT) && !defined(GAN_LITE_NAT_KEEPALIVE_FILTER)
static bool
_turn_on_arp_filter(dhd_pub_t *dhd, int op_mode_param)
{
	bool _apply = FALSE;
	/* In case of IBSS mode, apply arp pkt filter */
	if (op_mode_param & DHD_FLAG_IBSS_MODE) {
		_apply = TRUE;
		goto exit;
	}
	/* In case of P2P GO or GC, apply pkt filter to pass arp pkt to host */
	if (op_mode_param & (DHD_FLAG_P2P_GC_MODE | DHD_FLAG_P2P_GO_MODE)) {
		_apply = TRUE;
		goto exit;
	}

exit:
	return _apply;
}
#endif /* !GAN_LITE_NAT_KEEPALIVE_FILTER */

void
dhd_set_packet_filter(dhd_pub_t *dhd)
{
	int i;

	DHD_TRACE(("%s: enter\n", __FUNCTION__));
	if (dhd_pkt_filter_enable) {
		for (i = 0; i < dhd->pktfilter_count; i++) {
			dhd_pktfilter_offload_set(dhd, dhd->pktfilter[i]);
		}
	}
}

void
dhd_enable_packet_filter(int value, dhd_pub_t *dhd)
{
	int i;

	DHD_ERROR(("%s: enter, value = %d\n", __FUNCTION__, value));
	if ((dhd->op_mode & DHD_FLAG_HOSTAP_MODE) && value &&
			!dhd_conf_get_insuspend(dhd, AP_FILTER_IN_SUSPEND)) {
		DHD_ERROR(("%s: DHD_FLAG_HOSTAP_MODE\n", __FUNCTION__));
		return;
	}
	/* 1 - Enable packet filter, only allow unicast packet to send up */
	/* 0 - Disable packet filter */
	if (dhd_pkt_filter_enable && (!value ||
	    (dhd_support_sta_mode(dhd) && !dhd->dhcp_in_progress) ||
	    dhd_conf_get_insuspend(dhd, AP_FILTER_IN_SUSPEND)))
	{
		for (i = 0; i < dhd->pktfilter_count; i++) {
// terence 20160615: fix building error if ARP_OFFLOAD_SUPPORT removed
#if defined(ARP_OFFLOAD_SUPPORT) && !defined(GAN_LITE_NAT_KEEPALIVE_FILTER)
			if (value && (i == DHD_ARP_FILTER_NUM) &&
				!_turn_on_arp_filter(dhd, dhd->op_mode)) {
				DHD_TRACE(("Do not turn on ARP white list pkt filter:"
					"val %d, cnt %d, op_mode 0x%x\n",
					value, i, dhd->op_mode));
				continue;
			}
#endif /* !GAN_LITE_NAT_KEEPALIVE_FILTER */
			dhd_pktfilter_offload_enable(dhd, dhd->pktfilter[i],
				value, dhd_master_mode);
		}
	}
}

int
dhd_packet_filter_add_remove(dhd_pub_t *dhdp, int add_remove, int num)
{
	char *filterp = NULL;
	int filter_id = 0;

	switch (num) {
		case DHD_BROADCAST_FILTER_NUM:
			filterp = "101 0 0 0 0xFFFFFFFFFFFF 0xFFFFFFFFFFFF";
			filter_id = 101;
			break;
		case DHD_MULTICAST4_FILTER_NUM:
			filter_id = 102;
			if (FW_SUPPORTED((dhdp), pf6)) {
				if (dhdp->pktfilter[num] != NULL) {
					dhd_pktfilter_offload_delete(dhdp, filter_id);
					dhdp->pktfilter[num] = NULL;
				}
				if (!add_remove) {
					filterp = DISCARD_IPV4_MCAST;
					add_remove = 1;
					break;
				}
			}
			filterp = "102 0 0 0 0xFFFFFF 0x01005E";
			break;
		case DHD_MULTICAST6_FILTER_NUM:
			filter_id = 103;
			if (FW_SUPPORTED((dhdp), pf6)) {
				if (dhdp->pktfilter[num] != NULL) {
					dhd_pktfilter_offload_delete(dhdp, filter_id);
					dhdp->pktfilter[num] = NULL;
				}
				if (!add_remove) {
					filterp = DISCARD_IPV6_MCAST;
					add_remove = 1;
					break;
				}
			}
			filterp = "103 0 0 0 0xFFFF 0x3333";
			break;
		case DHD_MDNS_FILTER_NUM:
			filterp = "104 0 0 0 0xFFFFFFFFFFFF 0x01005E0000FB";
			filter_id = 104;
			break;
		case DHD_ARP_FILTER_NUM:
			filterp = "105 0 0 12 0xFFFF 0x0806";
			filter_id = 105;
			break;
		case DHD_BROADCAST_ARP_FILTER_NUM:
			filterp = "106 0 0 0 0xFFFFFFFFFFFF0000000000000806"
				" 0xFFFFFFFFFFFF0000000000000806";
			filter_id = 106;
			break;
		default:
			return -EINVAL;
	}

	/* Add filter */
	if (add_remove) {
		dhdp->pktfilter[num] = filterp;
		dhd_pktfilter_offload_set(dhdp, dhdp->pktfilter[num]);
	} else { /* Delete filter */
		if (dhdp->pktfilter[num]) {
			dhd_pktfilter_offload_delete(dhdp, filter_id);
			dhdp->pktfilter[num] = NULL;
		}
	}

	return 0;
}
#endif /* PKT_FILTER_SUPPORT */

static int dhd_set_suspend(int value, dhd_pub_t *dhd)
{
#ifndef SUPPORT_PM2_ONLY
	int power_mode = PM_MAX;
#endif /* SUPPORT_PM2_ONLY */
	/* wl_pkt_filter_enable_t	enable_parm; */
	int bcn_li_dtim = 0; /* Default bcn_li_dtim in resume mode is 0 */
	int ret = 0;
#ifdef DHD_USE_EARLYSUSPEND
#ifdef CUSTOM_BCN_TIMEOUT_IN_SUSPEND
	int bcn_timeout = 0;
#endif /* CUSTOM_BCN_TIMEOUT_IN_SUSPEND */
#ifdef CUSTOM_ROAM_TIME_THRESH_IN_SUSPEND
	int roam_time_thresh = 0;   /* (ms) */
#endif /* CUSTOM_ROAM_TIME_THRESH_IN_SUSPEND */
#ifndef ENABLE_FW_ROAM_SUSPEND
	uint roamvar = 1;
#endif /* ENABLE_FW_ROAM_SUSPEND */
#ifdef ENABLE_BCN_LI_BCN_WAKEUP
	int bcn_li_bcn = 1;
#endif /* ENABLE_BCN_LI_BCN_WAKEUP */
	uint nd_ra_filter = 0;
#ifdef ENABLE_IPMCAST_FILTER
	int ipmcast_l2filter;
#endif /* ENABLE_IPMCAST_FILTER */
#ifdef CUSTOM_EVENT_PM_WAKE
	uint32 pm_awake_thresh = CUSTOM_EVENT_PM_WAKE;
#endif /* CUSTOM_EVENT_PM_WAKE */
#endif /* DHD_USE_EARLYSUSPEND */
#ifdef PASS_ALL_MCAST_PKTS
	struct dhd_info *dhdinfo;
	uint32 allmulti;
	uint i;
#endif /* PASS_ALL_MCAST_PKTS */
#ifdef DYNAMIC_SWOOB_DURATION
#ifndef CUSTOM_INTR_WIDTH
#define CUSTOM_INTR_WIDTH 100
	int intr_width = 0;
#endif /* CUSTOM_INTR_WIDTH */
#endif /* DYNAMIC_SWOOB_DURATION */

#if defined(BCMPCIE)
	int lpas = 0;
	int dtim_period = 0;
	int bcn_interval = 0;
	int bcn_to_dly = 0;
#if defined(CUSTOM_BCN_TIMEOUT_IN_SUSPEND) && defined(DHD_USE_EARLYSUSPEND)
	bcn_timeout = CUSTOM_BCN_TIMEOUT_SETTING;
#else
	int bcn_timeout = CUSTOM_BCN_TIMEOUT_SETTING;
#endif /* CUSTOM_BCN_TIMEOUT_IN_SUSPEND && DHD_USE_EARLYSUSPEND */
#endif /* OEM_ANDROID && BCMPCIE */

	if (!dhd)
		return -ENODEV;

#ifdef PASS_ALL_MCAST_PKTS
	dhdinfo = dhd->info;
#endif /* PASS_ALL_MCAST_PKTS */

	DHD_TRACE(("%s: enter, value = %d in_suspend=%d\n",
		__FUNCTION__, value, dhd->in_suspend));

	dhd_suspend_lock(dhd);

#ifdef CUSTOM_SET_CPUCORE
	DHD_TRACE(("%s set cpucore(suspend%d)\n", __FUNCTION__, value));
	/* set specific cpucore */
	dhd_set_cpucore(dhd, TRUE);
#endif /* CUSTOM_SET_CPUCORE */
	if (dhd->up) {
		if (value && dhd->in_suspend) {
			dhd->early_suspended = 1;
			/* Kernel suspended */
			DHD_ERROR(("%s: force extra Suspend setting\n", __FUNCTION__));

#ifndef SUPPORT_PM2_ONLY
			dhd_wl_ioctl_cmd(dhd, WLC_SET_PM, (char *)&power_mode,
				sizeof(power_mode), TRUE, 0);
#endif /* SUPPORT_PM2_ONLY */

#ifdef PKT_FILTER_SUPPORT
			/* Enable packet filter,
			 * only allow unicast packet to send up
			 */
			dhd_enable_packet_filter(1, dhd);
#ifdef APF
			dhd_dev_apf_enable_filter(dhd_linux_get_primary_netdev(dhd));
#endif /* APF */
#endif /* PKT_FILTER_SUPPORT */
#ifdef ARP_OFFLOAD_SUPPORT
				dhd_arp_offload_enable(dhd, TRUE);
#endif /* ARP_OFFLOAD_SUPPORT */

#ifdef PASS_ALL_MCAST_PKTS
			allmulti = 0;
			for (i = 0; i < DHD_MAX_IFS; i++) {
				if (dhdinfo->iflist[i] && dhdinfo->iflist[i]->net)
					ret = dhd_iovar(dhd, i, "allmulti", (char *)&allmulti,
							sizeof(allmulti), NULL, 0, TRUE);
				if (ret < 0) {
					DHD_ERROR(("%s allmulti failed %d\n", __FUNCTION__, ret));
				}
			}
#endif /* PASS_ALL_MCAST_PKTS */

			/* If DTIM skip is set up as default, force it to wake
			 * each third DTIM for better power savings.  Note that
			 * one side effect is a chance to miss BC/MC packet.
			 */
#ifdef WLTDLS
			/* Do not set bcn_li_ditm on WFD mode */
			if (dhd->tdls_mode) {
				bcn_li_dtim = 0;
			} else
#endif /* WLTDLS */
#if defined(BCMPCIE)
			bcn_li_dtim = dhd_get_suspend_bcn_li_dtim(dhd, &dtim_period,
				&bcn_interval);
			ret = dhd_iovar(dhd, 0, "bcn_li_dtim", (char *)&bcn_li_dtim,
					sizeof(bcn_li_dtim), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s bcn_li_dtim failed %d\n", __FUNCTION__, ret));
			}
			if ((bcn_li_dtim * dtim_period * bcn_interval) >=
				MIN_DTIM_FOR_ROAM_THRES_EXTEND) {
				/*
				 * Increase max roaming threshold from 2 secs to 8 secs
				 * the real roam threshold is MIN(max_roam_threshold,
				 * bcn_timeout/2)
				 */
				lpas = 1;
				ret = dhd_iovar(dhd, 0, "lpas", (char *)&lpas, sizeof(lpas),
						NULL, 0, TRUE);
				if (ret < 0) {
					DHD_ERROR(("%s lpas failed %d\n", __FUNCTION__, ret));
				}
				bcn_to_dly = 1;
				/*
				 * if bcn_to_dly is 1, the real roam threshold is
				 * MIN(max_roam_threshold, bcn_timeout -1);
				 * notify link down event after roaming procedure complete
				 * if we hit bcn_timeout while we are in roaming progress.
				 */
				ret = dhd_iovar(dhd, 0, "bcn_to_dly", (char *)&bcn_to_dly,
						sizeof(bcn_to_dly), NULL, 0, TRUE);
				if (ret < 0) {
					DHD_ERROR(("%s bcn_to_dly failed %d\n", __FUNCTION__, ret));
				}
				/* Increase beacon timeout to 6 secs or use bigger one */
				bcn_timeout = max(bcn_timeout, BCN_TIMEOUT_IN_SUSPEND);
				ret = dhd_iovar(dhd, 0, "bcn_timeout", (char *)&bcn_timeout,
						sizeof(bcn_timeout), NULL, 0, TRUE);
				if (ret < 0) {
					DHD_ERROR(("%s bcn_timeout failed %d\n", __FUNCTION__, ret));
				}
			}
#else
			bcn_li_dtim = dhd_get_suspend_bcn_li_dtim(dhd);
			if (dhd_iovar(dhd, 0, "bcn_li_dtim", (char *)&bcn_li_dtim,
					sizeof(bcn_li_dtim), NULL, 0, TRUE) < 0)
				DHD_ERROR(("%s: set dtim failed\n", __FUNCTION__));
#endif /* OEM_ANDROID && BCMPCIE */
#ifdef WL_CFG80211
			/* Disable cfg80211 feature events during suspend */
			ret = wl_cfg80211_config_suspend_events(
				dhd_linux_get_primary_netdev(dhd), FALSE);
			if (ret < 0) {
				DHD_ERROR(("failed to disable events (%d)\n", ret));
			}
#endif /* WL_CFG80211 */
#ifdef DHD_USE_EARLYSUSPEND
#ifdef CUSTOM_BCN_TIMEOUT_IN_SUSPEND
			bcn_timeout = CUSTOM_BCN_TIMEOUT_IN_SUSPEND;
			ret = dhd_iovar(dhd, 0, "bcn_timeout", (char *)&bcn_timeout,
					sizeof(bcn_timeout), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s bcn_timeout failed %d\n", __FUNCTION__, ret));
			}
#endif /* CUSTOM_BCN_TIMEOUT_IN_SUSPEND */
#ifdef CUSTOM_ROAM_TIME_THRESH_IN_SUSPEND
			roam_time_thresh = CUSTOM_ROAM_TIME_THRESH_IN_SUSPEND;
			ret = dhd_iovar(dhd, 0, "roam_time_thresh", (char *)&roam_time_thresh,
					sizeof(roam_time_thresh), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s roam_time_thresh failed %d\n", __FUNCTION__, ret));
			}
#endif /* CUSTOM_ROAM_TIME_THRESH_IN_SUSPEND */
#ifndef ENABLE_FW_ROAM_SUSPEND
			/* Disable firmware roaming during suspend */
			ret = dhd_iovar(dhd, 0, "roam_off", (char *)&roamvar,
					sizeof(roamvar), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s roam_off failed %d\n", __FUNCTION__, ret));
			}
#endif /* ENABLE_FW_ROAM_SUSPEND */
#ifdef ENABLE_BCN_LI_BCN_WAKEUP
			if (bcn_li_dtim) {
				bcn_li_bcn = 0;
			}
			ret = dhd_iovar(dhd, 0, "bcn_li_bcn", (char *)&bcn_li_bcn,
					sizeof(bcn_li_bcn), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s bcn_li_bcn failed %d\n", __FUNCTION__, ret));
			}
#endif /* ENABLE_BCN_LI_BCN_WAKEUP */
#if defined(WL_CFG80211) && defined(WL_BCNRECV)
			ret = wl_android_bcnrecv_suspend(dhd_linux_get_primary_netdev(dhd));
			if (ret != BCME_OK) {
				DHD_ERROR(("failed to stop beacon recv event on"
					" suspend state (%d)\n", ret));
			}
#endif /* WL_CFG80211 && WL_BCNRECV */
#ifdef NDO_CONFIG_SUPPORT
			if (dhd->ndo_enable) {
				if (!dhd->ndo_host_ip_overflow) {
					/* enable ND offload on suspend */
					ret = dhd_ndo_enable(dhd, TRUE);
					if (ret < 0) {
						DHD_ERROR(("%s: failed to enable NDO\n",
							__FUNCTION__));
					}
				} else {
					DHD_INFO(("%s: NDO disabled on suspend due to"
							"HW capacity\n", __FUNCTION__));
				}
			}
#endif /* NDO_CONFIG_SUPPORT */
#ifndef APF
			if (FW_SUPPORTED(dhd, ndoe))
#else
			if (FW_SUPPORTED(dhd, ndoe) && !FW_SUPPORTED(dhd, apf))
#endif /* APF */
			{
				/* enable IPv6 RA filter in  firmware during suspend */
				nd_ra_filter = 1;
				ret = dhd_iovar(dhd, 0, "nd_ra_filter_enable",
						(char *)&nd_ra_filter, sizeof(nd_ra_filter),
						NULL, 0, TRUE);
				if (ret < 0)
					DHD_ERROR(("failed to set nd_ra_filter (%d)\n",
						ret));
			}
			dhd_os_suppress_logging(dhd, TRUE);
#ifdef ENABLE_IPMCAST_FILTER
			ipmcast_l2filter = 1;
			ret = dhd_iovar(dhd, 0, "ipmcast_l2filter",
					(char *)&ipmcast_l2filter, sizeof(ipmcast_l2filter),
					NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("failed to set ipmcast_l2filter (%d)\n", ret));
			}
#endif /* ENABLE_IPMCAST_FILTER */
#ifdef DYNAMIC_SWOOB_DURATION
			intr_width = CUSTOM_INTR_WIDTH;
			ret = dhd_iovar(dhd, 0, "bus:intr_width", (char *)&intr_width,
					sizeof(intr_width), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("failed to set intr_width (%d)\n", ret));
			}
#endif /* DYNAMIC_SWOOB_DURATION */
#ifdef CUSTOM_EVENT_PM_WAKE
			pm_awake_thresh = CUSTOM_EVENT_PM_WAKE * 4;
			ret = dhd_iovar(dhd, 0, "const_awake_thresh",
				(char *)&pm_awake_thresh,
				sizeof(pm_awake_thresh), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s set const_awake_thresh failed %d\n",
					__FUNCTION__, ret));
			}
#endif /* CUSTOM_EVENT_PM_WAKE */
#ifdef CONFIG_SILENT_ROAM
			if (!dhd->sroamed) {
				ret = dhd_sroam_set_mon(dhd, TRUE);
				if (ret < 0) {
					DHD_ERROR(("%s set sroam failed %d\n",
						__FUNCTION__, ret));
				}
			}
			dhd->sroamed = FALSE;
#endif /* CONFIG_SILENT_ROAM */
#endif /* DHD_USE_EARLYSUSPEND */
		} else {
			dhd->early_suspended = 0;
			/* Kernel resumed  */
			DHD_ERROR(("%s: Remove extra suspend setting \n", __FUNCTION__));
#ifdef DYNAMIC_SWOOB_DURATION
			intr_width = 0;
			ret = dhd_iovar(dhd, 0, "bus:intr_width", (char *)&intr_width,
					sizeof(intr_width), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("failed to set intr_width (%d)\n", ret));
			}
#endif /* DYNAMIC_SWOOB_DURATION */
#ifndef SUPPORT_PM2_ONLY
			power_mode = PM_FAST;
			dhd_wl_ioctl_cmd(dhd, WLC_SET_PM, (char *)&power_mode,
				sizeof(power_mode), TRUE, 0);
#endif /* SUPPORT_PM2_ONLY */
#if defined(WL_CFG80211) && defined(WL_BCNRECV)
			ret = wl_android_bcnrecv_resume(dhd_linux_get_primary_netdev(dhd));
			if (ret != BCME_OK) {
				DHD_ERROR(("failed to resume beacon recv state (%d)\n",
						ret));
			}
#endif /* WL_CF80211 && WL_BCNRECV */
#ifdef ARP_OFFLOAD_SUPPORT
				dhd_arp_offload_enable(dhd, FALSE);
#endif /* ARP_OFFLOAD_SUPPORT */
#ifdef PKT_FILTER_SUPPORT
			/* disable pkt filter */
			dhd_enable_packet_filter(0, dhd);
#ifdef APF
			dhd_dev_apf_disable_filter(dhd_linux_get_primary_netdev(dhd));
#endif /* APF */
#endif /* PKT_FILTER_SUPPORT */
#ifdef PASS_ALL_MCAST_PKTS
			allmulti = 1;
			for (i = 0; i < DHD_MAX_IFS; i++) {
				if (dhdinfo->iflist[i] && dhdinfo->iflist[i]->net)
					ret = dhd_iovar(dhd, i, "allmulti", (char *)&allmulti,
							sizeof(allmulti), NULL, 0, TRUE);
				if (ret < 0) {
					DHD_ERROR(("%s: allmulti failed:%d\n", __FUNCTION__, ret));
				}
			}
#endif /* PASS_ALL_MCAST_PKTS */
#if defined(BCMPCIE)
			/* restore pre-suspend setting */
			ret = dhd_iovar(dhd, 0, "bcn_li_dtim", (char *)&bcn_li_dtim,
					sizeof(bcn_li_dtim), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s:bcn_li_ditm failed:%d\n", __FUNCTION__, ret));
			}
			ret = dhd_iovar(dhd, 0, "lpas", (char *)&lpas, sizeof(lpas), NULL,
					0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s:lpas failed:%d\n", __FUNCTION__, ret));
			}
			ret = dhd_iovar(dhd, 0, "bcn_to_dly", (char *)&bcn_to_dly,
					sizeof(bcn_to_dly), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s:bcn_to_dly failed:%d\n", __FUNCTION__, ret));
			}
			ret = dhd_iovar(dhd, 0, "bcn_timeout", (char *)&bcn_timeout,
					sizeof(bcn_timeout), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s:bcn_timeout failed:%d\n", __FUNCTION__, ret));
			}
#else
			/* restore pre-suspend setting for dtim_skip */
			ret = dhd_iovar(dhd, 0, "bcn_li_dtim", (char *)&bcn_li_dtim,
					sizeof(bcn_li_dtim), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s:bcn_li_ditm fail:%d\n", __FUNCTION__, ret));
			}
#endif /* OEM_ANDROID && BCMPCIE */
#ifdef DHD_USE_EARLYSUSPEND
#ifdef CUSTOM_BCN_TIMEOUT_IN_SUSPEND
			bcn_timeout = CUSTOM_BCN_TIMEOUT;
			ret = dhd_iovar(dhd, 0, "bcn_timeout", (char *)&bcn_timeout,
					sizeof(bcn_timeout), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s:bcn_timeout failed:%d\n", __FUNCTION__, ret));
			}
#endif /* CUSTOM_BCN_TIMEOUT_IN_SUSPEND */
#ifdef CUSTOM_ROAM_TIME_THRESH_IN_SUSPEND
			roam_time_thresh = 2000;
			ret = dhd_iovar(dhd, 0, "roam_time_thresh", (char *)&roam_time_thresh,
					sizeof(roam_time_thresh), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s:roam_time_thresh failed:%d\n", __FUNCTION__, ret));
			}

#endif /* CUSTOM_ROAM_TIME_THRESH_IN_SUSPEND */
#ifndef ENABLE_FW_ROAM_SUSPEND
			roamvar = dhd_roam_disable;
			ret = dhd_iovar(dhd, 0, "roam_off", (char *)&roamvar,
					sizeof(roamvar), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s: roam_off fail:%d\n", __FUNCTION__, ret));
			}
#endif /* ENABLE_FW_ROAM_SUSPEND */
#ifdef ENABLE_BCN_LI_BCN_WAKEUP
			ret = dhd_iovar(dhd, 0, "bcn_li_bcn", (char *)&bcn_li_bcn,
					sizeof(bcn_li_bcn), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s: bcn_li_bcn failed:%d\n", __FUNCTION__, ret));
			}
#endif /* ENABLE_BCN_LI_BCN_WAKEUP */
#ifdef NDO_CONFIG_SUPPORT
			if (dhd->ndo_enable) {
				/* Disable ND offload on resume */
				ret = dhd_ndo_enable(dhd, FALSE);
				if (ret < 0) {
					DHD_ERROR(("%s: failed to disable NDO\n",
						__FUNCTION__));
				}
			}
#endif /* NDO_CONFIG_SUPPORT */
#ifndef APF
			if (FW_SUPPORTED(dhd, ndoe))
#else
			if (FW_SUPPORTED(dhd, ndoe) && !FW_SUPPORTED(dhd, apf))
#endif /* APF */
			{
				/* disable IPv6 RA filter in  firmware during suspend */
				nd_ra_filter = 0;
				ret = dhd_iovar(dhd, 0, "nd_ra_filter_enable",
						(char *)&nd_ra_filter, sizeof(nd_ra_filter),
						NULL, 0, TRUE);
				if (ret < 0) {
					DHD_ERROR(("failed to set nd_ra_filter (%d)\n",
						ret));
				}
			}
			dhd_os_suppress_logging(dhd, FALSE);
#ifdef ENABLE_IPMCAST_FILTER
			ipmcast_l2filter = 0;
			ret = dhd_iovar(dhd, 0, "ipmcast_l2filter",
					(char *)&ipmcast_l2filter, sizeof(ipmcast_l2filter),
					NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("failed to clear ipmcast_l2filter ret:%d", ret));
			}
#endif /* ENABLE_IPMCAST_FILTER */
#ifdef CUSTOM_EVENT_PM_WAKE
			ret = dhd_iovar(dhd, 0, "const_awake_thresh",
				(char *)&pm_awake_thresh,
				sizeof(pm_awake_thresh), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s set const_awake_thresh failed %d\n",
					__FUNCTION__, ret));
			}
#endif /* CUSTOM_EVENT_PM_WAKE */
#ifdef CONFIG_SILENT_ROAM
			ret = dhd_sroam_set_mon(dhd, FALSE);
			if (ret < 0) {
				DHD_ERROR(("%s set sroam failed %d\n", __FUNCTION__, ret));
			}
#endif /* CONFIG_SILENT_ROAM */
#endif /* DHD_USE_EARLYSUSPEND */
#ifdef WL_CFG80211
			/* Enable cfg80211 feature events during resume */
			ret = wl_cfg80211_config_suspend_events(
				dhd_linux_get_primary_netdev(dhd), TRUE);
			if (ret < 0) {
				DHD_ERROR(("failed to enable events (%d)\n", ret));
			}
#endif /* WL_CFG80211 */
#ifdef DHD_LB_IRQSET
			dhd_irq_set_affinity(dhd, dhd->info->cpumask_primary);
#endif /* DHD_LB_IRQSET */
		}
	}
	dhd_suspend_unlock(dhd);

	return 0;
}

static int dhd_suspend_resume_helper(struct dhd_info *dhd, int val, int force)
{
	dhd_pub_t *dhdp = &dhd->pub;
	int ret = 0;

	DHD_OS_WAKE_LOCK(dhdp);
	DHD_PERIM_LOCK(dhdp);

	/* Set flag when early suspend was called */
	dhdp->in_suspend = val;
	if ((force || !dhdp->suspend_disable_flag) &&
		(dhd_support_sta_mode(dhdp) || dhd_conf_get_insuspend(dhdp, ALL_IN_SUSPEND)))
	{
		ret = dhd_set_suspend(val, dhdp);
	}

	DHD_PERIM_UNLOCK(dhdp);
	DHD_OS_WAKE_UNLOCK(dhdp);
	return ret;
}

#if defined(CONFIG_HAS_EARLYSUSPEND) && defined(DHD_USE_EARLYSUSPEND)
static void dhd_early_suspend(struct early_suspend *h)
{
	struct dhd_info *dhd = container_of(h, struct dhd_info, early_suspend);
	DHD_TRACE_HW4(("%s: enter\n", __FUNCTION__));

	if (dhd && (dhd->pub.conf->suspend_mode == EARLY_SUSPEND ||
			dhd->pub.conf->suspend_mode == SUSPEND_MODE_2)) {
		dhd_suspend_resume_helper(dhd, 1, 0);
		if (dhd->pub.conf->suspend_mode == EARLY_SUSPEND)
			dhd_conf_set_suspend_resume(&dhd->pub, 1);
	}
}

static void dhd_late_resume(struct early_suspend *h)
{
	struct dhd_info *dhd = container_of(h, struct dhd_info, early_suspend);
	DHD_TRACE_HW4(("%s: enter\n", __FUNCTION__));

	if (dhd && (dhd->pub.conf->suspend_mode == EARLY_SUSPEND ||
			dhd->pub.conf->suspend_mode == SUSPEND_MODE_2)) {
		dhd_conf_set_suspend_resume(&dhd->pub, 0);
		if (dhd->pub.conf->suspend_mode == EARLY_SUSPEND)
			dhd_suspend_resume_helper(dhd, 0, 0);
	}
}
#endif /* CONFIG_HAS_EARLYSUSPEND && DHD_USE_EARLYSUSPEND */

/*
 * Generalized timeout mechanism.  Uses spin sleep with exponential back-off until
 * the sleep time reaches one jiffy, then switches over to task delay.  Usage:
 *
 *      dhd_timeout_start(&tmo, usec);
 *      while (!dhd_timeout_expired(&tmo))
 *              if (poll_something())
 *                      break;
 *      if (dhd_timeout_expired(&tmo))
 *              fatal();
 */

void
dhd_timeout_start(dhd_timeout_t *tmo, uint usec)
{
	tmo->limit = usec;
	tmo->increment = 0;
	tmo->elapsed = 0;
	tmo->tick = jiffies_to_usecs(1);
}

int
dhd_timeout_expired(dhd_timeout_t *tmo)
{
	/* Does nothing the first call */
	if (tmo->increment == 0) {
		tmo->increment = 1;
		return 0;
	}

	if (tmo->elapsed >= tmo->limit)
		return 1;

	/* Add the delay that's about to take place */
	tmo->elapsed += tmo->increment;

	if ((!CAN_SLEEP()) || tmo->increment < tmo->tick) {
		OSL_DELAY(tmo->increment);
		tmo->increment *= 2;
		if (tmo->increment > tmo->tick)
			tmo->increment = tmo->tick;
	} else {
		/*
		 * OSL_SLEEP() is corresponding to usleep_range(). In non-atomic
		 * context where the exact wakeup time is flexible, it would be good
		 * to use usleep_range() instead of udelay(). It takes a few advantages
		 * such as improving responsiveness and reducing power.
		 */
		OSL_SLEEP(jiffies_to_msecs(1));
	}

	return 0;
}

int
dhd_net2idx(dhd_info_t *dhd, struct net_device *net)
{
	int i = 0;

	if (!dhd) {
		DHD_ERROR(("%s : DHD_BAD_IF return\n", __FUNCTION__));
		return DHD_BAD_IF;
	}

	while (i < DHD_MAX_IFS) {
		if (dhd->iflist[i] && dhd->iflist[i]->net && (dhd->iflist[i]->net == net))
			return i;
		i++;
	}

	return DHD_BAD_IF;
}

struct net_device * dhd_idx2net(void *pub, int ifidx)
{
	struct dhd_pub *dhd_pub = (struct dhd_pub *)pub;
	struct dhd_info *dhd_info;

	if (!dhd_pub || ifidx < 0 || ifidx >= DHD_MAX_IFS)
		return NULL;
	dhd_info = dhd_pub->info;
	if (dhd_info && dhd_info->iflist[ifidx])
		return dhd_info->iflist[ifidx]->net;
	return NULL;
}

int
dhd_ifname2idx(dhd_info_t *dhd, char *name)
{
	int i = DHD_MAX_IFS;

	ASSERT(dhd);

	if (name == NULL || *name == '\0')
		return 0;

	while (--i > 0)
		if (dhd->iflist[i] && !strncmp(dhd->iflist[i]->dngl_name, name, IFNAMSIZ))
				break;

	DHD_TRACE(("%s: return idx %d for \"%s\"\n", __FUNCTION__, i, name));

	return i;	/* default - the primary interface */
}

char *
dhd_ifname(dhd_pub_t *dhdp, int ifidx)
{
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;

	ASSERT(dhd);

	if (ifidx < 0 || ifidx >= DHD_MAX_IFS) {
		DHD_ERROR(("%s: ifidx %d out of range\n", __FUNCTION__, ifidx));
		return "<if_bad>";
	}

	if (dhd->iflist[ifidx] == NULL) {
		DHD_ERROR(("%s: null i/f %d\n", __FUNCTION__, ifidx));
		return "<if_null>";
	}

	if (dhd->iflist[ifidx]->net)
		return dhd->iflist[ifidx]->net->name;

	return "<if_none>";
}

uint8 *
dhd_bssidx2bssid(dhd_pub_t *dhdp, int idx)
{
	int i;
	dhd_info_t *dhd = (dhd_info_t *)dhdp;

	ASSERT(dhd);
	for (i = 0; i < DHD_MAX_IFS; i++)
	if (dhd->iflist[i] && dhd->iflist[i]->bssidx == idx)
		return dhd->iflist[i]->mac_addr;

	return NULL;
}

static void
_dhd_set_multicast_list(dhd_info_t *dhd, int ifidx)
{
	struct net_device *dev;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
	struct netdev_hw_addr *ha;
#else
	struct dev_mc_list *mclist;
#endif
	uint32 allmulti, cnt;

	wl_ioctl_t ioc;
	char *buf, *bufp;
	uint buflen;
	int ret;

#ifdef MCAST_LIST_ACCUMULATION
	int i;
	uint32 cnt_iface[DHD_MAX_IFS];
	cnt = 0;
	allmulti = 0;

	for (i = 0; i < DHD_MAX_IFS; i++) {
		if (dhd->iflist[i]) {
			dev = dhd->iflist[i]->net;
			if (!dev)
				continue;
			netif_addr_lock_bh(dev);
			cnt_iface[i] = netdev_mc_count(dev);
			cnt += cnt_iface[i];
			netif_addr_unlock_bh(dev);

			/* Determine initial value of allmulti flag */
			allmulti |= (dev->flags & IFF_ALLMULTI) ? TRUE : FALSE;
		}
	}
#else /* !MCAST_LIST_ACCUMULATION */
	if (!dhd->iflist[ifidx]) {
		DHD_ERROR(("%s : dhd->iflist[%d] was NULL\n", __FUNCTION__, ifidx));
		return;
	}
	dev = dhd->iflist[ifidx]->net;
	if (!dev)
		return;
	netif_addr_lock_bh(dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
	cnt = netdev_mc_count(dev);
#else
	cnt = dev->mc_count;
#endif /* LINUX_VERSION_CODE */

	netif_addr_unlock_bh(dev);

	/* Determine initial value of allmulti flag */
	allmulti = (dev->flags & IFF_ALLMULTI) ? TRUE : FALSE;
#endif /* MCAST_LIST_ACCUMULATION */

#ifdef PASS_ALL_MCAST_PKTS
#ifdef PKT_FILTER_SUPPORT
	if (!dhd->pub.early_suspended)
#endif /* PKT_FILTER_SUPPORT */
		allmulti = TRUE;
#endif /* PASS_ALL_MCAST_PKTS */

	/* Send down the multicast list first. */

	buflen = sizeof("mcast_list") + sizeof(cnt) + (cnt * ETHER_ADDR_LEN);
	if (!(bufp = buf = MALLOC(dhd->pub.osh, buflen))) {
		DHD_ERROR(("%s: out of memory for mcast_list, cnt %d\n",
		           dhd_ifname(&dhd->pub, ifidx), cnt));
		return;
	}

	strncpy(bufp, "mcast_list", buflen - 1);
	bufp[buflen - 1] = '\0';
	bufp += strlen("mcast_list") + 1;

	cnt = htol32(cnt);
	memcpy(bufp, &cnt, sizeof(cnt));
	bufp += sizeof(cnt);

#ifdef MCAST_LIST_ACCUMULATION
	for (i = 0; i < DHD_MAX_IFS; i++) {
		if (dhd->iflist[i]) {
			DHD_TRACE(("_dhd_set_multicast_list: ifidx %d\n", i));
			dev = dhd->iflist[i]->net;

			netif_addr_lock_bh(dev);
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif // endif
			netdev_for_each_mc_addr(ha, dev) {
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic pop
#endif // endif
				if (!cnt_iface[i])
					break;
				memcpy(bufp, ha->addr, ETHER_ADDR_LEN);
				bufp += ETHER_ADDR_LEN;
				DHD_TRACE(("_dhd_set_multicast_list: cnt "
					"%d " MACDBG "\n",
					cnt_iface[i], MAC2STRDBG(ha->addr)));
				cnt_iface[i]--;
			}
			netif_addr_unlock_bh(dev);
		}
	}
#else /* !MCAST_LIST_ACCUMULATION */
	netif_addr_lock_bh(dev);
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif // endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
	netdev_for_each_mc_addr(ha, dev) {
		if (!cnt)
			break;
		memcpy(bufp, ha->addr, ETHER_ADDR_LEN);
		bufp += ETHER_ADDR_LEN;
		cnt--;
	}
#else
	for (mclist = dev->mc_list; (mclist && (cnt > 0));
			cnt--, mclist = mclist->next) {
		memcpy(bufp, (void *)mclist->dmi_addr, ETHER_ADDR_LEN);
		bufp += ETHER_ADDR_LEN;
	}
#endif /* LINUX_VERSION_CODE */
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic pop
#endif // endif
	netif_addr_unlock_bh(dev);
#endif /* MCAST_LIST_ACCUMULATION */

	memset(&ioc, 0, sizeof(ioc));
	ioc.cmd = WLC_SET_VAR;
	ioc.buf = buf;
	ioc.len = buflen;
	ioc.set = TRUE;

	ret = dhd_wl_ioctl(&dhd->pub, ifidx, &ioc, ioc.buf, ioc.len);
	if (ret < 0) {
		DHD_ERROR(("%s: set mcast_list failed, cnt %d\n",
			dhd_ifname(&dhd->pub, ifidx), cnt));
		allmulti = cnt ? TRUE : allmulti;
	}

	MFREE(dhd->pub.osh, buf, buflen);

	/* Now send the allmulti setting.  This is based on the setting in the
	 * net_device flags, but might be modified above to be turned on if we
	 * were trying to set some addresses and dongle rejected it...
	 */

	allmulti = htol32(allmulti);
	ret = dhd_iovar(&dhd->pub, ifidx, "allmulti", (char *)&allmulti,
			sizeof(allmulti), NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s: set allmulti %d failed\n",
		           dhd_ifname(&dhd->pub, ifidx), ltoh32(allmulti)));
	}

	/* Finally, pick up the PROMISC flag as well, like the NIC driver does */

#ifdef MCAST_LIST_ACCUMULATION
	allmulti = 0;
	for (i = 0; i < DHD_MAX_IFS; i++) {
		if (dhd->iflist[i]) {
			dev = dhd->iflist[i]->net;
			allmulti |= (dev->flags & IFF_PROMISC) ? TRUE : FALSE;
		}
	}
#else
	allmulti = (dev->flags & IFF_PROMISC) ? TRUE : FALSE;
#endif /* MCAST_LIST_ACCUMULATION */

	allmulti = htol32(allmulti);

	memset(&ioc, 0, sizeof(ioc));
	ioc.cmd = WLC_SET_PROMISC;
	ioc.buf = &allmulti;
	ioc.len = sizeof(allmulti);
	ioc.set = TRUE;

	ret = dhd_wl_ioctl(&dhd->pub, ifidx, &ioc, ioc.buf, ioc.len);
	if (ret < 0) {
		DHD_ERROR(("%s: set promisc %d failed\n",
		           dhd_ifname(&dhd->pub, ifidx), ltoh32(allmulti)));
	}
}

int
_dhd_set_mac_address(dhd_info_t *dhd, int ifidx, uint8 *addr, bool skip_stop)
{
	int ret;

#ifdef DHD_NOTIFY_MAC_CHANGED
	if (skip_stop) {
		WL_MSG(dhd_ifname(&dhd->pub, ifidx), "close dev for mac changing\n");
		dhd->pub.skip_dhd_stop = TRUE;
		dev_close(dhd->iflist[ifidx]->net);
	}
#endif /* DHD_NOTIFY_MAC_CHANGED */

	ret = dhd_iovar(&dhd->pub, ifidx, "cur_etheraddr", (char *)addr,
			ETHER_ADDR_LEN, NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s: set cur_etheraddr %pM failed ret=%d\n",
			dhd_ifname(&dhd->pub, ifidx), addr, ret));
		goto exit;
	} else {
		memcpy(dhd->iflist[ifidx]->net->dev_addr, addr, ETHER_ADDR_LEN);
		if (ifidx == 0)
			memcpy(dhd->pub.mac.octet, addr, ETHER_ADDR_LEN);
		WL_MSG(dhd_ifname(&dhd->pub, ifidx), "MACID %pM is overwritten\n", addr);
	}

exit:
#ifdef DHD_NOTIFY_MAC_CHANGED
	if (skip_stop) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0))
		dev_open(dhd->iflist[ifidx]->net, NULL);
#else
		dev_open(dhd->iflist[ifidx]->net);
#endif
		dhd->pub.skip_dhd_stop = FALSE;
		WL_MSG(dhd_ifname(&dhd->pub, ifidx), "notify mac changed done\n");
	}
#endif /* DHD_NOTIFY_MAC_CHANGED */

	return ret;
}

#ifdef DHD_PSTA
/* Get psta/psr configuration configuration */
int dhd_get_psta_mode(dhd_pub_t *dhdp)
{
	dhd_info_t *dhd = dhdp->info;
	return (int)dhd->psta_mode;
}
/* Set psta/psr configuration configuration */
int dhd_set_psta_mode(dhd_pub_t *dhdp, uint32 val)
{
	dhd_info_t *dhd = dhdp->info;
	dhd->psta_mode = val;
	return 0;
}
#endif /* DHD_PSTA */

#if (defined(DHD_WET) || defined(DHD_MCAST_REGEN) || defined(DHD_L2_FILTER))
static void
dhd_update_rx_pkt_chainable_state(dhd_pub_t* dhdp, uint32 idx)
{
	dhd_info_t *dhd = dhdp->info;
	dhd_if_t *ifp;

	ASSERT(idx < DHD_MAX_IFS);

	ifp = dhd->iflist[idx];

	if (
#ifdef DHD_L2_FILTER
		(ifp->block_ping) ||
#endif // endif
#ifdef DHD_WET
		(dhd->wet_mode) ||
#endif // endif
#ifdef DHD_MCAST_REGEN
		(ifp->mcast_regen_bss_enable) ||
#endif // endif
		FALSE) {
		ifp->rx_pkt_chainable = FALSE;
	}
}
#endif /* DHD_WET || DHD_MCAST_REGEN || DHD_L2_FILTER */

#ifdef DHD_WET
/* Get wet configuration configuration */
int dhd_get_wet_mode(dhd_pub_t *dhdp)
{
	dhd_info_t *dhd = dhdp->info;
	return (int)dhd->wet_mode;
}

/* Set wet configuration configuration */
int dhd_set_wet_mode(dhd_pub_t *dhdp, uint32 val)
{
	dhd_info_t *dhd = dhdp->info;
	dhd->wet_mode = val;
	dhd_update_rx_pkt_chainable_state(dhdp, 0);
	return 0;
}
#endif /* DHD_WET */

#if defined(WL_CFG80211) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
int32 dhd_role_to_nl80211_iftype(int32 role)
{
	switch (role) {
	case WLC_E_IF_ROLE_STA:
		return NL80211_IFTYPE_STATION;
	case WLC_E_IF_ROLE_AP:
		return NL80211_IFTYPE_AP;
	case WLC_E_IF_ROLE_WDS:
		return NL80211_IFTYPE_WDS;
	case WLC_E_IF_ROLE_P2P_GO:
		return NL80211_IFTYPE_P2P_GO;
	case WLC_E_IF_ROLE_P2P_CLIENT:
		return NL80211_IFTYPE_P2P_CLIENT;
	case WLC_E_IF_ROLE_IBSS:
	case WLC_E_IF_ROLE_NAN:
		return NL80211_IFTYPE_ADHOC;
	default:
		return NL80211_IFTYPE_UNSPECIFIED;
	}
}
#endif /* WL_CFG80211 && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0) */

static void
dhd_ifadd_event_handler(void *handle, void *event_info, u8 event)
{
	dhd_info_t *dhd = handle;
	dhd_if_event_t *if_event = event_info;
	int ifidx, bssidx;
	int ret;
#if defined(WL_CFG80211) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	struct wl_if_event_info info;
#if defined(WLDWDS) && defined(FOURADDR_AUTO_BRG)
	struct net_device *ndev = NULL;
#endif
#else
	struct net_device *ndev;
#endif /* WL_CFG80211 && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0) */

	BCM_REFERENCE(ret);
	if (event != DHD_WQ_WORK_IF_ADD) {
		DHD_ERROR(("%s: unexpected event \n", __FUNCTION__));
		return;
	}

	if (!dhd) {
		DHD_ERROR(("%s: dhd info not available \n", __FUNCTION__));
		return;
	}

	if (!if_event) {
		DHD_ERROR(("%s: event data is null \n", __FUNCTION__));
		return;
	}

	dhd_net_if_lock_local(dhd);
	DHD_OS_WAKE_LOCK(&dhd->pub);
	DHD_PERIM_LOCK(&dhd->pub);

	ifidx = if_event->event.ifidx;
	bssidx = if_event->event.bssidx;
	DHD_TRACE(("%s: registering if with ifidx %d\n", __FUNCTION__, ifidx));

#if defined(WL_CFG80211) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	if (if_event->event.ifidx > 0) {
		u8 *mac_addr;
		bzero(&info, sizeof(info));
		info.ifidx = ifidx;
		info.bssidx = bssidx;
		info.role = if_event->event.role;
		strncpy(info.name, if_event->name, IFNAMSIZ);
		if (is_valid_ether_addr(if_event->mac)) {
			mac_addr = if_event->mac;
		} else {
			mac_addr = NULL;
		}

#ifdef WLEASYMESH
		if ((ndev = wl_cfg80211_post_ifcreate(dhd->pub.info->iflist[0]->net,
			&info, mac_addr, if_event->name, true)) == NULL)
#else
		if (wl_cfg80211_post_ifcreate(dhd->pub.info->iflist[0]->net,
			&info, mac_addr, NULL, true) == NULL)
#endif
		{
			/* Do the post interface create ops */
			DHD_ERROR(("Post ifcreate ops failed. Returning \n"));
			goto done;
		}
	}
#else
	/* This path is for non-android case */
	/* The interface name in host and in event msg are same */
	/* if name in event msg is used to create dongle if list on host */
	ndev = dhd_allocate_if(&dhd->pub, ifidx, if_event->name,
		if_event->mac, bssidx, TRUE, if_event->name);
	if (!ndev) {
		DHD_ERROR(("%s: net device alloc failed  \n", __FUNCTION__));
		goto done;
	}

	DHD_PERIM_UNLOCK(&dhd->pub);
	ret = dhd_register_if(&dhd->pub, ifidx, TRUE);
	DHD_PERIM_LOCK(&dhd->pub);
	if (ret != BCME_OK) {
		DHD_ERROR(("%s: dhd_register_if failed\n", __FUNCTION__));
		dhd_remove_if(&dhd->pub, ifidx, TRUE);
		goto done;
	}
#endif /* WL_CFG80211 && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0) */

#ifndef PCIE_FULL_DONGLE
	/* Turn on AP isolation in the firmware for interfaces operating in AP mode */
	if (FW_SUPPORTED((&dhd->pub), ap) && (if_event->event.role != WLC_E_IF_ROLE_STA)) {
		uint32 var_int =  1;
		ret = dhd_iovar(&dhd->pub, ifidx, "ap_isolate", (char *)&var_int, sizeof(var_int),
				NULL, 0, TRUE);
		if (ret != BCME_OK) {
			DHD_ERROR(("%s: Failed to set ap_isolate to dongle\n", __FUNCTION__));
			dhd_remove_if(&dhd->pub, ifidx, TRUE);
		}
	}
#endif /* PCIE_FULL_DONGLE */

done:
	MFREE(dhd->pub.osh, if_event, sizeof(dhd_if_event_t));
#if defined(WLDWDS) && defined(FOURADDR_AUTO_BRG)
	if (dhd->pub.info->iflist[ifidx]) {
		dhd_bridge_dev_set(dhd, ifidx, ndev);
    }
#endif /* defiend(WLDWDS) && defined(FOURADDR_AUTO_BRG) */

	DHD_PERIM_UNLOCK(&dhd->pub);
	DHD_OS_WAKE_UNLOCK(&dhd->pub);
	dhd_net_if_unlock_local(dhd);
}

static void
dhd_ifdel_event_handler(void *handle, void *event_info, u8 event)
{
	dhd_info_t *dhd = handle;
	int ifidx;
	dhd_if_event_t *if_event = event_info;

	if (event != DHD_WQ_WORK_IF_DEL) {
		DHD_ERROR(("%s: unexpected event \n", __FUNCTION__));
		return;
	}

	if (!dhd) {
		DHD_ERROR(("%s: dhd info not available \n", __FUNCTION__));
		return;
	}

	if (!if_event) {
		DHD_ERROR(("%s: event data is null \n", __FUNCTION__));
		return;
	}

	dhd_net_if_lock_local(dhd);
	DHD_OS_WAKE_LOCK(&dhd->pub);
	DHD_PERIM_LOCK(&dhd->pub);

	ifidx = if_event->event.ifidx;
	DHD_TRACE(("Removing interface with idx %d\n", ifidx));
#if defined(WLDWDS) && defined(FOURADDR_AUTO_BRG)
	if (dhd->pub.info->iflist[ifidx]) {
		dhd_bridge_dev_set(dhd, ifidx, NULL);
    }
#endif /* defiend(WLDWDS) && defined(FOURADDR_AUTO_BRG) */

	DHD_PERIM_UNLOCK(&dhd->pub);
	if (!dhd->pub.info->iflist[ifidx]) {
		/* No matching netdev found */
		DHD_ERROR(("Netdev not found! Do nothing.\n"));
		goto done;
	}
#if defined(WL_CFG80211) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	if (if_event->event.ifidx > 0) {
		/* Do the post interface del ops */
		if (wl_cfg80211_post_ifdel(dhd->pub.info->iflist[ifidx]->net,
				true, if_event->event.ifidx) != 0) {
			DHD_TRACE(("Post ifdel ops failed. Returning \n"));
			goto done;
		}
	}
#else
	/* For non-cfg80211 drivers */
	dhd_remove_if(&dhd->pub, ifidx, TRUE);
#endif /* WL_CFG80211 && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0) */

done:
	DHD_PERIM_LOCK(&dhd->pub);
	MFREE(dhd->pub.osh, if_event, sizeof(dhd_if_event_t));
	DHD_PERIM_UNLOCK(&dhd->pub);
	DHD_OS_WAKE_UNLOCK(&dhd->pub);
	dhd_net_if_unlock_local(dhd);
}

#ifdef DHD_UPDATE_INTF_MAC
static void
dhd_ifupdate_event_handler(void *handle, void *event_info, u8 event)
{
	dhd_info_t *dhd = handle;
	int ifidx;
	dhd_if_event_t *if_event = event_info;

	if (event != DHD_WQ_WORK_IF_UPDATE) {
		DHD_ERROR(("%s: unexpected event \n", __FUNCTION__));
		return;
	}

	if (!dhd) {
		DHD_ERROR(("%s: dhd info not available \n", __FUNCTION__));
		return;
	}

	if (!if_event) {
		DHD_ERROR(("%s: event data is null \n", __FUNCTION__));
		return;
	}

	dhd_net_if_lock_local(dhd);
	DHD_OS_WAKE_LOCK(&dhd->pub);

	ifidx = if_event->event.ifidx;
	DHD_TRACE(("%s: Update interface with idx %d\n", __FUNCTION__, ifidx));

	dhd_op_if_update(&dhd->pub, ifidx);

	MFREE(dhd->pub.osh, if_event, sizeof(dhd_if_event_t));

	DHD_OS_WAKE_UNLOCK(&dhd->pub);
	dhd_net_if_unlock_local(dhd);
}

int dhd_op_if_update(dhd_pub_t *dhdpub, int ifidx)
{
	dhd_info_t *    dhdinfo = NULL;
	dhd_if_t   *    ifp = NULL;
	int             ret = 0;
	char            buf[128];

	if ((NULL==dhdpub)||(NULL==dhdpub->info)) {
		DHD_ERROR(("%s: *** DHD handler is NULL!\n", __FUNCTION__));
		return -1;
	} else {
		dhdinfo = (dhd_info_t *)dhdpub->info;
		ifp = dhdinfo->iflist[ifidx];
		if (NULL==ifp) {
		    DHD_ERROR(("%s: *** ifp handler is NULL!\n", __FUNCTION__));
		    return -2;
		}
	}

	DHD_TRACE(("%s: idx %d\n", __FUNCTION__, ifidx));
	// Get MAC address
	strcpy(buf, "cur_etheraddr");
	ret = dhd_wl_ioctl_cmd(&dhdinfo->pub, WLC_GET_VAR, buf, sizeof(buf), FALSE, ifp->idx);
	if (0>ret) {
		DHD_ERROR(("Failed to upudate the MAC address for itf=%s, ret=%d\n", ifp->name, ret));
		// avoid collision
		dhdinfo->iflist[ifp->idx]->mac_addr[5] += 1;
		// force locally administrate address
		ETHER_SET_LOCALADDR(&dhdinfo->iflist[ifp->idx]->mac_addr);
	} else {
		DHD_EVENT(("Got mac for itf %s, idx %d, MAC=%02X:%02X:%02X:%02X:%02X:%02X\n",
		           ifp->name, ifp->idx,
		           (unsigned char)buf[0], (unsigned char)buf[1], (unsigned char)buf[2],
		           (unsigned char)buf[3], (unsigned char)buf[4], (unsigned char)buf[5]));
		memcpy(dhdinfo->iflist[ifp->idx]->mac_addr, buf, ETHER_ADDR_LEN);
		if (dhdinfo->iflist[ifp->idx]->net) {
		    memcpy(dhdinfo->iflist[ifp->idx]->net->dev_addr, buf, ETHER_ADDR_LEN);
		}
	}

	return ret;
}
#endif /* DHD_UPDATE_INTF_MAC */

static void
dhd_set_mac_addr_handler(void *handle, void *event_info, u8 event)
{
	dhd_info_t *dhd = handle;
	dhd_if_t *ifp = event_info;

	if (event != DHD_WQ_WORK_SET_MAC) {
		DHD_ERROR(("%s: unexpected event \n", __FUNCTION__));
	}

	if (!dhd) {
		DHD_ERROR(("%s: dhd info not available \n", __FUNCTION__));
		return;
	}

	dhd_net_if_lock_local(dhd);
	DHD_OS_WAKE_LOCK(&dhd->pub);
	DHD_PERIM_LOCK(&dhd->pub);

	// terence 20160907: fix for not able to set mac when wlan0 is down
	if (ifp == NULL || !ifp->set_macaddress) {
		goto done;
	}
	if (ifp == NULL || !dhd->pub.up) {
		DHD_ERROR(("%s: interface info not available/down \n", __FUNCTION__));
		goto done;
	}

	ifp->set_macaddress = FALSE;

#ifdef DHD_NOTIFY_MAC_CHANGED
	rtnl_lock();
#endif /* DHD_NOTIFY_MAC_CHANGED */

	if (_dhd_set_mac_address(dhd, ifp->idx, ifp->mac_addr, TRUE) == 0)
		DHD_INFO(("%s: MACID is overwritten\n",	__FUNCTION__));
	else
		DHD_ERROR(("%s: _dhd_set_mac_address() failed\n", __FUNCTION__));

#ifdef DHD_NOTIFY_MAC_CHANGED
	rtnl_unlock();
#endif /* DHD_NOTIFY_MAC_CHANGED */

done:
	DHD_PERIM_UNLOCK(&dhd->pub);
	DHD_OS_WAKE_UNLOCK(&dhd->pub);
	dhd_net_if_unlock_local(dhd);
}

static void
dhd_set_mcast_list_handler(void *handle, void *event_info, u8 event)
{
	dhd_info_t *dhd = handle;
	int ifidx = (int)((long int)event_info);
	dhd_if_t *ifp = NULL;

	if (event != DHD_WQ_WORK_SET_MCAST_LIST) {
		DHD_ERROR(("%s: unexpected event \n", __FUNCTION__));
		return;
	}

	if (!dhd) {
		DHD_ERROR(("%s: dhd info not available \n", __FUNCTION__));
		return;
	}

	dhd_net_if_lock_local(dhd);
	DHD_OS_WAKE_LOCK(&dhd->pub);
	DHD_PERIM_LOCK(&dhd->pub);

	ifp = dhd->iflist[ifidx];

	if (ifp == NULL || !dhd->pub.up) {
		DHD_ERROR(("%s: interface info not available/down \n", __FUNCTION__));
		goto done;
	}

	if (ifp == NULL || !dhd->pub.up) {
		DHD_ERROR(("%s: interface info not available/down \n", __FUNCTION__));
		goto done;
	}

	ifidx = ifp->idx;

#ifdef MCAST_LIST_ACCUMULATION
	ifidx = 0;
#endif /* MCAST_LIST_ACCUMULATION */

	_dhd_set_multicast_list(dhd, ifidx);
	DHD_INFO(("%s: set multicast list for if %d\n", __FUNCTION__, ifidx));

done:
	DHD_PERIM_UNLOCK(&dhd->pub);
	DHD_OS_WAKE_UNLOCK(&dhd->pub);
	dhd_net_if_unlock_local(dhd);
}

static int
dhd_set_mac_address(struct net_device *dev, void *addr)
{
	int ret = 0;

	dhd_info_t *dhd = DHD_DEV_INFO(dev);
	struct sockaddr *sa = (struct sockaddr *)addr;
	int ifidx;
	dhd_if_t *dhdif;

	ifidx = dhd_net2idx(dhd, dev);
	if (ifidx == DHD_BAD_IF)
		return -1;

	dhdif = dhd->iflist[ifidx];

	dhd_net_if_lock_local(dhd);
	memcpy(dhdif->mac_addr, sa->sa_data, ETHER_ADDR_LEN);
	dhdif->set_macaddress = TRUE;
	dhd_net_if_unlock_local(dhd);
	WL_MSG(dev->name, "macaddr = %pM\n", dhdif->mac_addr);
	dhd_deferred_schedule_work(dhd->dhd_deferred_wq, (void *)dhdif, DHD_WQ_WORK_SET_MAC,
		dhd_set_mac_addr_handler, DHD_WQ_WORK_PRIORITY_LOW);
	return ret;
}

static void
dhd_set_multicast_list(struct net_device *dev)
{
	dhd_info_t *dhd = DHD_DEV_INFO(dev);
	int ifidx;

	ifidx = dhd_net2idx(dhd, dev);
	if (ifidx == DHD_BAD_IF)
		return;

	dhd->iflist[ifidx]->set_multicast = TRUE;
	dhd_deferred_schedule_work(dhd->dhd_deferred_wq, (void *)((long int)ifidx),
		DHD_WQ_WORK_SET_MCAST_LIST, dhd_set_mcast_list_handler, DHD_WQ_WORK_PRIORITY_LOW);

	// terence 20160907: fix for not able to set mac when wlan0 is down
	dhd_deferred_schedule_work(dhd->dhd_deferred_wq, (void *)dhd->iflist[ifidx],
		DHD_WQ_WORK_SET_MAC, dhd_set_mac_addr_handler, DHD_WQ_WORK_PRIORITY_LOW);
}

#ifdef DHD_UCODE_DOWNLOAD
/* Get ucode path */
char *
dhd_get_ucode_path(dhd_pub_t *dhdp)
{
	dhd_info_t *dhd = dhdp->info;
	return dhd->uc_path;
}
#endif /* DHD_UCODE_DOWNLOAD */

#ifdef PROP_TXSTATUS
int
dhd_os_wlfc_block(dhd_pub_t *pub)
{
	dhd_info_t *di = (dhd_info_t *)(pub->info);
	ASSERT(di != NULL);
	/* terence 20161229: don't do spin lock if proptx not enabled */
	if (disable_proptx)
		return 1;
#ifdef BCMDBUS
	spin_lock_irqsave(&di->wlfc_spinlock, di->wlfc_lock_flags);
#else
	spin_lock_bh(&di->wlfc_spinlock);
#endif /* BCMDBUS */
	return 1;
}

int
dhd_os_wlfc_unblock(dhd_pub_t *pub)
{
	dhd_info_t *di = (dhd_info_t *)(pub->info);

	ASSERT(di != NULL);
	/* terence 20161229: don't do spin lock if proptx not enabled */
	if (disable_proptx)
		return 1;
#ifdef BCMDBUS
	spin_unlock_irqrestore(&di->wlfc_spinlock, di->wlfc_lock_flags);
#else
	spin_unlock_bh(&di->wlfc_spinlock);
#endif /* BCMDBUS */
	return 1;
}

#endif /* PROP_TXSTATUS */

#if defined(WL_MONITOR) && defined(BCMSDIO)
static void
dhd_rx_mon_pkt_sdio(dhd_pub_t *dhdp, void *pkt, int ifidx);
bool
dhd_monitor_enabled(dhd_pub_t *dhd, int ifidx);
#endif /* WL_MONITOR && BCMSDIO */

/*  This routine do not support Packet chain feature, Currently tested for
 *  proxy arp feature
 */
int dhd_sendup(dhd_pub_t *dhdp, int ifidx, void *p)
{
	struct sk_buff *skb;
	void *skbhead = NULL;
	void *skbprev = NULL;
	dhd_if_t *ifp;
	ASSERT(!PKTISCHAINED(p));
	skb = PKTTONATIVE(dhdp->osh, p);

	ifp = dhdp->info->iflist[ifidx];
	skb->dev = ifp->net;

	skb->protocol = eth_type_trans(skb, skb->dev);

	if (in_interrupt()) {
		bcm_object_trace_opr(skb, BCM_OBJDBG_REMOVE,
			__FUNCTION__, __LINE__);
		netif_rx(skb);
	} else {
		if (dhdp->info->rxthread_enabled) {
			if (!skbhead) {
				skbhead = skb;
			} else {
				PKTSETNEXT(dhdp->osh, skbprev, skb);
			}
			skbprev = skb;
		} else {
			/* If the receive is not processed inside an ISR,
			 * the softirqd must be woken explicitly to service
			 * the NET_RX_SOFTIRQ.	In 2.6 kernels, this is handled
			 * by netif_rx_ni(), but in earlier kernels, we need
			 * to do it manually.
			 */
			bcm_object_trace_opr(skb, BCM_OBJDBG_REMOVE,
				__FUNCTION__, __LINE__);
#if defined(WL_MONITOR) && defined(BCMSDIO)
			if (dhd_monitor_enabled(dhdp, ifidx)) 
				dhd_rx_mon_pkt_sdio(dhdp, skb, ifidx);
			else
#endif /* WL_MONITOR && BCMSDIO */
			netif_rx_ni(skb);
		}
	}

	if (dhdp->info->rxthread_enabled && skbhead)
		dhd_sched_rxf(dhdp, skbhead);

	return BCME_OK;
}

int BCMFASTPATH
__dhd_sendpkt(dhd_pub_t *dhdp, int ifidx, void *pktbuf)
{
	int ret = BCME_OK;
	dhd_info_t *dhd = (dhd_info_t *)(dhdp->info);
	struct ether_header *eh = NULL;
	bool pkt_ether_type_802_1x = FALSE;
	uint8 pkt_flow_prio;

#if defined(DHD_L2_FILTER)
	dhd_if_t *ifp = dhd_get_ifp(dhdp, ifidx);
#endif // endif

	/* Reject if down */
	if (!dhdp->up || (dhdp->busstate == DHD_BUS_DOWN)) {
		/* free the packet here since the caller won't */
		PKTCFREE(dhdp->osh, pktbuf, TRUE);
		return -ENODEV;
	}

#ifdef PCIE_FULL_DONGLE
	if (dhdp->busstate == DHD_BUS_SUSPEND) {
		DHD_ERROR(("%s : pcie is still in suspend state!!\n", __FUNCTION__));
		PKTCFREE(dhdp->osh, pktbuf, TRUE);
		return NETDEV_TX_BUSY;
	}
#endif /* PCIE_FULL_DONGLE */

	/* Reject if pktlen > MAX_MTU_SZ */
	if (PKTLEN(dhdp->osh, pktbuf) > MAX_MTU_SZ) {
		/* free the packet here since the caller won't */
		dhdp->tx_big_packets++;
		PKTCFREE(dhdp->osh, pktbuf, TRUE);
		return BCME_ERROR;
	}

#ifdef DHD_L2_FILTER
	/* if dhcp_unicast is enabled, we need to convert the */
	/* broadcast DHCP ACK/REPLY packets to Unicast. */
	if (ifp->dhcp_unicast) {
	    uint8* mac_addr;
	    uint8* ehptr = NULL;
	    int ret;
	    ret = bcm_l2_filter_get_mac_addr_dhcp_pkt(dhdp->osh, pktbuf, ifidx, &mac_addr);
	    if (ret == BCME_OK) {
		/*  if given mac address having valid entry in sta list
		 *  copy the given mac address, and return with BCME_OK
		*/
		if (dhd_find_sta(dhdp, ifidx, mac_addr)) {
		    ehptr = PKTDATA(dhdp->osh, pktbuf);
		    bcopy(mac_addr, ehptr + ETHER_DEST_OFFSET, ETHER_ADDR_LEN);
		}
	    }
	}

	if (ifp->grat_arp && DHD_IF_ROLE_AP(dhdp, ifidx)) {
	    if (bcm_l2_filter_gratuitous_arp(dhdp->osh, pktbuf) == BCME_OK) {
			PKTCFREE(dhdp->osh, pktbuf, TRUE);
			return BCME_ERROR;
	    }
	}

	if (ifp->parp_enable && DHD_IF_ROLE_AP(dhdp, ifidx)) {
		ret = dhd_l2_filter_pkt_handle(dhdp, ifidx, pktbuf, TRUE);

		/* Drop the packets if l2 filter has processed it already
		 * otherwise continue with the normal path
		 */
		if (ret == BCME_OK) {
			PKTCFREE(dhdp->osh, pktbuf, TRUE);
			return BCME_ERROR;
		}
	}
#endif /* DHD_L2_FILTER */
	/* Update multicast statistic */
	if (PKTLEN(dhdp->osh, pktbuf) >= ETHER_HDR_LEN) {
		uint8 *pktdata = (uint8 *)PKTDATA(dhdp->osh, pktbuf);
		eh = (struct ether_header *)pktdata;

		if (ETHER_ISMULTI(eh->ether_dhost))
			dhdp->tx_multicast++;
		if (ntoh16(eh->ether_type) == ETHER_TYPE_802_1X) {
#ifdef DHD_LOSSLESS_ROAMING
			uint8 prio = (uint8)PKTPRIO(pktbuf);

			/* back up 802.1x's priority */
			dhdp->prio_8021x = prio;
#endif /* DHD_LOSSLESS_ROAMING */
			pkt_ether_type_802_1x = TRUE;
			DBG_EVENT_LOG(dhdp, WIFI_EVENT_DRIVER_EAPOL_FRAME_TRANSMIT_REQUESTED);
			atomic_inc(&dhd->pend_8021x_cnt);
#if defined(WL_CFG80211) && defined(WL_WPS_SYNC)
			wl_handle_wps_states(dhd_idx2net(dhdp, ifidx),
				pktdata, PKTLEN(dhdp->osh, pktbuf), TRUE);
#endif /* WL_CFG80211 && WL_WPS_SYNC */
		}
		dhd_dump_pkt(dhdp, ifidx, pktdata,
			(uint32)PKTLEN(dhdp->osh, pktbuf), TRUE, NULL, NULL);
	} else {
		PKTCFREE(dhdp->osh, pktbuf, TRUE);
		return BCME_ERROR;
	}

	{
		/* Look into the packet and update the packet priority */
#ifndef PKTPRIO_OVERRIDE
		if (PKTPRIO(pktbuf) == 0)
#endif /* !PKTPRIO_OVERRIDE */
		{
#if defined(QOS_MAP_SET)
			pktsetprio_qms(pktbuf, wl_get_up_table(dhdp, ifidx), FALSE);
#else
			pktsetprio(pktbuf, FALSE);
#endif /* QOS_MAP_SET */
		}
#ifndef PKTPRIO_OVERRIDE
		else {
			/* Some protocols like OZMO use priority values from 256..263.
			 * these are magic values to indicate a specific 802.1d priority.
			 * make sure that priority field is in range of 0..7
			 */
			PKTSETPRIO(pktbuf, PKTPRIO(pktbuf) & 0x7);
		}
#endif /* !PKTPRIO_OVERRIDE */
	}

	BCM_REFERENCE(pkt_ether_type_802_1x);
	BCM_REFERENCE(pkt_flow_prio);

#ifdef SUPPORT_SET_TID
	dhd_set_tid_based_on_uid(dhdp, pktbuf);
#endif	/* SUPPORT_SET_TID */

#ifdef PCIE_FULL_DONGLE
	/*
	 * Lkup the per interface hash table, for a matching flowring. If one is not
	 * available, allocate a unique flowid and add a flowring entry.
	 * The found or newly created flowid is placed into the pktbuf's tag.
	 */

#ifdef DHD_LOSSLESS_ROAMING
	/* For LLR override and use flowring with prio 7 for 802.1x packets */
	if (pkt_ether_type_802_1x) {
		pkt_flow_prio = PRIO_8021D_NC;
	} else
#endif /* DHD_LOSSLESS_ROAMING */
	{
		pkt_flow_prio = dhdp->flow_prio_map[(PKTPRIO(pktbuf))];
	}

	ret = dhd_flowid_update(dhdp, ifidx, pkt_flow_prio, pktbuf);
	if (ret != BCME_OK) {
		PKTCFREE(dhd->pub.osh, pktbuf, TRUE);
		return ret;
	}
#endif /* PCIE_FULL_DONGLE */
	/* terence 20150901: Micky add to ajust the 802.1X priority */
	/* Set the 802.1X packet with the highest priority 7 */
	if (dhdp->conf->pktprio8021x >= 0)
		pktset8021xprio(pktbuf, dhdp->conf->pktprio8021x);

#ifdef PROP_TXSTATUS
	if (dhd_wlfc_is_supported(dhdp)) {
		/* store the interface ID */
		DHD_PKTTAG_SETIF(PKTTAG(pktbuf), ifidx);

		/* store destination MAC in the tag as well */
		DHD_PKTTAG_SETDSTN(PKTTAG(pktbuf), eh->ether_dhost);

		/* decide which FIFO this packet belongs to */
		if (ETHER_ISMULTI(eh->ether_dhost))
			/* one additional queue index (highest AC + 1) is used for bc/mc queue */
			DHD_PKTTAG_SETFIFO(PKTTAG(pktbuf), AC_COUNT);
		else
			DHD_PKTTAG_SETFIFO(PKTTAG(pktbuf), WME_PRIO2AC(PKTPRIO(pktbuf)));
	} else
#endif /* PROP_TXSTATUS */
	{
		/* If the protocol uses a data header, apply it */
		dhd_prot_hdrpush(dhdp, ifidx, pktbuf);
	}

	/* Use bus module to send data frame */
#ifdef PROP_TXSTATUS
	{
		if (dhd_wlfc_commit_packets(dhdp, (f_commitpkt_t)dhd_bus_txdata,
			dhdp->bus, pktbuf, TRUE) == WLFC_UNSUPPORTED) {
			/* non-proptxstatus way */
#ifdef BCMPCIE
			ret = dhd_bus_txdata(dhdp->bus, pktbuf, (uint8)ifidx);
#else
			ret = dhd_bus_txdata(dhdp->bus, pktbuf);
#endif /* BCMPCIE */
		}
	}
#else
#ifdef BCMPCIE
	ret = dhd_bus_txdata(dhdp->bus, pktbuf, (uint8)ifidx);
#else
	ret = dhd_bus_txdata(dhdp->bus, pktbuf);
#endif /* BCMPCIE */
#endif /* PROP_TXSTATUS */
#ifdef BCMDBUS
	if (ret)
		PKTCFREE(dhdp->osh, pktbuf, TRUE);
#endif /* BCMDBUS */

	return ret;
}

int BCMFASTPATH
dhd_sendpkt(dhd_pub_t *dhdp, int ifidx, void *pktbuf)
{
	int ret = 0;
	unsigned long flags;
	dhd_if_t *ifp;

	DHD_GENERAL_LOCK(dhdp, flags);
	ifp = dhd_get_ifp(dhdp, ifidx);
	if (!ifp || ifp->del_in_progress) {
		DHD_ERROR(("%s: ifp:%p del_in_progress:%d\n",
			__FUNCTION__, ifp, ifp ? ifp->del_in_progress : 0));
		DHD_GENERAL_UNLOCK(dhdp, flags);
		PKTCFREE(dhdp->osh, pktbuf, TRUE);
		return -ENODEV;
	}
	if (DHD_BUS_CHECK_DOWN_OR_DOWN_IN_PROGRESS(dhdp)) {
		DHD_ERROR(("%s: returning as busstate=%d\n",
			__FUNCTION__, dhdp->busstate));
		DHD_GENERAL_UNLOCK(dhdp, flags);
		PKTCFREE(dhdp->osh, pktbuf, TRUE);
		return -ENODEV;
	}
	DHD_IF_SET_TX_ACTIVE(ifp, DHD_TX_SEND_PKT);
	DHD_BUS_BUSY_SET_IN_SEND_PKT(dhdp);
	DHD_GENERAL_UNLOCK(dhdp, flags);

	DHD_GENERAL_LOCK(dhdp, flags);
	if (DHD_BUS_CHECK_SUSPEND_OR_SUSPEND_IN_PROGRESS(dhdp)) {
		DHD_ERROR(("%s: bus is in suspend(%d) or suspending(0x%x) state!!\n",
			__FUNCTION__, dhdp->busstate, dhdp->dhd_bus_busy_state));
		DHD_BUS_BUSY_CLEAR_IN_SEND_PKT(dhdp);
		DHD_IF_CLR_TX_ACTIVE(ifp, DHD_TX_SEND_PKT);
		dhd_os_tx_completion_wake(dhdp);
		dhd_os_busbusy_wake(dhdp);
		DHD_GENERAL_UNLOCK(dhdp, flags);
		PKTCFREE(dhdp->osh, pktbuf, TRUE);
		return -ENODEV;
	}
	DHD_GENERAL_UNLOCK(dhdp, flags);

	ret = __dhd_sendpkt(dhdp, ifidx, pktbuf);

	DHD_GENERAL_LOCK(dhdp, flags);
	DHD_BUS_BUSY_CLEAR_IN_SEND_PKT(dhdp);
	DHD_IF_CLR_TX_ACTIVE(ifp, DHD_TX_SEND_PKT);
	dhd_os_tx_completion_wake(dhdp);
	dhd_os_busbusy_wake(dhdp);
	DHD_GENERAL_UNLOCK(dhdp, flags);
	return ret;
}

netdev_tx_t BCMFASTPATH
dhd_start_xmit(struct sk_buff *skb, struct net_device *net)
{
	int ret;
	uint datalen;
	void *pktbuf;
	dhd_info_t *dhd = DHD_DEV_INFO(net);
	dhd_if_t *ifp = NULL;
	int ifidx;
	unsigned long flags;
	uint8 htsfdlystat_sz = 0;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (dhd_query_bus_erros(&dhd->pub)) {
		return -ENODEV;
	}

	DHD_GENERAL_LOCK(&dhd->pub, flags);
	DHD_BUS_BUSY_SET_IN_TX(&dhd->pub);
	DHD_GENERAL_UNLOCK(&dhd->pub, flags);

	DHD_GENERAL_LOCK(&dhd->pub, flags);
#ifdef BCMPCIE
	if (DHD_BUS_CHECK_SUSPEND_OR_SUSPEND_IN_PROGRESS(&dhd->pub)) {
		DHD_ERROR(("%s: bus is in suspend(%d) or suspending(0x%x) state!!\n",
			__FUNCTION__, dhd->pub.busstate, dhd->pub.dhd_bus_busy_state));
		DHD_BUS_BUSY_CLEAR_IN_TX(&dhd->pub);
#ifdef PCIE_FULL_DONGLE
		/* Stop tx queues if suspend is in progress */
		if (DHD_BUS_CHECK_ANY_SUSPEND_IN_PROGRESS(&dhd->pub)) {
			dhd_bus_stop_queue(dhd->pub.bus);
		}
#endif /* PCIE_FULL_DONGLE */
		dhd_os_busbusy_wake(&dhd->pub);
		DHD_GENERAL_UNLOCK(&dhd->pub, flags);
		return NETDEV_TX_BUSY;
	}
#else
	if (DHD_BUS_CHECK_SUSPEND_OR_SUSPEND_IN_PROGRESS(&dhd->pub)) {
		DHD_ERROR(("%s: bus is in suspend(%d) or suspending(0x%x) state!!\n",
			__FUNCTION__, dhd->pub.busstate, dhd->pub.dhd_bus_busy_state));
	}
#endif

	DHD_OS_WAKE_LOCK(&dhd->pub);
	DHD_PERIM_LOCK_TRY(DHD_FWDER_UNIT(dhd), lock_taken);

	/* Reject if down */
	if (dhd->pub.hang_was_sent || DHD_BUS_CHECK_DOWN_OR_DOWN_IN_PROGRESS(&dhd->pub)) {
		DHD_ERROR(("%s: xmit rejected pub.up=%d busstate=%d \n",
			__FUNCTION__, dhd->pub.up, dhd->pub.busstate));
		netif_stop_queue(net);
		/* Send Event when bus down detected during data session */
		if (dhd->pub.up && !dhd->pub.hang_was_sent && !DHD_BUS_CHECK_REMOVE(&dhd->pub)) {
			DHD_ERROR(("%s: Event HANG sent up\n", __FUNCTION__));
			dhd->pub.hang_reason = HANG_REASON_BUS_DOWN;
			net_os_send_hang_message(net);
		}
		DHD_BUS_BUSY_CLEAR_IN_TX(&dhd->pub);
		dhd_os_busbusy_wake(&dhd->pub);
		DHD_GENERAL_UNLOCK(&dhd->pub, flags);
		DHD_PERIM_UNLOCK_TRY(DHD_FWDER_UNIT(dhd), lock_taken);
		DHD_OS_WAKE_UNLOCK(&dhd->pub);
		return NETDEV_TX_BUSY;
	}

	ifp = DHD_DEV_IFP(net);
	ifidx = DHD_DEV_IFIDX(net);
	if (!ifp || (ifidx == DHD_BAD_IF) ||
		ifp->del_in_progress) {
		DHD_ERROR(("%s: ifidx %d ifp:%p del_in_progress:%d\n",
		__FUNCTION__, ifidx, ifp, (ifp ? ifp->del_in_progress : 0)));
		netif_stop_queue(net);
		DHD_BUS_BUSY_CLEAR_IN_TX(&dhd->pub);
		dhd_os_busbusy_wake(&dhd->pub);
		DHD_GENERAL_UNLOCK(&dhd->pub, flags);
		DHD_PERIM_UNLOCK_TRY(DHD_FWDER_UNIT(dhd), lock_taken);
		DHD_OS_WAKE_UNLOCK(&dhd->pub);
		return NETDEV_TX_BUSY;
	}

	DHD_IF_SET_TX_ACTIVE(ifp, DHD_TX_START_XMIT);
	DHD_GENERAL_UNLOCK(&dhd->pub, flags);

	ASSERT(ifidx == dhd_net2idx(dhd, net));
	ASSERT((ifp != NULL) && ((ifidx < DHD_MAX_IFS) && (ifp == dhd->iflist[ifidx])));

	bcm_object_trace_opr(skb, BCM_OBJDBG_ADD_PKT, __FUNCTION__, __LINE__);

	/* re-align socket buffer if "skb->data" is odd address */
	if (((unsigned long)(skb->data)) & 0x1) {
		unsigned char *data = skb->data;
		uint32 length = skb->len;
		PKTPUSH(dhd->pub.osh, skb, 1);
		memmove(skb->data, data, length);
		PKTSETLEN(dhd->pub.osh, skb, length);
	}

	datalen  = PKTLEN(dhd->pub.osh, skb);

#ifdef TPUT_MONITOR
	if (dhd->pub.conf->tput_monitor_ms) {
		dhd_os_sdlock_txq(&dhd->pub);
		dhd->pub.conf->net_len += datalen;
		dhd_os_sdunlock_txq(&dhd->pub);
		if ((dhd->pub.conf->data_drop_mode == XMIT_DROP) &&
				(PKTLEN(dhd->pub.osh, skb) > 500)) {
			dev_kfree_skb(skb);
			return NETDEV_TX_OK;
		}
	}
#endif
	/* Make sure there's enough room for any header */
	if (skb_headroom(skb) < dhd->pub.hdrlen + htsfdlystat_sz) {
		struct sk_buff *skb2;

		DHD_INFO(("%s: insufficient headroom\n",
		          dhd_ifname(&dhd->pub, ifidx)));
		dhd->pub.tx_realloc++;

		bcm_object_trace_opr(skb, BCM_OBJDBG_REMOVE, __FUNCTION__, __LINE__);
		skb2 = skb_realloc_headroom(skb, dhd->pub.hdrlen + htsfdlystat_sz);

		dev_kfree_skb(skb);
		if ((skb = skb2) == NULL) {
			DHD_ERROR(("%s: skb_realloc_headroom failed\n",
			           dhd_ifname(&dhd->pub, ifidx)));
			ret = -ENOMEM;
			goto done;
		}
		bcm_object_trace_opr(skb, BCM_OBJDBG_ADD_PKT, __FUNCTION__, __LINE__);
	}

	/* move from dhdsdio_sendfromq(), try to orphan skb early */
	if (dhd->pub.conf->orphan_move == 2)
		PKTORPHAN(skb, dhd->pub.conf->tsq);
	else if (dhd->pub.conf->orphan_move == 3)
		skb_orphan(skb);

	/* Convert to packet */
	if (!(pktbuf = PKTFRMNATIVE(dhd->pub.osh, skb))) {
		DHD_ERROR(("%s: PKTFRMNATIVE failed\n",
		           dhd_ifname(&dhd->pub, ifidx)));
		bcm_object_trace_opr(skb, BCM_OBJDBG_REMOVE, __FUNCTION__, __LINE__);
		dev_kfree_skb_any(skb);
		ret = -ENOMEM;
		goto done;
	}

#ifdef DHD_WET
	/* wet related packet proto manipulation should be done in DHD
	   since dongle doesn't have complete payload
	 */
	if (WET_ENABLED(&dhd->pub) &&
			(dhd_wet_send_proc(dhd->pub.wet_info, pktbuf, &pktbuf) < 0)) {
		DHD_INFO(("%s:%s: wet send proc failed\n",
				__FUNCTION__, dhd_ifname(&dhd->pub, ifidx)));
		PKTFREE(dhd->pub.osh, pktbuf, FALSE);
		ret =  -EFAULT;
		goto done;
	}
#endif /* DHD_WET */

#ifdef DHD_PSTA
	/* PSR related packet proto manipulation should be done in DHD
	 * since dongle doesn't have complete payload
	 */
	if (PSR_ENABLED(&dhd->pub) &&
		(dhd_psta_proc(&dhd->pub, ifidx, &pktbuf, TRUE) < 0)) {

			DHD_ERROR(("%s:%s: psta send proc failed\n", __FUNCTION__,
				dhd_ifname(&dhd->pub, ifidx)));
	}
#endif /* DHD_PSTA */

#ifdef DHDTCPSYNC_FLOOD_BLK
	if (dhd_tcpdata_get_flag(&dhd->pub, pktbuf) == FLAG_SYNCACK) {
		ifp->tsyncack_txed ++;
	}
#endif /* DHDTCPSYNC_FLOOD_BLK */

#ifdef DHDTCPACK_SUPPRESS
	if (dhd->pub.tcpack_sup_mode == TCPACK_SUP_HOLD) {
		/* If this packet has been hold or got freed, just return */
		if (dhd_tcpack_hold(&dhd->pub, pktbuf, ifidx)) {
			ret = 0;
			goto done;
		}
	} else {
		/* If this packet has replaced another packet and got freed, just return */
		if (dhd_tcpack_suppress(&dhd->pub, pktbuf)) {
			ret = 0;
			goto done;
		}
	}
#endif /* DHDTCPACK_SUPPRESS */

	/*
	 * If Load Balance is enabled queue the packet
	 * else send directly from here.
	 */
#if defined(DHD_LB_TXP)
	ret = dhd_lb_sendpkt(dhd, net, ifidx, pktbuf);
#else
	ret = __dhd_sendpkt(&dhd->pub, ifidx, pktbuf);
#endif // endif

done:
	if (ret) {
		ifp->stats.tx_dropped++;
		dhd->pub.tx_dropped++;
	} else {
#ifdef PROP_TXSTATUS
		/* tx_packets counter can counted only when wlfc is disabled */
		if (!dhd_wlfc_is_supported(&dhd->pub))
#endif // endif
		{
			dhd->pub.tx_packets++;
			ifp->stats.tx_packets++;
			ifp->stats.tx_bytes += datalen;
		}
	}

	DHD_GENERAL_LOCK(&dhd->pub, flags);
	DHD_BUS_BUSY_CLEAR_IN_TX(&dhd->pub);
	DHD_IF_CLR_TX_ACTIVE(ifp, DHD_TX_START_XMIT);
	dhd_os_tx_completion_wake(&dhd->pub);
	dhd_os_busbusy_wake(&dhd->pub);
	DHD_GENERAL_UNLOCK(&dhd->pub, flags);
	DHD_PERIM_UNLOCK_TRY(DHD_FWDER_UNIT(dhd), lock_taken);
	DHD_OS_WAKE_UNLOCK(&dhd->pub);
	/* Return ok: we always eat the packet */
	return NETDEV_TX_OK;
}

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
void dhd_rx_wq_wakeup(struct work_struct *ptr)
{
	struct dhd_rx_tx_work *work;
	struct dhd_pub * pub;

	work = container_of(ptr, struct dhd_rx_tx_work, work);

	pub = work->pub;

	DHD_RPM(("%s: ENTER. \n", __FUNCTION__));

	if (atomic_read(&pub->block_bus) || pub->busstate == DHD_BUS_DOWN) {
		return;
	}

	DHD_OS_WAKE_LOCK(pub);
	if (pm_runtime_get_sync(dhd_bus_to_dev(pub->bus)) >= 0) {

		// do nothing but wakeup the bus.
		pm_runtime_mark_last_busy(dhd_bus_to_dev(pub->bus));
		pm_runtime_put_autosuspend(dhd_bus_to_dev(pub->bus));
	}
	DHD_OS_WAKE_UNLOCK(pub);
	kfree(work);
}

void dhd_start_xmit_wq_adapter(struct work_struct *ptr)
{
	struct dhd_rx_tx_work *work;
	netdev_tx_t ret;
	dhd_info_t *dhd;
	struct dhd_bus * bus;

	work = container_of(ptr, struct dhd_rx_tx_work, work);

	dhd = DHD_DEV_INFO(work->net);

	bus = dhd->pub.bus;

	if (atomic_read(&dhd->pub.block_bus)) {
		kfree_skb(work->skb);
		kfree(work);
		dhd_netif_start_queue(bus);
		return;
	}

	if (pm_runtime_get_sync(dhd_bus_to_dev(bus)) >= 0) {
		ret = dhd_start_xmit(work->skb, work->net);
		pm_runtime_mark_last_busy(dhd_bus_to_dev(bus));
		pm_runtime_put_autosuspend(dhd_bus_to_dev(bus));
	}
	kfree(work);
	dhd_netif_start_queue(bus);

	if (ret)
		netdev_err(work->net,
			   "error: dhd_start_xmit():%d\n", ret);
}

netdev_tx_t BCMFASTPATH
dhd_start_xmit_wrapper(struct sk_buff *skb, struct net_device *net)
{
	struct dhd_rx_tx_work *start_xmit_work;
	netdev_tx_t ret;
	dhd_info_t *dhd = DHD_DEV_INFO(net);

	if (dhd->pub.busstate == DHD_BUS_SUSPEND) {
		DHD_RPM(("%s: wakeup the bus using workqueue.\n", __FUNCTION__));

		dhd_netif_stop_queue(dhd->pub.bus);

		start_xmit_work = (struct dhd_rx_tx_work*)
			kmalloc(sizeof(*start_xmit_work), GFP_ATOMIC);

		if (!start_xmit_work) {
			netdev_err(net,
				   "error: failed to alloc start_xmit_work\n");
			ret = -ENOMEM;
			goto exit;
		}

		INIT_WORK(&start_xmit_work->work, dhd_start_xmit_wq_adapter);
		start_xmit_work->skb = skb;
		start_xmit_work->net = net;
		queue_work(dhd->tx_wq, &start_xmit_work->work);
		ret = NET_XMIT_SUCCESS;

	} else if (dhd->pub.busstate == DHD_BUS_DATA) {
		ret = dhd_start_xmit(skb, net);
	} else {
		/* when bus is down */
		ret = -ENODEV;
	}

exit:
	return ret;
}
void
dhd_bus_wakeup_work(dhd_pub_t *dhdp)
{
	struct dhd_rx_tx_work *rx_work;
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;

	rx_work = kmalloc(sizeof(*rx_work), GFP_ATOMIC);
	if (!rx_work) {
		DHD_ERROR(("%s: start_rx_work alloc error. \n", __FUNCTION__));
		return;
	}

	INIT_WORK(&rx_work->work, dhd_rx_wq_wakeup);
	rx_work->pub = dhdp;
	queue_work(dhd->rx_wq, &rx_work->work);

}
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

static void
__dhd_txflowcontrol(dhd_pub_t *dhdp, struct net_device *net, bool state)
{

	if ((state == ON) && (dhdp->txoff == FALSE)) {
		netif_stop_queue(net);
		dhd_prot_update_pktid_txq_stop_cnt(dhdp);
	} else if (state == ON) {
		DHD_INFO(("%s: Netif Queue has already stopped\n", __FUNCTION__));
	}
	if ((state == OFF) && (dhdp->txoff == TRUE)) {
		netif_wake_queue(net);
		dhd_prot_update_pktid_txq_start_cnt(dhdp);
	} else if (state == OFF) {
		DHD_INFO(("%s: Netif Queue has already started\n", __FUNCTION__));
	}
}

void
dhd_txflowcontrol(dhd_pub_t *dhdp, int ifidx, bool state)
{
	struct net_device *net;
	dhd_info_t *dhd = dhdp->info;
	unsigned long flags;
	int i;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	ASSERT(dhd);

#ifdef DHD_LOSSLESS_ROAMING
	/* block flowcontrol during roaming */
	if ((dhdp->dequeue_prec_map == 1 << PRIO_8021D_NC) && state == ON) {
		return;
	}
#endif // endif

	flags = dhd_os_sdlock_txoff(&dhd->pub);
	if (ifidx == ALL_INTERFACES) {
		for (i = 0; i < DHD_MAX_IFS; i++) {
			if (dhd->iflist[i]) {
				net = dhd->iflist[i]->net;
				__dhd_txflowcontrol(dhdp, net, state);
			}
		}
	} else {
		if (dhd->iflist[ifidx]) {
			net = dhd->iflist[ifidx]->net;
			__dhd_txflowcontrol(dhdp, net, state);
		}
	}
	dhdp->txoff = state;
	dhd_os_sdunlock_txoff(&dhd->pub, flags);
}

#ifdef DHD_MCAST_REGEN
/*
 * Description: This function is called to do the reverse translation
 *
 * Input    eh - pointer to the ethernet header
 */
int32
dhd_mcast_reverse_translation(struct ether_header *eh)
{
	uint8 *iph;
	uint32 dest_ip;

	iph = (uint8 *)eh + ETHER_HDR_LEN;
	dest_ip = ntoh32(*((uint32 *)(iph + IPV4_DEST_IP_OFFSET)));

	/* Only IP packets are handled */
	if (eh->ether_type != hton16(ETHER_TYPE_IP))
		return BCME_ERROR;

	/* Non-IPv4 multicast packets are not handled */
	if (IP_VER(iph) != IP_VER_4)
		return BCME_ERROR;

	/*
	 * The packet has a multicast IP and unicast MAC. That means
	 * we have to do the reverse translation
	 */
	if (IPV4_ISMULTI(dest_ip) && !ETHER_ISMULTI(&eh->ether_dhost)) {
		ETHER_FILL_MCAST_ADDR_FROM_IP(eh->ether_dhost, dest_ip);
		return BCME_OK;
	}

	return BCME_ERROR;
}
#endif /* MCAST_REGEN */

#ifdef SHOW_LOGTRACE
static void
dhd_netif_rx_ni(struct sk_buff * skb)
{
	/* Do not call netif_recieve_skb as this workqueue scheduler is
	 * not from NAPI Also as we are not in INTR context, do not call
	 * netif_rx, instead call netif_rx_ni (for kerenl >= 2.6) which
	 * does netif_rx, disables irq, raise NET_IF_RX softirq and
	 * enables interrupts back
	 */
	netif_rx_ni(skb);
}

static int
dhd_event_logtrace_pkt_process(dhd_pub_t *dhdp, struct sk_buff * skb)
{
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;
	int ret = BCME_OK;
	uint datalen;
	bcm_event_msg_u_t evu;
	void *data = NULL;
	void *pktdata = NULL;
	bcm_event_t *pvt_data;
	uint pktlen;

	DHD_TRACE(("%s:Enter\n", __FUNCTION__));

	/* In dhd_rx_frame, header is stripped using skb_pull
	 * of size ETH_HLEN, so adjust pktlen accordingly
	 */
	pktlen = skb->len + ETH_HLEN;

	pktdata = (void *)skb_mac_header(skb);
	ret = wl_host_event_get_data(pktdata, pktlen, &evu);

	if (ret != BCME_OK) {
		DHD_ERROR(("%s: wl_host_event_get_data err = %d\n",
			__FUNCTION__, ret));
		goto exit;
	}

	datalen = ntoh32(evu.event.datalen);

	pvt_data = (bcm_event_t *)pktdata;
	data = &pvt_data[1];

	dhd_dbg_trace_evnt_handler(dhdp, data, &dhd->event_data, datalen);

exit:
	return ret;
}

/*
 * dhd_event_logtrace_process_items processes
 * each skb from evt_trace_queue.
 * Returns TRUE if more packets to be processed
 * else returns FALSE
 */

static int
dhd_event_logtrace_process_items(dhd_info_t *dhd)
{
	dhd_pub_t *dhdp;
	struct sk_buff *skb;
	uint32 qlen;
	uint32 process_len;

	if (!dhd) {
		DHD_ERROR(("%s: dhd info not available \n", __FUNCTION__));
		return 0;
	}

	dhdp = &dhd->pub;

	if (!dhdp) {
		DHD_ERROR(("%s: dhd pub is null \n", __FUNCTION__));
		return 0;
	}

	qlen = skb_queue_len(&dhd->evt_trace_queue);
	process_len = MIN(qlen, DHD_EVENT_LOGTRACE_BOUND);

	/* Run while loop till bound is reached or skb queue is empty */
	while (process_len--) {
		int ifid = 0;
		skb = skb_dequeue(&dhd->evt_trace_queue);
		if (skb == NULL) {
			DHD_ERROR(("%s: skb is NULL, which is not valid case\n",
				__FUNCTION__));
			break;
		}
		BCM_REFERENCE(ifid);
#ifdef PCIE_FULL_DONGLE
		/* Check if pkt is from INFO ring or WLC_E_TRACE */
		ifid = DHD_PKTTAG_IFID((dhd_pkttag_fr_t *)PKTTAG(skb));
		if (ifid == DHD_DUMMY_INFO_IF) {
			/* Process logtrace from info rings */
			dhd_event_logtrace_infobuf_pkt_process(dhdp, skb, &dhd->event_data);
		} else
#endif /* PCIE_FULL_DONGLE */
		{
			/* Processing WLC_E_TRACE case OR non PCIE PCIE_FULL_DONGLE case */
			dhd_event_logtrace_pkt_process(dhdp, skb);
		}

		/* Dummy sleep so that scheduler kicks in after processing any logprints */
		OSL_SLEEP(0);

		/* Send packet up if logtrace_pkt_sendup is TRUE */
		if (dhdp->logtrace_pkt_sendup) {
#ifdef DHD_USE_STATIC_CTRLBUF
			/* If bufs are allocated via static buf pool
			 * and logtrace_pkt_sendup enabled, make a copy,
			 * free the local one and send the copy up.
			 */
			void *npkt = PKTDUP(dhdp->osh, skb);
			/* Clone event and send it up */
			PKTFREE_STATIC(dhdp->osh, skb, FALSE);
			if (npkt) {
				skb = npkt;
			} else {
				DHD_ERROR(("skb clone failed. dropping logtrace pkt.\n"));
				/* Packet is already freed, go to next packet */
				continue;
			}
#endif /* DHD_USE_STATIC_CTRLBUF */
#ifdef PCIE_FULL_DONGLE
			/* For infobuf packets as if is DHD_DUMMY_INFO_IF,
			 * to send skb to network layer, assign skb->dev with
			 * Primary interface n/w device
			 */
			if (ifid == DHD_DUMMY_INFO_IF) {
				skb = PKTTONATIVE(dhdp->osh, skb);
				skb->dev = dhd->iflist[0]->net;
			}
#endif /* PCIE_FULL_DONGLE */
			/* Send pkt UP */
			dhd_netif_rx_ni(skb);
		} else	{
			/* Don't send up. Free up the packet. */
#ifdef DHD_USE_STATIC_CTRLBUF
			PKTFREE_STATIC(dhdp->osh, skb, FALSE);
#else
			PKTFREE(dhdp->osh, skb, FALSE);
#endif /* DHD_USE_STATIC_CTRLBUF */
		}
	}

	/* Reschedule if more packets to be processed */
	return (qlen >= DHD_EVENT_LOGTRACE_BOUND);
}

#ifdef DHD_USE_KTHREAD_FOR_LOGTRACE
static int
dhd_logtrace_thread(void *data)
{
	tsk_ctl_t *tsk = (tsk_ctl_t *)data;
	dhd_info_t *dhd = (dhd_info_t *)tsk->parent;
	dhd_pub_t *dhdp = (dhd_pub_t *)&dhd->pub;
	int ret;

	while (1) {
		dhdp->logtrace_thr_ts.entry_time = OSL_LOCALTIME_NS();
		if (!binary_sema_down(tsk)) {
			dhdp->logtrace_thr_ts.sem_down_time = OSL_LOCALTIME_NS();
			SMP_RD_BARRIER_DEPENDS();
			if (dhd->pub.dongle_reset == FALSE) {
				do {
					/* Check terminated before processing the items */
					if (tsk->terminated) {
						DHD_ERROR(("%s: task terminated\n", __FUNCTION__));
						goto exit;
					}
#ifdef EWP_EDL
					/* check if EDL is being used */
					if (dhd->pub.dongle_edl_support) {
						ret = dhd_prot_process_edl_complete(&dhd->pub,
								&dhd->event_data);
					} else {
						ret = dhd_event_logtrace_process_items(dhd);
					}
#else
					ret = dhd_event_logtrace_process_items(dhd);
#endif /* EWP_EDL */
					/* if ret > 0, bound has reached so to be fair to other
					 * processes need to yield the scheduler.
					 * The comment above yield()'s definition says:
					 * If you want to use yield() to wait for something,
					 * use wait_event().
					 * If you want to use yield() to be 'nice' for others,
					 * use cond_resched().
					 * If you still want to use yield(), do not!
					 */
					if (ret > 0) {
						cond_resched();
						OSL_SLEEP(DHD_EVENT_LOGTRACE_RESCHEDULE_DELAY_MS);
					} else if (ret < 0) {
						DHD_ERROR(("%s: ERROR should not reach here\n",
							__FUNCTION__));
					}
				} while (ret > 0);
			}
			if (tsk->flush_ind) {
				DHD_ERROR(("%s: flushed\n", __FUNCTION__));
				dhdp->logtrace_thr_ts.flush_time = OSL_LOCALTIME_NS();
				tsk->flush_ind = 0;
				complete(&tsk->flushed);
			}
		} else {
			DHD_ERROR(("%s: unexpted break\n", __FUNCTION__));
			dhdp->logtrace_thr_ts.unexpected_break_time = OSL_LOCALTIME_NS();
			break;
		}
	}
exit:
	complete_and_exit(&tsk->completed, 0);
	dhdp->logtrace_thr_ts.complete_time = OSL_LOCALTIME_NS();
}
#else
static void
dhd_event_logtrace_process(struct work_struct * work)
{
	int ret = 0;
/* Ignore compiler warnings due to -Werror=cast-qual */
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif // endif
	struct delayed_work *dw = to_delayed_work(work);
	struct dhd_info *dhd =
		container_of(dw, struct dhd_info, event_log_dispatcher_work);
#if defined(STRICT_GCC_WARNINGS) && defined(__GNUC__)
#pragma GCC diagnostic pop
#endif // endif
#ifdef EWP_EDL
	if (dhd->pub.dongle_edl_support) {
		ret = dhd_prot_process_edl_complete(&dhd->pub, &dhd->event_data);
	} else {
		ret = dhd_event_logtrace_process_items(dhd);
	}
#else
	ret = dhd_event_logtrace_process_items(dhd);
#endif /* EWP_EDL */

	if (ret > 0) {
		schedule_delayed_work(&(dhd)->event_log_dispatcher_work,
			msecs_to_jiffies(DHD_EVENT_LOGTRACE_RESCHEDULE_DELAY_MS));
	}

	return;
}
#endif /* DHD_USE_KTHREAD_FOR_LOGTRACE */

void
dhd_schedule_logtrace(void *dhd_info)
{
	dhd_info_t *dhd = (dhd_info_t *)dhd_info;

#ifdef DHD_USE_KTHREAD_FOR_LOGTRACE
	if (dhd->thr_logtrace_ctl.thr_pid >= 0) {
		binary_sema_up(&dhd->thr_logtrace_ctl);
	} else {
		DHD_ERROR(("%s: thr_logtrace_ctl(%ld) not inited\n", __FUNCTION__,
			dhd->thr_logtrace_ctl.thr_pid));
	}
#else
	schedule_delayed_work(&dhd->event_log_dispatcher_work, 0);
#endif /* DHD_USE_KTHREAD_FOR_LOGTRACE */
	return;
}

void
dhd_cancel_logtrace_process_sync(dhd_info_t *dhd)
{
#ifdef DHD_USE_KTHREAD_FOR_LOGTRACE
	if (dhd->thr_logtrace_ctl.thr_pid >= 0) {
		PROC_STOP_USING_BINARY_SEMA(&dhd->thr_logtrace_ctl);
	} else {
		DHD_ERROR(("%s: thr_logtrace_ctl(%ld) not inited\n", __FUNCTION__,
			dhd->thr_logtrace_ctl.thr_pid));
	}
#else
	cancel_delayed_work_sync(&dhd->event_log_dispatcher_work);
#endif /* DHD_USE_KTHREAD_FOR_LOGTRACE */
}

void
dhd_flush_logtrace_process(dhd_info_t *dhd)
{
#ifdef DHD_USE_KTHREAD_FOR_LOGTRACE
	if (dhd->thr_logtrace_ctl.thr_pid >= 0) {
		PROC_FLUSH_USING_BINARY_SEMA(&dhd->thr_logtrace_ctl);
	} else {
		DHD_ERROR(("%s: thr_logtrace_ctl(%ld) not inited\n", __FUNCTION__,
			dhd->thr_logtrace_ctl.thr_pid));
	}
#else
	flush_delayed_work(&dhd->event_log_dispatcher_work);
#endif /* DHD_USE_KTHREAD_FOR_LOGTRACE */
}

int
dhd_init_logtrace_process(dhd_info_t *dhd)
{
#ifdef DHD_USE_KTHREAD_FOR_LOGTRACE
	dhd->thr_logtrace_ctl.thr_pid = DHD_PID_KT_INVALID;
	PROC_START(dhd_logtrace_thread, dhd, &dhd->thr_logtrace_ctl, 0, "dhd_logtrace_thread");
	if (dhd->thr_logtrace_ctl.thr_pid < 0) {
		DHD_ERROR(("%s: init logtrace process failed\n", __FUNCTION__));
		return BCME_ERROR;
	} else {
		DHD_ERROR(("%s: thr_logtrace_ctl(%ld) succedded\n", __FUNCTION__,
			dhd->thr_logtrace_ctl.thr_pid));
	}
#else
	INIT_DELAYED_WORK(&dhd->event_log_dispatcher_work, dhd_event_logtrace_process);
#endif /* DHD_USE_KTHREAD_FOR_LOGTRACE */
	return BCME_OK;
}

int
dhd_reinit_logtrace_process(dhd_info_t *dhd)
{
#ifdef DHD_USE_KTHREAD_FOR_LOGTRACE
	/* Re-init only if PROC_STOP from dhd_stop was called
	 * which can be checked via thr_pid
	 */
	if (dhd->thr_logtrace_ctl.thr_pid < 0) {
		PROC_START(dhd_logtrace_thread, dhd, &dhd->thr_logtrace_ctl,
			0, "dhd_logtrace_thread");
		if (dhd->thr_logtrace_ctl.thr_pid < 0) {
			DHD_ERROR(("%s: reinit logtrace process failed\n", __FUNCTION__));
			return BCME_ERROR;
		} else {
			DHD_ERROR(("%s: thr_logtrace_ctl(%ld) succedded\n", __FUNCTION__,
				dhd->thr_logtrace_ctl.thr_pid));
		}
	}
#else
	/* No need to re-init for WQ as calcel_delayed_work_sync will
	 * will not delete the WQ
	 */
#endif /* DHD_USE_KTHREAD_FOR_LOGTRACE */
	return BCME_OK;
}

void
dhd_event_logtrace_enqueue(dhd_pub_t *dhdp, int ifidx, void *pktbuf)
{
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;

#ifdef PCIE_FULL_DONGLE
	/* Add ifidx in the PKTTAG */
	DHD_PKTTAG_SET_IFID((dhd_pkttag_fr_t *)PKTTAG(pktbuf), ifidx);
#endif /* PCIE_FULL_DONGLE */
	skb_queue_tail(&dhd->evt_trace_queue, pktbuf);

	dhd_schedule_logtrace(dhd);
}

void
dhd_event_logtrace_flush_queue(dhd_pub_t *dhdp)
{
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&dhd->evt_trace_queue)) != NULL) {
#ifdef DHD_USE_STATIC_CTRLBUF
		PKTFREE_STATIC(dhdp->osh, skb, FALSE);
#else
		PKTFREE(dhdp->osh, skb, FALSE);
#endif /* DHD_USE_STATIC_CTRLBUF */
	}
}

void
dhd_sendup_info_buf(dhd_pub_t *dhdp, uint8 *msg)
{
	struct sk_buff *skb = NULL;
	uint32 pktsize = 0;
	void *pkt = NULL;
	info_buf_payload_hdr_t *infobuf = NULL;
	dhd_info_t *dhd = dhdp->info;
	uint8 *pktdata = NULL;

	if (!msg)
		return;

	/* msg = |infobuf_ver(u32)|info_buf_payload_hdr_t|msgtrace_hdr_t|<var len data>| */
	infobuf = (info_buf_payload_hdr_t *)(msg + sizeof(uint32));
	pktsize = (uint32)(ltoh16(infobuf->length) + sizeof(info_buf_payload_hdr_t) +
			sizeof(uint32));
	pkt = PKTGET(dhdp->osh, pktsize, FALSE);
	if (!pkt) {
		DHD_ERROR(("%s: skb alloc failed ! not sending event log up.\n", __FUNCTION__));
	} else {
		PKTSETLEN(dhdp->osh, pkt, pktsize);
		pktdata = PKTDATA(dhdp->osh, pkt);
		memcpy(pktdata, msg, pktsize);
		/* For infobuf packets assign skb->dev with
		 * Primary interface n/w device
		 */
		skb = PKTTONATIVE(dhdp->osh, pkt);
		skb->dev = dhd->iflist[0]->net;
		/* Send pkt UP */
		dhd_netif_rx_ni(skb);
	}
}
#endif /* SHOW_LOGTRACE */

/** Called when a frame is received by the dongle on interface 'ifidx' */
void
dhd_rx_frame(dhd_pub_t *dhdp, int ifidx, void *pktbuf, int numpkt, uint8 chan)
{
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;
	struct sk_buff *skb;
	uchar *eth;
	uint len;
	void *data, *pnext = NULL;
	int i;
	dhd_if_t *ifp;
	wl_event_msg_t event;
	int tout_rx = 0;
	int tout_ctrl = 0;
	void *skbhead = NULL;
	void *skbprev = NULL;
	uint16 protocol;
	unsigned char *dump_data;
#ifdef DHD_MCAST_REGEN
	uint8 interface_role;
	if_flow_lkup_t *if_flow_lkup;
	unsigned long flags;
#endif // endif
#ifdef DHD_WAKE_STATUS
	int pkt_wake = 0;
	wake_counts_t *wcp = NULL;
#endif /* DHD_WAKE_STATUS */

#ifdef CONFIG_AP6XXX_WIFI6_HDF
	struct NetDevice *netDevice = NULL;
	struct sk_buff *eap_skb = NULL;
	int ret = 0;
#endif
	DHD_TRACE(("%s: Enter\n", __FUNCTION__));
	BCM_REFERENCE(dump_data);

#ifdef DHD_TPUT_PATCH
	if (dhdp->conf->pktsetsum)
		PKTSETSUMGOOD(pktbuf, TRUE);
#endif

	for (i = 0; pktbuf && i < numpkt; i++, pktbuf = pnext) {
		struct ether_header *eh;

		pnext = PKTNEXT(dhdp->osh, pktbuf);
		PKTSETNEXT(dhdp->osh, pktbuf, NULL);

		/* info ring "debug" data, which is not a 802.3 frame, is sent/hacked with a
		 * special ifidx of DHD_DUMMY_INFO_IF.  This is just internal to dhd to get the data
		 * from dhd_msgbuf.c:dhd_prot_infobuf_cmplt_process() to here (dhd_rx_frame).
		 */
		if (ifidx == DHD_DUMMY_INFO_IF) {
			/* Event msg printing is called from dhd_rx_frame which is in Tasklet
			 * context in case of PCIe FD, in case of other bus this will be from
			 * DPC context. If we get bunch of events from Dongle then printing all
			 * of them from Tasklet/DPC context that too in data path is costly.
			 * Also in the new Dongle SW(4359, 4355 onwards) console prints too come as
			 * events with type WLC_E_TRACE.
			 * We'll print this console logs from the WorkQueue context by enqueing SKB
			 * here and Dequeuing will be done in WorkQueue and will be freed only if
			 * logtrace_pkt_sendup is TRUE
			 */
#ifdef SHOW_LOGTRACE
			dhd_event_logtrace_enqueue(dhdp, ifidx, pktbuf);
#else /* !SHOW_LOGTRACE */
		/* If SHOW_LOGTRACE not defined and ifidx is DHD_DUMMY_INFO_IF,
		 * free the PKT here itself
		 */
#ifdef DHD_USE_STATIC_CTRLBUF
		PKTFREE_STATIC(dhdp->osh, pktbuf, FALSE);
#else
		PKTFREE(dhdp->osh, pktbuf, FALSE);
#endif /* DHD_USE_STATIC_CTRLBUF */
#endif /* SHOW_LOGTRACE */
			continue;
		}
#ifdef DHD_WAKE_STATUS
#ifdef BCMDBUS
		wcp = NULL;
#else
		pkt_wake = dhd_bus_get_bus_wake(dhdp);
		wcp = dhd_bus_get_wakecount(dhdp);
#endif /* BCMDBUS */
		if (wcp == NULL) {
			/* If wakeinfo count buffer is null do not  update wake count values */
			pkt_wake = 0;
		}
#endif /* DHD_WAKE_STATUS */

		eh = (struct ether_header *)PKTDATA(dhdp->osh, pktbuf);

		if (ifidx >= DHD_MAX_IFS) {
			DHD_ERROR(("%s: ifidx(%d) Out of bound. drop packet\n",
				__FUNCTION__, ifidx));
			if (ntoh16(eh->ether_type) == ETHER_TYPE_BRCM) {
#ifdef DHD_USE_STATIC_CTRLBUF
				PKTFREE_STATIC(dhdp->osh, pktbuf, FALSE);
#else
				PKTFREE(dhdp->osh, pktbuf, FALSE);
#endif /* DHD_USE_STATIC_CTRLBUF */
			} else {
				PKTCFREE(dhdp->osh, pktbuf, FALSE);
			}
			continue;
		}

		ifp = dhd->iflist[ifidx];
		if (ifp == NULL) {
			DHD_ERROR(("%s: ifp is NULL. drop packet\n",
				__FUNCTION__));
			if (ntoh16(eh->ether_type) == ETHER_TYPE_BRCM) {
#ifdef DHD_USE_STATIC_CTRLBUF
				PKTFREE_STATIC(dhdp->osh, pktbuf, FALSE);
#else
				PKTFREE(dhdp->osh, pktbuf, FALSE);
#endif /* DHD_USE_STATIC_CTRLBUF */
			} else {
				PKTCFREE(dhdp->osh, pktbuf, FALSE);
			}
			continue;
		}

		/* Dropping only data packets before registering net device to avoid kernel panic */
#ifndef PROP_TXSTATUS_VSDB
		if ((!ifp->net || ifp->net->reg_state != NETREG_REGISTERED) &&
			(ntoh16(eh->ether_type) != ETHER_TYPE_BRCM))
#else
		if ((!ifp->net || ifp->net->reg_state != NETREG_REGISTERED || !dhd->pub.up) &&
			(ntoh16(eh->ether_type) != ETHER_TYPE_BRCM))
#endif /* PROP_TXSTATUS_VSDB */
		{
			DHD_ERROR(("%s: net device is NOT registered yet. drop packet\n",
			__FUNCTION__));
			PKTCFREE(dhdp->osh, pktbuf, FALSE);
			continue;
		}

#ifdef PROP_TXSTATUS
		if (dhd_wlfc_is_header_only_pkt(dhdp, pktbuf)) {
			/* WLFC may send header only packet when
			there is an urgent message but no packet to
			piggy-back on
			*/
			PKTCFREE(dhdp->osh, pktbuf, FALSE);
			continue;
		}
#endif // endif
#ifdef DHD_L2_FILTER
		/* If block_ping is enabled drop the ping packet */
		if (ifp->block_ping) {
			if (bcm_l2_filter_block_ping(dhdp->osh, pktbuf) == BCME_OK) {
				PKTCFREE(dhdp->osh, pktbuf, FALSE);
				continue;
			}
		}
		if (ifp->grat_arp && DHD_IF_ROLE_STA(dhdp, ifidx)) {
		    if (bcm_l2_filter_gratuitous_arp(dhdp->osh, pktbuf) == BCME_OK) {
				PKTCFREE(dhdp->osh, pktbuf, FALSE);
				continue;
		    }
		}
		if (ifp->parp_enable && DHD_IF_ROLE_AP(dhdp, ifidx)) {
			int ret = dhd_l2_filter_pkt_handle(dhdp, ifidx, pktbuf, FALSE);

			/* Drop the packets if l2 filter has processed it already
			 * otherwise continue with the normal path
			 */
			if (ret == BCME_OK) {
				PKTCFREE(dhdp->osh, pktbuf, TRUE);
				continue;
			}
		}
		if (ifp->block_tdls) {
			if (bcm_l2_filter_block_tdls(dhdp->osh, pktbuf) == BCME_OK) {
				PKTCFREE(dhdp->osh, pktbuf, FALSE);
				continue;
			}
		}
#endif /* DHD_L2_FILTER */

#ifdef DHD_MCAST_REGEN
		DHD_FLOWID_LOCK(dhdp->flowid_lock, flags);
		if_flow_lkup = (if_flow_lkup_t *)dhdp->if_flow_lkup;
		ASSERT(if_flow_lkup);

		interface_role = if_flow_lkup[ifidx].role;
		DHD_FLOWID_UNLOCK(dhdp->flowid_lock, flags);

		if (ifp->mcast_regen_bss_enable && (interface_role != WLC_E_IF_ROLE_WDS) &&
				!DHD_IF_ROLE_AP(dhdp, ifidx) &&
				ETHER_ISUCAST(eh->ether_dhost)) {
			if (dhd_mcast_reverse_translation(eh) ==  BCME_OK) {
#ifdef DHD_PSTA
				/* Change bsscfg to primary bsscfg for unicast-multicast packets */
				if ((dhd_get_psta_mode(dhdp) == DHD_MODE_PSTA) ||
						(dhd_get_psta_mode(dhdp) == DHD_MODE_PSR)) {
					if (ifidx != 0) {
						/* Let the primary in PSTA interface handle this
						 * frame after unicast to Multicast conversion
						 */
						ifp = dhd_get_ifp(dhdp, 0);
						ASSERT(ifp);
					}
				}
			}
#endif /* PSTA */
		}
#endif /* MCAST_REGEN */

#ifdef DHDTCPSYNC_FLOOD_BLK
		if (dhd_tcpdata_get_flag(dhdp, pktbuf) == FLAG_SYNC) {
			int delta_sec;
			int delta_sync;
			int sync_per_sec;
			u64 curr_time = DIV_U64_BY_U32(OSL_LOCALTIME_NS(), NSEC_PER_SEC);
			ifp->tsync_rcvd ++;
			delta_sync = ifp->tsync_rcvd - ifp->tsyncack_txed;
			delta_sec = curr_time - ifp->last_sync;
			if (delta_sec > 1) {
				sync_per_sec = delta_sync/delta_sec;
				if (sync_per_sec > TCP_SYNC_FLOOD_LIMIT) {
					schedule_work(&ifp->blk_tsfl_work);
					DHD_ERROR(("ifx %d TCP SYNC Flood attack suspected! "
						"sync recvied %d pkt/sec \n",
						ifidx, sync_per_sec));
				}
				dhd_reset_tcpsync_info_by_ifp(ifp);
			}

		}
#endif /* DHDTCPSYNC_FLOOD_BLK */

#ifdef DHDTCPACK_SUPPRESS
		dhd_tcpdata_info_get(dhdp, pktbuf);
#endif // endif
		skb = PKTTONATIVE(dhdp->osh, pktbuf);

		ASSERT(ifp);
		skb->dev = ifp->net;
#ifdef DHD_WET
		/* wet related packet proto manipulation should be done in DHD
		 * since dongle doesn't have complete payload
		 */
		if (WET_ENABLED(&dhd->pub) && (dhd_wet_recv_proc(dhd->pub.wet_info,
				pktbuf) < 0)) {
			DHD_INFO(("%s:%s: wet recv proc failed\n",
				__FUNCTION__, dhd_ifname(dhdp, ifidx)));
		}
#endif /* DHD_WET */

#ifdef DHD_PSTA
		if (PSR_ENABLED(dhdp) &&
				(dhd_psta_proc(dhdp, ifidx, &pktbuf, FALSE) < 0)) {
			DHD_ERROR(("%s:%s: psta recv proc failed\n", __FUNCTION__,
				dhd_ifname(dhdp, ifidx)));
		}
#endif /* DHD_PSTA */

#ifdef PCIE_FULL_DONGLE
		if ((DHD_IF_ROLE_AP(dhdp, ifidx) || DHD_IF_ROLE_P2PGO(dhdp, ifidx)) &&
			(!ifp->ap_isolate)) {
			eh = (struct ether_header *)PKTDATA(dhdp->osh, pktbuf);
			if (ETHER_ISUCAST(eh->ether_dhost)) {
				if (dhd_find_sta(dhdp, ifidx, (void *)eh->ether_dhost)) {
					dhd_sendpkt(dhdp, ifidx, pktbuf);
					continue;
				}
			} else {
				void *npktbuf = NULL;
				if ((ntoh16(eh->ether_type) != ETHER_TYPE_IAPP_L2_UPDATE) &&
					(npktbuf = PKTDUP(dhdp->osh, pktbuf)) != NULL) {
					dhd_sendpkt(dhdp, ifidx, npktbuf);
				}
			}
		}
#endif /* PCIE_FULL_DONGLE */
#ifdef DHD_POST_EAPOL_M1_AFTER_ROAM_EVT
		if (IS_STA_IFACE(ndev_to_wdev(ifp->net)) &&
			(ifp->recv_reassoc_evt == TRUE) && (ifp->post_roam_evt == FALSE) &&
			(dhd_is_4way_msg((char *)(skb->data)) == EAPOL_4WAY_M1)) {
				DHD_ERROR(("%s: Reassoc is in progress. "
					"Drop EAPOL M1 frame\n", __FUNCTION__));
				PKTFREE(dhdp->osh, pktbuf, FALSE);
				continue;
		}
#endif /* DHD_POST_EAPOL_M1_AFTER_ROAM_EVT */
#ifdef WLEASYMESH
		if ((dhdp->conf->fw_type == FW_TYPE_EZMESH) &&
				(ntoh16(eh->ether_type) != ETHER_TYPE_BRCM)) {
			uint16 * da = (uint16 *)(eh->ether_dhost);
			ASSERT(ISALIGNED(da, 2));

			/* XXX: Special handling for 1905 messages
			 * if DA matches with configured 1905 AL MAC addresses
			 * bypass fwder and foward it to linux stack
			 */
			if (ntoh16(eh->ether_type) == ETHER_TYPE_1905_1) {
				if (!eacmp(da, ifp->_1905_al_ucast) || !eacmp(da, ifp->_1905_al_mcast)) {
					//skb->fwr_flood = 0;
				} else {
					//skb->fwr_flood = 1;
				}
			}
		}
#endif /* WLEASYMESH */
		/* Get the protocol, maintain skb around eth_type_trans()
		 * The main reason for this hack is for the limitation of
		 * Linux 2.4 where 'eth_type_trans' uses the 'net->hard_header_len'
		 * to perform skb_pull inside vs ETH_HLEN. Since to avoid
		 * coping of the packet coming from the network stack to add
		 * BDC, Hardware header etc, during network interface registration
		 * we set the 'net->hard_header_len' to ETH_HLEN + extra space required
		 * for BDC, Hardware header etc. and not just the ETH_HLEN
		 */
		eth = skb->data;
		len = skb->len;
		dump_data = skb->data;
		protocol = (skb->data[12] << 8) | skb->data[13];

		if (protocol == ETHER_TYPE_802_1X) {
			DBG_EVENT_LOG(dhdp, WIFI_EVENT_DRIVER_EAPOL_FRAME_RECEIVED);
#if defined(WL_CFG80211) && defined(WL_WPS_SYNC)
			wl_handle_wps_states(ifp->net, dump_data, len, FALSE);
#endif /* WL_CFG80211 && WL_WPS_SYNC */
#ifdef DHD_4WAYM4_FAIL_DISCONNECT
			if (dhd_is_4way_msg((uint8 *)(skb->data)) == EAPOL_4WAY_M3) {
				OSL_ATOMIC_SET(dhdp->osh, &ifp->m4state, M3_RXED);
			}
#endif /* DHD_4WAYM4_FAIL_DISCONNECT */
		}
		dhd_dump_pkt(dhdp, ifidx, dump_data, len, FALSE, NULL, NULL);

		skb->protocol = eth_type_trans(skb, skb->dev);

		if (skb->pkt_type == PACKET_MULTICAST) {
			dhd->pub.rx_multicast++;
			ifp->stats.multicast++;
		}

		skb->data = eth;
		skb->len = len;

#ifdef CONFIG_AP6XXX_WIFI6_HDF
		// send EAPOL pkt to HDF WIFI
		if (protocol == ETHER_TYPE_802_1X) {
			netDevice = GetHdfNetDeviceByLinuxInf(skb->dev);
			if (netDevice && netDevice->netDeviceIf != NULL && netDevice->netDeviceIf->specialEtherTypeProcess != NULL) {
				eap_skb = skb_copy(skb, GFP_ATOMIC);
				skb_linearize(eap_skb);
				ret = netDevice->netDeviceIf->specialEtherTypeProcess(netDevice, eap_skb);
				DHD_ERROR(("%s: send EAPOL pkt ret=%d, from %s, data_len=%d\n", __FUNCTION__, ret, netDevice->name, eap_skb->len));
				print_hex_dump(KERN_INFO, "recv EAPOL: ", DUMP_PREFIX_NONE, 16, 1, eap_skb->data, eap_skb->len, true);
			}
		}
#endif
		DHD_DBG_PKT_MON_RX(dhdp, skb);
		/* Strip header, count, deliver upward */
		skb_pull(skb, ETH_HLEN);

		/* Process special event packets and then discard them */
		memset(&event, 0, sizeof(event));

		if (ntoh16(skb->protocol) == ETHER_TYPE_BRCM) {
			bcm_event_msg_u_t evu;
			int ret_event, event_type;
			void *pkt_data = skb_mac_header(skb);

			ret_event = wl_host_event_get_data(pkt_data, len, &evu);

			if (ret_event != BCME_OK) {
				DHD_ERROR(("%s: wl_host_event_get_data err = %d\n",
					__FUNCTION__, ret_event));
#ifdef DHD_USE_STATIC_CTRLBUF
				PKTFREE_STATIC(dhdp->osh, pktbuf, FALSE);
#else
				PKTFREE(dhdp->osh, pktbuf, FALSE);
#endif // endif
				continue;
			}

			memcpy(&event, &evu.event, sizeof(wl_event_msg_t));
			event_type = ntoh32_ua((void *)&event.event_type);
#ifdef SHOW_LOGTRACE
			/* Event msg printing is called from dhd_rx_frame which is in Tasklet
			 * context in case of PCIe FD, in case of other bus this will be from
			 * DPC context. If we get bunch of events from Dongle then printing all
			 * of them from Tasklet/DPC context that too in data path is costly.
			 * Also in the new Dongle SW(4359, 4355 onwards) console prints too come as
			 * events with type WLC_E_TRACE.
			 * We'll print this console logs from the WorkQueue context by enqueing SKB
			 * here and Dequeuing will be done in WorkQueue and will be freed only if
			 * logtrace_pkt_sendup is true
			 */
			if (event_type == WLC_E_TRACE) {
				DHD_EVENT(("%s: WLC_E_TRACE\n", __FUNCTION__));
				dhd_event_logtrace_enqueue(dhdp, ifidx, pktbuf);
				continue;
			}
#endif /* SHOW_LOGTRACE */

			ret_event = dhd_wl_host_event(dhd, ifidx, pkt_data, len, &event, &data);

			wl_event_to_host_order(&event);
			if (!tout_ctrl)
				tout_ctrl = DHD_PACKET_TIMEOUT_MS;

#if defined(PNO_SUPPORT)
			if (event_type == WLC_E_PFN_NET_FOUND) {
				/* enforce custom wake lock to garantee that Kernel not suspended */
				tout_ctrl = CUSTOM_PNO_EVENT_LOCK_xTIME * DHD_PACKET_TIMEOUT_MS;
			}
#endif /* PNO_SUPPORT */
			if (numpkt != 1) {
				DHD_TRACE(("%s: Got BRCM event packet in a chained packet.\n",
				__FUNCTION__));
			}

#ifdef DHD_WAKE_STATUS
			if (unlikely(pkt_wake)) {
#ifdef DHD_WAKE_EVENT_STATUS
				if (event.event_type < WLC_E_LAST) {
					wcp->rc_event[event.event_type]++;
					wcp->rcwake++;
					pkt_wake = 0;
				}
#endif /* DHD_WAKE_EVENT_STATUS */
			}
#endif /* DHD_WAKE_STATUS */

			/* For delete virtual interface event, wl_host_event returns positive
			 * i/f index, do not proceed. just free the pkt.
			 */
			if ((event_type == WLC_E_IF) && (ret_event > 0)) {
				DHD_ERROR(("%s: interface is deleted. Free event packet\n",
				__FUNCTION__));
#ifdef DHD_USE_STATIC_CTRLBUF
				PKTFREE_STATIC(dhdp->osh, pktbuf, FALSE);
#else
				PKTFREE(dhdp->osh, pktbuf, FALSE);
#endif // endif
				continue;
			}

			/*
			 * For the event packets, there is a possibility
			 * of ifidx getting modifed.Thus update the ifp
			 * once again.
			 */
			ASSERT(ifidx < DHD_MAX_IFS && dhd->iflist[ifidx]);
			ifp = dhd->iflist[ifidx];
#ifndef PROP_TXSTATUS_VSDB
			if (!(ifp && ifp->net && (ifp->net->reg_state == NETREG_REGISTERED)))
#else
			if (!(ifp && ifp->net && (ifp->net->reg_state == NETREG_REGISTERED) &&
				dhd->pub.up))
#endif /* PROP_TXSTATUS_VSDB */
			{
				DHD_ERROR(("%s: net device is NOT registered. drop event packet\n",
				__FUNCTION__));
#ifdef DHD_USE_STATIC_CTRLBUF
				PKTFREE_STATIC(dhdp->osh, pktbuf, FALSE);
#else
				PKTFREE(dhdp->osh, pktbuf, FALSE);
#endif // endif
				continue;
			}

#ifdef SENDPROB
			if (dhdp->wl_event_enabled ||
				(dhdp->recv_probereq && (event.event_type == WLC_E_PROBREQ_MSG)))
#else
			if (dhdp->wl_event_enabled)
#endif
			{
#ifdef DHD_USE_STATIC_CTRLBUF
				/* If event bufs are allocated via static buf pool
				 * and wl events are enabled, make a copy, free the
				 * local one and send the copy up.
				 */
				void *npkt = PKTDUP(dhdp->osh, skb);
				/* Clone event and send it up */
				PKTFREE_STATIC(dhdp->osh, pktbuf, FALSE);
				if (npkt) {
					skb = npkt;
				} else {
					DHD_ERROR(("skb clone failed. dropping event.\n"));
					continue;
				}
#endif /* DHD_USE_STATIC_CTRLBUF */
			} else {
				/* If event enabled not explictly set, drop events */
#ifdef DHD_USE_STATIC_CTRLBUF
				PKTFREE_STATIC(dhdp->osh, pktbuf, FALSE);
#else
				PKTFREE(dhdp->osh, pktbuf, FALSE);
#endif /* DHD_USE_STATIC_CTRLBUF */
				continue;
			}
		} else {
			tout_rx = DHD_PACKET_TIMEOUT_MS;

#ifdef PROP_TXSTATUS
			dhd_wlfc_save_rxpath_ac_time(dhdp, (uint8)PKTPRIO(skb));
#endif /* PROP_TXSTATUS */

#ifdef DHD_WAKE_STATUS
			if (unlikely(pkt_wake)) {
				wcp->rxwake++;
#ifdef DHD_WAKE_RX_STATUS
#define ETHER_ICMP6_HEADER	20
#define ETHER_IPV6_SADDR (ETHER_ICMP6_HEADER + 2)
#define ETHER_IPV6_DAADR (ETHER_IPV6_SADDR + IPV6_ADDR_LEN)
#define ETHER_ICMPV6_TYPE (ETHER_IPV6_DAADR + IPV6_ADDR_LEN)

				if (ntoh16(skb->protocol) == ETHER_TYPE_ARP) /* ARP */
					wcp->rx_arp++;
				if (dump_data[0] == 0xFF) { /* Broadcast */
					wcp->rx_bcast++;
				} else if (dump_data[0] & 0x01) { /* Multicast */
					wcp->rx_mcast++;
					if (ntoh16(skb->protocol) == ETHER_TYPE_IPV6) {
					    wcp->rx_multi_ipv6++;
					    if ((skb->len > ETHER_ICMP6_HEADER) &&
					        (dump_data[ETHER_ICMP6_HEADER] == IPPROTO_ICMPV6)) {
					        wcp->rx_icmpv6++;
					        if (skb->len > ETHER_ICMPV6_TYPE) {
					            switch (dump_data[ETHER_ICMPV6_TYPE]) {
					            case NDISC_ROUTER_ADVERTISEMENT:
					                wcp->rx_icmpv6_ra++;
					                break;
					            case NDISC_NEIGHBOUR_ADVERTISEMENT:
					                wcp->rx_icmpv6_na++;
					                break;
					            case NDISC_NEIGHBOUR_SOLICITATION:
					                wcp->rx_icmpv6_ns++;
					                break;
					            }
					        }
					    }
					} else if (dump_data[2] == 0x5E) {
						wcp->rx_multi_ipv4++;
					} else {
						wcp->rx_multi_other++;
					}
				} else { /* Unicast */
					wcp->rx_ucast++;
				}
#undef ETHER_ICMP6_HEADER
#undef ETHER_IPV6_SADDR
#undef ETHER_IPV6_DAADR
#undef ETHER_ICMPV6_TYPE
#endif /* DHD_WAKE_RX_STATUS */
				pkt_wake = 0;
			}
#endif /* DHD_WAKE_STATUS */
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
		ifp->net->last_rx = jiffies;
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0) */

		if (ntoh16(skb->protocol) != ETHER_TYPE_BRCM) {
			dhdp->dstats.rx_bytes += skb->len;
			dhdp->rx_packets++; /* Local count */
			ifp->stats.rx_bytes += skb->len;
			ifp->stats.rx_packets++;
		}

		if (in_interrupt()) {
			bcm_object_trace_opr(skb, BCM_OBJDBG_REMOVE,
				__FUNCTION__, __LINE__);
			DHD_PERIM_UNLOCK_ALL((dhd->fwder_unit % FWDER_MAX_UNIT));
#if defined(WL_MONITOR) && defined(BCMSDIO)
			if (dhd_monitor_enabled(dhdp, ifidx)) 
				dhd_rx_mon_pkt_sdio(dhdp, skb, ifidx);
			else
#endif /* WL_MONITOR && BCMSDIO */
#if defined(DHD_LB_RXP)
			netif_receive_skb(skb);
#else /* !defined(DHD_LB_RXP) */
			netif_rx(skb);
#endif /* !defined(DHD_LB_RXP) */
			DHD_PERIM_LOCK_ALL((dhd->fwder_unit % FWDER_MAX_UNIT));
		} else {
			if (dhd->rxthread_enabled) {
				if (!skbhead)
					skbhead = skb;
				else
					PKTSETNEXT(dhdp->osh, skbprev, skb);
				skbprev = skb;
			} else {

				/* If the receive is not processed inside an ISR,
				 * the softirqd must be woken explicitly to service
				 * the NET_RX_SOFTIRQ.	In 2.6 kernels, this is handled
				 * by netif_rx_ni(), but in earlier kernels, we need
				 * to do it manually.
				 */
				bcm_object_trace_opr(skb, BCM_OBJDBG_REMOVE,
					__FUNCTION__, __LINE__);

#if defined(ARGOS_NOTIFY_CB)
		argos_register_notifier_deinit();
#endif // endif
#if defined(BCMPCIE) && defined(DHDTCPACK_SUPPRESS)
		dhd_tcpack_suppress_set(&dhd->pub, TCPACK_SUP_OFF);
#endif /* BCMPCIE && DHDTCPACK_SUPPRESS */
				DHD_PERIM_UNLOCK_ALL((dhd->fwder_unit % FWDER_MAX_UNIT));
#if defined(DHD_LB_RXP)
				netif_receive_skb(skb);
#else /* !defined(DHD_LB_RXP) */
				netif_rx_ni(skb);
#endif /* defined(DHD_LB_RXP) */
				DHD_PERIM_LOCK_ALL((dhd->fwder_unit % FWDER_MAX_UNIT));
			}
		}
	}

	if (dhd->rxthread_enabled && skbhead)
		dhd_sched_rxf(dhdp, skbhead);

	DHD_OS_WAKE_LOCK_RX_TIMEOUT_ENABLE(dhdp, tout_rx);
	DHD_OS_WAKE_LOCK_CTRL_TIMEOUT_ENABLE(dhdp, tout_ctrl);
}

void
dhd_event(struct dhd_info *dhd, char *evpkt, int evlen, int ifidx)
{
	/* Linux version has nothing to do */
	return;
}

void
dhd_txcomplete(dhd_pub_t *dhdp, void *txp, bool success)
{
	dhd_info_t *dhd = (dhd_info_t *)(dhdp->info);
	struct ether_header *eh;
	uint16 type;

	dhd_prot_hdrpull(dhdp, NULL, txp, NULL, NULL);

	eh = (struct ether_header *)PKTDATA(dhdp->osh, txp);
	type  = ntoh16(eh->ether_type);

	if (type == ETHER_TYPE_802_1X) {
		atomic_dec(&dhd->pend_8021x_cnt);
	}

#ifdef PROP_TXSTATUS
	if (dhdp->wlfc_state && (dhdp->proptxstatus_mode != WLFC_FCMODE_NONE)) {
		dhd_if_t *ifp = dhd->iflist[DHD_PKTTAG_IF(PKTTAG(txp))];
		uint datalen  = PKTLEN(dhd->pub.osh, txp);
		if (ifp != NULL) {
			if (success) {
				dhd->pub.tx_packets++;
				ifp->stats.tx_packets++;
				ifp->stats.tx_bytes += datalen;
			} else {
				ifp->stats.tx_dropped++;
			}
		}
	}
#endif // endif
}

static struct net_device_stats *
dhd_get_stats(struct net_device *net)
{
	dhd_info_t *dhd = DHD_DEV_INFO(net);
	dhd_if_t *ifp;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (!dhd) {
		DHD_ERROR(("%s : dhd is NULL\n", __FUNCTION__));
		goto error;
	}

	ifp = dhd_get_ifp_by_ndev(&dhd->pub, net);
	if (!ifp) {
		/* return empty stats */
		DHD_ERROR(("%s: BAD_IF\n", __FUNCTION__));
		goto error;
	}

	if (dhd->pub.up) {
		/* Use the protocol to get dongle stats */
		dhd_prot_dstats(&dhd->pub);
	}
	return &ifp->stats;

error:
	memset(&net->stats, 0, sizeof(net->stats));
	return &net->stats;
}

#ifndef BCMDBUS
static int
dhd_watchdog_thread(void *data)
{
	tsk_ctl_t *tsk = (tsk_ctl_t *)data;
	dhd_info_t *dhd = (dhd_info_t *)tsk->parent;
	/* This thread doesn't need any user-level access,
	 * so get rid of all our resources
	 */
	if (dhd_watchdog_prio > 0) {
		struct sched_param param;
		param.sched_priority = (dhd_watchdog_prio < MAX_RT_PRIO)?
			dhd_watchdog_prio:(MAX_RT_PRIO-1);
		setScheduler(current, SCHED_FIFO, &param);
	}

	while (1) {
		if (down_interruptible (&tsk->sema) == 0) {
			unsigned long flags;
			unsigned long jiffies_at_start = jiffies;
			unsigned long time_lapse;
#ifdef BCMPCIE
			DHD_OS_WD_WAKE_LOCK(&dhd->pub);
#endif /* BCMPCIE */

			SMP_RD_BARRIER_DEPENDS();
			if (tsk->terminated) {
#ifdef BCMPCIE
				DHD_OS_WD_WAKE_UNLOCK(&dhd->pub);
#endif /* BCMPCIE */
				break;
			}

			if (dhd->pub.dongle_reset == FALSE) {
				DHD_TIMER(("%s:\n", __FUNCTION__));
				dhd_bus_watchdog(&dhd->pub);

				DHD_GENERAL_LOCK(&dhd->pub, flags);
				/* Count the tick for reference */
				dhd->pub.tickcnt++;
#ifdef DHD_L2_FILTER
				dhd_l2_filter_watchdog(&dhd->pub);
#endif /* DHD_L2_FILTER */
				time_lapse = jiffies - jiffies_at_start;

				/* Reschedule the watchdog */
				if (dhd->wd_timer_valid) {
					mod_timer(&dhd->timer,
					    jiffies +
					    msecs_to_jiffies(dhd_watchdog_ms) -
					    min(msecs_to_jiffies(dhd_watchdog_ms), time_lapse));
				}
				DHD_GENERAL_UNLOCK(&dhd->pub, flags);
			}
#ifdef BCMPCIE
			DHD_OS_WD_WAKE_UNLOCK(&dhd->pub);
#endif /* BCMPCIE */
		} else {
			break;
		}
	}

	complete_and_exit(&tsk->completed, 0);
}

static void dhd_watchdog(ulong data)
{
	dhd_info_t *dhd = (dhd_info_t *)data;
	unsigned long flags;

	if (dhd->pub.dongle_reset) {
		return;
	}

	if (dhd->thr_wdt_ctl.thr_pid >= 0) {
		up(&dhd->thr_wdt_ctl.sema);
		return;
	}

#ifdef BCMPCIE
	DHD_OS_WD_WAKE_LOCK(&dhd->pub);
#endif /* BCMPCIE */
	/* Call the bus module watchdog */
	dhd_bus_watchdog(&dhd->pub);

	DHD_GENERAL_LOCK(&dhd->pub, flags);
	/* Count the tick for reference */
	dhd->pub.tickcnt++;

#ifdef DHD_L2_FILTER
	dhd_l2_filter_watchdog(&dhd->pub);
#endif /* DHD_L2_FILTER */
	/* Reschedule the watchdog */
	if (dhd->wd_timer_valid)
		mod_timer(&dhd->timer, jiffies + msecs_to_jiffies(dhd_watchdog_ms));
	DHD_GENERAL_UNLOCK(&dhd->pub, flags);
#ifdef BCMPCIE
	DHD_OS_WD_WAKE_UNLOCK(&dhd->pub);
#endif /* BCMPCIE */
}

#ifdef ENABLE_ADAPTIVE_SCHED
static void
dhd_sched_policy(int prio)
{
	struct sched_param param;
	if (cpufreq_quick_get(0) <= CUSTOM_CPUFREQ_THRESH) {
		param.sched_priority = 0;
		setScheduler(current, SCHED_NORMAL, &param);
	} else {
		if (get_scheduler_policy(current) != SCHED_FIFO) {
			param.sched_priority = (prio < MAX_RT_PRIO)? prio : (MAX_RT_PRIO-1);
			setScheduler(current, SCHED_FIFO, &param);
		}
	}
}
#endif /* ENABLE_ADAPTIVE_SCHED */
#ifdef DEBUG_CPU_FREQ
static int dhd_cpufreq_notifier(struct notifier_block *nb, unsigned long val, void *data)
{
	dhd_info_t *dhd = container_of(nb, struct dhd_info, freq_trans);
	struct cpufreq_freqs *freq = data;
	if (dhd) {
		if (!dhd->new_freq)
			goto exit;
		if (val == CPUFREQ_POSTCHANGE) {
			DHD_ERROR(("cpu freq is changed to %u kHZ on CPU %d\n",
				freq->new, freq->cpu));
			*per_cpu_ptr(dhd->new_freq, freq->cpu) = freq->new;
		}
	}
exit:
	return 0;
}
#endif /* DEBUG_CPU_FREQ */

static int
dhd_dpc_thread(void *data)
{
	tsk_ctl_t *tsk = (tsk_ctl_t *)data;
	dhd_info_t *dhd = (dhd_info_t *)tsk->parent;

	/* This thread doesn't need any user-level access,
	 * so get rid of all our resources
	 */
	if (dhd_dpc_prio > 0)
	{
		struct sched_param param;
		param.sched_priority = (dhd_dpc_prio < MAX_RT_PRIO)?dhd_dpc_prio:(MAX_RT_PRIO-1);
		setScheduler(current, SCHED_FIFO, &param);
	}

#ifdef CUSTOM_DPC_CPUCORE
	set_cpus_allowed_ptr(current, cpumask_of(CUSTOM_DPC_CPUCORE));
#endif // endif
#ifdef CUSTOM_SET_CPUCORE
	dhd->pub.current_dpc = current;
#endif /* CUSTOM_SET_CPUCORE */
	/* Run until signal received */
	while (1) {
		if (dhd->pub.conf->dpc_cpucore >= 0) {
			printf("%s: set dpc_cpucore %d\n", __FUNCTION__, dhd->pub.conf->dpc_cpucore);
			set_cpus_allowed_ptr(current, cpumask_of(dhd->pub.conf->dpc_cpucore));
			dhd->pub.conf->dpc_cpucore = -1;
		}
		if (dhd->pub.conf->dhd_dpc_prio >= 0) {
			struct sched_param param;
			printf("%s: set dhd_dpc_prio %d\n", __FUNCTION__, dhd->pub.conf->dhd_dpc_prio);
			param.sched_priority = (dhd->pub.conf->dhd_dpc_prio < MAX_RT_PRIO)?
				dhd->pub.conf->dhd_dpc_prio:(MAX_RT_PRIO-1);
			setScheduler(current, SCHED_FIFO, &param);
			dhd->pub.conf->dhd_dpc_prio = -1;
		}
		if (!binary_sema_down(tsk)) {
#ifdef ENABLE_ADAPTIVE_SCHED
			dhd_sched_policy(dhd_dpc_prio);
#endif /* ENABLE_ADAPTIVE_SCHED */
			SMP_RD_BARRIER_DEPENDS();
			if (tsk->terminated) {
				break;
			}

			/* Call bus dpc unless it indicated down (then clean stop) */
			if (dhd->pub.busstate != DHD_BUS_DOWN) {
#ifdef DEBUG_DPC_THREAD_WATCHDOG
				int resched_cnt = 0;
#endif /* DEBUG_DPC_THREAD_WATCHDOG */
				dhd_os_wd_timer_extend(&dhd->pub, TRUE);
				while (dhd_bus_dpc(dhd->pub.bus)) {
					/* process all data */
#ifdef DEBUG_DPC_THREAD_WATCHDOG
					resched_cnt++;
					if (resched_cnt > MAX_RESCHED_CNT) {
						DHD_INFO(("%s Calling msleep to"
							"let other processes run. \n",
							__FUNCTION__));
						dhd->pub.dhd_bug_on = true;
						resched_cnt = 0;
						OSL_SLEEP(1);
					}
#endif /* DEBUG_DPC_THREAD_WATCHDOG */
				}
				dhd_os_wd_timer_extend(&dhd->pub, FALSE);
				DHD_OS_WAKE_UNLOCK(&dhd->pub);
			} else {
				if (dhd->pub.up)
					dhd_bus_stop(dhd->pub.bus, TRUE);
				DHD_OS_WAKE_UNLOCK(&dhd->pub);
			}
		} else {
			break;
		}
	}
	complete_and_exit(&tsk->completed, 0);
}

static int
dhd_rxf_thread(void *data)
{
	tsk_ctl_t *tsk = (tsk_ctl_t *)data;
	dhd_info_t *dhd = (dhd_info_t *)tsk->parent;
#if defined(WAIT_DEQUEUE)
#define RXF_WATCHDOG_TIME 250 /* BARK_TIME(1000) /  */
	ulong watchdogTime = OSL_SYSUPTIME(); /* msec */
#endif // endif
	dhd_pub_t *pub = &dhd->pub;

	/* This thread doesn't need any user-level access,
	 * so get rid of all our resources
	 */
	if (dhd_rxf_prio > 0)
	{
		struct sched_param param;
		param.sched_priority = (dhd_rxf_prio < MAX_RT_PRIO)?dhd_rxf_prio:(MAX_RT_PRIO-1);
		setScheduler(current, SCHED_FIFO, &param);
	}

#ifdef CUSTOM_SET_CPUCORE
	dhd->pub.current_rxf = current;
#endif /* CUSTOM_SET_CPUCORE */
	/* Run until signal received */
	while (1) {
		if (dhd->pub.conf->rxf_cpucore >= 0) {
			printf("%s: set rxf_cpucore %d\n", __FUNCTION__, dhd->pub.conf->rxf_cpucore);
			set_cpus_allowed_ptr(current, cpumask_of(dhd->pub.conf->rxf_cpucore));
			dhd->pub.conf->rxf_cpucore = -1;
		}
		if (down_interruptible(&tsk->sema) == 0) {
			void *skb;
#ifdef ENABLE_ADAPTIVE_SCHED
			dhd_sched_policy(dhd_rxf_prio);
#endif /* ENABLE_ADAPTIVE_SCHED */

			SMP_RD_BARRIER_DEPENDS();

			if (tsk->terminated) {
				break;
			}
			skb = dhd_rxf_dequeue(pub);

			if (skb == NULL) {
				continue;
			}
			while (skb) {
				void *skbnext = PKTNEXT(pub->osh, skb);
				PKTSETNEXT(pub->osh, skb, NULL);
				bcm_object_trace_opr(skb, BCM_OBJDBG_REMOVE,
					__FUNCTION__, __LINE__);
#if defined(WL_MONITOR) && defined(BCMSDIO)
				if (dhd_monitor_enabled(pub, 0)) 
					dhd_rx_mon_pkt_sdio(pub, skb, 0);
				else
#endif /* WL_MONITOR && BCMSDIO */
				netif_rx_ni(skb);
				skb = skbnext;
			}
#if defined(WAIT_DEQUEUE)
			if (OSL_SYSUPTIME() - watchdogTime > RXF_WATCHDOG_TIME) {
				OSL_SLEEP(1);
				watchdogTime = OSL_SYSUPTIME();
			}
#endif // endif

			DHD_OS_WAKE_UNLOCK(pub);
		} else {
			break;
		}
	}
	complete_and_exit(&tsk->completed, 0);
}

#ifdef BCMPCIE
void dhd_dpc_enable(dhd_pub_t *dhdp)
{
#if defined(DHD_LB_RXP) || defined(DHD_LB_TXP)
	dhd_info_t *dhd;

	if (!dhdp || !dhdp->info)
		return;
	dhd = dhdp->info;
#endif /* DHD_LB_RXP || DHD_LB_TXP */

#ifdef DHD_LB_RXP
	__skb_queue_head_init(&dhd->rx_pend_queue);
#endif /* DHD_LB_RXP */

#ifdef DHD_LB_TXP
	skb_queue_head_init(&dhd->tx_pend_queue);
#endif /* DHD_LB_TXP */
}
#endif /* BCMPCIE */

#ifdef BCMPCIE
void
dhd_dpc_kill(dhd_pub_t *dhdp)
{
	dhd_info_t *dhd;

	if (!dhdp) {
		return;
	}

	dhd = dhdp->info;

	if (!dhd) {
		return;
	}

	if (dhd->thr_dpc_ctl.thr_pid < 0) {
		tasklet_kill(&dhd->tasklet);
		DHD_ERROR(("%s: tasklet disabled\n", __FUNCTION__));
	}

#ifdef DHD_LB
#ifdef DHD_LB_RXP
	cancel_work_sync(&dhd->rx_napi_dispatcher_work);
	__skb_queue_purge(&dhd->rx_pend_queue);
#endif /* DHD_LB_RXP */
#ifdef DHD_LB_TXP
	cancel_work_sync(&dhd->tx_dispatcher_work);
	skb_queue_purge(&dhd->tx_pend_queue);
#endif /* DHD_LB_TXP */

	/* Kill the Load Balancing Tasklets */
#if defined(DHD_LB_TXC)
	tasklet_kill(&dhd->tx_compl_tasklet);
#endif /* DHD_LB_TXC */
#if defined(DHD_LB_RXC)
	tasklet_kill(&dhd->rx_compl_tasklet);
#endif /* DHD_LB_RXC */
#if defined(DHD_LB_TXP)
	tasklet_kill(&dhd->tx_tasklet);
#endif /* DHD_LB_TXP */
#endif /* DHD_LB */
}

void
dhd_dpc_tasklet_kill(dhd_pub_t *dhdp)
{
	dhd_info_t *dhd;

	if (!dhdp) {
		return;
	}

	dhd = dhdp->info;

	if (!dhd) {
		return;
	}

	if (dhd->thr_dpc_ctl.thr_pid < 0) {
		tasklet_kill(&dhd->tasklet);
	}
}
#endif /* BCMPCIE */

static void
dhd_dpc(ulong data)
{
	dhd_info_t *dhd;

	dhd = (dhd_info_t *)data;

	/* this (tasklet) can be scheduled in dhd_sched_dpc[dhd_linux.c]
	 * down below , wake lock is set,
	 * the tasklet is initialized in dhd_attach()
	 */
	/* Call bus dpc unless it indicated down (then clean stop) */
	if (dhd->pub.busstate != DHD_BUS_DOWN) {
#if defined(DHD_LB_STATS) && defined(PCIE_FULL_DONGLE)
		DHD_LB_STATS_INCR(dhd->dhd_dpc_cnt);
#endif /* DHD_LB_STATS && PCIE_FULL_DONGLE */
		if (dhd_bus_dpc(dhd->pub.bus)) {
			tasklet_schedule(&dhd->tasklet);
		}
	} else {
		dhd_bus_stop(dhd->pub.bus, TRUE);
	}
}

void
dhd_sched_dpc(dhd_pub_t *dhdp)
{
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;

	if (dhd->thr_dpc_ctl.thr_pid >= 0) {
		DHD_OS_WAKE_LOCK(dhdp);
		/* If the semaphore does not get up,
		* wake unlock should be done here
		*/
		if (!binary_sema_up(&dhd->thr_dpc_ctl)) {
			DHD_OS_WAKE_UNLOCK(dhdp);
		}
		return;
	} else {
		dhd_bus_set_dpc_sched_time(dhdp);
		tasklet_schedule(&dhd->tasklet);
	}
}
#endif /* BCMDBUS */

static void
dhd_sched_rxf(dhd_pub_t *dhdp, void *skb)
{
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;

	DHD_OS_WAKE_LOCK(dhdp);

	DHD_TRACE(("dhd_sched_rxf: Enter\n"));
	do {
		if (dhd_rxf_enqueue(dhdp, skb) == BCME_OK)
			break;
	} while (1);
	if (dhd->thr_rxf_ctl.thr_pid >= 0) {
		up(&dhd->thr_rxf_ctl.sema);
	}
	return;
}

#if defined(BCM_DNGL_EMBEDIMAGE) || defined(BCM_REQUEST_FW)
#endif /* defined(BCM_DNGL_EMBEDIMAGE) || defined(BCM_REQUEST_FW) */

#ifdef TOE
/* Retrieve current toe component enables, which are kept as a bitmap in toe_ol iovar */
static int
dhd_toe_get(dhd_info_t *dhd, int ifidx, uint32 *toe_ol)
{
	char buf[32];
	int ret;

	ret = dhd_iovar(&dhd->pub, ifidx, "toe_ol", NULL, 0, (char *)&buf, sizeof(buf), FALSE);

	if (ret < 0) {
		if (ret == -EIO) {
			DHD_ERROR(("%s: toe not supported by device\n", dhd_ifname(&dhd->pub,
				ifidx)));
			return -EOPNOTSUPP;
		}

		DHD_INFO(("%s: could not get toe_ol: ret=%d\n", dhd_ifname(&dhd->pub, ifidx), ret));
		return ret;
	}

	memcpy(toe_ol, buf, sizeof(uint32));
	return 0;
}

/* Set current toe component enables in toe_ol iovar, and set toe global enable iovar */
static int
dhd_toe_set(dhd_info_t *dhd, int ifidx, uint32 toe_ol)
{
	int toe, ret;

	/* Set toe_ol as requested */
	ret = dhd_iovar(&dhd->pub, ifidx, "toe_ol", (char *)&toe_ol, sizeof(toe_ol), NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s: could not set toe_ol: ret=%d\n",
			dhd_ifname(&dhd->pub, ifidx), ret));
		return ret;
	}

	/* Enable toe globally only if any components are enabled. */
	toe = (toe_ol != 0);
	ret = dhd_iovar(&dhd->pub, ifidx, "toe", (char *)&toe, sizeof(toe), NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s: could not set toe: ret=%d\n", dhd_ifname(&dhd->pub, ifidx), ret));
		return ret;
	}

	return 0;
}
#endif /* TOE */

#if defined(WL_CFG80211) && defined(NUM_SCB_MAX_PROBE)
void dhd_set_scb_probe(dhd_pub_t *dhd)
{
	wl_scb_probe_t scb_probe;
	char iovbuf[WL_EVENTING_MASK_LEN + sizeof(wl_scb_probe_t)];
	int ret;

	if (dhd->op_mode & DHD_FLAG_HOSTAP_MODE) {
		return;
	}

	ret = dhd_iovar(dhd, 0, "scb_probe", NULL, 0, iovbuf, sizeof(iovbuf), FALSE);
	if (ret < 0) {
		DHD_ERROR(("%s: GET max_scb_probe failed\n", __FUNCTION__));
	}

	memcpy(&scb_probe, iovbuf, sizeof(wl_scb_probe_t));

	scb_probe.scb_max_probe = NUM_SCB_MAX_PROBE;

	ret = dhd_iovar(dhd, 0, "scb_probe", (char *)&scb_probe, sizeof(wl_scb_probe_t), NULL, 0,
			TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s: max_scb_probe setting failed\n", __FUNCTION__));
		return;
	}
}
#endif /* WL_CFG80211 && NUM_SCB_MAX_PROBE */

static void
dhd_ethtool_get_drvinfo(struct net_device *net, struct ethtool_drvinfo *info)
{
	dhd_info_t *dhd = DHD_DEV_INFO(net);

	snprintf(info->driver, sizeof(info->driver), "wl");
	snprintf(info->version, sizeof(info->version), "%lu", dhd->pub.drv_version);
}

struct ethtool_ops dhd_ethtool_ops = {
	.get_drvinfo = dhd_ethtool_get_drvinfo
};

static int
dhd_ethtool(dhd_info_t *dhd, void *uaddr)
{
	struct ethtool_drvinfo info;
	char drvname[sizeof(info.driver)];
	uint32 cmd;
#ifdef TOE
	struct ethtool_value edata;
	uint32 toe_cmpnt, csum_dir;
	int ret;
#endif // endif

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	/* all ethtool calls start with a cmd word */
	if (copy_from_user(&cmd, uaddr, sizeof (uint32)))
		return -EFAULT;

	switch (cmd) {
	case ETHTOOL_GDRVINFO:
		/* Copy out any request driver name */
		if (copy_from_user(&info, uaddr, sizeof(info)))
			return -EFAULT;
		strncpy(drvname, info.driver, sizeof(drvname) - 1);
		drvname[sizeof(drvname) - 1] = '\0';

		/* clear struct for return */
		memset(&info, 0, sizeof(info));
		info.cmd = cmd;

		/* if dhd requested, identify ourselves */
		if (strcmp(drvname, "?dhd") == 0) {
			snprintf(info.driver, sizeof(info.driver), "dhd");
			strncpy(info.version, EPI_VERSION_STR, sizeof(info.version) - 1);
			info.version[sizeof(info.version) - 1] = '\0';
		}

		/* otherwise, require dongle to be up */
		else if (!dhd->pub.up) {
			DHD_ERROR(("%s: dongle is not up\n", __FUNCTION__));
			return -ENODEV;
		}

		/* finally, report dongle driver type */
		else if (dhd->pub.iswl)
			snprintf(info.driver, sizeof(info.driver), "wl");
		else
			snprintf(info.driver, sizeof(info.driver), "xx");

		snprintf(info.version, sizeof(info.version), "%lu", dhd->pub.drv_version);
		if (copy_to_user(uaddr, &info, sizeof(info)))
			return -EFAULT;
		DHD_CTL(("%s: given %*s, returning %s\n", __FUNCTION__,
		         (int)sizeof(drvname), drvname, info.driver));
		break;

#ifdef TOE
	/* Get toe offload components from dongle */
	case ETHTOOL_GRXCSUM:
	case ETHTOOL_GTXCSUM:
		if ((ret = dhd_toe_get(dhd, 0, &toe_cmpnt)) < 0)
			return ret;

		csum_dir = (cmd == ETHTOOL_GTXCSUM) ? TOE_TX_CSUM_OL : TOE_RX_CSUM_OL;

		edata.cmd = cmd;
		edata.data = (toe_cmpnt & csum_dir) ? 1 : 0;

		if (copy_to_user(uaddr, &edata, sizeof(edata)))
			return -EFAULT;
		break;

	/* Set toe offload components in dongle */
	case ETHTOOL_SRXCSUM:
	case ETHTOOL_STXCSUM:
		if (copy_from_user(&edata, uaddr, sizeof(edata)))
			return -EFAULT;

		/* Read the current settings, update and write back */
		if ((ret = dhd_toe_get(dhd, 0, &toe_cmpnt)) < 0)
			return ret;

		csum_dir = (cmd == ETHTOOL_STXCSUM) ? TOE_TX_CSUM_OL : TOE_RX_CSUM_OL;

		if (edata.data != 0)
			toe_cmpnt |= csum_dir;
		else
			toe_cmpnt &= ~csum_dir;

		if ((ret = dhd_toe_set(dhd, 0, toe_cmpnt)) < 0)
			return ret;

		/* If setting TX checksum mode, tell Linux the new mode */
		if (cmd == ETHTOOL_STXCSUM) {
			if (edata.data)
				dhd->iflist[0]->net->features |= NETIF_F_IP_CSUM;
			else
				dhd->iflist[0]->net->features &= ~NETIF_F_IP_CSUM;
		}

		break;
#endif /* TOE */

	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static bool dhd_check_hang(struct net_device *net, dhd_pub_t *dhdp, int error)
{
	if (!dhdp) {
		DHD_ERROR(("%s: dhdp is NULL\n", __FUNCTION__));
		return FALSE;
	}

	if (!dhdp->up)
		return FALSE;

#if !defined(BCMPCIE) && !defined(BCMDBUS)
	if (dhdp->info->thr_dpc_ctl.thr_pid < 0) {
		DHD_ERROR(("%s : skipped due to negative pid - unloading?\n", __FUNCTION__));
		return FALSE;
	}
#endif /* !BCMPCIE && !BCMDBUS */

	if ((error == -ETIMEDOUT) || (error == -EREMOTEIO) ||
		((dhdp->busstate == DHD_BUS_DOWN) && (!dhdp->dongle_reset))) {
#ifdef BCMPCIE
		DHD_ERROR(("%s: Event HANG send up due to  re=%d te=%d d3acke=%d e=%d s=%d\n",
			__FUNCTION__, dhdp->rxcnt_timeout, dhdp->txcnt_timeout,
			dhdp->d3ackcnt_timeout, error, dhdp->busstate));
#else
		DHD_ERROR(("%s: Event HANG send up due to  re=%d te=%d e=%d s=%d\n", __FUNCTION__,
			dhdp->rxcnt_timeout, dhdp->txcnt_timeout, error, dhdp->busstate));
#endif /* BCMPCIE */
		if (dhdp->hang_reason == 0) {
			if (dhdp->dongle_trap_occured) {
				dhdp->hang_reason = HANG_REASON_DONGLE_TRAP;
#ifdef BCMPCIE
			} else if (dhdp->d3ackcnt_timeout) {
				dhdp->hang_reason = dhdp->is_sched_error ?
					HANG_REASON_D3_ACK_TIMEOUT_SCHED_ERROR :
					HANG_REASON_D3_ACK_TIMEOUT;
#endif /* BCMPCIE */
			} else {
				dhdp->hang_reason = dhdp->is_sched_error ?
					HANG_REASON_IOCTL_RESP_TIMEOUT_SCHED_ERROR :
					HANG_REASON_IOCTL_RESP_TIMEOUT;
			}
		}
		printf("%s\n", info_string);
		printf("MAC %pM\n", &dhdp->mac);
		net_os_send_hang_message(net);
		return TRUE;
	}
	return FALSE;
}

#ifdef WL_MONITOR
bool
dhd_monitor_enabled(dhd_pub_t *dhd, int ifidx)
{
	return (dhd->info->monitor_type != 0);
}

#ifdef BCMSDIO
static void
dhd_rx_mon_pkt_sdio(dhd_pub_t *dhdp, void *pkt, int ifidx)
{
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;

	if (!dhd->monitor_skb) {
		if ((dhd->monitor_skb = PKTTONATIVE(dhdp->osh, pkt)) == NULL)
			return;
	}

	if (dhd->monitor_type && dhd->monitor_dev)
		dhd->monitor_skb->dev = dhd->monitor_dev;
	else {
		PKTFREE(dhdp->osh, pkt, FALSE);
		dhd->monitor_skb = NULL;
		return;
	}

	dhd->monitor_skb->protocol =
		eth_type_trans(dhd->monitor_skb, dhd->monitor_skb->dev);
	dhd->monitor_len = 0;

	netif_rx_ni(dhd->monitor_skb);

	dhd->monitor_skb = NULL;
}
#elif defined(BCMPCIE)
void
dhd_rx_mon_pkt(dhd_pub_t *dhdp, host_rxbuf_cmpl_t* msg, void *pkt, int ifidx)
{
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;
	{
		uint8 amsdu_flag = (msg->flags & BCMPCIE_PKT_FLAGS_MONITOR_MASK) >>
			BCMPCIE_PKT_FLAGS_MONITOR_SHIFT;
		switch (amsdu_flag) {
			case BCMPCIE_PKT_FLAGS_MONITOR_NO_AMSDU:
			default:
				if (!dhd->monitor_skb) {
					if ((dhd->monitor_skb = PKTTONATIVE(dhdp->osh, pkt))
						== NULL)
						return;
				}
				if (dhd->monitor_type && dhd->monitor_dev)
					dhd->monitor_skb->dev = dhd->monitor_dev;
				else {
					PKTFREE(dhdp->osh, pkt, FALSE);
					dhd->monitor_skb = NULL;
					return;
				}
				dhd->monitor_skb->protocol =
					eth_type_trans(dhd->monitor_skb, dhd->monitor_skb->dev);
				dhd->monitor_len = 0;
				break;

			case BCMPCIE_PKT_FLAGS_MONITOR_FIRST_PKT:
				if (!dhd->monitor_skb) {
					if ((dhd->monitor_skb = dev_alloc_skb(MAX_MON_PKT_SIZE))
						== NULL)
						return;
					dhd->monitor_len = 0;
				}
				if (dhd->monitor_type && dhd->monitor_dev)
					dhd->monitor_skb->dev = dhd->monitor_dev;
				else {
					PKTFREE(dhdp->osh, pkt, FALSE);
					dev_kfree_skb(dhd->monitor_skb);
					return;
				}
				memcpy(PKTDATA(dhdp->osh, dhd->monitor_skb),
				PKTDATA(dhdp->osh, pkt), PKTLEN(dhdp->osh, pkt));
				dhd->monitor_len = PKTLEN(dhdp->osh, pkt);
				PKTFREE(dhdp->osh, pkt, FALSE);
				return;

			case BCMPCIE_PKT_FLAGS_MONITOR_INTER_PKT:
				memcpy(PKTDATA(dhdp->osh, dhd->monitor_skb) + dhd->monitor_len,
				PKTDATA(dhdp->osh, pkt), PKTLEN(dhdp->osh, pkt));
				dhd->monitor_len += PKTLEN(dhdp->osh, pkt);
				PKTFREE(dhdp->osh, pkt, FALSE);
				return;

			case BCMPCIE_PKT_FLAGS_MONITOR_LAST_PKT:
				memcpy(PKTDATA(dhdp->osh, dhd->monitor_skb) + dhd->monitor_len,
				PKTDATA(dhdp->osh, pkt), PKTLEN(dhdp->osh, pkt));
				dhd->monitor_len += PKTLEN(dhdp->osh, pkt);
				PKTFREE(dhdp->osh, pkt, FALSE);
				skb_put(dhd->monitor_skb, dhd->monitor_len);
				dhd->monitor_skb->protocol =
					eth_type_trans(dhd->monitor_skb, dhd->monitor_skb->dev);
				dhd->monitor_len = 0;
				break;
		}
	}

	if (in_interrupt()) {
		bcm_object_trace_opr(skb, BCM_OBJDBG_REMOVE,
			__FUNCTION__, __LINE__);
		DHD_PERIM_UNLOCK_ALL((dhd->fwder_unit % FWDER_MAX_UNIT));
		netif_rx(dhd->monitor_skb);
		DHD_PERIM_LOCK_ALL((dhd->fwder_unit % FWDER_MAX_UNIT));
	} else {
		/* If the receive is not processed inside an ISR,
		 * the softirqd must be woken explicitly to service
		 * the NET_RX_SOFTIRQ.	In 2.6 kernels, this is handled
		 * by netif_rx_ni(), but in earlier kernels, we need
		 * to do it manually.
		 */
		bcm_object_trace_opr(dhd->monitor_skb, BCM_OBJDBG_REMOVE,
			__FUNCTION__, __LINE__);

		DHD_PERIM_UNLOCK_ALL((dhd->fwder_unit % FWDER_MAX_UNIT));
		netif_rx_ni(dhd->monitor_skb);
		DHD_PERIM_LOCK_ALL((dhd->fwder_unit % FWDER_MAX_UNIT));
	}

	dhd->monitor_skb = NULL;
}
#endif

typedef struct dhd_mon_dev_priv {
	struct net_device_stats stats;
} dhd_mon_dev_priv_t;

#define DHD_MON_DEV_PRIV_SIZE		(sizeof(dhd_mon_dev_priv_t))
#define DHD_MON_DEV_PRIV(dev)		((dhd_mon_dev_priv_t *)DEV_PRIV(dev))
#define DHD_MON_DEV_STATS(dev)		(((dhd_mon_dev_priv_t *)DEV_PRIV(dev))->stats)

static int
dhd_monitor_start(struct sk_buff *skb, struct net_device *dev)
{
	PKTFREE(NULL, skb, FALSE);
	return 0;
}

#if defined(BT_OVER_SDIO)

void
dhdsdio_bus_usr_cnt_inc(dhd_pub_t *dhdp)
{
	dhdp->info->bus_user_count++;
}

void
dhdsdio_bus_usr_cnt_dec(dhd_pub_t *dhdp)
{
	dhdp->info->bus_user_count--;
}

/* Return values:
 * Success: Returns 0
 * Failure: Returns -1 or errono code
 */
int
dhd_bus_get(wlan_bt_handle_t handle, bus_owner_t owner)
{
	dhd_pub_t *dhdp = (dhd_pub_t *)handle;
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;
	int ret = 0;

	mutex_lock(&dhd->bus_user_lock);
	++dhd->bus_user_count;
	if (dhd->bus_user_count < 0) {
		DHD_ERROR(("%s(): bus_user_count is negative, which is invalid\n", __FUNCTION__));
		ret = -1;
		goto exit;
	}

	if (dhd->bus_user_count == 1) {

		dhd->pub.hang_was_sent = 0;

		/* First user, turn on WL_REG, start the bus */
		DHD_ERROR(("%s(): First user Turn On WL_REG & start the bus", __FUNCTION__));

		if (!wifi_platform_set_power(dhd->adapter, TRUE, WIFI_TURNON_DELAY)) {
			/* Enable F1 */
			ret = dhd_bus_resume(dhdp, 0);
			if (ret) {
				DHD_ERROR(("%s(): Failed to enable F1, err=%d\n",
					__FUNCTION__, ret));
				goto exit;
			}
		}

		dhd_update_fw_nv_path(dhd);
		/* update firmware and nvram path to sdio bus */
		dhd_bus_update_fw_nv_path(dhd->pub.bus,
			dhd->fw_path, dhd->nv_path);
		/* download the firmware, Enable F2 */
		/* TODO: Should be done only in case of FW switch */
		ret = dhd_bus_devreset(dhdp, FALSE);
		dhd_bus_resume(dhdp, 1);
		if (!ret) {
			if (dhd_sync_with_dongle(&dhd->pub) < 0) {
				DHD_ERROR(("%s(): Sync with dongle failed!!\n", __FUNCTION__));
				ret = -EFAULT;
			}
		} else {
			DHD_ERROR(("%s(): Failed to download, err=%d\n", __FUNCTION__, ret));
		}
	} else {
		DHD_ERROR(("%s(): BUS is already acquired, just increase the count %d \r\n",
			__FUNCTION__, dhd->bus_user_count));
	}
exit:
	mutex_unlock(&dhd->bus_user_lock);
	return ret;
}
EXPORT_SYMBOL(dhd_bus_get);

/* Return values:
 * Success: Returns 0
 * Failure: Returns -1 or errono code
 */
int
dhd_bus_put(wlan_bt_handle_t handle, bus_owner_t owner)
{
	dhd_pub_t *dhdp = (dhd_pub_t *)handle;
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;
	int ret = 0;
	BCM_REFERENCE(owner);

	mutex_lock(&dhd->bus_user_lock);
	--dhd->bus_user_count;
	if (dhd->bus_user_count < 0) {
		DHD_ERROR(("%s(): bus_user_count is negative, which is invalid\n", __FUNCTION__));
		dhd->bus_user_count = 0;
		ret = -1;
		goto exit;
	}

	if (dhd->bus_user_count == 0) {
		/* Last user, stop the bus and turn Off WL_REG */
		DHD_ERROR(("%s(): There are no owners left Trunf Off WL_REG & stop the bus \r\n",
			__FUNCTION__));
#ifdef PROP_TXSTATUS
		if (dhd->pub.wlfc_enabled) {
			dhd_wlfc_deinit(&dhd->pub);
		}
#endif /* PROP_TXSTATUS */
#ifdef PNO_SUPPORT
		if (dhd->pub.pno_state) {
			dhd_pno_deinit(&dhd->pub);
		}
#endif /* PNO_SUPPORT */
#ifdef RTT_SUPPORT
		if (dhd->pub.rtt_state) {
			dhd_rtt_deinit(&dhd->pub);
		}
#endif /* RTT_SUPPORT */
		ret = dhd_bus_devreset(dhdp, TRUE);
		if (!ret) {
			dhd_bus_suspend(dhdp);
			wifi_platform_set_power(dhd->adapter, FALSE, WIFI_TURNOFF_DELAY);
		}
	} else {
		DHD_ERROR(("%s(): Other owners using bus, decrease the count %d \r\n",
			__FUNCTION__, dhd->bus_user_count));
	}
exit:
	mutex_unlock(&dhd->bus_user_lock);
	return ret;
}
EXPORT_SYMBOL(dhd_bus_put);

int
dhd_net_bus_get(struct net_device *dev)
{
	dhd_info_t *dhd = DHD_DEV_INFO(dev);
	return dhd_bus_get(&dhd->pub, WLAN_MODULE);
}

int
dhd_net_bus_put(struct net_device *dev)
{
	dhd_info_t *dhd = DHD_DEV_INFO(dev);
	return dhd_bus_put(&dhd->pub, WLAN_MODULE);
}

/*
 * Function to enable the Bus Clock
 * Returns BCME_OK on success and BCME_xxx on failure
 *
 * This function is not callable from non-sleepable context
 */
int dhd_bus_clk_enable(wlan_bt_handle_t handle, bus_owner_t owner)
{
	dhd_pub_t *dhdp = (dhd_pub_t *)handle;

	int ret;

	dhd_os_sdlock(dhdp);
	/*
	 * The second argument is TRUE, that means, we expect
	 * the function to "wait" until the clocks are really
	 * available
	 */
	ret = __dhdsdio_clk_enable(dhdp->bus, owner, TRUE);
	dhd_os_sdunlock(dhdp);

	return ret;
}
EXPORT_SYMBOL(dhd_bus_clk_enable);

/*
 * Function to disable the Bus Clock
 * Returns BCME_OK on success and BCME_xxx on failure
 *
 * This function is not callable from non-sleepable context
 */
int dhd_bus_clk_disable(wlan_bt_handle_t handle, bus_owner_t owner)
{
	dhd_pub_t *dhdp = (dhd_pub_t *)handle;

	int ret;

	dhd_os_sdlock(dhdp);
	/*
	 * The second argument is TRUE, that means, we expect
	 * the function to "wait" until the clocks are really
	 * disabled
	 */
	ret = __dhdsdio_clk_disable(dhdp->bus, owner, TRUE);
	dhd_os_sdunlock(dhdp);

	return ret;
}
EXPORT_SYMBOL(dhd_bus_clk_disable);

/*
 * Function to reset bt_use_count counter to zero.
 *
 * This function is not callable from non-sleepable context
 */
void dhd_bus_reset_bt_use_count(wlan_bt_handle_t handle)
{
	dhd_pub_t *dhdp = (dhd_pub_t *)handle;

	/* take the lock and reset bt use count */
	dhd_os_sdlock(dhdp);
	dhdsdio_reset_bt_use_count(dhdp->bus);
	dhd_os_sdunlock(dhdp);
}
EXPORT_SYMBOL(dhd_bus_reset_bt_use_count);

void dhd_bus_retry_hang_recovery(wlan_bt_handle_t handle)
{
	dhd_pub_t *dhdp = (dhd_pub_t *)handle;
	dhd_info_t *dhd = (dhd_info_t*)dhdp->info;

	dhdp->hang_was_sent = 0;

	dhd_os_send_hang_message(&dhd->pub);
}
EXPORT_SYMBOL(dhd_bus_retry_hang_recovery);

#endif /* BT_OVER_SDIO */

static int
dhd_monitor_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	return 0;
}

static struct net_device_stats*
dhd_monitor_get_stats(struct net_device *dev)
{
	return &DHD_MON_DEV_STATS(dev);
}

static const struct net_device_ops netdev_monitor_ops =
{
	.ndo_start_xmit = dhd_monitor_start,
	.ndo_get_stats = dhd_monitor_get_stats,
	.ndo_do_ioctl = dhd_monitor_ioctl
};

static void
dhd_add_monitor_if(dhd_info_t *dhd)
{
	struct net_device *dev;
	char *devname;
	uint32 scan_suppress = FALSE;
	int ret = BCME_OK;

	if (!dhd) {
		DHD_ERROR(("%s: dhd info not available \n", __FUNCTION__));
		return;
	}

	if (dhd->monitor_dev) {
		DHD_ERROR(("%s: monitor i/f already exists", __FUNCTION__));
		return;
	}

	dev = alloc_etherdev(DHD_MON_DEV_PRIV_SIZE);
	if (!dev) {
		DHD_ERROR(("%s: alloc wlif failed\n", __FUNCTION__));
		return;
	}

	devname = "radiotap";

	snprintf(dev->name, sizeof(dev->name), "%s%u", devname, dhd->unit);

#ifndef ARPHRD_IEEE80211_PRISM  /* From Linux 2.4.18 */
#define ARPHRD_IEEE80211_PRISM 802
#endif // endif

#ifndef ARPHRD_IEEE80211_RADIOTAP
#define ARPHRD_IEEE80211_RADIOTAP	803 /* IEEE 802.11 + radiotap header */
#endif /* ARPHRD_IEEE80211_RADIOTAP */

	dev->type = ARPHRD_IEEE80211_RADIOTAP;

	dev->netdev_ops = &netdev_monitor_ops;

	if (register_netdevice(dev)) {
		DHD_ERROR(("%s, register_netdev failed for %s\n",
			__FUNCTION__, dev->name));
		free_netdev(dev);
		return;
	}

	if (FW_SUPPORTED((&dhd->pub), monitor)) {
		scan_suppress = TRUE;
		/* Set the SCAN SUPPRESS Flag in the firmware to disable scan in Monitor mode */
		ret = dhd_iovar(&dhd->pub, 0, "scansuppress", (char *)&scan_suppress,
			sizeof(scan_suppress), NULL, 0, TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s: scansuppress set failed, ret=%d\n", __FUNCTION__, ret));
		}
	}

	dhd->monitor_dev = dev;
}

static void
dhd_del_monitor_if(dhd_info_t *dhd)
{
	int ret = BCME_OK;
	uint32 scan_suppress = FALSE;

	if (!dhd) {
		DHD_ERROR(("%s: dhd info not available \n", __FUNCTION__));
		return;
	}

	if (!dhd->monitor_dev) {
		DHD_ERROR(("%s: monitor i/f doesn't exist", __FUNCTION__));
		return;
	}

	if (FW_SUPPORTED((&dhd->pub), monitor)) {
		scan_suppress = FALSE;
		/* Unset the SCAN SUPPRESS Flag in the firmware to enable scan */
		ret = dhd_iovar(&dhd->pub, 0, "scansuppress", (char *)&scan_suppress,
			sizeof(scan_suppress), NULL, 0, TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s: scansuppress set failed, ret=%d\n", __FUNCTION__, ret));
		}
	}

	if (dhd->monitor_dev) {
		if (dhd->monitor_dev->reg_state == NETREG_UNINITIALIZED) {
			free_netdev(dhd->monitor_dev);
		} else {
			unregister_netdevice(dhd->monitor_dev);
		}
		dhd->monitor_dev = NULL;
	}
}

void
dhd_set_monitor(dhd_pub_t *pub, int ifidx, int val)
{
	dhd_info_t *dhd = pub->info;

	DHD_TRACE(("%s: val %d\n", __FUNCTION__, val));

	dhd_net_if_lock_local(dhd);
	if (!val) {
			/* Delete monitor */
			dhd_del_monitor_if(dhd);
	} else {
			/* Add monitor */
			dhd_add_monitor_if(dhd);
	}
	dhd->monitor_type = val;
	dhd_net_if_unlock_local(dhd);
}
#endif /* WL_MONITOR */

#if defined(DHD_H2D_LOG_TIME_SYNC)
/*
 * Helper function:
 * Used for RTE console message time syncing with Host printk
 */
void dhd_h2d_log_time_sync_deferred_wq_schedule(dhd_pub_t *dhdp)
{
	dhd_info_t *info = dhdp->info;

	/* Ideally the "state" should be always TRUE */
	dhd_deferred_schedule_work(info->dhd_deferred_wq, NULL,
			DHD_WQ_WORK_H2D_CONSOLE_TIME_STAMP_MATCH,
			dhd_deferred_work_rte_log_time_sync,
			DHD_WQ_WORK_PRIORITY_LOW);
}

void
dhd_deferred_work_rte_log_time_sync(void *handle, void *event_info, u8 event)
{
	dhd_info_t *dhd_info = handle;
	dhd_pub_t *dhd;

	if (event != DHD_WQ_WORK_H2D_CONSOLE_TIME_STAMP_MATCH) {
		DHD_ERROR(("%s: unexpected event \n", __FUNCTION__));
		return;
	}

	if (!dhd_info) {
		DHD_ERROR(("%s: dhd info not available \n", __FUNCTION__));
		return;
	}

	dhd = &dhd_info->pub;

	/*
	 * Function to send IOVAR for console timesyncing
	 * between Host and Dongle.
	 * If the IOVAR fails,
	 * 1. dhd_rte_time_sync_ms is set to 0 and
	 * 2. HOST Dongle console time sync will *not* happen.
	 */
	dhd_h2d_log_time_sync(dhd);
}
#endif /* DHD_H2D_LOG_TIME_SYNC */

int dhd_ioctl_process(dhd_pub_t *pub, int ifidx, dhd_ioctl_t *ioc, void *data_buf)
{
	int bcmerror = BCME_OK;
	int buflen = 0;
	struct net_device *net;

	net = dhd_idx2net(pub, ifidx);
	if (!net) {
		bcmerror = BCME_BADARG;
		/*
		 * The netdev pointer is bad means the DHD can't communicate
		 * to higher layers, so just return from here
		 */
		return bcmerror;
	}

	/* check for local dhd ioctl and handle it */
	if (ioc->driver == DHD_IOCTL_MAGIC) {
		/* This is a DHD IOVAR, truncate buflen to DHD_IOCTL_MAXLEN */
		if (data_buf)
			buflen = MIN(ioc->len, DHD_IOCTL_MAXLEN);
		bcmerror = dhd_ioctl((void *)pub, ioc, data_buf, buflen);
		if (bcmerror)
			pub->bcmerror = bcmerror;
		goto done;
	}

	/* This is a WL IOVAR, truncate buflen to WLC_IOCTL_MAXLEN */
	if (data_buf)
		buflen = MIN(ioc->len, WLC_IOCTL_MAXLEN);

#ifndef BCMDBUS
	/* send to dongle (must be up, and wl). */
	if (pub->busstate == DHD_BUS_DOWN || pub->busstate == DHD_BUS_LOAD) {
		if ((!pub->dongle_trap_occured) && allow_delay_fwdl) {
			int ret;
			if (atomic_read(&exit_in_progress)) {
				DHD_ERROR(("%s module exit in progress\n", __func__));
				bcmerror = BCME_DONGLE_DOWN;
				goto done;
			}
			ret = dhd_bus_start(pub);
			if (ret != 0) {
				DHD_ERROR(("%s: failed with code %d\n", __FUNCTION__, ret));
				bcmerror = BCME_DONGLE_DOWN;
				goto done;
			}
		} else {
			bcmerror = BCME_DONGLE_DOWN;
			goto done;
		}
	}

	if (!pub->iswl) {
		bcmerror = BCME_DONGLE_DOWN;
		goto done;
	}
#endif /* !BCMDBUS */

	/*
	 * Flush the TX queue if required for proper message serialization:
	 * Intercept WLC_SET_KEY IOCTL - serialize M4 send and set key IOCTL to
	 * prevent M4 encryption and
	 * intercept WLC_DISASSOC IOCTL - serialize WPS-DONE and WLC_DISASSOC IOCTL to
	 * prevent disassoc frame being sent before WPS-DONE frame.
	 */
	if (ioc->cmd == WLC_SET_KEY ||
	    (ioc->cmd == WLC_SET_VAR && data_buf != NULL &&
	     strncmp("wsec_key", data_buf, 9) == 0) ||
	    (ioc->cmd == WLC_SET_VAR && data_buf != NULL &&
	     strncmp("bsscfg:wsec_key", data_buf, 15) == 0) ||
	    ioc->cmd == WLC_DISASSOC)
		dhd_wait_pend8021x(net);

	if ((ioc->cmd == WLC_SET_VAR || ioc->cmd == WLC_GET_VAR) &&
		data_buf != NULL && strncmp("rpc_", data_buf, 4) == 0) {
		bcmerror = BCME_UNSUPPORTED;
		goto done;
	}

	bcmerror = dhd_wl_ioctl(pub, ifidx, (wl_ioctl_t *)ioc, data_buf, buflen);

done:
	dhd_check_hang(net, pub, bcmerror);

	return bcmerror;
}

/**
 * Called by the OS (optionally via a wrapper function).
 * @param net  Linux per dongle instance
 * @param ifr  Linux request structure
 * @param cmd  e.g. SIOCETHTOOL
 */
static int
dhd_ioctl_entry(struct net_device *net, struct ifreq *ifr,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	void __user *data,
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(5, 15, 0) */
	int cmd)
{
	dhd_info_t *dhd = DHD_DEV_INFO(net);
	dhd_ioctl_t ioc;
	int bcmerror = 0;
	int ifidx;
	int ret;
	void *local_buf = NULL;           /**< buffer in kernel space */
	void __user *ioc_buf_user = NULL; /**< buffer in user space */
	u16 buflen = 0;

	if (atomic_read(&exit_in_progress)) {
		DHD_ERROR(("%s module exit in progress\n", __func__));
		bcmerror = BCME_DONGLE_DOWN;
		return OSL_ERROR(bcmerror);
	}

	DHD_OS_WAKE_LOCK(&dhd->pub);
	DHD_PERIM_LOCK(&dhd->pub);

	/* Interface up check for built-in type */
	if (!dhd_download_fw_on_driverload && dhd->pub.up == FALSE) {
		DHD_ERROR(("%s: Interface is down \n", __FUNCTION__));
		DHD_PERIM_UNLOCK(&dhd->pub);
		DHD_OS_WAKE_UNLOCK(&dhd->pub);
		return OSL_ERROR(BCME_NOTUP);
	}

	ifidx = dhd_net2idx(dhd, net);
	DHD_TRACE(("%s: ifidx %d, cmd 0x%04x\n", __FUNCTION__, ifidx, cmd));

#if defined(WL_STATIC_IF)
	/* skip for static ndev when it is down */
	if (dhd_is_static_ndev(&dhd->pub, net) && !(net->flags & IFF_UP)) {
		DHD_PERIM_UNLOCK(&dhd->pub);
		DHD_OS_WAKE_UNLOCK(&dhd->pub);
		return -1;
	}
#endif /* WL_STATIC_iF */

	if (ifidx == DHD_BAD_IF) {
		DHD_ERROR(("%s: BAD IF\n", __FUNCTION__));
		DHD_PERIM_UNLOCK(&dhd->pub);
		DHD_OS_WAKE_UNLOCK(&dhd->pub);
		return -1;
	}

#if defined(WL_WIRELESS_EXT)
	/* linux wireless extensions */
	if ((cmd >= SIOCIWFIRST) && (cmd <= SIOCIWLAST)) {
		/* may recurse, do NOT lock */
		ret = wl_iw_ioctl(net, ifr, cmd);
		DHD_PERIM_UNLOCK(&dhd->pub);
		DHD_OS_WAKE_UNLOCK(&dhd->pub);
		return ret;
	}
#endif /* defined(WL_WIRELESS_EXT) */

	if (cmd == SIOCETHTOOL) {
		ret = dhd_ethtool(dhd, (void*)ifr->ifr_data);
		DHD_PERIM_UNLOCK(&dhd->pub);
		DHD_OS_WAKE_UNLOCK(&dhd->pub);
		return ret;
	}

	if (cmd == SIOCDEVPRIVATE+1) {
		ret = wl_android_priv_cmd(net, ifr);
		dhd_check_hang(net, &dhd->pub, ret);
		DHD_PERIM_UNLOCK(&dhd->pub);
		DHD_OS_WAKE_UNLOCK(&dhd->pub);
		return ret;
	}

	if (cmd != SIOCDEVPRIVATE) {
		DHD_PERIM_UNLOCK(&dhd->pub);
		DHD_OS_WAKE_UNLOCK(&dhd->pub);
		return -EOPNOTSUPP;
	}

	memset(&ioc, 0, sizeof(ioc));

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	/* Copy the ioc control structure part of ioctl request */
	if (copy_from_user(&ioc, data, sizeof(wl_ioctl_t))) {
		bcmerror = BCME_BADADDR;
		goto done;
	}
	/* To differentiate between wl and dhd read 4 more byes */
	if ((copy_from_user(&ioc.driver, (char *)data + sizeof(wl_ioctl_t),
			sizeof(uint)) != 0)) {
		bcmerror = BCME_BADADDR;
		goto done;
	}
#else
#ifdef CONFIG_COMPAT
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0))
	if (in_compat_syscall())
#else
	if (is_compat_task()) 
#endif /* LINUX_VER >= 4.6 */
	{
		compat_wl_ioctl_t compat_ioc;
		if (copy_from_user(&compat_ioc, ifr->ifr_data, sizeof(compat_wl_ioctl_t))) {
			bcmerror = BCME_BADADDR;
			goto done;
		}
		ioc.cmd = compat_ioc.cmd;
		if (ioc.cmd & WLC_SPEC_FLAG) {
			memset(&ioc, 0, sizeof(ioc));
			/* Copy the ioc control structure part of ioctl request */
			if (copy_from_user(&ioc, ifr->ifr_data, sizeof(wl_ioctl_t))) {
				bcmerror = BCME_BADADDR;
				goto done;
			}
			ioc.cmd &= ~WLC_SPEC_FLAG; /* Clear the FLAG */

			/* To differentiate between wl and dhd read 4 more byes */
			if ((copy_from_user(&ioc.driver, (char *)ifr->ifr_data + sizeof(wl_ioctl_t),
				sizeof(uint)) != 0)) {
				bcmerror = BCME_BADADDR;
				goto done;
			}

		} else { /* ioc.cmd & WLC_SPEC_FLAG */
			ioc.buf = compat_ptr(compat_ioc.buf);
			ioc.len = compat_ioc.len;
			ioc.set = compat_ioc.set;
			ioc.used = compat_ioc.used;
			ioc.needed = compat_ioc.needed;
			/* To differentiate between wl and dhd read 4 more byes */
			if ((copy_from_user(&ioc.driver, (char *)ifr->ifr_data + sizeof(compat_wl_ioctl_t),
				sizeof(uint)) != 0)) {
				bcmerror = BCME_BADADDR;
				goto done;
			}
		} /* ioc.cmd & WLC_SPEC_FLAG */
	} else
#endif /* CONFIG_COMPAT */
	{
		/* Copy the ioc control structure part of ioctl request */
		if (copy_from_user(&ioc, ifr->ifr_data, sizeof(wl_ioctl_t))) {
			bcmerror = BCME_BADADDR;
			goto done;
		}
#ifdef CONFIG_COMPAT
		ioc.cmd &= ~WLC_SPEC_FLAG; /* make sure it was clear when it isn't a compat task*/
#endif

		/* To differentiate between wl and dhd read 4 more byes */
		if ((copy_from_user(&ioc.driver, (char *)ifr->ifr_data + sizeof(wl_ioctl_t),
			sizeof(uint)) != 0)) {
			bcmerror = BCME_BADADDR;
			goto done;
		}
	}
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(5, 15, 0) */

	if (!capable(CAP_NET_ADMIN)) {
		bcmerror = BCME_EPERM;
		goto done;
	}

	/* Take backup of ioc.buf and restore later */
	ioc_buf_user = ioc.buf;

	if (ioc.len > 0) {
		buflen = MIN(ioc.len, DHD_IOCTL_MAXLEN);
		if (!(local_buf = MALLOC(dhd->pub.osh, buflen+1))) {
			bcmerror = BCME_NOMEM;
			goto done;
		}

		DHD_PERIM_UNLOCK(&dhd->pub);
		if (copy_from_user(local_buf, ioc.buf, buflen)) {
			DHD_PERIM_LOCK(&dhd->pub);
			bcmerror = BCME_BADADDR;
			goto done;
		}
		DHD_PERIM_LOCK(&dhd->pub);

		*((char *)local_buf + buflen) = '\0';

		/* For some platforms accessing userspace memory
		 * of ioc.buf is causing kernel panic, so to avoid that
		 * make ioc.buf pointing to kernel space memory local_buf
		 */
		ioc.buf = local_buf;
	}

	/* Skip all the non DHD iovars (wl iovars) after f/w hang */
	if (ioc.driver != DHD_IOCTL_MAGIC && dhd->pub.hang_was_sent) {
		DHD_TRACE(("%s: HANG was sent up earlier\n", __FUNCTION__));
		DHD_OS_WAKE_LOCK_CTRL_TIMEOUT_ENABLE(&dhd->pub, DHD_EVENT_TIMEOUT_MS);
		bcmerror = BCME_DONGLE_DOWN;
		goto done;
	}

	bcmerror = dhd_ioctl_process(&dhd->pub, ifidx, &ioc, local_buf);

	/* Restore back userspace pointer to ioc.buf */
	ioc.buf = ioc_buf_user;

	if (!bcmerror && buflen && local_buf && ioc.buf) {
		DHD_PERIM_UNLOCK(&dhd->pub);
		if (copy_to_user(ioc.buf, local_buf, buflen))
			bcmerror = -EFAULT;
		DHD_PERIM_LOCK(&dhd->pub);
	}

done:
	if (local_buf)
		MFREE(dhd->pub.osh, local_buf, buflen+1);

	DHD_PERIM_UNLOCK(&dhd->pub);
	DHD_OS_WAKE_UNLOCK(&dhd->pub);

	return OSL_ERROR(bcmerror);
}

#if defined(WL_CFG80211) && defined(SUPPORT_DEEP_SLEEP)
/* Flags to indicate if we distingish power off policy when
 * user set the memu "Keep Wi-Fi on during sleep" to "Never"
 */
int trigger_deep_sleep = 0;
#endif /* WL_CFG80211 && SUPPORT_DEEP_SLEEP */

#ifdef FIX_CPU_MIN_CLOCK
static int dhd_init_cpufreq_fix(dhd_info_t *dhd)
{
	if (dhd) {
		mutex_init(&dhd->cpufreq_fix);
		dhd->cpufreq_fix_status = FALSE;
	}
	return 0;
}

static void dhd_fix_cpu_freq(dhd_info_t *dhd)
{
	mutex_lock(&dhd->cpufreq_fix);
	if (dhd && !dhd->cpufreq_fix_status) {
		pm_qos_add_request(&dhd->dhd_cpu_qos, PM_QOS_CPU_FREQ_MIN, 300000);
#ifdef FIX_BUS_MIN_CLOCK
		pm_qos_add_request(&dhd->dhd_bus_qos, PM_QOS_BUS_THROUGHPUT, 400000);
#endif /* FIX_BUS_MIN_CLOCK */
		DHD_ERROR(("pm_qos_add_requests called\n"));

		dhd->cpufreq_fix_status = TRUE;
	}
	mutex_unlock(&dhd->cpufreq_fix);
}

static void dhd_rollback_cpu_freq(dhd_info_t *dhd)
{
	mutex_lock(&dhd ->cpufreq_fix);
	if (dhd && dhd->cpufreq_fix_status != TRUE) {
		mutex_unlock(&dhd->cpufreq_fix);
		return;
	}

	pm_qos_remove_request(&dhd->dhd_cpu_qos);
#ifdef FIX_BUS_MIN_CLOCK
	pm_qos_remove_request(&dhd->dhd_bus_qos);
#endif /* FIX_BUS_MIN_CLOCK */
	DHD_ERROR(("pm_qos_add_requests called\n"));

	dhd->cpufreq_fix_status = FALSE;
	mutex_unlock(&dhd->cpufreq_fix);
}
#endif /* FIX_CPU_MIN_CLOCK */

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
static int
dhd_ioctl_entry_wrapper(struct net_device *net, struct ifreq *ifr,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	void __user *data, 
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(5, 15, 0) */
	int cmd)
{
	int error;
	dhd_info_t *dhd = DHD_DEV_INFO(net);

	if (atomic_read(&dhd->pub.block_bus))
		return -EHOSTDOWN;

	if (pm_runtime_get_sync(dhd_bus_to_dev(dhd->pub.bus)) < 0)
		return BCME_ERROR;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	error = dhd_ioctl_entry(net, ifr, data, cmd);
#else
	error = dhd_ioctl_entry(net, ifr, cmd);
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(5, 15, 0) */

	pm_runtime_mark_last_busy(dhd_bus_to_dev(dhd->pub.bus));
	pm_runtime_put_autosuspend(dhd_bus_to_dev(dhd->pub.bus));

	return error;
}
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

static int
dhd_stop(struct net_device *net)
{
	int ifidx = 0;
	bool skip_reset = false;
#if defined(WL_CFG80211)
	unsigned long flags = 0;
#ifdef WL_STATIC_IF
	struct bcm_cfg80211 *cfg = wl_get_cfg(net);
#endif /* WL_STATIC_IF */
#endif /* WL_CFG80211 */
	dhd_info_t *dhd = DHD_DEV_INFO(net);
	DHD_OS_WAKE_LOCK(&dhd->pub);
	DHD_PERIM_LOCK(&dhd->pub);
	WL_MSG(net->name, "Enter\n");
	dhd->pub.rxcnt_timeout = 0;
	dhd->pub.txcnt_timeout = 0;

#ifdef BCMPCIE
	dhd->pub.d3ackcnt_timeout = 0;
#endif /* BCMPCIE */

	mutex_lock(&dhd->pub.ndev_op_sync);

	if (dhd->pub.up == 0) {
		goto exit;
	}

	dhd_if_flush_sta(DHD_DEV_IFP(net));

#ifdef FIX_CPU_MIN_CLOCK
	if (dhd_get_fw_mode(dhd) == DHD_FLAG_HOSTAP_MODE)
		dhd_rollback_cpu_freq(dhd);
#endif /* FIX_CPU_MIN_CLOCK */

	ifidx = dhd_net2idx(dhd, net);
	BCM_REFERENCE(ifidx);

	DHD_ERROR(("%s: ######### dhd_stop called for ifidx=%d #########\n", __FUNCTION__, ifidx));

#if defined(WL_STATIC_IF) && defined(WL_CFG80211)
	/* If static if is operational, don't reset the chip */
	if (wl_cfg80211_static_if_active(cfg)) {
		WL_MSG(net->name, "static if operational. skip chip reset.\n");
		skip_reset = true;
		wl_cfg80211_sta_ifdown(net);
		goto exit;
	}
#endif /* WL_STATIC_IF && WL_CFG80211 */
#ifdef DHD_NOTIFY_MAC_CHANGED
	if (dhd->pub.skip_dhd_stop) {
		WL_MSG(net->name, "skip chip reset.\n");
		skip_reset = true;
#if defined(WL_CFG80211)
		wl_cfg80211_sta_ifdown(net);
#endif /* WL_CFG80211 */
		goto exit;
	}
#endif /* DHD_NOTIFY_MAC_CHANGED */

	DHD_ERROR(("%s: making dhdpub up FALSE\n", __FUNCTION__));
#ifdef WL_CFG80211

	/* Disable Runtime PM before interface down */
	DHD_DISABLE_RUNTIME_PM(&dhd->pub);

	spin_lock_irqsave(&dhd->pub.up_lock, flags);
	dhd->pub.up = 0;
	spin_unlock_irqrestore(&dhd->pub.up_lock, flags);
#else
	dhd->pub.up = 0;
#endif /* WL_CFG80211 */

#ifdef WL_CFG80211
	if (ifidx == 0) {
		dhd_if_t *ifp;
		wl_cfg80211_down(net);

		ifp = dhd->iflist[0];
		/*
		 * For CFG80211: Clean up all the left over virtual interfaces
		 * when the primary Interface is brought down. [ifconfig wlan0 down]
		 */
		if (!dhd_download_fw_on_driverload) {
			DHD_STATLOG_CTRL(&dhd->pub, ST(WLAN_POWER_OFF), ifidx, 0);
			if ((dhd->dhd_state & DHD_ATTACH_STATE_ADD_IF) &&
				(dhd->dhd_state & DHD_ATTACH_STATE_CFG80211)) {
				int i;
#ifdef WL_CFG80211_P2P_DEV_IF
				wl_cfg80211_del_p2p_wdev(net);
#endif /* WL_CFG80211_P2P_DEV_IF */
#ifdef DHD_4WAYM4_FAIL_DISCONNECT
				dhd_cleanup_m4_state_work(&dhd->pub, ifidx);
#endif /* DHD_4WAYM4_FAIL_DISCONNECT */
#ifdef DHD_PKTDUMP_ROAM
				dhd_dump_pkt_clear(&dhd->pub);
#endif /* DHD_PKTDUMP_ROAM */

				dhd_net_if_lock_local(dhd);
				for (i = 1; i < DHD_MAX_IFS; i++)
					dhd_remove_if(&dhd->pub, i, FALSE);

				if (ifp && ifp->net) {
					dhd_if_del_sta_list(ifp);
				}
#ifdef ARP_OFFLOAD_SUPPORT
				if (dhd_inetaddr_notifier_registered) {
					dhd_inetaddr_notifier_registered = FALSE;
					unregister_inetaddr_notifier(&dhd_inetaddr_notifier);
				}
#endif /* ARP_OFFLOAD_SUPPORT */
#if defined(CONFIG_IPV6) && defined(IPV6_NDO_SUPPORT)
				if (dhd_inet6addr_notifier_registered) {
					dhd_inet6addr_notifier_registered = FALSE;
					unregister_inet6addr_notifier(&dhd_inet6addr_notifier);
				}
#endif /* CONFIG_IPV6 && IPV6_NDO_SUPPORT */
				dhd_net_if_unlock_local(dhd);
			}
#if 0
			// terence 20161024: remove this to prevent dev_close() get stuck in dhd_hang_process
			cancel_work_sync(dhd->dhd_deferred_wq);
#endif

#ifdef SHOW_LOGTRACE
			/* Wait till event logs work/kthread finishes */
			dhd_cancel_logtrace_process_sync(dhd);
#endif /* SHOW_LOGTRACE */

#if defined(DHD_LB_RXP)
			__skb_queue_purge(&dhd->rx_pend_queue);
#endif /* DHD_LB_RXP */

#if defined(DHD_LB_TXP)
			skb_queue_purge(&dhd->tx_pend_queue);
#endif /* DHD_LB_TXP */
		}

#if defined(ARGOS_NOTIFY_CB)
		argos_register_notifier_deinit();
#endif // endif
#ifdef DHDTCPACK_SUPPRESS
		dhd_tcpack_suppress_set(&dhd->pub, TCPACK_SUP_OFF);
#endif /* DHDTCPACK_SUPPRESS */
#if defined(DHD_LB_RXP)
		if (ifp && ifp->net == dhd->rx_napi_netdev) {
			DHD_INFO(("%s napi<%p> disabled ifp->net<%p,%s>\n",
				__FUNCTION__, &dhd->rx_napi_struct, net, net->name));
			skb_queue_purge(&dhd->rx_napi_queue);
			napi_disable(&dhd->rx_napi_struct);
			netif_napi_del(&dhd->rx_napi_struct);
			dhd->rx_napi_netdev = NULL;
		}
#endif /* DHD_LB_RXP */
	}
#endif /* WL_CFG80211 */

	DHD_SSSR_DUMP_DEINIT(&dhd->pub);

#ifdef PROP_TXSTATUS
	dhd_wlfc_cleanup(&dhd->pub, NULL, 0);
#endif // endif
#ifdef SHOW_LOGTRACE
	if (!dhd_download_fw_on_driverload) {
		/* Release the skbs from queue for WLC_E_TRACE event */
		dhd_event_logtrace_flush_queue(&dhd->pub);
		if (dhd->dhd_state & DHD_ATTACH_LOGTRACE_INIT) {
			if (dhd->event_data.fmts) {
				MFREE(dhd->pub.osh, dhd->event_data.fmts,
					dhd->event_data.fmts_size);
				dhd->event_data.fmts = NULL;
			}
			if (dhd->event_data.raw_fmts) {
				MFREE(dhd->pub.osh, dhd->event_data.raw_fmts,
					dhd->event_data.raw_fmts_size);
				dhd->event_data.raw_fmts = NULL;
			}
			if (dhd->event_data.raw_sstr) {
				MFREE(dhd->pub.osh, dhd->event_data.raw_sstr,
					dhd->event_data.raw_sstr_size);
				dhd->event_data.raw_sstr = NULL;
			}
			if (dhd->event_data.rom_raw_sstr) {
				MFREE(dhd->pub.osh, dhd->event_data.rom_raw_sstr,
					dhd->event_data.rom_raw_sstr_size);
				dhd->event_data.rom_raw_sstr = NULL;
			}
			dhd->dhd_state &= ~DHD_ATTACH_LOGTRACE_INIT;
		}
	}
#endif /* SHOW_LOGTRACE */
#ifdef APF
	dhd_dev_apf_delete_filter(net);
#endif /* APF */

	/* Stop the protocol module */
	dhd_prot_stop(&dhd->pub);

	OLD_MOD_DEC_USE_COUNT;
exit:
	if (skip_reset == false) {
#ifdef WL_ESCAN
		if (ifidx == 0) {
			wl_escan_down(net);
		}
#endif /* WL_ESCAN */
		if (ifidx == 0 && !dhd_download_fw_on_driverload) {
#if defined(BT_OVER_SDIO)
			dhd_bus_put(&dhd->pub, WLAN_MODULE);
			wl_android_set_wifi_on_flag(FALSE);
#else
			wl_android_wifi_off(net, TRUE);
#ifdef WL_EXT_IAPSTA
			wl_ext_iapsta_dettach_netdev(net, ifidx);
#endif /* WL_EXT_IAPSTA */
#ifdef WL_ESCAN
			wl_escan_event_dettach(net, ifidx);
#endif /* WL_ESCAN */
#ifdef WL_EVENT
			wl_ext_event_dettach_netdev(net, ifidx);
#endif /* WL_EVENT */
#endif /* BT_OVER_SDIO */
		}
#ifdef SUPPORT_DEEP_SLEEP
		else {
			/* CSP#505233: Flags to indicate if we distingish
			 * power off policy when user set the memu
			 * "Keep Wi-Fi on during sleep" to "Never"
			 */
			if (trigger_deep_sleep) {
				dhd_deepsleep(net, 1);
				trigger_deep_sleep = 0;
			}
		}
#endif /* SUPPORT_DEEP_SLEEP */
		dhd->pub.hang_was_sent = 0;
		dhd->pub.hang_was_pending = 0;

		/* Clear country spec for for built-in type driver */
		if (!dhd_download_fw_on_driverload) {
			dhd->pub.dhd_cspec.country_abbrev[0] = 0x00;
			dhd->pub.dhd_cspec.rev = 0;
			dhd->pub.dhd_cspec.ccode[0] = 0x00;
		}

#ifdef BCMDBGFS
		dhd_dbgfs_remove();
#endif // endif
	}

	DHD_PERIM_UNLOCK(&dhd->pub);
	DHD_OS_WAKE_UNLOCK(&dhd->pub);

	/* Destroy wakelock */
	if (!dhd_download_fw_on_driverload &&
		(dhd->dhd_state & DHD_ATTACH_STATE_WAKELOCKS_INIT) &&
		(skip_reset == false)) {
		DHD_OS_WAKE_LOCK_DESTROY(dhd);
		dhd->dhd_state &= ~DHD_ATTACH_STATE_WAKELOCKS_INIT;
	}
	WL_MSG(net->name, "Exit\n");

	mutex_unlock(&dhd->pub.ndev_op_sync);
	return 0;
}

#if defined(WL_CFG80211) && (defined(USE_INITIAL_2G_SCAN) || \
	defined(USE_INITIAL_SHORT_DWELL_TIME))
extern bool g_first_broadcast_scan;
#endif /* OEM_ANDROID && WL_CFG80211 && (USE_INITIAL_2G_SCAN || USE_INITIAL_SHORT_DWELL_TIME) */

#ifdef WL11U
static int dhd_interworking_enable(dhd_pub_t *dhd)
{
	uint32 enable = true;
	int ret = BCME_OK;

	ret = dhd_iovar(dhd, 0, "interworking", (char *)&enable, sizeof(enable), NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s: enableing interworking failed, ret=%d\n", __FUNCTION__, ret));
	}

	return ret;
}
#endif /* WL11u */

static int
dhd_open(struct net_device *net)
{
	dhd_info_t *dhd = DHD_DEV_INFO(net);
#ifdef TOE
	uint32 toe_ol;
#endif // endif
	int ifidx;
	int32 ret = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
#if defined(OOB_INTR_ONLY)
	uint32 bus_type = -1;
	uint32 bus_num = -1;
	uint32 slot_num = -1;
	wifi_adapter_info_t *adapter = NULL;
#endif
#endif /* LINUX_VERSION >= KERNEL_VERSION(2, 6, 35)  */
#if defined(WL_EXT_IAPSTA) && defined(ISAM_PREINIT)
	int bytes_written = 0;
#endif
#ifdef SCAN_SUPPRESS
	struct wl_apsta_params *apsta_params = (struct wl_apsta_params *)dhd->pub.iapsta_params;
#endif

	mutex_lock(&dhd->pub.ndev_op_sync);
	
#ifdef SCAN_SUPPRESS
	apsta_params->scan_busy_cnt = 0;
#endif

	if (dhd->pub.up == 1) {
		/* already up */
		WL_MSG(net->name, "Primary net_device is already up\n");
		mutex_unlock(&dhd->pub.ndev_op_sync);
		return BCME_OK;
	}

	if (!dhd_download_fw_on_driverload) {
		if (!dhd_driver_init_done) {
			DHD_ERROR(("%s: WLAN driver is not initialized\n", __FUNCTION__));
			mutex_unlock(&dhd->pub.ndev_op_sync);
			return -1;
		}
	}

	WL_MSG(net->name, "Enter\n");
	DHD_ERROR(("%s\n", dhd_version));
	/* Init wakelock */
	if (!dhd_download_fw_on_driverload) {
		if (!(dhd->dhd_state & DHD_ATTACH_STATE_WAKELOCKS_INIT)) {
			DHD_OS_WAKE_LOCK_INIT(dhd);
			dhd->dhd_state |= DHD_ATTACH_STATE_WAKELOCKS_INIT;
		}

#ifdef SHOW_LOGTRACE
		skb_queue_head_init(&dhd->evt_trace_queue);

		if (!(dhd->dhd_state & DHD_ATTACH_LOGTRACE_INIT)) {
			ret = dhd_init_logstrs_array(dhd->pub.osh, &dhd->event_data);
			if (ret == BCME_OK) {
				dhd_init_static_strs_array(dhd->pub.osh, &dhd->event_data,
					st_str_file_path, map_file_path);
				dhd_init_static_strs_array(dhd->pub.osh, &dhd->event_data,
					rom_st_str_file_path, rom_map_file_path);
				dhd->dhd_state |= DHD_ATTACH_LOGTRACE_INIT;
			}
		}
#endif /* SHOW_LOGTRACE */
	}

	DHD_OS_WAKE_LOCK(&dhd->pub);
	DHD_PERIM_LOCK(&dhd->pub);
	dhd->pub.dongle_trap_occured = 0;
	dhd->pub.hang_was_sent = 0;
	dhd->pub.hang_was_pending = 0;
	dhd->pub.hang_reason = 0;
	dhd->pub.iovar_timeout_occured = 0;
#ifdef PCIE_FULL_DONGLE
	dhd->pub.d3ack_timeout_occured = 0;
	dhd->pub.livelock_occured = 0;
	dhd->pub.pktid_audit_failed = 0;
#endif /* PCIE_FULL_DONGLE */
	dhd->pub.iface_op_failed = 0;
	dhd->pub.scan_timeout_occurred = 0;
	dhd->pub.scan_busy_occurred = 0;
	dhd->pub.smmu_fault_occurred = 0;

#ifdef DHD_LOSSLESS_ROAMING
	dhd->pub.dequeue_prec_map = ALLPRIO;
#endif // endif

#if 0
	/*
	 * Force start if ifconfig_up gets called before START command
	 *  We keep WEXT's wl_control_wl_start to provide backward compatibility
	 *  This should be removed in the future
	 */
	ret = wl_control_wl_start(net);
	if (ret != 0) {
		DHD_ERROR(("%s: failed with code %d\n", __FUNCTION__, ret));
		ret = -1;
		goto exit;
	}

#endif // endif

	ifidx = dhd_net2idx(dhd, net);
	DHD_TRACE(("%s: ifidx %d\n", __FUNCTION__, ifidx));

	if (ifidx < 0) {
		DHD_ERROR(("%s: Error: called with invalid IF\n", __FUNCTION__));
		ret = -1;
		goto exit;
	}

	if (!dhd->iflist[ifidx]) {
		DHD_ERROR(("%s: Error: called when IF already deleted\n", __FUNCTION__));
		ret = -1;
		goto exit;
	}

	if (ifidx == 0) {
		atomic_set(&dhd->pend_8021x_cnt, 0);
		if (!dhd_download_fw_on_driverload) {
			DHD_STATLOG_CTRL(&dhd->pub, ST(WLAN_POWER_ON), ifidx, 0);
#ifdef WL_EVENT
			wl_ext_event_attach_netdev(net, ifidx, dhd->iflist[ifidx]->bssidx);
#endif /* WL_EVENT */
#ifdef WL_ESCAN
			wl_escan_event_attach(net, ifidx);
#endif /* WL_ESCAN */
#ifdef WL_EXT_IAPSTA
			wl_ext_iapsta_attach_netdev(net, ifidx, dhd->iflist[ifidx]->bssidx);
#endif /* WL_EXT_IAPSTA */
#if defined(USE_INITIAL_2G_SCAN) || defined(USE_INITIAL_SHORT_DWELL_TIME)
			g_first_broadcast_scan = TRUE;
#endif /* USE_INITIAL_2G_SCAN || USE_INITIAL_SHORT_DWELL_TIME */
#ifdef SHOW_LOGTRACE
			/* dhd_cancel_logtrace_process_sync is called in dhd_stop
			 * for built-in models. Need to start logtrace kthread before
			 * calling wifi on, because once wifi is on, EDL will be in action
			 * any moment, and if kthread is not active, FW event logs will
			 * not be available
			 */
			if (dhd_reinit_logtrace_process(dhd) != BCME_OK) {
				goto exit;
			}
#endif /* SHOW_LOGTRACE */
#if defined(BT_OVER_SDIO)
			ret = dhd_bus_get(&dhd->pub, WLAN_MODULE);
			wl_android_set_wifi_on_flag(TRUE);
#else
			ret = wl_android_wifi_on(net);
#endif /* BT_OVER_SDIO */
			if (ret != 0) {
				DHD_ERROR(("%s : wl_android_wifi_on failed (%d)\n",
					__FUNCTION__, ret));
				ret = -1;
				goto exit;
			}
		}
#ifdef SUPPORT_DEEP_SLEEP
		else {
			/* Flags to indicate if we distingish
			 * power off policy when user set the memu
			 * "Keep Wi-Fi on during sleep" to "Never"
			 */
			if (trigger_deep_sleep) {
#if defined(USE_INITIAL_2G_SCAN) || defined(USE_INITIAL_SHORT_DWELL_TIME)
				g_first_broadcast_scan = TRUE;
#endif /* USE_INITIAL_2G_SCAN || USE_INITIAL_SHORT_DWELL_TIME */
				dhd_deepsleep(net, 0);
				trigger_deep_sleep = 0;
			}
		}
#endif /* SUPPORT_DEEP_SLEEP */
#ifdef FIX_CPU_MIN_CLOCK
		if (dhd_get_fw_mode(dhd) == DHD_FLAG_HOSTAP_MODE) {
			dhd_init_cpufreq_fix(dhd);
			dhd_fix_cpu_freq(dhd);
		}
#endif /* FIX_CPU_MIN_CLOCK */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
#if defined(OOB_INTR_ONLY)
		if (dhd->pub.conf->dpc_cpucore >= 0) {
			dhd_bus_get_ids(dhd->pub.bus, &bus_type, &bus_num, &slot_num);
			adapter = dhd_wifi_platform_get_adapter(bus_type, bus_num, slot_num);
			if (adapter) {
				printf("%s: set irq affinity hit %d\n", __FUNCTION__, dhd->pub.conf->dpc_cpucore);
				irq_set_affinity_hint(adapter->irq_num, cpumask_of(dhd->pub.conf->dpc_cpucore));
			}
		}
#endif
#endif /* LINUX_VERSION >= KERNEL_VERSION(2, 6, 35)  */

		if (dhd->pub.busstate != DHD_BUS_DATA) {
#ifdef BCMDBUS
			dhd_set_path(&dhd->pub);
			DHD_MUTEX_UNLOCK();
			wait_event_interruptible_timeout(dhd->adapter->status_event,
				wifi_get_adapter_status(dhd->adapter, WIFI_STATUS_FW_READY),
				msecs_to_jiffies(DHD_FW_READY_TIMEOUT));
			DHD_MUTEX_LOCK();
			if ((ret = dbus_up(dhd->pub.bus)) != 0) {
				DHD_ERROR(("%s: failed to dbus_up with code %d\n", __FUNCTION__, ret));
				goto exit;
			} else {
				dhd->pub.busstate = DHD_BUS_DATA;
			}
			if ((ret = dhd_sync_with_dongle(&dhd->pub)) < 0) {
				DHD_ERROR(("%s: failed with code %d\n", __FUNCTION__, ret));
				goto exit;
			}
#else
			/* try to bring up bus */
			DHD_PERIM_UNLOCK(&dhd->pub);

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
			if (pm_runtime_get_sync(dhd_bus_to_dev(dhd->pub.bus)) >= 0) {
				ret = dhd_bus_start(&dhd->pub);
				pm_runtime_mark_last_busy(dhd_bus_to_dev(dhd->pub.bus));
				pm_runtime_put_autosuspend(dhd_bus_to_dev(dhd->pub.bus));
			}
#else
			ret = dhd_bus_start(&dhd->pub);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

			DHD_PERIM_LOCK(&dhd->pub);
			if (ret) {
				DHD_ERROR(("%s: failed with code %d\n", __FUNCTION__, ret));
				ret = -1;
				goto exit;
			}
#endif /* !BCMDBUS */

		}
#ifdef WL_EXT_IAPSTA
		wl_ext_iapsta_attach_name(net, ifidx);
#endif

#ifdef BT_OVER_SDIO
		if (dhd->pub.is_bt_recovery_required) {
			DHD_ERROR(("%s: Send Hang Notification 2 to BT\n", __FUNCTION__));
			bcmsdh_btsdio_process_dhd_hang_notification(TRUE);
		}
		dhd->pub.is_bt_recovery_required = FALSE;
#endif // endif

		/* dhd_sync_with_dongle has been called in dhd_bus_start or wl_android_wifi_on */
		memcpy(net->dev_addr, dhd->pub.mac.octet, ETHER_ADDR_LEN);

#ifdef TOE
		/* Get current TOE mode from dongle */
		if (dhd_toe_get(dhd, ifidx, &toe_ol) >= 0 && (toe_ol & TOE_TX_CSUM_OL) != 0) {
			dhd->iflist[ifidx]->net->features |= NETIF_F_IP_CSUM;
		} else {
			dhd->iflist[ifidx]->net->features &= ~NETIF_F_IP_CSUM;
		}
#endif /* TOE */

#if defined(DHD_LB_RXP)
		__skb_queue_head_init(&dhd->rx_pend_queue);
		if (dhd->rx_napi_netdev == NULL) {
			dhd->rx_napi_netdev = dhd->iflist[ifidx]->net;
			memset(&dhd->rx_napi_struct, 0, sizeof(struct napi_struct));
			netif_napi_add(dhd->rx_napi_netdev, &dhd->rx_napi_struct,
				dhd_napi_poll, dhd_napi_weight);
			DHD_INFO(("%s napi<%p> enabled ifp->net<%p,%s>\n",
				__FUNCTION__, &dhd->rx_napi_struct, net, net->name));
			napi_enable(&dhd->rx_napi_struct);
			DHD_INFO(("%s load balance init rx_napi_struct\n", __FUNCTION__));
			skb_queue_head_init(&dhd->rx_napi_queue);
		} /* rx_napi_netdev == NULL */
#endif /* DHD_LB_RXP */

#if defined(DHD_LB_TXP)
		/* Use the variant that uses locks */
		skb_queue_head_init(&dhd->tx_pend_queue);
#endif /* DHD_LB_TXP */

#if defined(WL_CFG80211)
		if (unlikely(wl_cfg80211_up(net))) {
			DHD_ERROR(("%s: failed to bring up cfg80211\n", __FUNCTION__));
			ret = -1;
			goto exit;
		}
		if (!dhd_download_fw_on_driverload) {
#ifdef ARP_OFFLOAD_SUPPORT
			dhd->pend_ipaddr = 0;
			if (!dhd_inetaddr_notifier_registered) {
				dhd_inetaddr_notifier_registered = TRUE;
				register_inetaddr_notifier(&dhd_inetaddr_notifier);
			}
#endif /* ARP_OFFLOAD_SUPPORT */
#if defined(CONFIG_IPV6) && defined(IPV6_NDO_SUPPORT)
			if (!dhd_inet6addr_notifier_registered) {
				dhd_inet6addr_notifier_registered = TRUE;
				register_inet6addr_notifier(&dhd_inet6addr_notifier);
			}
#endif /* CONFIG_IPV6 && IPV6_NDO_SUPPORT */
		}

#if defined(DHD_CONTROL_PCIE_ASPM_WIFI_TURNON)
		dhd_bus_aspm_enable_rc_ep(dhd->pub.bus, TRUE);
#endif /* DHD_CONTROL_PCIE_ASPM_WIFI_TURNON */
#if defined(DHD_CONTROL_PCIE_CPUCORE_WIFI_TURNON)
		dhd_irq_set_affinity(&dhd->pub, cpumask_of(0));
#endif /* DHD_CONTROL_PCIE_CPUCORE_WIFI_TURNON */
#ifdef DHD_LB_IRQSET
		dhd_irq_set_affinity(&dhd->pub, dhd->cpumask_primary);
#endif /* DHD_LB_IRQSET */
#if defined(ARGOS_NOTIFY_CB)
		argos_register_notifier_init(net);
#endif // endif
#if defined(NUM_SCB_MAX_PROBE)
		dhd_set_scb_probe(&dhd->pub);
#endif /* NUM_SCB_MAX_PROBE */
#endif /* WL_CFG80211 */
#ifdef WL_ESCAN
		if (unlikely(wl_escan_up(net))) {
			DHD_ERROR(("%s: failed to bring up escan\n", __FUNCTION__));
			ret = -1;
			goto exit;
		}
#endif /* WL_ESCAN */
#if defined(ISAM_PREINIT)
		if (!dhd_download_fw_on_driverload) {
			if (dhd->pub.conf) {
				wl_android_ext_priv_cmd(net, dhd->pub.conf->isam_init, 0, &bytes_written);
				wl_android_ext_priv_cmd(net, dhd->pub.conf->isam_config, 0, &bytes_written);
				wl_android_ext_priv_cmd(net, dhd->pub.conf->isam_enable, 0, &bytes_written);
			}
		}
#endif
	}

	dhd->pub.up = 1;

	if (wl_event_enable) {
		/* For wl utility to receive events */
		dhd->pub.wl_event_enabled = true;
	} else {
		dhd->pub.wl_event_enabled = false;
	}

	if (logtrace_pkt_sendup) {
		/* For any deamon to recieve logtrace */
		dhd->pub.logtrace_pkt_sendup = true;
	} else {
		dhd->pub.logtrace_pkt_sendup = false;
	}

	OLD_MOD_INC_USE_COUNT;

#ifdef BCMDBGFS
	dhd_dbgfs_init(&dhd->pub);
#endif // endif

exit:
	mutex_unlock(&dhd->pub.ndev_op_sync);
#if defined(ENABLE_INSMOD_NO_FW_LOAD) && defined(NO_POWER_OFF_AFTER_OPEN)
	dhd_download_fw_on_driverload = TRUE;
	dhd_driver_init_done = TRUE;
#elif defined(ENABLE_INSMOD_NO_FW_LOAD) && defined(ENABLE_INSMOD_NO_POWER_OFF)
	dhd_download_fw_on_driverload = FALSE;
	dhd_driver_init_done = TRUE;
#endif
	if (ret) {
		dhd_stop(net);
	}

	DHD_PERIM_UNLOCK(&dhd->pub);
	DHD_OS_WAKE_UNLOCK(&dhd->pub);

	WL_MSG(net->name, "Exit ret=%d\n", ret);
	return ret;
}

/*
 * ndo_start handler for primary ndev
 */
static int
dhd_pri_open(struct net_device *net)
{
	s32 ret;
	s32 max_cnt = 0;

	DHD_MUTEX_IS_LOCK_RETURN();
	DHD_MUTEX_LOCK();

	while (++max_cnt <= 5) {
		ret = dhd_open(net);
		if (unlikely(ret)) {
			DHD_ERROR(("Failed to open primary dev ret %d, cnt=%d\n", ret, max_cnt));
			msleep(20);
			continue;
		}
		else {
			break;
		}
	}

	if (unlikely(ret)) {
        DHD_ERROR(("Failed to open primary dev ret %d, cnt=%d, oooo\n", ret, max_cnt));
        DHD_MUTEX_UNLOCK();
        return ret;
    }

	/* Allow transmit calls */
	netif_start_queue(net);
	WL_MSG(net->name, "tx queue started\n");

#if defined(SET_RPS_CPUS)
	dhd_rps_cpus_enable(net, TRUE);
#endif

#if defined(SET_XPS_CPUS)
	dhd_xps_cpus_enable(net, TRUE);
#endif
	DHD_MUTEX_UNLOCK();

	return ret;
}

/*
 * ndo_stop handler for primary ndev
 */
static int
dhd_pri_stop(struct net_device *net)
{
	s32 ret;

	/* stop tx queue */
	netif_stop_queue(net);
	WL_MSG(net->name, "tx queue stopped\n");

	ret = dhd_stop(net);
	if (unlikely(ret)) {
		DHD_ERROR(("dhd_stop failed: %d\n", ret));
		return ret;
	}

	return ret;
}

#if defined(WL_STATIC_IF) && defined(WL_CFG80211)
/*
 * For static I/Fs, the firmware interface init
 * is done from the IFF_UP context.
 */
static int
dhd_static_if_open(struct net_device *net)
{
	s32 ret = 0;
	struct bcm_cfg80211 *cfg;
	struct net_device *primary_netdev = NULL;
#ifdef WLEASYMESH
	dhd_info_t *dhd = DHD_DEV_INFO(net);
#endif /* WLEASYMESH */

	DHD_MUTEX_LOCK();
	cfg = wl_get_cfg(net);
	primary_netdev = bcmcfg_to_prmry_ndev(cfg);

	if (!wl_cfg80211_static_if(cfg, net)) {
		WL_MSG(net->name, "non-static interface ..do nothing\n");
		ret = BCME_OK;
		goto done;
	}

	WL_MSG(net->name, "Enter\n");
	/* Ensure fw is initialized. If it is already initialized,
	 * dhd_open will return success.
	 */
#ifdef WLEASYMESH
	WL_MSG(net->name, "switch to EasyMesh fw\n");
	dhd->pub.conf->fw_type = FW_TYPE_EZMESH;
	ret = dhd_stop(primary_netdev);
	if (unlikely(ret)) {
		printf("===>%s, Failed to close primary dev ret %d\n", __FUNCTION__, ret);
		goto done;
	}
	OSL_SLEEP(1);
#endif /* WLEASYMESH */
	ret = dhd_open(primary_netdev);
	if (unlikely(ret)) {
		DHD_ERROR(("Failed to open primary dev ret %d\n", ret));
		goto done;
	}

	ret = wl_cfg80211_static_if_open(net);
	if (!ret) {
		/* Allow transmit calls */
		netif_start_queue(net);
	}
done:
	WL_MSG(net->name, "Exit ret=%d\n", ret);
	DHD_MUTEX_UNLOCK();
	return ret;
}

static int
dhd_static_if_stop(struct net_device *net)
{
	struct bcm_cfg80211 *cfg;
	struct net_device *primary_netdev = NULL;
	int ret = BCME_OK;
	dhd_info_t *dhd = DHD_DEV_INFO(net);

	WL_MSG(net->name, "Enter\n");

	cfg = wl_get_cfg(net);
	if (!wl_cfg80211_static_if(cfg, net)) {
		DHD_TRACE(("non-static interface (%s)..do nothing \n", net->name));
		return BCME_OK;
	}
#ifdef DHD_NOTIFY_MAC_CHANGED
	if (dhd->pub.skip_dhd_stop) {
		WL_MSG(net->name, "Exit skip stop\n");
		return BCME_OK;
	}
#endif /* DHD_NOTIFY_MAC_CHANGED */

	/* Ensure queue is disabled */
	netif_tx_disable(net);

	dhd_net_if_lock_local(dhd);
	ret = wl_cfg80211_static_if_close(net);
	dhd_net_if_unlock_local(dhd);

	if (dhd->pub.up == 0) {
		/* If fw is down, return */
		DHD_ERROR(("fw down\n"));
		return BCME_OK;
	}
	/* If STA iface is not in operational, invoke dhd_close from this
	* context.
	*/
	primary_netdev = bcmcfg_to_prmry_ndev(cfg);
#ifdef WLEASYMESH
	if (dhd->pub.conf->fw_type == FW_TYPE_EZMESH) {
		WL_MSG(net->name, "switch to STA fw\n");
		dhd->pub.conf->fw_type = FW_TYPE_STA;
	} else
#endif /* WLEASYMESH */
	if (!(primary_netdev->flags & IFF_UP)) {
		ret = dhd_stop(primary_netdev);
	} else {
		DHD_ERROR(("Skipped dhd_stop, as sta is operational\n"));
	}
	WL_MSG(net->name, "Exit ret=%d\n", ret);

	return ret;
}
#endif /* WL_STATIC_IF && WL_CF80211 */

int dhd_do_driver_init(struct net_device *net)
{
	dhd_info_t *dhd = NULL;
	int ret = 0;

	if (!net) {
		DHD_ERROR(("Primary Interface not initialized \n"));
		return -EINVAL;
	}

	DHD_MUTEX_IS_LOCK_RETURN();
	DHD_MUTEX_LOCK();

	/*  && defined(OEM_ANDROID) && defined(BCMSDIO) */
	dhd = DHD_DEV_INFO(net);

	/* If driver is already initialized, do nothing
	 */
	if (dhd->pub.busstate == DHD_BUS_DATA) {
		DHD_TRACE(("Driver already Inititalized. Nothing to do"));
		goto exit;
	}

	if (dhd_open(net) < 0) {
		DHD_ERROR(("Driver Init Failed \n"));
		ret = -1;
		goto exit;
	}

exit:
	DHD_MUTEX_UNLOCK();
	return ret;
}

int
dhd_event_ifadd(dhd_info_t *dhdinfo, wl_event_data_if_t *ifevent, char *name, uint8 *mac)
{

#ifdef WL_CFG80211
		if (wl_cfg80211_notify_ifadd(dhd_linux_get_primary_netdev(&dhdinfo->pub),
			ifevent->ifidx, name, mac, ifevent->bssidx, ifevent->role) == BCME_OK)
		return BCME_OK;
#endif // endif

	/* handle IF event caused by wl commands, SoftAP, WEXT and
	 * anything else. This has to be done asynchronously otherwise
	 * DPC will be blocked (and iovars will timeout as DPC has no chance
	 * to read the response back)
	 */
	if (ifevent->ifidx > 0) {
		dhd_if_event_t *if_event = MALLOC(dhdinfo->pub.osh, sizeof(dhd_if_event_t));
		if (if_event == NULL) {
			DHD_ERROR(("dhd_event_ifadd: Failed MALLOC, malloced %d bytes",
				MALLOCED(dhdinfo->pub.osh)));
			return BCME_NOMEM;
		}

		memcpy(&if_event->event, ifevent, sizeof(if_event->event));
		memcpy(if_event->mac, mac, ETHER_ADDR_LEN);
		strncpy(if_event->name, name, IFNAMSIZ);
		if_event->name[IFNAMSIZ - 1] = '\0';
		dhd_deferred_schedule_work(dhdinfo->dhd_deferred_wq, (void *)if_event,
			DHD_WQ_WORK_IF_ADD, dhd_ifadd_event_handler, DHD_WQ_WORK_PRIORITY_LOW);
	}

	return BCME_OK;
}

int
dhd_event_ifdel(dhd_info_t *dhdinfo, wl_event_data_if_t *ifevent, char *name, uint8 *mac)
{
	dhd_if_event_t *if_event;

#ifdef WL_CFG80211
		if (wl_cfg80211_notify_ifdel(dhd_linux_get_primary_netdev(&dhdinfo->pub),
			ifevent->ifidx, name, mac, ifevent->bssidx) == BCME_OK)
		return BCME_OK;
#endif /* WL_CFG80211 */

	/* handle IF event caused by wl commands, SoftAP, WEXT and
	 * anything else
	 */
	if_event = MALLOC(dhdinfo->pub.osh, sizeof(dhd_if_event_t));
	if (if_event == NULL) {
		DHD_ERROR(("dhd_event_ifdel: malloc failed for if_event, malloced %d bytes",
			MALLOCED(dhdinfo->pub.osh)));
		return BCME_NOMEM;
	}
	memcpy(&if_event->event, ifevent, sizeof(if_event->event));
	memcpy(if_event->mac, mac, ETHER_ADDR_LEN);
	strncpy(if_event->name, name, IFNAMSIZ);
	if_event->name[IFNAMSIZ - 1] = '\0';
	dhd_deferred_schedule_work(dhdinfo->dhd_deferred_wq, (void *)if_event, DHD_WQ_WORK_IF_DEL,
		dhd_ifdel_event_handler, DHD_WQ_WORK_PRIORITY_LOW);

	return BCME_OK;
}

int
dhd_event_ifchange(dhd_info_t *dhdinfo, wl_event_data_if_t *ifevent, char *name, uint8 *mac)
{
#ifdef DHD_UPDATE_INTF_MAC
	dhd_if_event_t *if_event;
#endif /* DHD_UPDATE_INTF_MAC */

#ifdef WL_CFG80211
	wl_cfg80211_notify_ifchange(dhd_linux_get_primary_netdev(&dhdinfo->pub),
		ifevent->ifidx, name, mac, ifevent->bssidx);
#endif /* WL_CFG80211 */

#ifdef DHD_UPDATE_INTF_MAC
	/* handle IF event caused by wl commands, SoftAP, WEXT, MBSS and
	 * anything else
	 */
	if_event = MALLOC(dhdinfo->pub.osh, sizeof(dhd_if_event_t));
	if (if_event == NULL) {
		DHD_ERROR(("dhd_event_ifdel: malloc failed for if_event, malloced %d bytes",
			MALLOCED(dhdinfo->pub.osh)));
		return BCME_NOMEM;
	}
	memcpy(&if_event->event, ifevent, sizeof(if_event->event));
	// construct a change event
	if_event->event.ifidx = dhd_ifname2idx(dhdinfo, name);
	if_event->event.opcode = WLC_E_IF_CHANGE;
	memcpy(if_event->mac, mac, ETHER_ADDR_LEN);
	strncpy(if_event->name, name, IFNAMSIZ);
	if_event->name[IFNAMSIZ - 1] = '\0';
	dhd_deferred_schedule_work(dhdinfo->dhd_deferred_wq, (void *)if_event, DHD_WQ_WORK_IF_UPDATE,
		dhd_ifupdate_event_handler, DHD_WQ_WORK_PRIORITY_LOW);
#endif /* DHD_UPDATE_INTF_MAC */

	return BCME_OK;
}

#ifdef WL_NATOE
/* Handler to update natoe info and bind with new subscriptions if there is change in config */
static void
dhd_natoe_ct_event_hanlder(void *handle, void *event_info, u8 event)
{
	dhd_info_t *dhd = handle;
	wl_event_data_natoe_t *natoe = event_info;
	dhd_nfct_info_t *nfct = dhd->pub.nfct;

	if (event != DHD_WQ_WORK_NATOE_EVENT) {
		DHD_ERROR(("%s: unexpected event \n", __FUNCTION__));
		return;
	}

	if (!dhd) {
		DHD_ERROR(("%s: dhd info not available \n", __FUNCTION__));
		return;
	}
	if (natoe->natoe_active && natoe->sta_ip && natoe->start_port && natoe->end_port &&
			(natoe->start_port < natoe->end_port)) {
		/* Rebind subscriptions to start receiving notifications from groups */
		if (dhd_ct_nl_bind(nfct, nfct->subscriptions) < 0) {
			dhd_ct_close(nfct);
		}
		dhd_ct_send_dump_req(nfct);
	} else if (!natoe->natoe_active) {
		/* Rebind subscriptions to stop receiving notifications from groups */
		if (dhd_ct_nl_bind(nfct, CT_NULL_SUBSCRIPTION) < 0) {
			dhd_ct_close(nfct);
		}
	}
}

/* As NATOE enable/disbale event is received, we have to bind with new NL subscriptions.
 * Scheduling workq to switch from tasklet context as bind call may sleep in handler
 */
int
dhd_natoe_ct_event(dhd_pub_t *dhd, char *data)
{
	wl_event_data_natoe_t *event_data = (wl_event_data_natoe_t *)data;

	if (dhd->nfct) {
		wl_event_data_natoe_t *natoe = dhd->nfct->natoe_info;
		uint8 prev_enable = natoe->natoe_active;

		spin_lock_bh(&dhd->nfct_lock);
		memcpy(natoe, event_data, sizeof(*event_data));
		spin_unlock_bh(&dhd->nfct_lock);

		if (prev_enable != event_data->natoe_active) {
			dhd_deferred_schedule_work(dhd->info->dhd_deferred_wq,
					(void *)natoe, DHD_WQ_WORK_NATOE_EVENT,
					dhd_natoe_ct_event_hanlder, DHD_WQ_WORK_PRIORITY_LOW);
		}
		return BCME_OK;
	}
	DHD_ERROR(("%s ERROR NFCT is not enabled \n", __FUNCTION__));
	return BCME_ERROR;
}

/* Handler to send natoe ioctl to dongle */
static void
dhd_natoe_ct_ioctl_handler(void *handle, void *event_info, uint8 event)
{
	dhd_info_t *dhd = handle;
	dhd_ct_ioc_t *ct_ioc = event_info;

	if (event != DHD_WQ_WORK_NATOE_IOCTL) {
		DHD_ERROR(("%s: unexpected event \n", __FUNCTION__));
		return;
	}

	if (!dhd) {
		DHD_ERROR(("%s: dhd info not available \n", __FUNCTION__));
		return;
	}

	if (dhd_natoe_prep_send_exception_port_ioctl(&dhd->pub, ct_ioc) < 0) {
		DHD_ERROR(("%s: Error in sending NATOE IOCTL \n", __FUNCTION__));
	}
}

/* When Netlink message contains port collision info, the info must be sent to dongle FW
 * For that we have to switch context from softirq/tasklet by scheduling workq for natoe_ct ioctl
 */
void
dhd_natoe_ct_ioctl_schedule_work(dhd_pub_t *dhd, dhd_ct_ioc_t *ioc)
{

	dhd_deferred_schedule_work(dhd->info->dhd_deferred_wq, (void *)ioc,
			DHD_WQ_WORK_NATOE_IOCTL, dhd_natoe_ct_ioctl_handler,
			DHD_WQ_WORK_PRIORITY_HIGH);
}
#endif /* WL_NATOE */

/* This API maps ndev to ifp inclusive of static IFs */
static dhd_if_t *
dhd_get_ifp_by_ndev(dhd_pub_t *dhdp, struct net_device *ndev)
{
	dhd_if_t *ifp = NULL;
#ifdef WL_STATIC_IF
	u32 ifidx = (DHD_MAX_IFS + DHD_MAX_STATIC_IFS - 1);
#else
	u32 ifidx = (DHD_MAX_IFS - 1);
#endif /* WL_STATIC_IF */

	dhd_info_t *dhdinfo = (dhd_info_t *)dhdp->info;
	do {
		ifp = dhdinfo->iflist[ifidx];
		if (ifp && (ifp->net == ndev)) {
			DHD_TRACE(("match found for %s. ifidx:%d\n",
				ndev->name, ifidx));
			return ifp;
		}
	} while (ifidx--);

	DHD_ERROR(("no entry found for %s\n", ndev->name));
	return NULL;
}

bool
dhd_is_static_ndev(dhd_pub_t *dhdp, struct net_device *ndev)
{
	dhd_if_t *ifp = NULL;

	if (!dhdp || !ndev) {
		DHD_ERROR(("wrong input\n"));
		ASSERT(0);
		return false;
	}

	ifp = dhd_get_ifp_by_ndev(dhdp, ndev);
	return (ifp && (ifp->static_if == true));
}

#ifdef WL_STATIC_IF
/* In some cases, while registering I/F, the actual ifidx, bssidx and dngl_name
 * are not known. For e.g: static i/f case. This function lets to update it once
 * it is known.
 */
s32
dhd_update_iflist_info(dhd_pub_t *dhdp, struct net_device *ndev, int ifidx,
	uint8 *mac, uint8 bssidx, const char *dngl_name, int if_state)
{
	dhd_info_t *dhdinfo = (dhd_info_t *)dhdp->info;
	dhd_if_t *ifp, *ifp_new;
	s32 cur_idx;
	dhd_dev_priv_t * dev_priv;

	DHD_TRACE(("[STATIC_IF] update ifinfo for state:%d ifidx:%d\n",
			if_state, ifidx));

	ASSERT(dhdinfo && (ifidx < (DHD_MAX_IFS + DHD_MAX_STATIC_IFS)));

	if ((ifp = dhd_get_ifp_by_ndev(dhdp, ndev)) == NULL) {
		return -ENODEV;
	}
	cur_idx = ifp->idx;

	if (if_state == NDEV_STATE_OS_IF_CREATED) {
		/* mark static if */
		ifp->static_if = TRUE;
		return BCME_OK;
	}

	ifp_new = dhdinfo->iflist[ifidx];
	if (ifp_new && (ifp_new != ifp)) {
		/* There should be only one entry for a given ifidx. */
		DHD_ERROR(("ifp ptr already present for ifidx:%d\n", ifidx));
		ASSERT(0);
		dhdp->hang_reason = HANG_REASON_IFACE_ADD_FAILURE;
		net_os_send_hang_message(ifp->net);
		return -EINVAL;
	}

	/* For static if delete case, cleanup the if before ifidx update */
	if ((if_state == NDEV_STATE_FW_IF_DELETED) ||
		(if_state == NDEV_STATE_FW_IF_FAILED)) {
		dhd_cleanup_if(ifp->net);
		dev_priv = DHD_DEV_PRIV(ndev);
		dev_priv->ifidx = ifidx;
	}

	/* update the iflist ifidx slot with cached info */
	dhdinfo->iflist[ifidx] = ifp;
	dhdinfo->iflist[cur_idx] = NULL;

	/* update the values */
	ifp->idx = ifidx;
	ifp->bssidx = bssidx;

	if (if_state == NDEV_STATE_FW_IF_CREATED) {
		dhd_dev_priv_save(ndev, dhdinfo, ifp, ifidx);
		/* initialize the dongle provided if name */
		if (dngl_name) {
			strlcpy(ifp->dngl_name, dngl_name, IFNAMSIZ);
		} else if (ndev->name[0] != '\0') {
			strlcpy(ifp->dngl_name, ndev->name, IFNAMSIZ);
		}
		if (mac != NULL) {
			(void)memcpy_s(&ifp->mac_addr, ETHER_ADDR_LEN, mac, ETHER_ADDR_LEN);
		}
#ifdef WL_EVENT
		wl_ext_event_attach_netdev(ndev, ifidx, bssidx);
#endif /* WL_EVENT */
#ifdef WL_ESCAN
		wl_escan_event_attach(ndev, ifidx);
#endif /* WL_ESCAN */
#ifdef WL_EXT_IAPSTA
		wl_ext_iapsta_ifadding(ndev, ifidx);
		wl_ext_iapsta_attach_netdev(ndev, ifidx, bssidx);
		wl_ext_iapsta_attach_name(ndev, ifidx);
#endif /* WL_EXT_IAPSTA */
	}
	else if (if_state == NDEV_STATE_FW_IF_DELETED) {
#ifdef WL_EXT_IAPSTA
		wl_ext_iapsta_dettach_netdev(ndev, cur_idx);
#endif /* WL_EXT_IAPSTA */
#ifdef WL_ESCAN
		wl_escan_event_dettach(ndev, cur_idx);
#endif /* WL_ESCAN */
#ifdef WL_EVENT
		wl_ext_event_dettach_netdev(ndev, cur_idx);
#endif /* WL_EVENT */
	}
	DHD_INFO(("[STATIC_IF] ifp ptr updated for ifidx:%d curidx:%d if_state:%d\n",
		ifidx, cur_idx, if_state));
	return BCME_OK;
}
#endif /* WL_STATIC_IF */

#ifdef CONFIG_AP6XXX_WIFI6_HDF
struct net_device * get_krn_netdev(int ifidx);

int get_dhd_priv_data_size(void)
{
    return DHD_DEV_PRIV_SIZE;
}

const static struct net_device_ops *hdf_netdev_ops = NULL;

#endif

/* unregister and free the existing net_device interface (if any) in iflist and
 * allocate a new one. the slot is reused. this function does NOT register the
 * new interface to linux kernel. dhd_register_if does the job
 */
struct net_device*
dhd_allocate_if(dhd_pub_t *dhdpub, int ifidx, const char *name,
	uint8 *mac, uint8 bssidx, bool need_rtnl_lock, const char *dngl_name)
{
	dhd_info_t *dhdinfo = (dhd_info_t *)dhdpub->info;
	dhd_if_t *ifp;

#ifdef CONFIG_AP6XXX_WIFI6_HDF
	DHD_ERROR(("%s: bdh6: create netdevice %s hdfidx=%d, ifidx=%d, bssidx=%u\n", __FUNCTION__, name, g_hdf_ifidx, ifidx, bssidx));
#else
	DHD_ERROR(("%s: bdh6: create netdevice %s ifidx=%d, bssidx=%u\n", __FUNCTION__, name, ifidx, bssidx));
#endif

	ASSERT(dhdinfo && (ifidx < (DHD_MAX_IFS + DHD_MAX_STATIC_IFS)));

	ifp = dhdinfo->iflist[ifidx];

	if (ifp != NULL) {
		if (ifp->net != NULL) {
			DHD_ERROR(("%s: free existing IF %s ifidx:%d \n",
				__FUNCTION__, ifp->net->name, ifidx));

			if (ifidx == 0) {
				/* For primary ifidx (0), there shouldn't be
				 * any netdev present already.
				 */
				DHD_ERROR(("Primary ifidx populated already\n"));
				ASSERT(0);
				return NULL;
			}

			dhd_dev_priv_clear(ifp->net); /* clear net_device private */

			/* in unregister_netdev case, the interface gets freed by net->destructor
			 * (which is set to free_netdev)
			 */
			if (ifp->net->reg_state == NETREG_UNINITIALIZED) {
				free_netdev(ifp->net);
			} else {
				netif_stop_queue(ifp->net);
				if (need_rtnl_lock)
					unregister_netdev(ifp->net);
				else
					unregister_netdevice(ifp->net);
			}
			ifp->net = NULL;
		}
	} else {
		ifp = MALLOC(dhdinfo->pub.osh, sizeof(dhd_if_t));
		if (ifp == NULL) {
			DHD_ERROR(("%s: OOM - dhd_if_t(%zu)\n", __FUNCTION__, sizeof(dhd_if_t)));
			return NULL;
		}
	}

	memset(ifp, 0, sizeof(dhd_if_t));
	ifp->info = dhdinfo;
	ifp->idx = ifidx;
	ifp->bssidx = bssidx;
#ifdef DHD_MCAST_REGEN
	ifp->mcast_regen_bss_enable = FALSE;
#endif // endif
	/* set to TRUE rx_pkt_chainable at alloc time */
	ifp->rx_pkt_chainable = TRUE;

	if (mac != NULL)
		memcpy(&ifp->mac_addr, mac, ETHER_ADDR_LEN);

	/* Allocate etherdev, including space for private structure */
#ifdef CONFIG_AP6XXX_WIFI6_HDF
	ifp->net = get_krn_netdev(g_hdf_ifidx);
	if (0 == g_hdf_ifidx) {
        hdf_netdev_ops = ifp->net->netdev_ops;
	}
#else
	ifp->net = alloc_etherdev(DHD_DEV_PRIV_SIZE);
#endif
	if (ifp->net == NULL) {
		DHD_ERROR(("%s: OOM - alloc_etherdev(%zu)\n", __FUNCTION__, sizeof(dhdinfo)));
		goto fail;
	}

	/* Setup the dhd interface's netdevice private structure. */
	dhd_dev_priv_save(ifp->net, dhdinfo, ifp, ifidx);

	if (name && name[0]) {
		strncpy(ifp->net->name, name, IFNAMSIZ);
		ifp->net->name[IFNAMSIZ - 1] = '\0';
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 9))
#define IFP_NET_DESTRUCTOR	ifp->net->priv_destructor
#else
#define IFP_NET_DESTRUCTOR	ifp->net->destructor
#endif // endif

#ifdef WL_CFG80211
	if (ifidx == 0) {
		IFP_NET_DESTRUCTOR = free_netdev;
	} else {
		IFP_NET_DESTRUCTOR = dhd_netdev_free;
	}
#else
	IFP_NET_DESTRUCTOR = free_netdev;
#endif /* WL_CFG80211 */
	strncpy(ifp->name, ifp->net->name, IFNAMSIZ);
	ifp->name[IFNAMSIZ - 1] = '\0';
	dhdinfo->iflist[ifidx] = ifp;

	/* initialize the dongle provided if name */
	if (dngl_name) {
		strncpy(ifp->dngl_name, dngl_name, IFNAMSIZ);
	} else if (name) {
		strncpy(ifp->dngl_name, name, IFNAMSIZ);
	}

#ifdef PCIE_FULL_DONGLE
	/* Initialize STA info list */
	INIT_LIST_HEAD(&ifp->sta_list);
	DHD_IF_STA_LIST_LOCK_INIT(ifp);
#endif /* PCIE_FULL_DONGLE */

#ifdef DHD_L2_FILTER
	ifp->phnd_arp_table = init_l2_filter_arp_table(dhdpub->osh);
	ifp->parp_allnode = TRUE;
#endif /* DHD_L2_FILTER */

	DHD_CUMM_CTR_INIT(&ifp->cumm_ctr);

#ifdef DHD_4WAYM4_FAIL_DISCONNECT
	INIT_DELAYED_WORK(&ifp->m4state_work, dhd_m4_state_handler);
#endif /* DHD_4WAYM4_FAIL_DISCONNECT */

#ifdef DHD_POST_EAPOL_M1_AFTER_ROAM_EVT
	ifp->recv_reassoc_evt = FALSE;
	ifp->post_roam_evt = FALSE;
#endif /* DHD_POST_EAPOL_M1_AFTER_ROAM_EVT */

#ifdef DHDTCPSYNC_FLOOD_BLK
	INIT_WORK(&ifp->blk_tsfl_work, dhd_blk_tsfl_handler);
	dhd_reset_tcpsync_info_by_ifp(ifp);
#endif /* DHDTCPSYNC_FLOOD_BLK */

	return ifp->net;

fail:
	if (ifp != NULL) {
		if (ifp->net != NULL) {
#if defined(DHD_LB_RXP) && defined(PCIE_FULL_DONGLE)
			if (ifp->net == dhdinfo->rx_napi_netdev) {
				napi_disable(&dhdinfo->rx_napi_struct);
				netif_napi_del(&dhdinfo->rx_napi_struct);
				skb_queue_purge(&dhdinfo->rx_napi_queue);
				dhdinfo->rx_napi_netdev = NULL;
			}
#endif /* DHD_LB_RXP && PCIE_FULL_DONGLE */
			dhd_dev_priv_clear(ifp->net);
			free_netdev(ifp->net);
			ifp->net = NULL;
		}
		MFREE(dhdinfo->pub.osh, ifp, sizeof(*ifp));
		ifp = NULL;
	}

	dhdinfo->iflist[ifidx] = NULL;
	return NULL;
}

static void
dhd_cleanup_ifp(dhd_pub_t *dhdp, dhd_if_t *ifp)
{
#ifdef PCIE_FULL_DONGLE
	s32 ifidx = 0;
	if_flow_lkup_t *if_flow_lkup = (if_flow_lkup_t *)dhdp->if_flow_lkup;
#endif /* PCIE_FULL_DONGLE */

	if (ifp != NULL) {
		if ((ifp->idx < 0) || (ifp->idx >= DHD_MAX_IFS)) {
			DHD_ERROR(("Wrong idx:%d \n", ifp->idx));
			ASSERT(0);
			return;
		}
#ifdef DHD_L2_FILTER
		bcm_l2_filter_arp_table_update(dhdpub->osh, ifp->phnd_arp_table, TRUE,
			NULL, FALSE, dhdpub->tickcnt);
		deinit_l2_filter_arp_table(dhdpub->osh, ifp->phnd_arp_table);
		ifp->phnd_arp_table = NULL;
#endif /* DHD_L2_FILTER */

		dhd_if_del_sta_list(ifp);
#ifdef PCIE_FULL_DONGLE
		/* Delete flowrings of virtual interface */
		ifidx = ifp->idx;
		if ((ifidx != 0) && (if_flow_lkup[ifidx].role != WLC_E_IF_ROLE_AP)) {
			dhd_flow_rings_delete(dhdp, ifidx);
		}
#endif /* PCIE_FULL_DONGLE */
	}
}

void
dhd_cleanup_if(struct net_device *net)
{
	dhd_info_t *dhdinfo = DHD_DEV_INFO(net);
	dhd_pub_t *dhdp = &dhdinfo->pub;
	dhd_if_t *ifp;

	if (!(ifp = dhd_get_ifp_by_ndev(dhdp, net)) ||
			(ifp->idx >= DHD_MAX_IFS)) {
		DHD_ERROR(("Wrong ifidx: %p, %d\n", ifp, ifp ? ifp->idx : -1));
		ASSERT(0);
		return;
	}

	dhd_cleanup_ifp(dhdp, ifp);
}

/* unregister and free the the net_device interface associated with the indexed
 * slot, also free the slot memory and set the slot pointer to NULL
 */
#define DHD_TX_COMPLETION_TIMEOUT 5000
int
dhd_remove_if(dhd_pub_t *dhdpub, int ifidx, bool need_rtnl_lock)
{
	dhd_info_t *dhdinfo = (dhd_info_t *)dhdpub->info;
	dhd_if_t *ifp;
	unsigned long flags;
	long timeout;

	ifp = dhdinfo->iflist[ifidx];

	if (ifp != NULL) {
#ifdef DHD_4WAYM4_FAIL_DISCONNECT
		cancel_delayed_work_sync(&ifp->m4state_work);
#endif /* DHD_4WAYM4_FAIL_DISCONNECT */

#ifdef DHDTCPSYNC_FLOOD_BLK
		cancel_work_sync(&ifp->blk_tsfl_work);
#endif /* DHDTCPSYNC_FLOOD_BLK */

#ifdef WL_STATIC_IF
		/* static IF will be handled in detach */
		if (ifp->static_if) {
			DHD_TRACE(("Skip del iface for static interface\n"));
			return BCME_OK;
		}
#endif /* WL_STATIC_IF */
		if (ifp->net != NULL) {
			DHD_ERROR(("deleting interface '%s' idx %d\n", ifp->net->name, ifp->idx));

			DHD_GENERAL_LOCK(dhdpub, flags);
			ifp->del_in_progress = true;
			DHD_GENERAL_UNLOCK(dhdpub, flags);

			/* If TX is in progress, hold the if del */
			if (DHD_IF_IS_TX_ACTIVE(ifp)) {
				DHD_INFO(("TX in progress. Wait for it to be complete."));
				timeout = wait_event_timeout(dhdpub->tx_completion_wait,
					((ifp->tx_paths_active & DHD_TX_CONTEXT_MASK) == 0),
					msecs_to_jiffies(DHD_TX_COMPLETION_TIMEOUT));
				if (!timeout) {
					/* Tx completion timeout. Attempt proceeding ahead */
					DHD_ERROR(("Tx completion timed out!\n"));
					ASSERT(0);
				}
			} else {
				DHD_TRACE(("No outstanding TX!\n"));
			}
			dhdinfo->iflist[ifidx] = NULL;
			/* in unregister_netdev case, the interface gets freed by net->destructor
			 * (which is set to free_netdev)
			 */
			if (ifp->net->reg_state == NETREG_UNINITIALIZED) {
				free_netdev(ifp->net);
			} else {
				netif_tx_disable(ifp->net);

#if defined(SET_RPS_CPUS)
				custom_rps_map_clear(ifp->net->_rx);
#endif /* SET_RPS_CPUS */
#if defined(SET_RPS_CPUS)
#if (defined(DHDTCPACK_SUPPRESS) && defined(BCMPCIE))
				dhd_tcpack_suppress_set(dhdpub, TCPACK_SUP_OFF);
#endif /* DHDTCPACK_SUPPRESS && BCMPCIE */
#endif // endif
				if (need_rtnl_lock)
					unregister_netdev(ifp->net);
				else
					unregister_netdevice(ifp->net);
#ifdef WL_EXT_IAPSTA
				wl_ext_iapsta_dettach_netdev(ifp->net, ifidx);
#endif /* WL_EXT_IAPSTA */
#ifdef WL_ESCAN
				wl_escan_event_dettach(ifp->net, ifidx);
#endif /* WL_ESCAN */
#ifdef WL_EVENT
				wl_ext_event_dettach_netdev(ifp->net, ifidx);
#endif /* WL_EVENT */
			}
			ifp->net = NULL;
			DHD_GENERAL_LOCK(dhdpub, flags);
			ifp->del_in_progress = false;
			DHD_GENERAL_UNLOCK(dhdpub, flags);
		}
		dhd_cleanup_ifp(dhdpub, ifp);
		DHD_CUMM_CTR_INIT(&ifp->cumm_ctr);

		MFREE(dhdinfo->pub.osh, ifp, sizeof(*ifp));
		ifp = NULL;
	}

	return BCME_OK;
}

#ifndef CONFIG_AP6XXX_WIFI6_HDF
static 
#endif
struct net_device_ops dhd_ops_pri = {
	.ndo_open = dhd_pri_open,
	.ndo_stop = dhd_pri_stop,
	.ndo_get_stats = dhd_get_stats,
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	.ndo_siocdevprivate = dhd_ioctl_entry_wrapper,
#else
	.ndo_do_ioctl = dhd_ioctl_entry_wrapper,
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(5, 15, 0) */
	.ndo_start_xmit = dhd_start_xmit_wrapper,
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	.ndo_siocdevprivate = dhd_ioctl_entry,
#else
	.ndo_do_ioctl = dhd_ioctl_entry,
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(5, 15, 0) */
	.ndo_start_xmit = dhd_start_xmit,
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */
	.ndo_set_mac_address = dhd_set_mac_address,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0))
	.ndo_set_rx_mode = dhd_set_multicast_list,
#else
	.ndo_set_multicast_list = dhd_set_multicast_list,
#endif // endif
};

static struct net_device_ops dhd_ops_virt = {
#if defined(WL_CFG80211) && defined(WL_STATIC_IF)
	.ndo_open = dhd_static_if_open,
	.ndo_stop = dhd_static_if_stop,
#endif // endif
	.ndo_get_stats = dhd_get_stats,
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	.ndo_siocdevprivate = dhd_ioctl_entry_wrapper,
#else
	.ndo_do_ioctl = dhd_ioctl_entry_wrapper,
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(5, 15, 0) */
	.ndo_start_xmit = dhd_start_xmit_wrapper,
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	.ndo_siocdevprivate = dhd_ioctl_entry,
#else
	.ndo_do_ioctl = dhd_ioctl_entry,
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(5, 15, 0) */
	.ndo_start_xmit = dhd_start_xmit,
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */
	.ndo_set_mac_address = dhd_set_mac_address,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0))
	.ndo_set_rx_mode = dhd_set_multicast_list,
#else
	.ndo_set_multicast_list = dhd_set_multicast_list,
#endif // endif
};

int
dhd_os_write_file_posn(void *fp, unsigned long *posn, void *buf,
		unsigned long buflen)
{
	loff_t wr_posn = *posn;

	if (!fp || !buf || buflen == 0)
		return -1;

	if (compat_vfs_write((struct file *)fp, buf, buflen, &wr_posn) < 0)
		return -1;

	*posn = wr_posn;
	return 0;
}

#ifdef SHOW_LOGTRACE
int
dhd_os_read_file(void *file, char *buf, uint32 size)
{
	struct file *filep = (struct file *)file;

	if (!file || !buf)
		return -1;

	return vfs_read(filep, buf, size, &filep->f_pos);
}

int
dhd_os_seek_file(void *file, int64 offset)
{
	struct file *filep = (struct file *)file;
	if (!file)
		return -1;

	/* offset can be -ve */
	filep->f_pos = filep->f_pos + offset;

	return 0;
}

static int
dhd_init_logstrs_array(osl_t *osh, dhd_event_log_t *temp)
{
	struct file *filep = NULL;
	struct kstat stat;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	mm_segment_t fs;
#endif
	char *raw_fmts =  NULL;
	int logstrs_size = 0;
	int error = 0;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	fs = get_fs();
	set_fs(KERNEL_DS);
#endif

	filep = filp_open(logstrs_path, O_RDONLY, 0);

	if (IS_ERR(filep)) {
		DHD_ERROR_NO_HW4(("%s: Failed to open the file %s \n", __FUNCTION__, logstrs_path));
		goto fail;
	}
	error = vfs_stat(logstrs_path, &stat);
	if (error) {
		DHD_ERROR_NO_HW4(("%s: Failed to stat file %s \n", __FUNCTION__, logstrs_path));
		goto fail;
	}
	logstrs_size = (int) stat.size;

	if (logstrs_size == 0) {
		DHD_ERROR(("%s: return as logstrs_size is 0\n", __FUNCTION__));
		goto fail1;
	}

	raw_fmts = MALLOC(osh, logstrs_size);
	if (raw_fmts == NULL) {
		DHD_ERROR(("%s: Failed to allocate memory \n", __FUNCTION__));
		goto fail;
	}

	if (vfs_read(filep, raw_fmts, logstrs_size, &filep->f_pos) !=	logstrs_size) {
		DHD_ERROR_NO_HW4(("%s: Failed to read file %s\n", __FUNCTION__, logstrs_path));
		goto fail;
	}

	if (dhd_parse_logstrs_file(osh, raw_fmts, logstrs_size, temp)
				== BCME_OK) {
		filp_close(filep, NULL);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
		set_fs(fs);
#endif
		return BCME_OK;
	}

fail:
	if (raw_fmts) {
		MFREE(osh, raw_fmts, logstrs_size);
		raw_fmts = NULL;
	}

fail1:
	if (!IS_ERR(filep))
		filp_close(filep, NULL);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	set_fs(fs);
#endif
	temp->fmts = NULL;
	return BCME_ERROR;
}

static int
dhd_read_map(osl_t *osh, char *fname, uint32 *ramstart, uint32 *rodata_start,
		uint32 *rodata_end)
{
	struct file *filep = NULL;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	mm_segment_t fs;
#endif
	int err = BCME_ERROR;

	if (fname == NULL) {
		DHD_ERROR(("%s: ERROR fname is NULL \n", __FUNCTION__));
		return BCME_ERROR;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	fs = get_fs();
	set_fs(KERNEL_DS);
#endif

	filep = filp_open(fname, O_RDONLY, 0);
	if (IS_ERR(filep)) {
		DHD_ERROR_NO_HW4(("%s: Failed to open %s \n",  __FUNCTION__, fname));
		goto fail;
	}

	if ((err = dhd_parse_map_file(osh, filep, ramstart,
			rodata_start, rodata_end)) < 0)
		goto fail;

fail:
	if (!IS_ERR(filep))
		filp_close(filep, NULL);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	set_fs(fs);
#endif

	return err;
}

static int
dhd_init_static_strs_array(osl_t *osh, dhd_event_log_t *temp, char *str_file, char *map_file)
{
	struct file *filep = NULL;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	mm_segment_t fs;
#endif
	char *raw_fmts =  NULL;
	uint32 logstrs_size = 0;
	int error = 0;
	uint32 ramstart = 0;
	uint32 rodata_start = 0;
	uint32 rodata_end = 0;
	uint32 logfilebase = 0;

	error = dhd_read_map(osh, map_file, &ramstart, &rodata_start, &rodata_end);
	if (error != BCME_OK) {
		DHD_ERROR(("readmap Error!! \n"));
		/* don't do event log parsing in actual case */
		if (strstr(str_file, ram_file_str) != NULL) {
			temp->raw_sstr = NULL;
		} else if (strstr(str_file, rom_file_str) != NULL) {
			temp->rom_raw_sstr = NULL;
		}
		return error;
	}
	DHD_ERROR(("ramstart: 0x%x, rodata_start: 0x%x, rodata_end:0x%x\n",
		ramstart, rodata_start, rodata_end));

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	fs = get_fs();
	set_fs(KERNEL_DS);
#endif

	filep = filp_open(str_file, O_RDONLY, 0);
	if (IS_ERR(filep)) {
		DHD_ERROR(("%s: Failed to open the file %s \n",  __FUNCTION__, str_file));
		goto fail;
	}

	if (TRUE) {
		/* Full file size is huge. Just read required part */
		logstrs_size = rodata_end - rodata_start;
		logfilebase = rodata_start - ramstart;
	}

	if (logstrs_size == 0) {
		DHD_ERROR(("%s: return as logstrs_size is 0\n", __FUNCTION__));
		goto fail1;
	}

	raw_fmts = MALLOC(osh, logstrs_size);
	if (raw_fmts == NULL) {
		DHD_ERROR(("%s: Failed to allocate raw_fmts memory \n", __FUNCTION__));
		goto fail;
	}

	if (TRUE) {
		error = generic_file_llseek(filep, logfilebase, SEEK_SET);
		if (error < 0) {
			DHD_ERROR(("%s: %s llseek failed %d \n", __FUNCTION__, str_file, error));
			goto fail;
		}
	}

	error = vfs_read(filep, raw_fmts, logstrs_size, (&filep->f_pos));
	if (error != logstrs_size) {
		DHD_ERROR(("%s: %s read failed %d \n", __FUNCTION__, str_file, error));
		goto fail;
	}

	if (strstr(str_file, ram_file_str) != NULL) {
		temp->raw_sstr = raw_fmts;
		temp->raw_sstr_size = logstrs_size;
		temp->rodata_start = rodata_start;
		temp->rodata_end = rodata_end;
	} else if (strstr(str_file, rom_file_str) != NULL) {
		temp->rom_raw_sstr = raw_fmts;
		temp->rom_raw_sstr_size = logstrs_size;
		temp->rom_rodata_start = rodata_start;
		temp->rom_rodata_end = rodata_end;
	}

	filp_close(filep, NULL);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	set_fs(fs);
#endif

	return BCME_OK;

fail:
	if (raw_fmts) {
		MFREE(osh, raw_fmts, logstrs_size);
		raw_fmts = NULL;
	}

fail1:
	if (!IS_ERR(filep))
		filp_close(filep, NULL);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	set_fs(fs);
#endif

	if (strstr(str_file, ram_file_str) != NULL) {
		temp->raw_sstr = NULL;
	} else if (strstr(str_file, rom_file_str) != NULL) {
		temp->rom_raw_sstr = NULL;
	}

	return error;
} /* dhd_init_static_strs_array */

#endif /* SHOW_LOGTRACE */

#ifdef DHD_ERPOM
uint enable_erpom = 0;
module_param(enable_erpom, int, 0);

int
dhd_wlan_power_off_handler(void *handler, unsigned char reason)
{
	dhd_pub_t *dhdp = (dhd_pub_t *)handler;
	bool dongle_isolation = dhdp->dongle_isolation;

	DHD_ERROR(("%s: WLAN DHD cleanup reason: %d\n", __FUNCTION__, reason));

	if ((reason == BY_BT_DUE_TO_BT) || (reason == BY_BT_DUE_TO_WLAN)) {
#if defined(DHD_FW_COREDUMP)
		/* save core dump to a file */
		if (dhdp->memdump_enabled) {
#ifdef DHD_SSSR_DUMP
			dhdp->collect_sssr = TRUE;
#endif /* DHD_SSSR_DUMP */
			dhdp->memdump_type = DUMP_TYPE_DUE_TO_BT;
			dhd_bus_mem_dump(dhdp);
		}
#endif /* DHD_FW_COREDUMP */
	}

	/* pause data on all the interfaces */
	dhd_bus_stop_queue(dhdp->bus);

	/* Devreset function will perform FLR again, to avoid it set dongle_isolation */
	dhdp->dongle_isolation = TRUE;
	dhd_bus_devreset(dhdp, 1); /* DHD structure cleanup */
	dhdp->dongle_isolation = dongle_isolation; /* Restore the old value */
	return 0;
}

int
dhd_wlan_power_on_handler(void *handler, unsigned char reason)
{
	dhd_pub_t *dhdp = (dhd_pub_t *)handler;
	bool dongle_isolation = dhdp->dongle_isolation;

	DHD_ERROR(("%s: WLAN DHD re-init reason: %d\n", __FUNCTION__, reason));
	/* Devreset function will perform FLR again, to avoid it set dongle_isolation */
	dhdp->dongle_isolation = TRUE;
	dhd_bus_devreset(dhdp, 0); /* DHD structure re-init */
	dhdp->dongle_isolation = dongle_isolation; /* Restore the old value */
	/* resume data on all the interfaces */
	dhd_bus_start_queue(dhdp->bus);
	return 0;

}

#endif /* DHD_ERPOM */

#ifdef BCMDBUS
uint
dhd_get_rxsz(dhd_pub_t *pub)
{
	struct net_device *net = NULL;
	dhd_info_t *dhd = NULL;
	uint rxsz;

	/* Assign rxsz for dbus_attach */
	dhd = pub->info;
	net = dhd->iflist[0]->net;
	net->hard_header_len = ETH_HLEN + pub->hdrlen;
	rxsz = DBUS_RX_BUFFER_SIZE_DHD(net);

	return rxsz;
}

void
dhd_set_path(dhd_pub_t *pub)
{
	dhd_info_t *dhd = NULL;

	dhd = pub->info;

	/* try to download image and nvram to the dongle */
	if	(dhd_update_fw_nv_path(dhd) && dhd->pub.bus) {
		DHD_INFO(("%s: fw %s, nv %s, conf %s\n",
			__FUNCTION__, dhd->fw_path, dhd->nv_path, dhd->conf_path));
		dhd_bus_update_fw_nv_path(dhd->pub.bus,
				dhd->fw_path, dhd->nv_path, dhd->clm_path, dhd->conf_path);
	}
}
#endif

/** Called once for each hardware (dongle) instance that this DHD manages */
dhd_pub_t *
dhd_attach(osl_t *osh, struct dhd_bus *bus, uint bus_hdrlen
#ifdef BCMDBUS
	, void *data
#endif
)
{
	dhd_info_t *dhd = NULL;
	struct net_device *net = NULL;
	char if_name[IFNAMSIZ] = {'\0'};
#ifdef SHOW_LOGTRACE
	int ret;
#endif /* SHOW_LOGTRACE */
#ifdef DHD_ERPOM
	pom_func_handler_t *pom_handler;
#endif /* DHD_ERPOM */
#if defined(BCMSDIO) || defined(BCMPCIE)
	uint32 bus_type = -1;
	uint32 bus_num = -1;
	uint32 slot_num = -1;
	wifi_adapter_info_t *adapter = NULL;
#elif defined(BCMDBUS)
	wifi_adapter_info_t *adapter = data;
#endif

	dhd_attach_states_t dhd_state = DHD_ATTACH_STATE_INIT;
	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

#ifdef PCIE_FULL_DONGLE
	ASSERT(sizeof(dhd_pkttag_fd_t) <= OSL_PKTTAG_SZ);
	ASSERT(sizeof(dhd_pkttag_fr_t) <= OSL_PKTTAG_SZ);
#endif /* PCIE_FULL_DONGLE */

	/* will implement get_ids for DBUS later */
#if defined(BCMSDIO) || defined(BCMPCIE)
	dhd_bus_get_ids(bus, &bus_type, &bus_num, &slot_num);
	adapter = dhd_wifi_platform_get_adapter(bus_type, bus_num, slot_num);
#endif

	/* Allocate primary dhd_info */
	dhd = wifi_platform_prealloc(adapter, DHD_PREALLOC_DHD_INFO, sizeof(dhd_info_t));
	if (dhd == NULL) {
		dhd = MALLOC(osh, sizeof(dhd_info_t));
		if (dhd == NULL) {
			DHD_ERROR(("%s: OOM - alloc dhd_info\n", __FUNCTION__));
			goto dhd_null_flag;
		}
	}
	memset(dhd, 0, sizeof(dhd_info_t));
	dhd_state |= DHD_ATTACH_STATE_DHD_ALLOC;

	dhd->unit = dhd_found + instance_base; /* do not increment dhd_found, yet */

	dhd->pub.osh = osh;
#ifdef DUMP_IOCTL_IOV_LIST
	dll_init(&(dhd->pub.dump_iovlist_head));
#endif /* DUMP_IOCTL_IOV_LIST */
	dhd->adapter = adapter;
	dhd->pub.adapter = (void *)adapter;
#ifdef BT_OVER_SDIO
	dhd->pub.is_bt_recovery_required = FALSE;
	mutex_init(&dhd->bus_user_lock);
#endif /* BT_OVER_SDIO */

	g_dhd_pub = &dhd->pub;

#ifdef DHD_DEBUG
	dll_init(&(dhd->pub.mw_list_head));
#endif /* DHD_DEBUG */

#ifdef CUSTOM_FORCE_NODFS_FLAG
	dhd->pub.dhd_cflags |= WLAN_PLAT_NODFS_FLAG;
	dhd->pub.force_country_change = TRUE;
#endif /* CUSTOM_FORCE_NODFS_FLAG */
#ifdef CUSTOM_COUNTRY_CODE
	get_customized_country_code(dhd->adapter,
		dhd->pub.dhd_cspec.country_abbrev, &dhd->pub.dhd_cspec,
		dhd->pub.dhd_cflags);
#endif /* CUSTOM_COUNTRY_CODE */
#ifndef BCMDBUS
	dhd->thr_dpc_ctl.thr_pid = DHD_PID_KT_TL_INVALID;
	dhd->thr_wdt_ctl.thr_pid = DHD_PID_KT_INVALID;
#ifdef DHD_WET
	dhd->pub.wet_info = dhd_get_wet_info(&dhd->pub);
#endif /* DHD_WET */
	/* Initialize thread based operation and lock */
	sema_init(&dhd->sdsem, 1);
#endif /* !BCMDBUS */
	dhd->pub.pcie_txs_metadata_enable = pcie_txs_metadata_enable;

	/* Link to info module */
	dhd->pub.info = dhd;

	/* Link to bus module */
	dhd->pub.bus = bus;
	dhd->pub.hdrlen = bus_hdrlen;
	dhd->pub.txoff = FALSE;

	/* dhd_conf must be attached after linking dhd to dhd->pub.info,
	 * because dhd_detech will check .info is NULL or not.
	*/
	if (dhd_conf_attach(&dhd->pub) != 0) {
		DHD_ERROR(("dhd_conf_attach failed\n"));
		goto fail;
	}
#ifndef BCMDBUS
	dhd_conf_reset(&dhd->pub);
	dhd_conf_set_chiprev(&dhd->pub, dhd_bus_chip(bus), dhd_bus_chiprev(bus));
	dhd_conf_preinit(&dhd->pub);
#endif /* !BCMDBUS */

	/* Some DHD modules (e.g. cfg80211) configures operation mode based on firmware name.
	 * This is indeed a hack but we have to make it work properly before we have a better
	 * solution
	 */
	dhd_update_fw_nv_path(dhd);

	/* Set network interface name if it was provided as module parameter */
	if (iface_name[0]) {
		int len;
		char ch;
		strncpy(if_name, iface_name, IFNAMSIZ);
		if_name[IFNAMSIZ - 1] = 0;
		len = strlen(if_name);
		ch = if_name[len - 1];
		if ((ch > '9' || ch < '0') && (len < IFNAMSIZ - 2))
			strncat(if_name, "%d", IFNAMSIZ - len - 1);
	}

	/* Passing NULL to dngl_name to ensure host gets if_name in dngl_name member */
	net = dhd_allocate_if(&dhd->pub, 0, if_name, NULL, 0, TRUE, NULL);
	if (net == NULL) {
		goto fail;
	}
	mutex_init(&dhd->pub.ndev_op_sync);

	dhd_state |= DHD_ATTACH_STATE_ADD_IF;
#ifdef DHD_L2_FILTER
	/* initialize the l2_filter_cnt */
	dhd->pub.l2_filter_cnt = 0;
#endif // endif

#ifndef CONFIG_AP6XXX_WIFI6_HDF
	net->netdev_ops = NULL;
#endif

	mutex_init(&dhd->dhd_iovar_mutex);
	sema_init(&dhd->proto_sem, 1);
#ifdef DHD_ULP
	if (!(dhd_ulp_init(osh, &dhd->pub)))
		goto fail;
#endif /* DHD_ULP */

#ifdef PROP_TXSTATUS
	spin_lock_init(&dhd->wlfc_spinlock);

	dhd->pub.skip_fc = dhd_wlfc_skip_fc;
	dhd->pub.plat_init = dhd_wlfc_plat_init;
	dhd->pub.plat_deinit = dhd_wlfc_plat_deinit;

#ifdef DHD_WLFC_THREAD
	init_waitqueue_head(&dhd->pub.wlfc_wqhead);
	dhd->pub.wlfc_thread = kthread_create(dhd_wlfc_transfer_packets, &dhd->pub, "wlfc-thread");
	if (IS_ERR(dhd->pub.wlfc_thread)) {
		DHD_ERROR(("create wlfc thread failed\n"));
		goto fail;
	} else {
		wake_up_process(dhd->pub.wlfc_thread);
	}
#endif /* DHD_WLFC_THREAD */
#endif /* PROP_TXSTATUS */

	/* Initialize other structure content */
	init_waitqueue_head(&dhd->ioctl_resp_wait);
	init_waitqueue_head(&dhd->d3ack_wait);
	init_waitqueue_head(&dhd->ctrl_wait);
	init_waitqueue_head(&dhd->dhd_bus_busy_state_wait);
	init_waitqueue_head(&dhd->dmaxfer_wait);
	init_waitqueue_head(&dhd->pub.tx_completion_wait);
	dhd->pub.dhd_bus_busy_state = 0;
	/* Initialize the spinlocks */
	spin_lock_init(&dhd->sdlock);
	spin_lock_init(&dhd->txqlock);
	spin_lock_init(&dhd->dhd_lock);
	spin_lock_init(&dhd->txoff_lock);
	spin_lock_init(&dhd->rxf_lock);
#ifdef WLTDLS
	spin_lock_init(&dhd->pub.tdls_lock);
#endif /* WLTDLS */
#if defined(RXFRAME_THREAD)
	dhd->rxthread_enabled = TRUE;
#endif /* defined(RXFRAME_THREAD) */

#ifdef DHDTCPACK_SUPPRESS
	spin_lock_init(&dhd->tcpack_lock);
#endif /* DHDTCPACK_SUPPRESS */

	/* Initialize Wakelock stuff */
	spin_lock_init(&dhd->wakelock_spinlock);
	spin_lock_init(&dhd->wakelock_evt_spinlock);
	DHD_OS_WAKE_LOCK_INIT(dhd);
	dhd->wakelock_counter = 0;
	/* wakelocks prevent a system from going into a low power state */
#ifdef CONFIG_HAS_WAKELOCK
	// terence 20161023: can not destroy wl_wifi when wlan down, it will happen null pointer in dhd_ioctl_entry
	wake_lock_init(&dhd->wl_wifi, WAKE_LOCK_SUSPEND, "wlan_wake");
	wake_lock_init(&dhd->wl_wdwake, WAKE_LOCK_SUSPEND, "wlan_wd_wake");
#endif /* CONFIG_HAS_WAKELOCK */

	mutex_init(&dhd->dhd_net_if_mutex);
	mutex_init(&dhd->dhd_suspend_mutex);
#if defined(PKT_FILTER_SUPPORT) && defined(APF)
	mutex_init(&dhd->dhd_apf_mutex);
#endif /* PKT_FILTER_SUPPORT && APF */
	dhd_state |= DHD_ATTACH_STATE_WAKELOCKS_INIT;

	/* Attach and link in the protocol */
	if (dhd_prot_attach(&dhd->pub) != 0) {
		DHD_ERROR(("dhd_prot_attach failed\n"));
		goto fail;
	}
	dhd_state |= DHD_ATTACH_STATE_PROT_ATTACH;

#ifdef WL_CFG80211
	spin_lock_init(&dhd->pub.up_lock);
	/* Attach and link in the cfg80211 */
	if (unlikely(wl_cfg80211_attach(net, &dhd->pub))) {
		DHD_ERROR(("wl_cfg80211_attach failed\n"));
		goto fail;
	}

	dhd_monitor_init(&dhd->pub);
	dhd_state |= DHD_ATTACH_STATE_CFG80211;
#endif // endif

#ifdef WL_EVENT
	if (wl_ext_event_attach(net) != 0) {
		DHD_ERROR(("wl_ext_event_attach failed\n"));
		goto fail;
	}
#endif /* WL_EVENT */
#ifdef WL_ESCAN
	/* Attach and link in the escan */
	if (wl_escan_attach(net) != 0) {
		DHD_ERROR(("wl_escan_attach failed\n"));
		goto fail;
	}
#endif /* WL_ESCAN */
#ifdef WL_EXT_IAPSTA
	if (wl_ext_iapsta_attach(net) != 0) {
		DHD_ERROR(("wl_ext_iapsta_attach failed\n"));
		goto fail;
	}
#endif /* WL_EXT_IAPSTA */
#ifdef WL_EXT_GENL
	if (wl_ext_genl_init(net)) {
		DHD_ERROR(("wl_ext_genl_init failed\n"));
		goto fail;
	}
#endif
#if defined(WL_WIRELESS_EXT)
	/* Attach and link in the iw */
	if (wl_iw_attach(net) != 0) {
		DHD_ERROR(("wl_iw_attach failed\n"));
		goto fail;
	}
	dhd_state |= DHD_ATTACH_STATE_WL_ATTACH;
#endif /* defined(WL_WIRELESS_EXT) */

#ifdef SHOW_LOGTRACE
	ret = dhd_init_logstrs_array(osh, &dhd->event_data);
	if (ret == BCME_OK) {
		dhd_init_static_strs_array(osh, &dhd->event_data, st_str_file_path, map_file_path);
		dhd_init_static_strs_array(osh, &dhd->event_data, rom_st_str_file_path,
			rom_map_file_path);
		dhd_state |= DHD_ATTACH_LOGTRACE_INIT;
	}
#endif /* SHOW_LOGTRACE */

	/* attach debug if support */
	if (dhd_os_dbg_attach(&dhd->pub)) {
		DHD_ERROR(("%s debug module attach failed\n", __FUNCTION__));
		goto fail;
	}
#ifdef DEBUGABILITY
#if defined(SHOW_LOGTRACE) && defined(DBG_RING_LOG_INIT_DEFAULT)
	/* enable verbose ring to support dump_trace_buf */
	dhd_os_start_logging(&dhd->pub, FW_VERBOSE_RING_NAME, 3, 0, 0, 0);
#endif /* SHOW_LOGTRACE */

#ifdef DBG_PKT_MON
	dhd->pub.dbg->pkt_mon_lock = dhd_os_spin_lock_init(dhd->pub.osh);
#ifdef DBG_PKT_MON_INIT_DEFAULT
	dhd_os_dbg_attach_pkt_monitor(&dhd->pub);
#endif /* DBG_PKT_MON_INIT_DEFAULT */
#endif /* DBG_PKT_MON */
#endif /* DEBUGABILITY */

#ifdef DHD_STATUS_LOGGING
	dhd->pub.statlog = dhd_attach_statlog(&dhd->pub, MAX_STATLOG_ITEM,
		MAX_STATLOG_REQ_ITEM, STATLOG_LOGBUF_LEN);
	if (dhd->pub.statlog == NULL) {
		DHD_ERROR(("%s: alloc statlog failed\n", __FUNCTION__));
	}
#endif /* DHD_STATUS_LOGGING */

#ifdef DHD_LOG_DUMP
	dhd_log_dump_init(&dhd->pub);
#endif /* DHD_LOG_DUMP */
#ifdef DHD_PKTDUMP_ROAM
	dhd_dump_pkt_init(&dhd->pub);
#endif /* DHD_PKTDUMP_ROAM */

	if (dhd_sta_pool_init(&dhd->pub, DHD_MAX_STA) != BCME_OK) {
		DHD_ERROR(("%s: Initializing %u sta\n", __FUNCTION__, DHD_MAX_STA));
		goto fail;
	}

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
	dhd->tx_wq = alloc_workqueue("bcmdhd-tx-wq", WQ_HIGHPRI | WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!dhd->tx_wq) {
		DHD_ERROR(("%s: alloc_workqueue(bcmdhd-tx-wq) failed\n", __FUNCTION__));
		goto fail;
	}
	dhd->rx_wq = alloc_workqueue("bcmdhd-rx-wq", WQ_HIGHPRI | WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!dhd->rx_wq) {
		DHD_ERROR(("%s: alloc_workqueue(bcmdhd-rx-wq) failed\n", __FUNCTION__));
		destroy_workqueue(dhd->tx_wq);
		dhd->tx_wq = NULL;
		goto fail;
	}
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

#ifndef BCMDBUS
	/* Set up the watchdog timer */
	init_timer_compat(&dhd->timer, dhd_watchdog, dhd);
	dhd->default_wd_interval = dhd_watchdog_ms;

	if (dhd_watchdog_prio >= 0) {
		/* Initialize watchdog thread */
		PROC_START(dhd_watchdog_thread, dhd, &dhd->thr_wdt_ctl, 0, "dhd_watchdog_thread");
		if (dhd->thr_wdt_ctl.thr_pid < 0) {
			goto fail;
		}

	} else {
		dhd->thr_wdt_ctl.thr_pid = -1;
	}

#ifdef SHOW_LOGTRACE
	skb_queue_head_init(&dhd->evt_trace_queue);

	/* Create ring proc entries */
	dhd_dbg_ring_proc_create(&dhd->pub);
#endif /* SHOW_LOGTRACE */

	/* Set up the bottom half handler */
	if (dhd_dpc_prio >= 0) {
		/* Initialize DPC thread */
		PROC_START(dhd_dpc_thread, dhd, &dhd->thr_dpc_ctl, 0, "dhd_dpc");
		if (dhd->thr_dpc_ctl.thr_pid < 0) {
			goto fail;
		}
	} else {
		/*  use tasklet for dpc */
		tasklet_init(&dhd->tasklet, dhd_dpc, (ulong)dhd);
		dhd->thr_dpc_ctl.thr_pid = -1;
	}

	if (dhd->rxthread_enabled) {
		bzero(&dhd->pub.skbbuf[0], sizeof(void *) * MAXSKBPEND);
		/* Initialize RXF thread */
		PROC_START(dhd_rxf_thread, dhd, &dhd->thr_rxf_ctl, 0, "dhd_rxf");
		if (dhd->thr_rxf_ctl.thr_pid < 0) {
			goto fail;
		}
	}
#endif /* !BCMDBUS */

	dhd_state |= DHD_ATTACH_STATE_THREADS_CREATED;

#if defined(CONFIG_PM_SLEEP)
	if (!dhd_pm_notifier_registered) {
		dhd_pm_notifier_registered = TRUE;
		dhd->pm_notifier.notifier_call = dhd_pm_callback;
		dhd->pm_notifier.priority = 10;
		register_pm_notifier(&dhd->pm_notifier);
	}

#endif /* CONFIG_PM_SLEEP */

#if defined(CONFIG_HAS_EARLYSUSPEND) && defined(DHD_USE_EARLYSUSPEND)
	dhd->early_suspend.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN + 20;
	dhd->early_suspend.suspend = dhd_early_suspend;
	dhd->early_suspend.resume = dhd_late_resume;
	register_early_suspend(&dhd->early_suspend);
	dhd_state |= DHD_ATTACH_STATE_EARLYSUSPEND_DONE;
#endif /* CONFIG_HAS_EARLYSUSPEND && DHD_USE_EARLYSUSPEND */

#ifdef ARP_OFFLOAD_SUPPORT
	dhd->pend_ipaddr = 0;
	if (!dhd_inetaddr_notifier_registered) {
		dhd_inetaddr_notifier_registered = TRUE;
		register_inetaddr_notifier(&dhd_inetaddr_notifier);
	}
#endif /* ARP_OFFLOAD_SUPPORT */

#if defined(CONFIG_IPV6) && defined(IPV6_NDO_SUPPORT)
	if (!dhd_inet6addr_notifier_registered) {
		dhd_inet6addr_notifier_registered = TRUE;
		register_inet6addr_notifier(&dhd_inet6addr_notifier);
	}
#endif /* CONFIG_IPV6 && IPV6_NDO_SUPPORT */
	dhd->dhd_deferred_wq = dhd_deferred_work_init((void *)dhd);
	INIT_WORK(&dhd->dhd_hang_process_work, dhd_hang_process);
#ifdef DEBUG_CPU_FREQ
	dhd->new_freq = alloc_percpu(int);
	dhd->freq_trans.notifier_call = dhd_cpufreq_notifier;
	cpufreq_register_notifier(&dhd->freq_trans, CPUFREQ_TRANSITION_NOTIFIER);
#endif // endif
#ifdef DHDTCPACK_SUPPRESS
#ifdef BCMSDIO
	dhd_tcpack_suppress_set(&dhd->pub, TCPACK_SUP_DELAYTX);
#elif defined(BCMPCIE)
	dhd_tcpack_suppress_set(&dhd->pub, TCPACK_SUP_HOLD);
#else
	dhd_tcpack_suppress_set(&dhd->pub, TCPACK_SUP_OFF);
#endif /* BCMSDIO */
#endif /* DHDTCPACK_SUPPRESS */

#if defined(BCM_DNGL_EMBEDIMAGE) || defined(BCM_REQUEST_FW)
#endif /* defined(BCM_DNGL_EMBEDIMAGE) || defined(BCM_REQUEST_FW) */

#ifdef DHD_DEBUG_PAGEALLOC
	register_page_corrupt_cb(dhd_page_corrupt_cb, &dhd->pub);
#endif /* DHD_DEBUG_PAGEALLOC */

#if defined(DHD_LB)

	dhd_lb_set_default_cpus(dhd);
	DHD_LB_STATS_INIT(&dhd->pub);

	/* Initialize the CPU Masks */
	if (dhd_cpumasks_init(dhd) == 0) {
		/* Now we have the current CPU maps, run through candidacy */
		dhd_select_cpu_candidacy(dhd);

		/* Register the call backs to CPU Hotplug sub-system */
		dhd_register_cpuhp_callback(dhd);

	} else {
		/*
		* We are unable to initialize CPU masks, so candidacy algorithm
		* won't run, but still Load Balancing will be honoured based
		* on the CPUs allocated for a given job statically during init
		*/
		dhd->cpu_notifier.notifier_call = NULL;
		DHD_ERROR(("%s():dhd_cpumasks_init failed CPUs for JOB would be static\n",
			__FUNCTION__));
	}

#ifdef DHD_LB_TXP
#ifdef DHD_LB_TXP_DEFAULT_ENAB
	/* Trun ON the feature by default */
	atomic_set(&dhd->lb_txp_active, 1);
#else
	/* Trun OFF the feature by default */
	atomic_set(&dhd->lb_txp_active, 0);
#endif /* DHD_LB_TXP_DEFAULT_ENAB */
#endif /* DHD_LB_TXP */

#ifdef DHD_LB_RXP
	/* Trun ON the feature by default */
	atomic_set(&dhd->lb_rxp_active, 1);
#endif /* DHD_LB_RXP */

	/* Initialize the Load Balancing Tasklets and Napi object */
#if defined(DHD_LB_TXC)
	tasklet_init(&dhd->tx_compl_tasklet,
		dhd_lb_tx_compl_handler, (ulong)(&dhd->pub));
	INIT_WORK(&dhd->tx_compl_dispatcher_work, dhd_tx_compl_dispatcher_fn);
	DHD_INFO(("%s load balance init tx_compl_tasklet\n", __FUNCTION__));
#endif /* DHD_LB_TXC */
#if defined(DHD_LB_RXC)
	tasklet_init(&dhd->rx_compl_tasklet,
		dhd_lb_rx_compl_handler, (ulong)(&dhd->pub));
	INIT_WORK(&dhd->rx_compl_dispatcher_work, dhd_rx_compl_dispatcher_fn);
	DHD_INFO(("%s load balance init rx_compl_tasklet\n", __FUNCTION__));
#endif /* DHD_LB_RXC */

#if defined(DHD_LB_RXP)
	__skb_queue_head_init(&dhd->rx_pend_queue);
	skb_queue_head_init(&dhd->rx_napi_queue);
	/* Initialize the work that dispatches NAPI job to a given core */
	INIT_WORK(&dhd->rx_napi_dispatcher_work, dhd_rx_napi_dispatcher_fn);
	DHD_INFO(("%s load balance init rx_napi_queue\n", __FUNCTION__));
#endif /* DHD_LB_RXP */

#if defined(DHD_LB_TXP)
	INIT_WORK(&dhd->tx_dispatcher_work, dhd_tx_dispatcher_work);
	skb_queue_head_init(&dhd->tx_pend_queue);
	/* Initialize the work that dispatches TX job to a given core */
	tasklet_init(&dhd->tx_tasklet,
		dhd_lb_tx_handler, (ulong)(dhd));
	DHD_INFO(("%s load balance init tx_pend_queue\n", __FUNCTION__));
#endif /* DHD_LB_TXP */

	dhd_state |= DHD_ATTACH_STATE_LB_ATTACH_DONE;
#endif /* DHD_LB */

#if defined(DNGL_AXI_ERROR_LOGGING) && defined(DHD_USE_WQ_FOR_DNGL_AXI_ERROR)
	INIT_WORK(&dhd->axi_error_dispatcher_work, dhd_axi_error_dispatcher_fn);
#endif /* DNGL_AXI_ERROR_LOGGING && DHD_USE_WQ_FOR_DNGL_AXI_ERROR */

#if defined(BCMPCIE)
	dhd->pub.extended_trap_data = MALLOCZ(osh, BCMPCIE_EXT_TRAP_DATA_MAXLEN);
	if (dhd->pub.extended_trap_data == NULL) {
		DHD_ERROR(("%s: Failed to alloc extended_trap_data\n", __FUNCTION__));
	}
#ifdef DNGL_AXI_ERROR_LOGGING
	dhd->pub.axi_err_dump = MALLOCZ(osh, sizeof(dhd_axi_error_dump_t));
	if (dhd->pub.axi_err_dump == NULL) {
		DHD_ERROR(("%s: Failed to alloc axi_err_dump\n", __FUNCTION__));
	}
#endif /* DNGL_AXI_ERROR_LOGGING */
#endif /* BCMPCIE && ETD */

#ifdef SHOW_LOGTRACE
	if (dhd_init_logtrace_process(dhd) != BCME_OK) {
		goto fail;
	}
#endif /* SHOW_LOGTRACE */

	DHD_SSSR_MEMPOOL_INIT(&dhd->pub);

#ifdef EWP_EDL
	if (host_edl_support) {
		if (DHD_EDL_MEM_INIT(&dhd->pub) != BCME_OK) {
			host_edl_support = FALSE;
		}
	}
#endif /* EWP_EDL */

	(void)dhd_sysfs_init(dhd);

#ifdef WL_NATOE
	/* Open Netlink socket for NF_CONNTRACK notifications */
	dhd->pub.nfct = dhd_ct_open(&dhd->pub, NFNL_SUBSYS_CTNETLINK | NFNL_SUBSYS_CTNETLINK_EXP,
			CT_ALL);
#endif /* WL_NATOE */

	dhd_state |= DHD_ATTACH_STATE_DONE;
	dhd->dhd_state = dhd_state;

	dhd_found++;
	
#ifdef CSI_SUPPORT
	dhd_csi_init(&dhd->pub);
#endif /* CSI_SUPPORT */

#ifdef DHD_DUMP_MNGR
	dhd->pub.dump_file_manage =
		(dhd_dump_file_manage_t *)MALLOCZ(dhd->pub.osh, sizeof(dhd_dump_file_manage_t));
	if (unlikely(!dhd->pub.dump_file_manage)) {
		DHD_ERROR(("%s(): could not allocate memory for - "
					"dhd_dump_file_manage_t\n", __FUNCTION__));
	}
#endif /* DHD_DUMP_MNGR */
#ifdef DHD_FW_COREDUMP
	/* Set memdump default values */
	dhd->pub.memdump_enabled = DUMP_MEMFILE_BUGON;
	/* Check the memdump capability */
	dhd_get_memdump_info(&dhd->pub);
#endif /* DHD_FW_COREDUMP */

#ifdef DHD_ERPOM
	if (enable_erpom) {
		pom_handler = &dhd->pub.pom_wlan_handler;
		pom_handler->func_id = WLAN_FUNC_ID;
		pom_handler->handler = (void *)g_dhd_pub;
		pom_handler->power_off = dhd_wlan_power_off_handler;
		pom_handler->power_on = dhd_wlan_power_on_handler;

		dhd->pub.pom_func_register = NULL;
		dhd->pub.pom_func_deregister = NULL;
		dhd->pub.pom_toggle_reg_on = NULL;

		dhd->pub.pom_func_register = symbol_get(pom_func_register);
		dhd->pub.pom_func_deregister = symbol_get(pom_func_deregister);
		dhd->pub.pom_toggle_reg_on = symbol_get(pom_toggle_reg_on);

		symbol_put(pom_func_register);
		symbol_put(pom_func_deregister);
		symbol_put(pom_toggle_reg_on);

		if (!dhd->pub.pom_func_register ||
			!dhd->pub.pom_func_deregister ||
			!dhd->pub.pom_toggle_reg_on) {
			DHD_ERROR(("%s, enable_erpom enabled through module parameter but "
				"POM is not loaded\n", __FUNCTION__));
			ASSERT(0);
			goto fail;
		}
		dhd->pub.pom_func_register(pom_handler);
		dhd->pub.enable_erpom = TRUE;

	}
#endif /* DHD_ERPOM */
	return &dhd->pub;

fail:
	if (dhd_state >= DHD_ATTACH_STATE_DHD_ALLOC) {
		DHD_TRACE(("%s: Calling dhd_detach dhd_state 0x%x &dhd->pub %p\n",
			__FUNCTION__, dhd_state, &dhd->pub));
		dhd->dhd_state = dhd_state;
		dhd_detach(&dhd->pub);
		dhd_free(&dhd->pub);
	}

dhd_null_flag:
	return NULL;
}

int dhd_get_fw_mode(dhd_info_t *dhdinfo)
{
	if (strstr(dhdinfo->fw_path, "_apsta") != NULL)
		return DHD_FLAG_HOSTAP_MODE;
	if (strstr(dhdinfo->fw_path, "_p2p") != NULL)
		return DHD_FLAG_P2P_MODE;
	if (strstr(dhdinfo->fw_path, "_ibss") != NULL)
		return DHD_FLAG_IBSS_MODE;
	if (strstr(dhdinfo->fw_path, "_mfg") != NULL)
		return DHD_FLAG_MFG_MODE;

	return DHD_FLAG_STA_MODE;
}

int dhd_bus_get_fw_mode(dhd_pub_t *dhdp)
{
	return dhd_get_fw_mode(dhdp->info);
}

extern char * nvram_get(const char *name);
bool dhd_update_fw_nv_path(dhd_info_t *dhdinfo)
{
	int fw_len;
	int nv_len;
	int clm_len;
	int conf_len;
	const char *fw = NULL;
	const char *nv = NULL;
	const char *clm = NULL;
	const char *conf = NULL;
#ifdef DHD_UCODE_DOWNLOAD
	int uc_len;
	const char *uc = NULL;
#endif /* DHD_UCODE_DOWNLOAD */
	wifi_adapter_info_t *adapter = dhdinfo->adapter;
	int fw_path_len = sizeof(dhdinfo->fw_path);
	int nv_path_len = sizeof(dhdinfo->nv_path);

	/* Update firmware and nvram path. The path may be from adapter info or module parameter
	 * The path from adapter info is used for initialization only (as it won't change).
	 *
	 * The firmware_path/nvram_path module parameter may be changed by the system at run
	 * time. When it changes we need to copy it to dhdinfo->fw_path. Also Android private
	 * command may change dhdinfo->fw_path. As such we need to clear the path info in
	 * module parameter after it is copied. We won't update the path until the module parameter
	 * is changed again (first character is not '\0')
	 */

	/* set default firmware and nvram path for built-in type driver */
//	if (!dhd_download_fw_on_driverload) {
#ifdef CONFIG_BCMDHD_FW_PATH
		fw = VENDOR_PATH CONFIG_BCMDHD_FW_PATH;
#endif /* CONFIG_BCMDHD_FW_PATH */
#ifdef CONFIG_BCMDHD_NVRAM_PATH
		nv = VENDOR_PATH CONFIG_BCMDHD_NVRAM_PATH;
#endif /* CONFIG_BCMDHD_NVRAM_PATH */
//	}

	/* check if we need to initialize the path */
	if (dhdinfo->fw_path[0] == '\0') {
		if (adapter && adapter->fw_path && adapter->fw_path[0] != '\0')
			fw = adapter->fw_path;
	}
	if (dhdinfo->nv_path[0] == '\0') {
		if (adapter && adapter->nv_path && adapter->nv_path[0] != '\0')
			nv = adapter->nv_path;
	}
	if (dhdinfo->clm_path[0] == '\0') {
		if (adapter && adapter->clm_path && adapter->clm_path[0] != '\0')
			clm = adapter->clm_path;
	}
	if (dhdinfo->conf_path[0] == '\0') {
		if (adapter && adapter->conf_path && adapter->conf_path[0] != '\0')
			conf = adapter->conf_path;
	}

	/* Use module parameter if it is valid, EVEN IF the path has not been initialized
	 *
	 * TODO: need a solution for multi-chip, can't use the same firmware for all chips
	 */
	if (firmware_path[0] != '\0')
		fw = firmware_path;

	if (nvram_path[0] != '\0')
		nv = nvram_path;
	if (clm_path[0] != '\0')
		clm = clm_path;
	if (config_path[0] != '\0')
		conf = config_path;

#ifdef DHD_UCODE_DOWNLOAD
	if (ucode_path[0] != '\0')
		uc = ucode_path;
#endif /* DHD_UCODE_DOWNLOAD */

	if (fw && fw[0] != '\0') {
		fw_len = strlen(fw);
		if (fw_len >= fw_path_len) {
			DHD_ERROR(("fw path len exceeds max len of dhdinfo->fw_path\n"));
			return FALSE;
		}
		strncpy(dhdinfo->fw_path, fw, fw_path_len);
		if (dhdinfo->fw_path[fw_len-1] == '\n')
		       dhdinfo->fw_path[fw_len-1] = '\0';
	}
	if (nv && nv[0] != '\0') {
		nv_len = strlen(nv);
		if (nv_len >= nv_path_len) {
			DHD_ERROR(("nvram path len exceeds max len of dhdinfo->nv_path\n"));
			return FALSE;
		}
		memset(dhdinfo->nv_path, 0, nv_path_len);
		strncpy(dhdinfo->nv_path, nv, nv_path_len);
		dhdinfo->nv_path[nv_len] = '\0';
#ifdef DHD_USE_SINGLE_NVRAM_FILE
		/* Remove "_net" or "_mfg" tag from current nvram path */
		{
			char *nvram_tag = "nvram_";
			char *ext_tag = ".txt";
			char *sp_nvram = strnstr(dhdinfo->nv_path, nvram_tag, nv_path_len);
			bool valid_buf = sp_nvram && ((uint32)(sp_nvram + strlen(nvram_tag) +
				strlen(ext_tag) - dhdinfo->nv_path) <= nv_path_len);
			if (valid_buf) {
				char *sp = sp_nvram + strlen(nvram_tag) - 1;
				uint32 padding_size = (uint32)(dhdinfo->nv_path +
					nv_path_len - sp);
				memset(sp, 0, padding_size);
				strncat(dhdinfo->nv_path, ext_tag, strlen(ext_tag));
				nv_len = strlen(dhdinfo->nv_path);
				DHD_INFO(("%s: new nvram path = %s\n",
					__FUNCTION__, dhdinfo->nv_path));
			} else if (sp_nvram) {
				DHD_ERROR(("%s: buffer space for nvram path is not enough\n",
					__FUNCTION__));
				return FALSE;
			} else {
				DHD_ERROR(("%s: Couldn't find the nvram tag. current"
					" nvram path = %s\n", __FUNCTION__, dhdinfo->nv_path));
			}
		}
#endif /* DHD_USE_SINGLE_NVRAM_FILE */
		if (dhdinfo->nv_path[nv_len-1] == '\n')
		       dhdinfo->nv_path[nv_len-1] = '\0';
	}
	if (clm && clm[0] != '\0') {
		clm_len = strlen(clm);
		if (clm_len >= sizeof(dhdinfo->clm_path)) {
			DHD_ERROR(("clm path len exceeds max len of dhdinfo->clm_path\n"));
			return FALSE;
		}
		strncpy(dhdinfo->clm_path, clm, sizeof(dhdinfo->clm_path));
		if (dhdinfo->clm_path[clm_len-1] == '\n')
		       dhdinfo->clm_path[clm_len-1] = '\0';
	}
	if (conf && conf[0] != '\0') {
		conf_len = strlen(conf);
		if (conf_len >= sizeof(dhdinfo->conf_path)) {
			DHD_ERROR(("config path len exceeds max len of dhdinfo->conf_path\n"));
			return FALSE;
		}
		strncpy(dhdinfo->conf_path, conf, sizeof(dhdinfo->conf_path));
		if (dhdinfo->conf_path[conf_len-1] == '\n')
		       dhdinfo->conf_path[conf_len-1] = '\0';
	}
#ifdef DHD_UCODE_DOWNLOAD
	if (uc && uc[0] != '\0') {
		uc_len = strlen(uc);
		if (uc_len >= sizeof(dhdinfo->uc_path)) {
			DHD_ERROR(("uc path len exceeds max len of dhdinfo->uc_path\n"));
			return FALSE;
		}
		strncpy(dhdinfo->uc_path, uc, sizeof(dhdinfo->uc_path));
		if (dhdinfo->uc_path[uc_len-1] == '\n')
		       dhdinfo->uc_path[uc_len-1] = '\0';
	}
#endif /* DHD_UCODE_DOWNLOAD */

#if 0
	/* clear the path in module parameter */
	if (dhd_download_fw_on_driverload) {
		firmware_path[0] = '\0';
		nvram_path[0] = '\0';
		clm_path[0] = '\0';
		config_path[0] = '\0';
	}
#endif
#ifdef DHD_UCODE_DOWNLOAD
	ucode_path[0] = '\0';
	DHD_ERROR(("ucode path: %s\n", dhdinfo->uc_path));
#endif /* DHD_UCODE_DOWNLOAD */

	/* fw_path and nv_path are not mandatory for BCMEMBEDIMAGE */
	if (dhdinfo->fw_path[0] == '\0') {
		DHD_ERROR(("firmware path not found\n"));
		return FALSE;
	}
	if (dhdinfo->nv_path[0] == '\0') {
		DHD_ERROR(("nvram path not found\n"));
		return FALSE;
	}

	return TRUE;
}

#if defined(BT_OVER_SDIO)
extern bool dhd_update_btfw_path(dhd_info_t *dhdinfo, char* btfw_path)
{
	int fw_len;
	const char *fw = NULL;
	wifi_adapter_info_t *adapter = dhdinfo->adapter;

	/* Update bt firmware path. The path may be from adapter info or module parameter
	 * The path from adapter info is used for initialization only (as it won't change).
	 *
	 * The btfw_path module parameter may be changed by the system at run
	 * time. When it changes we need to copy it to dhdinfo->btfw_path. Also Android private
	 * command may change dhdinfo->btfw_path. As such we need to clear the path info in
	 * module parameter after it is copied. We won't update the path until the module parameter
	 * is changed again (first character is not '\0')
	 */

	/* set default firmware and nvram path for built-in type driver */
	if (!dhd_download_fw_on_driverload) {
#ifdef CONFIG_BCMDHD_BTFW_PATH
		fw = CONFIG_BCMDHD_BTFW_PATH;
#endif /* CONFIG_BCMDHD_FW_PATH */
	}

	/* check if we need to initialize the path */
	if (dhdinfo->btfw_path[0] == '\0') {
		if (adapter && adapter->btfw_path && adapter->btfw_path[0] != '\0')
			fw = adapter->btfw_path;
	}

	/* Use module parameter if it is valid, EVEN IF the path has not been initialized
	 */
	if (btfw_path[0] != '\0')
		fw = btfw_path;

	if (fw && fw[0] != '\0') {
		fw_len = strlen(fw);
		if (fw_len >= sizeof(dhdinfo->btfw_path)) {
			DHD_ERROR(("fw path len exceeds max len of dhdinfo->btfw_path\n"));
			return FALSE;
		}
		strncpy(dhdinfo->btfw_path, fw, sizeof(dhdinfo->btfw_path));
		if (dhdinfo->btfw_path[fw_len-1] == '\n')
		       dhdinfo->btfw_path[fw_len-1] = '\0';
	}

	/* clear the path in module parameter */
	btfw_path[0] = '\0';

	if (dhdinfo->btfw_path[0] == '\0') {
		DHD_ERROR(("bt firmware path not found\n"));
		return FALSE;
	}

	return TRUE;
}
#endif /* defined (BT_OVER_SDIO) */

#if defined(BT_OVER_SDIO)
wlan_bt_handle_t dhd_bt_get_pub_hndl(void)
{
	DHD_ERROR(("%s: g_dhd_pub %p\n", __FUNCTION__, g_dhd_pub));
	/* assuming that dhd_pub_t type pointer is available from a global variable */
	return (wlan_bt_handle_t) g_dhd_pub;
} EXPORT_SYMBOL(dhd_bt_get_pub_hndl);

int dhd_download_btfw(wlan_bt_handle_t handle, char* btfw_path)
{
	int ret = -1;
	dhd_pub_t *dhdp = (dhd_pub_t *)handle;
	dhd_info_t *dhd = (dhd_info_t*)dhdp->info;

	/* Download BT firmware image to the dongle */
	if (dhd->pub.busstate == DHD_BUS_DATA && dhd_update_btfw_path(dhd, btfw_path)) {
		DHD_INFO(("%s: download btfw from: %s\n", __FUNCTION__, dhd->btfw_path));
		ret = dhd_bus_download_btfw(dhd->pub.bus, dhd->pub.osh, dhd->btfw_path);
		if (ret < 0) {
			DHD_ERROR(("%s: failed to download btfw from: %s\n",
				__FUNCTION__, dhd->btfw_path));
			return ret;
		}
	}
	return ret;
} EXPORT_SYMBOL(dhd_download_btfw);
#endif /* defined (BT_OVER_SDIO) */

#ifndef BCMDBUS
int
dhd_bus_start(dhd_pub_t *dhdp)
{
	int ret = -1;
	dhd_info_t *dhd = (dhd_info_t*)dhdp->info;
	unsigned long flags;

#if defined(DHD_DEBUG) && defined(BCMSDIO)
	int fw_download_start = 0, fw_download_end = 0, f2_sync_start = 0, f2_sync_end = 0;
#endif /* DHD_DEBUG && BCMSDIO */
	ASSERT(dhd);

	DHD_TRACE(("Enter %s:\n", __FUNCTION__));
	dhdp->dongle_trap_occured = 0;
#ifdef DHD_SSSR_DUMP
	/* Flag to indicate sssr dump is collected */
	dhdp->sssr_dump_collected = 0;
#endif /* DHD_SSSR_DUMP */
	dhdp->iovar_timeout_occured = 0;
#ifdef PCIE_FULL_DONGLE
	dhdp->d3ack_timeout_occured = 0;
	dhdp->livelock_occured = 0;
	dhdp->pktid_audit_failed = 0;
#endif /* PCIE_FULL_DONGLE */
	dhd->pub.iface_op_failed = 0;
	dhd->pub.scan_timeout_occurred = 0;
	dhd->pub.scan_busy_occurred = 0;
	/* Clear induced error during initialize */
	dhd->pub.dhd_induce_error = DHD_INDUCE_ERROR_CLEAR;

	/* set default value for now. Will be updated again in dhd_preinit_ioctls()
	 * after querying FW
	 */
	dhdp->event_log_max_sets = NUM_EVENT_LOG_SETS;
	dhdp->event_log_max_sets_queried = FALSE;
	dhdp->smmu_fault_occurred = 0;
#ifdef DNGL_AXI_ERROR_LOGGING
	dhdp->axi_error = FALSE;
#endif /* DNGL_AXI_ERROR_LOGGING */

	DHD_PERIM_LOCK(dhdp);
	/* try to download image and nvram to the dongle */
	if  (dhd->pub.busstate == DHD_BUS_DOWN && dhd_update_fw_nv_path(dhd)) {
		/* Indicate FW Download has not yet done */
		dhd->pub.fw_download_status = FW_DOWNLOAD_IN_PROGRESS;
		DHD_INFO(("%s download fw %s, nv %s, conf %s\n",
			__FUNCTION__, dhd->fw_path, dhd->nv_path, dhd->conf_path));
#if defined(DHD_DEBUG) && defined(BCMSDIO)
		fw_download_start = OSL_SYSUPTIME();
#endif /* DHD_DEBUG && BCMSDIO */
		ret = dhd_bus_download_firmware(dhd->pub.bus, dhd->pub.osh,
			dhd->fw_path, dhd->nv_path, dhd->clm_path, dhd->conf_path);
#if defined(DHD_DEBUG) && defined(BCMSDIO)
		fw_download_end = OSL_SYSUPTIME();
#endif /* DHD_DEBUG && BCMSDIO */
		if (ret < 0) {
			DHD_ERROR(("%s: failed to download firmware %s\n",
				__FUNCTION__, dhd->fw_path));
			DHD_PERIM_UNLOCK(dhdp);
			return ret;
		}
		/* Indicate FW Download has succeeded */
		dhd->pub.fw_download_status = FW_DOWNLOAD_DONE;
	}
	if (dhd->pub.busstate != DHD_BUS_LOAD) {
		DHD_PERIM_UNLOCK(dhdp);
		return -ENETDOWN;
	}

#ifdef BCMSDIO
	dhd_os_sdlock(dhdp);
#endif /* BCMSDIO */

	/* Start the watchdog timer */
	dhd->pub.tickcnt = 0;
	dhd_os_wd_timer(&dhd->pub, dhd_watchdog_ms);

	/* Bring up the bus */
	if ((ret = dhd_bus_init(&dhd->pub, FALSE)) != 0) {

		DHD_ERROR(("%s, dhd_bus_init failed %d\n", __FUNCTION__, ret));
#ifdef BCMSDIO
		dhd_os_sdunlock(dhdp);
#endif /* BCMSDIO */
		DHD_PERIM_UNLOCK(dhdp);
		return ret;
	}

	DHD_ENABLE_RUNTIME_PM(&dhd->pub);

#ifdef DHD_ULP
	dhd_ulp_set_ulp_state(dhdp, DHD_ULP_DISABLED);
#endif /* DHD_ULP */
#if defined(OOB_INTR_ONLY) || defined(BCMSPI_ANDROID) || defined(BCMPCIE_OOB_HOST_WAKE)
	/* Host registration for OOB interrupt */
	if (dhd_bus_oob_intr_register(dhdp)) {
		/* deactivate timer and wait for the handler to finish */
#if !defined(BCMPCIE_OOB_HOST_WAKE)
		DHD_GENERAL_LOCK(&dhd->pub, flags);
		dhd->wd_timer_valid = FALSE;
		DHD_GENERAL_UNLOCK(&dhd->pub, flags);
		del_timer_sync(&dhd->timer);

#endif /* !BCMPCIE_OOB_HOST_WAKE */
		DHD_DISABLE_RUNTIME_PM(&dhd->pub);
		DHD_PERIM_UNLOCK(dhdp);
		DHD_ERROR(("%s Host failed to register for OOB\n", __FUNCTION__));
		DHD_OS_WD_WAKE_UNLOCK(&dhd->pub);
		return -ENODEV;
	}

#if defined(BCMPCIE_OOB_HOST_WAKE)
	dhd_bus_oob_intr_set(dhdp, TRUE);
#else
	/* Enable oob at firmware */
	dhd_enable_oob_intr(dhd->pub.bus, TRUE);
#endif /* BCMPCIE_OOB_HOST_WAKE */
#elif defined(FORCE_WOWLAN)
	/* Enable oob at firmware */
	dhd_enable_oob_intr(dhd->pub.bus, TRUE);
#endif /* OOB_INTR_ONLY || BCMSPI_ANDROID || BCMPCIE_OOB_HOST_WAKE */
#ifdef PCIE_FULL_DONGLE
	{
		/* max_h2d_rings includes H2D common rings */
		uint32 max_h2d_rings = dhd_bus_max_h2d_queues(dhd->pub.bus);

		DHD_ERROR(("%s: Initializing %u h2drings\n", __FUNCTION__,
			max_h2d_rings));
		if ((ret = dhd_flow_rings_init(&dhd->pub, max_h2d_rings)) != BCME_OK) {
#ifdef BCMSDIO
			dhd_os_sdunlock(dhdp);
#endif /* BCMSDIO */
			DHD_PERIM_UNLOCK(dhdp);
			return ret;
		}
	}
#endif /* PCIE_FULL_DONGLE */

	/* Do protocol initialization necessary for IOCTL/IOVAR */
	ret = dhd_prot_init(&dhd->pub);
	if (unlikely(ret) != BCME_OK) {
		DHD_PERIM_UNLOCK(dhdp);
		DHD_OS_WD_WAKE_UNLOCK(&dhd->pub);
		return ret;
	}

	/* If bus is not ready, can't come up */
	if (dhd->pub.busstate != DHD_BUS_DATA) {
		DHD_GENERAL_LOCK(&dhd->pub, flags);
		dhd->wd_timer_valid = FALSE;
		DHD_GENERAL_UNLOCK(&dhd->pub, flags);
		del_timer_sync(&dhd->timer);
		DHD_ERROR(("%s failed bus is not ready\n", __FUNCTION__));
		DHD_DISABLE_RUNTIME_PM(&dhd->pub);
#ifdef BCMSDIO
		dhd_os_sdunlock(dhdp);
#endif /* BCMSDIO */
		DHD_PERIM_UNLOCK(dhdp);
		DHD_OS_WD_WAKE_UNLOCK(&dhd->pub);
		return -ENODEV;
	}

#ifdef BCMSDIO
	dhd_os_sdunlock(dhdp);
#endif /* BCMSDIO */

	/* Bus is ready, query any dongle information */
#if defined(DHD_DEBUG) && defined(BCMSDIO)
	f2_sync_start = OSL_SYSUPTIME();
#endif /* DHD_DEBUG && BCMSDIO */
	if ((ret = dhd_sync_with_dongle(&dhd->pub)) < 0) {
		DHD_GENERAL_LOCK(&dhd->pub, flags);
		dhd->wd_timer_valid = FALSE;
		DHD_GENERAL_UNLOCK(&dhd->pub, flags);
		del_timer_sync(&dhd->timer);
		DHD_ERROR(("%s failed to sync with dongle\n", __FUNCTION__));
		DHD_OS_WD_WAKE_UNLOCK(&dhd->pub);
		DHD_PERIM_UNLOCK(dhdp);
		return ret;
	}

#if defined(CONFIG_SOC_EXYNOS8895) || defined(CONFIG_SOC_EXYNOS9810) || \
	defined(CONFIG_SOC_EXYNOS9820)
	DHD_ERROR(("%s: Enable L1ss EP side\n", __FUNCTION__));
	exynos_pcie_l1ss_ctrl(1, PCIE_L1SS_CTRL_WIFI);
#endif /* CONFIG_SOC_EXYNOS8895 || CONFIG_SOC_EXYNOS9810 || CONFIG_SOC_EXYNOS9820 */

#if defined(DHD_DEBUG) && defined(BCMSDIO)
	f2_sync_end = OSL_SYSUPTIME();
	DHD_ERROR(("Time taken for FW download and F2 ready is: %d msec\n",
			(fw_download_end - fw_download_start) + (f2_sync_end - f2_sync_start)));
#endif /* DHD_DEBUG && BCMSDIO */

#ifdef ARP_OFFLOAD_SUPPORT
	if (dhd->pend_ipaddr) {
#ifdef AOE_IP_ALIAS_SUPPORT
		aoe_update_host_ipv4_table(&dhd->pub, dhd->pend_ipaddr, TRUE, 0);
#endif /* AOE_IP_ALIAS_SUPPORT */
		dhd->pend_ipaddr = 0;
	}
#endif /* ARP_OFFLOAD_SUPPORT */

	DHD_PERIM_UNLOCK(dhdp);

	return 0;
}
#endif /* !BCMDBUS */

#ifdef WLTDLS
int _dhd_tdls_enable(dhd_pub_t *dhd, bool tdls_on, bool auto_on, struct ether_addr *mac)
{
	uint32 tdls = tdls_on;
	int ret = 0;
	uint32 tdls_auto_op = 0;
	uint32 tdls_idle_time = CUSTOM_TDLS_IDLE_MODE_SETTING;
	int32 tdls_rssi_high = CUSTOM_TDLS_RSSI_THRESHOLD_HIGH;
	int32 tdls_rssi_low = CUSTOM_TDLS_RSSI_THRESHOLD_LOW;
	uint32 tdls_pktcnt_high = CUSTOM_TDLS_PCKTCNT_THRESHOLD_HIGH;
	uint32 tdls_pktcnt_low = CUSTOM_TDLS_PCKTCNT_THRESHOLD_LOW;

	BCM_REFERENCE(mac);
	if (!FW_SUPPORTED(dhd, tdls))
		return BCME_ERROR;

	if (dhd->tdls_enable == tdls_on)
		goto auto_mode;
	ret = dhd_iovar(dhd, 0, "tdls_enable", (char *)&tdls, sizeof(tdls), NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s: tdls %d failed %d\n", __FUNCTION__, tdls, ret));
		goto exit;
	}
	dhd->tdls_enable = tdls_on;
auto_mode:

	tdls_auto_op = auto_on;
	ret = dhd_iovar(dhd, 0, "tdls_auto_op", (char *)&tdls_auto_op, sizeof(tdls_auto_op), NULL,
			0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s: tdls_auto_op failed %d\n", __FUNCTION__, ret));
		goto exit;
	}

	if (tdls_auto_op) {
		ret = dhd_iovar(dhd, 0, "tdls_idle_time", (char *)&tdls_idle_time,
				sizeof(tdls_idle_time), NULL, 0, TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s: tdls_idle_time failed %d\n", __FUNCTION__, ret));
			goto exit;
		}
		ret = dhd_iovar(dhd, 0, "tdls_rssi_high", (char *)&tdls_rssi_high,
				sizeof(tdls_rssi_high), NULL, 0, TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s: tdls_rssi_high failed %d\n", __FUNCTION__, ret));
			goto exit;
		}
		ret = dhd_iovar(dhd, 0, "tdls_rssi_low", (char *)&tdls_rssi_low,
				sizeof(tdls_rssi_low), NULL, 0, TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s: tdls_rssi_low failed %d\n", __FUNCTION__, ret));
			goto exit;
		}
		ret = dhd_iovar(dhd, 0, "tdls_trigger_pktcnt_high", (char *)&tdls_pktcnt_high,
				sizeof(tdls_pktcnt_high), NULL, 0, TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s: tdls_trigger_pktcnt_high failed %d\n", __FUNCTION__, ret));
			goto exit;
		}
		ret = dhd_iovar(dhd, 0, "tdls_trigger_pktcnt_low", (char *)&tdls_pktcnt_low,
				sizeof(tdls_pktcnt_low), NULL, 0, TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s: tdls_trigger_pktcnt_low failed %d\n", __FUNCTION__, ret));
			goto exit;
		}
	}

exit:
	return ret;
}

int dhd_tdls_enable(struct net_device *dev, bool tdls_on, bool auto_on, struct ether_addr *mac)
{
	dhd_info_t *dhd = DHD_DEV_INFO(dev);
	int ret = 0;
	if (dhd)
		ret = _dhd_tdls_enable(&dhd->pub, tdls_on, auto_on, mac);
	else
		ret = BCME_ERROR;
	return ret;
}

int
dhd_tdls_set_mode(dhd_pub_t *dhd, bool wfd_mode)
{
	int ret = 0;
	bool auto_on = false;
	uint32 mode =  wfd_mode;

#ifdef ENABLE_TDLS_AUTO_MODE
	if (wfd_mode) {
		auto_on = false;
	} else {
		auto_on = true;
	}
#else
	auto_on = false;
#endif /* ENABLE_TDLS_AUTO_MODE */
	ret = _dhd_tdls_enable(dhd, false, auto_on, NULL);
	if (ret < 0) {
		DHD_ERROR(("Disable tdls_auto_op failed. %d\n", ret));
		return ret;
	}

	ret = dhd_iovar(dhd, 0, "tdls_wfd_mode", (char *)&mode, sizeof(mode), NULL, 0, TRUE);
	if ((ret < 0) && (ret != BCME_UNSUPPORTED)) {
		DHD_ERROR(("%s: tdls_wfd_mode faile_wfd_mode %d\n", __FUNCTION__, ret));
		return ret;
	}

	ret = _dhd_tdls_enable(dhd, true, auto_on, NULL);
	if (ret < 0) {
		DHD_ERROR(("enable tdls_auto_op failed. %d\n", ret));
		return ret;
	}

	dhd->tdls_mode = mode;
	return ret;
}
#ifdef PCIE_FULL_DONGLE
int dhd_tdls_update_peer_info(dhd_pub_t *dhdp, wl_event_msg_t *event)
{
	dhd_pub_t *dhd_pub = dhdp;
	tdls_peer_node_t *cur = dhd_pub->peer_tbl.node;
	tdls_peer_node_t *new = NULL, *prev = NULL;
	int ifindex = dhd_ifname2idx(dhd_pub->info, event->ifname);
	uint8 *da = (uint8 *)&event->addr.octet[0];
	bool connect = FALSE;
	uint32 reason = ntoh32(event->reason);
	unsigned long flags;

	/* No handling needed for peer discovered reason */
	if (reason == WLC_E_TDLS_PEER_DISCOVERED) {
		return BCME_ERROR;
	}
	if (reason == WLC_E_TDLS_PEER_CONNECTED)
		connect = TRUE;
	else if (reason == WLC_E_TDLS_PEER_DISCONNECTED)
		connect = FALSE;
	else
	{
		DHD_ERROR(("%s: TDLS Event reason is unknown\n", __FUNCTION__));
		return BCME_ERROR;
	}
	if (ifindex == DHD_BAD_IF)
		return BCME_ERROR;

	if (connect) {
		while (cur != NULL) {
			if (!memcmp(da, cur->addr, ETHER_ADDR_LEN)) {
				DHD_ERROR(("%s: TDLS Peer exist already %d\n",
					__FUNCTION__, __LINE__));
				return BCME_ERROR;
			}
			cur = cur->next;
		}

		new = MALLOC(dhd_pub->osh, sizeof(tdls_peer_node_t));
		if (new == NULL) {
			DHD_ERROR(("%s: Failed to allocate memory\n", __FUNCTION__));
			return BCME_ERROR;
		}
		memcpy(new->addr, da, ETHER_ADDR_LEN);
		DHD_TDLS_LOCK(&dhdp->tdls_lock, flags);
		new->next = dhd_pub->peer_tbl.node;
		dhd_pub->peer_tbl.node = new;
		dhd_pub->peer_tbl.tdls_peer_count++;
		DHD_TDLS_UNLOCK(&dhdp->tdls_lock, flags);

	} else {
		while (cur != NULL) {
			if (!memcmp(da, cur->addr, ETHER_ADDR_LEN)) {
				dhd_flow_rings_delete_for_peer(dhd_pub, (uint8)ifindex, da);
				DHD_TDLS_LOCK(&dhdp->tdls_lock, flags);
				if (prev)
					prev->next = cur->next;
				else
					dhd_pub->peer_tbl.node = cur->next;
				MFREE(dhd_pub->osh, cur, sizeof(tdls_peer_node_t));
				dhd_pub->peer_tbl.tdls_peer_count--;
				DHD_TDLS_UNLOCK(&dhdp->tdls_lock, flags);
				return BCME_OK;
			}
			prev = cur;
			cur = cur->next;
		}
		DHD_ERROR(("%s: TDLS Peer Entry Not found\n", __FUNCTION__));
	}
	return BCME_OK;
}
#endif /* PCIE_FULL_DONGLE */
#endif // endif

bool dhd_is_concurrent_mode(dhd_pub_t *dhd)
{
	if (!dhd)
		return FALSE;

	if (dhd->op_mode & DHD_FLAG_CONCURR_MULTI_CHAN_MODE)
		return TRUE;
	else if ((dhd->op_mode & DHD_FLAG_CONCURR_SINGLE_CHAN_MODE) ==
		DHD_FLAG_CONCURR_SINGLE_CHAN_MODE)
		return TRUE;
	else
		return FALSE;
}
#if !defined(AP) && defined(WLP2P)
/* From Android JerryBean release, the concurrent mode is enabled by default and the firmware
 * name would be fw_bcmdhd.bin. So we need to determine whether P2P is enabled in the STA
 * firmware and accordingly enable concurrent mode (Apply P2P settings). SoftAP firmware
 * would still be named as fw_bcmdhd_apsta.
 */
uint32
dhd_get_concurrent_capabilites(dhd_pub_t *dhd)
{
	int32 ret = 0;
	char buf[WLC_IOCTL_SMLEN];
	bool mchan_supported = FALSE;
	/* if dhd->op_mode is already set for HOSTAP and Manufacturing
	 * test mode, that means we only will use the mode as it is
	 */
	if (dhd->op_mode & (DHD_FLAG_HOSTAP_MODE | DHD_FLAG_MFG_MODE))
		return 0;
	if (FW_SUPPORTED(dhd, vsdb)) {
		mchan_supported = TRUE;
	}
	if (!FW_SUPPORTED(dhd, p2p)) {
		DHD_TRACE(("Chip does not support p2p\n"));
		return 0;
	} else {
		/* Chip supports p2p but ensure that p2p is really implemented in firmware or not */
		memset(buf, 0, sizeof(buf));
		ret = dhd_iovar(dhd, 0, "p2p", NULL, 0, (char *)&buf,
				sizeof(buf), FALSE);
		if (ret < 0) {
			DHD_ERROR(("%s: Get P2P failed (error=%d)\n", __FUNCTION__, ret));
			return 0;
		} else {
			if (buf[0] == 1) {
				/* By default, chip supports single chan concurrency,
				* now lets check for mchan
				*/
				ret = DHD_FLAG_CONCURR_SINGLE_CHAN_MODE;
				if (mchan_supported)
					ret |= DHD_FLAG_CONCURR_MULTI_CHAN_MODE;
				if (FW_SUPPORTED(dhd, rsdb)) {
					ret |= DHD_FLAG_RSDB_MODE;
				}
#ifdef WL_SUPPORT_MULTIP2P
				if (FW_SUPPORTED(dhd, mp2p)) {
					ret |= DHD_FLAG_MP2P_MODE;
				}
#endif /* WL_SUPPORT_MULTIP2P */
#if defined(WL_ENABLE_P2P_IF) || defined(WL_CFG80211_P2P_DEV_IF)
				return ret;
#else
				return 0;
#endif /* WL_ENABLE_P2P_IF || WL_CFG80211_P2P_DEV_IF */
			}
		}
	}
	return 0;
}
#endif // endif

#if defined(WLADPS)

int
dhd_enable_adps(dhd_pub_t *dhd, uint8 on)
{
	int i;
	int len;
	int ret = BCME_OK;

	bcm_iov_buf_t *iov_buf = NULL;
	wl_adps_params_v1_t *data = NULL;

	len = OFFSETOF(bcm_iov_buf_t, data) + sizeof(*data);
	iov_buf = MALLOC(dhd->osh, len);
	if (iov_buf == NULL) {
		DHD_ERROR(("%s - failed to allocate %d bytes for iov_buf\n", __FUNCTION__, len));
		ret = BCME_NOMEM;
		goto exit;
	}

	iov_buf->version = WL_ADPS_IOV_VER;
	iov_buf->len = sizeof(*data);
	iov_buf->id = WL_ADPS_IOV_MODE;

	data = (wl_adps_params_v1_t *)iov_buf->data;
	data->version = ADPS_SUB_IOV_VERSION_1;
	data->length = sizeof(*data);
	data->mode = on;

	for (i = 1; i <= MAX_BANDS; i++) {
		data->band = i;
		ret = dhd_iovar(dhd, 0, "adps", (char *)iov_buf, len, NULL, 0, TRUE);
		if (ret < 0) {
			if (ret == BCME_UNSUPPORTED) {
				DHD_ERROR(("%s adps is not supported\n", __FUNCTION__));
				ret = BCME_OK;
				goto exit;
			}
			else {
				DHD_ERROR(("%s fail to set adps %s for band %d (%d)\n",
					__FUNCTION__, on ? "On" : "Off", i, ret));
				goto exit;
			}
		}
	}

exit:
	if (iov_buf) {
		MFREE(dhd->osh, iov_buf, len);
		iov_buf = NULL;
	}
	return ret;
}
#endif // endif

int
dhd_preinit_ioctls(dhd_pub_t *dhd)
{
	int ret = 0;
	char eventmask[WL_EVENTING_MASK_LEN];
	char iovbuf[WL_EVENTING_MASK_LEN + 12];	/*  Room for "event_msgs" + '\0' + bitvec  */
	uint32 buf_key_b4_m4 = 1;
	uint8 msglen;
	eventmsgs_ext_t *eventmask_msg = NULL;
	uint32 event_log_max_sets = 0;
	char* iov_buf = NULL;
	int ret2 = 0;
	uint32 wnm_cap = 0;
#if defined(BCMSUP_4WAY_HANDSHAKE)
	uint32 sup_wpa = 1;
#endif /* BCMSUP_4WAY_HANDSHAKE */
#if defined(CUSTOM_AMPDU_BA_WSIZE)
	uint32 ampdu_ba_wsize = 0;
#endif // endif
#if defined(CUSTOM_AMPDU_MPDU)
	int32 ampdu_mpdu = 0;
#endif // endif
#if defined(CUSTOM_AMPDU_RELEASE)
	int32 ampdu_release = 0;
#endif // endif
#if defined(CUSTOM_AMSDU_AGGSF)
	int32 amsdu_aggsf = 0;
#endif // endif

#if defined(BCMSDIO) || defined(BCMDBUS)
#ifdef PROP_TXSTATUS
	int wlfc_enable = TRUE;
#ifndef DISABLE_11N
	uint32 hostreorder = 1;
	uint wl_down = 1;
#endif /* DISABLE_11N */
#endif /* PROP_TXSTATUS */
#endif /* BCMSDIO || BCMDBUS */
#ifndef PCIE_FULL_DONGLE
	uint32 wl_ap_isolate;
#endif /* PCIE_FULL_DONGLE */
	uint32 frameburst = CUSTOM_FRAMEBURST_SET;
	uint wnm_bsstrans_resp = 0;
#ifdef SUPPORT_SET_CAC
	uint32 cac = 1;
#endif /* SUPPORT_SET_CAC */

#ifdef DHD_ENABLE_LPC
	uint32 lpc = 1;
#endif /* DHD_ENABLE_LPC */
	uint power_mode = PM_FAST;
#if defined(BCMSDIO)
	uint32 dongle_align = DHD_SDALIGN;
	uint32 glom = CUSTOM_GLOM_SETTING;
#endif /* defined(BCMSDIO) */
#if defined(USE_WL_CREDALL)
	uint32 credall = 1;
#endif // endif
	uint bcn_timeout = CUSTOM_BCN_TIMEOUT;
	uint scancache_enab = TRUE;
#ifdef ENABLE_BCN_LI_BCN_WAKEUP
	uint32 bcn_li_bcn = 1;
#endif /* ENABLE_BCN_LI_BCN_WAKEUP */
	uint retry_max = CUSTOM_ASSOC_RETRY_MAX;
#if defined(ARP_OFFLOAD_SUPPORT)
	int arpoe = 0;
#endif // endif
	int scan_assoc_time = DHD_SCAN_ASSOC_ACTIVE_TIME;
	int scan_unassoc_time = DHD_SCAN_UNASSOC_ACTIVE_TIME;
	int scan_passive_time = DHD_SCAN_PASSIVE_TIME;
	char buf[WLC_IOCTL_SMLEN];
	char *ptr;
	uint32 listen_interval = CUSTOM_LISTEN_INTERVAL; /* Default Listen Interval in Beacons */
#if defined(DHD_8021X_DUMP) && defined(SHOW_LOGTRACE)
	wl_el_tag_params_t *el_tag = NULL;
#endif /* DHD_8021X_DUMP */
#ifdef ROAM_ENABLE
	uint roamvar = 0;
	int roam_trigger[2] = {CUSTOM_ROAM_TRIGGER_SETTING, WLC_BAND_ALL};
	int roam_scan_period[2] = {10, WLC_BAND_ALL};
	int roam_delta[2] = {CUSTOM_ROAM_DELTA_SETTING, WLC_BAND_ALL};
#ifdef ROAM_AP_ENV_DETECTION
	int roam_env_mode = AP_ENV_INDETERMINATE;
#endif /* ROAM_AP_ENV_DETECTION */
#ifdef FULL_ROAMING_SCAN_PERIOD_60_SEC
	int roam_fullscan_period = 60;
#else /* FULL_ROAMING_SCAN_PERIOD_60_SEC */
	int roam_fullscan_period = 120;
#endif /* FULL_ROAMING_SCAN_PERIOD_60_SEC */
#ifdef DISABLE_BCNLOSS_ROAM
	uint roam_bcnloss_off = 1;
#endif /* DISABLE_BCNLOSS_ROAM */
#else
#ifdef DISABLE_BUILTIN_ROAM
	uint roamvar = 1;
#endif /* DISABLE_BUILTIN_ROAM */
#endif /* ROAM_ENABLE */

#if defined(SOFTAP)
	uint dtim = 1;
#endif // endif
#if (defined(AP) && !defined(WLP2P)) || (!defined(AP) && defined(WL_CFG80211))
	struct ether_addr p2p_ea;
#endif // endif
#ifdef BCMCCX
	uint32 ccx = 1;
#endif // endif
#ifdef SOFTAP_UAPSD_OFF
	uint32 wme_apsd = 0;
#endif /* SOFTAP_UAPSD_OFF */
#if (defined(AP) || defined(WLP2P)) && !defined(SOFTAP_AND_GC)
	uint32 apsta = 1; /* Enable APSTA mode */
#elif defined(SOFTAP_AND_GC)
	uint32 apsta = 0;
	int ap_mode = 1;
#endif /* (defined(AP) || defined(WLP2P)) && !defined(SOFTAP_AND_GC) */
#ifdef GET_CUSTOM_MAC_ENABLE
	struct ether_addr ea_addr;
	char hw_ether[62];
#endif /* GET_CUSTOM_MAC_ENABLE */
#ifdef OKC_SUPPORT
	uint32 okc = 1;
#endif // endif

#ifdef DISABLE_11N
	uint32 nmode = 0;
#endif /* DISABLE_11N */

#ifdef USE_WL_TXBF
	uint32 txbf = 1;
#endif /* USE_WL_TXBF */
#ifdef DISABLE_TXBFR
	uint32 txbf_bfr_cap = 0;
#endif /* DISABLE_TXBFR */
#ifdef AMPDU_VO_ENABLE
	struct ampdu_tid_control tid;
#endif // endif
#if defined(PROP_TXSTATUS)
#ifdef USE_WFA_CERT_CONF
	uint32 proptx = 0;
#endif /* USE_WFA_CERT_CONF */
#endif /* PROP_TXSTATUS */
#ifdef DHD_SET_FW_HIGHSPEED
	uint32 ack_ratio = 250;
	uint32 ack_ratio_depth = 64;
#endif /* DHD_SET_FW_HIGHSPEED */
#if defined(SUPPORT_2G_VHT) || defined(SUPPORT_5G_1024QAM_VHT)
	uint32 vht_features = 0; /* init to 0, will be set based on each support */
#endif /* SUPPORT_2G_VHT || SUPPORT_5G_1024QAM_VHT */
#ifdef DISABLE_11N_PROPRIETARY_RATES
	uint32 ht_features = 0;
#endif /* DISABLE_11N_PROPRIETARY_RATES */
#ifdef CUSTOM_PSPRETEND_THR
	uint32 pspretend_thr = CUSTOM_PSPRETEND_THR;
#endif // endif
#ifdef CUSTOM_EVENT_PM_WAKE
	uint32 pm_awake_thresh = CUSTOM_EVENT_PM_WAKE;
#endif	/* CUSTOM_EVENT_PM_WAKE */
#ifdef DISABLE_PRUNED_SCAN
	uint32 scan_features = 0;
#endif /* DISABLE_PRUNED_SCAN */
#ifdef BCMPCIE_OOB_HOST_WAKE
	uint32 hostwake_oob = 0;
#endif /* BCMPCIE_OOB_HOST_WAKE */
#ifdef EVENT_LOG_RATE_HC
	/* threshold number of lines per second */
#define EVENT_LOG_RATE_HC_THRESHOLD	1000
	uint32 event_log_rate_hc = EVENT_LOG_RATE_HC_THRESHOLD;
#endif /* EVENT_LOG_RATE_HC */
	wl_wlc_version_t wlc_ver;

#ifdef PKT_FILTER_SUPPORT
	dhd_pkt_filter_enable = TRUE;
#ifdef APF
	dhd->apf_set = FALSE;
#endif /* APF */
#endif /* PKT_FILTER_SUPPORT */
	dhd->suspend_bcn_li_dtim = CUSTOM_SUSPEND_BCN_LI_DTIM;
#ifdef ENABLE_MAX_DTIM_IN_SUSPEND
	dhd->max_dtim_enable = TRUE;
#else
	dhd->max_dtim_enable = FALSE;
#endif /* ENABLE_MAX_DTIM_IN_SUSPEND */
	dhd->disable_dtim_in_suspend = FALSE;
#ifdef SUPPORT_SET_TID
	dhd->tid_mode = SET_TID_OFF;
	dhd->target_uid = 0;
	dhd->target_tid = 0;
#endif /* SUPPORT_SET_TID */
	DHD_TRACE(("Enter %s\n", __FUNCTION__));

#ifdef DHDTCPACK_SUPPRESS
	dhd_tcpack_suppress_set(dhd, dhd->conf->tcpack_sup_mode);
#endif
	dhd->op_mode = 0;

#if defined(CUSTOM_COUNTRY_CODE)
	/* clear AP flags */
	dhd->dhd_cflags &= ~WLAN_PLAT_AP_FLAG;
#endif /* CUSTOM_COUNTRY_CODE && (CUSTOMER_HW2 || BOARD_HIKEY) */

	/* query for 'ver' to get version info from firmware */
	memset(buf, 0, sizeof(buf));
	ptr = buf;
	ret = dhd_iovar(dhd, 0, "ver", NULL, 0, (char *)&buf, sizeof(buf), FALSE);
	if (ret < 0)
		DHD_ERROR(("%s failed %d\n", __FUNCTION__, ret));
	else {
		bcmstrtok(&ptr, "\n", 0);
		/* Print fw version info */
		strncpy(fw_version, buf, FW_VER_STR_LEN);
		fw_version[FW_VER_STR_LEN-1] = '\0';
	}

	/* Set op_mode as MFG_MODE if WLTEST is present in "wl ver" */
	if (strstr(fw_version, "WLTEST") != NULL) {
		DHD_ERROR(("%s: wl ver has WLTEST, setting op_mode as DHD_FLAG_MFG_MODE\n",
			__FUNCTION__));
		op_mode = DHD_FLAG_MFG_MODE;
	}

	if ((!op_mode && dhd_get_fw_mode(dhd->info) == DHD_FLAG_MFG_MODE) ||
		(op_mode == DHD_FLAG_MFG_MODE)) {
		dhd->op_mode = DHD_FLAG_MFG_MODE;
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
		/* disable runtimePM by default in MFG mode. */
		pm_runtime_disable(dhd_bus_to_dev(dhd->bus));
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */
		/* Check and adjust IOCTL response timeout for Manufactring firmware */
		dhd_os_set_ioctl_resp_timeout(MFG_IOCTL_RESP_TIMEOUT);
		DHD_ERROR(("%s : Set IOCTL response time for Manufactring Firmware\n",
			__FUNCTION__));
	} else {
		dhd_os_set_ioctl_resp_timeout(IOCTL_RESP_TIMEOUT);
		DHD_INFO(("%s : Set IOCTL response time.\n", __FUNCTION__));
	}
#ifdef BCMPCIE_OOB_HOST_WAKE
	ret = dhd_iovar(dhd, 0, "bus:hostwake_oob", NULL, 0, (char *)&hostwake_oob,
		sizeof(hostwake_oob), FALSE);
	if (ret < 0) {
		DHD_ERROR(("%s: hostwake_oob IOVAR not present, proceed\n", __FUNCTION__));
	} else {
		if (hostwake_oob == 0) {
			DHD_ERROR(("%s: hostwake_oob is not enabled in the NVRAM, STOP\n",
				__FUNCTION__));
			ret = BCME_UNSUPPORTED;
			goto done;
		} else {
			DHD_ERROR(("%s: hostwake_oob enabled\n", __FUNCTION__));
		}
	}
#endif /* BCMPCIE_OOB_HOST_WAKE */

#ifdef DNGL_AXI_ERROR_LOGGING
	ret = dhd_iovar(dhd, 0, "axierror_logbuf_addr", NULL, 0, (char *)&dhd->axierror_logbuf_addr,
		sizeof(dhd->axierror_logbuf_addr), FALSE);
	if (ret < 0) {
		DHD_ERROR(("%s: axierror_logbuf_addr IOVAR not present, proceed\n", __FUNCTION__));
		dhd->axierror_logbuf_addr = 0;
	} else {
		DHD_ERROR(("%s: axierror_logbuf_addr : 0x%x\n", __FUNCTION__,
			dhd->axierror_logbuf_addr));
	}
#endif /* DNGL_AXI_ERROR_LOGGING */

#ifdef EVENT_LOG_RATE_HC
	ret = dhd_iovar(dhd, 0, "event_log_rate_hc", (char *)&event_log_rate_hc,
		sizeof(event_log_rate_hc), NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s event_log_rate_hc set failed %d\n", __FUNCTION__, ret));
	} else  {
		DHD_ERROR(("%s event_log_rate_hc set with threshold:%d\n", __FUNCTION__,
			event_log_rate_hc));
	}
#endif /* EVENT_LOG_RATE_HC */

#ifdef GET_CUSTOM_MAC_ENABLE
	memset(hw_ether, 0, sizeof(hw_ether));
	ret = wifi_platform_get_mac_addr(dhd->info->adapter, hw_ether, 0);
#ifdef GET_CUSTOM_MAC_FROM_CONFIG
	if (!memcmp(&ether_null, &dhd->conf->hw_ether, ETHER_ADDR_LEN)) {
		ret = 0;
	} else
#endif
	if (!ret) {
		memset(buf, 0, sizeof(buf));
#ifdef GET_CUSTOM_MAC_FROM_CONFIG
		memcpy(hw_ether, &dhd->conf->hw_ether, sizeof(dhd->conf->hw_ether));
#endif
		bcopy(hw_ether, ea_addr.octet, sizeof(struct ether_addr));
		bcm_mkiovar("cur_etheraddr", (void *)&ea_addr, ETHER_ADDR_LEN, buf, sizeof(buf));
		ret = dhd_wl_ioctl_cmd(dhd, WLC_SET_VAR, buf, sizeof(buf), TRUE, 0);
		if (ret < 0) {
			memset(buf, 0, sizeof(buf));
			bcm_mkiovar("hw_ether", hw_ether, sizeof(hw_ether), buf, sizeof(buf));
			ret = dhd_wl_ioctl_cmd(dhd, WLC_SET_VAR, buf, sizeof(buf), TRUE, 0);
			if (ret) {
				DHD_ERROR(("%s: can't set MAC address MAC="MACDBG", error=%d\n",
					__FUNCTION__, MAC2STRDBG(hw_ether), ret));
				prhex("MACPAD", &hw_ether[ETHER_ADDR_LEN], sizeof(hw_ether)-ETHER_ADDR_LEN);
				ret = BCME_NOTUP;
				goto done;
			}
		}
	} else {
		DHD_ERROR(("%s: can't get custom MAC address, ret=%d\n", __FUNCTION__, ret));
		ret = BCME_NOTUP;
		goto done;
	}
#endif /* GET_CUSTOM_MAC_ENABLE */
	/* Get the default device MAC address directly from firmware */
	memset(buf, 0, sizeof(buf));
	bcm_mkiovar("cur_etheraddr", 0, 0, buf, sizeof(buf));
	if ((ret = dhd_wl_ioctl_cmd(dhd, WLC_GET_VAR, buf, sizeof(buf),
		FALSE, 0)) < 0) {
		DHD_ERROR(("%s: can't get MAC address , error=%d\n", __FUNCTION__, ret));
		ret = BCME_NOTUP;
		goto done;
	}
	/* Update public MAC address after reading from Firmware */
	memcpy(dhd->mac.octet, buf, ETHER_ADDR_LEN);

	if ((ret = dhd_apply_default_clm(dhd, dhd->clm_path)) < 0) {
		DHD_ERROR(("%s: CLM set failed. Abort initialization.\n", __FUNCTION__));
		goto done;
	}

	/* get a capabilities from firmware */
	{
		uint32 cap_buf_size = sizeof(dhd->fw_capabilities);
		memset(dhd->fw_capabilities, 0, cap_buf_size);
		ret = dhd_iovar(dhd, 0, "cap", NULL, 0, dhd->fw_capabilities, (cap_buf_size - 1),
				FALSE);
		if (ret < 0) {
			DHD_ERROR(("%s: Get Capability failed (error=%d)\n",
				__FUNCTION__, ret));
			return 0;
		}

		memmove(&dhd->fw_capabilities[1], dhd->fw_capabilities, (cap_buf_size - 1));
		dhd->fw_capabilities[0] = ' ';
		dhd->fw_capabilities[cap_buf_size - 2] = ' ';
		dhd->fw_capabilities[cap_buf_size - 1] = '\0';
	}

	if ((!op_mode && dhd_get_fw_mode(dhd->info) == DHD_FLAG_HOSTAP_MODE) ||
		(op_mode == DHD_FLAG_HOSTAP_MODE)) {
#ifdef SET_RANDOM_MAC_SOFTAP
		uint rand_mac;
#endif /* SET_RANDOM_MAC_SOFTAP */
		dhd->op_mode = DHD_FLAG_HOSTAP_MODE;
#if defined(ARP_OFFLOAD_SUPPORT)
			arpoe = 0;
#endif // endif
#ifdef PKT_FILTER_SUPPORT
		if (dhd_conf_get_insuspend(dhd, AP_FILTER_IN_SUSPEND))
			dhd_pkt_filter_enable = TRUE;
		else
			dhd_pkt_filter_enable = FALSE;
#endif // endif
#ifdef SET_RANDOM_MAC_SOFTAP
		SRANDOM32((uint)jiffies);
		rand_mac = RANDOM32();
		iovbuf[0] = (unsigned char)(vendor_oui >> 16) | 0x02;	/* local admin bit */
		iovbuf[1] = (unsigned char)(vendor_oui >> 8);
		iovbuf[2] = (unsigned char)vendor_oui;
		iovbuf[3] = (unsigned char)(rand_mac & 0x0F) | 0xF0;
		iovbuf[4] = (unsigned char)(rand_mac >> 8);
		iovbuf[5] = (unsigned char)(rand_mac >> 16);

		ret = dhd_iovar(dhd, 0, "cur_etheraddr", (char *)&iovbuf, ETHER_ADDR_LEN, NULL, 0,
				TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s: can't set MAC address , error=%d\n", __FUNCTION__, ret));
		} else
			memcpy(dhd->mac.octet, iovbuf, ETHER_ADDR_LEN);
#endif /* SET_RANDOM_MAC_SOFTAP */
#ifdef USE_DYNAMIC_F2_BLKSIZE
		dhdsdio_func_blocksize(dhd, 2, DYNAMIC_F2_BLKSIZE_FOR_NONLEGACY);
#endif /* USE_DYNAMIC_F2_BLKSIZE */
#ifdef SOFTAP_UAPSD_OFF
		ret = dhd_iovar(dhd, 0, "wme_apsd", (char *)&wme_apsd, sizeof(wme_apsd), NULL, 0,
				TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s: set wme_apsd 0 fail (error=%d)\n",
				__FUNCTION__, ret));
		}
#endif /* SOFTAP_UAPSD_OFF */
#if defined(CUSTOM_COUNTRY_CODE)
		/* set AP flag for specific country code of SOFTAP */
		dhd->dhd_cflags |= WLAN_PLAT_AP_FLAG | WLAN_PLAT_NODFS_FLAG;
#endif /* CUSTOM_COUNTRY_CODE && (CUSTOMER_HW2 || BOARD_HIKEY) */
	} else if ((!op_mode && dhd_get_fw_mode(dhd->info) == DHD_FLAG_MFG_MODE) ||
		(op_mode == DHD_FLAG_MFG_MODE)) {
#if defined(ARP_OFFLOAD_SUPPORT)
		arpoe = 0;
#endif /* ARP_OFFLOAD_SUPPORT */
#ifdef PKT_FILTER_SUPPORT
		dhd_pkt_filter_enable = FALSE;
#endif /* PKT_FILTER_SUPPORT */
		dhd->op_mode = DHD_FLAG_MFG_MODE;
#ifdef USE_DYNAMIC_F2_BLKSIZE
		dhdsdio_func_blocksize(dhd, 2, DYNAMIC_F2_BLKSIZE_FOR_NONLEGACY);
#endif /* USE_DYNAMIC_F2_BLKSIZE */
#ifndef CUSTOM_SET_ANTNPM
		if (FW_SUPPORTED(dhd, rsdb)) {
			wl_config_t rsdb_mode;
			memset(&rsdb_mode, 0, sizeof(rsdb_mode));
			ret = dhd_iovar(dhd, 0, "rsdb_mode", (char *)&rsdb_mode, sizeof(rsdb_mode),
				NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s Disable rsdb_mode is failed ret= %d\n",
					__FUNCTION__, ret));
			}
		}
#endif /* !CUSTOM_SET_ANTNPM */
	} else {
		uint32 concurrent_mode = 0;
		if ((!op_mode && dhd_get_fw_mode(dhd->info) == DHD_FLAG_P2P_MODE) ||
			(op_mode == DHD_FLAG_P2P_MODE)) {
#if defined(ARP_OFFLOAD_SUPPORT)
			arpoe = 0;
#endif // endif
#ifdef PKT_FILTER_SUPPORT
			dhd_pkt_filter_enable = FALSE;
#endif // endif
			dhd->op_mode = DHD_FLAG_P2P_MODE;
		} else if ((!op_mode && dhd_get_fw_mode(dhd->info) == DHD_FLAG_IBSS_MODE) ||
			(op_mode == DHD_FLAG_IBSS_MODE)) {
			dhd->op_mode = DHD_FLAG_IBSS_MODE;
		} else
			dhd->op_mode = DHD_FLAG_STA_MODE;
#if !defined(AP) && defined(WLP2P)
		if (dhd->op_mode != DHD_FLAG_IBSS_MODE &&
			(concurrent_mode = dhd_get_concurrent_capabilites(dhd))) {
#if defined(ARP_OFFLOAD_SUPPORT)
			arpoe = 1;
#endif // endif
			dhd->op_mode |= concurrent_mode;
		}

		/* Check if we are enabling p2p */
		if (dhd->op_mode & DHD_FLAG_P2P_MODE) {
			ret = dhd_iovar(dhd, 0, "apsta", (char *)&apsta, sizeof(apsta), NULL, 0,
					TRUE);
			if (ret < 0)
				DHD_ERROR(("%s APSTA for P2P failed ret= %d\n", __FUNCTION__, ret));

#if defined(SOFTAP_AND_GC)
		if ((ret = dhd_wl_ioctl_cmd(dhd, WLC_SET_AP,
			(char *)&ap_mode, sizeof(ap_mode), TRUE, 0)) < 0) {
				DHD_ERROR(("%s WLC_SET_AP failed %d\n", __FUNCTION__, ret));
		}
#endif // endif
			memcpy(&p2p_ea, &dhd->mac, ETHER_ADDR_LEN);
			ETHER_SET_LOCALADDR(&p2p_ea);
			ret = dhd_iovar(dhd, 0, "p2p_da_override", (char *)&p2p_ea, sizeof(p2p_ea),
					NULL, 0, TRUE);
			if (ret < 0)
				DHD_ERROR(("%s p2p_da_override ret= %d\n", __FUNCTION__, ret));
			else
				DHD_INFO(("dhd_preinit_ioctls: p2p_da_override succeeded\n"));
		}
#else
	(void)concurrent_mode;
#endif // endif
	}

#ifdef DISABLE_PRUNED_SCAN
	if (FW_SUPPORTED(dhd, rsdb)) {
		ret = dhd_iovar(dhd, 0, "scan_features", (char *)&scan_features,
				sizeof(scan_features), iovbuf, sizeof(iovbuf), FALSE);
		if (ret < 0) {
			DHD_ERROR(("%s get scan_features is failed ret=%d\n",
				__FUNCTION__, ret));
		} else {
			memcpy(&scan_features, iovbuf, 4);
			scan_features &= ~RSDB_SCAN_DOWNGRADED_CH_PRUNE_ROAM;
			ret = dhd_iovar(dhd, 0, "scan_features", (char *)&scan_features,
					sizeof(scan_features), NULL, 0, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s set scan_features is failed ret=%d\n",
					__FUNCTION__, ret));
			}
		}
	}
#endif /* DISABLE_PRUNED_SCAN */

	DHD_ERROR(("Firmware up: op_mode=0x%04x, MAC="MACDBG"\n",
		dhd->op_mode, MAC2STRDBG(dhd->mac.octet)));
#if defined(DHD_BLOB_EXISTENCE_CHECK)
	if (!dhd->is_blob)
#endif /* DHD_BLOB_EXISTENCE_CHECK */
	{
		/* get a ccode and revision for the country code */
#if defined(CUSTOM_COUNTRY_CODE)
		get_customized_country_code(dhd->info->adapter, dhd->dhd_cspec.country_abbrev,
			&dhd->dhd_cspec, dhd->dhd_cflags);
#else
		get_customized_country_code(dhd->info->adapter, dhd->dhd_cspec.country_abbrev,
			&dhd->dhd_cspec);
#endif /* CUSTOM_COUNTRY_CODE */
	}

#if defined(RXFRAME_THREAD) && defined(RXTHREAD_ONLYSTA)
	if (dhd->op_mode == DHD_FLAG_HOSTAP_MODE)
		dhd->info->rxthread_enabled = FALSE;
	else
		dhd->info->rxthread_enabled = TRUE;
#endif // endif
	/* Set Country code  */
	if (dhd->dhd_cspec.ccode[0] != 0) {
		ret = dhd_iovar(dhd, 0, "country", (char *)&dhd->dhd_cspec, sizeof(wl_country_t),
				NULL, 0, TRUE);
		if (ret < 0)
			DHD_ERROR(("%s: country code setting failed\n", __FUNCTION__));
	}

	/* Set Listen Interval */
	ret = dhd_iovar(dhd, 0, "assoc_listen", (char *)&listen_interval, sizeof(listen_interval),
			NULL, 0, TRUE);
	if (ret < 0)
		DHD_ERROR(("%s assoc_listen failed %d\n", __FUNCTION__, ret));

#if defined(ROAM_ENABLE) || defined(DISABLE_BUILTIN_ROAM)
#ifdef USE_WFA_CERT_CONF
	if (sec_get_param_wfa_cert(dhd, SET_PARAM_ROAMOFF, &roamvar) == BCME_OK) {
		DHD_ERROR(("%s: read roam_off param =%d\n", __FUNCTION__, roamvar));
	}
#endif /* USE_WFA_CERT_CONF */
	/* Disable built-in roaming to allowed ext supplicant to take care of roaming */
	ret = dhd_iovar(dhd, 0, "roam_off", (char *)&roamvar, sizeof(roamvar), NULL, 0, TRUE);
#endif /* ROAM_ENABLE || DISABLE_BUILTIN_ROAM */
#if defined(ROAM_ENABLE)
#ifdef DISABLE_BCNLOSS_ROAM
	ret = dhd_iovar(dhd, 0, "roam_bcnloss_off", (char *)&roam_bcnloss_off,
			sizeof(roam_bcnloss_off), NULL, 0, TRUE);
#endif /* DISABLE_BCNLOSS_ROAM */
	if ((ret = dhd_wl_ioctl_cmd(dhd, WLC_SET_ROAM_TRIGGER, roam_trigger,
		sizeof(roam_trigger), TRUE, 0)) < 0)
		DHD_ERROR(("%s: roam trigger set failed %d\n", __FUNCTION__, ret));
	if ((ret = dhd_wl_ioctl_cmd(dhd, WLC_SET_ROAM_SCAN_PERIOD, roam_scan_period,
		sizeof(roam_scan_period), TRUE, 0)) < 0)
		DHD_ERROR(("%s: roam scan period set failed %d\n", __FUNCTION__, ret));
	if ((dhd_wl_ioctl_cmd(dhd, WLC_SET_ROAM_DELTA, roam_delta,
		sizeof(roam_delta), TRUE, 0)) < 0)
		DHD_ERROR(("%s: roam delta set failed %d\n", __FUNCTION__, ret));
	ret = dhd_iovar(dhd, 0, "fullroamperiod", (char *)&roam_fullscan_period,
			sizeof(roam_fullscan_period), NULL, 0, TRUE);
	if (ret < 0)
		DHD_ERROR(("%s: roam fullscan period set failed %d\n", __FUNCTION__, ret));
#ifdef ROAM_AP_ENV_DETECTION
	if (roam_trigger[0] == WL_AUTO_ROAM_TRIGGER) {
		if (dhd_iovar(dhd, 0, "roam_env_detection", (char *)&roam_env_mode,
				sizeof(roam_env_mode), NULL, 0, TRUE) == BCME_OK)
			dhd->roam_env_detection = TRUE;
		else
			dhd->roam_env_detection = FALSE;
	}
#endif /* ROAM_AP_ENV_DETECTION */
#endif /* ROAM_ENABLE */

#ifdef CUSTOM_EVENT_PM_WAKE
	ret = dhd_iovar(dhd, 0, "const_awake_thresh", (char *)&pm_awake_thresh,
			sizeof(pm_awake_thresh), NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s set const_awake_thresh failed %d\n", __FUNCTION__, ret));
	}
#endif	/* CUSTOM_EVENT_PM_WAKE */
#ifdef OKC_SUPPORT
	ret = dhd_iovar(dhd, 0, "okc_enable", (char *)&okc, sizeof(okc), NULL, 0, TRUE);
#endif // endif
#ifdef BCMCCX
	ret = dhd_iovar(dhd, 0, "ccx_enable", (char *)&ccx, sizeof(ccx), NULL, 0, TRUE);
#endif /* BCMCCX */

#ifdef WLTDLS
	dhd->tdls_enable = FALSE;
	dhd_tdls_set_mode(dhd, false);
#endif /* WLTDLS */

#ifdef DHD_ENABLE_LPC
	/* Set lpc 1 */
	ret = dhd_iovar(dhd, 0, "lpc", (char *)&lpc, sizeof(lpc), NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s Set lpc failed  %d\n", __FUNCTION__, ret));

		if (ret == BCME_NOTDOWN) {
			uint wl_down = 1;
			ret = dhd_wl_ioctl_cmd(dhd, WLC_DOWN,
				(char *)&wl_down, sizeof(wl_down), TRUE, 0);
			DHD_ERROR(("%s lpc fail WL_DOWN : %d, lpc = %d\n", __FUNCTION__, ret, lpc));

			ret = dhd_iovar(dhd, 0, "lpc", (char *)&lpc, sizeof(lpc), NULL, 0, TRUE);
			DHD_ERROR(("%s Set lpc ret --> %d\n", __FUNCTION__, ret));
		}
	}
#endif /* DHD_ENABLE_LPC */

#ifdef WLADPS
	if (dhd->op_mode & DHD_FLAG_STA_MODE) {
		if ((ret = dhd_enable_adps(dhd, ADPS_ENABLE)) != BCME_OK) {
			DHD_ERROR(("%s dhd_enable_adps failed %d\n",
					__FUNCTION__, ret));
		}
	}
#endif /* WLADPS */

#ifdef DHD_PM_CONTROL_FROM_FILE
	sec_control_pm(dhd, &power_mode);
#else
	/* Set PowerSave mode */
	(void) dhd_wl_ioctl_cmd(dhd, WLC_SET_PM, (char *)&power_mode, sizeof(power_mode), TRUE, 0);
#endif /* DHD_PM_CONTROL_FROM_FILE */

#if defined(BCMSDIO)
	/* Match Host and Dongle rx alignment */
	ret = dhd_iovar(dhd, 0, "bus:txglomalign", (char *)&dongle_align, sizeof(dongle_align),
			NULL, 0, TRUE);

#if defined(USE_WL_CREDALL)
	/* enable credall to reduce the chance of no bus credit happened. */
	ret = dhd_iovar(dhd, 0, "bus:credall", (char *)&credall, sizeof(credall), NULL, 0, TRUE);
#endif // endif

#ifdef USE_WFA_CERT_CONF
	if (sec_get_param_wfa_cert(dhd, SET_PARAM_BUS_TXGLOM_MODE, &glom) == BCME_OK) {
		DHD_ERROR(("%s, read txglom param =%d\n", __FUNCTION__, glom));
	}
#endif /* USE_WFA_CERT_CONF */
	if (glom != DEFAULT_GLOM_VALUE) {
		DHD_INFO(("%s set glom=0x%X\n", __FUNCTION__, glom));
		ret = dhd_iovar(dhd, 0, "bus:txglom", (char *)&glom, sizeof(glom), NULL, 0, TRUE);
	}
#endif /* defined(BCMSDIO) */

	/* Setup timeout if Beacons are lost and roam is off to report link down */
	ret = dhd_iovar(dhd, 0, "bcn_timeout", (char *)&bcn_timeout, sizeof(bcn_timeout), NULL, 0,
			TRUE);

	/* Setup assoc_retry_max count to reconnect target AP in dongle */
	ret = dhd_iovar(dhd, 0, "assoc_retry_max", (char *)&retry_max, sizeof(retry_max), NULL, 0,
			TRUE);

#if defined(AP) && !defined(WLP2P)
	ret = dhd_iovar(dhd, 0, "apsta", (char *)&apsta, sizeof(apsta), NULL, 0, TRUE);

#endif /* defined(AP) && !defined(WLP2P) */

#ifdef MIMO_ANT_SETTING
	dhd_sel_ant_from_file(dhd);
#endif /* MIMO_ANT_SETTING */

#if defined(SOFTAP)
	if (ap_fw_loaded == TRUE) {
		dhd_wl_ioctl_cmd(dhd, WLC_SET_DTIMPRD, (char *)&dtim, sizeof(dtim), TRUE, 0);
	}
#endif // endif

#if defined(KEEP_ALIVE)
	{
	/* Set Keep Alive : be sure to use FW with -keepalive */
	int res;

#if defined(SOFTAP)
	if (ap_fw_loaded == FALSE)
#endif // endif
		if (!(dhd->op_mode &
			(DHD_FLAG_HOSTAP_MODE | DHD_FLAG_MFG_MODE))) {
			if ((res = dhd_keep_alive_onoff(dhd)) < 0)
				DHD_ERROR(("%s set keeplive failed %d\n",
				__FUNCTION__, res));
		}
	}
#endif /* defined(KEEP_ALIVE) */

#ifdef USE_WL_TXBF
	ret = dhd_iovar(dhd, 0, "txbf", (char *)&txbf, sizeof(txbf), NULL, 0, TRUE);
	if (ret < 0)
		DHD_ERROR(("%s Set txbf failed  %d\n", __FUNCTION__, ret));

#endif /* USE_WL_TXBF */

	ret = dhd_iovar(dhd, 0, "scancache", (char *)&scancache_enab, sizeof(scancache_enab), NULL,
			0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s Set scancache failed %d\n", __FUNCTION__, ret));
	}

	ret = dhd_iovar(dhd, 0, "event_log_max_sets", NULL, 0, (char *)&event_log_max_sets,
		sizeof(event_log_max_sets), FALSE);
	if (ret == BCME_OK) {
		dhd->event_log_max_sets = event_log_max_sets;
	} else {
		dhd->event_log_max_sets = NUM_EVENT_LOG_SETS;
	}
	/* Make sure max_sets is set first with wmb and then sets_queried,
	 * this will be used during parsing the logsets in the reverse order.
	 */
	OSL_SMP_WMB();
	dhd->event_log_max_sets_queried = TRUE;
	DHD_ERROR(("%s: event_log_max_sets: %d ret: %d\n",
		__FUNCTION__, dhd->event_log_max_sets, ret));

#ifdef DISABLE_TXBFR
	ret = dhd_iovar(dhd, 0, "txbf_bfr_cap", (char *)&txbf_bfr_cap, sizeof(txbf_bfr_cap), NULL,
			0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s Clear txbf_bfr_cap failed  %d\n", __FUNCTION__, ret));
	}
#endif /* DISABLE_TXBFR */

#ifdef USE_WFA_CERT_CONF
#ifdef USE_WL_FRAMEBURST
	 if (sec_get_param_wfa_cert(dhd, SET_PARAM_FRAMEBURST, &frameburst) == BCME_OK) {
		DHD_ERROR(("%s, read frameburst param=%d\n", __FUNCTION__, frameburst));
	 }
#endif /* USE_WL_FRAMEBURST */
	 g_frameburst = frameburst;
#endif /* USE_WFA_CERT_CONF */
#ifdef DISABLE_WL_FRAMEBURST_SOFTAP
	/* Disable Framebursting for SofAP */
	if (dhd->op_mode & DHD_FLAG_HOSTAP_MODE) {
		frameburst = 0;
	}
#endif /* DISABLE_WL_FRAMEBURST_SOFTAP */
	/* Set frameburst to value */
	if ((ret = dhd_wl_ioctl_cmd(dhd, WLC_SET_FAKEFRAG, (char *)&frameburst,
		sizeof(frameburst), TRUE, 0)) < 0) {
		DHD_INFO(("%s frameburst not supported  %d\n", __FUNCTION__, ret));
	}
#ifdef DHD_SET_FW_HIGHSPEED
	/* Set ack_ratio */
	ret = dhd_iovar(dhd, 0, "ack_ratio", (char *)&ack_ratio, sizeof(ack_ratio), NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s Set ack_ratio failed  %d\n", __FUNCTION__, ret));
	}

	/* Set ack_ratio_depth */
	ret = dhd_iovar(dhd, 0, "ack_ratio_depth", (char *)&ack_ratio_depth,
			sizeof(ack_ratio_depth), NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s Set ack_ratio_depth failed  %d\n", __FUNCTION__, ret));
	}
#endif /* DHD_SET_FW_HIGHSPEED */

	iov_buf = (char*)MALLOC(dhd->osh, WLC_IOCTL_SMLEN);
	if (iov_buf == NULL) {
		DHD_ERROR(("failed to allocate %d bytes for iov_buf\n", WLC_IOCTL_SMLEN));
		ret = BCME_NOMEM;
		goto done;
	}

#if defined(CUSTOM_AMPDU_BA_WSIZE)
	/* Set ampdu ba wsize to 64 or 16 */
#ifdef CUSTOM_AMPDU_BA_WSIZE
	ampdu_ba_wsize = CUSTOM_AMPDU_BA_WSIZE;
#endif // endif
	if (ampdu_ba_wsize != 0) {
		ret = dhd_iovar(dhd, 0, "ampdu_ba_wsize", (char *)&ampdu_ba_wsize,
				sizeof(ampdu_ba_wsize), NULL, 0, TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s Set ampdu_ba_wsize to %d failed  %d\n",
				__FUNCTION__, ampdu_ba_wsize, ret));
		}
	}
#endif // endif

#if defined(CUSTOM_AMPDU_MPDU)
	ampdu_mpdu = CUSTOM_AMPDU_MPDU;
	if (ampdu_mpdu != 0 && (ampdu_mpdu <= ampdu_ba_wsize)) {
		ret = dhd_iovar(dhd, 0, "ampdu_mpdu", (char *)&ampdu_mpdu, sizeof(ampdu_mpdu),
				NULL, 0, TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s Set ampdu_mpdu to %d failed  %d\n",
				__FUNCTION__, CUSTOM_AMPDU_MPDU, ret));
		}
	}
#endif /* CUSTOM_AMPDU_MPDU */

#if defined(CUSTOM_AMPDU_RELEASE)
	ampdu_release = CUSTOM_AMPDU_RELEASE;
	if (ampdu_release != 0 && (ampdu_release <= ampdu_ba_wsize)) {
		ret = dhd_iovar(dhd, 0, "ampdu_release", (char *)&ampdu_release,
				sizeof(ampdu_release), NULL, 0, TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s Set ampdu_release to %d failed  %d\n",
				__FUNCTION__, CUSTOM_AMPDU_RELEASE, ret));
		}
	}
#endif /* CUSTOM_AMPDU_RELEASE */

#if defined(CUSTOM_AMSDU_AGGSF)
	amsdu_aggsf = CUSTOM_AMSDU_AGGSF;
	if (amsdu_aggsf != 0) {
		ret = dhd_iovar(dhd, 0, "amsdu_aggsf", (char *)&amsdu_aggsf, sizeof(amsdu_aggsf),
				NULL, 0, TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s Set amsdu_aggsf to %d failed  %d\n",
				__FUNCTION__, CUSTOM_AMSDU_AGGSF, ret));
		}
	}
#endif /* CUSTOM_AMSDU_AGGSF */

#if defined(BCMSUP_4WAY_HANDSHAKE)
	/* Read 4-way handshake requirements */
	if (dhd_use_idsup == 1) {
		ret = dhd_iovar(dhd, 0, "sup_wpa", (char *)&sup_wpa, sizeof(sup_wpa),
				(char *)&iovbuf, sizeof(iovbuf), FALSE);
		/* sup_wpa iovar returns NOTREADY status on some platforms using modularized
		 * in-dongle supplicant.
		 */
		if (ret >= 0 || ret == BCME_NOTREADY)
			dhd->fw_4way_handshake = TRUE;
		DHD_TRACE(("4-way handshake mode is: %d\n", dhd->fw_4way_handshake));
	}
#endif /* BCMSUP_4WAY_HANDSHAKE */
#if defined(SUPPORT_2G_VHT) || defined(SUPPORT_5G_1024QAM_VHT)
	ret = dhd_iovar(dhd, 0, "vht_features", (char *)&vht_features, sizeof(vht_features),
			NULL, 0, FALSE);
	if (ret < 0) {
		DHD_ERROR(("%s vht_features get failed %d\n", __FUNCTION__, ret));
		vht_features = 0;
	} else {
#ifdef SUPPORT_2G_VHT
		vht_features |= 0x3; /* 2G support */
#endif /* SUPPORT_2G_VHT */
#ifdef SUPPORT_5G_1024QAM_VHT
		vht_features |= 0x6; /* 5G 1024 QAM support */
#endif /* SUPPORT_5G_1024QAM_VHT */
	}
	if (vht_features) {
		ret = dhd_iovar(dhd, 0, "vht_features", (char *)&vht_features, sizeof(vht_features),
				NULL, 0, TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s vht_features set failed %d\n", __FUNCTION__, ret));

			if (ret == BCME_NOTDOWN) {
				uint wl_down = 1;
				ret = dhd_wl_ioctl_cmd(dhd, WLC_DOWN,
					(char *)&wl_down, sizeof(wl_down), TRUE, 0);
				DHD_ERROR(("%s vht_features fail WL_DOWN : %d,"
					" vht_features = 0x%x\n",
					__FUNCTION__, ret, vht_features));

				ret = dhd_iovar(dhd, 0, "vht_features", (char *)&vht_features,
						sizeof(vht_features), NULL, 0, TRUE);

				DHD_ERROR(("%s vht_features set. ret --> %d\n", __FUNCTION__, ret));
			}
		}
	}
#endif /* SUPPORT_2G_VHT || SUPPORT_5G_1024QAM_VHT */
#ifdef DISABLE_11N_PROPRIETARY_RATES
	ret = dhd_iovar(dhd, 0, "ht_features", (char *)&ht_features, sizeof(ht_features), NULL, 0,
			TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s ht_features set failed %d\n", __FUNCTION__, ret));
	}
#endif /* DISABLE_11N_PROPRIETARY_RATES */
#if defined(DISABLE_HE_ENAB) || defined(CUSTOM_CONTROL_HE_ENAB)
#if defined(DISABLE_HE_ENAB)
	control_he_enab = 0;
#endif /* DISABLE_HE_ENAB */
	dhd_control_he_enab(dhd, control_he_enab);
#endif /* DISABLE_HE_ENAB || CUSTOM_CONTROL_HE_ENAB */

#ifdef CUSTOM_PSPRETEND_THR
	/* Turn off MPC in AP mode */
	ret = dhd_iovar(dhd, 0, "pspretend_threshold", (char *)&pspretend_thr,
			sizeof(pspretend_thr), NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s pspretend_threshold for HostAPD failed  %d\n",
			__FUNCTION__, ret));
	}
#endif // endif

	ret = dhd_iovar(dhd, 0, "buf_key_b4_m4", (char *)&buf_key_b4_m4, sizeof(buf_key_b4_m4),
			NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s buf_key_b4_m4 set failed %d\n", __FUNCTION__, ret));
	}
#ifdef SUPPORT_SET_CAC
	ret = dhd_iovar(dhd, 0, "cac", (char *)&cac, sizeof(cac), NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s Failed to set cac to %d, %d\n", __FUNCTION__, cac, ret));
	}
#endif /* SUPPORT_SET_CAC */
#ifdef DHD_ULP
	/* Get the required details from dongle during preinit ioctl */
	dhd_ulp_preinit(dhd);
#endif /* DHD_ULP */

	/* Read event_msgs mask */
	ret = dhd_iovar(dhd, 0, "event_msgs", eventmask, WL_EVENTING_MASK_LEN, iovbuf,
			sizeof(iovbuf), FALSE);
	if (ret < 0) {
		DHD_ERROR(("%s read Event mask failed %d\n", __FUNCTION__, ret));
		goto done;
	}
	bcopy(iovbuf, eventmask, WL_EVENTING_MASK_LEN);

	/* Setup event_msgs */
	setbit(eventmask, WLC_E_SET_SSID);
	setbit(eventmask, WLC_E_PRUNE);
	setbit(eventmask, WLC_E_AUTH);
	setbit(eventmask, WLC_E_AUTH_IND);
	setbit(eventmask, WLC_E_ASSOC);
	setbit(eventmask, WLC_E_REASSOC);
	setbit(eventmask, WLC_E_REASSOC_IND);
	if (!(dhd->op_mode & DHD_FLAG_IBSS_MODE))
		setbit(eventmask, WLC_E_DEAUTH);
	setbit(eventmask, WLC_E_DEAUTH_IND);
	setbit(eventmask, WLC_E_DISASSOC_IND);
	setbit(eventmask, WLC_E_DISASSOC);
	setbit(eventmask, WLC_E_JOIN);
	setbit(eventmask, WLC_E_START);
	setbit(eventmask, WLC_E_ASSOC_IND);
	setbit(eventmask, WLC_E_PSK_SUP);
	setbit(eventmask, WLC_E_LINK);
	setbit(eventmask, WLC_E_MIC_ERROR);
	setbit(eventmask, WLC_E_ASSOC_REQ_IE);
	setbit(eventmask, WLC_E_ASSOC_RESP_IE);
#ifdef LIMIT_BORROW
	setbit(eventmask, WLC_E_ALLOW_CREDIT_BORROW);
#endif // endif
#ifndef WL_CFG80211
	setbit(eventmask, WLC_E_PMKID_CACHE);
//	setbit(eventmask, WLC_E_TXFAIL); // terence 20181106: remove unnecessary event
#endif // endif
	setbit(eventmask, WLC_E_JOIN_START);
//	setbit(eventmask, WLC_E_SCAN_COMPLETE); // terence 20150628: remove redundant event
#ifdef DHD_DEBUG
	setbit(eventmask, WLC_E_SCAN_CONFIRM_IND);
#endif // endif
#ifdef PNO_SUPPORT
	setbit(eventmask, WLC_E_PFN_NET_FOUND);
	setbit(eventmask, WLC_E_PFN_BEST_BATCHING);
	setbit(eventmask, WLC_E_PFN_BSSID_NET_FOUND);
	setbit(eventmask, WLC_E_PFN_BSSID_NET_LOST);
#endif /* PNO_SUPPORT */
	/* enable dongle roaming event */
#ifdef WL_CFG80211
#if !defined(ROAM_EVT_DISABLE)
	setbit(eventmask, WLC_E_ROAM);
#endif /* !ROAM_EVT_DISABLE */
	setbit(eventmask, WLC_E_BSSID);
#endif /* WL_CFG80211 */
#ifdef BCMCCX
	setbit(eventmask, WLC_E_ADDTS_IND);
	setbit(eventmask, WLC_E_DELTS_IND);
#endif /* BCMCCX */
#ifdef WLTDLS
	setbit(eventmask, WLC_E_TDLS_PEER_EVENT);
#endif /* WLTDLS */
#ifdef WL_ESCAN
	setbit(eventmask, WLC_E_ESCAN_RESULT);
#endif /* WL_ESCAN */
#ifdef CSI_SUPPORT
	setbit(eventmask, WLC_E_CSI);
#endif /* CSI_SUPPORT */
#ifdef RTT_SUPPORT
	setbit(eventmask, WLC_E_PROXD);
#endif /* RTT_SUPPORT */
#ifdef WL_CFG80211
	setbit(eventmask, WLC_E_ESCAN_RESULT);
	setbit(eventmask, WLC_E_AP_STARTED);
	setbit(eventmask, WLC_E_ACTION_FRAME_RX);
	if (dhd->op_mode & DHD_FLAG_P2P_MODE) {
		setbit(eventmask, WLC_E_P2P_DISC_LISTEN_COMPLETE);
	}
#endif /* WL_CFG80211 */

#if defined(SHOW_LOGTRACE) && defined(LOGTRACE_FROM_FILE)
	if (dhd_logtrace_from_file(dhd)) {
		setbit(eventmask, WLC_E_TRACE);
	} else {
		clrbit(eventmask, WLC_E_TRACE);
	}
#elif defined(SHOW_LOGTRACE)
	setbit(eventmask, WLC_E_TRACE);
#else
	clrbit(eventmask, WLC_E_TRACE);
#endif /* defined(SHOW_LOGTRACE) && defined(LOGTRACE_FROM_FILE) */

	setbit(eventmask, WLC_E_CSA_COMPLETE_IND);
#ifdef CUSTOM_EVENT_PM_WAKE
	setbit(eventmask, WLC_E_EXCESS_PM_WAKE_EVENT);
#endif	/* CUSTOM_EVENT_PM_WAKE */
#ifdef DHD_LOSSLESS_ROAMING
	setbit(eventmask, WLC_E_ROAM_PREP);
#endif // endif
	/* nan events */
	setbit(eventmask, WLC_E_NAN);
#if defined(PCIE_FULL_DONGLE) && defined(DHD_LOSSLESS_ROAMING)
	dhd_update_flow_prio_map(dhd, DHD_FLOW_PRIO_LLR_MAP);
#endif /* defined(PCIE_FULL_DONGLE) && defined(DHD_LOSSLESS_ROAMING) */

#if defined(BCMPCIE) && defined(EAPOL_PKT_PRIO)
	dhd_update_flow_prio_map(dhd, DHD_FLOW_PRIO_LLR_MAP);
#endif /* defined(BCMPCIE) && defined(EAPOL_PKT_PRIO) */

	/* Write updated Event mask */
	ret = dhd_iovar(dhd, 0, "event_msgs", eventmask, WL_EVENTING_MASK_LEN, NULL, 0, TRUE);
	if (ret < 0) {
		DHD_ERROR(("%s Set Event mask failed %d\n", __FUNCTION__, ret));
		goto done;
	}

	/* make up event mask ext message iovar for event larger than 128 */
	msglen = ROUNDUP(WLC_E_LAST, NBBY)/NBBY + EVENTMSGS_EXT_STRUCT_SIZE;
	eventmask_msg = (eventmsgs_ext_t*)MALLOC(dhd->osh, msglen);
	if (eventmask_msg == NULL) {
		DHD_ERROR(("failed to allocate %d bytes for event_msg_ext\n", msglen));
		ret = BCME_NOMEM;
		goto done;
	}
	bzero(eventmask_msg, msglen);
	eventmask_msg->ver = EVENTMSGS_VER;
	eventmask_msg->len = ROUNDUP(WLC_E_LAST, NBBY)/NBBY;

	/* Read event_msgs_ext mask */
	ret2 = dhd_iovar(dhd, 0, "event_msgs_ext", (char *)eventmask_msg, msglen, iov_buf,
			WLC_IOCTL_SMLEN, FALSE);

	if (ret2 == 0) { /* event_msgs_ext must be supported */
		bcopy(iov_buf, eventmask_msg, msglen);
#ifdef RSSI_MONITOR_SUPPORT
		setbit(eventmask_msg->mask, WLC_E_RSSI_LQM);
#endif /* RSSI_MONITOR_SUPPORT */
#ifdef GSCAN_SUPPORT
		setbit(eventmask_msg->mask, WLC_E_PFN_GSCAN_FULL_RESULT);
		setbit(eventmask_msg->mask, WLC_E_PFN_SCAN_COMPLETE);
		setbit(eventmask_msg->mask, WLC_E_PFN_SSID_EXT);
		setbit(eventmask_msg->mask, WLC_E_ROAM_EXP_EVENT);
#endif /* GSCAN_SUPPORT */
		setbit(eventmask_msg->mask, WLC_E_RSSI_LQM);
#ifdef BT_WIFI_HANDOVER
		setbit(eventmask_msg->mask, WLC_E_BT_WIFI_HANDOVER_REQ);
#endif /* BT_WIFI_HANDOVER */
#ifdef DBG_PKT_MON
		setbit(eventmask_msg->mask, WLC_E_ROAM_PREP);
#endif /* DBG_PKT_MON */
#ifdef DHD_ULP
		setbit(eventmask_msg->mask, WLC_E_ULP);
#endif // endif
#ifdef WL_NATOE
		setbit(eventmask_msg->mask, WLC_E_NATOE_NFCT);
#endif /* WL_NATOE */
#ifdef WL_NAN
		setbit(eventmask_msg->mask, WLC_E_SLOTTED_BSS_PEER_OP);
#endif /* WL_NAN */
#ifdef WL_MBO
		setbit(eventmask_msg->mask, WLC_E_MBO);
#endif /* WL_MBO */
#ifdef WL_CLIENT_SAE
		setbit(eventmask_msg->mask, WLC_E_JOIN_START);
#endif /* WL_CLIENT_SAE */
#ifdef WL_BCNRECV
		setbit(eventmask_msg->mask, WLC_E_BCNRECV_ABORTED);
#endif /* WL_BCNRECV */
#ifdef WL_CAC_TS
		setbit(eventmask_msg->mask, WLC_E_ADDTS_IND);
		setbit(eventmask_msg->mask, WLC_E_DELTS_IND);
#endif /* WL_CAC_TS */
#ifdef WL_CHAN_UTIL
		setbit(eventmask_msg->mask, WLC_E_BSS_LOAD);
#endif /* WL_CHAN_UTIL */

		/* Write updated Event mask */
		eventmask_msg->ver = EVENTMSGS_VER;
		eventmask_msg->command = EVENTMSGS_SET_MASK;
		eventmask_msg->len = ROUNDUP(WLC_E_LAST, NBBY)/NBBY;
		ret = dhd_iovar(dhd, 0, "event_msgs_ext", (char *)eventmask_msg, msglen, NULL, 0,
				TRUE);
		if (ret < 0) {
			DHD_ERROR(("%s write event mask ext failed %d\n", __FUNCTION__, ret));
			goto done;
		}
	} else if (ret2 == BCME_UNSUPPORTED || ret2 == BCME_VERSION) {
		/* Skip for BCME_UNSUPPORTED or BCME_VERSION */
		DHD_ERROR(("%s event_msgs_ext not support or version mismatch %d\n",
			__FUNCTION__, ret2));
	} else {
		DHD_ERROR(("%s read event mask ext failed %d\n", __FUNCTION__, ret2));
		ret = ret2;
		goto done;
	}

#if defined(DHD_8021X_DUMP) && defined(SHOW_LOGTRACE)
	/* Enabling event log trace for EAP events */
	el_tag = (wl_el_tag_params_t *)MALLOC(dhd->osh, sizeof(wl_el_tag_params_t));
	if (el_tag == NULL) {
		DHD_ERROR(("failed to allocate %d bytes for event_msg_ext\n",
				(int)sizeof(wl_el_tag_params_t)));
		ret = BCME_NOMEM;
		goto done;
	}
	el_tag->tag = EVENT_LOG_TAG_4WAYHANDSHAKE;
	el_tag->set = 1;
	el_tag->flags = EVENT_LOG_TAG_FLAG_LOG;
	ret = dhd_iovar(dhd, 0, "event_log_tag_control", (char *)el_tag, sizeof(*el_tag), NULL, 0,
			TRUE);
#endif /* DHD_8021X_DUMP */

	dhd_wl_ioctl_cmd(dhd, WLC_SET_SCAN_CHANNEL_TIME, (char *)&scan_assoc_time,
		sizeof(scan_assoc_time), TRUE, 0);
	dhd_wl_ioctl_cmd(dhd, WLC_SET_SCAN_UNASSOC_TIME, (char *)&scan_unassoc_time,
		sizeof(scan_unassoc_time), TRUE, 0);
	dhd_wl_ioctl_cmd(dhd, WLC_SET_SCAN_PASSIVE_TIME, (char *)&scan_passive_time,
		sizeof(scan_passive_time), TRUE, 0);

#ifdef ARP_OFFLOAD_SUPPORT
	/* Set and enable ARP offload feature for STA only  */
#if defined(SOFTAP)
	if (arpoe && !ap_fw_loaded)
#else
	if (arpoe)
#endif // endif
	{
		dhd_arp_offload_enable(dhd, TRUE);
		dhd_arp_offload_set(dhd, dhd_arp_mode);
	} else {
		dhd_arp_offload_enable(dhd, FALSE);
		dhd_arp_offload_set(dhd, 0);
	}
	dhd_arp_enable = arpoe;
#endif /* ARP_OFFLOAD_SUPPORT */

#ifdef PKT_FILTER_SUPPORT
	/* Setup default defintions for pktfilter , enable in suspend */
	if (dhd_master_mode) {
		dhd->pktfilter_count = 6;
		dhd->pktfilter[DHD_BROADCAST_FILTER_NUM] = NULL;
		if (!FW_SUPPORTED(dhd, pf6)) {
			dhd->pktfilter[DHD_MULTICAST4_FILTER_NUM] = NULL;
			dhd->pktfilter[DHD_MULTICAST6_FILTER_NUM] = NULL;
		} else {
			/* Immediately pkt filter TYPE 6 Discard IPv4/IPv6 Multicast Packet */
			dhd->pktfilter[DHD_MULTICAST4_FILTER_NUM] = DISCARD_IPV4_MCAST;
			dhd->pktfilter[DHD_MULTICAST6_FILTER_NUM] = DISCARD_IPV6_MCAST;
		}
		/* apply APP pktfilter */
		dhd->pktfilter[DHD_ARP_FILTER_NUM] = "105 0 0 12 0xFFFF 0x0806";

#ifdef BLOCK_IPV6_PACKET
		/* Setup filter to allow only IPv4 unicast frames */
		dhd->pktfilter[DHD_UNICAST_FILTER_NUM] = "100 0 0 0 "
			HEX_PREF_STR UNI_FILTER_STR ZERO_ADDR_STR ETHER_TYPE_STR IPV6_FILTER_STR
			" "
			HEX_PREF_STR ZERO_ADDR_STR ZERO_ADDR_STR ETHER_TYPE_STR ZERO_TYPE_STR;
#else
		/* Setup filter to allow only unicast */
		dhd->pktfilter[DHD_UNICAST_FILTER_NUM] = "100 0 0 0 0x01 0x00";
#endif /* BLOCK_IPV6_PACKET */

#ifdef PASS_IPV4_SUSPEND
		dhd->pktfilter[DHD_MDNS_FILTER_NUM] = "104 0 0 0 0xFFFFFF 0x01005E";
#else
		/* Add filter to pass multicastDNS packet and NOT filter out as Broadcast */
		dhd->pktfilter[DHD_MDNS_FILTER_NUM] = NULL;
#endif /* PASS_IPV4_SUSPEND */
		if (FW_SUPPORTED(dhd, pf6)) {
			/* Immediately pkt filter TYPE 6 Dicard Broadcast IP packet */
			dhd->pktfilter[DHD_IP4BCAST_DROP_FILTER_NUM] = DISCARD_IPV4_BCAST;
			/* Immediately pkt filter TYPE 6 Dicard Cisco STP packet */
			dhd->pktfilter[DHD_LLC_STP_DROP_FILTER_NUM] = DISCARD_LLC_STP;
			/* Immediately pkt filter TYPE 6 Dicard Cisco XID protocol */
			dhd->pktfilter[DHD_LLC_XID_DROP_FILTER_NUM] = DISCARD_LLC_XID;
			dhd->pktfilter_count = 10;
		}

#ifdef GAN_LITE_NAT_KEEPALIVE_FILTER
		dhd->pktfilter_count = 4;
		/* Setup filter to block broadcast and NAT Keepalive packets */
		/* discard all broadcast packets */
		dhd->pktfilter[DHD_UNICAST_FILTER_NUM] = "100 0 0 0 0xffffff 0xffffff";
		/* discard NAT Keepalive packets */
		dhd->pktfilter[DHD_BROADCAST_FILTER_NUM] = "102 0 0 36 0xffffffff 0x11940009";
		/* discard NAT Keepalive packets */
		dhd->pktfilter[DHD_MULTICAST4_FILTER_NUM] = "104 0 0 38 0xffffffff 0x11940009";
		dhd->pktfilter[DHD_MULTICAST6_FILTER_NUM] = NULL;
#endif /* GAN_LITE_NAT_KEEPALIVE_FILTER */
	} else
		dhd_conf_discard_pkt_filter(dhd);
	dhd_conf_add_pkt_filter(dhd);

#if defined(SOFTAP)
	if (ap_fw_loaded) {
		dhd_enable_packet_filter(0, dhd);
	}
#endif /* defined(SOFTAP) */
	dhd_set_packet_filter(dhd);
#endif /* PKT_FILTER_SUPPORT */
#ifdef DISABLE_11N
	ret = dhd_iovar(dhd, 0, "nmode", (char *)&nmode, sizeof(nmode), NULL, 0, TRUE);
	if (ret < 0)
		DHD_ERROR(("%s wl nmode 0 failed %d\n", __FUNCTION__, ret));
#endif /* DISABLE_11N */

#ifdef ENABLE_BCN_LI_BCN_WAKEUP
	ret = dhd_iovar(dhd, 0, "bcn_li_bcn", (char *)&bcn_li_bcn, sizeof(bcn_li_bcn), NULL, 0,
			TRUE);
#endif /* ENABLE_BCN_LI_BCN_WAKEUP */
#ifdef AMPDU_VO_ENABLE
	tid.tid = PRIO_8021D_VO; /* Enable TID(6) for voice */
	tid.enable = TRUE;
	ret = dhd_iovar(dhd, 0, "ampdu_tid", (char *)&tid, sizeof(tid), NULL, 0, TRUE);

	tid.tid = PRIO_8021D_NC; /* Enable TID(7) for voice */
	tid.enable = TRUE;
	ret = dhd_iovar(dhd, 0, "ampdu_tid", (char *)&tid, sizeof(tid), NULL, 0, TRUE);
#endif // endif
	/* query for 'clmver' to get clm version info from firmware */
	memset(buf, 0, sizeof(buf));
	ret = dhd_iovar(dhd, 0, "clmver", NULL, 0, buf, sizeof(buf), FALSE);
	if (ret < 0)
		DHD_ERROR(("%s clmver failed %d\n", __FUNCTION__, ret));
	else {
		char *ver_temp_buf = NULL, *ver_date_buf = NULL;
		int len;

		if ((ver_temp_buf = bcmstrstr(buf, "Data:")) == NULL) {
			DHD_ERROR(("Couldn't find \"Data:\"\n"));
		} else {
			ver_date_buf = bcmstrstr(buf, "Creation:");
			ptr = (ver_temp_buf + strlen("Data:"));
			if ((ver_temp_buf = bcmstrtok(&ptr, "\n", 0)) == NULL) {
				DHD_ERROR(("Couldn't find New line character\n"));
			} else {
				memset(clm_version, 0, CLM_VER_STR_LEN);
				len = snprintf(clm_version, CLM_VER_STR_LEN - 1, "%s", ver_temp_buf);
				if (ver_date_buf) {
					ptr = (ver_date_buf + strlen("Creation:"));
					ver_date_buf = bcmstrtok(&ptr, "\n", 0);
					if (ver_date_buf)
						snprintf(clm_version+len, CLM_VER_STR_LEN-1-len,
							" (%s)", ver_date_buf);
				}
				DHD_INFO(("CLM version = %s\n", clm_version));
			}
		}

		if (strlen(clm_version)) {
			DHD_INFO(("CLM version = %s\n", clm_version));
		} else {
			DHD_ERROR(("Couldn't find CLM version!\n"));
		}
	}
	dhd_set_version_info(dhd, fw_version);

#ifdef WRITE_WLANINFO
	sec_save_wlinfo(fw_version, EPI_VERSION_STR, dhd->info->nv_path, clm_version);
#endif /* WRITE_WLANINFO */

	/* query for 'wlc_ver' to get version info from firmware */
	memset(&wlc_ver, 0, sizeof(wl_wlc_version_t));
	ret2 = dhd_iovar(dhd, 0, "wlc_ver", NULL, 0, (char *)&wlc_ver,
		sizeof(wl_wlc_version_t), FALSE);
	if (ret2 < 0) {
		DHD_ERROR(("%s wlc_ver failed %d\n", __FUNCTION__, ret2));
		if (ret2 != BCME_UNSUPPORTED)
			ret = ret2;
	} else {
		dhd->wlc_ver_major = wlc_ver.wlc_ver_major;
		dhd->wlc_ver_minor = wlc_ver.wlc_ver_minor;
	}
#ifdef GEN_SOFTAP_INFO_FILE
	sec_save_softap_info();
#endif /* GEN_SOFTAP_INFO_FILE */

#if defined(BCMSDIO)
	dhd_txglom_enable(dhd, dhd->conf->bus_rxglom);
#endif /* defined(BCMSDIO) */

#if defined(BCMSDIO) || defined(BCMDBUS)
#ifdef PROP_TXSTATUS
	if (disable_proptx ||
#ifdef PROP_TXSTATUS_VSDB
		/* enable WLFC only if the firmware is VSDB when it is in STA mode */
		(dhd->op_mode != DHD_FLAG_HOSTAP_MODE &&
		 dhd->op_mode != DHD_FLAG_IBSS_MODE) ||
#endif /* PROP_TXSTATUS_VSDB */
		FALSE) {
		wlfc_enable = FALSE;
	}
	ret = dhd_conf_get_disable_proptx(dhd);
	if (ret == 0){
		disable_proptx = 0;
		wlfc_enable = TRUE;
	} else if (ret >= 1) {
		disable_proptx = 1;
		wlfc_enable = FALSE;
		/* terence 20161229: we should set ampdu_hostreorder=0 when disable_proptx=1 */
		hostreorder = 0;
	}

#if defined(PROP_TXSTATUS)
#ifdef USE_WFA_CERT_CONF
	if (sec_get_param_wfa_cert(dhd, SET_PARAM_PROPTX, &proptx) == BCME_OK) {
		DHD_ERROR(("%s , read proptx param=%d\n", __FUNCTION__, proptx));
		wlfc_enable = proptx;
	}
#endif /* USE_WFA_CERT_CONF */
#endif /* PROP_TXSTATUS */

#ifndef DISABLE_11N
	ret = dhd_wl_ioctl_cmd(dhd, WLC_DOWN, (char *)&wl_down, sizeof(wl_down), TRUE, 0);
	ret2 = dhd_iovar(dhd, 0, "ampdu_hostreorder", (char *)&hostreorder, sizeof(hostreorder),
			NULL, 0, TRUE);
	if (ret2 < 0) {
		DHD_ERROR(("%s wl ampdu_hostreorder failed %d\n", __FUNCTION__, ret2));
		if (ret2 != BCME_UNSUPPORTED)
			ret = ret2;

		if (ret == BCME_NOTDOWN) {
			uint wl_down = 1;
			ret2 = dhd_wl_ioctl_cmd(dhd, WLC_DOWN, (char *)&wl_down,
				sizeof(wl_down), TRUE, 0);
			DHD_ERROR(("%s ampdu_hostreorder fail WL_DOWN : %d, hostreorder :%d\n",
				__FUNCTION__, ret2, hostreorder));

			ret2 = dhd_iovar(dhd, 0, "ampdu_hostreorder", (char *)&hostreorder,
					sizeof(hostreorder), NULL, 0, TRUE);
			DHD_ERROR(("%s wl ampdu_hostreorder. ret --> %d\n", __FUNCTION__, ret2));
			if (ret2 != BCME_UNSUPPORTED)
					ret = ret2;
		}
		if (ret2 != BCME_OK)
			hostreorder = 0;
	}
#endif /* DISABLE_11N */

	if (wlfc_enable) {
		dhd_wlfc_init(dhd);
		/* terence 20161229: enable ampdu_hostreorder if tlv enabled */
		dhd_conf_set_intiovar(dhd, 0, WLC_SET_VAR, "ampdu_hostreorder", 1, 0, TRUE);
	}
#ifndef DISABLE_11N
	else if (hostreorder)
		dhd_wlfc_hostreorder_init(dhd);
#endif /* DISABLE_11N */
#else
	/* terence 20161229: disable ampdu_hostreorder if PROP_TXSTATUS not defined */
	printf("%s: not define PROP_TXSTATUS\n", __FUNCTION__);
	dhd_conf_set_intiovar(dhd, 0, WLC_SET_VAR, "ampdu_hostreorder", 0, 0, TRUE);
#endif /* PROP_TXSTATUS */
#endif /* BCMSDIO || BCMDBUS */
#ifndef PCIE_FULL_DONGLE
	/* For FD we need all the packets at DHD to handle intra-BSS forwarding */
	if (FW_SUPPORTED(dhd, ap)) {
		wl_ap_isolate = AP_ISOLATE_SENDUP_ALL;
		ret = dhd_iovar(dhd, 0, "ap_isolate", (char *)&wl_ap_isolate, sizeof(wl_ap_isolate),
				NULL, 0, TRUE);
		if (ret < 0)
			DHD_ERROR(("%s failed %d\n", __FUNCTION__, ret));
	}
#endif /* PCIE_FULL_DONGLE */
#ifdef PNO_SUPPORT
	if (!dhd->pno_state) {
		dhd_pno_init(dhd);
	}
#endif // endif
#ifdef RTT_SUPPORT
	if (!dhd->rtt_state) {
		ret = dhd_rtt_init(dhd);
		if (ret < 0) {
			DHD_ERROR(("%s failed to initialize RTT\n", __FUNCTION__));
		}
	}
#endif // endif
#ifdef FILTER_IE
	/* Failure to configure filter IE is not a fatal error, ignore it. */
	if (!(dhd->op_mode & (DHD_FLAG_HOSTAP_MODE | DHD_FLAG_MFG_MODE)))
		dhd_read_from_file(dhd);
#endif /* FILTER_IE */
#ifdef WL11U
	dhd_interworking_enable(dhd);
#endif /* WL11U */

#ifdef NDO_CONFIG_SUPPORT
	dhd->ndo_enable = FALSE;
	dhd->ndo_host_ip_overflow = FALSE;
	dhd->ndo_max_host_ip = NDO_MAX_HOST_IP_ENTRIES;
#endif /* NDO_CONFIG_SUPPORT */

	/* ND offload version supported */
	dhd->ndo_version = dhd_ndo_get_version(dhd);
	if (dhd->ndo_version > 0) {
		DHD_INFO(("%s: ndo version %d\n", __FUNCTION__, dhd->ndo_version));

#ifdef NDO_CONFIG_SUPPORT
		/* enable Unsolicited NA filter */
		ret = dhd_ndo_unsolicited_na_filter_enable(dhd, 1);
		if (ret < 0) {
			DHD_ERROR(("%s failed to enable Unsolicited NA filter\n", __FUNCTION__));
		}
#endif /* NDO_CONFIG_SUPPORT */
	}

	/* check dongle supports wbtext (product policy) or not */
	dhd->wbtext_support = FALSE;
	if (dhd_wl_ioctl_get_intiovar(dhd, "wnm_bsstrans_resp", &wnm_bsstrans_resp,
			WLC_GET_VAR, FALSE, 0) != BCME_OK) {
		DHD_ERROR(("failed to get wnm_bsstrans_resp\n"));
	}
	dhd->wbtext_policy = wnm_bsstrans_resp;
	if (dhd->wbtext_policy == WL_BSSTRANS_POLICY_PRODUCT_WBTEXT) {
		dhd->wbtext_support = TRUE;
	}
	/* driver can turn off wbtext feature through makefile */
	if (dhd->wbtext_support) {
		if (dhd_wl_ioctl_set_intiovar(dhd, "wnm_bsstrans_resp",
				WL_BSSTRANS_POLICY_ROAM_ALWAYS,
				WLC_SET_VAR, FALSE, 0) != BCME_OK) {
			DHD_ERROR(("failed to disable WBTEXT\n"));
		}
	}

#ifdef DHD_NON_DMA_M2M_CORRUPTION
	/* check pcie non dma loopback */
	if (dhd->op_mode == DHD_FLAG_MFG_MODE &&
		(dhd_bus_dmaxfer_lpbk(dhd, M2M_NON_DMA_LPBK) < 0)) {
			goto done;
	}
#endif /* DHD_NON_DMA_M2M_CORRUPTION */

	/* WNM capabilities */
	wnm_cap = 0
#ifdef WL11U
		| WL_WNM_BSSTRANS | WL_WNM_NOTIF
#endif // endif
		;
#if defined(WL_MBO) && defined(WL_OCE)
	if (FW_SUPPORTED(dhd, estm)) {
		wnm_cap |= WL_WNM_ESTM;
	}
#endif /* WL_MBO && WL_OCE */
	if (dhd_iovar(dhd, 0, "wnm", (char *)&wnm_cap, sizeof(wnm_cap), NULL, 0, TRUE) < 0) {
		DHD_ERROR(("failed to set WNM capabilities\n"));
	}

	if (FW_SUPPORTED(dhd, ecounters) && enable_ecounter) {
		dhd_ecounter_configure(dhd, TRUE);
	}

	/* store the preserve log set numbers */
	if (dhd_get_preserve_log_numbers(dhd, &dhd->logset_prsrv_mask)
			!= BCME_OK) {
		DHD_ERROR(("%s: Failed to get preserve log # !\n", __FUNCTION__));
	}

#ifdef WL_MONITOR
	if (FW_SUPPORTED(dhd, monitor)) {
		dhd->monitor_enable = TRUE;
		DHD_ERROR(("%s: Monitor mode is enabled in FW cap\n", __FUNCTION__));
	} else {
		dhd->monitor_enable = FALSE;
		DHD_ERROR(("%s: Monitor mode is not enabled in FW cap\n", __FUNCTION__));
	}
#endif /* WL_MONITOR */

#ifdef CONFIG_SILENT_ROAM
	dhd->sroam_turn_on = TRUE;
	dhd->sroamed = FALSE;
#endif /* CONFIG_SILENT_ROAM */

	dhd_conf_postinit_ioctls(dhd);
done:

	if (eventmask_msg) {
		MFREE(dhd->osh, eventmask_msg, msglen);
		eventmask_msg = NULL;
	}
	if (iov_buf) {
		MFREE(dhd->osh, iov_buf, WLC_IOCTL_SMLEN);
		iov_buf = NULL;
	}
#if defined(DHD_8021X_DUMP) && defined(SHOW_LOGTRACE)
	if (el_tag) {
		MFREE(dhd->osh, el_tag, sizeof(wl_el_tag_params_t));
		el_tag = NULL;
	}
#endif /* DHD_8021X_DUMP */
	return ret;
}

int
dhd_iovar(dhd_pub_t *pub, int ifidx, char *name, char *param_buf, uint param_len, char *res_buf,
		uint res_len, int set)
{
	char *buf = NULL;
	int input_len;
	wl_ioctl_t ioc;
	int ret;

	if (res_len > WLC_IOCTL_MAXLEN || param_len > WLC_IOCTL_MAXLEN)
		return BCME_BADARG;

	input_len = strlen(name) + 1 + param_len;
	if (input_len > WLC_IOCTL_MAXLEN)
		return BCME_BADARG;

	buf = NULL;
	if (set) {
		if (res_buf || res_len != 0) {
			DHD_ERROR(("%s: SET wrong arguemnet\n", __FUNCTION__));
			ret = BCME_BADARG;
			goto exit;
		}
		buf = MALLOCZ(pub->osh, input_len);
		if (!buf) {
			DHD_ERROR(("%s: mem alloc failed\n", __FUNCTION__));
			ret = BCME_NOMEM;
			goto exit;
		}
		ret = bcm_mkiovar(name, param_buf, param_len, buf, input_len);
		if (!ret) {
			ret = BCME_NOMEM;
			goto exit;
		}

		ioc.cmd = WLC_SET_VAR;
		ioc.buf = buf;
		ioc.len = input_len;
		ioc.set = set;

		ret = dhd_wl_ioctl(pub, ifidx, &ioc, ioc.buf, ioc.len);
	} else {
		if (!res_buf || !res_len) {
			DHD_ERROR(("%s: GET failed. resp_buf NULL or length 0.\n", __FUNCTION__));
			ret = BCME_BADARG;
			goto exit;
		}

		if (res_len < input_len) {
			DHD_INFO(("%s: res_len(%d) < input_len(%d)\n", __FUNCTION__,
					res_len, input_len));
			buf = MALLOCZ(pub->osh, input_len);
			if (!buf) {
				DHD_ERROR(("%s: mem alloc failed\n", __FUNCTION__));
				ret = BCME_NOMEM;
				goto exit;
			}
			ret = bcm_mkiovar(name, param_buf, param_len, buf, input_len);
			if (!ret) {
				ret = BCME_NOMEM;
				goto exit;
			}

			ioc.cmd = WLC_GET_VAR;
			ioc.buf = buf;
			ioc.len = input_len;
			ioc.set = set;

			ret = dhd_wl_ioctl(pub, ifidx, &ioc, ioc.buf, ioc.len);

			if (ret == BCME_OK) {
				memcpy(res_buf, buf, res_len);
			}
		} else {
			memset(res_buf, 0, res_len);
			ret = bcm_mkiovar(name, param_buf, param_len, res_buf, res_len);
			if (!ret) {
				ret = BCME_NOMEM;
				goto exit;
			}

			ioc.cmd = WLC_GET_VAR;
			ioc.buf = res_buf;
			ioc.len = res_len;
			ioc.set = set;

			ret = dhd_wl_ioctl(pub, ifidx, &ioc, ioc.buf, ioc.len);
		}
	}
exit:
	if (buf) {
		MFREE(pub->osh, buf, input_len);
		buf = NULL;
	}
	return ret;
}

int
dhd_getiovar(dhd_pub_t *pub, int ifidx, char *name, char *cmd_buf,
	uint cmd_len, char **resptr, uint resp_len)
{
	int len = resp_len;
	int ret;
	char *buf = *resptr;
	wl_ioctl_t ioc;
	if (resp_len > WLC_IOCTL_MAXLEN)
		return BCME_BADARG;

	memset(buf, 0, resp_len);

	ret = bcm_mkiovar(name, cmd_buf, cmd_len, buf, len);
	if (ret == 0) {
		return BCME_BUFTOOSHORT;
	}

	memset(&ioc, 0, sizeof(ioc));

	ioc.cmd = WLC_GET_VAR;
	ioc.buf = buf;
	ioc.len = len;
	ioc.set = 0;

	ret = dhd_wl_ioctl(pub, ifidx, &ioc, ioc.buf, ioc.len);

	return ret;
}

int dhd_change_mtu(dhd_pub_t *dhdp, int new_mtu, int ifidx)
{
	struct dhd_info *dhd = dhdp->info;
	struct net_device *dev = NULL;

	ASSERT(dhd && dhd->iflist[ifidx]);
	dev = dhd->iflist[ifidx]->net;
	ASSERT(dev);

#ifndef DHD_TPUT_PATCH
	if (netif_running(dev)) {
		DHD_ERROR(("%s: Must be down to change its MTU\n", dev->name));
		return BCME_NOTDOWN;
	}
#endif

#define DHD_MIN_MTU 1500
#define DHD_MAX_MTU 1752

	if ((new_mtu < DHD_MIN_MTU) || (new_mtu > DHD_MAX_MTU)) {
		DHD_ERROR(("%s: MTU size %d is invalid.\n", __FUNCTION__, new_mtu));
		return BCME_BADARG;
	}

	dev->mtu = new_mtu;
	return 0;
}

#ifdef CONFIG_AP6XXX_WIFI6_HDF
int dhd_netdev_changemtu_wrapper(struct net_device *netdev, int mtu)
{
	int bcmerror = BCME_OK;
	dhd_info_t *dhd = DHD_DEV_INFO(netdev);
	mtu &= 0xffff;
	bcmerror = dhd_change_mtu(&dhd->pub, mtu, 0);	
	return bcmerror;
}
#endif


#ifdef ARP_OFFLOAD_SUPPORT
/* add or remove AOE host ip(s) (up to 8 IPs on the interface)  */
void
aoe_update_host_ipv4_table(dhd_pub_t *dhd_pub, u32 ipa, bool add, int idx)
{
	u32 ipv4_buf[MAX_IPV4_ENTRIES]; /* temp save for AOE host_ip table */
	int i;
	int ret;

	bzero(ipv4_buf, sizeof(ipv4_buf));

	/* display what we've got */
	ret = dhd_arp_get_arp_hostip_table(dhd_pub, ipv4_buf, sizeof(ipv4_buf), idx);
	DHD_ARPOE(("%s: hostip table read from Dongle:\n", __FUNCTION__));
#ifdef AOE_DBG
	dhd_print_buf(ipv4_buf, 32, 4); /* max 8 IPs 4b each */
#endif // endif
	/* now we saved hoste_ip table, clr it in the dongle AOE */
	dhd_aoe_hostip_clr(dhd_pub, idx);

	if (ret) {
		DHD_ERROR(("%s failed\n", __FUNCTION__));
		return;
	}

	for (i = 0; i < MAX_IPV4_ENTRIES; i++) {
		if (add && (ipv4_buf[i] == 0)) {
				ipv4_buf[i] = ipa;
				add = FALSE; /* added ipa to local table  */
				DHD_ARPOE(("%s: Saved new IP in temp arp_hostip[%d]\n",
				__FUNCTION__, i));
		} else if (ipv4_buf[i] == ipa) {
			ipv4_buf[i]	= 0;
			DHD_ARPOE(("%s: removed IP:%x from temp table %d\n",
				__FUNCTION__, ipa, i));
		}

		if (ipv4_buf[i] != 0) {
			/* add back host_ip entries from our local cache */
			dhd_arp_offload_add_ip(dhd_pub, ipv4_buf[i], idx);
			DHD_ARPOE(("%s: added IP:%x to dongle arp_hostip[%d]\n\n",
				__FUNCTION__, ipv4_buf[i], i));
		}
	}
#ifdef AOE_DBG
	/* see the resulting hostip table */
	dhd_arp_get_arp_hostip_table(dhd_pub, ipv4_buf, sizeof(ipv4_buf), idx);
	DHD_ARPOE(("%s: read back arp_hostip table:\n", __FUNCTION__));
	dhd_print_buf(ipv4_buf, 32, 4); /* max 8 IPs 4b each */
#endif // endif
}

/*
 * Notification mechanism from kernel to our driver. This function is called by the Linux kernel
 * whenever there is an event related to an IP address.
 * ptr : kernel provided pointer to IP address that has changed
 */
static int dhd_inetaddr_notifier_call(struct notifier_block *this,
	unsigned long event,
	void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;

	dhd_info_t *dhd;
	dhd_pub_t *dhd_pub;
	int idx;

	if (!dhd_arp_enable)
		return NOTIFY_DONE;
	if (!ifa || !(ifa->ifa_dev->dev))
		return NOTIFY_DONE;

	/* Filter notifications meant for non Broadcom devices */
	if ((ifa->ifa_dev->dev->netdev_ops != &dhd_ops_pri) &&
	    (ifa->ifa_dev->dev->netdev_ops != &dhd_ops_virt) 
#ifdef CONFIG_AP6XXX_WIFI6_HDF
	    && (ifa->ifa_dev->dev->netdev_ops != hdf_netdev_ops)
#endif
		) {
#if defined(WL_ENABLE_P2P_IF)
		if (!wl_cfgp2p_is_ifops(ifa->ifa_dev->dev->netdev_ops))
#endif /* WL_ENABLE_P2P_IF */
			return NOTIFY_DONE;
	}

	dhd = DHD_DEV_INFO(ifa->ifa_dev->dev);
	if (!dhd)
		return NOTIFY_DONE;

	dhd_pub = &dhd->pub;

	if (dhd_pub->arp_version == 1) {
		idx = 0;
	} else {
		for (idx = 0; idx < DHD_MAX_IFS; idx++) {
			if (dhd->iflist[idx] && dhd->iflist[idx]->net == ifa->ifa_dev->dev)
			break;
		}
		if (idx < DHD_MAX_IFS)
			DHD_TRACE(("ifidx : %p %s %d\n", dhd->iflist[idx]->net,
				dhd->iflist[idx]->name, dhd->iflist[idx]->idx));
		else {
			DHD_ERROR(("Cannot find ifidx for(%s) set to 0\n", ifa->ifa_label));
			idx = 0;
		}
	}

	switch (event) {
		case NETDEV_UP:
			DHD_ARPOE(("%s: [%s] Up IP: 0x%x\n",
				__FUNCTION__, ifa->ifa_label, ifa->ifa_address));

			/*
			 * Skip if Bus is not in a state to transport the IOVAR
			 * (or) the Dongle is not ready.
			 */
			if (DHD_BUS_CHECK_DOWN_OR_DOWN_IN_PROGRESS(&dhd->pub) ||
				dhd->pub.busstate ==  DHD_BUS_LOAD) {
				DHD_ERROR(("%s: bus not ready, exit NETDEV_UP : %d\n",
					__FUNCTION__, dhd->pub.busstate));
				if (dhd->pend_ipaddr) {
					DHD_ERROR(("%s: overwrite pending ipaddr: 0x%x\n",
						__FUNCTION__, dhd->pend_ipaddr));
				}
				dhd->pend_ipaddr = ifa->ifa_address;
				break;
			}

#ifdef AOE_IP_ALIAS_SUPPORT
			DHD_ARPOE(("%s:add aliased IP to AOE hostip cache\n",
				__FUNCTION__));
			aoe_update_host_ipv4_table(dhd_pub, ifa->ifa_address, TRUE, idx);
#endif /* AOE_IP_ALIAS_SUPPORT */
			dhd_conf_set_garp(dhd_pub, idx, ifa->ifa_address, TRUE);
			break;

		case NETDEV_DOWN:
			DHD_ARPOE(("%s: [%s] Down IP: 0x%x\n",
				__FUNCTION__, ifa->ifa_label, ifa->ifa_address));
			dhd->pend_ipaddr = 0;
#ifdef AOE_IP_ALIAS_SUPPORT
			DHD_ARPOE(("%s:interface is down, AOE clr all for this if\n",
				__FUNCTION__));
			if ((dhd_pub->op_mode & DHD_FLAG_HOSTAP_MODE) ||
				(ifa->ifa_dev->dev != dhd_linux_get_primary_netdev(dhd_pub))) {
				aoe_update_host_ipv4_table(dhd_pub, ifa->ifa_address, FALSE, idx);
			} else
#endif /* AOE_IP_ALIAS_SUPPORT */
			{
				dhd_aoe_hostip_clr(&dhd->pub, idx);
				dhd_aoe_arp_clr(&dhd->pub, idx);
			}
			dhd_conf_set_garp(dhd_pub, idx, ifa->ifa_address, FALSE);
			break;

		default:
			DHD_ARPOE(("%s: do noting for [%s] Event: %lu\n",
				__func__, ifa->ifa_label, event));
			break;
	}
	return NOTIFY_DONE;
}
#endif /* ARP_OFFLOAD_SUPPORT */

#if defined(CONFIG_IPV6) && defined(IPV6_NDO_SUPPORT)
/* Neighbor Discovery Offload: defered handler */
static void
dhd_inet6_work_handler(void *dhd_info, void *event_data, u8 event)
{
	struct ipv6_work_info_t *ndo_work = (struct ipv6_work_info_t *)event_data;
	dhd_info_t *dhd = (dhd_info_t *)dhd_info;
	dhd_pub_t *dhdp;
	int ret;

	if (!dhd) {
		DHD_ERROR(("%s: invalid dhd_info\n", __FUNCTION__));
		goto done;
	}
	dhdp = &dhd->pub;

	if (event != DHD_WQ_WORK_IPV6_NDO) {
		DHD_ERROR(("%s: unexpected event\n", __FUNCTION__));
		goto done;
	}

	if (!ndo_work) {
		DHD_ERROR(("%s: ipv6 work info is not initialized\n", __FUNCTION__));
		return;
	}

	switch (ndo_work->event) {
		case NETDEV_UP:
#ifndef NDO_CONFIG_SUPPORT
			DHD_TRACE(("%s: Enable NDO \n ", __FUNCTION__));
			ret = dhd_ndo_enable(dhdp, TRUE);
			if (ret < 0) {
				DHD_ERROR(("%s: Enabling NDO Failed %d\n", __FUNCTION__, ret));
			}
#endif /* !NDO_CONFIG_SUPPORT */
			DHD_TRACE(("%s: Add a host ip for NDO\n", __FUNCTION__));
			if (dhdp->ndo_version > 0) {
				/* inet6 addr notifier called only for unicast address */
				ret = dhd_ndo_add_ip_with_type(dhdp, &ndo_work->ipv6_addr[0],
					WL_ND_IPV6_ADDR_TYPE_UNICAST, ndo_work->if_idx);
			} else {
				ret = dhd_ndo_add_ip(dhdp, &ndo_work->ipv6_addr[0],
					ndo_work->if_idx);
			}
			if (ret < 0) {
				DHD_ERROR(("%s: Adding a host ip for NDO failed %d\n",
					__FUNCTION__, ret));
			}
			break;
		case NETDEV_DOWN:
			if (dhdp->ndo_version > 0) {
				DHD_TRACE(("%s: Remove a host ip for NDO\n", __FUNCTION__));
				ret = dhd_ndo_remove_ip_by_addr(dhdp,
					&ndo_work->ipv6_addr[0], ndo_work->if_idx);
			} else {
				DHD_TRACE(("%s: Clear host ip table for NDO \n", __FUNCTION__));
				ret = dhd_ndo_remove_ip(dhdp, ndo_work->if_idx);
			}
			if (ret < 0) {
				DHD_ERROR(("%s: Removing host ip for NDO failed %d\n",
					__FUNCTION__, ret));
				goto done;
			}
#ifdef NDO_CONFIG_SUPPORT
			if (dhdp->ndo_host_ip_overflow) {
				ret = dhd_dev_ndo_update_inet6addr(
					dhd_idx2net(dhdp, ndo_work->if_idx));
				if ((ret < 0) && (ret != BCME_NORESOURCE)) {
					DHD_ERROR(("%s: Updating host ip for NDO failed %d\n",
						__FUNCTION__, ret));
					goto done;
				}
			}
#else /* !NDO_CONFIG_SUPPORT */
			DHD_TRACE(("%s: Disable NDO\n ", __FUNCTION__));
			ret = dhd_ndo_enable(dhdp, FALSE);
			if (ret < 0) {
				DHD_ERROR(("%s: disabling NDO Failed %d\n", __FUNCTION__, ret));
				goto done;
			}
#endif /* NDO_CONFIG_SUPPORT */
			break;

		default:
			DHD_ERROR(("%s: unknown notifier event \n", __FUNCTION__));
			break;
	}
done:

	/* free ndo_work. alloced while scheduling the work */
	if (ndo_work) {
		kfree(ndo_work);
	}

	return;
} /* dhd_init_logstrs_array */

/*
 * Neighbor Discovery Offload: Called when an interface
 * is assigned with ipv6 address.
 * Handles only primary interface
 */
int dhd_inet6addr_notifier_call(struct notifier_block *this, unsigned long event, void *ptr)
{
	dhd_info_t *dhd;
	dhd_pub_t *dhdp;
	struct inet6_ifaddr *inet6_ifa = ptr;
	struct ipv6_work_info_t *ndo_info;
	int idx;

	/* Filter notifications meant for non Broadcom devices */
	if (inet6_ifa->idev->dev->netdev_ops != &dhd_ops_pri 
#ifdef CONFIG_AP6XXX_WIFI6_HDF
        && inet6_ifa->idev->dev->netdev_ops != hdf_netdev_ops
#endif
		) {
			return NOTIFY_DONE;
	}

	dhd = DHD_DEV_INFO(inet6_ifa->idev->dev);
	if (!dhd) {
		return NOTIFY_DONE;
	}
	dhdp = &dhd->pub;

	/* Supports only primary interface */
	idx = dhd_net2idx(dhd, inet6_ifa->idev->dev);
	if (idx != 0) {
		return NOTIFY_DONE;
	}

	/* FW capability */
	if (!FW_SUPPORTED(dhdp, ndoe)) {
		return NOTIFY_DONE;
	}

	ndo_info = (struct ipv6_work_info_t *)kzalloc(sizeof(struct ipv6_work_info_t), GFP_ATOMIC);
	if (!ndo_info) {
		DHD_ERROR(("%s: ipv6 work alloc failed\n", __FUNCTION__));
		return NOTIFY_DONE;
	}

	/* fill up ndo_info */
	ndo_info->event = event;
	ndo_info->if_idx = idx;
	memcpy(ndo_info->ipv6_addr, &inet6_ifa->addr, IPV6_ADDR_LEN);

	/* defer the work to thread as it may block kernel */
	dhd_deferred_schedule_work(dhd->dhd_deferred_wq, (void *)ndo_info, DHD_WQ_WORK_IPV6_NDO,
		dhd_inet6_work_handler, DHD_WQ_WORK_PRIORITY_LOW);
	return NOTIFY_DONE;
}
#endif /* CONFIG_IPV6 && IPV6_NDO_SUPPORT */

/* Network attach to be invoked from the bus probe handlers */
int
dhd_attach_net(dhd_pub_t *dhdp, bool need_rtnl_lock)
{
	struct net_device *primary_ndev;
#ifdef GET_CUSTOM_MAC_ENABLE
	char hw_ether[62];
#endif /* GET_CUSTOM_MAC_ENABLE */
#if defined(GET_CUSTOM_MAC_ENABLE) || defined(GET_OTP_MAC_ENABLE)
	int ret = BCME_ERROR;
#endif /* GET_CUSTOM_MAC_ENABLE || GET_OTP_MAC_ENABLE */

	BCM_REFERENCE(primary_ndev);

#ifdef GET_CUSTOM_MAC_ENABLE
	ret = wifi_platform_get_mac_addr(dhdp->adapter, hw_ether, 0);
	if (!ret)
		bcopy(hw_ether, dhdp->mac.octet, ETHER_ADDR_LEN);
#endif /* GET_CUSTOM_MAC_ENABLE */

#ifdef GET_OTP_MAC_ENABLE
	if (ret && memcmp(&ether_null, &dhdp->conf->otp_mac, ETHER_ADDR_LEN))
		bcopy(&dhdp->conf->otp_mac, &dhdp->mac, ETHER_ADDR_LEN);
#endif /* GET_OTP_MAC_ENABLE */

	/* Register primary net device */
	if (dhd_register_if(dhdp, 0, need_rtnl_lock) != 0) {
		return BCME_ERROR;
	}

#if defined(WL_CFG80211)
	primary_ndev =  dhd_linux_get_primary_netdev(dhdp);
	if (wl_cfg80211_net_attach(primary_ndev) < 0) {
		/* fail the init */
		dhd_remove_if(dhdp, 0, TRUE);
		return BCME_ERROR;
	}
#endif /* WL_CFG80211 */
	return BCME_OK;
}

int
dhd_register_if(dhd_pub_t *dhdp, int ifidx, bool need_rtnl_lock)
{
	dhd_info_t *dhd = (dhd_info_t *)dhdp->info;
	dhd_if_t *ifp;
	struct net_device *net = NULL;
	int err = 0;
	uint8 temp_addr[ETHER_ADDR_LEN] = { 0x00, 0x90, 0x4c, 0x11, 0x22, 0x33 };
#ifdef CONFIG_AP6XXX_WIFI6_HDF
	struct NetDevice *hnetdev = NULL;
#endif

	DHD_TRACE(("%s: ifidx %d\n", __FUNCTION__, ifidx));

	if (dhd == NULL || dhd->iflist[ifidx] == NULL) {
		DHD_ERROR(("%s: Invalid Interface\n", __FUNCTION__));
		return BCME_ERROR;
	}

	ASSERT(dhd && dhd->iflist[ifidx]);
	ifp = dhd->iflist[ifidx];
	net = ifp->net;
	ASSERT(net && (ifp->idx == ifidx));

	ASSERT(!net->netdev_ops);

#ifdef CONFIG_AP6XXX_WIFI6_HDF
	DHD_ERROR(("%s: bdh6 register netdev=%s hdfidx=%d, ifidx=%d, %p, %p\n", __FUNCTION__, net->name, g_hdf_ifidx, 
		ifidx, net->netdev_ops, &dhd_ops_virt));
#else
	net->netdev_ops = &dhd_ops_virt;
	DHD_ERROR(("%s: bdh6 register netdev=%s ifidx=%d\n", __FUNCTION__, net->name, ifidx));
#endif

	/* Ok, link into the network layer... */
	if (ifidx == 0) {
		/*
		 * device functions for the primary interface only
		 */
#ifdef CONFIG_AP6XXX_WIFI6_HDF
		DHD_ERROR(("%s: for primary inf don't set ops %d\n", __FUNCTION__, g_hdf_ifidx));
#else
		net->netdev_ops = &dhd_ops_pri;
#endif
		if (!ETHER_ISNULLADDR(dhd->pub.mac.octet))
			memcpy(temp_addr, dhd->pub.mac.octet, ETHER_ADDR_LEN);
	} else {
		/*
		 * We have to use the primary MAC for virtual interfaces
		 */
		memcpy(temp_addr, ifp->mac_addr, ETHER_ADDR_LEN);
		/*
		 * Android sets the locally administered bit to indicate that this is a
		 * portable hotspot.  This will not work in simultaneous AP/STA mode,
		 * nor with P2P.  Need to set the Donlge's MAC address, and then use that.
		 */
		if (!memcmp(temp_addr, dhd->iflist[0]->mac_addr,
			ETHER_ADDR_LEN)) {
			DHD_ERROR(("%s interface [%s]: set locally administered bit in MAC\n",
			__func__, net->name));
			temp_addr[0] |= 0x02;
		}
	}

	net->hard_header_len = ETH_HLEN + dhd->pub.hdrlen;
	net->ethtool_ops = &dhd_ethtool_ops;

#if defined(WL_WIRELESS_EXT)
#if WIRELESS_EXT < 19
	net->get_wireless_stats = dhd_get_wireless_stats;
#endif /* WIRELESS_EXT < 19 */
#if WIRELESS_EXT > 12
	net->wireless_handlers = &wl_iw_handler_def;
#endif /* WIRELESS_EXT > 12 */
#endif /* defined(WL_WIRELESS_EXT) */

	dhd->pub.rxsz = DBUS_RX_BUFFER_SIZE_DHD(net);

#ifdef WLMESH
	if (ifidx >= 2 && dhdp->conf->fw_type == FW_TYPE_MESH) {
		temp_addr[4] ^= 0x80;
		temp_addr[4] += ifidx;
		temp_addr[5] += ifidx;
	}
#endif
	memcpy(net->dev_addr, temp_addr, ETHER_ADDR_LEN);

	if (ifidx == 0)
		printf("%s\n", dhd_version);
	else {
#ifdef WL_EXT_IAPSTA
		wl_ext_iapsta_update_net_device(net, ifidx);
#endif /* WL_EXT_IAPSTA */
		if (dhd->pub.up == 1) {
			if (_dhd_set_mac_address(dhd, ifidx, net->dev_addr, FALSE) == 0)
				DHD_INFO(("%s: MACID is overwritten\n", __FUNCTION__));
			else
				DHD_ERROR(("%s: _dhd_set_mac_address() failed\n", __FUNCTION__));
		}
	}

#ifdef CONFIG_AP6XXX_WIFI6_HDF
	//if (0 == g_hdf_ifidx) {
	DHD_ERROR(("%s: for hdf inf %d don't register netdev\n", __FUNCTION__, g_hdf_ifidx));

	// update mac address
	hnetdev = GetHdfNetDeviceByLinuxInf(net);
	memcpy(hnetdev->macAddr, net->dev_addr, ETHER_ADDR_LEN);
	// Call linux register_netdev()
	err = NetDeviceAdd(hnetdev);
	DHD_ERROR(("%s:NetDeviceAdd %s ret=%d\n", __FUNCTION__, net->name, err));
	//}
#else
	if (need_rtnl_lock)
		err = register_netdev(net);
	else {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)) && defined(WL_CFG80211)
		err = cfg80211_register_netdevice(net);
#else
		err = register_netdevice(net);
#endif
	}
#endif
	if (err != 0) {
		DHD_ERROR(("couldn't register the net device [%s], err %d\n", net->name, err));
		goto fail;
	}
#ifdef WL_EVENT
	wl_ext_event_attach_netdev(net, ifidx, ifp->bssidx);
#endif /* WL_EVENT */
#ifdef WL_ESCAN
	wl_escan_event_attach(net, ifidx);
#endif /* WL_ESCAN */
#ifdef WL_EXT_IAPSTA
	wl_ext_iapsta_attach_netdev(net, ifidx, ifp->bssidx);
	wl_ext_iapsta_attach_name(net, ifidx);
#endif /* WL_EXT_IAPSTA */

	printf("Register interface [%s]  MAC: "MACDBG"\n\n", net->name,
		MAC2STRDBG(net->dev_addr));

#if defined(SOFTAP) && defined(WL_WIRELESS_EXT) && !defined(WL_CFG80211)
//		wl_iw_iscan_set_scan_broadcast_prep(net, 1);
#endif // endif

#if (defined(BCMPCIE) || defined(BCMLXSDMMC) || defined(BCMDBUS))
	if (ifidx == 0) {
#if defined(BCMLXSDMMC) && !defined(DHD_PRELOAD)
		up(&dhd_registration_sem);
#endif /* BCMLXSDMMC */
		if (!dhd_download_fw_on_driverload) {
#ifdef WL_CFG80211
			wl_terminate_event_handler(net);
#endif /* WL_CFG80211 */
#if defined(DHD_LB_RXP)
			__skb_queue_purge(&dhd->rx_pend_queue);
#endif /* DHD_LB_RXP */

#if defined(DHD_LB_TXP)
			skb_queue_purge(&dhd->tx_pend_queue);
#endif /* DHD_LB_TXP */

#ifdef SHOW_LOGTRACE
			/* Release the skbs from queue for WLC_E_TRACE event */
			dhd_event_logtrace_flush_queue(dhdp);
#endif /* SHOW_LOGTRACE */

#if defined(BCMPCIE) && defined(DHDTCPACK_SUPPRESS)
			dhd_tcpack_suppress_set(dhdp, TCPACK_SUP_OFF);
#endif /* BCMPCIE && DHDTCPACK_SUPPRESS */
			dhd_net_bus_devreset(net, TRUE);
#ifdef BCMLXSDMMC
			dhd_net_bus_suspend(net);
#endif /* BCMLXSDMMC */
			wifi_platform_set_power(dhdp->info->adapter, FALSE, WIFI_TURNOFF_DELAY);
#if defined(BT_OVER_SDIO)
			dhd->bus_user_count--;
#endif /* BT_OVER_SDIO */
		}
	}
#endif /* OEM_ANDROID && (BCMPCIE || BCMLXSDMMC) */
	return 0;

fail:
#ifndef CONFIG_AP6XXX_WIFI6_HDF
	net->netdev_ops = NULL;
#endif
	return err;
}

void
dhd_bus_detach(dhd_pub_t *dhdp)
{
	dhd_info_t *dhd;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (dhdp) {
		dhd = (dhd_info_t *)dhdp->info;
		if (dhd) {

			/*
			 * In case of Android cfg80211 driver, the bus is down in dhd_stop,
			 *  calling stop again will cuase SD read/write errors.
			 */
			if (dhd->pub.busstate != DHD_BUS_DOWN && dhd_download_fw_on_driverload) {
				/* Stop the protocol module */
				dhd_prot_stop(&dhd->pub);

				/* Stop the bus module */
#ifdef BCMDBUS
				/* Force Dongle terminated */
				if (dhd_wl_ioctl_cmd(dhdp, WLC_TERMINATED, NULL, 0, TRUE, 0) < 0)
					DHD_ERROR(("%s Setting WLC_TERMINATED failed\n",
						__FUNCTION__));
				dbus_stop(dhd->pub.bus);
				dhd->pub.busstate = DHD_BUS_DOWN;
#else
				dhd_bus_stop(dhd->pub.bus, TRUE);
#endif /* BCMDBUS */
			}

#if defined(OOB_INTR_ONLY) || defined(BCMSPI_ANDROID) || defined(BCMPCIE_OOB_HOST_WAKE)
			dhd_bus_oob_intr_unregister(dhdp);
#endif /* OOB_INTR_ONLY || BCMSPI_ANDROID || BCMPCIE_OOB_HOST_WAKE */
		}
	}
}

void dhd_detach(dhd_pub_t *dhdp)
{
	dhd_info_t *dhd;
	unsigned long flags;
	int timer_valid = FALSE;
	struct net_device *dev;
#ifdef WL_CFG80211
	struct bcm_cfg80211 *cfg = NULL;
#endif // endif
	if (!dhdp)
		return;

	dhd = (dhd_info_t *)dhdp->info;
	if (!dhd)
		return;

	dev = dhd->iflist[0]->net;

	if (dev) {
		rtnl_lock();
#if defined(WL_CFG80211) && defined(WL_STATIC_IF)
		if (dhd->dhd_state & DHD_ATTACH_STATE_CFG80211) {
			wl_cfg80211_static_if_dev_close(dev);
		}
#endif /* WL_CFG80211 && WL_STATIC_IF */
		if (dev->flags & IFF_UP) {
			/* If IFF_UP is still up, it indicates that
			 * "ifconfig wlan0 down" hasn't been called.
			 * So invoke dev_close explicitly here to
			 * bring down the interface.
			 */
			DHD_TRACE(("IFF_UP flag is up. Enforcing dev_close from detach \n"));
			dev_close(dev);
		}
		rtnl_unlock();
	}

	DHD_TRACE(("%s: Enter state 0x%x\n", __FUNCTION__, dhd->dhd_state));

	DHD_ERROR(("%s: making dhdpub up FALSE\n", __FUNCTION__));
	dhd->pub.up = 0;
	if (!(dhd->dhd_state & DHD_ATTACH_STATE_DONE)) {
		/* Give sufficient time for threads to start running in case
		 * dhd_attach() has failed
		 */
		OSL_SLEEP(100);
	}
#ifdef DHD_WET
	dhd_free_wet_info(&dhd->pub, dhd->pub.wet_info);
#endif /* DHD_WET */
#if defined(BCM_DNGL_EMBEDIMAGE) || defined(BCM_REQUEST_FW)
#endif /* defined(BCM_DNGL_EMBEDIMAGE) || defined(BCM_REQUEST_FW) */

#ifdef PROP_TXSTATUS
#ifdef DHD_WLFC_THREAD
	if (dhd->pub.wlfc_thread) {
		kthread_stop(dhd->pub.wlfc_thread);
		dhdp->wlfc_thread_go = TRUE;
		wake_up_interruptible(&dhdp->wlfc_wqhead);
	}
	dhd->pub.wlfc_thread = NULL;
#endif /* DHD_WLFC_THREAD */
#endif /* PROP_TXSTATUS */

#ifdef WL_CFG80211
	if (dev)
		wl_cfg80211_down(dev);
#endif /* WL_CFG80211 */

	if (dhd->dhd_state & DHD_ATTACH_STATE_PROT_ATTACH) {

		dhd_bus_detach(dhdp);
#ifdef BCMPCIE
		if (is_reboot == SYS_RESTART) {
			extern bcmdhd_wifi_platdata_t *dhd_wifi_platdata;
			if (dhd_wifi_platdata && !dhdp->dongle_reset) {
				dhdpcie_bus_clock_stop(dhdp->bus);
				wifi_platform_set_power(dhd_wifi_platdata->adapters,
					FALSE, WIFI_TURNOFF_DELAY);
			}
		}
#endif /* BCMPCIE */
#ifndef PCIE_FULL_DONGLE
		if (dhdp->prot)
			dhd_prot_detach(dhdp);
#endif /* !PCIE_FULL_DONGLE */
	}

#ifdef ARP_OFFLOAD_SUPPORT
	if (dhd_inetaddr_notifier_registered) {
		dhd_inetaddr_notifier_registered = FALSE;
		unregister_inetaddr_notifier(&dhd_inetaddr_notifier);
	}
#endif /* ARP_OFFLOAD_SUPPORT */
#if defined(CONFIG_IPV6) && defined(IPV6_NDO_SUPPORT)
	if (dhd_inet6addr_notifier_registered) {
		dhd_inet6addr_notifier_registered = FALSE;
		unregister_inet6addr_notifier(&dhd_inet6addr_notifier);
	}
#endif /* CONFIG_IPV6 && IPV6_NDO_SUPPORT */
#if defined(CONFIG_HAS_EARLYSUSPEND) && defined(DHD_USE_EARLYSUSPEND)
	if (dhd->dhd_state & DHD_ATTACH_STATE_EARLYSUSPEND_DONE) {
		if (dhd->early_suspend.suspend)
			unregister_early_suspend(&dhd->early_suspend);
	}
#endif /* CONFIG_HAS_EARLYSUSPEND && DHD_USE_EARLYSUSPEND */

#if defined(WL_WIRELESS_EXT)
	if (dhd->dhd_state & DHD_ATTACH_STATE_WL_ATTACH) {
		/* Detatch and unlink in the iw */
		wl_iw_detach(dev);
	}
#endif /* defined(WL_WIRELESS_EXT) */
#ifdef WL_EXT_GENL
	wl_ext_genl_deinit(dev);
#endif
#ifdef WL_EXT_IAPSTA
	wl_ext_iapsta_dettach(dev);
#endif /* WL_EXT_IAPSTA */
#ifdef WL_ESCAN
	wl_escan_detach(dev);
#endif /* WL_ESCAN */
#ifdef WL_EVENT
	wl_ext_event_dettach(dhdp);
#endif /* WL_EVENT */

#ifdef DHD_ULP
	dhd_ulp_deinit(dhd->pub.osh, dhdp);
#endif /* DHD_ULP */

	/* delete all interfaces, start with virtual  */
	if (dhd->dhd_state & DHD_ATTACH_STATE_ADD_IF) {
		int i = 1;
		dhd_if_t *ifp;

		/* Cleanup virtual interfaces */
		dhd_net_if_lock_local(dhd);
		for (i = 1; i < DHD_MAX_IFS; i++) {
			if (dhd->iflist[i]) {
				dhd_remove_if(&dhd->pub, i, TRUE);
			}
		}
		dhd_net_if_unlock_local(dhd);

		/*  delete primary interface 0 */
		ifp = dhd->iflist[0];
		if (ifp && ifp->net) {

#ifdef WL_CFG80211
			cfg = wl_get_cfg(ifp->net);
#endif // endif
			/* in unregister_netdev case, the interface gets freed by net->destructor
			 * (which is set to free_netdev)
			 */
			if (ifp->net->reg_state == NETREG_UNINITIALIZED) {
				free_netdev(ifp->net);
			} else {
#if defined(ARGOS_NOTIFY_CB)
				argos_register_notifier_deinit();
#endif // endif
#ifdef SET_RPS_CPUS
				custom_rps_map_clear(ifp->net->_rx);
#endif /* SET_RPS_CPUS */
				netif_tx_disable(ifp->net);
#ifdef CONFIG_AP6XXX_WIFI6_HDF
                IFP_NET_DESTRUCTOR = NULL;
#endif
				unregister_netdev(ifp->net);
			}
#ifdef PCIE_FULL_DONGLE
			ifp->net = DHD_NET_DEV_NULL;
#else
			ifp->net = NULL;
#endif /* PCIE_FULL_DONGLE */

#ifdef DHD_L2_FILTER
			bcm_l2_filter_arp_table_update(dhdp->osh, ifp->phnd_arp_table, TRUE,
				NULL, FALSE, dhdp->tickcnt);
			deinit_l2_filter_arp_table(dhdp->osh, ifp->phnd_arp_table);
			ifp->phnd_arp_table = NULL;
#endif /* DHD_L2_FILTER */

			dhd_if_del_sta_list(ifp);

			MFREE(dhd->pub.osh, ifp, sizeof(*ifp));
			dhd->iflist[0] = NULL;
#ifdef WL_CFG80211
			if (cfg && cfg->wdev)
				cfg->wdev->netdev = NULL;
#endif
		}
	}

	/* Clear the watchdog timer */
	DHD_GENERAL_LOCK(&dhd->pub, flags);
	timer_valid = dhd->wd_timer_valid;
	dhd->wd_timer_valid = FALSE;
	DHD_GENERAL_UNLOCK(&dhd->pub, flags);
	if (timer_valid)
		del_timer_sync(&dhd->timer);
	DHD_DISABLE_RUNTIME_PM(&dhd->pub);

#ifdef BCMDBUS
	tasklet_kill(&dhd->tasklet);
#else
	if (dhd->dhd_state & DHD_ATTACH_STATE_THREADS_CREATED) {
		if (dhd->thr_wdt_ctl.thr_pid >= 0) {
			PROC_STOP(&dhd->thr_wdt_ctl);
		}

		if (dhd->rxthread_enabled && dhd->thr_rxf_ctl.thr_pid >= 0) {
			PROC_STOP(&dhd->thr_rxf_ctl);
		}

		if (dhd->thr_dpc_ctl.thr_pid >= 0) {
			PROC_STOP(&dhd->thr_dpc_ctl);
		} else
		{
			tasklet_kill(&dhd->tasklet);
		}
	}
#endif /* BCMDBUS */

#ifdef WL_NATOE
	if (dhd->pub.nfct) {
		dhd_ct_close(dhd->pub.nfct);
	}
#endif /* WL_NATOE */

#ifdef DHD_LB
	if (dhd->dhd_state & DHD_ATTACH_STATE_LB_ATTACH_DONE) {
		/* Clear the flag first to avoid calling the cpu notifier */
		dhd->dhd_state &= ~DHD_ATTACH_STATE_LB_ATTACH_DONE;

		/* Kill the Load Balancing Tasklets */
#ifdef DHD_LB_RXP
		cancel_work_sync(&dhd->rx_napi_dispatcher_work);
		__skb_queue_purge(&dhd->rx_pend_queue);
#endif /* DHD_LB_RXP */
#ifdef DHD_LB_TXP
		cancel_work_sync(&dhd->tx_dispatcher_work);
		tasklet_kill(&dhd->tx_tasklet);
		__skb_queue_purge(&dhd->tx_pend_queue);
#endif /* DHD_LB_TXP */
#ifdef DHD_LB_TXC
		cancel_work_sync(&dhd->tx_compl_dispatcher_work);
		tasklet_kill(&dhd->tx_compl_tasklet);
#endif /* DHD_LB_TXC */
#ifdef DHD_LB_RXC
		tasklet_kill(&dhd->rx_compl_tasklet);
#endif /* DHD_LB_RXC */

		/* Unregister from CPU Hotplug framework */
		dhd_unregister_cpuhp_callback(dhd);

		dhd_cpumasks_deinit(dhd);
		DHD_LB_STATS_DEINIT(&dhd->pub);
	}
#endif /* DHD_LB */

#ifdef CSI_SUPPORT
	dhd_csi_deinit(dhdp);
#endif /* CSI_SUPPORT */

#if defined(DNGL_AXI_ERROR_LOGGING) && defined(DHD_USE_WQ_FOR_DNGL_AXI_ERROR)
	cancel_work_sync(&dhd->axi_error_dispatcher_work);
#endif /* DNGL_AXI_ERROR_LOGGING && DHD_USE_WQ_FOR_DNGL_AXI_ERROR */

	DHD_SSSR_MEMPOOL_DEINIT(&dhd->pub);

#ifdef WL_CFG80211
	if (dhd->dhd_state & DHD_ATTACH_STATE_CFG80211) {
		if (!cfg) {
			DHD_ERROR(("cfg NULL!\n"));
			ASSERT(0);
		} else {
			wl_cfg80211_detach(cfg);
			dhd_monitor_uninit();
		}
	}
#endif // endif

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
	destroy_workqueue(dhd->tx_wq);
	dhd->tx_wq = NULL;
	destroy_workqueue(dhd->rx_wq);
	dhd->rx_wq = NULL;
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */
#ifdef DEBUGABILITY
	if (dhdp->dbg) {
#ifdef DBG_PKT_MON
		dhd_os_dbg_detach_pkt_monitor(dhdp);
		dhd_os_spin_lock_deinit(dhd->pub.osh, dhd->pub.dbg->pkt_mon_lock);
#endif /* DBG_PKT_MON */
	}
#endif /* DEBUGABILITY */
	if (dhdp->dbg) {
		dhd_os_dbg_detach(dhdp);
	}
#ifdef DHD_STATUS_LOGGING
	dhd_detach_statlog(dhdp);
#endif /* DHD_STATUS_LOGGING */
#ifdef DHD_PKTDUMP_ROAM
	dhd_dump_pkt_deinit(dhdp);
#endif /* DHD_PKTDUMP_ROAM */
#ifdef SHOW_LOGTRACE
	/* Release the skbs from queue for WLC_E_TRACE event */
	dhd_event_logtrace_flush_queue(dhdp);

	/* Wait till event logtrace context finishes */
	dhd_cancel_logtrace_process_sync(dhd);

	/* Remove ring proc entries */
	dhd_dbg_ring_proc_destroy(&dhd->pub);

	if (dhd->dhd_state & DHD_ATTACH_LOGTRACE_INIT) {
		if (dhd->event_data.fmts) {
			MFREE(dhd->pub.osh, dhd->event_data.fmts,
					dhd->event_data.fmts_size);
			dhd->event_data.fmts = NULL;
		}
		if (dhd->event_data.raw_fmts) {
			MFREE(dhd->pub.osh, dhd->event_data.raw_fmts,
					dhd->event_data.raw_fmts_size);
			dhd->event_data.raw_fmts = NULL;
		}
		if (dhd->event_data.raw_sstr) {
			MFREE(dhd->pub.osh, dhd->event_data.raw_sstr,
					dhd->event_data.raw_sstr_size);
			dhd->event_data.raw_sstr = NULL;
		}
		if (dhd->event_data.rom_raw_sstr) {
			MFREE(dhd->pub.osh, dhd->event_data.rom_raw_sstr,
					dhd->event_data.rom_raw_sstr_size);
			dhd->event_data.rom_raw_sstr = NULL;
		}
		dhd->dhd_state &= ~DHD_ATTACH_LOGTRACE_INIT;
	}
#endif /* SHOW_LOGTRACE */
#ifdef PNO_SUPPORT
	if (dhdp->pno_state)
		dhd_pno_deinit(dhdp);
#endif // endif
#ifdef RTT_SUPPORT
	if (dhdp->rtt_state) {
		dhd_rtt_deinit(dhdp);
	}
#endif // endif
#if defined(CONFIG_PM_SLEEP)
	if (dhd_pm_notifier_registered) {
		unregister_pm_notifier(&dhd->pm_notifier);
		dhd_pm_notifier_registered = FALSE;
	}
#endif /* CONFIG_PM_SLEEP */

#ifdef DEBUG_CPU_FREQ
		if (dhd->new_freq)
			free_percpu(dhd->new_freq);
		dhd->new_freq = NULL;
		cpufreq_unregister_notifier(&dhd->freq_trans, CPUFREQ_TRANSITION_NOTIFIER);
#endif // endif
	DHD_TRACE(("wd wakelock count:%d\n", dhd->wakelock_wd_counter));
#ifdef CONFIG_HAS_WAKELOCK
	dhd->wakelock_wd_counter = 0;
	wake_lock_destroy(&dhd->wl_wdwake);
	// terence 20161023: can not destroy wl_wifi when wlan down, it will happen null pointer in dhd_ioctl_entry
	wake_lock_destroy(&dhd->wl_wifi);
#endif /* CONFIG_HAS_WAKELOCK */
	if (dhd->dhd_state & DHD_ATTACH_STATE_WAKELOCKS_INIT) {
		DHD_OS_WAKE_LOCK_DESTROY(dhd);
	}

#ifdef DHDTCPACK_SUPPRESS
	/* This will free all MEM allocated for TCPACK SUPPRESS */
	dhd_tcpack_suppress_set(&dhd->pub, TCPACK_SUP_OFF);
#endif /* DHDTCPACK_SUPPRESS */

#ifdef PCIE_FULL_DONGLE
	dhd_flow_rings_deinit(dhdp);
	if (dhdp->prot)
		dhd_prot_detach(dhdp);
#endif // endif

#if defined(WLTDLS) && defined(PCIE_FULL_DONGLE)
		dhd_free_tdls_peer_list(dhdp);
#endif // endif

#ifdef DUMP_IOCTL_IOV_LIST
	dhd_iov_li_delete(dhdp, &(dhdp->dump_iovlist_head));
#endif /* DUMP_IOCTL_IOV_LIST */
#ifdef DHD_DEBUG
	/* memory waste feature list initilization */
	dhd_mw_list_delete(dhdp, &(dhdp->mw_list_head));
#endif /* DHD_DEBUG */
#ifdef WL_MONITOR
	dhd_del_monitor_if(dhd);
#endif /* WL_MONITOR */

#ifdef DHD_ERPOM
	if (dhdp->enable_erpom) {
		dhdp->pom_func_deregister(&dhdp->pom_wlan_handler);
	}
#endif /* DHD_ERPOM */

	cancel_work_sync(&dhd->dhd_hang_process_work);

	/* Prefer adding de-init code above this comment unless necessary.
	 * The idea is to cancel work queue, sysfs and flags at the end.
	 */
	dhd_deferred_work_deinit(dhd->dhd_deferred_wq);
	dhd->dhd_deferred_wq = NULL;

	/* log dump related buffers should be freed after wq is purged */
#ifdef DHD_LOG_DUMP
	dhd_log_dump_deinit(&dhd->pub);
#endif /* DHD_LOG_DUMP */
#if defined(BCMPCIE)
	if (dhdp->extended_trap_data)
	{
		MFREE(dhdp->osh, dhdp->extended_trap_data, BCMPCIE_EXT_TRAP_DATA_MAXLEN);
		dhdp->extended_trap_data = NULL;
	}
#ifdef DNGL_AXI_ERROR_LOGGING
	if (dhdp->axi_err_dump)
	{
		MFREE(dhdp->osh, dhdp->axi_err_dump, sizeof(dhd_axi_error_dump_t));
		dhdp->axi_err_dump = NULL;
	}
#endif /* DNGL_AXI_ERROR_LOGGING */
#endif /* BCMPCIE */

#ifdef DHD_DUMP_MNGR
	if (dhd->pub.dump_file_manage) {
		MFREE(dhd->pub.osh, dhd->pub.dump_file_manage,
			sizeof(dhd_dump_file_manage_t));
	}
#endif /* DHD_DUMP_MNGR */
	dhd_sysfs_exit(dhd);
	dhd->pub.fw_download_status = FW_UNLOADED;

#if defined(BT_OVER_SDIO)
	mutex_destroy(&dhd->bus_user_lock);
#endif /* BT_OVER_SDIO */
	dhd_conf_detach(dhdp);

} /* dhd_detach */

void
dhd_free(dhd_pub_t *dhdp)
{
	dhd_info_t *dhd;
	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (dhdp) {
		int i;
		for (i = 0; i < ARRAYSIZE(dhdp->reorder_bufs); i++) {
			if (dhdp->reorder_bufs[i]) {
				reorder_info_t *ptr;
				uint32 buf_size = sizeof(struct reorder_info);

				ptr = dhdp->reorder_bufs[i];

				buf_size += ((ptr->max_idx + 1) * sizeof(void*));
				DHD_REORDER(("free flow id buf %d, maxidx is %d, buf_size %d\n",
					i, ptr->max_idx, buf_size));

				MFREE(dhdp->osh, dhdp->reorder_bufs[i], buf_size);
				dhdp->reorder_bufs[i] = NULL;
			}
		}

		dhd_sta_pool_fini(dhdp, DHD_MAX_STA);

		dhd = (dhd_info_t *)dhdp->info;
		if (dhdp->soc_ram) {
#if defined(CONFIG_DHD_USE_STATIC_BUF) && defined(DHD_USE_STATIC_MEMDUMP)
			DHD_OS_PREFREE(dhdp, dhdp->soc_ram, dhdp->soc_ram_length);
#else
			MFREE(dhdp->osh, dhdp->soc_ram, dhdp->soc_ram_length);
#endif /* CONFIG_DHD_USE_STATIC_BUF && DHD_USE_STATIC_MEMDUMP */
			dhdp->soc_ram = NULL;
		}
		if (dhd != NULL) {

			/* If pointer is allocated by dhd_os_prealloc then avoid MFREE */
			if (dhd != (dhd_info_t *)dhd_os_prealloc(dhdp,
					DHD_PREALLOC_DHD_INFO, 0, FALSE))
				MFREE(dhd->pub.osh, dhd, sizeof(*dhd));
			dhd = NULL;
		}
	}
}

void
dhd_clear(dhd_pub_t *dhdp)
{
	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (dhdp) {
		int i;
#ifdef DHDTCPACK_SUPPRESS
		/* Clean up timer/data structure for any remaining/pending packet or timer. */
		dhd_tcpack_info_tbl_clean(dhdp);
#endif /* DHDTCPACK_SUPPRESS */
		for (i = 0; i < ARRAYSIZE(dhdp->reorder_bufs); i++) {
			if (dhdp->reorder_bufs[i]) {
				reorder_info_t *ptr;
				uint32 buf_size = sizeof(struct reorder_info);

				ptr = dhdp->reorder_bufs[i];

				buf_size += ((ptr->max_idx + 1) * sizeof(void*));
				DHD_REORDER(("free flow id buf %d, maxidx is %d, buf_size %d\n",
					i, ptr->max_idx, buf_size));

				MFREE(dhdp->osh, dhdp->reorder_bufs[i], buf_size);
				dhdp->reorder_bufs[i] = NULL;
			}
		}

		dhd_sta_pool_clear(dhdp, DHD_MAX_STA);

		if (dhdp->soc_ram) {
#if defined(CONFIG_DHD_USE_STATIC_BUF) && defined(DHD_USE_STATIC_MEMDUMP)
			DHD_OS_PREFREE(dhdp, dhdp->soc_ram, dhdp->soc_ram_length);
#else
			MFREE(dhdp->osh, dhdp->soc_ram, dhdp->soc_ram_length);
#endif /* CONFIG_DHD_USE_STATIC_BUF && DHD_USE_STATIC_MEMDUMP */
			dhdp->soc_ram = NULL;
		}
	}
}

static void
dhd_module_cleanup(void)
{
	printf("%s: Enter\n", __FUNCTION__);

	dhd_bus_unregister();

	wl_android_exit();

	dhd_wifi_platform_unregister_drv();
	printf("%s: Exit\n", __FUNCTION__);
}

#ifdef CONFIG_AP6XXX_WIFI6_HDF
void
#else
static void __exit
#endif
dhd_module_exit(void)
{
	atomic_set(&exit_in_progress, 1);
	dhd_module_cleanup();
	unregister_reboot_notifier(&dhd_reboot_notifier);
	dhd_destroy_to_notifier_skt();
}
#ifdef CONFIG_AP6XXX_WIFI6_HDF
int 
#else
static int __init 
#endif
dhd_module_init(void)
{
	int err;
	int retry = POWERUP_MAX_RETRY;

	printf("%s: in %s\n", __FUNCTION__, dhd_version);

	DHD_PERIM_RADIO_INIT();

	if (firmware_path[0] != '\0') {
		strncpy(fw_bak_path, firmware_path, MOD_PARAM_PATHLEN);
		fw_bak_path[MOD_PARAM_PATHLEN-1] = '\0';
	}

	if (nvram_path[0] != '\0') {
		strncpy(nv_bak_path, nvram_path, MOD_PARAM_PATHLEN);
		nv_bak_path[MOD_PARAM_PATHLEN-1] = '\0';
	}

	do {
		err = dhd_wifi_platform_register_drv();
		if (!err) {
			register_reboot_notifier(&dhd_reboot_notifier);
			break;
		} else {
			DHD_ERROR(("%s: Failed to load the driver, try cnt %d\n",
				__FUNCTION__, retry));
			strncpy(firmware_path, fw_bak_path, MOD_PARAM_PATHLEN);
			firmware_path[MOD_PARAM_PATHLEN-1] = '\0';
			strncpy(nvram_path, nv_bak_path, MOD_PARAM_PATHLEN);
			nvram_path[MOD_PARAM_PATHLEN-1] = '\0';
		}
	} while (retry--);

	dhd_create_to_notifier_skt();

	if (err) {
		DHD_ERROR(("%s: Failed to load driver max retry reached**\n", __FUNCTION__));
	} else {
		if (!dhd_download_fw_on_driverload) {
			dhd_driver_init_done = TRUE;
		}
	}

	printf("%s: Exit err=%d\n", __FUNCTION__, err);
	return err;
}

static int
dhd_reboot_callback(struct notifier_block *this, unsigned long code, void *unused)
{
	DHD_TRACE(("%s: code = %ld\n", __FUNCTION__, code));
	if (code == SYS_RESTART) {
#ifdef BCMPCIE
		is_reboot = code;
#endif /* BCMPCIE */
	}
	return NOTIFY_DONE;
}

#ifndef CONFIG_AP6XXX_WIFI6_HDF
#if defined(CONFIG_DEFERRED_INITCALLS) && !defined(EXYNOS_PCIE_MODULE_PATCH)
#if defined(CONFIG_MACH_UNIVERSAL7420) || defined(CONFIG_SOC_EXYNOS8890) || \
	defined(CONFIG_ARCH_MSM8996) || defined(CONFIG_ARCH_MSM8998) || \
	defined(CONFIG_SOC_EXYNOS8895) || defined(CONFIG_SOC_EXYNOS9810) || \
	defined(CONFIG_ARCH_SDM845) || defined(CONFIG_SOC_EXYNOS9820) || \
	defined(CONFIG_ARCH_SM8150)
deferred_module_init_sync(dhd_module_init);
#else
deferred_module_init(dhd_module_init);
#endif /* CONFIG_MACH_UNIVERSAL7420 || CONFIG_SOC_EXYNOS8890 ||
	* CONFIG_ARCH_MSM8996 || CONFIG_ARCH_MSM8998 || CONFIG_SOC_EXYNOS8895
	* CONFIG_SOC_EXYNOS9810 || CONFIG_ARCH_SDM845 || CONFIG_SOC_EXYNOS9820
	* CONFIG_ARCH_SM8150
	*/
#elif defined(USE_LATE_INITCALL_SYNC)
late_initcall_sync(dhd_module_init);
#else
late_initcall(dhd_module_init);
#endif /* USE_LATE_INITCALL_SYNC */

module_exit(dhd_module_exit);
#endif

/*
 * OS specific functions required to implement DHD driver in OS independent way
 */
int
dhd_os_proto_block(dhd_pub_t *pub)
{
	dhd_info_t * dhd = (dhd_info_t *)(pub->info);

	if (dhd) {
		DHD_PERIM_UNLOCK(pub);

		down(&dhd->proto_sem);

		DHD_PERIM_LOCK(pub);
		return 1;
	}

	return 0;
}

int
dhd_os_proto_unblock(dhd_pub_t *pub)
{
	dhd_info_t * dhd = (dhd_info_t *)(pub->info);

	if (dhd) {
		up(&dhd->proto_sem);
		return 1;
	}

	return 0;
}

void
dhd_os_dhdiovar_lock(dhd_pub_t *pub)
{
	dhd_info_t * dhd = (dhd_info_t *)(pub->info);

	if (dhd) {
		mutex_lock(&dhd->dhd_iovar_mutex);
	}
}

void
dhd_os_dhdiovar_unlock(dhd_pub_t *pub)
{
	dhd_info_t * dhd = (dhd_info_t *)(pub->info);

	if (dhd) {
		mutex_unlock(&dhd->dhd_iovar_mutex);
	}
}

void
dhd_os_logdump_lock(dhd_pub_t *pub)
{
	dhd_info_t *dhd = NULL;

	if (!pub)
		return;

	dhd = (dhd_info_t *)(pub->info);

	if (dhd) {
		mutex_lock(&dhd->logdump_lock);
	}
}

void
dhd_os_logdump_unlock(dhd_pub_t *pub)
{
	dhd_info_t *dhd = NULL;

	if (!pub)
		return;

	dhd = (dhd_info_t *)(pub->info);

	if (dhd) {
		mutex_unlock(&dhd->logdump_lock);
	}
}

unsigned long
dhd_os_dbgring_lock(void *lock)
{
	if (!lock)
		return 0;

	mutex_lock((struct mutex *)lock);

	return 0;
}

void
dhd_os_dbgring_unlock(void *lock, unsigned long flags)
{
	BCM_REFERENCE(flags);

	if (!lock)
		return;

	mutex_unlock((struct mutex *)lock);
}

unsigned int
dhd_os_get_ioctl_resp_timeout(void)
{
	return ((unsigned int)dhd_ioctl_timeout_msec);
}

void
dhd_os_set_ioctl_resp_timeout(unsigned int timeout_msec)
{
	dhd_ioctl_timeout_msec = (int)timeout_msec;
}

int
dhd_os_ioctl_resp_wait(dhd_pub_t *pub, uint *condition)
{
	dhd_info_t * dhd = (dhd_info_t *)(pub->info);
	int timeout;

	/* Convert timeout in millsecond to jiffies */
	timeout = msecs_to_jiffies(dhd_ioctl_timeout_msec);

	DHD_PERIM_UNLOCK(pub);

	timeout = wait_event_timeout(dhd->ioctl_resp_wait, (*condition), timeout);

	DHD_PERIM_LOCK(pub);

	return timeout;
}

int
dhd_os_ioctl_resp_wake(dhd_pub_t *pub)
{
	dhd_info_t *dhd = (dhd_info_t *)(pub->info);

	wake_up(&dhd->ioctl_resp_wait);
	return 0;
}

int
dhd_os_d3ack_wait(dhd_pub_t *pub, uint *condition)
{
	dhd_info_t * dhd = (dhd_info_t *)(pub->info);
	int timeout;

	/* Convert timeout in millsecond to jiffies */
	timeout = msecs_to_jiffies(D3_ACK_RESP_TIMEOUT);

	DHD_PERIM_UNLOCK(pub);

	timeout = wait_event_timeout(dhd->d3ack_wait, (*condition), timeout);

	DHD_PERIM_LOCK(pub);

	return timeout;
}

int
dhd_os_d3ack_wake(dhd_pub_t *pub)
{
	dhd_info_t *dhd = (dhd_info_t *)(pub->info);

	wake_up(&dhd->d3ack_wait);
	return 0;
}

int
dhd_os_busbusy_wait_negation(dhd_pub_t *pub, uint *condition)
{
	dhd_info_t * dhd = (dhd_info_t *)(pub->info);
	int timeout;

	/* Wait for bus usage contexts to gracefully exit within some timeout value
	 * Set time out to little higher than dhd_ioctl_timeout_msec,
	 * so that IOCTL timeout should not get affected.
	 */
	/* Convert timeout in millsecond to jiffies */
	timeout = msecs_to_jiffies(DHD_BUS_BUSY_TIMEOUT);

	timeout = wait_event_timeout(dhd->dhd_bus_busy_state_wait, !(*condition), timeout);

	return timeout;
}

/*
 * Wait until the condition *var == condition is met.
 * Returns 0 if the @condition evaluated to false after the timeout elapsed
 * Returns 1 if the @condition evaluated to true
 */
int
dhd_os_busbusy_wait_condition(dhd_pub_t *pub, uint *var, uint condition)
{
	dhd_info_t * dhd = (dhd_info_t *)(pub->info);
	int timeout;

	/* Convert timeout in millsecond to jiffies */
	timeout = msecs_to_jiffies(DHD_BUS_BUSY_TIMEOUT);

	timeout = wait_event_timeout(dhd->dhd_bus_busy_state_wait, (*var == condition), timeout);

	return timeout;
}

/*
 * Wait until the '(*var & bitmask) == condition' is met.
 * Returns 0 if the @condition evaluated to false after the timeout elapsed
 * Returns 1 if the @condition evaluated to true
 */
int
dhd_os_busbusy_wait_bitmask(dhd_pub_t *pub, uint *var,
		uint bitmask, uint condition)
{
	dhd_info_t * dhd = (dhd_info_t *)(pub->info);
	int timeout;

	/* Convert timeout in millsecond to jiffies */
	timeout = msecs_to_jiffies(DHD_BUS_BUSY_TIMEOUT);

	timeout = wait_event_timeout(dhd->dhd_bus_busy_state_wait,
			((*var & bitmask) == condition), timeout);

	return timeout;
}

int
dhd_os_dmaxfer_wait(dhd_pub_t *pub, uint *condition)
{
	int ret = 0;
	dhd_info_t * dhd = (dhd_info_t *)(pub->info);
	int timeout;

	timeout = msecs_to_jiffies(IOCTL_DMAXFER_TIMEOUT);

	DHD_PERIM_UNLOCK(pub);
	ret = wait_event_timeout(dhd->dmaxfer_wait, (*condition), timeout);
	DHD_PERIM_LOCK(pub);

	return ret;

}

int
dhd_os_dmaxfer_wake(dhd_pub_t *pub)
{
	dhd_info_t *dhd = (dhd_info_t *)(pub->info);

	wake_up(&dhd->dmaxfer_wait);
	return 0;
}

void
dhd_os_tx_completion_wake(dhd_pub_t *dhd)
{
	/* Call wmb() to make sure before waking up the other event value gets updated */
	OSL_SMP_WMB();
	wake_up(&dhd->tx_completion_wait);
}

/* Fix compilation error for FC11 */
INLINE int
dhd_os_busbusy_wake(dhd_pub_t *pub)
{
	dhd_info_t *dhd = (dhd_info_t *)(pub->info);
	/* Call wmb() to make sure before waking up the other event value gets updated */
	OSL_SMP_WMB();
	wake_up(&dhd->dhd_bus_busy_state_wait);
	return 0;
}

void
dhd_os_wd_timer_extend(void *bus, bool extend)
{
#ifndef BCMDBUS
	dhd_pub_t *pub = bus;
	dhd_info_t *dhd = (dhd_info_t *)pub->info;

	if (extend)
		dhd_os_wd_timer(bus, WATCHDOG_EXTEND_INTERVAL);
	else
		dhd_os_wd_timer(bus, dhd->default_wd_interval);
#endif /* !BCMDBUS */
}
