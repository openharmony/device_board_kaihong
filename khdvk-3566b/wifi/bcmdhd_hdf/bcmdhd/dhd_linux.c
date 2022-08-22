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
