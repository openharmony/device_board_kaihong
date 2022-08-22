/*
 * Header file describing the internal (inter-module) DHD interfaces.
 *
 * Provides type definitions and function prototypes used to link the
 * DHD OS, bus, and protocol modules.
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
 * $Id: dhd.h 822756 2019-05-30 13:20:26Z $
 */

/****************
 * Common types *
 */

#ifndef _dhd_h_
#define _dhd_h_

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/ethtool.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <asm/unaligned.h>
#if defined(CONFIG_HAS_WAKELOCK)
#include <linux/wakelock.h>
#endif /* defined CONFIG_HAS_WAKELOCK */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#include <uapi/linux/sched/types.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/types.h>
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) */
/* The kernel threading is sdio-specific */
struct task_struct;
struct sched_param;
#if defined(BT_OVER_SDIO)
#include <dhd_bt_interface.h>
#endif /* defined (BT_OVER_SDIO) */
int setScheduler(struct task_struct *p, int policy, struct sched_param *param);
int get_scheduler_policy(struct task_struct *p);
#define MAX_EVENT	16

#define ALL_INTERFACES	0xff

/* H2D and D2H ring dump is enabled by default */
#ifdef PCIE_FULL_DONGLE
#define DHD_DUMP_PCIE_RINGS
#endif /* PCIE_FULL_DONGLE */

#include <wlioctl.h>
#include <bcmstdlib_s.h>
#include <dhdioctl.h>
#include <wlfc_proto.h>
#include <hnd_armtrap.h>
#if defined(DUMP_IOCTL_IOV_LIST) || defined(DHD_DEBUG)
#include <bcmutils.h>
#endif /* DUMP_IOCTL_IOV_LIST || DHD_DEBUG */

#if defined(BCMWDF)
#include <wdf.h>
#include <WdfMiniport.h>
#endif /* (BCMWDF)  */

#ifdef DHD_ERPOM
#include <pom.h>
#endif /* DHD_ERPOM */

#include <dngl_stats.h>

#ifdef DEBUG_DPC_THREAD_WATCHDOG
#define MAX_RESCHED_CNT 600
#endif /* DEBUG_DPC_THREAD_WATCHDOG */

#if defined(KEEP_ALIVE)
/* Default KEEP_ALIVE Period is 55 sec to prevent AP from sending Keep Alive probe frame */
#define KEEP_ALIVE_PERIOD 55000
#define NULL_PKT_STR	"null_pkt"
#endif /* KEEP_ALIVE */

/* By default enabled from here, later the WQ code will be removed */
#define DHD_USE_KTHREAD_FOR_LOGTRACE

/*
 * Earlier DHD used to have it own time stamp for printk and
 * Dongle used to have its own time stamp for console messages
 * With this flag, DHD and Dongle console messges will have same time zone
 */
#ifdef BCMPCIE
#define DHD_H2D_LOG_TIME_SYNC
#endif
/* Forward decls */
struct dhd_bus;
struct dhd_prot;
struct dhd_info;
struct dhd_ioctl;
struct dhd_dbg;
struct dhd_ts;
#ifdef DNGL_AXI_ERROR_LOGGING
struct dhd_axi_error_dump;
#endif /* DNGL_AXI_ERROR_LOGGING */

/* The level of bus communication with the dongle */
enum dhd_bus_state {
	DHD_BUS_DOWN,		/* Not ready for frame transfers */
	DHD_BUS_LOAD,		/* Download access only (CPU reset) */
	DHD_BUS_DATA,		/* Ready for frame transfers */
	DHD_BUS_SUSPEND,	/* Bus has been suspended */
	DHD_BUS_DOWN_IN_PROGRESS,	/* Bus going Down */
	DHD_BUS_REMOVE,	/* Bus has been removed */
};

/* The level of bus communication with the dongle */
enum dhd_bus_devreset_type {
	DHD_BUS_DEVRESET_ON = 0,	/* ON */
	DHD_BUS_DEVRESET_OFF = 1,		/* OFF */
	DHD_BUS_DEVRESET_FLR = 2,		/* FLR */
	DHD_BUS_DEVRESET_FLR_FORCE_FAIL = 3,	/* FLR FORCE FAIL */
	DHD_BUS_DEVRESET_QUIESCE = 4,		/* FLR */
};

/*
 * Bit fields to Indicate clean up process that wait till they are finished.
 * Future synchronizable processes can add their bit filed below and update
 * their functionalities accordingly
 */
#define DHD_BUS_BUSY_IN_TX                   0x01
#define DHD_BUS_BUSY_IN_SEND_PKT             0x02
#define DHD_BUS_BUSY_IN_DPC                  0x04
#define DHD_BUS_BUSY_IN_WD                   0x08
#define DHD_BUS_BUSY_IN_IOVAR                0x10
#define DHD_BUS_BUSY_IN_DHD_IOVAR            0x20
#define DHD_BUS_BUSY_SUSPEND_IN_PROGRESS     0x40
#define DHD_BUS_BUSY_RESUME_IN_PROGRESS      0x80
#define DHD_BUS_BUSY_RPM_SUSPEND_IN_PROGRESS 0x100
#define DHD_BUS_BUSY_RPM_SUSPEND_DONE        0x200
#define DHD_BUS_BUSY_RPM_RESUME_IN_PROGRESS  0x400
#define DHD_BUS_BUSY_RPM_ALL                 (DHD_BUS_BUSY_RPM_SUSPEND_DONE | \
		DHD_BUS_BUSY_RPM_SUSPEND_IN_PROGRESS | \
		DHD_BUS_BUSY_RPM_RESUME_IN_PROGRESS)
#define DHD_BUS_BUSY_IN_CHECKDIED            0x800
#define DHD_BUS_BUSY_IN_MEMDUMP				 0x1000
#define DHD_BUS_BUSY_IN_SSSRDUMP			 0x2000
#define DHD_BUS_BUSY_IN_LOGDUMP				 0x4000
#define DHD_BUS_BUSY_IN_HALDUMP				 0x8000

#define DHD_BUS_BUSY_SET_IN_TX(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_IN_TX
#define DHD_BUS_BUSY_SET_IN_SEND_PKT(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_IN_SEND_PKT
#define DHD_BUS_BUSY_SET_IN_DPC(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_IN_DPC
#define DHD_BUS_BUSY_SET_IN_WD(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_IN_WD
#define DHD_BUS_BUSY_SET_IN_IOVAR(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_IN_IOVAR
#define DHD_BUS_BUSY_SET_IN_DHD_IOVAR(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_IN_DHD_IOVAR
#define DHD_BUS_BUSY_SET_SUSPEND_IN_PROGRESS(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_SUSPEND_IN_PROGRESS
#define DHD_BUS_BUSY_SET_RESUME_IN_PROGRESS(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_RESUME_IN_PROGRESS
#define DHD_BUS_BUSY_SET_RPM_SUSPEND_IN_PROGRESS(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_RPM_SUSPEND_IN_PROGRESS
#define DHD_BUS_BUSY_SET_RPM_SUSPEND_DONE(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_RPM_SUSPEND_DONE
#define DHD_BUS_BUSY_SET_RPM_RESUME_IN_PROGRESS(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_RPM_RESUME_IN_PROGRESS
#define DHD_BUS_BUSY_SET_IN_CHECKDIED(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_IN_CHECKDIED
#define DHD_BUS_BUSY_SET_IN_MEMDUMP(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_IN_MEMDUMP
#define DHD_BUS_BUSY_SET_IN_SSSRDUMP(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_IN_SSSRDUMP
#define DHD_BUS_BUSY_SET_IN_LOGDUMP(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_IN_LOGDUMP
#define DHD_BUS_BUSY_SET_IN_HALDUMP(dhdp) \
	(dhdp)->dhd_bus_busy_state |= DHD_BUS_BUSY_IN_HALDUMP

#define DHD_BUS_BUSY_CLEAR_IN_TX(dhdp) \
	(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_IN_TX
#define DHD_BUS_BUSY_CLEAR_IN_SEND_PKT(dhdp) \
	(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_IN_SEND_PKT
#define DHD_BUS_BUSY_CLEAR_IN_DPC(dhdp) \
	(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_IN_DPC
#define DHD_BUS_BUSY_CLEAR_IN_WD(dhdp) \
	(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_IN_WD
#define DHD_BUS_BUSY_CLEAR_IN_IOVAR(dhdp) \
	(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_IN_IOVAR
#define DHD_BUS_BUSY_CLEAR_IN_DHD_IOVAR(dhdp) \
	(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_IN_DHD_IOVAR
#define DHD_BUS_BUSY_CLEAR_SUSPEND_IN_PROGRESS(dhdp) \
	(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_SUSPEND_IN_PROGRESS
#define DHD_BUS_BUSY_CLEAR_RESUME_IN_PROGRESS(dhdp) \
	(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_RESUME_IN_PROGRESS
#define DHD_BUS_BUSY_CLEAR_RPM_SUSPEND_IN_PROGRESS(dhdp) \
	(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_RPM_SUSPEND_IN_PROGRESS
#define DHD_BUS_BUSY_CLEAR_RPM_SUSPEND_DONE(dhdp) \
	(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_RPM_SUSPEND_DONE
#define DHD_BUS_BUSY_CLEAR_RPM_RESUME_IN_PROGRESS(dhdp) \
	(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_RPM_RESUME_IN_PROGRESS
#define DHD_BUS_BUSY_CLEAR_IN_CHECKDIED(dhdp) \
	(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_IN_CHECKDIED
#define DHD_BUS_BUSY_CLEAR_IN_MEMDUMP(dhdp) \
		(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_IN_MEMDUMP
#define DHD_BUS_BUSY_CLEAR_IN_SSSRDUMP(dhdp) \
		(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_IN_SSSRDUMP
#define DHD_BUS_BUSY_CLEAR_IN_LOGDUMP(dhdp) \
		(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_IN_LOGDUMP
#define DHD_BUS_BUSY_CLEAR_IN_HALDUMP(dhdp) \
			(dhdp)->dhd_bus_busy_state &= ~DHD_BUS_BUSY_IN_HALDUMP

#define DHD_BUS_BUSY_CHECK_IN_TX(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_IN_TX)
#define DHD_BUS_BUSY_CHECK_IN_SEND_PKT(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_IN_SEND_PKT)
#define DHD_BUS_BUSY_CHECK_IN_DPC(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_IN_DPC)
#define DHD_BUS_BUSY_CHECK_IN_WD(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_IN_WD)
#define DHD_BUS_BUSY_CHECK_IN_IOVAR(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_IN_IOVAR)
#define DHD_BUS_BUSY_CHECK_IN_DHD_IOVAR(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_IN_DHD_IOVAR)
#define DHD_BUS_BUSY_CHECK_SUSPEND_IN_PROGRESS(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_SUSPEND_IN_PROGRESS)
#define DHD_BUS_BUSY_CHECK_RESUME_IN_PROGRESS(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_RESUME_IN_PROGRESS)
#define DHD_BUS_BUSY_CHECK_RPM_SUSPEND_IN_PROGRESS(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_RPM_SUSPEND_IN_PROGRESS)
#define DHD_BUS_BUSY_CHECK_RPM_SUSPEND_DONE(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_RPM_SUSPEND_DONE)
#define DHD_BUS_BUSY_CHECK_RPM_RESUME_IN_PROGRESS(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_RPM_RESUME_IN_PROGRESS)
#define DHD_BUS_BUSY_CHECK_RPM_ALL(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_RPM_ALL)
#define DHD_BUS_BUSY_CHECK_IN_CHECKDIED(dhdp) \
	((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_IN_CHECKDIED)
#define DHD_BUS_BUSY_CHECK_IN_MEMDUMP(dhdp) \
		((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_IN_MEMDUMP)
#define DHD_BUS_BUSY_CHECK_IN_SSSRDUMP(dhdp) \
		((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_IN_SSSRDUMP)
#define DHD_BUS_BUSY_CHECK_IN_LOGDUMP(dhdp) \
		((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_IN_LOGDUMP)
#define DHD_BUS_BUSY_CHECK_IN_HALDUMP(dhdp) \
			((dhdp)->dhd_bus_busy_state & DHD_BUS_BUSY_IN_HALDUMP)
#define DHD_BUS_BUSY_CHECK_IDLE(dhdp) \
		((dhdp)->dhd_bus_busy_state == 0)

#define DHD_BUS_CHECK_SUSPEND_OR_SUSPEND_IN_PROGRESS(dhdp) \
	((dhdp)->busstate == DHD_BUS_SUSPEND || DHD_BUS_BUSY_CHECK_SUSPEND_IN_PROGRESS(dhdp))

#define DHD_BUS_CHECK_ANY_SUSPEND_IN_PROGRESS(dhdp) \
		(DHD_BUS_BUSY_CHECK_SUSPEND_IN_PROGRESS(dhdp) || \
		 DHD_BUS_BUSY_CHECK_RPM_SUSPEND_IN_PROGRESS(dhdp))

#define DHD_BUS_CHECK_SUSPEND_OR_ANY_SUSPEND_IN_PROGRESS(dhdp) \
	((dhdp)->busstate == DHD_BUS_SUSPEND || DHD_BUS_CHECK_ANY_SUSPEND_IN_PROGRESS(dhdp))

#define DHD_BUS_CHECK_DOWN_OR_DOWN_IN_PROGRESS(dhdp) \
		((dhdp)->busstate == DHD_BUS_DOWN || (dhdp)->busstate == DHD_BUS_DOWN_IN_PROGRESS || \
		(dhdp)->busstate == DHD_BUS_REMOVE)

#define DHD_BUS_CHECK_REMOVE(dhdp) \
		((dhdp)->busstate == DHD_BUS_REMOVE)

/* IOVar flags for common error checks */
#define DHD_IOVF_PWRREQ_BYPASS	(1<<0) /* flags to prevent bp access during host sleep state */

#define MAX_MTU_SZ (1600u)

/* (u64)result = (u64)dividend / (u64)divisor */
#define DIV_U64_BY_U64(dividend, divisor)	div64_u64(dividend, divisor)

/* (u64)result = (u64)dividend / (u32)divisor */
#define DIV_U64_BY_U32(dividend, divisor)	div_u64(dividend, divisor)

/* Be careful while using this, as it divides dividend also
 * (u32)remainder = (u64)dividend % (u32)divisor
 * (u64)dividend = (u64)dividend / (u32)divisor
 */
#define DIV_AND_MOD_U64_BY_U32(dividend, divisor)	do_div(dividend, divisor)

/* (u32)remainder = (u64)dividend % (u32)divisor */
#define MOD_U64_BY_U32(dividend, divisor) ({				\
	uint64 temp_dividend = (dividend);				\
	uint32 rem = DIV_AND_MOD_U64_BY_U32(temp_dividend, (divisor));	\
	rem;								\
})

#define SEC_USEC_FMT \
	"%5llu.%06u"

/* t: time in nano second */
#define GET_SEC_USEC(t) \
	DIV_U64_BY_U32(t, NSEC_PER_SEC), \
	((uint32)(MOD_U64_BY_U32(t, NSEC_PER_SEC) / (uint32)NSEC_PER_USEC))

/* Download Types */
typedef enum download_type {
	FW,
	NVRAM,
	CLM_BLOB,
	TXCAP_BLOB
} download_type_t;

/* For supporting multiple interfaces */
#define DHD_MAX_IFS			16
#ifndef DHD_MAX_STATIC_IFS
#define DHD_MAX_STATIC_IFS	1
#endif
#define DHD_DEL_IF		-0xE
#define DHD_BAD_IF		-0xF
#define DHD_DUMMY_INFO_IF	0xDEAF	/* Hack i/f to handle events from INFO Ring */
#define DHD_EVENT_IF DHD_DUMMY_INFO_IF

enum dhd_op_flags {
/* Firmware requested operation mode */
	DHD_FLAG_STA_MODE				= (1 << (0)), /* STA only */
	DHD_FLAG_HOSTAP_MODE				= (1 << (1)), /* SOFTAP only */
	DHD_FLAG_P2P_MODE				= (1 << (2)), /* P2P Only */
	/* STA + P2P */
	DHD_FLAG_CONCURR_SINGLE_CHAN_MODE = (DHD_FLAG_STA_MODE | DHD_FLAG_P2P_MODE),
	/* STA + SoftAP */
	DHD_FLAG_CONCURR_STA_HOSTAP_MODE = (DHD_FLAG_STA_MODE | DHD_FLAG_HOSTAP_MODE),
	DHD_FLAG_CONCURR_MULTI_CHAN_MODE		= (1 << (4)), /* STA + P2P */
	/* Current P2P mode for P2P connection */
	DHD_FLAG_P2P_GC_MODE				= (1 << (5)),
	DHD_FLAG_P2P_GO_MODE				= (1 << (6)),
	DHD_FLAG_MBSS_MODE				= (1 << (7)), /* MBSS in future */
	DHD_FLAG_IBSS_MODE				= (1 << (8)),
	DHD_FLAG_MFG_MODE				= (1 << (9)),
	DHD_FLAG_RSDB_MODE				= (1 << (10)),
	DHD_FLAG_MP2P_MODE				= (1 << (11))
};

#define DHD_OPMODE_SUPPORTED(dhd, opmode_flag) \
	(dhd ? ((((dhd_pub_t *)dhd)->op_mode)  &  opmode_flag) : -1)
#define DHD_OPMODE_STA_SOFTAP_CONCURR(dhd) \
	(dhd ? (((dhd->op_mode) & DHD_FLAG_CONCURR_STA_HOSTAP_MODE) == \
	DHD_FLAG_CONCURR_STA_HOSTAP_MODE) : 0)

/* Max sequential TX/RX Control timeouts to set HANG event */
#ifndef MAX_CNTL_TX_TIMEOUT
#define MAX_CNTL_TX_TIMEOUT 2
#endif /* MAX_CNTL_TX_TIMEOUT */
#ifndef MAX_CNTL_RX_TIMEOUT
#define MAX_CNTL_RX_TIMEOUT 1
#endif /* MAX_CNTL_RX_TIMEOUT */

#define DHD_SCAN_ASSOC_ACTIVE_TIME	40 /* ms: Embedded default Active setting from DHD */
#define DHD_SCAN_UNASSOC_ACTIVE_TIME 80 /* ms: Embedded def. Unassoc Active setting from DHD */
#define DHD_SCAN_HOME_TIME		45 /* ms: Embedded default Home time setting from DHD */
#define DHD_SCAN_HOME_AWAY_TIME	100 /* ms: Embedded default Home Away time setting from DHD */
#ifndef CUSTOM_SCAN_PASSIVE_TIME
#define DHD_SCAN_PASSIVE_TIME		130 /* ms: Embedded default Passive setting from DHD */
#else
#define DHD_SCAN_PASSIVE_TIME	CUSTOM_SCAN_PASSIVE_TIME /* ms: Custom Passive setting from DHD */
#endif	/* CUSTOM_SCAN_PASSIVE_TIME */

#ifndef POWERUP_MAX_RETRY
#define POWERUP_MAX_RETRY	3 /* how many times we retry to power up the chip */
#endif // endif
#ifndef POWERUP_WAIT_MS
#define POWERUP_WAIT_MS		2000 /* ms: time out in waiting wifi to come up */
#endif // endif
/*
 * MAX_NVRAMBUF_SIZE determines the size of the Buffer in the DHD that holds
 * the NVRAM data. That is the size of the buffer pointed by bus->vars
 * This also needs to be increased to 16K to support NVRAM size higher than 8K
 */
#define MAX_NVRAMBUF_SIZE	(16 * 1024) /* max nvram buf size */
#define MAX_CLM_BUF_SIZE	(48 * 1024) /* max clm blob size */
#define MAX_TXCAP_BUF_SIZE	(16 * 1024) /* max txcap blob size */
#ifdef DHD_DEBUG
#define DHD_JOIN_MAX_TIME_DEFAULT 10000 /* ms: Max time out for joining AP */
#define DHD_SCAN_DEF_TIMEOUT 10000 /* ms: Max time out for scan in progress */
#endif /* DHD_DEBUG */

#ifndef CONFIG_BCMDHD_CLM_PATH
#define CONFIG_BCMDHD_CLM_PATH "/etc/wifi/bcmdhd_clm.blob"
#endif /* CONFIG_BCMDHD_CLM_PATH */
#define WL_CCODE_NULL_COUNTRY  "#n"

#define FW_VER_STR_LEN	128
#define FWID_STR_LEN 256
#define CLM_VER_STR_LEN 128
#define BUS_API_REV_STR_LEN	128
#define FW_VER_STR "Version"
#define FWID_STR_1 "FWID: 01-"
#define FWID_STR_2 "FWID=01-"
extern char bus_api_revision[];

enum dhd_bus_wake_state {
	WAKE_LOCK_OFF			= 0,
	WAKE_LOCK_PRIV			= 1,
	WAKE_LOCK_DPC			= 2,
	WAKE_LOCK_IOCTL			= 3,
	WAKE_LOCK_DOWNLOAD		= 4,
	WAKE_LOCK_TMOUT			= 5,
	WAKE_LOCK_WATCHDOG		= 6,
	WAKE_LOCK_LINK_DOWN_TMOUT	= 7,
	WAKE_LOCK_PNO_FIND_TMOUT	= 8,
	WAKE_LOCK_SOFTAP_SET		= 9,
	WAKE_LOCK_SOFTAP_STOP		= 10,
	WAKE_LOCK_SOFTAP_START		= 11,
	WAKE_LOCK_SOFTAP_THREAD		= 12
};

enum dhd_prealloc_index {
	DHD_PREALLOC_PROT			= 0,
	DHD_PREALLOC_RXBUF			= 1,
	DHD_PREALLOC_DATABUF			= 2,
	DHD_PREALLOC_OSL_BUF			= 3,
	DHD_PREALLOC_SKB_BUF = 4,
	DHD_PREALLOC_WIPHY_ESCAN0		= 5,
	DHD_PREALLOC_WIPHY_ESCAN1		= 6,
	DHD_PREALLOC_DHD_INFO			= 7,
	DHD_PREALLOC_DHD_WLFC_INFO		= 8,
	DHD_PREALLOC_IF_FLOW_LKUP		= 9,
	/* 10 */
	DHD_PREALLOC_MEMDUMP_RAM		= 11,
	DHD_PREALLOC_DHD_WLFC_HANGER		= 12,
	DHD_PREALLOC_PKTID_MAP			= 13,
	DHD_PREALLOC_PKTID_MAP_IOCTL		= 14,
	DHD_PREALLOC_DHD_LOG_DUMP_BUF		= 15,
	DHD_PREALLOC_DHD_LOG_DUMP_BUF_EX	= 16,
	DHD_PREALLOC_DHD_PKTLOG_DUMP_BUF	= 17,
	DHD_PREALLOC_STAT_REPORT_BUF = 18,
	DHD_PREALLOC_WL_ESCAN = 19,
	DHD_PREALLOC_FW_VERBOSE_RING = 20,
	DHD_PREALLOC_FW_EVENT_RING = 21,
	DHD_PREALLOC_DHD_EVENT_RING = 22,
	DHD_PREALLOC_NAN_EVENT_RING = 23
};

enum dhd_dongledump_mode {
	DUMP_DISABLED		= 0,
	DUMP_MEMONLY		= 1,
	DUMP_MEMFILE		= 2,
	DUMP_MEMFILE_BUGON	= 3,
	DUMP_MEMFILE_MAX	= 4
};

enum dhd_dongledump_type {
	DUMP_TYPE_RESUMED_ON_TIMEOUT		= 1,
	DUMP_TYPE_D3_ACK_TIMEOUT		= 2,
	DUMP_TYPE_DONGLE_TRAP			= 3,
	DUMP_TYPE_MEMORY_CORRUPTION		= 4,
	DUMP_TYPE_PKTID_AUDIT_FAILURE		= 5,
	DUMP_TYPE_PKTID_INVALID			= 6,
	DUMP_TYPE_SCAN_TIMEOUT			= 7,
	DUMP_TYPE_SCAN_BUSY			= 8,
	DUMP_TYPE_BY_SYSDUMP			= 9,
	DUMP_TYPE_BY_LIVELOCK			= 10,
	DUMP_TYPE_AP_LINKUP_FAILURE		= 11,
	DUMP_TYPE_AP_ABNORMAL_ACCESS		= 12,
	DUMP_TYPE_CFG_VENDOR_TRIGGERED		= 13,
	DUMP_TYPE_RESUMED_ON_TIMEOUT_TX		= 14,
	DUMP_TYPE_RESUMED_ON_TIMEOUT_RX		= 15,
	DUMP_TYPE_RESUMED_ON_INVALID_RING_RDWR	= 16,
	DUMP_TYPE_TRANS_ID_MISMATCH		= 17,
	DUMP_TYPE_IFACE_OP_FAILURE		= 18,
	DUMP_TYPE_DONGLE_INIT_FAILURE		= 19,
	DUMP_TYPE_READ_SHM_FAIL			= 20,
	DUMP_TYPE_DONGLE_HOST_EVENT		= 21,
	DUMP_TYPE_SMMU_FAULT			= 22,
	DUMP_TYPE_RESUMED_UNKNOWN		= 23,
	DUMP_TYPE_DUE_TO_BT			= 24,
	DUMP_TYPE_LOGSET_BEYOND_RANGE		= 25,
	DUMP_TYPE_BY_USER			= 26,
	DUMP_TYPE_CTO_RECOVERY			= 27,
	DUMP_TYPE_SEQUENTIAL_PRIVCMD_ERROR	= 28,
	DUMP_TYPE_PROXD_TIMEOUT			= 29,
	DUMP_TYPE_PKTID_POOL_DEPLETED		= 30
};

enum dhd_hang_reason {
	HANG_REASON_MASK				= 0x8000,
	HANG_REASON_IOCTL_RESP_TIMEOUT			= 0x8001,
	HANG_REASON_DONGLE_TRAP				= 0x8002,
	HANG_REASON_D3_ACK_TIMEOUT			= 0x8003,
	HANG_REASON_BUS_DOWN				= 0x8004,
	HANG_REASON_MSGBUF_LIVELOCK			= 0x8006,
	HANG_REASON_IFACE_DEL_FAILURE			= 0x8007,
	HANG_REASON_HT_AVAIL_ERROR			= 0x8008,
	HANG_REASON_PCIE_RC_LINK_UP_FAIL		= 0x8009,
	HANG_REASON_PCIE_PKTID_ERROR			= 0x800A,
	HANG_REASON_IFACE_ADD_FAILURE			= 0x800B,
	HANG_REASON_IOCTL_RESP_TIMEOUT_SCHED_ERROR	= 0x800C,
	HANG_REASON_D3_ACK_TIMEOUT_SCHED_ERROR		= 0x800D,
	HANG_REASON_SEQUENTIAL_PRIVCMD_ERROR		= 0x800E,
	HANG_REASON_SCAN_BUSY				= 0x800F,
	HANG_REASON_BSS_UP_FAILURE			= 0x8010,
	HANG_REASON_BSS_DOWN_FAILURE			= 0x8011,
	HANG_REASON_PCIE_LINK_DOWN_RC_DETECT		= 0x8805,
	HANG_REASON_INVALID_EVENT_OR_DATA		= 0x8806,
	HANG_REASON_UNKNOWN				= 0x8807,
	HANG_REASON_PCIE_LINK_DOWN_EP_DETECT		= 0x8808,
	HANG_REASON_PCIE_CTO_DETECT			= 0x8809,
	HANG_REASON_MAX					= 0x880A
};

#define WLC_E_DEAUTH_MAX_REASON 0x0FFF

enum dhd_rsdb_scan_features {
	/* Downgraded scan feature for AP active */
	RSDB_SCAN_DOWNGRADED_AP_SCAN = 0x01,
	/* Downgraded scan feature for P2P Discovery */
	RSDB_SCAN_DOWNGRADED_P2P_DISC_SCAN = 0x02,
	/* Enable channel pruning for ROAM SCAN */
	RSDB_SCAN_DOWNGRADED_CH_PRUNE_ROAM = 0x10,
	/* Enable channel pruning for any SCAN */
	RSDB_SCAN_DOWNGRADED_CH_PRUNE_ALL  = 0x20
};

#define VENDOR_SEND_HANG_EXT_INFO_LEN (800 + 1)

#ifdef DHD_EWPR_VER2
#define VENDOR_SEND_HANG_EXT_INFO_VER 20181111
#else
#define VENDOR_SEND_HANG_EXT_INFO_VER 20170905
#endif // endif

#define HANG_INFO_TRAP_T_NAME_MAX 6
#define HANG_INFO_TRAP_T_REASON_IDX 0
#define HANG_INFO_TRAP_T_SUBTYPE_IDX 2
#define HANG_INFO_TRAP_T_OFFSET_IDX 3
#define HANG_INFO_TRAP_T_EPC_IDX 4
#define HANG_FIELD_STR_MAX_LEN 9
#define HANG_FIELD_CNT_MAX 69
#define HANG_FIELD_IF_FAILURE_CNT 10
#define HANG_FIELD_IOCTL_RESP_TIMEOUT_CNT 8
#define HANG_FIELD_TRAP_T_STACK_CNT_MAX 16
#define HANG_FIELD_MISMATCH_CNT 10
#define HANG_INFO_BIGDATA_KEY_STACK_CNT 4

#define DEBUG_DUMP_TIME_BUF_LEN (16 + 1)
/* delimiter between values */
#define HANG_KEY_DEL	' '
#define HANG_RAW_DEL	'_'

#ifdef DHD_EWPR_VER2
#define HANG_INFO_BIGDATA_EXTRA_KEY 4
#define HANG_INFO_TRAP_T_EXTRA_KEY_IDX 5
#endif // endif

/* Packet alignment for most efficient SDIO (can change based on platform) */
#ifndef DHD_SDALIGN
#define DHD_SDALIGN	32
#endif // endif

#define DHD_TX_CONTEXT_MASK 0xff
#define DHD_TX_START_XMIT   0x01
#define DHD_TX_SEND_PKT     0x02
#define DHD_IF_SET_TX_ACTIVE(ifp, context)	\
    ifp->tx_paths_active |= context;
#define DHD_IF_CLR_TX_ACTIVE(ifp, context)	\
    ifp->tx_paths_active &= ~context;
#define DHD_IF_IS_TX_ACTIVE(ifp)	\
	(ifp->tx_paths_active)
/**
 * DMA-able buffer parameters
 * - dmaaddr_t is 32bits on a 32bit host.
 *   dhd_dma_buf::pa may not be used as a sh_addr_t, bcm_addr64_t or uintptr
 * - dhd_dma_buf::_alloced is ONLY for freeing a DMA-able buffer.
 */
typedef struct dhd_dma_buf {
	void      *va;      /* virtual address of buffer */
	uint32    len;      /* user requested buffer length */
	dmaaddr_t pa;       /* physical address of buffer */
	void      *dmah;    /* dma mapper handle */
	void      *secdma;  /* secure dma sec_cma_info handle */
	uint32    _alloced; /* actual size of buffer allocated with align and pad */
} dhd_dma_buf_t;

/* host reordering packts logic */
/* followed the structure to hold the reorder buffers (void **p) */
typedef struct reorder_info {
	void **p;
	uint8 flow_id;
	uint8 cur_idx;
	uint8 exp_idx;
	uint8 max_idx;
	uint8 pend_pkts;
} reorder_info_t;

/* throughput test packet format */
typedef struct tput_pkt {
	/* header */
	uint8 mac_sta[ETHER_ADDR_LEN];
	uint8 mac_ap[ETHER_ADDR_LEN];
	uint16 pkt_type;
	uint8 PAD[2];
	/* data */
	uint32 crc32;
	uint32 pkt_id;
	uint32 num_pkts;
} tput_pkt_t;

typedef enum {
	TPUT_PKT_TYPE_NORMAL,
	TPUT_PKT_TYPE_STOP
} tput_pkt_type_t;

#define TPUT_TEST_MAX_PAYLOAD 1500
#define TPUT_TEST_WAIT_TIMEOUT_DEFAULT 5000

#ifdef DHDTCPACK_SUPPRESS

enum {
	/* TCPACK suppress off */
	TCPACK_SUP_OFF,
	/* Replace TCPACK in txq when new coming one has higher ACK number. */
	TCPACK_SUP_REPLACE,
	/* TCPACK_SUP_REPLACE + delayed TCPACK TX unless ACK to PSH DATA.
	 * This will give benefits to Half-Duplex bus interface(e.g. SDIO) that
	 * 1. we are able to read TCP DATA packets first from the bus
	 * 2. TCPACKs that don't need to hurry delivered remains longer in TXQ so can be suppressed.
	 */
	TCPACK_SUP_DELAYTX,
	TCPACK_SUP_HOLD,
	TCPACK_SUP_LAST_MODE
};
#endif /* DHDTCPACK_SUPPRESS */

#define DHD_NULL_CHK_AND_RET(cond) \
	if (!cond) { \
		DHD_ERROR(("%s " #cond " is NULL\n", __FUNCTION__)); \
		return; \
	}

#define DHD_NULL_CHK_AND_RET_VAL(cond, value) \
	if (!cond) { \
		DHD_ERROR(("%s " #cond " is NULL\n", __FUNCTION__)); \
		return value; \
	}

#define DHD_NULL_CHK_AND_GOTO(cond, label) \
	if (!cond) { \
		DHD_ERROR(("%s " #cond " is NULL\n", __FUNCTION__)); \
		goto label; \
	}

/*
 * Accumulating the queue lengths of all flowring queues in a parent object,
 * to assert flow control, when the cummulative queue length crosses an upper
 * threshold defined on a parent object. Upper threshold may be maintained
 * at a station level, at an interface level, or at a dhd instance.
 *
 * cumm_ctr_t abstraction:
 * cumm_ctr_t abstraction may be enhanced to use an object with a hysterisis
 * pause on/off threshold callback.
 * All macros use the address of the cummulative length in the parent objects.
 *
 * BCM_GMAC3 builds use a single perimeter lock, as opposed to a per queue lock.
 * Cummulative counters in parent objects may be updated without spinlocks.
 *
 * In non BCM_GMAC3, if a cummulative queue length is desired across all flows
 * belonging to either of (a station, or an interface or a dhd instance), then
 * an atomic operation is required using an atomic_t cummulative counters or
 * using a spinlock. BCM_ROUTER_DHD uses the Linux atomic_t construct.
 */

/* Cummulative length not supported. */
typedef uint32 cumm_ctr_t;
#define DHD_CUMM_CTR_PTR(clen)     ((cumm_ctr_t*)(clen))
#define DHD_CUMM_CTR(clen)         *(DHD_CUMM_CTR_PTR(clen)) /* accessor */
#define DHD_CUMM_CTR_READ(clen)    DHD_CUMM_CTR(clen) /* read access */
#define DHD_CUMM_CTR_INIT(clen)                                                \
	ASSERT(DHD_CUMM_CTR_PTR(clen) != DHD_CUMM_CTR_PTR(NULL));
#define DHD_CUMM_CTR_INCR(clen)                                                \
	ASSERT(DHD_CUMM_CTR_PTR(clen) != DHD_CUMM_CTR_PTR(NULL));
#define DHD_CUMM_CTR_DECR(clen)                                                \
	ASSERT(DHD_CUMM_CTR_PTR(clen) != DHD_CUMM_CTR_PTR(NULL));

#if defined(WLTDLS) && defined(PCIE_FULL_DONGLE)
struct tdls_peer_node {
	uint8 addr[ETHER_ADDR_LEN];
	struct tdls_peer_node *next;
};
typedef struct tdls_peer_node tdls_peer_node_t;
typedef struct {
	tdls_peer_node_t *node;
	uint8 tdls_peer_count;
} tdls_peer_tbl_t;
#endif /* defined(WLTDLS) && defined(PCIE_FULL_DONGLE) */

#ifdef DHD_LOG_DUMP
#define DUMP_SSSR_ATTR_START	2
#define DUMP_SSSR_ATTR_COUNT	6

typedef enum {
	SSSR_C0_D11_BEFORE = 0,
	SSSR_C0_D11_AFTER = 1,
	SSSR_C1_D11_BEFORE = 2,
	SSSR_C1_D11_AFTER = 3,
	SSSR_DIG_BEFORE = 4,
	SSSR_DIG_AFTER = 5
} EWP_SSSR_DUMP;

typedef enum {
	DLD_BUF_TYPE_GENERAL = 0,
	DLD_BUF_TYPE_PRESERVE = 1,
	DLD_BUF_TYPE_SPECIAL = 2,
	DLD_BUF_TYPE_ECNTRS = 3,
	DLD_BUF_TYPE_FILTER = 4,
	DLD_BUF_TYPE_ALL = 5
} log_dump_type_t;

#define LOG_DUMP_MAGIC 0xDEB3DEB3
#define HEALTH_CHK_BUF_SIZE 256

#ifdef EWP_ECNTRS_LOGGING
#define ECNTR_RING_ID 0xECDB
#define	ECNTR_RING_NAME	"ewp_ecntr_ring"
#endif /* EWP_ECNTRS_LOGGING */

#ifdef EWP_RTT_LOGGING
#define	RTT_RING_ID 0xADCD
#define	RTT_RING_NAME	"ewp_rtt_ring"
#endif /* EWP_ECNTRS_LOGGING */

#if defined(DEBUGABILITY) && defined(EWP_ECNTRS_LOGGING)
#error "Duplicate rings will be created since both the features are enabled"
#endif /* DEBUGABILITY && EWP_ECNTRS_LOGGING */

typedef enum {
	LOG_DUMP_SECTION_GENERAL = 0,
	LOG_DUMP_SECTION_ECNTRS,
	LOG_DUMP_SECTION_SPECIAL,
	LOG_DUMP_SECTION_DHD_DUMP,
	LOG_DUMP_SECTION_EXT_TRAP,
	LOG_DUMP_SECTION_HEALTH_CHK,
	LOG_DUMP_SECTION_PRESERVE,
	LOG_DUMP_SECTION_COOKIE,
	LOG_DUMP_SECTION_FLOWRING,
	LOG_DUMP_SECTION_STATUS,
	LOG_DUMP_SECTION_RTT
} log_dump_section_type_t;

/* Each section in the debug_dump log file shall begin with a header */
typedef struct {
	uint32 magic;  /* 0xDEB3DEB3 */
	uint32 type;   /* of type log_dump_section_type_t */
	uint64 timestamp;
	uint32 length;  /* length of the section that follows */
	uint32 pad;
} log_dump_section_hdr_t;

/* below structure describe ring buffer. */
struct dhd_log_dump_buf
{
	spinlock_t lock;
	void *dhd_pub;
	unsigned int enable;
	unsigned int wraparound;
	unsigned long max;
	unsigned int remain;
	char* present;
	char* front;
	char* buffer;
};

#define DHD_LOG_DUMP_MAX_TEMP_BUFFER_SIZE	256
#define DHD_LOG_DUMP_MAX_TAIL_FLUSH_SIZE (80 * 1024)

extern void dhd_log_dump_write(int type, char *binary_data,
		int binary_len, const char *fmt, ...);
#endif /* DHD_LOG_DUMP */

/* DEBUG_DUMP SUB COMMAND */
enum {
	CMD_DEFAULT,
	CMD_UNWANTED,
	CMD_DISCONNECTED,
	CMD_MAX
};

#define DHD_LOG_DUMP_TS_MULTIPLIER_VALUE    60
#define DHD_LOG_DUMP_TS_FMT_YYMMDDHHMMSSMSMS    "%02d%02d%02d%02d%02d%02d%04d"
#define DHD_DEBUG_DUMP_TYPE		"debug_dump_FORUSER"
#define DHD_DUMP_SUBSTR_UNWANTED	"_unwanted"
#define DHD_DUMP_SUBSTR_DISCONNECTED	"_disconnected"

#ifdef DNGL_AXI_ERROR_LOGGING
#define DHD_DUMP_AXI_ERROR_FILENAME	"axi_error"
#define DHD_DUMP_HAL_FILENAME_SUFFIX	"_hal"
#endif /* DNGL_AXI_ERROR_LOGGING */

extern void get_debug_dump_time(char *str);
extern void clear_debug_dump_time(char *str);

#define FW_LOGSET_MASK_ALL 0xFFFFu

#ifdef WL_MONITOR
#define MONPKT_EXTRA_LEN	48u
#endif /* WL_MONITOR */

#define DHDIF_FWDER(dhdif)      FALSE

#define DHD_COMMON_DUMP_PATH	"/data/misc/wifi/"

struct cntry_locales_custom {
	char iso_abbrev[WLC_CNTRY_BUF_SZ];      /* ISO 3166-1 country abbreviation */
	char custom_locale[WLC_CNTRY_BUF_SZ];   /* Custom firmware locale */
	int32 custom_locale_rev;                /* Custom local revisin default -1 */
};

int dhd_send_msg_to_daemon(struct sk_buff *skb, void *data, int size);

#ifdef DMAMAP_STATS
typedef struct dmamap_stats {
	uint64 txdata;
	uint64 txdata_sz;
	uint64 rxdata;
	uint64 rxdata_sz;
	uint64 ioctl_rx;
	uint64 ioctl_rx_sz;
	uint64 event_rx;
	uint64 event_rx_sz;
	uint64 info_rx;
	uint64 info_rx_sz;
	uint64 tsbuf_rx;
	uint64 tsbuf_rx_sz;
} dma_stats_t;
#endif /* DMAMAP_STATS */

/*  see wlfc_proto.h for tx status details */
#define DHD_MAX_TX_STATUS_MSGS     9u

#ifdef TX_STATUS_LATENCY_STATS
typedef struct dhd_if_tx_status_latency {
	/* total number of tx_status received on this interface */
	uint64 num_tx_status;
	/* cumulative tx_status latency for this interface */
	uint64 cum_tx_status_latency;
} dhd_if_tx_status_latency_t;
#endif /* TX_STATUS_LATENCY_STATS */

#if defined(SHOW_LOGTRACE) && defined(DHD_USE_KTHREAD_FOR_LOGTRACE)
/* Timestamps to trace dhd_logtrace_thread() */
struct dhd_logtrace_thr_ts {
	uint64 entry_time;
	uint64 sem_down_time;
	uint64 flush_time;
	uint64 unexpected_break_time;
	uint64 complete_time;
};
#endif /* SHOW_LOGTRACE && DHD_USE_KTHREAD_FOR_LOGTRACE */

/* Enable Reserve STA flowrings only for Android */
#define DHD_LIMIT_MULTI_CLIENT_FLOWRINGS

typedef enum dhd_induce_error_states
{
	DHD_INDUCE_ERROR_CLEAR		= 0x0,
	DHD_INDUCE_IOCTL_TIMEOUT	= 0x1,
	DHD_INDUCE_D3_ACK_TIMEOUT	= 0x2,
	DHD_INDUCE_LIVELOCK		= 0x3,
	DHD_INDUCE_DROP_OOB_IRQ		= 0x4,
	DHD_INDUCE_DROP_AXI_SIG		= 0x5,
	DHD_INDUCE_ERROR_MAX		= 0x6
} dhd_induce_error_states_t;

#ifdef DHD_HP2P
#define MAX_TX_HIST_BIN		16
#define MAX_RX_HIST_BIN		10
#define MAX_HP2P_FLOWS		16
#define HP2P_PRIO		7
#define HP2P_PKT_THRESH		48
#define HP2P_TIME_THRESH	200
#define HP2P_PKT_EXPIRY		40
#define	HP2P_TIME_SCALE		32

typedef struct hp2p_info {
	void	*dhd_pub;
	uint16	flowid;
	bool	hrtimer_init;
	void	*ring;
	struct	tasklet_hrtimer timer;
	uint64	num_pkt_limit;
	uint64	num_timer_limit;
	uint64	num_timer_start;
	uint64	tx_t0[MAX_TX_HIST_BIN];
	uint64	tx_t1[MAX_TX_HIST_BIN];
	uint64	rx_t0[MAX_RX_HIST_BIN];
} hp2p_info_t;
#endif /* DHD_HP2P */

typedef enum {
	FW_UNLOADED = 0,
	FW_DOWNLOAD_IN_PROGRESS = 1,
	FW_DOWNLOAD_DONE = 2
} fw_download_status_t;

/**
 * Common structure for module and instance linkage.
 * Instantiated once per hardware (dongle) instance that this DHD manages.
 */
typedef struct dhd_pub {
	/* Linkage ponters */
	osl_t *osh;		/* OSL handle */
	struct dhd_bus *bus;	/* Bus module handle */
	struct dhd_prot *prot;	/* Protocol module handle */
	struct dhd_info  *info; /* Info module handle */
	struct dhd_dbg *dbg;	/* Debugability module handle */
#if defined(SHOW_LOGTRACE) && defined(DHD_USE_KTHREAD_FOR_LOGTRACE)
	struct dhd_logtrace_thr_ts logtrace_thr_ts;
#endif /* SHOW_LOGTRACE && DHD_USE_KTHREAD_FOR_LOGTRACE */

	/* to NDIS developer, the structure dhd_common is redundant,
	 * please do NOT merge it back from other branches !!!
	 */

#ifdef BCMDBUS
	struct dbus_pub *dbus;
#endif /* BCMDBUS */

	/* Internal dhd items */
	bool up;		/* Driver up/down (to OS) */
#ifdef WL_CFG80211
	spinlock_t up_lock;	/* Synchronization with CFG80211 down */
#endif /* WL_CFG80211 */
	bool txoff;		/* Transmit flow-controlled */
	bool dongle_reset;  /* TRUE = DEVRESET put dongle into reset */
	enum dhd_bus_state busstate;
	uint dhd_bus_busy_state;	/* Bus busy state */
	uint hdrlen;		/* Total DHD header length (proto + bus) */
	uint maxctl;		/* Max size rxctl request from proto to bus */
	uint rxsz;		/* Rx buffer size bus module should use */
	uint8 wme_dp;	/* wme discard priority */
#ifdef DNGL_AXI_ERROR_LOGGING
	uint32 axierror_logbuf_addr;
	bool axi_error;
	struct dhd_axi_error_dump *axi_err_dump;
#endif /* DNGL_AXI_ERROR_LOGGING */
	/* Dongle media info */
	bool iswl;		/* Dongle-resident driver is wl */
	ulong drv_version;	/* Version of dongle-resident driver */
	struct ether_addr mac;	/* MAC address obtained from dongle */
	dngl_stats_t dstats;	/* Stats for dongle-based data */

	/* Additional stats for the bus level */
	ulong tx_packets;	/* Data packets sent to dongle */
	ulong tx_dropped;	/* Data packets dropped in dhd */
	ulong tx_multicast;	/* Multicast data packets sent to dongle */
	ulong tx_errors;	/* Errors in sending data to dongle */
	ulong tx_ctlpkts;	/* Control packets sent to dongle */
	ulong tx_ctlerrs;	/* Errors sending control frames to dongle */
	ulong rx_packets;	/* Packets sent up the network interface */
	ulong rx_multicast;	/* Multicast packets sent up the network interface */
	ulong rx_errors;	/* Errors processing rx data packets */
	ulong rx_ctlpkts;	/* Control frames processed from dongle */
	ulong rx_ctlerrs;	/* Errors in processing rx control frames */
	ulong rx_dropped;	/* Packets dropped locally (no memory) */
	ulong rx_flushed;  /* Packets flushed due to unscheduled sendup thread */
	ulong wd_dpc_sched;   /* Number of times dhd dpc scheduled by watchdog timer */
	ulong rx_pktgetfail; /* Number of PKTGET failures in DHD on RX */
	ulong tx_pktgetfail; /* Number of PKTGET failures in DHD on TX */
	ulong rx_readahead_cnt;	/* Number of packets where header read-ahead was used. */
	ulong tx_realloc;	/* Number of tx packets we had to realloc for headroom */
	ulong fc_packets;       /* Number of flow control pkts recvd */
	ulong tx_big_packets;	/* Dropped data packets that are larger than MAX_MTU_SZ */
#ifdef DMAMAP_STATS
	/* DMA Mapping statistics */
	dma_stats_t dma_stats;
#endif /* DMAMAP_STATS */

	/* Last error return */
	int bcmerror;
	uint tickcnt;

	/* Last error from dongle */
	int dongle_error;

	uint8 country_code[WLC_CNTRY_BUF_SZ];

	/* Suspend disable flag and "in suspend" flag */
	int suspend_disable_flag; /* "1" to disable all extra powersaving during suspend */
	int in_suspend;			/* flag set to 1 when early suspend called */
#ifdef PNO_SUPPORT
	int pno_enable;			/* pno status : "1" is pno enable */
	int pno_suspend;		/* pno suspend status : "1" is pno suspended */
#endif /* PNO_SUPPORT */
	/* DTIM skip value, default 0(or 1) means wake each DTIM
	 * 3 means skip 2 DTIMs and wake up 3rd DTIM(9th beacon when AP DTIM is 3)
	 */
	int suspend_bcn_li_dtim;         /* bcn_li_dtim value in suspend mode */
	int early_suspended;	/* Early suspend status */
#ifdef PKT_FILTER_SUPPORT
	int dhcp_in_progress;	/* DHCP period */
#endif // endif

	/* Pkt filter defination */
	char * pktfilter[100];
	int pktfilter_count;

	wl_country_t dhd_cspec;		/* Current Locale info */
#ifdef CUSTOM_COUNTRY_CODE
	uint dhd_cflags;
#endif /* CUSTOM_COUNTRY_CODE */
#if defined(DHD_BLOB_EXISTENCE_CHECK)
	bool is_blob;			/* Checking for existance of Blob file */
#endif /* DHD_BLOB_EXISTENCE_CHECK */
	bool force_country_change;
	char eventmask[WL_EVENTING_MASK_LEN];
	int	op_mode;				/* STA, HostAPD, WFD, SoftAP */

/* Set this to 1 to use a seperate interface (p2p0) for p2p operations.
 *  For ICS MR1 releases it should be disable to be compatable with ICS MR1 Framework
 *  see target dhd-cdc-sdmmc-panda-cfg80211-icsmr1-gpl-debug in Makefile
 */
/* #define WL_ENABLE_P2P_IF		1 */

	struct mutex wl_start_stop_lock; /* lock/unlock for Android start/stop */
	struct mutex wl_softap_lock;		 /* lock/unlock for any SoftAP/STA settings */

#ifdef PROP_TXSTATUS
	bool	wlfc_enabled;
	int	wlfc_mode;
	void*	wlfc_state;
	/*
	Mode in which the dhd flow control shall operate. Must be set before
	traffic starts to the device.
	0 - Do not do any proptxtstatus flow control
	1 - Use implied credit from a packet status
	2 - Use explicit credit
	3 - Only AMPDU hostreorder used. no wlfc.
	*/
	uint8	proptxstatus_mode;
	bool	proptxstatus_txoff;
	bool	proptxstatus_module_ignore;
	bool	proptxstatus_credit_ignore;
	bool	proptxstatus_txstatus_ignore;

	bool	wlfc_rxpkt_chk;
#ifdef LIMIT_BORROW
	bool wlfc_borrow_allowed;
#endif /* LIMIT_BORROW */
	/*
	 * implement below functions in each platform if needed.
	 */
	/* platform specific function whether to skip flow control */
	bool (*skip_fc)(void * dhdp, uint8 ifx);
	/* platform specific function for wlfc_enable and wlfc_deinit */
	void (*plat_init)(void *dhd);
	void (*plat_deinit)(void *dhd);
#ifdef DHD_WLFC_THREAD
	bool                wlfc_thread_go;
	struct task_struct* wlfc_thread;
	wait_queue_head_t   wlfc_wqhead;
#endif /* DHD_WLFC_THREAD */
#endif /* PROP_TXSTATUS */
#ifdef PNO_SUPPORT
	void *pno_state;
#endif // endif
#ifdef RTT_SUPPORT
	void *rtt_state;
	bool rtt_supported;
#endif // endif
#ifdef ROAM_AP_ENV_DETECTION
	bool	roam_env_detection;
#endif // endif
	bool	dongle_isolation;
	bool	is_pcie_watchdog_reset;

/* Begin - Variables to track Bus Errors */
	bool	dongle_trap_occured;	/* flag for sending HANG event to upper layer */
	bool	iovar_timeout_occured;	/* flag to indicate iovar resumed on timeout */
	bool	is_sched_error;		/* flag to indicate timeout due to scheduling issue */
#ifdef PCIE_FULL_DONGLE
	bool	d3ack_timeout_occured;	/* flag to indicate d3ack resumed on timeout */
	bool	livelock_occured;	/* flag to indicate livelock occured */
	bool	pktid_audit_failed;	/* flag to indicate pktid audit failure */
#endif /* PCIE_FULL_DONGLE */
	bool	iface_op_failed;	/* flag to indicate interface operation failed */
	bool	scan_timeout_occurred;	/* flag to indicate scan has timedout */
	bool	scan_busy_occurred;	/* flag to indicate scan busy occurred */
#ifdef BT_OVER_SDIO
	bool	is_bt_recovery_required;
#endif // endif
	bool	smmu_fault_occurred;	/* flag to indicate SMMU Fault */
	/*
	 * Add any new variables to track Bus errors above
	 * this line. Also ensure that the variable is
	 * cleared from dhd_clear_bus_errors
	 */
/* End - Variables to track Bus Errors */

	int   hang_was_sent;
	int   hang_was_pending;
	int   rxcnt_timeout;		/* counter rxcnt timeout to send HANG */
	int   txcnt_timeout;		/* counter txcnt timeout to send HANG */
#ifdef BCMPCIE
	int   d3ackcnt_timeout;		/* counter d3ack timeout to send HANG */
#endif /* BCMPCIE */
	bool hang_report;		/* enable hang report by default */
	uint16 hang_reason;		/* reason codes for HANG event */
#if defined(CONFIG_BCM_DETECT_CONSECUTIVE_HANG)
	uint hang_counts;
#endif /* CONFIG_BCM_DETECT_CONSECUTIVE_HANG */
#ifdef WLTDLS
	bool tdls_enable;
#endif // endif
	struct reorder_info *reorder_bufs[WLHOST_REORDERDATA_MAXFLOWS];
	#define WLC_IOCTL_MAXBUF_FWCAP	1024
	char  fw_capabilities[WLC_IOCTL_MAXBUF_FWCAP];
	#define MAXSKBPEND 1024
	void *skbbuf[MAXSKBPEND];
	uint32 store_idx;
	uint32 sent_idx;
#ifdef DHDTCPACK_SUPPRESS
	uint8 tcpack_sup_mode;		/* TCPACK suppress mode */
	void *tcpack_sup_module;	/* TCPACK suppress module */
	uint32 tcpack_sup_ratio;
	uint32 tcpack_sup_delay;
#endif /* DHDTCPACK_SUPPRESS */
#if defined(ARP_OFFLOAD_SUPPORT)
	uint32 arp_version;
	bool hmac_updated;
#endif // endif
#if defined(BCMSUP_4WAY_HANDSHAKE)
	bool fw_4way_handshake;		/* Whether firmware will to do the 4way handshake. */
#endif // endif
#ifdef DEBUG_DPC_THREAD_WATCHDOG
	bool dhd_bug_on;
#endif /* DEBUG_DPC_THREAD_WATCHDOG */
#ifdef CUSTOM_SET_CPUCORE
	struct task_struct * current_dpc;
	struct task_struct * current_rxf;
	int chan_isvht80;
#endif /* CUSTOM_SET_CPUCORE */

	void    *sta_pool;          /* pre-allocated pool of sta objects */
	void    *staid_allocator;   /* allocator of sta indexes */
#ifdef PCIE_FULL_DONGLE
	bool	flow_rings_inited;	/* set this flag after initializing flow rings */
#endif /* PCIE_FULL_DONGLE */
	void    *flowid_allocator;  /* unique flowid allocator */
	void	*flow_ring_table;   /* flow ring table, include prot and bus info */
	void	*if_flow_lkup;      /* per interface flowid lkup hash table */
	void    *flowid_lock;       /* per os lock for flowid info protection */
	void    *flowring_list_lock;       /* per os lock for flowring list protection */
	uint8	max_multi_client_flow_rings;
	uint8	multi_client_flow_rings;
	uint32  num_flow_rings;
	cumm_ctr_t cumm_ctr;        /* cumm queue length placeholder  */
	cumm_ctr_t l2cumm_ctr;      /* level 2 cumm queue length placeholder */
	uint32 d2h_sync_mode;       /* D2H DMA completion sync mode */
	uint8  flow_prio_map[NUMPRIO];
	uint8	flow_prio_map_type;
	char enable_log[MAX_EVENT];
	bool dma_d2h_ring_upd_support;
	bool dma_h2d_ring_upd_support;
	bool dma_ring_upd_overwrite;	/* host overwrites support setting */

	bool hwa_enable;
	uint hwa_inited;

	bool idma_enable;
	uint idma_inited;

	bool ifrm_enable;			/* implicit frm enable */
	uint ifrm_inited;			/* implicit frm init */

	bool dar_enable;		/* use DAR registers */
	uint dar_inited;

	bool fast_delete_ring_support;		/* fast delete ring supported */

#ifdef DHD_L2_FILTER
	unsigned long l2_filter_cnt;	/* for L2_FILTER ARP table timeout */
#endif /* DHD_L2_FILTER */
#ifdef DHD_SSSR_DUMP
	bool sssr_inited;
	bool sssr_dump_collected;	/* Flag to indicate sssr dump is collected */
	sssr_reg_info_v1_t sssr_reg_info;
	uint8 *sssr_mempool;
	uint *sssr_d11_before[MAX_NUM_D11CORES];
	uint *sssr_d11_after[MAX_NUM_D11CORES];
	bool sssr_d11_outofreset[MAX_NUM_D11CORES];
	uint *sssr_dig_buf_before;
	uint *sssr_dig_buf_after;
	uint32 sssr_dump_mode;
	bool collect_sssr;		/* Flag to indicate SSSR dump is required */
#endif /* DHD_SSSR_DUMP */
	uint8 *soc_ram;
	uint32 soc_ram_length;
	uint32 memdump_type;
#ifdef DHD_FW_COREDUMP
	uint32 memdump_enabled;
#ifdef DHD_DEBUG_UART
	bool memdump_success;
#endif	/* DHD_DEBUG_UART */
#endif /* DHD_FW_COREDUMP */
#ifdef PCIE_FULL_DONGLE
#ifdef WLTDLS
	tdls_peer_tbl_t peer_tbl;
#endif /* WLTDLS */
	uint8 tx_in_progress;
#endif /* PCIE_FULL_DONGLE */
#ifdef DHD_ULP
	void *dhd_ulp;
#endif // endif
#ifdef WLTDLS
	uint32 tdls_mode;
#endif // endif
#ifdef GSCAN_SUPPORT
	bool lazy_roam_enable;
#endif // endif
#if defined(PKT_FILTER_SUPPORT) && defined(APF)
	bool apf_set;
#endif /* PKT_FILTER_SUPPORT && APF */
	void *macdbg_info;
#ifdef DHD_WET
	void *wet_info;
#endif // endif
	bool	h2d_phase_supported;
	bool	force_dongletrap_on_bad_h2d_phase;
	uint32	dongle_trap_data;
	fw_download_status_t	fw_download_status;
	trap_t	last_trap_info; /* trap info from the last trap */
	uint8 rand_mac_oui[DOT11_OUI_LEN];
#ifdef DHD_LOSSLESS_ROAMING
	uint8 dequeue_prec_map;
	uint8 prio_8021x;
#endif // endif
#ifdef WL_NATOE
	struct dhd_nfct_info *nfct;
	spinlock_t nfct_lock;
#endif /* WL_NATOE */
	/* timesync link */
	struct dhd_ts *ts;
	bool	d2h_hostrdy_supported;
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
	atomic_t block_bus;
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */
#if defined(DBG_PKT_MON)
	bool d11_tx_status;
#endif // endif
	uint16 ndo_version;	/* ND offload version supported */
#ifdef NDO_CONFIG_SUPPORT
	bool ndo_enable;		/* ND offload feature enable */
	bool ndo_host_ip_overflow;	/* # of host ip addr exceed FW capacity */
	uint32 ndo_max_host_ip;		/* # of host ip addr supported by FW */
#endif /* NDO_CONFIG_SUPPORT */
#if defined(DHD_LOG_DUMP)
	/* buffer to hold 'dhd dump' data before dumping to file */
	uint8 *concise_dbg_buf;
	uint64 last_file_posn;
	int logdump_periodic_flush;
	/* ecounter debug ring */
#ifdef EWP_ECNTRS_LOGGING
	void *ecntr_dbg_ring;
#endif // endif
#ifdef EWP_RTT_LOGGING
	void *rtt_dbg_ring;
#endif // endif
#ifdef DNGL_EVENT_SUPPORT
	uint8 health_chk_event_data[HEALTH_CHK_BUF_SIZE];
#endif // endif
	void *logdump_cookie;
#endif /* DHD_LOG_DUMP */
	uint32 dhd_console_ms; /** interval for polling the dongle for console (log) messages */
	bool ext_trap_data_supported;
	uint32 *extended_trap_data;
#ifdef DUMP_IOCTL_IOV_LIST
	/* dump iovar list */
	dll_t dump_iovlist_head;
	uint8 dump_iovlist_len;
#endif /* DUMP_IOCTL_IOV_LIST */
#ifdef CUSTOM_SET_ANTNPM
	uint32 mimo_ant_set;
#endif /* CUSTOM_SET_ANTNPM */
#ifdef DHD_DEBUG
	/* memwaste feature */
	dll_t mw_list_head; /* memwaste list head */
	uint32 mw_id; /* memwaste list unique id */
#endif /* DHD_DEBUG */
#ifdef WLTDLS
	spinlock_t tdls_lock;
#endif /* WLTDLS */
	uint pcie_txs_metadata_enable;
	uint wbtext_policy;	/* wbtext policy of dongle */
	bool wbtext_support;	/* for product policy only */
	bool max_dtim_enable;	/* use MAX bcn_li_dtim value in suspend mode */
	tput_test_t tput_data;
	uint64 tput_start_ts;
	uint64 tput_stop_ts;
#ifdef WL_MONITOR
	bool monitor_enable;
#endif // endif
	uint dhd_watchdog_ms_backup;
	void *event_log_filter;
	char debug_dump_time_str[DEBUG_DUMP_TIME_BUF_LEN];
	uint32 logset_prsrv_mask;
	bool wl_event_enabled;
	bool logtrace_pkt_sendup;
#ifdef DHD_DUMP_MNGR
	struct _dhd_dump_file_manage *dump_file_manage;
#endif /* DHD_DUMP_MNGR */
	int debug_dump_subcmd;
	uint64 debug_dump_time_sec;
	bool hscb_enable;
	wait_queue_head_t tx_completion_wait;
	uint32 batch_tx_pkts_cmpl;
	uint32 batch_tx_num_pkts;
#ifdef DHD_ERPOM
	bool enable_erpom;
	pom_func_handler_t pom_wlan_handler;
	int (*pom_func_register)(pom_func_handler_t *func);
	int (*pom_func_deregister)(pom_func_handler_t *func);
	int (*pom_toggle_reg_on)(uchar func_id, uchar reason);
#endif /* DHD_ERPOM */
#ifdef EWP_EDL
	bool dongle_edl_support;
	dhd_dma_buf_t edl_ring_mem;
#endif /* EWP_EDL */
	struct mutex ndev_op_sync;

	bool debug_buf_dest_support;
	uint32 debug_buf_dest_stat[DEBUG_BUF_DEST_MAX];
#if defined(DHD_H2D_LOG_TIME_SYNC)
#define DHD_H2D_LOG_TIME_STAMP_MATCH	(10000) /* 10 Seconds */
	/*
	 * Interval for updating the dongle console message time stamp with the Host (DHD)
	 * time stamp
	 */
	uint32 dhd_rte_time_sync_ms;
#endif /* DHD_H2D_LOG_TIME_SYNC */
	int wlc_ver_major;
	int wlc_ver_minor;
#ifdef DHD_STATUS_LOGGING
	void *statlog;
#endif /* DHD_STATUS_LOGGING */
#ifdef DHD_HP2P
	bool hp2p_enable;
	bool hp2p_infra_enable;
	bool hp2p_capable;
	bool hp2p_ts_capable;
	uint16 pkt_thresh;
	uint16 time_thresh;
	uint16 pkt_expiry;
	hp2p_info_t hp2p_info[MAX_HP2P_FLOWS];
	bool hp2p_ring_active;
#endif /* D2H_HP2P */
#ifdef DHD_DB0TS
	bool db0ts_capable;
#endif /* DHD_DB0TS */
	bool event_log_max_sets_queried;
	uint32 event_log_max_sets;
	uint16 dhd_induce_error;
#ifdef CONFIG_SILENT_ROAM
	bool sroam_turn_on;	/* Silent roam monitor enable flags */
	bool sroamed;		/* Silent roam monitor check flags */
#endif /* CONFIG_SILENT_ROAM */
	bool extdtxs_in_txcpl;
	bool hostrdy_after_init;
#ifdef SUPPORT_SET_TID
	uint8 tid_mode;
	uint32 target_uid;
	uint8 target_tid;
#endif /* SUPPORT_SET_TID */
#ifdef DHD_PKTDUMP_ROAM
	void *pktcnts;
#endif /* DHD_PKTDUMP_ROAM */
	bool disable_dtim_in_suspend;	/* Disable set bcn_li_dtim in suspend */
#ifdef CSI_SUPPORT
	struct list_head csi_list;
	int csi_count;
#endif /* CSI_SUPPORT */
	char *clm_path;		/* module_param: path to clm vars file */
	char *conf_path;		/* module_param: path to config vars file */
	struct dhd_conf *conf;	/* Bus module handle */
	void *adapter;			/* adapter information, interrupt, fw path etc. */
	void *event_params;
#ifdef BCMDBUS
	bool dhd_remove;
#endif /* BCMDBUS */
#ifdef WL_ESCAN
	struct wl_escan_info *escan;
#endif
#if defined(WL_WIRELESS_EXT)
	void *wext_info;
#endif
#ifdef WL_EXT_IAPSTA
	void *iapsta_params;
#endif
	int hostsleep;
#ifdef SENDPROB
	bool recv_probereq;
#endif
#ifdef DHD_NOTIFY_MAC_CHANGED
	bool skip_dhd_stop;
#endif /* DHD_NOTIFY_MAC_CHANGED */
#ifdef WL_EXT_GENL
	void *zconf;
#endif
} dhd_pub_t;

typedef struct {
	uint rxwake;
	uint rcwake;
#ifdef DHD_WAKE_RX_STATUS
	uint rx_bcast;
	uint rx_arp;
	uint rx_mcast;
	uint rx_multi_ipv6;
	uint rx_icmpv6;
	uint rx_icmpv6_ra;
	uint rx_icmpv6_na;
	uint rx_icmpv6_ns;
	uint rx_multi_ipv4;
	uint rx_multi_other;
	uint rx_ucast;
#endif /* DHD_WAKE_RX_STATUS */
#ifdef DHD_WAKE_EVENT_STATUS
	uint rc_event[WLC_E_LAST];
#endif /* DHD_WAKE_EVENT_STATUS */
} wake_counts_t;

#if defined(PCIE_FULL_DONGLE)

/* Packet Tag for PCIE Full Dongle DHD */
typedef struct dhd_pkttag_fd {
	uint16    flowid;   /* Flowring Id */
	uint16    ifid;
#ifndef DHD_PCIE_PKTID
	uint16    dma_len;  /* pkt len for DMA_MAP/UNMAP */
	dmaaddr_t pa;       /* physical address */
	void      *dmah;    /* dma mapper handle */
	void      *secdma; /* secure dma sec_cma_info handle */
#endif /* !DHD_PCIE_PKTID */
#if defined(TX_STATUS_LATENCY_STATS)
	uint64	   q_time_us; /* time when tx pkt queued to flowring */
#endif // endif
} dhd_pkttag_fd_t;

/* Packet Tag for DHD PCIE Full Dongle */
#define DHD_PKTTAG_FD(pkt)          ((dhd_pkttag_fd_t *)(PKTTAG(pkt)))

#define DHD_PKT_GET_FLOWID(pkt)     ((DHD_PKTTAG_FD(pkt))->flowid)
#define DHD_PKT_SET_FLOWID(pkt, pkt_flowid) \
	DHD_PKTTAG_FD(pkt)->flowid = (uint16)(pkt_flowid)

#define DHD_PKT_GET_DATAOFF(pkt)    ((DHD_PKTTAG_FD(pkt))->dataoff)
#define DHD_PKT_SET_DATAOFF(pkt, pkt_dataoff) \
	DHD_PKTTAG_FD(pkt)->dataoff = (uint16)(pkt_dataoff)

#define DHD_PKT_GET_DMA_LEN(pkt)    ((DHD_PKTTAG_FD(pkt))->dma_len)
#define DHD_PKT_SET_DMA_LEN(pkt, pkt_dma_len) \
	DHD_PKTTAG_FD(pkt)->dma_len = (uint16)(pkt_dma_len)

#define DHD_PKT_GET_PA(pkt)         ((DHD_PKTTAG_FD(pkt))->pa)
#define DHD_PKT_SET_PA(pkt, pkt_pa) \
	DHD_PKTTAG_FD(pkt)->pa = (dmaaddr_t)(pkt_pa)

#define DHD_PKT_GET_DMAH(pkt)       ((DHD_PKTTAG_FD(pkt))->dmah)
#define DHD_PKT_SET_DMAH(pkt, pkt_dmah) \
	DHD_PKTTAG_FD(pkt)->dmah = (void *)(pkt_dmah)

#define DHD_PKT_GET_SECDMA(pkt)    ((DHD_PKTTAG_FD(pkt))->secdma)
#define DHD_PKT_SET_SECDMA(pkt, pkt_secdma) \
	DHD_PKTTAG_FD(pkt)->secdma = (void *)(pkt_secdma)

#if defined(TX_STATUS_LATENCY_STATS)
#define DHD_PKT_GET_QTIME(pkt)    ((DHD_PKTTAG_FD(pkt))->q_time_us)
#define DHD_PKT_SET_QTIME(pkt, pkt_q_time_us) \
	DHD_PKTTAG_FD(pkt)->q_time_us = (uint64)(pkt_q_time_us)
#endif // endif
#endif /* PCIE_FULL_DONGLE */

#if defined(BCMWDF)
typedef struct {
	dhd_pub_t *dhd_pub;
} dhd_workitem_context_t;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(dhd_workitem_context_t, dhd_get_dhd_workitem_context)
#endif /* (BCMWDF)  */

	#if defined(CONFIG_PM_SLEEP)

	#define DHD_PM_RESUME_WAIT_INIT(a) DECLARE_WAIT_QUEUE_HEAD(a);
	#define _DHD_PM_RESUME_WAIT(a, b) do {\
			int retry = 0; \
			SMP_RD_BARRIER_DEPENDS(); \
			while (dhd_mmc_suspend && retry++ != b) { \
				SMP_RD_BARRIER_DEPENDS(); \
				wait_event_interruptible_timeout(a, !dhd_mmc_suspend, 1); \
			} \
		} 	while (0)
	#define DHD_PM_RESUME_WAIT(a) 		_DHD_PM_RESUME_WAIT(a, 200)
	#define DHD_PM_RESUME_WAIT_FOREVER(a) 	_DHD_PM_RESUME_WAIT(a, ~0)
	#define DHD_PM_RESUME_RETURN_ERROR(a)   do { \
			if (dhd_mmc_suspend) { \
				printf("%s[%d]: mmc is still in suspend state!!!\n", \
					__FUNCTION__, __LINE__); \
				return a; \
			} \
		} while (0)
	#define DHD_PM_RESUME_RETURN		do { if (dhd_mmc_suspend) return; } while (0)

	#define DHD_SPINWAIT_SLEEP_INIT(a) DECLARE_WAIT_QUEUE_HEAD(a);
	#define SPINWAIT_SLEEP(a, exp, us) do { \
		uint countdown = (us) + 9999; \
		while ((exp) && (countdown >= 10000)) { \
			wait_event_interruptible_timeout(a, FALSE, 1); \
			countdown -= 10000; \
		} \
	} while (0)

	#else

	#define DHD_PM_RESUME_WAIT_INIT(a)
	#define DHD_PM_RESUME_WAIT(a)
	#define DHD_PM_RESUME_WAIT_FOREVER(a)
	#define DHD_PM_RESUME_RETURN_ERROR(a)
	#define DHD_PM_RESUME_RETURN

	#define DHD_SPINWAIT_SLEEP_INIT(a)
	#define SPINWAIT_SLEEP(a, exp, us)  do { \
		uint countdown = (us) + 9; \
		while ((exp) && (countdown >= 10)) { \
			OSL_DELAY(10);  \
			countdown -= 10;  \
		} \
	} while (0)

	#endif /* CONFIG_PM_SLEEP */

#ifndef OSL_SLEEP
#define OSL_SLEEP(ms)		OSL_DELAY(ms*1000)
#endif /* OSL_SLEEP */

#define DHD_IF_VIF	0x01	/* Virtual IF (Hidden from user) */

#ifdef PNO_SUPPORT
int dhd_pno_clean(dhd_pub_t *dhd);
#endif /* PNO_SUPPORT */

/*
 *  Wake locks are an Android power management concept. They are used by applications and services
 *  to request CPU resources.
 */
extern int dhd_os_wake_lock(dhd_pub_t *pub);
extern int dhd_os_wake_unlock(dhd_pub_t *pub);
extern int dhd_os_wake_lock_waive(dhd_pub_t *pub);
extern int dhd_os_wake_lock_restore(dhd_pub_t *pub);
extern void dhd_event_wake_lock(dhd_pub_t *pub);
extern void dhd_event_wake_unlock(dhd_pub_t *pub);
extern void dhd_pm_wake_lock_timeout(dhd_pub_t *pub, int val);
extern void dhd_pm_wake_unlock(dhd_pub_t *pub);
extern void dhd_txfl_wake_lock_timeout(dhd_pub_t *pub, int val);
extern void dhd_txfl_wake_unlock(dhd_pub_t *pub);
extern int dhd_os_wake_lock_timeout(dhd_pub_t *pub);
extern int dhd_os_wake_lock_rx_timeout_enable(dhd_pub_t *pub, int val);
extern int dhd_os_wake_lock_ctrl_timeout_enable(dhd_pub_t *pub, int val);
extern int dhd_os_wake_lock_ctrl_timeout_cancel(dhd_pub_t *pub);
extern int dhd_os_wd_wake_lock(dhd_pub_t *pub);
extern int dhd_os_wd_wake_unlock(dhd_pub_t *pub);
extern void dhd_os_wake_lock_init(struct dhd_info *dhd);
extern void dhd_os_wake_lock_destroy(struct dhd_info *dhd);
#ifdef DHD_USE_SCAN_WAKELOCK
extern void dhd_os_scan_wake_lock_timeout(dhd_pub_t *pub, int val);
extern void dhd_os_scan_wake_unlock(dhd_pub_t *pub);
#endif /* BCMPCIE_SCAN_WAKELOCK */

#ifdef WLEASYMESH
extern int dhd_get_1905_almac(dhd_pub_t *dhdp, uint8 ifidx, uint8* ea, bool mcast);
extern int dhd_set_1905_almac(dhd_pub_t *dhdp, uint8 ifidx, uint8* ea, bool mcast);
#endif /* WLEASYMESH */

inline static void MUTEX_LOCK_SOFTAP_SET_INIT(dhd_pub_t * dhdp)
{
	mutex_init(&dhdp->wl_softap_lock);
}

inline static void MUTEX_LOCK_SOFTAP_SET(dhd_pub_t * dhdp)
{
	mutex_lock(&dhdp->wl_softap_lock);
}

inline static void MUTEX_UNLOCK_SOFTAP_SET(dhd_pub_t * dhdp)
{
	mutex_unlock(&dhdp->wl_softap_lock);
}

#ifdef DHD_DEBUG_WAKE_LOCK
#define DHD_OS_WAKE_LOCK(pub) \
	do { \
		printf("call wake_lock: %s %d\n", \
			__FUNCTION__, __LINE__); \
		dhd_os_wake_lock(pub); \
	} while (0)
#define DHD_OS_WAKE_UNLOCK(pub) \
	do { \
		printf("call wake_unlock: %s %d\n", \
			__FUNCTION__, __LINE__); \
		dhd_os_wake_unlock(pub); \
	} while (0)
#define DHD_EVENT_WAKE_LOCK(pub) \
	do { \
		printf("call event wake_lock: %s %d\n", \
			__FUNCTION__, __LINE__); \
		dhd_event_wake_lock(pub); \
	} while (0)
#define DHD_EVENT_WAKE_UNLOCK(pub) \
	do { \
		printf("call event wake_unlock: %s %d\n", \
			__FUNCTION__, __LINE__); \
		dhd_event_wake_unlock(pub); \
	} while (0)
#define DHD_PM_WAKE_LOCK_TIMEOUT(pub, val) \
	do { \
		printf("call pm_wake_timeout enable\n"); \
	dhd_pm_wake_lock_timeout(pub, val); \
	} while (0)
#define DHD_PM_WAKE_UNLOCK(pub) \
	do { \
		printf("call pm_wake unlock\n"); \
	dhd_pm_wake_unlock(pub); \
	} while (0)
#define DHD_TXFL_WAKE_LOCK_TIMEOUT(pub, val) \
	do { \
		printf("call pm_wake_timeout enable\n"); \
		dhd_txfl_wake_lock_timeout(pub, val); \
	} while (0)
#define DHD_TXFL_WAKE_UNLOCK(pub) \
	do { \
		printf("call pm_wake unlock\n"); \
		dhd_txfl_wake_unlock(pub); \
	} while (0)
#define DHD_OS_WAKE_LOCK_TIMEOUT(pub) \
	do { \
		printf("call wake_lock_timeout: %s %d\n", \
			__FUNCTION__, __LINE__); \
		dhd_os_wake_lock_timeout(pub); \
	} while (0)
#define DHD_OS_WAKE_LOCK_RX_TIMEOUT_ENABLE(pub, val) \
	do { \
		printf("call wake_lock_rx_timeout_enable[%d]: %s %d\n", \
			val, __FUNCTION__, __LINE__); \
		dhd_os_wake_lock_rx_timeout_enable(pub, val); \
	} while (0)
#define DHD_OS_WAKE_LOCK_CTRL_TIMEOUT_ENABLE(pub, val) \
	do { \
		printf("call wake_lock_ctrl_timeout_enable[%d]: %s %d\n", \
			val, __FUNCTION__, __LINE__); \
		dhd_os_wake_lock_ctrl_timeout_enable(pub, val); \
	} while (0)
#define DHD_OS_WAKE_LOCK_CTRL_TIMEOUT_CANCEL(pub) \
	do { \
		printf("call wake_lock_ctrl_timeout_cancel: %s %d\n", \
			__FUNCTION__, __LINE__); \
		dhd_os_wake_lock_ctrl_timeout_cancel(pub); \
	} while (0)
#define DHD_OS_WAKE_LOCK_WAIVE(pub) \
	do { \
		printf("call wake_lock_waive: %s %d\n", \
			__FUNCTION__, __LINE__); \
		dhd_os_wake_lock_waive(pub); \
	} while (0)
#define DHD_OS_WAKE_LOCK_RESTORE(pub) \
	do { \
		printf("call wake_lock_restore: %s %d\n", \
			__FUNCTION__, __LINE__); \
		dhd_os_wake_lock_restore(pub); \
	} while (0)
#define DHD_OS_WAKE_LOCK_INIT(dhd) \
	do { \
		printf("call wake_lock_init: %s %d\n", \
			__FUNCTION__, __LINE__); \
		dhd_os_wake_lock_init(dhd); \
	} while (0)
#define DHD_OS_WAKE_LOCK_DESTROY(dhd) \
	do { \
		printf("call wake_lock_destroy: %s %d\n", \
			__FUNCTION__, __LINE__); \
		dhd_os_wake_lock_destroy(dhd); \
	} while (0)
#else
#define DHD_OS_WAKE_LOCK(pub)			dhd_os_wake_lock(pub)
#define DHD_OS_WAKE_UNLOCK(pub)		dhd_os_wake_unlock(pub)
#define DHD_EVENT_WAKE_LOCK(pub)			dhd_event_wake_lock(pub)
#define DHD_EVENT_WAKE_UNLOCK(pub)		dhd_event_wake_unlock(pub)
#define DHD_PM_WAKE_LOCK_TIMEOUT(pub, val)  dhd_pm_wake_lock_timeout(pub, val)
#define DHD_PM_WAKE_UNLOCK(pub) 			dhd_pm_wake_unlock(pub)
#define DHD_TXFL_WAKE_LOCK_TIMEOUT(pub, val)	dhd_txfl_wake_lock_timeout(pub, val)
#define DHD_TXFL_WAKE_UNLOCK(pub) 			dhd_txfl_wake_unlock(pub)
#define DHD_OS_WAKE_LOCK_TIMEOUT(pub)		dhd_os_wake_lock_timeout(pub)
#define DHD_OS_WAKE_LOCK_RX_TIMEOUT_ENABLE(pub, val) \
	dhd_os_wake_lock_rx_timeout_enable(pub, val)
#define DHD_OS_WAKE_LOCK_CTRL_TIMEOUT_ENABLE(pub, val) \
	dhd_os_wake_lock_ctrl_timeout_enable(pub, val)
#define DHD_OS_WAKE_LOCK_CTRL_TIMEOUT_CANCEL(pub) \
	dhd_os_wake_lock_ctrl_timeout_cancel(pub)
#define DHD_OS_WAKE_LOCK_WAIVE(pub)			dhd_os_wake_lock_waive(pub)
#define DHD_OS_WAKE_LOCK_RESTORE(pub)		dhd_os_wake_lock_restore(pub)
#define DHD_OS_WAKE_LOCK_INIT(dhd)		dhd_os_wake_lock_init(dhd);
#define DHD_OS_WAKE_LOCK_DESTROY(dhd)		dhd_os_wake_lock_destroy(dhd);
#endif /* DHD_DEBUG_WAKE_LOCK */

#define DHD_OS_WD_WAKE_LOCK(pub)		dhd_os_wd_wake_lock(pub)
#define DHD_OS_WD_WAKE_UNLOCK(pub)		dhd_os_wd_wake_unlock(pub)

#ifdef DHD_USE_SCAN_WAKELOCK
#ifdef DHD_DEBUG_SCAN_WAKELOCK
#define DHD_OS_SCAN_WAKE_LOCK_TIMEOUT(pub, val) \
	do { \
		printf("call wake_lock_scan: %s %d\n", \
			__FUNCTION__, __LINE__); \
		dhd_os_scan_wake_lock_timeout(pub, val); \
	} while (0)
#define DHD_OS_SCAN_WAKE_UNLOCK(pub) \
	do { \
		printf("call wake_unlock_scan: %s %d\n", \
			__FUNCTION__, __LINE__); \
		dhd_os_scan_wake_unlock(pub); \
	} while (0)
#else
#define DHD_OS_SCAN_WAKE_LOCK_TIMEOUT(pub, val)		dhd_os_scan_wake_lock_timeout(pub, val)
#define DHD_OS_SCAN_WAKE_UNLOCK(pub)			dhd_os_scan_wake_unlock(pub)
#endif /* DHD_DEBUG_SCAN_WAKELOCK */
#else
#define DHD_OS_SCAN_WAKE_LOCK_TIMEOUT(pub, val)
#define DHD_OS_SCAN_WAKE_UNLOCK(pub)
#endif /* DHD_USE_SCAN_WAKELOCK */

#ifdef BCMPCIE_OOB_HOST_WAKE
#define OOB_WAKE_LOCK_TIMEOUT 500
extern void dhd_os_oob_irq_wake_lock_timeout(dhd_pub_t *pub, int val);
extern void dhd_os_oob_irq_wake_unlock(dhd_pub_t *pub);

#define DHD_OS_OOB_IRQ_WAKE_LOCK_TIMEOUT(pub, val)	dhd_os_oob_irq_wake_lock_timeout(pub, val)
#define DHD_OS_OOB_IRQ_WAKE_UNLOCK(pub)			dhd_os_oob_irq_wake_unlock(pub)
#endif /* BCMPCIE_OOB_HOST_WAKE */

#define DHD_PACKET_TIMEOUT_MS	500
#define DHD_EVENT_TIMEOUT_MS	1500
#define SCAN_WAKE_LOCK_TIMEOUT	10000
#define MAX_TX_TIMEOUT			500

/* Enum for IOCTL recieved status */
typedef enum dhd_ioctl_recieved_status
{
	IOCTL_WAIT = 0,
	IOCTL_RETURN_ON_SUCCESS,
	IOCTL_RETURN_ON_TRAP,
	IOCTL_RETURN_ON_BUS_STOP,
	IOCTL_RETURN_ON_ERROR
} dhd_ioctl_recieved_status_t;

/* interface operations (register, remove) should be atomic, use this lock to prevent race
 * condition among wifi on/off and interface operation functions
 */
void dhd_net_if_lock(struct net_device *dev);
void dhd_net_if_unlock(struct net_device *dev);

#if defined(MULTIPLE_SUPPLICANT)
extern void wl_android_post_init(void); // terence 20120530: fix critical section in dhd_open and dhdsdio_probe
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)) && defined(MULTIPLE_SUPPLICANT)
extern struct mutex _dhd_mutex_lock_;
#define DHD_MUTEX_IS_LOCK_RETURN() \
	if (mutex_is_locked(&_dhd_mutex_lock_) != 0) { \
		printf("%s : probe is already running! return.\n", __FUNCTION__); \
		return -EBUSY;; \
	}
#define DHD_MUTEX_LOCK() \
	do { \
		if (mutex_is_locked(&_dhd_mutex_lock_) == 0) { \
			printf("%s : no mutex held\n", __FUNCTION__); \
		} else { \
			printf("%s : mutex is locked!. wait for unlocking\n", __FUNCTION__); \
		} \
		mutex_lock(&_dhd_mutex_lock_); \
		printf("%s : set mutex lock\n", __FUNCTION__); \
	} while (0)
#define DHD_MUTEX_UNLOCK() \
	do { \
		printf("%s : mutex is released.\n", __FUNCTION__); \
		mutex_unlock(&_dhd_mutex_lock_); \
	} while (0)
#else
#define DHD_MUTEX_IS_LOCK_RETURN(a)	do {} while (0)
#define DHD_MUTEX_LOCK(a)	do {} while (0)
#define DHD_MUTEX_UNLOCK(a)	do {} while (0)
#endif

typedef enum dhd_attach_states
{
	DHD_ATTACH_STATE_INIT = 0x0,
	DHD_ATTACH_STATE_NET_ALLOC = 0x1,
	DHD_ATTACH_STATE_DHD_ALLOC = 0x2,
	DHD_ATTACH_STATE_ADD_IF = 0x4,
	DHD_ATTACH_STATE_PROT_ATTACH = 0x8,
	DHD_ATTACH_STATE_WL_ATTACH = 0x10,
	DHD_ATTACH_STATE_THREADS_CREATED = 0x20,
	DHD_ATTACH_STATE_WAKELOCKS_INIT = 0x40,
	DHD_ATTACH_STATE_CFG80211 = 0x80,
	DHD_ATTACH_STATE_EARLYSUSPEND_DONE = 0x100,
	DHD_ATTACH_TIMESYNC_ATTACH_DONE = 0x200,
	DHD_ATTACH_LOGTRACE_INIT = 0x400,
	DHD_ATTACH_STATE_LB_ATTACH_DONE = 0x800,
	DHD_ATTACH_STATE_DONE = 0x1000
} dhd_attach_states_t;

/* Value -1 means we are unsuccessful in creating the kthread. */
#define DHD_PID_KT_INVALID 	-1
/* Value -2 means we are unsuccessful in both creating the kthread and tasklet */
#define DHD_PID_KT_TL_INVALID	-2

/* default reporting period */
#define ECOUNTERS_DEFAULT_PERIOD	0

/* default number of reports. '0' indicates forever */
#define ECOUNTERS_NUM_REPORTS		0

typedef struct ecounters_cfg {
	uint16 type;
	uint16 if_slice_idx;
	uint16 stats_rep;
} ecounters_cfg_t;

typedef struct event_ecounters_cfg {
	uint16 event_id;
	uint16 type;
	uint16 if_slice_idx;
	uint16 stats_rep;
} event_ecounters_cfg_t;

typedef struct ecountersv2_xtlv_list_elt {
	/* Not quite the exact bcm_xtlv_t type as data could be pointing to other pieces in
	 * memory at the time of parsing arguments.
	 */
	uint16 id;
	uint16 len;
	uint8 *data;
	struct ecountersv2_xtlv_list_elt *next;
} ecountersv2_xtlv_list_elt_t;

typedef struct ecountersv2_processed_xtlv_list_elt {
	uint8 *data;
	struct ecountersv2_processed_xtlv_list_elt *next;
} ecountersv2_processed_xtlv_list_elt;

/*
 * Exported from dhd OS modules (dhd_linux/dhd_ndis)
 */

/* Indication from bus module regarding presence/insertion of dongle.
 * Return dhd_pub_t pointer, used as handle to OS module in later calls.
 * Returned structure should have bus and prot pointers filled in.
 * bus_hdrlen specifies required headroom for bus module header.
 */
extern dhd_pub_t *dhd_attach(osl_t *osh, struct dhd_bus *bus, uint bus_hdrlen
#ifdef BCMDBUS
	, void *adapter
#endif
);
extern int dhd_attach_net(dhd_pub_t *dhdp, bool need_rtnl_lock);
#if defined(WLP2P) && defined(WL_CFG80211)
/* To allow attach/detach calls corresponding to p2p0 interface  */
extern int dhd_attach_p2p(dhd_pub_t *);
extern int dhd_detach_p2p(dhd_pub_t *);
#endif /* WLP2P && WL_CFG80211 */
extern int dhd_register_if(dhd_pub_t *dhdp, int idx, bool need_rtnl_lock);

/* Indication from bus module regarding removal/absence of dongle */
extern void dhd_detach(dhd_pub_t *dhdp);
extern void dhd_free(dhd_pub_t *dhdp);
extern void dhd_clear(dhd_pub_t *dhdp);

/* Indication from bus module to change flow-control state */
extern void dhd_txflowcontrol(dhd_pub_t *dhdp, int ifidx, bool on);

/* Store the status of a connection attempt for later retrieval by an iovar */
extern void dhd_store_conn_status(uint32 event, uint32 status, uint32 reason);

extern bool dhd_prec_enq(dhd_pub_t *dhdp, struct pktq *q, void *pkt, int prec);

extern void dhd_rx_frame(dhd_pub_t *dhdp, int ifidx, void *rxp, int numpkt, uint8 chan);

/* Return pointer to interface name */
extern char *dhd_ifname(dhd_pub_t *dhdp, int idx);

#ifdef DHD_UCODE_DOWNLOAD
/* Returns the ucode path */
extern char *dhd_get_ucode_path(dhd_pub_t *dhdp);
#endif /* DHD_UCODE_DOWNLOAD */

/* Request scheduling of the bus dpc */
extern void dhd_sched_dpc(dhd_pub_t *dhdp);

/* Notify tx completion */
extern void dhd_txcomplete(dhd_pub_t *dhdp, void *txp, bool success);
#ifdef DHD_4WAYM4_FAIL_DISCONNECT
extern void dhd_eap_txcomplete(dhd_pub_t *dhdp, void *txp, bool success, int ifidx);
extern void dhd_cleanup_m4_state_work(dhd_pub_t *dhdp, int ifidx);
#endif /* DHD_4WAYM4_FAIL_DISCONNECT */

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
extern void dhd_bus_wakeup_work(dhd_pub_t *dhdp);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */
