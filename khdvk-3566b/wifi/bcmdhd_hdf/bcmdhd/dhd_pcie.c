/*
 * DHD Bus Module for PCIE
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
 * $Id: dhd_pcie.c 825481 2019-06-14 10:06:03Z $
 */

/* include files */
#include <typedefs.h>
#include <bcmutils.h>
#include <bcmdevs.h>
#include <siutils.h>
#include <hndoobr.h>
#include <hndsoc.h>
#include <hndpmu.h>
#include <etd.h>
#include <hnd_debug.h>
#include <sbchipc.h>
#include <sbhndarm.h>
#include <hnd_armtrap.h>
#if defined(DHD_DEBUG)
#include <hnd_cons.h>
#endif /* defined(DHD_DEBUG) */
#include <dngl_stats.h>
#include <pcie_core.h>
#include <dhd.h>
#include <dhd_bus.h>
#include <dhd_flowring.h>
#include <dhd_proto.h>
#include <dhd_dbg.h>
#include <dhd_debug.h>
#include <dhd_daemon.h>
#include <dhdioctl.h>
#include <sdiovar.h>
#include <bcmmsgbuf.h>
#include <pcicfg.h>
#include <dhd_pcie.h>
#include <bcmpcie.h>
#include <bcmendian.h>
#include <bcmstdlib_s.h>
#ifdef DHDTCPACK_SUPPRESS
#include <dhd_ip.h>
#endif /* DHDTCPACK_SUPPRESS */
#include <bcmevent.h>
#include <dhd_config.h>

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
#include <linux/pm_runtime.h>
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

#if defined(DEBUGGER) || defined(DHD_DSCOPE)
#include <debugger.h>
#endif /* DEBUGGER || DHD_DSCOPE */

#ifdef DNGL_AXI_ERROR_LOGGING
#include <dhd_linux_wq.h>
#include <dhd_linux.h>
#endif /* DNGL_AXI_ERROR_LOGGING */

#if defined(DHD_CONTROL_PCIE_CPUCORE_WIFI_TURNON)
#include <dhd_linux_priv.h>
#endif /* DHD_CONTROL_PCIE_CPUCORE_WIFI_TURNON */

#include <otpdefs.h>
#define EXTENDED_PCIE_DEBUG_DUMP 1	/* Enable Extended pcie registers dump */

#define MEMBLOCK	2048		/* Block size used for downloading of dongle image */
#define MAX_WKLK_IDLE_CHECK	3	/* times wake_lock checked before deciding not to suspend */

#define	DHD_MAX_ITEMS_HPP_TXCPL_RING	512
#define	DHD_MAX_ITEMS_HPP_RXCPL_RING	512

#define ARMCR4REG_CORECAP	(0x4/sizeof(uint32))
#define ARMCR4REG_MPUCTRL	(0x90/sizeof(uint32))
#define ACC_MPU_SHIFT		25
#define ACC_MPU_MASK		(0x1u << ACC_MPU_SHIFT)

#define REG_WORK_AROUND		(0x1e4/sizeof(uint32))

#define ARMCR4REG_BANKIDX	(0x40/sizeof(uint32))
#define ARMCR4REG_BANKPDA	(0x4C/sizeof(uint32))
/* Temporary war to fix precommit till sync issue between trunk & precommit branch is resolved */

/* CTO Prevention Recovery */
#ifdef BCMQT_HW
#define CTO_TO_CLEAR_WAIT_MS 10000
#define CTO_TO_CLEAR_WAIT_MAX_CNT 100
#else
#define CTO_TO_CLEAR_WAIT_MS 1000
#define CTO_TO_CLEAR_WAIT_MAX_CNT 10
#endif // endif

/* Fetch address of a member in the pciedev_shared structure in dongle memory */
#define DHD_PCIE_SHARED_MEMBER_ADDR(bus, member) \
	(bus)->shared_addr + OFFSETOF(pciedev_shared_t, member)

/* Fetch address of a member in rings_info_ptr structure in dongle memory */
#define DHD_RING_INFO_MEMBER_ADDR(bus, member) \
	(bus)->pcie_sh->rings_info_ptr + OFFSETOF(ring_info_t, member)

/* Fetch address of a member in the ring_mem structure in dongle memory */
#define DHD_RING_MEM_MEMBER_ADDR(bus, ringid, member) \
	(bus)->ring_sh[ringid].ring_mem_addr + OFFSETOF(ring_mem_t, member)

#if defined(SUPPORT_MULTIPLE_BOARD_REV)
	extern unsigned int system_rev;
#endif /* SUPPORT_MULTIPLE_BOARD_REV */

#ifdef EWP_EDL
extern int host_edl_support;
#endif // endif

/* This can be overwritten by module parameter(dma_ring_indices) defined in dhd_linux.c */
uint dma_ring_indices = 0;
/* This can be overwritten by module parameter(h2d_phase) defined in dhd_linux.c */
bool h2d_phase = 0;
/* This can be overwritten by module parameter(force_trap_bad_h2d_phase)
 * defined in dhd_linux.c
 */
bool force_trap_bad_h2d_phase = 0;

int dhd_dongle_memsize;
int dhd_dongle_ramsize;
struct dhd_bus *g_dhd_bus = NULL;
#ifdef DNGL_AXI_ERROR_LOGGING
static void dhd_log_dump_axi_error(uint8 *axi_err);
#endif /* DNGL_AXI_ERROR_LOGGING */

static int dhdpcie_checkdied(dhd_bus_t *bus, char *data, uint size);
static int dhdpcie_bus_readconsole(dhd_bus_t *bus);
#if defined(DHD_FW_COREDUMP)
static int dhdpcie_mem_dump(dhd_bus_t *bus);
static int dhdpcie_get_mem_dump(dhd_bus_t *bus);
#endif /* DHD_FW_COREDUMP */

static int dhdpcie_bus_membytes(dhd_bus_t *bus, bool write, ulong address, uint8 *data, uint size);
static int dhdpcie_bus_doiovar(dhd_bus_t *bus, const bcm_iovar_t *vi, uint32 actionid,
	const char *name, void *params,
	int plen, void *arg, int len, int val_size);
static int dhdpcie_bus_lpback_req(struct  dhd_bus *bus, uint32 intval);
static int dhdpcie_bus_dmaxfer_req(struct  dhd_bus *bus,
	uint32 len, uint32 srcdelay, uint32 destdelay,
	uint32 d11_lpbk, uint32 core_num, uint32 wait);
static int dhdpcie_bus_download_state(dhd_bus_t *bus, bool enter);
static int _dhdpcie_download_firmware(struct dhd_bus *bus);
static int dhdpcie_download_firmware(dhd_bus_t *bus, osl_t *osh);
static int dhdpcie_bus_write_vars(dhd_bus_t *bus);
static bool dhdpcie_bus_process_mailbox_intr(dhd_bus_t *bus, uint32 intstatus);
static bool dhdpci_bus_read_frames(dhd_bus_t *bus);
static int dhdpcie_readshared(dhd_bus_t *bus);
static void dhdpcie_init_shared_addr(dhd_bus_t *bus);
static bool dhdpcie_dongle_attach(dhd_bus_t *bus);
static void dhdpcie_bus_dongle_setmemsize(dhd_bus_t *bus, int mem_size);
static void dhdpcie_bus_release_dongle(dhd_bus_t *bus, osl_t *osh,
	bool dongle_isolation, bool reset_flag);
static void dhdpcie_bus_release_malloc(dhd_bus_t *bus, osl_t *osh);
static int dhdpcie_downloadvars(dhd_bus_t *bus, void *arg, int len);
static void dhdpcie_setbar1win(dhd_bus_t *bus, uint32 addr);
static uint8 dhdpcie_bus_rtcm8(dhd_bus_t *bus, ulong offset);
static void dhdpcie_bus_wtcm8(dhd_bus_t *bus, ulong offset, uint8 data);
static void dhdpcie_bus_wtcm16(dhd_bus_t *bus, ulong offset, uint16 data);
static uint16 dhdpcie_bus_rtcm16(dhd_bus_t *bus, ulong offset);
static void dhdpcie_bus_wtcm32(dhd_bus_t *bus, ulong offset, uint32 data);
static uint32 dhdpcie_bus_rtcm32(dhd_bus_t *bus, ulong offset);
#ifdef DHD_SUPPORT_64BIT
static void dhdpcie_bus_wtcm64(dhd_bus_t *bus, ulong offset, uint64 data) __attribute__ ((used));
static uint64 dhdpcie_bus_rtcm64(dhd_bus_t *bus, ulong offset) __attribute__ ((used));
#endif /* DHD_SUPPORT_64BIT */
static void dhdpcie_bus_cfg_set_bar0_win(dhd_bus_t *bus, uint32 data);
static void dhdpcie_bus_reg_unmap(osl_t *osh, volatile char *addr, int size);
static int dhdpcie_cc_nvmshadow(dhd_bus_t *bus, struct bcmstrbuf *b);
static void dhdpcie_fw_trap(dhd_bus_t *bus);
static void dhd_fillup_ring_sharedptr_info(dhd_bus_t *bus, ring_info_t *ring_info);
static void dhdpcie_handle_mb_data(dhd_bus_t *bus);
extern void dhd_dpc_enable(dhd_pub_t *dhdp);
extern void dhd_dpc_kill(dhd_pub_t *dhdp);

#ifdef IDLE_TX_FLOW_MGMT
static void dhd_bus_check_idle_scan(dhd_bus_t *bus);
static void dhd_bus_idle_scan(dhd_bus_t *bus);
#endif /* IDLE_TX_FLOW_MGMT */

#ifdef EXYNOS_PCIE_DEBUG
extern void exynos_pcie_register_dump(int ch_num);
#endif /* EXYNOS_PCIE_DEBUG */

#if defined(DHD_H2D_LOG_TIME_SYNC)
static void dhdpci_bus_rte_log_time_sync_poll(dhd_bus_t *bus);
#endif /* DHD_H2D_LOG_TIME_SYNC */

#define     PCI_VENDOR_ID_BROADCOM          0x14e4

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
#define MAX_D3_ACK_TIMEOUT	100
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

#define DHD_DEFAULT_DOORBELL_TIMEOUT 200	/* ms */
static bool dhdpcie_check_firmware_compatible(uint32 f_api_version, uint32 h_api_version);
static int dhdpcie_cto_error_recovery(struct dhd_bus *bus);

static int dhdpcie_init_d11status(struct dhd_bus *bus);

static int dhdpcie_wrt_rnd(struct dhd_bus *bus);

extern uint16 dhd_prot_get_h2d_max_txpost(dhd_pub_t *dhd);
extern void dhd_prot_set_h2d_max_txpost(dhd_pub_t *dhd, uint16 max_txpost);

#ifdef DHD_HP2P
extern enum hrtimer_restart dhd_hp2p_write(struct hrtimer *timer);
static uint16 dhd_bus_set_hp2p_ring_max_size(struct dhd_bus *bus, bool tx, uint16 val);
#endif // endif
#define NUM_PATTERNS 2
static bool dhd_bus_tcm_test(struct dhd_bus *bus);

/* IOVar table */
enum {
	IOV_INTR = 1,
	IOV_MEMSIZE,
	IOV_SET_DOWNLOAD_STATE,
	IOV_DEVRESET,
	IOV_VARS,
	IOV_MSI_SIM,
	IOV_PCIE_LPBK,
	IOV_CC_NVMSHADOW,
	IOV_RAMSIZE,
	IOV_RAMSTART,
	IOV_SLEEP_ALLOWED,
	IOV_PCIE_DMAXFER,
	IOV_PCIE_SUSPEND,
	IOV_DONGLEISOLATION,
	IOV_LTRSLEEPON_UNLOOAD,
	IOV_METADATA_DBG,
	IOV_RX_METADATALEN,
	IOV_TX_METADATALEN,
	IOV_TXP_THRESHOLD,
	IOV_BUZZZ_DUMP,
	IOV_DUMP_RINGUPD_BLOCK,
	IOV_DMA_RINGINDICES,
	IOV_FORCE_FW_TRAP,
	IOV_DB1_FOR_MB,
	IOV_FLOW_PRIO_MAP,
	IOV_RXBOUND,
	IOV_TXBOUND,
	IOV_HANGREPORT,
	IOV_H2D_MAILBOXDATA,
	IOV_INFORINGS,
	IOV_H2D_PHASE,
	IOV_H2D_ENABLE_TRAP_BADPHASE,
	IOV_H2D_TXPOST_MAX_ITEM,
	IOV_TRAPDATA,
	IOV_TRAPDATA_RAW,
	IOV_CTO_PREVENTION,
	IOV_PCIE_WD_RESET,
	IOV_DUMP_DONGLE,
	IOV_HWA_ENAB_BMAP,
	IOV_IDMA_ENABLE,
	IOV_IFRM_ENABLE,
	IOV_CLEAR_RING,
	IOV_DAR_ENABLE,
	IOV_DNGL_CAPS,   /**< returns string with dongle capabilities */
#if defined(DEBUGGER) || defined(DHD_DSCOPE)
	IOV_GDB_SERVER,  /**< starts gdb server on given interface */
#endif /* DEBUGGER || DHD_DSCOPE */
	IOV_INB_DW_ENABLE,
	IOV_CTO_THRESHOLD,
	IOV_HSCBSIZE, /* get HSCB buffer size */
	IOV_HP2P_ENABLE,
	IOV_HP2P_PKT_THRESHOLD,
	IOV_HP2P_TIME_THRESHOLD,
	IOV_HP2P_PKT_EXPIRY,
	IOV_HP2P_TXCPL_MAXITEMS,
	IOV_HP2P_RXCPL_MAXITEMS,
	IOV_EXTDTXS_IN_TXCPL,
	IOV_HOSTRDY_AFTER_INIT,
	IOV_PCIE_LAST /**< unused IOVAR */
};

const bcm_iovar_t dhdpcie_iovars[] = {
	{"intr",	IOV_INTR,	0, 	0, IOVT_BOOL,	0 },
	{"memsize",	IOV_MEMSIZE,	0, 	0, IOVT_UINT32,	0 },
	{"dwnldstate",	IOV_SET_DOWNLOAD_STATE,	0, 	0, IOVT_BOOL,	0 },
	{"vars",	IOV_VARS,	0, 	0, IOVT_BUFFER,	0 },
	{"devreset",	IOV_DEVRESET,	0, 	0, IOVT_UINT8,	0 },
	{"pcie_device_trap", IOV_FORCE_FW_TRAP, 0, 	0, 0,	0 },
	{"pcie_lpbk",	IOV_PCIE_LPBK,	0,	0, IOVT_UINT32,	0 },
	{"cc_nvmshadow", IOV_CC_NVMSHADOW, 0,	0, IOVT_BUFFER, 0 },
	{"ramsize",	IOV_RAMSIZE,	0, 	0, IOVT_UINT32,	0 },
	{"ramstart",	IOV_RAMSTART,	0, 	0, IOVT_UINT32,	0 },
	{"pcie_dmaxfer", IOV_PCIE_DMAXFER, 0, 0, IOVT_BUFFER, sizeof(dma_xfer_info_t)},
	{"pcie_suspend", IOV_PCIE_SUSPEND,	DHD_IOVF_PWRREQ_BYPASS,	0, IOVT_UINT32,	0 },
	{"sleep_allowed",	IOV_SLEEP_ALLOWED,	0,	0, IOVT_BOOL,	0 },
	{"dngl_isolation", IOV_DONGLEISOLATION,	0, 	0, IOVT_UINT32,	0 },
	{"ltrsleep_on_unload", IOV_LTRSLEEPON_UNLOOAD,	0,	0, IOVT_UINT32,	0 },
	{"dump_ringupdblk", IOV_DUMP_RINGUPD_BLOCK,	0, 	0, IOVT_BUFFER,	0 },
	{"dma_ring_indices", IOV_DMA_RINGINDICES,	0, 	0, IOVT_UINT32,	0},
	{"metadata_dbg", IOV_METADATA_DBG,	0,	0, IOVT_BOOL,	0 },
	{"rx_metadata_len", IOV_RX_METADATALEN,	0, 	0, IOVT_UINT32,	0 },
	{"tx_metadata_len", IOV_TX_METADATALEN,	0, 	0, IOVT_UINT32,	0 },
	{"db1_for_mb", IOV_DB1_FOR_MB,	0, 	0, IOVT_UINT32,	0 },
	{"txp_thresh", IOV_TXP_THRESHOLD,	0,	0, IOVT_UINT32,	0 },
	{"buzzz_dump", IOV_BUZZZ_DUMP,		0, 	0, IOVT_UINT32,	0 },
	{"flow_prio_map", IOV_FLOW_PRIO_MAP,	0, 	0, IOVT_UINT32,	0 },
	{"rxbound",     IOV_RXBOUND,    0, 0,	IOVT_UINT32,    0 },
	{"txbound",     IOV_TXBOUND,    0, 0,	IOVT_UINT32,    0 },
	{"fw_hang_report", IOV_HANGREPORT,	0, 0,	IOVT_BOOL,	0 },
	{"h2d_mb_data",     IOV_H2D_MAILBOXDATA,    0, 0,      IOVT_UINT32,    0 },
	{"inforings",   IOV_INFORINGS,    0, 0,      IOVT_UINT32,    0 },
	{"h2d_phase",   IOV_H2D_PHASE,    0, 0,      IOVT_UINT32,    0 },
	{"force_trap_bad_h2d_phase", IOV_H2D_ENABLE_TRAP_BADPHASE,    0, 0,
	IOVT_UINT32,    0 },
	{"h2d_max_txpost",   IOV_H2D_TXPOST_MAX_ITEM,    0, 0,      IOVT_UINT32,    0 },
	{"trap_data",	IOV_TRAPDATA,	0, 0,	IOVT_BUFFER,	0 },
	{"trap_data_raw",	IOV_TRAPDATA_RAW,	0, 0,	IOVT_BUFFER,	0 },
	{"cto_prevention",	IOV_CTO_PREVENTION,	0, 0,	IOVT_UINT32,	0 },
	{"pcie_wd_reset",	IOV_PCIE_WD_RESET,	0,	0, IOVT_BOOL,	0 },
	{"dump_dongle", IOV_DUMP_DONGLE, 0, 0, IOVT_BUFFER,
	MAX(sizeof(dump_dongle_in_t), sizeof(dump_dongle_out_t))},
	{"clear_ring",   IOV_CLEAR_RING,    0, 0,  IOVT_UINT32,    0 },
	{"hwa_enab_bmap",   IOV_HWA_ENAB_BMAP,    0, 0,  IOVT_UINT32,    0 },
	{"idma_enable",   IOV_IDMA_ENABLE,    0, 0,  IOVT_UINT32,    0 },
	{"ifrm_enable",   IOV_IFRM_ENABLE,    0, 0,  IOVT_UINT32,    0 },
	{"dar_enable",   IOV_DAR_ENABLE,    0, 0,  IOVT_UINT32,    0 },
	{"cap", IOV_DNGL_CAPS,	0, 0, IOVT_BUFFER,	0},
#if defined(DEBUGGER) || defined(DHD_DSCOPE)
	{"gdb_server", IOV_GDB_SERVER,    0, 0,      IOVT_UINT32,    0 },
#endif /* DEBUGGER || DHD_DSCOPE */
	{"inb_dw_enable",   IOV_INB_DW_ENABLE,    0, 0,  IOVT_UINT32,    0 },
	{"cto_threshold",	IOV_CTO_THRESHOLD,	0,	0, IOVT_UINT32,	0 },
	{"hscbsize",	IOV_HSCBSIZE,	0,	0,	IOVT_UINT32,	0 },
#ifdef DHD_HP2P
	{"hp2p_enable", IOV_HP2P_ENABLE,	0,	0, IOVT_UINT32,	0 },
	{"hp2p_pkt_thresh", IOV_HP2P_PKT_THRESHOLD,	0,	0, IOVT_UINT32,	0 },
	{"hp2p_time_thresh", IOV_HP2P_TIME_THRESHOLD,	0,	0, IOVT_UINT32,	0 },
	{"hp2p_pkt_expiry", IOV_HP2P_PKT_EXPIRY,	0,	0, IOVT_UINT32,	0 },
	{"hp2p_txcpl_maxitems", IOV_HP2P_TXCPL_MAXITEMS,	0,	0, IOVT_UINT32,	0 },
	{"hp2p_rxcpl_maxitems", IOV_HP2P_RXCPL_MAXITEMS,	0,	0, IOVT_UINT32,	0 },
#endif // endif
	{"extdtxs_in_txcpl", IOV_EXTDTXS_IN_TXCPL,	0,	0, IOVT_UINT32,	0 },
	{"hostrdy_after_init", IOV_HOSTRDY_AFTER_INIT,	0,	0, IOVT_UINT32,	0 },
	{NULL, 0, 0, 0, 0, 0 }
};

#define MAX_READ_TIMEOUT	2 * 1000 * 1000

#ifndef DHD_RXBOUND
#define DHD_RXBOUND		64
#endif // endif
#ifndef DHD_TXBOUND
#define DHD_TXBOUND		64
#endif // endif

#define DHD_INFORING_BOUND	32
#define DHD_BTLOGRING_BOUND	32

uint dhd_rxbound = DHD_RXBOUND;
uint dhd_txbound = DHD_TXBOUND;

#if defined(DEBUGGER) || defined(DHD_DSCOPE)
/** the GDB debugger layer will call back into this (bus) layer to read/write dongle memory */
static struct dhd_gdb_bus_ops_s  bus_ops = {
	.read_u16 = dhdpcie_bus_rtcm16,
	.read_u32 = dhdpcie_bus_rtcm32,
	.write_u32 = dhdpcie_bus_wtcm32,
};
#endif /* DEBUGGER || DHD_DSCOPE */

bool
dhd_bus_get_flr_force_fail(struct dhd_bus *bus)
{
	return bus->flr_force_fail;
}

/**
 * Register/Unregister functions are called by the main DHD entry point (eg module insertion) to
 * link with the bus driver, in order to look for or await the device.
 */
int
dhd_bus_register(void)
{
	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	return dhdpcie_bus_register();
}

void
dhd_bus_unregister(void)
{
	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	dhdpcie_bus_unregister();
	return;
}

/** returns a host virtual address */
uint32 *
dhdpcie_bus_reg_map(osl_t *osh, ulong addr, int size)
{
	return (uint32 *)REG_MAP(addr, size);
}

void
dhdpcie_bus_reg_unmap(osl_t *osh, volatile char *addr, int size)
{
	REG_UNMAP(addr);
	return;
}

/**
 * retrun H2D Doorbell registers address
 * use DAR registers instead of enum register for corerev >= 23 (4347B0)
 */
static INLINE uint
dhd_bus_db0_addr_get(struct dhd_bus *bus)
{
	uint addr = PCIH2D_MailBox;
	uint dar_addr = DAR_PCIH2D_DB0_0(bus->sih->buscorerev);

	return ((DAR_ACTIVE(bus->dhd)) ? dar_addr : addr);
}

static INLINE uint
dhd_bus_db0_addr_2_get(struct dhd_bus *bus)
{
	return ((DAR_ACTIVE(bus->dhd)) ? DAR_PCIH2D_DB2_0(bus->sih->buscorerev) : PCIH2D_MailBox_2);
}

static INLINE uint
dhd_bus_db1_addr_get(struct dhd_bus *bus)
{
	return ((DAR_ACTIVE(bus->dhd)) ? DAR_PCIH2D_DB0_1(bus->sih->buscorerev) : PCIH2D_DB1);
}

static INLINE uint
dhd_bus_db1_addr_1_get(struct dhd_bus *bus)
{
	return ((DAR_ACTIVE(bus->dhd)) ? DAR_PCIH2D_DB1_1(bus->sih->buscorerev) : PCIH2D_DB1_1);
}

/*
 * WAR for SWWLAN-215055 - [4378B0] ARM fails to boot without DAR WL domain request
 */
static INLINE void
dhd_bus_pcie_pwr_req_wl_domain(struct dhd_bus *bus, uint offset, bool enable)
{
	if (enable) {
		si_corereg(bus->sih, bus->sih->buscoreidx, offset,
			SRPWR_DMN1_ARMBPSD_MASK << SRPWR_REQON_SHIFT,
			SRPWR_DMN1_ARMBPSD_MASK << SRPWR_REQON_SHIFT);
	} else {
		si_corereg(bus->sih, bus->sih->buscoreidx, offset,
			SRPWR_DMN1_ARMBPSD_MASK << SRPWR_REQON_SHIFT, 0);
	}
}

static INLINE void
_dhd_bus_pcie_pwr_req_clear_cmn(struct dhd_bus *bus)
{
	uint mask;

	/*
	 * If multiple de-asserts, decrement ref and return
	 * Clear power request when only one pending
	 * so initial request is not removed unexpectedly
	 */
	if (bus->pwr_req_ref > 1) {
		bus->pwr_req_ref--;
		return;
	}

	ASSERT(bus->pwr_req_ref == 1);

	if (MULTIBP_ENAB(bus->sih)) {
		/* Common BP controlled by HW so only need to toggle WL/ARM backplane */
		mask = SRPWR_DMN1_ARMBPSD_MASK;
	} else {
		mask = SRPWR_DMN0_PCIE_MASK | SRPWR_DMN1_ARMBPSD_MASK;
	}

	si_srpwr_request(bus->sih, mask, 0);
	bus->pwr_req_ref = 0;
}

static INLINE void
dhd_bus_pcie_pwr_req_clear(struct dhd_bus *bus)
{
	unsigned long flags = 0;

	DHD_GENERAL_LOCK(bus->dhd, flags);
	_dhd_bus_pcie_pwr_req_clear_cmn(bus);
	DHD_GENERAL_UNLOCK(bus->dhd, flags);
}

static INLINE void
dhd_bus_pcie_pwr_req_clear_nolock(struct dhd_bus *bus)
{
	_dhd_bus_pcie_pwr_req_clear_cmn(bus);
}

static INLINE void
_dhd_bus_pcie_pwr_req_cmn(struct dhd_bus *bus)
{
	uint mask, val;

	/* If multiple request entries, increment reference and return */
	if (bus->pwr_req_ref > 0) {
		bus->pwr_req_ref++;
		return;
	}

	ASSERT(bus->pwr_req_ref == 0);

	if (MULTIBP_ENAB(bus->sih)) {
		/* Common BP controlled by HW so only need to toggle WL/ARM backplane */
		mask = SRPWR_DMN1_ARMBPSD_MASK;
		val = SRPWR_DMN1_ARMBPSD_MASK;
	} else {
		mask = SRPWR_DMN0_PCIE_MASK | SRPWR_DMN1_ARMBPSD_MASK;
		val = SRPWR_DMN0_PCIE_MASK | SRPWR_DMN1_ARMBPSD_MASK;
	}

	si_srpwr_request(bus->sih, mask, val);

	bus->pwr_req_ref = 1;
}

static INLINE void
dhd_bus_pcie_pwr_req(struct dhd_bus *bus)
{
	unsigned long flags = 0;

	DHD_GENERAL_LOCK(bus->dhd, flags);
	_dhd_bus_pcie_pwr_req_cmn(bus);
	DHD_GENERAL_UNLOCK(bus->dhd, flags);
}

static INLINE void
_dhd_bus_pcie_pwr_req_pd0123_cmn(struct dhd_bus *bus)
{
	uint mask, val;

	mask = SRPWR_DMN_ALL_MASK(bus->sih);
	val = SRPWR_DMN_ALL_MASK(bus->sih);

	si_srpwr_request(bus->sih, mask, val);
}

static INLINE void
dhd_bus_pcie_pwr_req_reload_war(struct dhd_bus *bus)
{
	unsigned long flags = 0;

	DHD_GENERAL_LOCK(bus->dhd, flags);
	_dhd_bus_pcie_pwr_req_pd0123_cmn(bus);
	DHD_GENERAL_UNLOCK(bus->dhd, flags);
}

static INLINE void
_dhd_bus_pcie_pwr_req_clear_pd0123_cmn(struct dhd_bus *bus)
{
	uint mask;

	mask = SRPWR_DMN_ALL_MASK(bus->sih);

	si_srpwr_request(bus->sih, mask, 0);
}

static INLINE void
dhd_bus_pcie_pwr_req_clear_reload_war(struct dhd_bus *bus)
{
	unsigned long flags = 0;

	DHD_GENERAL_LOCK(bus->dhd, flags);
	_dhd_bus_pcie_pwr_req_clear_pd0123_cmn(bus);
	DHD_GENERAL_UNLOCK(bus->dhd, flags);
}

static INLINE void
dhd_bus_pcie_pwr_req_nolock(struct dhd_bus *bus)
{
	_dhd_bus_pcie_pwr_req_cmn(bus);
}

bool
dhdpcie_chip_support_msi(dhd_bus_t *bus)
{
	DHD_INFO(("%s: buscorerev=%d chipid=0x%x\n",
		__FUNCTION__, bus->sih->buscorerev, si_chipid(bus->sih)));
	if (bus->sih->buscorerev <= 14 ||
		si_chipid(bus->sih) == BCM4375_CHIP_ID ||
		si_chipid(bus->sih) == BCM4362_CHIP_ID ||
		si_chipid(bus->sih) == BCM43751_CHIP_ID ||
		si_chipid(bus->sih) == BCM4361_CHIP_ID ||
		si_chipid(bus->sih) == BCM4359_CHIP_ID) {
		return FALSE;
	} else {
		return TRUE;
	}
}

/**
 * Called once for each hardware (dongle) instance that this DHD manages.
 *
 * 'regs' is the host virtual address that maps to the start of the PCIe BAR0 window. The first 4096
 * bytes in this window are mapped to the backplane address in the PCIEBAR0Window register. The
 * precondition is that the PCIEBAR0Window register 'points' at the PCIe core.
 *
 * 'tcm' is the *host* virtual address at which tcm is mapped.
 */
int dhdpcie_bus_attach(osl_t *osh, dhd_bus_t **bus_ptr,
	volatile char *regs, volatile char *tcm, void *pci_dev, wifi_adapter_info_t *adapter)
{
	dhd_bus_t *bus = NULL;
	int ret = BCME_OK;

	DHD_TRACE(("%s: ENTER\n", __FUNCTION__));

	do {
		if (!(bus = MALLOCZ(osh, sizeof(dhd_bus_t)))) {
			DHD_ERROR(("%s: MALLOC of dhd_bus_t failed\n", __FUNCTION__));
			ret = BCME_NORESOURCE;
			break;
		}
		bus->bus = adapter->bus_type;
		bus->bus_num = adapter->bus_num;
		bus->slot_num = adapter->slot_num;

		bus->regs = regs;
		bus->tcm = tcm;
		bus->osh = osh;
		/* Save pci_dev into dhd_bus, as it may be needed in dhd_attach */
		bus->dev = (struct pci_dev *)pci_dev;

		dll_init(&bus->flowring_active_list);
#ifdef IDLE_TX_FLOW_MGMT
		bus->active_list_last_process_ts = OSL_SYSUPTIME();
#endif /* IDLE_TX_FLOW_MGMT */

		/* Attach pcie shared structure */
		if (!(bus->pcie_sh = MALLOCZ(osh, sizeof(pciedev_shared_t)))) {
			DHD_ERROR(("%s: MALLOC of bus->pcie_sh failed\n", __FUNCTION__));
			ret = BCME_NORESOURCE;
			break;
		}

		/* dhd_common_init(osh); */

		if (dhdpcie_dongle_attach(bus)) {
			DHD_ERROR(("%s: dhdpcie_probe_attach failed\n", __FUNCTION__));
			ret = BCME_NOTREADY;
			break;
		}

		/* software resources */
		if (!(bus->dhd = dhd_attach(osh, bus, PCMSGBUF_HDRLEN))) {
			DHD_ERROR(("%s: dhd_attach failed\n", __FUNCTION__));
			ret = BCME_NORESOURCE;
			break;
		}
#if defined(GET_OTP_MAC_ENABLE) || defined(GET_OTP_MODULE_NAME)
		dhd_conf_get_otp(bus->dhd, bus->sih);
#endif
		DHD_ERROR(("%s: making DHD_BUS_DOWN\n", __FUNCTION__));
		bus->dhd->busstate = DHD_BUS_DOWN;
		bus->dhd->hostrdy_after_init = TRUE;
		bus->db1_for_mb = TRUE;
		bus->dhd->hang_report = TRUE;
		bus->use_mailbox = FALSE;
		bus->use_d0_inform = FALSE;
		bus->intr_enabled = FALSE;
		bus->flr_force_fail = FALSE;
		/* By default disable HWA and enable it via iovar */
		bus->hwa_enab_bmap = 0;
		/* update the dma indices if set through module parameter. */
		if (dma_ring_indices != 0) {
			dhdpcie_set_dma_ring_indices(bus->dhd, dma_ring_indices);
		}
		/* update h2d phase support if set through module parameter */
		bus->dhd->h2d_phase_supported = h2d_phase ? TRUE : FALSE;
		/* update force trap on bad phase if set through module parameter */
		bus->dhd->force_dongletrap_on_bad_h2d_phase =
			force_trap_bad_h2d_phase ? TRUE : FALSE;
#ifdef IDLE_TX_FLOW_MGMT
		bus->enable_idle_flowring_mgmt = FALSE;
#endif /* IDLE_TX_FLOW_MGMT */
		bus->irq_registered = FALSE;

#ifdef DHD_MSI_SUPPORT
		bus->d2h_intr_method = enable_msi && dhdpcie_chip_support_msi(bus) ?
			PCIE_MSI : PCIE_INTX;
		if (bus->dhd->conf->d2h_intr_method >= 0)
			bus->d2h_intr_method = bus->dhd->conf->d2h_intr_method;
#else
		bus->d2h_intr_method = PCIE_INTX;
#endif /* DHD_MSI_SUPPORT */

#ifdef DHD_HP2P
		bus->hp2p_txcpl_max_items = DHD_MAX_ITEMS_HPP_TXCPL_RING;
		bus->hp2p_rxcpl_max_items = DHD_MAX_ITEMS_HPP_RXCPL_RING;
#endif /* DHD_HP2P */

		DHD_TRACE(("%s: EXIT SUCCESS\n",
			__FUNCTION__));
		g_dhd_bus = bus;
		*bus_ptr = bus;
		return ret;
	} while (0);

	DHD_TRACE(("%s: EXIT FAILURE\n", __FUNCTION__));

	if (bus && bus->pcie_sh) {
		MFREE(osh, bus->pcie_sh, sizeof(pciedev_shared_t));
	}

	if (bus) {
		MFREE(osh, bus, sizeof(dhd_bus_t));
	}

	return ret;
}

bool
dhd_bus_skip_clm(dhd_pub_t *dhdp)
{
	switch (dhd_bus_chip_id(dhdp)) {
		case BCM4369_CHIP_ID:
			return TRUE;
		default:
			return FALSE;
	}
}

uint
dhd_bus_chip(struct dhd_bus *bus)
{
	ASSERT(bus->sih != NULL);
	return bus->sih->chip;
}

uint
dhd_bus_chiprev(struct dhd_bus *bus)
{
	ASSERT(bus);
	ASSERT(bus->sih != NULL);
	return bus->sih->chiprev;
}

void *
dhd_bus_pub(struct dhd_bus *bus)
{
	return bus->dhd;
}

void *
dhd_bus_sih(struct dhd_bus *bus)
{
	return (void *)bus->sih;
}

void *
dhd_bus_txq(struct dhd_bus *bus)
{
	return &bus->txq;
}

/** Get Chip ID version */
uint dhd_bus_chip_id(dhd_pub_t *dhdp)
{
	dhd_bus_t *bus = dhdp->bus;
	return  bus->sih->chip;
}

/** Get Chip Rev ID version */
uint dhd_bus_chiprev_id(dhd_pub_t *dhdp)
{
	dhd_bus_t *bus = dhdp->bus;
	return bus->sih->chiprev;
}

/** Get Chip Pkg ID version */
uint dhd_bus_chippkg_id(dhd_pub_t *dhdp)
{
	dhd_bus_t *bus = dhdp->bus;
	return bus->sih->chippkg;
}

int dhd_bus_get_ids(struct dhd_bus *bus, uint32 *bus_type, uint32 *bus_num, uint32 *slot_num)
{
	*bus_type = bus->bus;
	*bus_num = bus->bus_num;
	*slot_num = bus->slot_num;
	return 0;
}

/** Conduct Loopback test */
int
dhd_bus_dmaxfer_lpbk(dhd_pub_t *dhdp, uint32 type)
{
	dma_xfer_info_t dmaxfer_lpbk;
	int ret = BCME_OK;

#define PCIE_DMAXFER_LPBK_LENGTH	4096
	memset(&dmaxfer_lpbk, 0, sizeof(dma_xfer_info_t));
	dmaxfer_lpbk.version = DHD_DMAXFER_VERSION;
	dmaxfer_lpbk.length = (uint16)sizeof(dma_xfer_info_t);
	dmaxfer_lpbk.num_bytes = PCIE_DMAXFER_LPBK_LENGTH;
	dmaxfer_lpbk.type = type;
	dmaxfer_lpbk.should_wait = TRUE;

	ret = dhd_bus_iovar_op(dhdp, "pcie_dmaxfer", NULL, 0,
		(char *)&dmaxfer_lpbk, sizeof(dma_xfer_info_t), IOV_SET);
	if (ret < 0) {
		DHD_ERROR(("failed to start PCIe Loopback Test!!! "
			"Type:%d Reason:%d\n", type, ret));
		return ret;
	}

	if (dmaxfer_lpbk.status != DMA_XFER_SUCCESS) {
		DHD_ERROR(("failed to check PCIe Loopback Test!!! "
			"Type:%d Status:%d Error code:%d\n", type,
			dmaxfer_lpbk.status, dmaxfer_lpbk.error_code));
		ret = BCME_ERROR;
	} else {
		DHD_ERROR(("successful to check PCIe Loopback Test"
			" Type:%d\n", type));
	}
#undef PCIE_DMAXFER_LPBK_LENGTH

	return ret;
}

/* Log the lastest DPC schedule time */
void
dhd_bus_set_dpc_sched_time(dhd_pub_t *dhdp)
{
	dhdp->bus->dpc_sched_time = OSL_LOCALTIME_NS();
}

/* Check if there is DPC scheduling errors */
bool
dhd_bus_query_dpc_sched_errors(dhd_pub_t *dhdp)
{
	dhd_bus_t *bus = dhdp->bus;
	bool sched_err;

	if (bus->dpc_entry_time < bus->isr_exit_time) {
		/* Kernel doesn't schedule the DPC after processing PCIe IRQ */
		sched_err = TRUE;
	} else if (bus->dpc_entry_time < bus->resched_dpc_time) {
		/* Kernel doesn't schedule the DPC after DHD tries to reschedule
		 * the DPC due to pending work items to be processed.
		 */
		sched_err = TRUE;
	} else {
		sched_err = FALSE;
	}

	if (sched_err) {
		/* print out minimum timestamp info */
		DHD_ERROR(("isr_entry_time="SEC_USEC_FMT
			" isr_exit_time="SEC_USEC_FMT
			" dpc_entry_time="SEC_USEC_FMT
			"\ndpc_exit_time="SEC_USEC_FMT
			" dpc_sched_time="SEC_USEC_FMT
			" resched_dpc_time="SEC_USEC_FMT"\n",
			GET_SEC_USEC(bus->isr_entry_time),
			GET_SEC_USEC(bus->isr_exit_time),
			GET_SEC_USEC(bus->dpc_entry_time),
			GET_SEC_USEC(bus->dpc_exit_time),
			GET_SEC_USEC(bus->dpc_sched_time),
			GET_SEC_USEC(bus->resched_dpc_time)));
	}

	return sched_err;
}

/** Read and clear intstatus. This should be called with interrupts disabled or inside isr */
uint32
dhdpcie_bus_intstatus(dhd_bus_t *bus)
{
	uint32 intstatus = 0;
	uint32 intmask = 0;

	if (bus->bus_low_power_state == DHD_BUS_D3_ACK_RECIEVED) {
		DHD_ERROR(("%s: trying to clear intstatus after D3 Ack\n", __FUNCTION__));
		return intstatus;
	}
	if ((bus->sih->buscorerev == 6) || (bus->sih->buscorerev == 4) ||
		(bus->sih->buscorerev == 2)) {
		intstatus = dhdpcie_bus_cfg_read_dword(bus, PCIIntstatus, 4);
		dhdpcie_bus_cfg_write_dword(bus, PCIIntstatus, 4, intstatus);
		intstatus &= I_MB;
	} else {
		/* this is a PCIE core register..not a config register... */
		intstatus = si_corereg(bus->sih, bus->sih->buscoreidx, bus->pcie_mailbox_int, 0, 0);

		/* this is a PCIE core register..not a config register... */
		intmask = si_corereg(bus->sih, bus->sih->buscoreidx, bus->pcie_mailbox_mask, 0, 0);
		/* Is device removed. intstatus & intmask read 0xffffffff */
		if (intstatus == (uint32)-1 || intmask == (uint32)-1) {
			DHD_ERROR(("%s: Device is removed or Link is down.\n", __FUNCTION__));
			DHD_ERROR(("%s: INTSTAT : 0x%x INTMASK : 0x%x.\n",
			    __FUNCTION__, intstatus, intmask));
			bus->is_linkdown = TRUE;
			dhd_pcie_debug_info_dump(bus->dhd);
			return intstatus;
		}

#ifndef DHD_READ_INTSTATUS_IN_DPC
		intstatus &= intmask;
#endif /* DHD_READ_INTSTATUS_IN_DPC */

		/*
		 * The fourth argument to si_corereg is the "mask" fields of the register to update
		 * and the fifth field is the "value" to update. Now if we are interested in only
		 * few fields of the "mask" bit map, we should not be writing back what we read
		 * By doing so, we might clear/ack interrupts that are not handled yet.
		 */
		si_corereg(bus->sih, bus->sih->buscoreidx, bus->pcie_mailbox_int, bus->def_intmask,
			intstatus);

		intstatus &= bus->def_intmask;
	}

	return intstatus;
}

void
dhdpcie_cto_recovery_handler(dhd_pub_t *dhd)
{
	dhd_bus_t *bus = dhd->bus;
	int ret;

	/* Disable PCIe Runtime PM to avoid D3_ACK timeout.
	 */
	DHD_DISABLE_RUNTIME_PM(dhd);

	/* Sleep for 1 seconds so that any AXI timeout
	 * if running on ALP clock also will be captured
	 */
	OSL_SLEEP(1000);

	/* reset backplane and cto,
	 * then access through pcie is recovered.
	 */
	ret = dhdpcie_cto_error_recovery(bus);
	if (!ret) {
		/* Waiting for backplane reset */
		OSL_SLEEP(10);
		/* Dump debug Info */
		dhd_prot_debug_info_print(bus->dhd);
		/* Dump console buffer */
		dhd_bus_dump_console_buffer(bus);
#if defined(DHD_FW_COREDUMP)
		/* save core dump or write to a file */
		if (!bus->is_linkdown && bus->dhd->memdump_enabled) {
#ifdef DHD_SSSR_DUMP
			bus->dhd->collect_sssr = TRUE;
#endif /* DHD_SSSR_DUMP */
			bus->dhd->memdump_type = DUMP_TYPE_CTO_RECOVERY;
			dhdpcie_mem_dump(bus);
		}
#endif /* DHD_FW_COREDUMP */
	}
	bus->is_linkdown = TRUE;
	bus->dhd->hang_reason = HANG_REASON_PCIE_CTO_DETECT;
	/* Send HANG event */
	dhd_os_send_hang_message(bus->dhd);
}

/**
 * Name:  dhdpcie_bus_isr
 * Parameters:
 * 1: IN int irq   -- interrupt vector
 * 2: IN void *arg      -- handle to private data structure
 * Return value:
 * Status (TRUE or FALSE)
 *
 * Description:
 * Interrupt Service routine checks for the status register,
 * disable interrupt and queue DPC if mail box interrupts are raised.
 */
int32
dhdpcie_bus_isr(dhd_bus_t *bus)
{
	uint32 intstatus = 0;

	do {
		DHD_INTR(("%s: Enter\n", __FUNCTION__));
		/* verify argument */
		if (!bus) {
			DHD_LOG_MEM(("%s : bus is null pointer, exit \n", __FUNCTION__));
			break;
		}

		if (bus->dhd->dongle_reset) {
			DHD_LOG_MEM(("%s : dongle is reset\n", __FUNCTION__));
			break;
		}

		if (bus->dhd->busstate == DHD_BUS_DOWN) {
			DHD_LOG_MEM(("%s : bus is down \n", __FUNCTION__));
			break;
		}

		/* avoid processing of interrupts until msgbuf prot is inited */
		if (!bus->intr_enabled) {
			DHD_INFO(("%s, not ready to receive interrupts\n", __FUNCTION__));
			break;
		}

		if (PCIECTO_ENAB(bus)) {
			/* read pci_intstatus */
			intstatus = dhdpcie_bus_cfg_read_dword(bus, PCI_INT_STATUS, 4);

			if (intstatus == (uint32)-1) {
				DHD_ERROR(("%s : Invalid intstatus for cto recovery\n",
					__FUNCTION__));
				dhdpcie_disable_irq_nosync(bus);
				break;
			}

			if (intstatus & PCI_CTO_INT_MASK) {
				DHD_ERROR(("%s: ##### CTO RECOVERY REPORTED BY DONGLE "
					"intstat=0x%x enab=%d\n", __FUNCTION__,
					intstatus, bus->cto_enable));
				bus->cto_triggered = 1;
				/*
				 * DAR still accessible
				 */
				dhd_bus_dump_dar_registers(bus);

				/* Disable further PCIe interrupts */
				dhdpcie_disable_irq_nosync(bus); /* Disable interrupt!! */
				/* Stop Tx flow */
				dhd_bus_stop_queue(bus);

				/* Schedule CTO recovery */
				dhd_schedule_cto_recovery(bus->dhd);

				return TRUE;
			}
		}

		if (bus->d2h_intr_method == PCIE_MSI &&
				!dhd_conf_legacy_msi_chip(bus->dhd)) {
			/* For MSI, as intstatus is cleared by firmware, no need to read */
			goto skip_intstatus_read;
		}

#ifndef DHD_READ_INTSTATUS_IN_DPC
		intstatus = dhdpcie_bus_intstatus(bus);

		/* Check if the interrupt is ours or not */
		if (intstatus == 0) {
			/* in EFI since we poll for interrupt, this message will flood the logs
			* so disable this for EFI
			*/
			DHD_LOG_MEM(("%s : this interrupt is not ours\n", __FUNCTION__));
			bus->non_ours_irq_count++;
			bus->last_non_ours_irq_time = OSL_LOCALTIME_NS();
			break;
		}

		/* save the intstatus */
		/* read interrupt status register!! Status bits will be cleared in DPC !! */
		bus->intstatus = intstatus;

		/* return error for 0xFFFFFFFF */
		if (intstatus == (uint32)-1) {
			DHD_LOG_MEM(("%s : wrong interrupt status val : 0x%x\n",
				__FUNCTION__, intstatus));
			dhdpcie_disable_irq_nosync(bus);
			break;
		}

skip_intstatus_read:
		/*  Overall operation:
		 *    - Mask further interrupts
		 *    - Read/ack intstatus
		 *    - Take action based on bits and state
		 *    - Reenable interrupts (as per state)
		 */

		/* Count the interrupt call */
		bus->intrcount++;
#endif /* DHD_READ_INTSTATUS_IN_DPC */

		bus->ipend = TRUE;

		bus->isr_intr_disable_count++;

#ifdef CHIP_INTR_CONTROL
		dhdpcie_bus_intr_disable(bus); /* Disable interrupt using IntMask!! */
#else
		/* For Linux, Macos etc (otherthan NDIS) instead of disabling
		* dongle interrupt by clearing the IntMask, disable directly
		* interrupt from the host side, so that host will not recieve
		* any interrupts at all, even though dongle raises interrupts
		*/
		dhdpcie_disable_irq_nosync(bus); /* Disable interrupt!! */
#endif /* HOST_INTR_CONTROL */

		bus->intdis = TRUE;

#if defined(PCIE_ISR_THREAD)

		DHD_TRACE(("Calling dhd_bus_dpc() from %s\n", __FUNCTION__));
		DHD_OS_WAKE_LOCK(bus->dhd);
		while (dhd_bus_dpc(bus));
		DHD_OS_WAKE_UNLOCK(bus->dhd);
#else
		bus->dpc_sched = TRUE;
		dhd_sched_dpc(bus->dhd);     /* queue DPC now!! */
#endif /* defined(SDIO_ISR_THREAD) */

		DHD_INTR(("%s: Exit Success DPC Queued\n", __FUNCTION__));
		return TRUE;

	} while (0);

	DHD_INTR(("%s: Exit Failure\n", __FUNCTION__));
	return FALSE;
}

int
dhdpcie_set_pwr_state(dhd_bus_t *bus, uint state)
{
	uint32 cur_state = 0;
	uint32 pm_csr = 0;
	osl_t *osh = bus->osh;

	pm_csr = OSL_PCI_READ_CONFIG(osh, PCIECFGREG_PM_CSR, sizeof(uint32));
	cur_state = pm_csr & PCIECFGREG_PM_CSR_STATE_MASK;

	if (cur_state == state) {
		DHD_ERROR(("%s: Already in state %u \n", __FUNCTION__, cur_state));
		return BCME_OK;
	}

	if (state > PCIECFGREG_PM_CSR_STATE_D3_HOT)
		return BCME_ERROR;

	/* Validate the state transition
	* if already in a lower power state, return error
	*/
	if (state != PCIECFGREG_PM_CSR_STATE_D0 &&
			cur_state <= PCIECFGREG_PM_CSR_STATE_D3_COLD &&
			cur_state > state) {
		DHD_ERROR(("%s: Invalid power state transition !\n", __FUNCTION__));
		return BCME_ERROR;
	}

	pm_csr &= ~PCIECFGREG_PM_CSR_STATE_MASK;
	pm_csr |= state;

	OSL_PCI_WRITE_CONFIG(osh, PCIECFGREG_PM_CSR, sizeof(uint32), pm_csr);

	/* need to wait for the specified mandatory pcie power transition delay time */
	if (state == PCIECFGREG_PM_CSR_STATE_D3_HOT ||
			cur_state == PCIECFGREG_PM_CSR_STATE_D3_HOT)
			OSL_DELAY(DHDPCIE_PM_D3_DELAY);
	else if (state == PCIECFGREG_PM_CSR_STATE_D2 ||
			cur_state == PCIECFGREG_PM_CSR_STATE_D2)
			OSL_DELAY(DHDPCIE_PM_D2_DELAY);

	/* read back the power state and verify */
	pm_csr = OSL_PCI_READ_CONFIG(osh, PCIECFGREG_PM_CSR, sizeof(uint32));
	cur_state = pm_csr & PCIECFGREG_PM_CSR_STATE_MASK;
	if (cur_state != state) {
		DHD_ERROR(("%s: power transition failed ! Current state is %u \n",
				__FUNCTION__, cur_state));
		return BCME_ERROR;
	} else {
		DHD_ERROR(("%s: power transition to %u success \n",
				__FUNCTION__, cur_state));
	}

	return BCME_OK;
}

int
dhdpcie_config_check(dhd_bus_t *bus)
{
	uint32 i, val;
	int ret = BCME_ERROR;

	for (i = 0; i < DHDPCIE_CONFIG_CHECK_RETRY_COUNT; i++) {
		val = OSL_PCI_READ_CONFIG(bus->osh, PCI_CFG_VID, sizeof(uint32));
		if ((val & 0xFFFF) == VENDOR_BROADCOM) {
			ret = BCME_OK;
			break;
		}
		OSL_DELAY(DHDPCIE_CONFIG_CHECK_DELAY_MS * 1000);
	}

	return ret;
}

int
dhdpcie_config_restore(dhd_bus_t *bus, bool restore_pmcsr)
{
	uint32 i;
	osl_t *osh = bus->osh;

	if (BCME_OK != dhdpcie_config_check(bus)) {
		return BCME_ERROR;
	}

	for (i = PCI_CFG_REV >> 2; i < DHDPCIE_CONFIG_HDR_SIZE; i++) {
		OSL_PCI_WRITE_CONFIG(osh, i << 2, sizeof(uint32), bus->saved_config.header[i]);
	}
	OSL_PCI_WRITE_CONFIG(osh, PCI_CFG_CMD, sizeof(uint32), bus->saved_config.header[1]);

	if (restore_pmcsr)
		OSL_PCI_WRITE_CONFIG(osh, PCIECFGREG_PM_CSR,
			sizeof(uint32), bus->saved_config.pmcsr);

	OSL_PCI_WRITE_CONFIG(osh, PCIECFGREG_MSI_CAP, sizeof(uint32), bus->saved_config.msi_cap);
	OSL_PCI_WRITE_CONFIG(osh, PCIECFGREG_MSI_ADDR_L, sizeof(uint32),
			bus->saved_config.msi_addr0);
	OSL_PCI_WRITE_CONFIG(osh, PCIECFGREG_MSI_ADDR_H,
			sizeof(uint32), bus->saved_config.msi_addr1);
	OSL_PCI_WRITE_CONFIG(osh, PCIECFGREG_MSI_DATA,
			sizeof(uint32), bus->saved_config.msi_data);

	OSL_PCI_WRITE_CONFIG(osh, PCIECFGREG_DEV_STATUS_CTRL,
			sizeof(uint32), bus->saved_config.exp_dev_ctrl_stat);
	OSL_PCI_WRITE_CONFIG(osh, PCIECFGGEN_DEV_STATUS_CTRL2,
			sizeof(uint32), bus->saved_config.exp_dev_ctrl_stat2);
	OSL_PCI_WRITE_CONFIG(osh, PCIECFGREG_LINK_STATUS_CTRL,
			sizeof(uint32), bus->saved_config.exp_link_ctrl_stat);
	OSL_PCI_WRITE_CONFIG(osh, PCIECFGREG_LINK_STATUS_CTRL2,
			sizeof(uint32), bus->saved_config.exp_link_ctrl_stat2);

	OSL_PCI_WRITE_CONFIG(osh, PCIECFGREG_PML1_SUB_CTRL1,
			sizeof(uint32), bus->saved_config.l1pm0);
	OSL_PCI_WRITE_CONFIG(osh, PCIECFGREG_PML1_SUB_CTRL2,
			sizeof(uint32), bus->saved_config.l1pm1);

	OSL_PCI_WRITE_CONFIG(bus->osh, PCI_BAR0_WIN, sizeof(uint32),
			bus->saved_config.bar0_win);
	dhdpcie_setbar1win(bus, bus->saved_config.bar1_win);

	return BCME_OK;
}

int
dhdpcie_config_save(dhd_bus_t *bus)
{
	uint32 i;
	osl_t *osh = bus->osh;

	if (BCME_OK != dhdpcie_config_check(bus)) {
		return BCME_ERROR;
	}

	for (i = 0; i < DHDPCIE_CONFIG_HDR_SIZE; i++) {
		bus->saved_config.header[i] = OSL_PCI_READ_CONFIG(osh, i << 2, sizeof(uint32));
	}

	bus->saved_config.pmcsr = OSL_PCI_READ_CONFIG(osh, PCIECFGREG_PM_CSR, sizeof(uint32));

	bus->saved_config.msi_cap = OSL_PCI_READ_CONFIG(osh, PCIECFGREG_MSI_CAP,
			sizeof(uint32));
	bus->saved_config.msi_addr0 = OSL_PCI_READ_CONFIG(osh, PCIECFGREG_MSI_ADDR_L,
			sizeof(uint32));
	bus->saved_config.msi_addr1 = OSL_PCI_READ_CONFIG(osh, PCIECFGREG_MSI_ADDR_H,
			sizeof(uint32));
	bus->saved_config.msi_data = OSL_PCI_READ_CONFIG(osh, PCIECFGREG_MSI_DATA,
			sizeof(uint32));

	bus->saved_config.exp_dev_ctrl_stat = OSL_PCI_READ_CONFIG(osh,
			PCIECFGREG_DEV_STATUS_CTRL, sizeof(uint32));
	bus->saved_config.exp_dev_ctrl_stat2 = OSL_PCI_READ_CONFIG(osh,
			PCIECFGGEN_DEV_STATUS_CTRL2, sizeof(uint32));
	bus->saved_config.exp_link_ctrl_stat = OSL_PCI_READ_CONFIG(osh,
			PCIECFGREG_LINK_STATUS_CTRL, sizeof(uint32));
	bus->saved_config.exp_link_ctrl_stat2 = OSL_PCI_READ_CONFIG(osh,
			PCIECFGREG_LINK_STATUS_CTRL2, sizeof(uint32));

	bus->saved_config.l1pm0 = OSL_PCI_READ_CONFIG(osh, PCIECFGREG_PML1_SUB_CTRL1,
			sizeof(uint32));
	bus->saved_config.l1pm1 = OSL_PCI_READ_CONFIG(osh, PCIECFGREG_PML1_SUB_CTRL2,
			sizeof(uint32));

	bus->saved_config.bar0_win = OSL_PCI_READ_CONFIG(osh, PCI_BAR0_WIN,
			sizeof(uint32));
	bus->saved_config.bar1_win = OSL_PCI_READ_CONFIG(osh, PCI_BAR1_WIN,
			sizeof(uint32));

	return BCME_OK;
}

#ifdef EXYNOS_PCIE_LINKDOWN_RECOVERY
dhd_pub_t *link_recovery = NULL;
#endif /* EXYNOS_PCIE_LINKDOWN_RECOVERY */

static void
dhdpcie_bus_intr_init(dhd_bus_t *bus)
{
	uint buscorerev = bus->sih->buscorerev;
	bus->pcie_mailbox_int = PCIMailBoxInt(buscorerev);
	bus->pcie_mailbox_mask = PCIMailBoxMask(buscorerev);
	bus->d2h_mb_mask = PCIE_MB_D2H_MB_MASK(buscorerev);
	bus->def_intmask = PCIE_MB_D2H_MB_MASK(buscorerev);
	if (buscorerev < 64) {
		bus->def_intmask |= PCIE_MB_TOPCIE_FN0_0 | PCIE_MB_TOPCIE_FN0_1;
	}
}

static void
dhdpcie_cc_watchdog_reset(dhd_bus_t *bus)
{
	uint32 wd_en = (bus->sih->buscorerev >= 66) ? WD_SSRESET_PCIE_F0_EN :
		(WD_SSRESET_PCIE_F0_EN | WD_SSRESET_PCIE_ALL_FN_EN);
	pcie_watchdog_reset(bus->osh, bus->sih, WD_ENABLE_MASK, wd_en);
}

void
dhdpcie_dongle_reset(dhd_bus_t *bus)
{
	/* if the pcie link is down, watchdog reset
	 * should not be done, as it may hang
	 */
	if (bus->is_linkdown) {
		return;
	}

	/* dhd_bus_perform_flr will return BCME_UNSUPPORTED if chip is not FLR capable */
	if (dhd_bus_perform_flr(bus, FALSE) == BCME_UNSUPPORTED) {
#ifdef DHD_USE_BP_RESET
		/* Backplane reset using SPROM cfg register(0x88) for buscorerev <= 24 */
		dhd_bus_perform_bp_reset(bus);
#else
		/* Legacy chipcommon watchdog reset */
		dhdpcie_cc_watchdog_reset(bus);
#endif /* DHD_USE_BP_RESET */
	}
}

static bool
dhdpcie_dongle_attach(dhd_bus_t *bus)
{
	osl_t *osh = bus->osh;
	volatile void *regsva = (volatile void*)bus->regs;
	uint16 devid;
	uint32 val;
	sbpcieregs_t *sbpcieregs;
	bool dongle_isolation;

	DHD_TRACE(("%s: ENTER\n", __FUNCTION__));

#ifdef EXYNOS_PCIE_LINKDOWN_RECOVERY
	link_recovery = bus->dhd;
#endif /* EXYNOS_PCIE_LINKDOWN_RECOVERY */

	bus->alp_only = TRUE;
	bus->sih = NULL;

	/* Checking PCIe bus status with reading configuration space */
	val = OSL_PCI_READ_CONFIG(osh, PCI_CFG_VID, sizeof(uint32));
	if ((val & 0xFFFF) != VENDOR_BROADCOM) {
		DHD_ERROR(("%s : failed to read PCI configuration space!\n", __FUNCTION__));
		goto fail;
	}
	devid = (val >> 16) & 0xFFFF;
	bus->cl_devid = devid;

	/* Set bar0 window to si_enum_base */
	dhdpcie_bus_cfg_set_bar0_win(bus, si_enum_base(devid));

	/*
	 * Checking PCI_SPROM_CONTROL register for preventing invalid address access
	 * due to switch address space from PCI_BUS to SI_BUS.
	 */
	val = OSL_PCI_READ_CONFIG(osh, PCI_SPROM_CONTROL, sizeof(uint32));
	if (val == 0xffffffff) {
		DHD_ERROR(("%s : failed to read SPROM control register\n", __FUNCTION__));
		goto fail;
	}

	/* si_attach() will provide an SI handle and scan the backplane */
	if (!(bus->sih = si_attach((uint)devid, osh, regsva, PCI_BUS, bus,
	                           &bus->vars, &bus->varsz))) {
		DHD_ERROR(("%s: si_attach failed!\n", __FUNCTION__));
		goto fail;
	}

	/* Configure CTO Prevention functionality */
#if defined(BCMFPGA_HW)
	DHD_ERROR(("Disable CTO\n"));
	bus->cto_enable = FALSE;
#else
#if defined(BCMPCIE_CTO_PREVENTION)
	if (bus->sih->buscorerev >= 24) {
		DHD_ERROR(("Enable CTO\n"));
		bus->cto_enable = TRUE;
	} else
#endif /* BCMPCIE_CTO_PREVENTION */
	{
		DHD_ERROR(("Disable CTO\n"));
		bus->cto_enable = FALSE;
	}
#endif /* BCMFPGA_HW */

	if (PCIECTO_ENAB(bus)) {
		dhdpcie_cto_init(bus, TRUE);
	}

	if (MULTIBP_ENAB(bus->sih) && (bus->sih->buscorerev >= 66)) {
		/*
		 * HW JIRA - CRWLPCIEGEN2-672
		 * Producer Index Feature which is used by F1 gets reset on F0 FLR
		 * fixed in REV68
		 */
		if (PCIE_ENUM_RESET_WAR_ENAB(bus->sih->buscorerev)) {
			dhdpcie_ssreset_dis_enum_rst(bus);
		}

		/* IOV_DEVRESET could exercise si_detach()/si_attach() again so reset
		*   dhdpcie_bus_release_dongle() --> si_detach()
		*   dhdpcie_dongle_attach() --> si_attach()
		*/
		bus->pwr_req_ref = 0;
	}

	if (MULTIBP_ENAB(bus->sih)) {
		dhd_bus_pcie_pwr_req_nolock(bus);
	}

	/* Get info on the ARM and SOCRAM cores... */
	/* Should really be qualified by device id */
	if ((si_setcore(bus->sih, ARM7S_CORE_ID, 0)) ||
	    (si_setcore(bus->sih, ARMCM3_CORE_ID, 0)) ||
	    (si_setcore(bus->sih, ARMCR4_CORE_ID, 0)) ||
	    (si_setcore(bus->sih, ARMCA7_CORE_ID, 0))) {
		bus->armrev = si_corerev(bus->sih);
		bus->coreid = si_coreid(bus->sih);
	} else {
		DHD_ERROR(("%s: failed to find ARM core!\n", __FUNCTION__));
		goto fail;
	}

	/* CA7 requires coherent bits on */
	if (bus->coreid == ARMCA7_CORE_ID) {
		val = dhdpcie_bus_cfg_read_dword(bus, PCIE_CFG_SUBSYSTEM_CONTROL, 4);
		dhdpcie_bus_cfg_write_dword(bus, PCIE_CFG_SUBSYSTEM_CONTROL, 4,
			(val | PCIE_BARCOHERENTACCEN_MASK));
	}

	/* Olympic EFI requirement - stop driver load if FW is already running
	*  need to do this here before pcie_watchdog_reset, because
	*  pcie_watchdog_reset will put the ARM back into halt state
	*/
	if (!dhdpcie_is_arm_halted(bus)) {
		DHD_ERROR(("%s: ARM is not halted,FW is already running! Abort.\n",
				__FUNCTION__));
		goto fail;
	}

	BCM_REFERENCE(dongle_isolation);

	/* For inbuilt drivers pcie clk req will be done by RC,
	 * so do not do clkreq from dhd
	 */
	if (dhd_download_fw_on_driverload)
	{
		/* Enable CLKREQ# */
		dhdpcie_clkreq(bus->osh, 1, 1);
	}

	/*
	 * bus->dhd will be NULL if it is called from dhd_bus_attach, so need to reset
	 * without checking dongle_isolation flag, but if it is called via some other path
	 * like quiesce FLR, then based on dongle_isolation flag, watchdog_reset should
	 * be called.
	 */
	if (bus->dhd == NULL) {
		/* dhd_attach not yet happened, do watchdog reset */
		dongle_isolation = FALSE;
	} else {
		dongle_isolation = bus->dhd->dongle_isolation;
	}

#ifndef DHD_SKIP_DONGLE_RESET_IN_ATTACH
	/*
	 * Issue CC watchdog to reset all the cores on the chip - similar to rmmod dhd
	 * This is required to avoid spurious interrupts to the Host and bring back
	 * dongle to a sane state (on host soft-reboot / watchdog-reboot).
	 */
	if (dongle_isolation == FALSE) {
		dhdpcie_dongle_reset(bus);
	}
#endif /* !DHD_SKIP_DONGLE_RESET_IN_ATTACH */

	/* need to set the force_bt_quiesce flag here
	 * before calling dhdpcie_dongle_flr_or_pwr_toggle
	 */
	bus->force_bt_quiesce = TRUE;
	/*
	 * For buscorerev = 66 and after, F0 FLR should be done independent from F1.
	 * So don't need BT quiesce.
	 */
	if (bus->sih->buscorerev >= 66) {
		bus->force_bt_quiesce = FALSE;
	}

	dhdpcie_dongle_flr_or_pwr_toggle(bus);

	si_setcore(bus->sih, PCIE2_CORE_ID, 0);
	sbpcieregs = (sbpcieregs_t*)(bus->regs);

	/* WAR where the BAR1 window may not be sized properly */
	W_REG(osh, &sbpcieregs->configaddr, 0x4e0);
	val = R_REG(osh, &sbpcieregs->configdata);
	W_REG(osh, &sbpcieregs->configdata, val);

	if (si_setcore(bus->sih, SYSMEM_CORE_ID, 0)) {
		/* Only set dongle RAMSIZE to default value when BMC vs ARM usage of SYSMEM is not
		 * adjusted.
		 */
		if (!bus->ramsize_adjusted) {
			if (!(bus->orig_ramsize = si_sysmem_size(bus->sih))) {
				DHD_ERROR(("%s: failed to find SYSMEM memory!\n", __FUNCTION__));
				goto fail;
			}
			switch ((uint16)bus->sih->chip) {
				default:
					/* also populate base address */
					bus->dongle_ram_base = CA7_4365_RAM_BASE;
					bus->orig_ramsize = 0x1c0000; /* Reserve 1.75MB for CA7 */
					break;
			}
		}
	} else if (!si_setcore(bus->sih, ARMCR4_CORE_ID, 0)) {
		if (!(bus->orig_ramsize = si_socram_size(bus->sih))) {
			DHD_ERROR(("%s: failed to find SOCRAM memory!\n", __FUNCTION__));
			goto fail;
		}
	} else {
		/* cr4 has a different way to find the RAM size from TCM's */
		if (!(bus->orig_ramsize = si_tcm_size(bus->sih))) {
			DHD_ERROR(("%s: failed to find CR4-TCM memory!\n", __FUNCTION__));
			goto fail;
		}
		/* also populate base address */
		switch ((uint16)bus->sih->chip) {
		case BCM4339_CHIP_ID:
		case BCM4335_CHIP_ID:
			bus->dongle_ram_base = CR4_4335_RAM_BASE;
			break;
		case BCM4358_CHIP_ID:
		case BCM4354_CHIP_ID:
		case BCM43567_CHIP_ID:
		case BCM43569_CHIP_ID:
		case BCM4350_CHIP_ID:
		case BCM43570_CHIP_ID:
			bus->dongle_ram_base = CR4_4350_RAM_BASE;
			break;
		case BCM4360_CHIP_ID:
			bus->dongle_ram_base = CR4_4360_RAM_BASE;
			break;

		case BCM4364_CHIP_ID:
			bus->dongle_ram_base = CR4_4364_RAM_BASE;
			break;

		CASE_BCM4345_CHIP:
			bus->dongle_ram_base = (bus->sih->chiprev < 6)  /* changed at 4345C0 */
				? CR4_4345_LT_C0_RAM_BASE : CR4_4345_GE_C0_RAM_BASE;
			break;
		CASE_BCM43602_CHIP:
			bus->dongle_ram_base = CR4_43602_RAM_BASE;
			break;
		case BCM4349_CHIP_GRPID:
			/* RAM based changed from 4349c0(revid=9) onwards */
			bus->dongle_ram_base = ((bus->sih->chiprev < 9) ?
				CR4_4349_RAM_BASE : CR4_4349_RAM_BASE_FROM_REV_9);
			break;
		case BCM4347_CHIP_ID:
		case BCM4357_CHIP_ID:
		case BCM4361_CHIP_ID:
			bus->dongle_ram_base = CR4_4347_RAM_BASE;
			break;
		case BCM4362_CHIP_ID:
			bus->dongle_ram_base = CR4_4362_RAM_BASE;
			break;
		case BCM43751_CHIP_ID:
			bus->dongle_ram_base = CR4_43751_RAM_BASE;
			break;
		case BCM43752_CHIP_ID:
			bus->dongle_ram_base = CR4_43752_RAM_BASE;
			break;
		case BCM4375_CHIP_ID:
		case BCM4369_CHIP_ID:
			bus->dongle_ram_base = CR4_4369_RAM_BASE;
			break;
		default:
			bus->dongle_ram_base = 0;
			DHD_ERROR(("%s: WARNING: Using default ram base at 0x%x\n",
			           __FUNCTION__, bus->dongle_ram_base));
		}
	}
	bus->ramsize = bus->orig_ramsize;
	if (dhd_dongle_memsize)
		dhdpcie_bus_dongle_setmemsize(bus, dhd_dongle_memsize);

	if (bus->ramsize > DONGLE_TCM_MAP_SIZE) {
		DHD_ERROR(("%s : invalid ramsize %d(0x%x) is returned from dongle\n",
				__FUNCTION__, bus->ramsize, bus->ramsize));
		goto fail;
	}

	DHD_ERROR(("DHD: dongle ram size is set to %d(orig %d) at 0x%x\n",
	           bus->ramsize, bus->orig_ramsize, bus->dongle_ram_base));

	bus->srmemsize = si_socram_srmem_size(bus->sih);

	dhdpcie_bus_intr_init(bus);

	/* Set the poll and/or interrupt flags */
	bus->intr = (bool)dhd_intr;
	if ((bus->poll = (bool)dhd_poll))
		bus->pollrate = 1;
#ifdef DHD_DISABLE_ASPM
	dhd_bus_aspm_enable_rc_ep(bus, FALSE);
#endif /* DHD_DISABLE_ASPM */

	bus->idma_enabled = TRUE;
	bus->ifrm_enabled = TRUE;
	DHD_TRACE(("%s: EXIT: SUCCESS\n", __FUNCTION__));

	if (MULTIBP_ENAB(bus->sih)) {
		dhd_bus_pcie_pwr_req_clear_nolock(bus);

		/*
		 * One time clearing of Common Power Domain since HW default is set
		 * Needs to be after FLR because FLR resets PCIe enum back to HW defaults
		 * for 4378B0 (rev 68).
		 * On 4378A0 (rev 66), PCIe enum reset is disabled due to CRWLPCIEGEN2-672
		 */
		si_srpwr_request(bus->sih, SRPWR_DMN0_PCIE_MASK, 0);

		/*
		 * WAR to fix ARM cold boot;
		 * Assert WL domain in DAR helps but not enum
		 */
		if (bus->sih->buscorerev >= 68) {
			dhd_bus_pcie_pwr_req_wl_domain(bus,
				DAR_PCIE_PWR_CTRL((bus->sih)->buscorerev), TRUE);
		}
	}

	return 0;

fail:
	if (bus->sih != NULL) {
		if (MULTIBP_ENAB(bus->sih)) {
			dhd_bus_pcie_pwr_req_clear_nolock(bus);
		}
		/* for EFI even if there is an error, load still succeeds
		* so si_detach should not be called here, it is called during unload
		*/
		si_detach(bus->sih);
		bus->sih = NULL;
	}
	DHD_TRACE(("%s: EXIT: FAILURE\n", __FUNCTION__));
	return -1;
}

int
dhpcie_bus_unmask_interrupt(dhd_bus_t *bus)
{
	dhdpcie_bus_cfg_write_dword(bus, PCIIntmask, 4, I_MB);
	return 0;
}
int
dhpcie_bus_mask_interrupt(dhd_bus_t *bus)
{
	dhdpcie_bus_cfg_write_dword(bus, PCIIntmask, 4, 0x0);
	return 0;
}

/* Non atomic function, caller should hold appropriate lock */
void
dhdpcie_bus_intr_enable(dhd_bus_t *bus)
{
	DHD_TRACE(("%s Enter\n", __FUNCTION__));
	if (bus) {
		if (bus->sih && !bus->is_linkdown) {
			/* Skip after recieving D3 ACK */
			if (bus->bus_low_power_state == DHD_BUS_D3_ACK_RECIEVED) {
				return;
			}
			if ((bus->sih->buscorerev == 2) || (bus->sih->buscorerev == 6) ||
				(bus->sih->buscorerev == 4)) {
				dhpcie_bus_unmask_interrupt(bus);
			} else {
	#if defined(BCMINTERNAL) && defined(DHD_DBG_DUMP)
				dhd_bus_mmio_trace(bus, bus->pcie_mailbox_mask,
					bus->def_intmask, TRUE);
	#endif
				si_corereg(bus->sih, bus->sih->buscoreidx, bus->pcie_mailbox_mask,
					bus->def_intmask, bus->def_intmask);
			}
		}

	}

	DHD_TRACE(("%s Exit\n", __FUNCTION__));
}

/* Non atomic function, caller should hold appropriate lock */
void
dhdpcie_bus_intr_disable(dhd_bus_t *bus)
{
	DHD_TRACE(("%s Enter\n", __FUNCTION__));
	if (bus && bus->sih && !bus->is_linkdown) {
		/* Skip after recieving D3 ACK */
		if (bus->bus_low_power_state == DHD_BUS_D3_ACK_RECIEVED) {
			return;
		}
		if ((bus->sih->buscorerev == 2) || (bus->sih->buscorerev == 6) ||
			(bus->sih->buscorerev == 4)) {
			dhpcie_bus_mask_interrupt(bus);
		} else {
			si_corereg(bus->sih, bus->sih->buscoreidx, bus->pcie_mailbox_mask,
				bus->def_intmask, 0);
		}
	}

	DHD_TRACE(("%s Exit\n", __FUNCTION__));
}

/*
 *  dhdpcie_advertise_bus_cleanup advertises that clean up is under progress
 * to other bus user contexts like Tx, Rx, IOVAR, WD etc and it waits for other contexts
 * to gracefully exit. All the bus usage contexts before marking busstate as busy, will check for
 * whether the busstate is DHD_BUS_DOWN or DHD_BUS_DOWN_IN_PROGRESS, if so
 * they will exit from there itself without marking dhd_bus_busy_state as BUSY.
 */
void
dhdpcie_advertise_bus_cleanup(dhd_pub_t	 *dhdp)
{
	unsigned long flags;
	int timeleft;

	dhdp->dhd_watchdog_ms_backup = dhd_watchdog_ms;
	if (dhdp->dhd_watchdog_ms_backup) {
		DHD_ERROR(("%s: Disabling wdtick before dhd deinit\n",
			__FUNCTION__));
		dhd_os_wd_timer(dhdp, 0);
	}
	if (dhdp->busstate != DHD_BUS_DOWN) {
		DHD_GENERAL_LOCK(dhdp, flags);
		dhdp->busstate = DHD_BUS_DOWN_IN_PROGRESS;
		DHD_GENERAL_UNLOCK(dhdp, flags);
	}

	timeleft = dhd_os_busbusy_wait_negation(dhdp, &dhdp->dhd_bus_busy_state);
	if ((timeleft == 0) || (timeleft == 1)) {
		DHD_ERROR(("%s : Timeout due to dhd_bus_busy_state=0x%x\n",
				__FUNCTION__, dhdp->dhd_bus_busy_state));
		ASSERT(0);
	}

	return;
}

static void
dhdpcie_advertise_bus_remove(dhd_pub_t	 *dhdp)
{
	unsigned long flags;
	int timeleft;

	DHD_GENERAL_LOCK(dhdp, flags);
	dhdp->busstate = DHD_BUS_REMOVE;
	DHD_GENERAL_UNLOCK(dhdp, flags);

	timeleft = dhd_os_busbusy_wait_negation(dhdp, &dhdp->dhd_bus_busy_state);
	if ((timeleft == 0) || (timeleft == 1)) {
		DHD_ERROR(("%s : Timeout due to dhd_bus_busy_state=0x%x\n",
				__FUNCTION__, dhdp->dhd_bus_busy_state));
		ASSERT(0);
	}

	return;
}

static void
dhdpcie_bus_remove_prep(dhd_bus_t *bus)
{
	unsigned long flags;
	DHD_TRACE(("%s Enter\n", __FUNCTION__));

	DHD_GENERAL_LOCK(bus->dhd, flags);
	DHD_ERROR(("%s: making DHD_BUS_DOWN\n", __FUNCTION__));
	bus->dhd->busstate = DHD_BUS_DOWN;
	DHD_GENERAL_UNLOCK(bus->dhd, flags);

	dhd_os_sdlock(bus->dhd);

	if (bus->sih && !bus->dhd->dongle_isolation) {
		if (PCIE_RELOAD_WAR_ENAB(bus->sih->buscorerev)) {
			dhd_bus_pcie_pwr_req_reload_war(bus);
		}

		/* Has insmod fails after rmmod issue in Brix Android */

		/* if the pcie link is down, watchdog reset
		* should not be done, as it may hang
		*/

		if (!bus->is_linkdown) {
#ifndef DHD_SKIP_DONGLE_RESET_IN_ATTACH
			/* for efi, depending on bt over pcie mode
			*  we either power toggle or do F0 FLR
			* from dhdpcie_bus_release dongle. So no need to
			* do dongle reset from here
			*/
			dhdpcie_dongle_reset(bus);
#endif /* !DHD_SKIP_DONGLE_RESET_IN_ATTACH */
		}

		bus->dhd->is_pcie_watchdog_reset = TRUE;
	}

	dhd_os_sdunlock(bus->dhd);

	DHD_TRACE(("%s Exit\n", __FUNCTION__));
}

void
dhd_init_bus_lock(dhd_bus_t *bus)
{
	if (!bus->bus_lock) {
		bus->bus_lock = dhd_os_spin_lock_init(bus->dhd->osh);
	}
}

void
dhd_deinit_bus_lock(dhd_bus_t *bus)
{
	if (bus->bus_lock) {
		dhd_os_spin_lock_deinit(bus->dhd->osh, bus->bus_lock);
		bus->bus_lock = NULL;
	}
}

void
dhd_init_backplane_access_lock(dhd_bus_t *bus)
{
	if (!bus->backplane_access_lock) {
		bus->backplane_access_lock = dhd_os_spin_lock_init(bus->dhd->osh);
	}
}

void
dhd_deinit_backplane_access_lock(dhd_bus_t *bus)
{
	if (bus->backplane_access_lock) {
		dhd_os_spin_lock_deinit(bus->dhd->osh, bus->backplane_access_lock);
		bus->backplane_access_lock = NULL;
	}
}

/** Detach and free everything */
void
dhdpcie_bus_release(dhd_bus_t *bus)
{
	bool dongle_isolation = FALSE;
	osl_t *osh = NULL;
	unsigned long flags_bus;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (bus) {

		osh = bus->osh;
		ASSERT(osh);

		if (bus->dhd) {
#if defined(DEBUGGER) || defined(DHD_DSCOPE)
			debugger_close();
#endif /* DEBUGGER || DHD_DSCOPE */
			dhdpcie_advertise_bus_remove(bus->dhd);
			dongle_isolation = bus->dhd->dongle_isolation;
			bus->dhd->is_pcie_watchdog_reset = FALSE;
			dhdpcie_bus_remove_prep(bus);

			if (bus->intr) {
				DHD_BUS_LOCK(bus->bus_lock, flags_bus);
				dhdpcie_bus_intr_disable(bus);
				DHD_BUS_UNLOCK(bus->bus_lock, flags_bus);
				dhdpcie_free_irq(bus);
			}
			dhd_deinit_bus_lock(bus);
			dhd_deinit_backplane_access_lock(bus);
			/**
			 * dhdpcie_bus_release_dongle free bus->sih  handle, which is needed to
			 * access Dongle registers.
			 * dhd_detach will communicate with dongle to delete flowring ..etc.
			 * So dhdpcie_bus_release_dongle should be called only after the dhd_detach.
			 */
			dhd_detach(bus->dhd);
			dhdpcie_bus_release_dongle(bus, osh, dongle_isolation, TRUE);
			dhd_free(bus->dhd);
			bus->dhd = NULL;
		}
		/* unmap the regs and tcm here!! */
		if (bus->regs) {
			dhdpcie_bus_reg_unmap(osh, bus->regs, DONGLE_REG_MAP_SIZE);
			bus->regs = NULL;
		}
		if (bus->tcm) {
			dhdpcie_bus_reg_unmap(osh, bus->tcm, DONGLE_TCM_MAP_SIZE);
			bus->tcm = NULL;
		}

		dhdpcie_bus_release_malloc(bus, osh);
		/* Detach pcie shared structure */
		if (bus->pcie_sh) {
			MFREE(osh, bus->pcie_sh, sizeof(pciedev_shared_t));
			bus->pcie_sh = NULL;
		}

		if (bus->console.buf != NULL) {
			MFREE(osh, bus->console.buf, bus->console.bufsize);
		}

		/* Finally free bus info */
		MFREE(osh, bus, sizeof(dhd_bus_t));

		g_dhd_bus = NULL;
	}

	DHD_TRACE(("%s: Exit\n", __FUNCTION__));
} /* dhdpcie_bus_release */

void
dhdpcie_bus_release_dongle(dhd_bus_t *bus, osl_t *osh, bool dongle_isolation, bool reset_flag)
{
	DHD_TRACE(("%s: Enter bus->dhd %p bus->dhd->dongle_reset %d \n", __FUNCTION__,
		bus->dhd, bus->dhd->dongle_reset));

	if ((bus->dhd && bus->dhd->dongle_reset) && reset_flag) {
		DHD_TRACE(("%s Exit\n", __FUNCTION__));
		return;
	}

	if (bus->is_linkdown) {
		DHD_ERROR(("%s : Skip release dongle due to linkdown \n", __FUNCTION__));
		return;
	}

	if (bus->sih) {

		if (!dongle_isolation &&
			(bus->dhd && !bus->dhd->is_pcie_watchdog_reset)) {
			dhdpcie_dongle_reset(bus);
		}

		dhdpcie_dongle_flr_or_pwr_toggle(bus);

		if (bus->ltrsleep_on_unload) {
			si_corereg(bus->sih, bus->sih->buscoreidx,
				OFFSETOF(sbpcieregs_t, u.pcie2.ltr_state), ~0, 0);
		}

		if (bus->sih->buscorerev == 13)
			 pcie_serdes_iddqdisable(bus->osh, bus->sih,
			                         (sbpcieregs_t *) bus->regs);

		/* For inbuilt drivers pcie clk req will be done by RC,
		 * so do not do clkreq from dhd
		 */
		if (dhd_download_fw_on_driverload)
		{
			/* Disable CLKREQ# */
			dhdpcie_clkreq(bus->osh, 1, 0);
		}

		if (bus->sih != NULL) {
			si_detach(bus->sih);
			bus->sih = NULL;
		}
		if (bus->vars && bus->varsz)
			MFREE(osh, bus->vars, bus->varsz);
		bus->vars = NULL;
	}

	DHD_TRACE(("%s Exit\n", __FUNCTION__));
}

uint32
dhdpcie_bus_cfg_read_dword(dhd_bus_t *bus, uint32 addr, uint32 size)
{
	uint32 data = OSL_PCI_READ_CONFIG(bus->osh, addr, size);
	return data;
}

/** 32 bit config write */
void
dhdpcie_bus_cfg_write_dword(dhd_bus_t *bus, uint32 addr, uint32 size, uint32 data)
{
	OSL_PCI_WRITE_CONFIG(bus->osh, addr, size, data);
}

void
dhdpcie_bus_cfg_set_bar0_win(dhd_bus_t *bus, uint32 data)
{
	OSL_PCI_WRITE_CONFIG(bus->osh, PCI_BAR0_WIN, 4, data);
}

void
dhdpcie_bus_dongle_setmemsize(struct dhd_bus *bus, int mem_size)
{
	int32 min_size =  DONGLE_MIN_MEMSIZE;
	/* Restrict the memsize to user specified limit */
	DHD_ERROR(("user: Restrict the dongle ram size to %d, min accepted %d\n",
		dhd_dongle_memsize, min_size));
	if ((dhd_dongle_memsize > min_size) &&
		(dhd_dongle_memsize < (int32)bus->orig_ramsize))
		bus->ramsize = dhd_dongle_memsize;
}

void
dhdpcie_bus_release_malloc(dhd_bus_t *bus, osl_t *osh)
{
	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (bus->dhd && bus->dhd->dongle_reset)
		return;

	if (bus->vars && bus->varsz) {
		MFREE(osh, bus->vars, bus->varsz);
		bus->vars = NULL;
	}

	DHD_TRACE(("%s: Exit\n", __FUNCTION__));
	return;

}

/** Stop bus module: clear pending frames, disable data flow */
void dhd_bus_stop(struct dhd_bus *bus, bool enforce_mutex)
{
	unsigned long flags, flags_bus;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (!bus->dhd)
		return;

	if (bus->dhd->busstate == DHD_BUS_DOWN) {
		DHD_ERROR(("%s: already down by net_dev_reset\n", __FUNCTION__));
		goto done;
	}

	DHD_DISABLE_RUNTIME_PM(bus->dhd);

	DHD_GENERAL_LOCK(bus->dhd, flags);
	DHD_ERROR(("%s: making DHD_BUS_DOWN\n", __FUNCTION__));
	bus->dhd->busstate = DHD_BUS_DOWN;
	DHD_GENERAL_UNLOCK(bus->dhd, flags);

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
	atomic_set(&bus->dhd->block_bus, TRUE);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

	DHD_BUS_LOCK(bus->bus_lock, flags_bus);
	dhdpcie_bus_intr_disable(bus);
	DHD_BUS_UNLOCK(bus->bus_lock, flags_bus);

	if (!bus->is_linkdown) {
		uint32 status;
		status = dhdpcie_bus_cfg_read_dword(bus, PCIIntstatus, 4);
		dhdpcie_bus_cfg_write_dword(bus, PCIIntstatus, 4, status);
	}

	if (!dhd_download_fw_on_driverload) {
		dhd_dpc_kill(bus->dhd);
	}

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
	pm_runtime_disable(dhd_bus_to_dev(bus));
	pm_runtime_set_suspended(dhd_bus_to_dev(bus));
	pm_runtime_enable(dhd_bus_to_dev(bus));
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

	/* Clear rx control and wake any waiters */
	dhd_os_set_ioctl_resp_timeout(IOCTL_DISABLE_TIMEOUT);
	dhd_wakeup_ioctl_event(bus->dhd, IOCTL_RETURN_ON_BUS_STOP);

done:
	return;
}

/**
 * Watchdog timer function.
 * @param dhd   Represents a specific hardware (dongle) instance that this DHD manages
 */
bool dhd_bus_watchdog(dhd_pub_t *dhd)
{
	unsigned long flags;
	dhd_bus_t *bus = dhd->bus;

	DHD_GENERAL_LOCK(dhd, flags);
	if (DHD_BUS_CHECK_DOWN_OR_DOWN_IN_PROGRESS(dhd) ||
			DHD_BUS_CHECK_SUSPEND_OR_SUSPEND_IN_PROGRESS(dhd)) {
		DHD_GENERAL_UNLOCK(dhd, flags);
		return FALSE;
	}
	DHD_BUS_BUSY_SET_IN_WD(dhd);
	DHD_GENERAL_UNLOCK(dhd, flags);

	/* Poll for console output periodically */
	if (dhd->busstate == DHD_BUS_DATA &&
		dhd->dhd_console_ms != 0 &&
		bus->bus_low_power_state == DHD_BUS_NO_LOW_POWER_STATE) {
		bus->console.count += dhd_watchdog_ms;
		if (bus->console.count >= dhd->dhd_console_ms) {
			bus->console.count -= dhd->dhd_console_ms;

			if (MULTIBP_ENAB(bus->sih)) {
				dhd_bus_pcie_pwr_req(bus);
			}

			/* Make sure backplane clock is on */
			if (dhdpcie_bus_readconsole(bus) < 0) {
				dhd->dhd_console_ms = 0; /* On error, stop trying */
			}

			if (MULTIBP_ENAB(bus->sih)) {
				dhd_bus_pcie_pwr_req_clear(bus);
			}
		}
	}

#ifdef DHD_READ_INTSTATUS_IN_DPC
	if (bus->poll) {
		bus->ipend = TRUE;
		bus->dpc_sched = TRUE;
		dhd_sched_dpc(bus->dhd);     /* queue DPC now!! */
	}
#endif /* DHD_READ_INTSTATUS_IN_DPC */

	DHD_GENERAL_LOCK(dhd, flags);
	DHD_BUS_BUSY_CLEAR_IN_WD(dhd);
	dhd_os_busbusy_wake(dhd);
	DHD_GENERAL_UNLOCK(dhd, flags);

	return TRUE;
} /* dhd_bus_watchdog */

#if defined(SUPPORT_MULTIPLE_REVISION)
static int concate_revision_bcm4358(dhd_bus_t *bus, char *fw_path, char *nv_path)
{
	uint32 chiprev;
#if defined(SUPPORT_MULTIPLE_CHIPS)
	char chipver_tag[20] = "_4358";
#else
	char chipver_tag[10] = {0, };
#endif /* SUPPORT_MULTIPLE_CHIPS */

	chiprev = dhd_bus_chiprev(bus);
	if (chiprev == 0) {
		DHD_ERROR(("----- CHIP 4358 A0 -----\n"));
		strcat(chipver_tag, "_a0");
	} else if (chiprev == 1) {
		DHD_ERROR(("----- CHIP 4358 A1 -----\n"));
#if defined(SUPPORT_MULTIPLE_CHIPS) || defined(SUPPORT_MULTIPLE_MODULE_CIS)
		strcat(chipver_tag, "_a1");
#endif /* defined(SUPPORT_MULTIPLE_CHIPS) || defined(SUPPORT_MULTIPLE_MODULE_CIS) */
	} else if (chiprev == 3) {
		DHD_ERROR(("----- CHIP 4358 A3 -----\n"));
#if defined(SUPPORT_MULTIPLE_CHIPS)
		strcat(chipver_tag, "_a3");
#endif /* SUPPORT_MULTIPLE_CHIPS */
	} else {
		DHD_ERROR(("----- Unknown chip version, ver=%x -----\n", chiprev));
	}

	strcat(fw_path, chipver_tag);

#if defined(SUPPORT_MULTIPLE_MODULE_CIS) && defined(USE_CID_CHECK)
	if (chiprev == 1 || chiprev == 3) {
		int ret = dhd_check_module_b85a();
		if ((chiprev == 1) && (ret < 0)) {
			memset(chipver_tag, 0x00, sizeof(chipver_tag));
			strcat(chipver_tag, "_b85");
			strcat(chipver_tag, "_a1");
		}
	}

	DHD_ERROR(("%s: chipver_tag %s \n", __FUNCTION__, chipver_tag));
#endif /* defined(SUPPORT_MULTIPLE_MODULE_CIS) && defined(USE_CID_CHECK) */

#if defined(SUPPORT_MULTIPLE_BOARD_REV)
	if (system_rev >= 10) {
		DHD_ERROR(("----- Board Rev  [%d]-----\n", system_rev));
		strcat(chipver_tag, "_r10");
	}
#endif /* SUPPORT_MULTIPLE_BOARD_REV */
	strcat(nv_path, chipver_tag);

	return 0;
}

static int concate_revision_bcm4359(dhd_bus_t *bus, char *fw_path, char *nv_path)
{
	uint32 chip_ver;
	char chipver_tag[10] = {0, };
#if defined(SUPPORT_MULTIPLE_MODULE_CIS) && defined(USE_CID_CHECK) && \
	defined(SUPPORT_BCM4359_MIXED_MODULES)
	int module_type = -1;
#endif /* SUPPORT_MULTIPLE_MODULE_CIS && USE_CID_CHECK && SUPPORT_BCM4359_MIXED_MODULES */

	chip_ver = bus->sih->chiprev;
	if (chip_ver == 4) {
		DHD_ERROR(("----- CHIP 4359 B0 -----\n"));
		strncat(chipver_tag, "_b0", strlen("_b0"));
	} else if (chip_ver == 5) {
		DHD_ERROR(("----- CHIP 4359 B1 -----\n"));
		strncat(chipver_tag, "_b1", strlen("_b1"));
	} else if (chip_ver == 9) {
		DHD_ERROR(("----- CHIP 4359 C0 -----\n"));
		strncat(chipver_tag, "_c0", strlen("_c0"));
	} else {
		DHD_ERROR(("----- Unknown chip version, ver=%x -----\n", chip_ver));
		return -1;
	}

#if defined(SUPPORT_MULTIPLE_MODULE_CIS) && defined(USE_CID_CHECK) && \
	defined(SUPPORT_BCM4359_MIXED_MODULES)
	module_type =  dhd_check_module_b90();

	switch (module_type) {
		case BCM4359_MODULE_TYPE_B90B:
			strcat(fw_path, chipver_tag);
			break;
		case BCM4359_MODULE_TYPE_B90S:
		default:
			/*
			 * .cid.info file not exist case,
			 * loading B90S FW force for initial MFG boot up.
			*/
			if (chip_ver == 5) {
				strncat(fw_path, "_b90s", strlen("_b90s"));
			}
			strcat(fw_path, chipver_tag);
			strcat(nv_path, chipver_tag);
			break;
	}
#else /* SUPPORT_MULTIPLE_MODULE_CIS && USE_CID_CHECK && SUPPORT_BCM4359_MIXED_MODULES */
	strcat(fw_path, chipver_tag);
	strcat(nv_path, chipver_tag);
#endif /* SUPPORT_MULTIPLE_MODULE_CIS && USE_CID_CHECK && SUPPORT_BCM4359_MIXED_MODULES */

	return 0;
}

#if defined(USE_CID_CHECK)

#define MAX_EXTENSION 20
#define MODULE_BCM4361_INDEX	3
#define CHIP_REV_A0	1
#define CHIP_REV_A1	2
#define CHIP_REV_B0	3
#define CHIP_REV_B1	4
#define CHIP_REV_B2	5
#define CHIP_REV_C0	6
#define BOARD_TYPE_EPA				0x080f
#define BOARD_TYPE_IPA				0x0827
#define BOARD_TYPE_IPA_OLD			0x081a
#define DEFAULT_CIDINFO_FOR_EPA		"r00a_e000_a0_ePA"
#define DEFAULT_CIDINFO_FOR_IPA		"r00a_e000_a0_iPA"
#define DEFAULT_CIDINFO_FOR_A1		"r01a_e30a_a1"
#define DEFAULT_CIDINFO_FOR_B0		"r01i_e32_b0"
#define MAX_VID_LEN					8
#define CIS_TUPLE_HDR_LEN		2
#if defined(BCM4361_CHIP)
#define CIS_TUPLE_START_ADDRESS		0x18011110
#define CIS_TUPLE_END_ADDRESS		0x18011167
#elif defined(BCM4375_CHIP)
#define CIS_TUPLE_START_ADDRESS		0x18011120
#define CIS_TUPLE_END_ADDRESS		0x18011177
#endif /* defined(BCM4361_CHIP) */
#define CIS_TUPLE_MAX_COUNT		(uint32)((CIS_TUPLE_END_ADDRESS - CIS_TUPLE_START_ADDRESS\
						+ 1) / sizeof(uint32))
#define CIS_TUPLE_TAG_START			0x80
#define CIS_TUPLE_TAG_VENDOR		0x81
#define CIS_TUPLE_TAG_BOARDTYPE		0x1b
#define CIS_TUPLE_TAG_LENGTH		1
#define NVRAM_FEM_MURATA			"_murata"
#define CID_FEM_MURATA				"_mur_"

typedef struct cis_tuple_format {
	uint8	id;
	uint8	len;	/* total length of tag and data */
	uint8	tag;
	uint8	data[1];
} cis_tuple_format_t;

typedef struct {
	char cid_ext[MAX_EXTENSION];
	char nvram_ext[MAX_EXTENSION];
	char fw_ext[MAX_EXTENSION];
} naming_info_t;

naming_info_t bcm4361_naming_table[] = {
	{ {""}, {""}, {""} },
	{ {"r00a_e000_a0_ePA"}, {"_a0_ePA"}, {"_a0_ePA"} },
	{ {"r00a_e000_a0_iPA"}, {"_a0"}, {"_a1"} },
	{ {"r01a_e30a_a1"}, {"_r01a_a1"}, {"_a1"} },
	{ {"r02a_e30a_a1"}, {"_r02a_a1"}, {"_a1"} },
	{ {"r02c_e30a_a1"}, {"_r02c_a1"}, {"_a1"} },
	{ {"r01d_e31_b0"}, {"_r01d_b0"}, {"_b0"} },
	{ {"r01f_e31_b0"}, {"_r01f_b0"}, {"_b0"} },
	{ {"r02g_e31_b0"}, {"_r02g_b0"}, {"_b0"} },
	{ {"r01h_e32_b0"}, {"_r01h_b0"}, {"_b0"} },
	{ {"r01i_e32_b0"}, {"_r01i_b0"}, {"_b0"} },
	{ {"r02j_e32_b0"}, {"_r02j_b0"}, {"_b0"} },
	{ {"r012_1kl_a1"}, {"_r012_a1"}, {"_a1"} },
	{ {"r013_1kl_b0"}, {"_r013_b0"}, {"_b0"} },
	{ {"r013_1kl_b0"}, {"_r013_b0"}, {"_b0"} },
	{ {"r014_1kl_b0"}, {"_r014_b0"}, {"_b0"} },
	{ {"r015_1kl_b0"}, {"_r015_b0"}, {"_b0"} },
	{ {"r020_1kl_b0"}, {"_r020_b0"}, {"_b0"} },
	{ {"r021_1kl_b0"}, {"_r021_b0"}, {"_b0"} },
	{ {"r022_1kl_b0"}, {"_r022_b0"}, {"_b0"} },
	{ {"r023_1kl_b0"}, {"_r023_b0"}, {"_b0"} },
	{ {"r024_1kl_b0"}, {"_r024_b0"}, {"_b0"} },
	{ {"r030_1kl_b0"}, {"_r030_b0"}, {"_b0"} },
	{ {"r031_1kl_b0"}, {"_r030_b0"}, {"_b0"} },	/* exceptional case : r31 -> r30 */
	{ {"r032_1kl_b0"}, {"_r032_b0"}, {"_b0"} },
	{ {"r033_1kl_b0"}, {"_r033_b0"}, {"_b0"} },
	{ {"r034_1kl_b0"}, {"_r034_b0"}, {"_b0"} },
	{ {"r02a_e32a_b2"}, {"_r02a_b2"}, {"_b2"} },
	{ {"r02b_e32a_b2"}, {"_r02b_b2"}, {"_b2"} },
	{ {"r020_1qw_b2"}, {"_r020_b2"}, {"_b2"} },
	{ {"r021_1qw_b2"}, {"_r021_b2"}, {"_b2"} },
	{ {"r022_1qw_b2"}, {"_r022_b2"}, {"_b2"} },
	{ {"r031_1qw_b2"}, {"_r031_b2"}, {"_b2"} },
	{ {"r032_1qw_b2"}, {"_r032_b2"}, {"_b2"} },
	{ {"r041_1qw_b2"}, {"_r041_b2"}, {"_b2"} }
};

#define MODULE_BCM4375_INDEX	3

naming_info_t bcm4375_naming_table[] = {
	{ {""}, {""}, {""} },
	{ {"e41_es11"}, {"_ES00_semco_b0"}, {"_b0"} },
	{ {"e43_es33"}, {"_ES01_semco_b0"}, {"_b0"} },
	{ {"e43_es34"}, {"_ES02_semco_b0"}, {"_b0"} },
	{ {"e43_es35"}, {"_ES02_semco_b0"}, {"_b0"} },
	{ {"e43_es36"}, {"_ES03_semco_b0"}, {"_b0"} },
	{ {"e43_cs41"}, {"_CS00_semco_b1"}, {"_b1"} },
	{ {"e43_cs51"}, {"_CS01_semco_b1"}, {"_b1"} },
	{ {"e43_cs53"}, {"_CS01_semco_b1"}, {"_b1"} },
	{ {"e43_cs61"}, {"_CS00_skyworks_b1"}, {"_b1"} },
	{ {"1rh_es10"}, {"_1rh_es10_b0"}, {"_b0"} },
	{ {"1rh_es11"}, {"_1rh_es11_b0"}, {"_b0"} },
	{ {"1rh_es12"}, {"_1rh_es12_b0"}, {"_b0"} },
	{ {"1rh_es13"}, {"_1rh_es13_b0"}, {"_b0"} },
	{ {"1rh_es20"}, {"_1rh_es20_b0"}, {"_b0"} },
	{ {"1rh_es32"}, {"_1rh_es32_b0"}, {"_b0"} },
	{ {"1rh_es41"}, {"_1rh_es41_b1"}, {"_b1"} },
	{ {"1rh_es42"}, {"_1rh_es42_b1"}, {"_b1"} },
	{ {"1rh_es43"}, {"_1rh_es43_b1"}, {"_b1"} },
	{ {"1rh_es44"}, {"_1rh_es44_b1"}, {"_b1"} }
};

static naming_info_t *
dhd_find_naming_info(naming_info_t table[], int table_size, char *module_type)
{
	int index_found = 0, i = 0;

	if (module_type && strlen(module_type) > 0) {
		for (i = 1; i < table_size; i++) {
			if (!strncmp(table[i].cid_ext, module_type, strlen(table[i].cid_ext))) {
				index_found = i;
				break;
			}
		}
	}

	DHD_INFO(("%s: index_found=%d\n", __FUNCTION__, index_found));

	return &table[index_found];
}

static naming_info_t *
dhd_find_naming_info_by_cid(naming_info_t table[], int table_size,
	char *cid_info)
{
	int index_found = 0, i = 0;
	char *ptr;

	/* truncate extension */
	for (i = 1, ptr = cid_info; i < MODULE_BCM4361_INDEX && ptr; i++) {
		ptr = bcmstrstr(ptr, "_");
		if (ptr) {
			ptr++;
		}
	}

	for (i = 1; i < table_size && ptr; i++) {
		if (!strncmp(table[i].cid_ext, ptr, strlen(table[i].cid_ext))) {
			index_found = i;
			break;
		}
	}

	DHD_INFO(("%s: index_found=%d\n", __FUNCTION__, index_found));

	return &table[index_found];
}

static int
dhd_parse_board_information_bcm(dhd_bus_t *bus, int *boardtype,
	unsigned char *vid, int *vid_length)
{
	int boardtype_backplane_addr[] = {
		0x18010324, /* OTP Control 1 */
		0x18012618, /* PMU min resource mask */
	};
	int boardtype_backplane_data[] = {
		0x00fa0000,
		0x0e4fffff /* Keep on ARMHTAVAIL */
	};
	int int_val = 0, i = 0;
	cis_tuple_format_t *tuple;
	int totlen, len;
	uint32 raw_data[CIS_TUPLE_MAX_COUNT];

	for (i = 0; i < ARRAYSIZE(boardtype_backplane_addr); i++) {
		/* Write new OTP and PMU configuration */
		if (si_backplane_access(bus->sih, boardtype_backplane_addr[i], sizeof(int),
				&boardtype_backplane_data[i], FALSE) != BCME_OK) {
			DHD_ERROR(("invalid size/addr combination\n"));
			return BCME_ERROR;
		}

		if (si_backplane_access(bus->sih, boardtype_backplane_addr[i], sizeof(int),
				&int_val, TRUE) != BCME_OK) {
			DHD_ERROR(("invalid size/addr combination\n"));
			return BCME_ERROR;
		}

		DHD_INFO(("%s: boardtype_backplane_addr 0x%08x rdata 0x%04x\n",
			__FUNCTION__, boardtype_backplane_addr[i], int_val));
	}

	/* read tuple raw data */
	for (i = 0; i < CIS_TUPLE_MAX_COUNT; i++) {
		if (si_backplane_access(bus->sih, CIS_TUPLE_START_ADDRESS + i * sizeof(uint32),
				sizeof(uint32),	&raw_data[i], TRUE) != BCME_OK) {
			break;
		}
	}

	totlen = i * sizeof(uint32);
	tuple = (cis_tuple_format_t *)raw_data;

	/* check the first tuple has tag 'start' */
	if (tuple->id != CIS_TUPLE_TAG_START) {
		return BCME_ERROR;
	}

	*vid_length = *boardtype = 0;

	/* find tagged parameter */
	while ((totlen >= (tuple->len + CIS_TUPLE_HDR_LEN)) &&
			(*vid_length == 0 || *boardtype == 0)) {
		len = tuple->len;

		if ((tuple->tag == CIS_TUPLE_TAG_VENDOR) &&
				(totlen >= (int)(len + CIS_TUPLE_HDR_LEN))) {
			/* found VID */
			memcpy(vid, tuple->data, tuple->len - CIS_TUPLE_TAG_LENGTH);
			*vid_length = tuple->len - CIS_TUPLE_TAG_LENGTH;
			prhex("OTP VID", tuple->data, tuple->len - CIS_TUPLE_TAG_LENGTH);
		}
		else if ((tuple->tag == CIS_TUPLE_TAG_BOARDTYPE) &&
				(totlen >= (int)(len + CIS_TUPLE_HDR_LEN))) {
			/* found boardtype */
			*boardtype = (int)tuple->data[0];
			prhex("OTP boardtype", tuple->data, tuple->len - CIS_TUPLE_TAG_LENGTH);
		}

		tuple = (cis_tuple_format_t*)((uint8*)tuple + (len + CIS_TUPLE_HDR_LEN));
		totlen -= (len + CIS_TUPLE_HDR_LEN);
	}

	if (*vid_length <= 0 || *boardtype <= 0) {
		DHD_ERROR(("failed to parse information (vid=%d, boardtype=%d)\n",
			*vid_length, *boardtype));
		return BCME_ERROR;
	}

	return BCME_OK;

}

static naming_info_t *
dhd_find_naming_info_by_chip_rev(naming_info_t table[], int table_size,
	dhd_bus_t *bus, bool *is_murata_fem)
{
	int board_type = 0, chip_rev = 0, vid_length = 0;
	unsigned char vid[MAX_VID_LEN];
	naming_info_t *info = &table[0];
	char *cid_info = NULL;

	if (!bus || !bus->sih) {
		DHD_ERROR(("%s:bus(%p) or bus->sih is NULL\n", __FUNCTION__, bus));
		return NULL;
	}
	chip_rev = bus->sih->chiprev;

	if (dhd_parse_board_information_bcm(bus, &board_type, vid, &vid_length)
			!= BCME_OK) {
		DHD_ERROR(("%s:failed to parse board information\n", __FUNCTION__));
		return NULL;
	}

	DHD_INFO(("%s:chip version %d\n", __FUNCTION__, chip_rev));

#if defined(BCM4361_CHIP)
	/* A0 chipset has exception only */
	if (chip_rev == CHIP_REV_A0) {
		if (board_type == BOARD_TYPE_EPA) {
			info = dhd_find_naming_info(table, table_size,
				DEFAULT_CIDINFO_FOR_EPA);
		} else if ((board_type == BOARD_TYPE_IPA) ||
				(board_type == BOARD_TYPE_IPA_OLD)) {
			info = dhd_find_naming_info(table, table_size,
				DEFAULT_CIDINFO_FOR_IPA);
		}
	} else {
		cid_info = dhd_get_cid_info(vid, vid_length);
		if (cid_info) {
			info = dhd_find_naming_info_by_cid(table, table_size, cid_info);
			if (strstr(cid_info, CID_FEM_MURATA)) {
				*is_murata_fem = TRUE;
			}
		}
	}
#else
	cid_info = dhd_get_cid_info(vid, vid_length);
	if (cid_info) {
		info = dhd_find_naming_info_by_cid(table, table_size, cid_info);
		if (strstr(cid_info, CID_FEM_MURATA)) {
			*is_murata_fem = TRUE;
		}
	}
#endif /* BCM4361_CHIP */

	return info;
}
#endif /* USE_CID_CHECK */

static int
concate_revision_bcm4361(dhd_bus_t *bus, char *fw_path, char *nv_path)
{
	int ret = BCME_OK;
#if defined(SUPPORT_BCM4361_MIXED_MODULES) && defined(USE_CID_CHECK)
	char module_type[MAX_VNAME_LEN];
	naming_info_t *info = NULL;
	bool is_murata_fem = FALSE;

	memset(module_type, 0, sizeof(module_type));

	if (dhd_check_module_bcm(module_type,
			MODULE_BCM4361_INDEX, &is_murata_fem) == BCME_OK) {
		info = dhd_find_naming_info(bcm4361_naming_table,
			ARRAYSIZE(bcm4361_naming_table), module_type);
	} else {
		/* in case of .cid.info doesn't exists */
		info = dhd_find_naming_info_by_chip_rev(bcm4361_naming_table,
			ARRAYSIZE(bcm4361_naming_table), bus, &is_murata_fem);
	}

	if (bcmstrnstr(nv_path, PATH_MAX,  "_murata", 7)) {
		is_murata_fem = FALSE;
	}

	if (info) {
		if (is_murata_fem) {
			strncat(nv_path, NVRAM_FEM_MURATA, strlen(NVRAM_FEM_MURATA));
		}
		strncat(nv_path, info->nvram_ext, strlen(info->nvram_ext));
		strncat(fw_path, info->fw_ext, strlen(info->fw_ext));
	} else {
		DHD_ERROR(("%s:failed to find extension for nvram and firmware\n", __FUNCTION__));
		ret = BCME_ERROR;
	}
#else /* SUPPORT_MULTIPLE_MODULE_CIS && USE_CID_CHECK */
	char chipver_tag[10] = {0, };

	strcat(fw_path, chipver_tag);
	strcat(nv_path, chipver_tag);
#endif /* SUPPORT_MULTIPLE_MODULE_CIS && USE_CID_CHECK */

	return ret;
}

static int
concate_revision_bcm4375(dhd_bus_t *bus, char *fw_path, char *nv_path)
{
	int ret = BCME_OK;
#if defined(SUPPORT_BCM4375_MIXED_MODULES) && defined(USE_CID_CHECK)
	char module_type[MAX_VNAME_LEN];
	naming_info_t *info = NULL;
	bool is_murata_fem = FALSE;

	memset(module_type, 0, sizeof(module_type));

	if (dhd_check_module_bcm(module_type,
			MODULE_BCM4375_INDEX, &is_murata_fem) == BCME_OK) {
		info = dhd_find_naming_info(bcm4375_naming_table,
				ARRAYSIZE(bcm4375_naming_table), module_type);
	} else {
		/* in case of .cid.info doesn't exists */
		info = dhd_find_naming_info_by_chip_rev(bcm4375_naming_table,
				ARRAYSIZE(bcm4375_naming_table), bus, &is_murata_fem);
	}

	if (info) {
		strncat(nv_path, info->nvram_ext, strlen(info->nvram_ext));
		strncat(fw_path, info->fw_ext, strlen(info->fw_ext));
	} else {
		DHD_ERROR(("%s:failed to find extension for nvram and firmware\n", __FUNCTION__));
		ret = BCME_ERROR;
	}
#else /* SUPPORT_BCM4375_MIXED_MODULES && USE_CID_CHECK */
	char chipver_tag[10] = {0, };

	strcat(fw_path, chipver_tag);
	strcat(nv_path, chipver_tag);
#endif /* SUPPORT_BCM4375_MIXED_MODULES && USE_CID_CHECK */

	return ret;
}

int
concate_revision(dhd_bus_t *bus, char *fw_path, char *nv_path)
{
	int res = 0;

	if (!bus || !bus->sih) {
		DHD_ERROR(("%s:Bus is Invalid\n", __FUNCTION__));
		return -1;
	}

	if (!fw_path || !nv_path) {
		DHD_ERROR(("fw_path or nv_path is null.\n"));
		return res;
	}

	switch (si_chipid(bus->sih)) {

	case BCM43569_CHIP_ID:
	case BCM4358_CHIP_ID:
		res = concate_revision_bcm4358(bus, fw_path, nv_path);
		break;
	case BCM4355_CHIP_ID:
	case BCM4359_CHIP_ID:
		res = concate_revision_bcm4359(bus, fw_path, nv_path);
		break;
	case BCM4361_CHIP_ID:
	case BCM4347_CHIP_ID:
		res = concate_revision_bcm4361(bus, fw_path, nv_path);
		break;
	case BCM4375_CHIP_ID:
		res = concate_revision_bcm4375(bus, fw_path, nv_path);
		break;
	default:
		DHD_ERROR(("REVISION SPECIFIC feature is not required\n"));
		return res;
	}

	return res;
}
#endif /* SUPPORT_MULTIPLE_REVISION */

uint16
dhd_get_chipid(dhd_pub_t *dhd)
{
	dhd_bus_t *bus = dhd->bus;

	if (bus && bus->sih)
		return (uint16)si_chipid(bus->sih);
	else
		return 0;
}

/**
 * Loads firmware given by caller supplied path and nvram image into PCIe dongle.
 *
 * BCM_REQUEST_FW specific :
 * Given the chip type, determines the to be used file paths within /lib/firmware/brcm/ containing
 * firmware and nvm for that chip. If the download fails, retries download with a different nvm file
 *
 * BCMEMBEDIMAGE specific:
 * If bus->fw_path is empty, or if the download of bus->fw_path failed, firmware contained in header
 * file will be used instead.
 *
 * @return BCME_OK on success
 */
int
dhd_bus_download_firmware(struct dhd_bus *bus, osl_t *osh,
                          char *pfw_path, char *pnv_path,
                          char *pclm_path, char *pconf_path)
{
	int ret;

	bus->fw_path = pfw_path;
	bus->nv_path = pnv_path;
	bus->dhd->clm_path = pclm_path;
	bus->dhd->conf_path = pconf_path;

#if defined(SUPPORT_MULTIPLE_REVISION)
	if (concate_revision(bus, bus->fw_path, bus->nv_path) != 0) {
		DHD_ERROR(("%s: fail to concatnate revison \n",
			__FUNCTION__));
		return BCME_BADARG;
	}
#endif /* SUPPORT_MULTIPLE_REVISION */

#if defined(DHD_BLOB_EXISTENCE_CHECK)
	dhd_set_blob_support(bus->dhd, bus->fw_path);
#endif /* DHD_BLOB_EXISTENCE_CHECK */

	DHD_ERROR(("%s: firmware path=%s, nvram path=%s\n",
		__FUNCTION__, bus->fw_path, bus->nv_path));
	dhdpcie_dump_resource(bus);

	ret = dhdpcie_download_firmware(bus, osh);

	return ret;
}

void
dhd_set_bus_params(struct dhd_bus *bus)
{
	if (bus->dhd->conf->dhd_poll >= 0) {
		bus->poll = bus->dhd->conf->dhd_poll;
		if (!bus->pollrate)
			bus->pollrate = 1;
		printf("%s: set polling mode %d\n", __FUNCTION__, bus->dhd->conf->dhd_poll);
	}
}

/**
 * Loads firmware given by 'bus->fw_path' into PCIe dongle.
 *
 * BCM_REQUEST_FW specific :
 * Given the chip type, determines the to be used file paths within /lib/firmware/brcm/ containing
 * firmware and nvm for that chip. If the download fails, retries download with a different nvm file
 *
 * BCMEMBEDIMAGE specific:
 * If bus->fw_path is empty, or if the download of bus->fw_path failed, firmware contained in header
 * file will be used instead.
 *
 * @return BCME_OK on success
 */
static int
dhdpcie_download_firmware(struct dhd_bus *bus, osl_t *osh)
{
	int ret = 0;
#if defined(BCM_REQUEST_FW)
	uint chipid = bus->sih->chip;
	uint revid = bus->sih->chiprev;
	char fw_path[64] = "/lib/firmware/brcm/bcm";	/* path to firmware image */
	char nv_path[64];		/* path to nvram vars file */
	bus->fw_path = fw_path;
	bus->nv_path = nv_path;
	switch (chipid) {
	case BCM43570_CHIP_ID:
		bcmstrncat(fw_path, "43570", 5);
		switch (revid) {
		case 0:
			bcmstrncat(fw_path, "a0", 2);
			break;
		case 2:
			bcmstrncat(fw_path, "a2", 2);
			break;
		default:
			DHD_ERROR(("%s: revid is not found %x\n", __FUNCTION__,
			revid));
			break;
		}
		break;
	default:
		DHD_ERROR(("%s: unsupported device %x\n", __FUNCTION__,
		chipid));
		return 0;
	}
	/* load board specific nvram file */
	snprintf(bus->nv_path, sizeof(nv_path), "%s.nvm", fw_path);
	/* load firmware */
	snprintf(bus->fw_path, sizeof(fw_path), "%s-firmware.bin", fw_path);
#endif /* BCM_REQUEST_FW */

	DHD_OS_WAKE_LOCK(bus->dhd);

	dhd_conf_set_path_params(bus->dhd, bus->fw_path, bus->nv_path);
	dhd_set_bus_params(bus);

	ret = _dhdpcie_download_firmware(bus);

	DHD_OS_WAKE_UNLOCK(bus->dhd);
	return ret;
} /* dhdpcie_download_firmware */

#define DHD_MEMORY_SET_PATTERN 0xAA

/**
 * Downloads a file containing firmware into dongle memory. In case of a .bea file, the DHD
 * is updated with the event logging partitions within that file as well.
 *
 * @param pfw_path    Path to .bin or .bea file
 */
static int
dhdpcie_download_code_file(struct dhd_bus *bus, char *pfw_path)
{
	int bcmerror = BCME_ERROR;
	int offset = 0;
	int len = 0;
	bool store_reset;
	char *imgbuf = NULL;
	uint8 *memblock = NULL, *memptr = NULL;
#ifdef CHECK_DOWNLOAD_FW
	uint8 *memptr_tmp = NULL; // terence: check downloaded firmware is correct
#endif
	int offset_end = bus->ramsize;
	uint32 file_size = 0, read_len = 0;

#if defined(DHD_FW_MEM_CORRUPTION)
	if (dhd_bus_get_fw_mode(bus->dhd) == DHD_FLAG_MFG_MODE) {
		dhd_tcm_test_enable = TRUE;
	} else {
		dhd_tcm_test_enable = FALSE;
	}
#endif /* DHD_FW_MEM_CORRUPTION */
	DHD_ERROR(("%s: dhd_tcm_test_enable %u\n", __FUNCTION__, dhd_tcm_test_enable));
	/* TCM check */
	if (dhd_tcm_test_enable && !dhd_bus_tcm_test(bus)) {
		DHD_ERROR(("dhd_bus_tcm_test failed\n"));
		bcmerror = BCME_ERROR;
		goto err;
	}
	DHD_ERROR(("%s: download firmware %s\n", __FUNCTION__, pfw_path));

	/* Should succeed in opening image if it is actually given through registry
	 * entry or in module param.
	 */
	imgbuf = dhd_os_open_image1(bus->dhd, pfw_path);
	if (imgbuf == NULL) {
		printf("%s: Open firmware file failed %s\n", __FUNCTION__, pfw_path);
		goto err;
	}

	file_size = dhd_os_get_image_size(imgbuf);
	if (!file_size) {
		DHD_ERROR(("%s: get file size fails ! \n", __FUNCTION__));
		goto err;
	}

	memptr = memblock = MALLOC(bus->dhd->osh, MEMBLOCK + DHD_SDALIGN);
	if (memblock == NULL) {
		DHD_ERROR(("%s: Failed to allocate memory %d bytes\n", __FUNCTION__, MEMBLOCK));
		bcmerror = BCME_NOMEM;
		goto err;
	}
#ifdef CHECK_DOWNLOAD_FW
	if (bus->dhd->conf->fwchk) {
		memptr_tmp = MALLOC(bus->dhd->osh, MEMBLOCK + DHD_SDALIGN);
		if (memptr_tmp == NULL) {
			DHD_ERROR(("%s: Failed to allocate memory %d bytes\n", __FUNCTION__, MEMBLOCK));
			goto err;
		}
	}
#endif
	if ((uint32)(uintptr)memblock % DHD_SDALIGN) {
		memptr += (DHD_SDALIGN - ((uint32)(uintptr)memblock % DHD_SDALIGN));
	}

	/* check if CR4/CA7 */
	store_reset = (si_setcore(bus->sih, ARMCR4_CORE_ID, 0) ||
			si_setcore(bus->sih, ARMCA7_CORE_ID, 0));
	/* Download image with MEMBLOCK size */
	while ((len = dhd_os_get_image_block((char*)memptr, MEMBLOCK, imgbuf))) {
		if (len < 0) {
			DHD_ERROR(("%s: dhd_os_get_image_block failed (%d)\n", __FUNCTION__, len));
			bcmerror = BCME_ERROR;
			goto err;
		}
		read_len += len;
		if (read_len > file_size) {
			DHD_ERROR(("%s: WARNING! reading beyond EOF, len=%d; read_len=%u;"
				" file_size=%u truncating len to %d \n", __FUNCTION__,
				len, read_len, file_size, (len - (read_len - file_size))));
			len -= (read_len - file_size);
		}

		/* if address is 0, store the reset instruction to be written in 0 */
		if (store_reset) {
			ASSERT(offset == 0);
			bus->resetinstr = *(((uint32*)memptr));
			/* Add start of RAM address to the address given by user */
			offset += bus->dongle_ram_base;
			offset_end += offset;
			store_reset = FALSE;
		}

		bcmerror = dhdpcie_bus_membytes(bus, TRUE, offset, (uint8 *)memptr, len);
		if (bcmerror) {
			DHD_ERROR(("%s: error %d on writing %d membytes at 0x%08x\n",
				__FUNCTION__, bcmerror, MEMBLOCK, offset));
			goto err;
		}

#ifdef CHECK_DOWNLOAD_FW
		if (bus->dhd->conf->fwchk) {
			bcmerror = dhdpcie_bus_membytes(bus, FALSE, offset, memptr_tmp, len);
			if (bcmerror) {
				DHD_ERROR(("%s: error %d on reading %d membytes at 0x%08x\n",
				        __FUNCTION__, bcmerror, MEMBLOCK, offset));
				goto err;
			}
			if (memcmp(memptr_tmp, memptr, len)) {
				DHD_ERROR(("%s: Downloaded image is corrupted at 0x%08x\n", __FUNCTION__, offset));
				bcmerror = BCME_ERROR;
				goto err;
			} else
				DHD_INFO(("%s: Download, Upload and compare succeeded.\n", __FUNCTION__));
		}
#endif
		offset += MEMBLOCK;

		if (offset >= offset_end) {
			DHD_ERROR(("%s: invalid address access to %x (offset end: %x)\n",
				__FUNCTION__, offset, offset_end));
			bcmerror = BCME_ERROR;
			goto err;
		}

		if (read_len >= file_size) {
			break;
		}
	}
err:
	if (memblock) {
		MFREE(bus->dhd->osh, memblock, MEMBLOCK + DHD_SDALIGN);
#ifdef CHECK_DOWNLOAD_FW
		if (memptr_tmp)
			MFREE(bus->dhd->osh, memptr_tmp, MEMBLOCK + DHD_SDALIGN);
#endif
	}

	if (imgbuf) {
		dhd_os_close_image1(bus->dhd, imgbuf);
	}

	return bcmerror;
} /* dhdpcie_download_code_file */

static int
dhdpcie_download_nvram(struct dhd_bus *bus)
{
	int bcmerror = BCME_ERROR;
	uint len;
	char * memblock = NULL;
	char *bufp;
	char *pnv_path;
	bool nvram_file_exists;
	bool nvram_uefi_exists = FALSE;
	bool local_alloc = FALSE;
	pnv_path = bus->nv_path;

	nvram_file_exists = ((pnv_path != NULL) && (pnv_path[0] != '\0'));

	/* First try UEFI */
	len = MAX_NVRAMBUF_SIZE;
	dhd_get_download_buffer(bus->dhd, NULL, NVRAM, &memblock, (int *)&len);

	/* If UEFI empty, then read from file system */
	if ((len <= 0) || (memblock == NULL)) {

		if (nvram_file_exists) {
			len = MAX_NVRAMBUF_SIZE;
			dhd_get_download_buffer(bus->dhd, pnv_path, NVRAM, &memblock, (int *)&len);
			if ((len <= 0 || len > MAX_NVRAMBUF_SIZE)) {
				goto err;
			}
		}
		else {
			/* For SROM OTP no external file or UEFI required */
			bcmerror = BCME_OK;
		}
	} else {
		nvram_uefi_exists = TRUE;
	}

	DHD_ERROR(("%s: dhd_get_download_buffer len %d\n", __FUNCTION__, len));

	if (len > 0 && len <= MAX_NVRAMBUF_SIZE && memblock != NULL) {
		bufp = (char *) memblock;

		{
			bufp[len] = 0;
			if (nvram_uefi_exists || nvram_file_exists) {
				len = process_nvram_vars(bufp, len);
			}
		}

		DHD_ERROR(("%s: process_nvram_vars len %d\n", __FUNCTION__, len));

		if (len % 4) {
			len += 4 - (len % 4);
		}
		bufp += len;
		*bufp++ = 0;
		if (len)
			bcmerror = dhdpcie_downloadvars(bus, memblock, len + 1);
		if (bcmerror) {
			DHD_ERROR(("%s: error downloading vars: %d\n",
				__FUNCTION__, bcmerror));
		}
	}

err:
	if (memblock) {
		if (local_alloc) {
			MFREE(bus->dhd->osh, memblock, MAX_NVRAMBUF_SIZE);
		} else {
			dhd_free_download_buffer(bus->dhd, memblock, MAX_NVRAMBUF_SIZE);
		}
	}

	return bcmerror;
}

static int
dhdpcie_ramsize_read_image(struct dhd_bus *bus, char *buf, int len)
{
	int bcmerror = BCME_ERROR;
	char *imgbuf = NULL;

	if (buf == NULL || len == 0)
		goto err;

	/* External image takes precedence if specified */
	if ((bus->fw_path != NULL) && (bus->fw_path[0] != '\0')) {
		// opens and seeks to correct file offset:
		imgbuf = dhd_os_open_image1(bus->dhd, bus->fw_path);
		if (imgbuf == NULL) {
			DHD_ERROR(("%s: Failed to open firmware file\n", __FUNCTION__));
			goto err;
		}

		/* Read it */
		if (len != dhd_os_get_image_block(buf, len, imgbuf)) {
			DHD_ERROR(("%s: Failed to read %d bytes data\n", __FUNCTION__, len));
			goto err;
		}

		bcmerror = BCME_OK;
	}

err:
	if (imgbuf)
		dhd_os_close_image1(bus->dhd, imgbuf);

	return bcmerror;
}

/* The ramsize can be changed in the dongle image, for example 4365 chip share the sysmem
 * with BMC and we can adjust how many sysmem belong to CA7 during dongle compilation.
 * So in DHD we need to detect this case and update the correct dongle RAMSIZE as well.
 */
static void
dhdpcie_ramsize_adj(struct dhd_bus *bus)
{
	int i, search_len = 0;
	uint8 *memptr = NULL;
	uint8 *ramsizeptr = NULL;
	uint ramsizelen;
	uint32 ramsize_ptr_ptr[] = {RAMSIZE_PTR_PTR_LIST};
	hnd_ramsize_ptr_t ramsize_info;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	/* Adjust dongle RAMSIZE already called. */
	if (bus->ramsize_adjusted) {
		return;
	}

	/* success or failure,  we don't want to be here
	 * more than once.
	 */
	bus->ramsize_adjusted = TRUE;

	/* Not handle if user restrict dongle ram size enabled */
	if (dhd_dongle_memsize) {
		DHD_ERROR(("%s: user restrict dongle ram size to %d.\n", __FUNCTION__,
			dhd_dongle_memsize));
		return;
	}

	/* Out immediately if no image to download */
	if ((bus->fw_path == NULL) || (bus->fw_path[0] == '\0')) {
		DHD_ERROR(("%s: no fimrware file\n", __FUNCTION__));
		return;
	}

	/* Get maximum RAMSIZE info search length */
	for (i = 0; ; i++) {
		if (ramsize_ptr_ptr[i] == RAMSIZE_PTR_PTR_END)
			break;

		if (search_len < (int)ramsize_ptr_ptr[i])
			search_len = (int)ramsize_ptr_ptr[i];
	}

	if (!search_len)
		return;

	search_len += sizeof(hnd_ramsize_ptr_t);

	memptr = MALLOC(bus->dhd->osh, search_len);
	if (memptr == NULL) {
		DHD_ERROR(("%s: Failed to allocate memory %d bytes\n", __FUNCTION__, search_len));
		return;
	}

	/* External image takes precedence if specified */
	if (dhdpcie_ramsize_read_image(bus, (char *)memptr, search_len) != BCME_OK) {
		goto err;
	}
	else {
		ramsizeptr = memptr;
		ramsizelen = search_len;
	}

	if (ramsizeptr) {
		/* Check Magic */
		for (i = 0; ; i++) {
			if (ramsize_ptr_ptr[i] == RAMSIZE_PTR_PTR_END)
				break;

			if (ramsize_ptr_ptr[i] + sizeof(hnd_ramsize_ptr_t) > ramsizelen)
				continue;

			memcpy((char *)&ramsize_info, ramsizeptr + ramsize_ptr_ptr[i],
				sizeof(hnd_ramsize_ptr_t));

			if (ramsize_info.magic == HTOL32(HND_RAMSIZE_PTR_MAGIC)) {
				bus->orig_ramsize = LTOH32(ramsize_info.ram_size);
				bus->ramsize = LTOH32(ramsize_info.ram_size);
				DHD_ERROR(("%s: Adjust dongle RAMSIZE to 0x%x\n", __FUNCTION__,
					bus->ramsize));
				break;
			}
		}
	}

err:
	if (memptr)
		MFREE(bus->dhd->osh, memptr, search_len);

	return;
} /* dhdpcie_ramsize_adj */

/**
 * Downloads firmware file given by 'bus->fw_path' into PCIe dongle
 *
 * BCMEMBEDIMAGE specific:
 * If bus->fw_path is empty, or if the download of bus->fw_path failed, firmware contained in header
 * file will be used instead.
 *
 */
static int
_dhdpcie_download_firmware(struct dhd_bus *bus)
{
	int bcmerror = -1;

	bool embed = FALSE;	/* download embedded firmware */
	bool dlok = FALSE;	/* download firmware succeeded */

	/* Out immediately if no image to download */
	if ((bus->fw_path == NULL) || (bus->fw_path[0] == '\0')) {
		DHD_ERROR(("%s: no fimrware file\n", __FUNCTION__));
		return 0;
	}
	/* Adjust ram size */
	dhdpcie_ramsize_adj(bus);

	/* Keep arm in reset */
	if (dhdpcie_bus_download_state(bus, TRUE)) {
		DHD_ERROR(("%s: error placing ARM core in reset\n", __FUNCTION__));
		goto err;
	}

	/* External image takes precedence if specified */
	if ((bus->fw_path != NULL) && (bus->fw_path[0] != '\0')) {
		if (dhdpcie_download_code_file(bus, bus->fw_path)) {
			DHD_ERROR(("%s:%d dongle image file download failed\n", __FUNCTION__,
				__LINE__));
			goto err;
		} else {
			embed = FALSE;
			dlok = TRUE;
		}
	}

	BCM_REFERENCE(embed);
	if (!dlok) {
		DHD_ERROR(("%s:%d dongle image download failed\n", __FUNCTION__, __LINE__));
		goto err;
	}

	/* EXAMPLE: nvram_array */
	/* If a valid nvram_arry is specified as above, it can be passed down to dongle */
	/* dhd_bus_set_nvram_params(bus, (char *)&nvram_array); */

	/* External nvram takes precedence if specified */
	if (dhdpcie_download_nvram(bus)) {
		DHD_ERROR(("%s:%d dongle nvram file download failed\n", __FUNCTION__, __LINE__));
		goto err;
	}

	/* Take arm out of reset */
	if (dhdpcie_bus_download_state(bus, FALSE)) {
		DHD_ERROR(("%s: error getting out of ARM core reset\n", __FUNCTION__));
		goto err;
	}

	bcmerror = 0;

err:
	return bcmerror;
} /* _dhdpcie_download_firmware */

static int
dhdpcie_bus_readconsole(dhd_bus_t *bus)
{
	dhd_console_t *c = &bus->console;
	uint8 line[CONSOLE_LINE_MAX], ch;
	uint32 n, idx, addr;
	int rv;
	uint readlen = 0;
	uint i = 0;

	/* Don't do anything until FWREADY updates console address */
	if (bus->console_addr == 0)
		return -1;

	/* Read console log struct */
	addr = bus->console_addr + OFFSETOF(hnd_cons_t, log);

	if ((rv = dhdpcie_bus_membytes(bus, FALSE, addr, (uint8 *)&c->log, sizeof(c->log))) < 0)
		return rv;

	/* Allocate console buffer (one time only) */
	if (c->buf == NULL) {
		c->bufsize = ltoh32(c->log.buf_size);
		if ((c->buf = MALLOC(bus->dhd->osh, c->bufsize)) == NULL)
			return BCME_NOMEM;
		DHD_INFO(("conlog: bufsize=0x%x\n", c->bufsize));
	}
	idx = ltoh32(c->log.idx);

	/* Protect against corrupt value */
	if (idx > c->bufsize)
		return BCME_ERROR;

	/* Skip reading the console buffer if the index pointer has not moved */
	if (idx == c->last)
		return BCME_OK;

	DHD_INFO(("conlog: addr=0x%x, idx=0x%x, last=0x%x \n", c->log.buf,
	   idx, c->last));

	/* Read the console buffer data to a local buffer */
	/* optimize and read only the portion of the buffer needed, but
	 * important to handle wrap-around.
	 */
	addr = ltoh32(c->log.buf);

	/* wrap around case - write ptr < read ptr */
	if (idx < c->last) {
		/* from read ptr to end of buffer */
		readlen = c->bufsize - c->last;
		if ((rv = dhdpcie_bus_membytes(bus, FALSE,
				addr + c->last, c->buf, readlen)) < 0) {
			DHD_ERROR(("conlog: read error[1] ! \n"));
			return rv;
		}
		/* from beginning of buffer to write ptr */
		if ((rv = dhdpcie_bus_membytes(bus, FALSE,
				addr, c->buf + readlen,
				idx)) < 0) {
			DHD_ERROR(("conlog: read error[2] ! \n"));
			return rv;
		}
		readlen += idx;
	} else {
		/* non-wraparound case, write ptr > read ptr */
		readlen = (uint)idx - c->last;
		if ((rv = dhdpcie_bus_membytes(bus, FALSE,
				addr + c->last, c->buf, readlen)) < 0) {
			DHD_ERROR(("conlog: read error[3] ! \n"));
			return rv;
		}
	}
	/* update read ptr */
	c->last = idx;

	/* now output the read data from the local buffer to the host console */
	while (i < readlen) {
		for (n = 0; n < CONSOLE_LINE_MAX - 2 && i < readlen; n++) {
			ch = c->buf[i];
			++i;
			if (ch == '\n')
				break;
			line[n] = ch;
		}

		if (n > 0) {
			if (line[n - 1] == '\r')
				n--;
			line[n] = 0;
			printf("CONSOLE: %s\n", line);
		}
	}

	return BCME_OK;

} /* dhdpcie_bus_readconsole */

void
dhd_bus_dump_console_buffer(dhd_bus_t *bus)
{
	uint32 n, i;
	uint32 addr;
	char *console_buffer = NULL;
	uint32 console_ptr, console_size, console_index;
	uint8 line[CONSOLE_LINE_MAX], ch;
	int rv;

	DHD_ERROR(("%s: Dump Complete Console Buffer\n", __FUNCTION__));

	if (bus->is_linkdown) {
		DHD_ERROR(("%s: Skip dump Console Buffer due to PCIe link down\n", __FUNCTION__));
		return;
	}

	addr =	bus->pcie_sh->console_addr + OFFSETOF(hnd_cons_t, log);
	if ((rv = dhdpcie_bus_membytes(bus, FALSE, addr,
		(uint8 *)&console_ptr, sizeof(console_ptr))) < 0) {
		goto exit;
	}

	addr =	bus->pcie_sh->console_addr + OFFSETOF(hnd_cons_t, log.buf_size);
	if ((rv = dhdpcie_bus_membytes(bus, FALSE, addr,
		(uint8 *)&console_size, sizeof(console_size))) < 0) {
		goto exit;
	}

	addr =	bus->pcie_sh->console_addr + OFFSETOF(hnd_cons_t, log.idx);
	if ((rv = dhdpcie_bus_membytes(bus, FALSE, addr,
		(uint8 *)&console_index, sizeof(console_index))) < 0) {
		goto exit;
	}

	console_ptr = ltoh32(console_ptr);
	console_size = ltoh32(console_size);
	console_index = ltoh32(console_index);

	if (console_size > CONSOLE_BUFFER_MAX ||
		!(console_buffer = MALLOC(bus->dhd->osh, console_size))) {
		goto exit;
	}

	if ((rv = dhdpcie_bus_membytes(bus, FALSE, console_ptr,
		(uint8 *)console_buffer, console_size)) < 0) {
		goto exit;
	}

	for (i = 0, n = 0; i < console_size; i += n + 1) {
		for (n = 0; n < CONSOLE_LINE_MAX - 2; n++) {
			ch = console_buffer[(console_index + i + n) % console_size];
			if (ch == '\n')
				break;
			line[n] = ch;
		}

		if (n > 0) {
			if (line[n - 1] == '\r')
				n--;
			line[n] = 0;
			/* Don't use DHD_ERROR macro since we print
			 * a lot of information quickly. The macro
			 * will truncate a lot of the printfs
			 */

			printf("CONSOLE: %s\n", line);
		}
	}

exit:
	if (console_buffer)
		MFREE(bus->dhd->osh, console_buffer, console_size);
	return;
}

/**
 * Opens the file given by bus->fw_path, reads part of the file into a buffer and closes the file.
 *
 * @return BCME_OK on success
 */
static int
dhdpcie_checkdied(dhd_bus_t *bus, char *data, uint size)
{
	int bcmerror = 0;
	uint msize = 512;
	char *mbuffer = NULL;
	uint maxstrlen = 256;
	char *str = NULL;
	pciedev_shared_t *local_pciedev_shared = bus->pcie_sh;
	struct bcmstrbuf strbuf;
	unsigned long flags;
	bool dongle_trap_occured = FALSE;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (DHD_NOCHECKDIED_ON()) {
		return 0;
	}

	if (data == NULL) {
		/*
		 * Called after a rx ctrl timeout. "data" is NULL.
		 * allocate memory to trace the trap or assert.
		 */
		size = msize;
		mbuffer = data = MALLOC(bus->dhd->osh, msize);

		if (mbuffer == NULL) {
			DHD_ERROR(("%s: MALLOC(%d) failed \n", __FUNCTION__, msize));
			bcmerror = BCME_NOMEM;
			goto done2;
		}
	}

	if ((str = MALLOC(bus->dhd->osh, maxstrlen)) == NULL) {
		DHD_ERROR(("%s: MALLOC(%d) failed \n", __FUNCTION__, maxstrlen));
		bcmerror = BCME_NOMEM;
		goto done2;
	}
	DHD_GENERAL_LOCK(bus->dhd, flags);
	DHD_BUS_BUSY_SET_IN_CHECKDIED(bus->dhd);
	DHD_GENERAL_UNLOCK(bus->dhd, flags);

	if (MULTIBP_ENAB(bus->sih)) {
		dhd_bus_pcie_pwr_req(bus);
	}
	if ((bcmerror = dhdpcie_readshared(bus)) < 0) {
		goto done1;
	}

	bcm_binit(&strbuf, data, size);

	bcm_bprintf(&strbuf, "msgtrace address : 0x%08X\nconsole address  : 0x%08X\n",
	            local_pciedev_shared->msgtrace_addr, local_pciedev_shared->console_addr);

	if ((local_pciedev_shared->flags & PCIE_SHARED_ASSERT_BUILT) == 0) {
		/* NOTE: Misspelled assert is intentional - DO NOT FIX.
		 * (Avoids conflict with real asserts for programmatic parsing of output.)
		 */
		bcm_bprintf(&strbuf, "Assrt not built in dongle\n");
	}

	if ((bus->pcie_sh->flags & (PCIE_SHARED_ASSERT|PCIE_SHARED_TRAP)) == 0) {
		/* NOTE: Misspelled assert is intentional - DO NOT FIX.
		 * (Avoids conflict with real asserts for programmatic parsing of output.)
		 */
		bcm_bprintf(&strbuf, "No trap%s in dongle",
		          (bus->pcie_sh->flags & PCIE_SHARED_ASSERT_BUILT)
		          ?"/assrt" :"");
	} else {
		if (bus->pcie_sh->flags & PCIE_SHARED_ASSERT) {
			/* Download assert */
			bcm_bprintf(&strbuf, "Dongle assert");
			if (bus->pcie_sh->assert_exp_addr != 0) {
				str[0] = '\0';
				if ((bcmerror = dhdpcie_bus_membytes(bus, FALSE,
					bus->pcie_sh->assert_exp_addr,
					(uint8 *)str, maxstrlen)) < 0) {
					goto done1;
				}

				str[maxstrlen - 1] = '\0';
				bcm_bprintf(&strbuf, " expr \"%s\"", str);
			}

			if (bus->pcie_sh->assert_file_addr != 0) {
				str[0] = '\0';
				if ((bcmerror = dhdpcie_bus_membytes(bus, FALSE,
					bus->pcie_sh->assert_file_addr,
					(uint8 *)str, maxstrlen)) < 0) {
					goto done1;
				}

				str[maxstrlen - 1] = '\0';
				bcm_bprintf(&strbuf, " file \"%s\"", str);
			}

			bcm_bprintf(&strbuf, " line %d ",  bus->pcie_sh->assert_line);
		}

		if (bus->pcie_sh->flags & PCIE_SHARED_TRAP) {
			trap_t *tr = &bus->dhd->last_trap_info;
			dongle_trap_occured = TRUE;
			if ((bcmerror = dhdpcie_bus_membytes(bus, FALSE,
				bus->pcie_sh->trap_addr, (uint8*)tr, sizeof(trap_t))) < 0) {
				bus->dhd->dongle_trap_occured = TRUE;
				goto done1;
			}
			dhd_bus_dump_trap_info(bus, &strbuf);
		}
	}

	if (bus->pcie_sh->flags & (PCIE_SHARED_ASSERT | PCIE_SHARED_TRAP)) {
		printf("%s: %s\n", __FUNCTION__, strbuf.origbuf);

		dhd_bus_dump_console_buffer(bus);
		dhd_prot_debug_info_print(bus->dhd);

#if defined(DHD_FW_COREDUMP)
		/* save core dump or write to a file */
		if (bus->dhd->memdump_enabled) {
#ifdef DHD_SSSR_DUMP
			bus->dhd->collect_sssr = TRUE;
#endif /* DHD_SSSR_DUMP */
			bus->dhd->memdump_type = DUMP_TYPE_DONGLE_TRAP;
			dhdpcie_mem_dump(bus);
		}
#endif /* DHD_FW_COREDUMP */

		/* set the trap occured flag only after all the memdump,
		* logdump and sssr dump collection has been scheduled
		*/
		if (dongle_trap_occured) {
			bus->dhd->dongle_trap_occured = TRUE;
		}

		/* wake up IOCTL wait event */
		dhd_wakeup_ioctl_event(bus->dhd, IOCTL_RETURN_ON_TRAP);

		dhd_schedule_reset(bus->dhd);

	}

done1:
	if (MULTIBP_ENAB(bus->sih)) {
		dhd_bus_pcie_pwr_req_clear(bus);
	}

	DHD_GENERAL_LOCK(bus->dhd, flags);
	DHD_BUS_BUSY_CLEAR_IN_CHECKDIED(bus->dhd);
	dhd_os_busbusy_wake(bus->dhd);
	DHD_GENERAL_UNLOCK(bus->dhd, flags);
done2:
	if (mbuffer)
		MFREE(bus->dhd->osh, mbuffer, msize);
	if (str)
		MFREE(bus->dhd->osh, str, maxstrlen);

	return bcmerror;
} /* dhdpcie_checkdied */

/* Custom copy of dhdpcie_mem_dump() that can be called at interrupt level */
void dhdpcie_mem_dump_bugcheck(dhd_bus_t *bus, uint8 *buf)
{
	int ret = 0;
	int size; /* Full mem size */
	int start; /* Start address */
	int read_size = 0; /* Read size of each iteration */
	uint8 *databuf = buf;

	if (bus == NULL) {
		return;
	}

	start = bus->dongle_ram_base;
	read_size = 4;
	/* check for dead bus */
	{
		uint test_word = 0;
		ret = dhdpcie_bus_membytes(bus, FALSE, start, (uint8*)&test_word, read_size);
		/* if read error or bus timeout */
		if (ret || (test_word == 0xFFFFFFFF)) {
			return;
		}
	}

	/* Get full mem size */
	size = bus->ramsize;
	/* Read mem content */
	while (size)
	{
		read_size = MIN(MEMBLOCK, size);
		if ((ret = dhdpcie_bus_membytes(bus, FALSE, start, databuf, read_size))) {
			return;
		}

		/* Decrement size and increment start address */
		size -= read_size;
		start += read_size;
		databuf += read_size;
	}
	bus->dhd->soc_ram = buf;
	bus->dhd->soc_ram_length = bus->ramsize;
	return;
}

#if defined(DHD_FW_COREDUMP)
static int
dhdpcie_get_mem_dump(dhd_bus_t *bus)
{
	int ret = BCME_OK;
	int size = 0;
	int start = 0;
	int read_size = 0; /* Read size of each iteration */
	uint8 *p_buf = NULL, *databuf = NULL;

	if (!bus) {
		DHD_ERROR(("%s: bus is NULL\n", __FUNCTION__));
		return BCME_ERROR;
	}

	if (!bus->dhd) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return BCME_ERROR;
	}

	size = bus->ramsize; /* Full mem size */
	start = bus->dongle_ram_base; /* Start address */

	/* Get full mem size */
	p_buf = dhd_get_fwdump_buf(bus->dhd, size);
	if (!p_buf) {
		DHD_ERROR(("%s: Out of memory (%d bytes)\n",
			__FUNCTION__, size));
		return BCME_ERROR;
	}

	/* Read mem content */
	DHD_TRACE_HW4(("Dump dongle memory\n"));
	databuf = p_buf;
	while (size > 0) {
		read_size = MIN(MEMBLOCK, size);
		ret = dhdpcie_bus_membytes(bus, FALSE, start, databuf, read_size);
		if (ret) {
			DHD_ERROR(("%s: Error membytes %d\n", __FUNCTION__, ret));
#ifdef DHD_DEBUG_UART
			bus->dhd->memdump_success = FALSE;
#endif	/* DHD_DEBUG_UART */
			break;
		}
		DHD_TRACE(("."));

		/* Decrement size and increment start address */
		size -= read_size;
		start += read_size;
		databuf += read_size;
	}

	return ret;
}

static int
dhdpcie_mem_dump(dhd_bus_t *bus)
{
	dhd_pub_t *dhdp;
	int ret;

#ifdef EXYNOS_PCIE_DEBUG
	exynos_pcie_register_dump(1);
#endif /* EXYNOS_PCIE_DEBUG */

	dhdp = bus->dhd;
	if (!dhdp) {
		DHD_ERROR(("%s: dhdp is NULL\n", __FUNCTION__));
		return BCME_ERROR;
	}

	if (DHD_BUS_CHECK_DOWN_OR_DOWN_IN_PROGRESS(dhdp)) {
		DHD_ERROR(("%s: bus is down! can't collect mem dump. \n", __FUNCTION__));
		return BCME_ERROR;
	}

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
	if (pm_runtime_get_sync(dhd_bus_to_dev(bus)) < 0)
		return BCME_ERROR;
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

	ret = dhdpcie_get_mem_dump(bus);
	if (ret) {
		DHD_ERROR(("%s: failed to get mem dump, err=%d\n",
			__FUNCTION__, ret));
		return ret;
	}

	dhd_schedule_memdump(dhdp, dhdp->soc_ram, dhdp->soc_ram_length);
	/* buf, actually soc_ram free handled in dhd_{free,clear} */

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
	pm_runtime_mark_last_busy(dhd_bus_to_dev(bus));
	pm_runtime_put_autosuspend(dhd_bus_to_dev(bus));
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

	return ret;
}

int
dhd_bus_get_mem_dump(dhd_pub_t *dhdp)
{
	if (!dhdp) {
		DHD_ERROR(("%s: dhdp is NULL\n", __FUNCTION__));
		return BCME_ERROR;
	}

	return dhdpcie_get_mem_dump(dhdp->bus);
}

int
dhd_bus_mem_dump(dhd_pub_t *dhdp)
{
	dhd_bus_t *bus = dhdp->bus;
	int ret = BCME_ERROR;

	if (dhdp->busstate == DHD_BUS_DOWN) {
		DHD_ERROR(("%s bus is down\n", __FUNCTION__));
		return BCME_ERROR;
	}

	/* Try to resume if already suspended or suspend in progress */

	/* Skip if still in suspended or suspend in progress */
	if (DHD_BUS_CHECK_SUSPEND_OR_ANY_SUSPEND_IN_PROGRESS(dhdp)) {
		DHD_ERROR(("%s: bus is in suspend(%d) or suspending(0x%x) state, so skip\n",
			__FUNCTION__, dhdp->busstate, dhdp->dhd_bus_busy_state));
		return BCME_ERROR;
	}

	DHD_OS_WAKE_LOCK(dhdp);
	ret = dhdpcie_mem_dump(bus);
	DHD_OS_WAKE_UNLOCK(dhdp);
	return ret;
}
#endif	/* DHD_FW_COREDUMP */

int
dhd_socram_dump(dhd_bus_t *bus)
{
#if defined(DHD_FW_COREDUMP)
	DHD_OS_WAKE_LOCK(bus->dhd);
	dhd_bus_mem_dump(bus->dhd);
	DHD_OS_WAKE_UNLOCK(bus->dhd);
	return 0;
#else
	return -1;
#endif // endif
}

/**
 * Transfers bytes from host to dongle using pio mode.
 * Parameter 'address' is a backplane address.
 */
static int
dhdpcie_bus_membytes(dhd_bus_t *bus, bool write, ulong address, uint8 *data, uint size)
{
	uint dsize;
	int detect_endian_flag = 0x01;
	bool little_endian;

	if (write && bus->is_linkdown) {
		DHD_ERROR(("%s: PCIe link was down\n", __FUNCTION__));
		return BCME_ERROR;
	}

	if (MULTIBP_ENAB(bus->sih)) {
		dhd_bus_pcie_pwr_req(bus);
	}
	/* Detect endianness. */
	little_endian = *(char *)&detect_endian_flag;

	/* In remap mode, adjust address beyond socram and redirect
	 * to devram at SOCDEVRAM_BP_ADDR since remap address > orig_ramsize
	 * is not backplane accessible
	 */

	/* Determine initial transfer parameters */
#ifdef DHD_SUPPORT_64BIT
	dsize = sizeof(uint64);
#else /* !DHD_SUPPORT_64BIT */
	dsize = sizeof(uint32);
#endif /* DHD_SUPPORT_64BIT */

	/* Do the transfer(s) */
	DHD_INFO(("%s: %s %d bytes in window 0x%08lx\n",
	          __FUNCTION__, (write ? "write" : "read"), size, address));
	if (write) {
		while (size) {
#ifdef DHD_SUPPORT_64BIT
			if (size >= sizeof(uint64) && little_endian &&	!(address % 8)) {
				dhdpcie_bus_wtcm64(bus, address, *((uint64 *)data));
			}
#else /* !DHD_SUPPORT_64BIT */
			if (size >= sizeof(uint32) && little_endian &&	!(address % 4)) {
				dhdpcie_bus_wtcm32(bus, address, *((uint32*)data));
			}
#endif /* DHD_SUPPORT_64BIT */
			else {
				dsize = sizeof(uint8);
				dhdpcie_bus_wtcm8(bus, address, *data);
			}

			/* Adjust for next transfer (if any) */
			if ((size -= dsize)) {
				data += dsize;
				address += dsize;
			}
		}
	} else {
		while (size) {
#ifdef DHD_SUPPORT_64BIT
			if (size >= sizeof(uint64) && little_endian &&	!(address % 8))
			{
				*(uint64 *)data = dhdpcie_bus_rtcm64(bus, address);
			}
#else /* !DHD_SUPPORT_64BIT */
			if (size >= sizeof(uint32) && little_endian &&	!(address % 4))
			{
				*(uint32 *)data = dhdpcie_bus_rtcm32(bus, address);
			}
#endif /* DHD_SUPPORT_64BIT */
			else {
				dsize = sizeof(uint8);
				*data = dhdpcie_bus_rtcm8(bus, address);
			}

			/* Adjust for next transfer (if any) */
			if ((size -= dsize) > 0) {
				data += dsize;
				address += dsize;
			}
		}
	}
	if (MULTIBP_ENAB(bus->sih)) {
		dhd_bus_pcie_pwr_req_clear(bus);
	}
	return BCME_OK;
} /* dhdpcie_bus_membytes */

/**
 * Transfers one transmit (ethernet) packet that was queued in the (flow controlled) flow ring queue
 * to the (non flow controlled) flow ring.
 */
int BCMFASTPATH
dhd_bus_schedule_queue(struct dhd_bus  *bus, uint16 flow_id, bool txs)
{
	flow_ring_node_t *flow_ring_node;
	int ret = BCME_OK;
#ifdef DHD_LOSSLESS_ROAMING
	dhd_pub_t *dhdp = bus->dhd;
#endif // endif
	DHD_INFO(("%s: flow_id is %d\n", __FUNCTION__, flow_id));

	/* ASSERT on flow_id */
	if (flow_id >= bus->max_submission_rings) {
		DHD_ERROR(("%s: flow_id is invalid %d, max %d\n", __FUNCTION__,
			flow_id, bus->max_submission_rings));
		return 0;
	}

	flow_ring_node = DHD_FLOW_RING(bus->dhd, flow_id);

	if (flow_ring_node->prot_info == NULL) {
	    DHD_ERROR((" %s : invalid flow_ring_node \n", __FUNCTION__));
	    return BCME_NOTREADY;
	}

#ifdef DHD_LOSSLESS_ROAMING
	if ((dhdp->dequeue_prec_map & (1 << flow_ring_node->flow_info.tid)) == 0) {
		DHD_INFO(("%s: tid %d is not in precedence map. block scheduling\n",
			__FUNCTION__, flow_ring_node->flow_info.tid));
		return BCME_OK;
	}
#endif /* DHD_LOSSLESS_ROAMING */

	{
		unsigned long flags;
		void *txp = NULL;
		flow_queue_t *queue;
#ifdef DHD_LOSSLESS_ROAMING
		struct ether_header *eh;
		uint8 *pktdata;
#endif /* DHD_LOSSLESS_ROAMING */
#ifdef TPUT_MONITOR
		int pktlen;
#endif

		queue = &flow_ring_node->queue; /* queue associated with flow ring */

		DHD_FLOWRING_LOCK(flow_ring_node->lock, flags);

		if (flow_ring_node->status != FLOW_RING_STATUS_OPEN) {
			DHD_FLOWRING_UNLOCK(flow_ring_node->lock, flags);
			return BCME_NOTREADY;
		}

		while ((txp = dhd_flow_queue_dequeue(bus->dhd, queue)) != NULL) {
			if (bus->dhd->conf->orphan_move <= 1)
				PKTORPHAN(txp, bus->dhd->conf->tsq);

			/*
			 * Modifying the packet length caused P2P cert failures.
			 * Specifically on test cases where a packet of size 52 bytes
			 * was injected, the sniffer capture showed 62 bytes because of
			 * which the cert tests failed. So making the below change
			 * only Router specific.
			 */

#ifdef DHDTCPACK_SUPPRESS
			if (bus->dhd->tcpack_sup_mode != TCPACK_SUP_HOLD) {
				ret = dhd_tcpack_check_xmit(bus->dhd, txp);
				if (ret != BCME_OK) {
					DHD_ERROR(("%s: dhd_tcpack_check_xmit() error.\n",
						__FUNCTION__));
				}
			}
#endif /* DHDTCPACK_SUPPRESS */
#ifdef DHD_LOSSLESS_ROAMING
			pktdata = (uint8 *)PKTDATA(OSH_NULL, txp);
			eh = (struct ether_header *) pktdata;
			if (eh->ether_type == hton16(ETHER_TYPE_802_1X)) {
				uint8 prio = (uint8)PKTPRIO(txp);
				/* Restore to original priority for 802.1X packet */
				if (prio == PRIO_8021D_NC) {
					PKTSETPRIO(txp, dhdp->prio_8021x);
				}
			}
#endif /* DHD_LOSSLESS_ROAMING */
			/* Attempt to transfer packet over flow ring */
#ifdef TPUT_MONITOR
			pktlen  = PKTLEN(OSH_NULL, txp);
			if ((bus->dhd->conf->data_drop_mode == TXPKT_DROP) && (pktlen > 500))
				ret = BCME_OK;
			else
#endif
			ret = dhd_prot_txdata(bus->dhd, txp, flow_ring_node->flow_info.ifindex);
			if (ret != BCME_OK) { /* may not have resources in flow ring */
				DHD_INFO(("%s: Reinserrt %d\n", __FUNCTION__, ret));
				dhd_prot_txdata_write_flush(bus->dhd, flow_id);
				/* reinsert at head */
				dhd_flow_queue_reinsert(bus->dhd, queue, txp);
				DHD_FLOWRING_UNLOCK(flow_ring_node->lock, flags);

				/* If we are able to requeue back, return success */
				return BCME_OK;
			}
		}

#ifdef DHD_HP2P
		if (!flow_ring_node->hp2p_ring) {
			dhd_prot_txdata_write_flush(bus->dhd, flow_id);
		}
#else
		dhd_prot_txdata_write_flush(bus->dhd, flow_id);
#endif // endif
		DHD_FLOWRING_UNLOCK(flow_ring_node->lock, flags);
	}

	return ret;
} /* dhd_bus_schedule_queue */

/** Sends an (ethernet) data frame (in 'txp') to the dongle. Callee disposes of txp. */
int BCMFASTPATH
dhd_bus_txdata(struct dhd_bus *bus, void *txp, uint8 ifidx)
{
	uint16 flowid;
#ifdef IDLE_TX_FLOW_MGMT
	uint8	node_status;
#endif /* IDLE_TX_FLOW_MGMT */
	flow_queue_t *queue;
	flow_ring_node_t *flow_ring_node;
	unsigned long flags;
	int ret = BCME_OK;
	void *txp_pend = NULL;

	if (!bus->dhd->flowid_allocator) {
		DHD_ERROR(("%s: Flow ring not intited yet  \n", __FUNCTION__));
		goto toss;
	}

	flowid = DHD_PKT_GET_FLOWID(txp);

	flow_ring_node = DHD_FLOW_RING(bus->dhd, flowid);

	DHD_TRACE(("%s: pkt flowid %d, status %d active %d\n",
		__FUNCTION__, flowid, flow_ring_node->status, flow_ring_node->active));

	DHD_FLOWRING_LOCK(flow_ring_node->lock, flags);
	if ((flowid >= bus->dhd->num_flow_rings) ||
#ifdef IDLE_TX_FLOW_MGMT
		(!flow_ring_node->active))
#else
		(!flow_ring_node->active) ||
		(flow_ring_node->status == FLOW_RING_STATUS_DELETE_PENDING) ||
		(flow_ring_node->status == FLOW_RING_STATUS_STA_FREEING))
#endif /* IDLE_TX_FLOW_MGMT */
	{
		DHD_FLOWRING_UNLOCK(flow_ring_node->lock, flags);
		DHD_INFO(("%s: Dropping pkt flowid %d, status %d active %d\n",
			__FUNCTION__, flowid, flow_ring_node->status,
			flow_ring_node->active));
		ret = BCME_ERROR;
			goto toss;
	}

#ifdef IDLE_TX_FLOW_MGMT
	node_status = flow_ring_node->status;

	/* handle diffrent status states here!! */
	switch (node_status)
	{
		case FLOW_RING_STATUS_OPEN:

			if (bus->enable_idle_flowring_mgmt) {
				/* Move the node to the head of active list */
				dhd_flow_ring_move_to_active_list_head(bus, flow_ring_node);
			}
			break;

		case FLOW_RING_STATUS_SUSPENDED:
			DHD_INFO(("Need to Initiate TX Flow resume\n"));
			/* Issue resume_ring request */
			dhd_bus_flow_ring_resume_request(bus,
					flow_ring_node);
			break;

		case FLOW_RING_STATUS_CREATE_PENDING:
		case FLOW_RING_STATUS_RESUME_PENDING:
			/* Dont do anything here!! */
			DHD_INFO(("Waiting for Flow create/resume! status is %u\n",
				node_status));
			break;

		case FLOW_RING_STATUS_DELETE_PENDING:
		default:
			DHD_ERROR(("Dropping packet!! flowid %u status is %u\n",
				flowid, node_status));
			/* error here!! */
			ret = BCME_ERROR;
			DHD_FLOWRING_UNLOCK(flow_ring_node->lock, flags);
			goto toss;
	}
	/* Now queue the packet */
#endif /* IDLE_TX_FLOW_MGMT */

	queue = &flow_ring_node->queue; /* queue associated with flow ring */

	if ((ret = dhd_flow_queue_enqueue(bus->dhd, queue, txp)) != BCME_OK)
		txp_pend = txp;

	DHD_FLOWRING_UNLOCK(flow_ring_node->lock, flags);

	if (flow_ring_node->status) {
		DHD_INFO(("%s: Enq pkt flowid %d, status %d active %d\n",
		    __FUNCTION__, flowid, flow_ring_node->status,
		    flow_ring_node->active));
		if (txp_pend) {
			txp = txp_pend;
			goto toss;
		}
		return BCME_OK;
	}
	ret = dhd_bus_schedule_queue(bus, flowid, FALSE); /* from queue to flowring */

	/* If we have anything pending, try to push into q */
	if (txp_pend) {
		DHD_FLOWRING_LOCK(flow_ring_node->lock, flags);

		if ((ret = dhd_flow_queue_enqueue(bus->dhd, queue, txp_pend)) != BCME_OK) {
			DHD_FLOWRING_UNLOCK(flow_ring_node->lock, flags);
			txp = txp_pend;
			goto toss;
		}

		DHD_FLOWRING_UNLOCK(flow_ring_node->lock, flags);
	}

	return ret;

toss:
	DHD_INFO(("%s: Toss %d\n", __FUNCTION__, ret));
	PKTCFREE(bus->dhd->osh, txp, TRUE);
	return ret;
} /* dhd_bus_txdata */

void
dhd_bus_stop_queue(struct dhd_bus *bus)
{
	dhd_txflowcontrol(bus->dhd, ALL_INTERFACES, ON);
}

void
dhd_bus_start_queue(struct dhd_bus *bus)
{
	/*
	 * Tx queue has been stopped due to resource shortage (or)
	 * bus is not in a state to turn on.
	 *
	 * Note that we try to re-start network interface only
	 * when we have enough resources, one has to first change the
	 * flag indicating we have all the resources.
	 */
	if (dhd_prot_check_tx_resource(bus->dhd)) {
		DHD_ERROR(("%s: Interface NOT started, previously stopped "
			"due to resource shortage\n", __FUNCTION__));
		return;
	}
	dhd_txflowcontrol(bus->dhd, ALL_INTERFACES, OFF);
}

/* Device console input function */
int dhd_bus_console_in(dhd_pub_t *dhd, uchar *msg, uint msglen)
{
	dhd_bus_t *bus = dhd->bus;
	uint32 addr, val;
	int rv;
	/* Address could be zero if CONSOLE := 0 in dongle Makefile */
	if (bus->console_addr == 0)
		return BCME_UNSUPPORTED;

	/* Don't allow input if dongle is in reset */
	if (bus->dhd->dongle_reset) {
		return BCME_NOTREADY;
	}

	/* Zero cbuf_index */
	addr = bus->console_addr + OFFSETOF(hnd_cons_t, cbuf_idx);
	val = htol32(0);
	if ((rv = dhdpcie_bus_membytes(bus, TRUE, addr, (uint8 *)&val, sizeof(val))) < 0)
		goto done;

	/* Write message into cbuf */
	addr = bus->console_addr + OFFSETOF(hnd_cons_t, cbuf);
	if ((rv = dhdpcie_bus_membytes(bus, TRUE, addr, (uint8 *)msg, msglen)) < 0)
		goto done;

	/* Write length into vcons_in */
	addr = bus->console_addr + OFFSETOF(hnd_cons_t, vcons_in);
	val = htol32(msglen);
	if ((rv = dhdpcie_bus_membytes(bus, TRUE, addr, (uint8 *)&val, sizeof(val))) < 0)
		goto done;

	/* generate an interrupt to dongle to indicate that it needs to process cons command */
	dhdpcie_send_mb_data(bus, H2D_HOST_CONS_INT);
done:
	return rv;
} /* dhd_bus_console_in */

/**
 * Called on frame reception, the frame was received from the dongle on interface 'ifidx' and is
 * contained in 'pkt'. Processes rx frame, forwards up the layer to netif.
 */
void BCMFASTPATH
dhd_bus_rx_frame(struct dhd_bus *bus, void* pkt, int ifidx, uint pkt_count)
{
	dhd_rx_frame(bus->dhd, ifidx, pkt, pkt_count, 0);
}

void
dhdpcie_setbar1win(dhd_bus_t *bus, uint32 addr)
{
	dhdpcie_os_setbar1win(bus, addr);
}

/** 'offset' is a backplane address */
void
dhdpcie_bus_wtcm8(dhd_bus_t *bus, ulong offset, uint8 data)
{
	if (bus->is_linkdown) {
		DHD_LOG_MEM(("%s: PCIe link was down\n", __FUNCTION__));
		return;
	} else {
		dhdpcie_os_wtcm8(bus, offset, data);
	}
}

uint8
dhdpcie_bus_rtcm8(dhd_bus_t *bus, ulong offset)
{
	volatile uint8 data;
	if (bus->is_linkdown) {
		DHD_LOG_MEM(("%s: PCIe link was down\n", __FUNCTION__));
		data = (uint8)-1;
	} else {
		data = dhdpcie_os_rtcm8(bus, offset);
	}
	return data;
}

void
dhdpcie_bus_wtcm32(dhd_bus_t *bus, ulong offset, uint32 data)
{
	if (bus->is_linkdown) {
		DHD_LOG_MEM(("%s: PCIe link was down\n", __FUNCTION__));
		return;
	} else {
		dhdpcie_os_wtcm32(bus, offset, data);
	}
}
void
dhdpcie_bus_wtcm16(dhd_bus_t *bus, ulong offset, uint16 data)
{
	if (bus->is_linkdown) {
		DHD_LOG_MEM(("%s: PCIe link was down\n", __FUNCTION__));
		return;
	} else {
		dhdpcie_os_wtcm16(bus, offset, data);
	}
}
#ifdef DHD_SUPPORT_64BIT
void
dhdpcie_bus_wtcm64(dhd_bus_t *bus, ulong offset, uint64 data)
{
	if (bus->is_linkdown) {
		DHD_LOG_MEM(("%s: PCIe link was down\n", __FUNCTION__));
		return;
	} else {
		dhdpcie_os_wtcm64(bus, offset, data);
	}
}
#endif /* DHD_SUPPORT_64BIT */

uint16
dhdpcie_bus_rtcm16(dhd_bus_t *bus, ulong offset)
{
	volatile uint16 data;
	if (bus->is_linkdown) {
		DHD_LOG_MEM(("%s: PCIe link was down\n", __FUNCTION__));
		data = (uint16)-1;
	} else {
		data = dhdpcie_os_rtcm16(bus, offset);
	}
	return data;
}

uint32
dhdpcie_bus_rtcm32(dhd_bus_t *bus, ulong offset)
{
	volatile uint32 data;
	if (bus->is_linkdown) {
		DHD_LOG_MEM(("%s: PCIe link was down\n", __FUNCTION__));
		data = (uint32)-1;
	} else {
		data = dhdpcie_os_rtcm32(bus, offset);
	}
	return data;
}

#ifdef DHD_SUPPORT_64BIT
uint64
dhdpcie_bus_rtcm64(dhd_bus_t *bus, ulong offset)
{
	volatile uint64 data;
	if (bus->is_linkdown) {
		DHD_LOG_MEM(("%s: PCIe link was down\n", __FUNCTION__));
		data = (uint64)-1;
	} else {
		data = dhdpcie_os_rtcm64(bus, offset);
	}
	return data;
}
#endif /* DHD_SUPPORT_64BIT */

/** A snippet of dongle memory is shared between host and dongle */
void
dhd_bus_cmn_writeshared(dhd_bus_t *bus, void *data, uint32 len, uint8 type, uint16 ringid)
{
	uint64 long_data;
	ulong addr; /* dongle address */

	DHD_INFO(("%s: writing to dongle type %d len %d\n", __FUNCTION__, type, len));

	if (bus->is_linkdown) {
		DHD_ERROR(("%s: PCIe link was down\n", __FUNCTION__));
		return;
	}

	if (MULTIBP_ENAB(bus->sih)) {
		dhd_bus_pcie_pwr_req(bus);
	}
	switch (type) {
		case D2H_DMA_SCRATCH_BUF:
			addr = DHD_PCIE_SHARED_MEMBER_ADDR(bus, host_dma_scratch_buffer);
			long_data = HTOL64(*(uint64 *)data);
			dhdpcie_bus_membytes(bus, TRUE, addr, (uint8*) &long_data, len);
			if (dhd_msg_level & DHD_INFO_VAL) {
				prhex(__FUNCTION__, data, len);
			}
			break;

		case D2H_DMA_SCRATCH_BUF_LEN :
			addr = DHD_PCIE_SHARED_MEMBER_ADDR(bus, host_dma_scratch_buffer_len);
			dhdpcie_bus_wtcm32(bus, addr, (uint32) HTOL32(*(uint32 *)data));
			if (dhd_msg_level & DHD_INFO_VAL) {
				prhex(__FUNCTION__, data, len);
			}
			break;

		case H2D_DMA_INDX_WR_BUF:
			long_data = HTOL64(*(uint64 *)data);
			addr = DHD_RING_INFO_MEMBER_ADDR(bus, h2d_w_idx_hostaddr);
			dhdpcie_bus_membytes(bus, TRUE, addr, (uint8*) &long_data, len);
			if (dhd_msg_level & DHD_INFO_VAL) {
				prhex(__FUNCTION__, data, len);
			}
			break;

		case H2D_DMA_INDX_RD_BUF:
			long_data = HTOL64(*(uint64 *)data);
			addr = DHD_RING_INFO_MEMBER_ADDR(bus, h2d_r_idx_hostaddr);
			dhdpcie_bus_membytes(bus, TRUE, addr, (uint8*) &long_data, len);
			if (dhd_msg_level & DHD_INFO_VAL) {
				prhex(__FUNCTION__, data, len);
			}
			break;

		case D2H_DMA_INDX_WR_BUF:
			long_data = HTOL64(*(uint64 *)data);
			addr = DHD_RING_INFO_MEMBER_ADDR(bus, d2h_w_idx_hostaddr);
			dhdpcie_bus_membytes(bus, TRUE, addr, (uint8*) &long_data, len);
			if (dhd_msg_level & DHD_INFO_VAL) {
				prhex(__FUNCTION__, data, len);
			}
			break;

		case D2H_DMA_INDX_RD_BUF:
			long_data = HTOL64(*(uint64 *)data);
			addr = DHD_RING_INFO_MEMBER_ADDR(bus, d2h_r_idx_hostaddr);
			dhdpcie_bus_membytes(bus, TRUE, addr, (uint8*) &long_data, len);
			if (dhd_msg_level & DHD_INFO_VAL) {
				prhex(__FUNCTION__, data, len);
			}
			break;

		case H2D_IFRM_INDX_WR_BUF:
			long_data = HTOL64(*(uint64 *)data);
			addr = DHD_RING_INFO_MEMBER_ADDR(bus, ifrm_w_idx_hostaddr);
			dhdpcie_bus_membytes(bus, TRUE, addr, (uint8*) &long_data, len);
			if (dhd_msg_level & DHD_INFO_VAL) {
				prhex(__FUNCTION__, data, len);
			}
			break;

		case RING_ITEM_LEN :
			addr = DHD_RING_MEM_MEMBER_ADDR(bus, ringid, len_items);
			dhdpcie_bus_wtcm16(bus, addr, (uint16) HTOL16(*(uint16 *)data));
			break;

		case RING_MAX_ITEMS :
			addr = DHD_RING_MEM_MEMBER_ADDR(bus, ringid, max_item);
			dhdpcie_bus_wtcm16(bus, addr, (uint16) HTOL16(*(uint16 *)data));
			break;

		case RING_BUF_ADDR :
			long_data = HTOL64(*(uint64 *)data);
			addr = DHD_RING_MEM_MEMBER_ADDR(bus, ringid, base_addr);
			dhdpcie_bus_membytes(bus, TRUE, addr, (uint8 *) &long_data, len);
			if (dhd_msg_level & DHD_INFO_VAL) {
				prhex(__FUNCTION__, data, len);
			}
			break;

		case RING_WR_UPD :
			addr = bus->ring_sh[ringid].ring_state_w;
			dhdpcie_bus_wtcm16(bus, addr, (uint16) HTOL16(*(uint16 *)data));
			break;

		case RING_RD_UPD :
			addr = bus->ring_sh[ringid].ring_state_r;
			dhdpcie_bus_wtcm16(bus, addr, (uint16) HTOL16(*(uint16 *)data));
			break;

		case D2H_MB_DATA:
			addr = bus->d2h_mb_data_ptr_addr;
			dhdpcie_bus_wtcm32(bus, addr, (uint32) HTOL32(*(uint32 *)data));
			break;

		case H2D_MB_DATA:
			addr = bus->h2d_mb_data_ptr_addr;
			dhdpcie_bus_wtcm32(bus, addr, (uint32) HTOL32(*(uint32 *)data));
			break;

		case HOST_API_VERSION:
			addr = DHD_PCIE_SHARED_MEMBER_ADDR(bus, host_cap);
			dhdpcie_bus_wtcm32(bus, addr, (uint32) HTOL32(*(uint32 *)data));
			break;

		case DNGL_TO_HOST_TRAP_ADDR:
			long_data = HTOL64(*(uint64 *)data);
			addr = DHD_PCIE_SHARED_MEMBER_ADDR(bus, host_trap_addr);
			dhdpcie_bus_membytes(bus, TRUE, addr, (uint8 *) &long_data, len);
			DHD_INFO(("Wrote trap addr:0x%x\n", (uint32) HTOL32(*(uint32 *)data)));
			break;

		case HOST_SCB_ADDR:
			addr = DHD_PCIE_SHARED_MEMBER_ADDR(bus, host_scb_addr);
#ifdef DHD_SUPPORT_64BIT
			dhdpcie_bus_wtcm64(bus, addr, (uint64) HTOL64(*(uint64 *)data));
#else /* !DHD_SUPPORT_64BIT */
			dhdpcie_bus_wtcm32(bus, addr, *((uint32*)data));
#endif /* DHD_SUPPORT_64BIT */
			DHD_INFO(("Wrote host_scb_addr:0x%x\n",
				(uint32) HTOL32(*(uint32 *)data)));
			break;

		default:
			break;
	}
	if (MULTIBP_ENAB(bus->sih)) {
		dhd_bus_pcie_pwr_req_clear(bus);
	}
} /* dhd_bus_cmn_writeshared */

/** A snippet of dongle memory is shared between host and dongle */
void
dhd_bus_cmn_readshared(dhd_bus_t *bus, void* data, uint8 type, uint16 ringid)
{
	ulong addr; /* dongle address */

	if (MULTIBP_ENAB(bus->sih)) {
		dhd_bus_pcie_pwr_req(bus);
	}
	switch (type) {
		case RING_WR_UPD :
			addr = bus->ring_sh[ringid].ring_state_w;
			*(uint16*)data = LTOH16(dhdpcie_bus_rtcm16(bus, addr));
			break;

		case RING_RD_UPD :
			addr = bus->ring_sh[ringid].ring_state_r;
			*(uint16*)data = LTOH16(dhdpcie_bus_rtcm16(bus, addr));
			break;

		case TOTAL_LFRAG_PACKET_CNT :
			addr = DHD_PCIE_SHARED_MEMBER_ADDR(bus, total_lfrag_pkt_cnt);
			*(uint16*)data = LTOH16(dhdpcie_bus_rtcm16(bus, addr));
			break;

		case H2D_MB_DATA:
			addr = bus->h2d_mb_data_ptr_addr;
			*(uint32*)data = LTOH32(dhdpcie_bus_rtcm32(bus, addr));
			break;

		case D2H_MB_DATA:
			addr = bus->d2h_mb_data_ptr_addr;
			*(uint32*)data = LTOH32(dhdpcie_bus_rtcm32(bus, addr));
			break;

		case MAX_HOST_RXBUFS :
			addr = DHD_PCIE_SHARED_MEMBER_ADDR(bus, max_host_rxbufs);
			*(uint16*)data = LTOH16(dhdpcie_bus_rtcm16(bus, addr));
			break;

		case HOST_SCB_ADDR:
			addr = DHD_PCIE_SHARED_MEMBER_ADDR(bus, host_scb_size);
			*(uint32*)data = LTOH32(dhdpcie_bus_rtcm32(bus, addr));
			break;

		default :
			break;
	}
	if (MULTIBP_ENAB(bus->sih)) {
		dhd_bus_pcie_pwr_req_clear(bus);
	}
}

uint32 dhd_bus_get_sharedflags(dhd_bus_t *bus)
{
	return ((pciedev_shared_t*)bus->pcie_sh)->flags;
}

void
dhd_bus_clearcounts(dhd_pub_t *dhdp)
{
}

/**
 * @param params    input buffer, NULL for 'set' operation.
 * @param plen      length of 'params' buffer, 0 for 'set' operation.
 * @param arg       output buffer
 */
int
dhd_bus_iovar_op(dhd_pub_t *dhdp, const char *name,
                 void *params, int plen, void *arg, int len, bool set)
{
	dhd_bus_t *bus = dhdp->bus;
	const bcm_iovar_t *vi = NULL;
	int bcmerror = BCME_UNSUPPORTED;
	int val_size;
	uint32 actionid;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	ASSERT(name);
	ASSERT(len >= 0);
	if (!name || len < 0)
		return BCME_BADARG;

	/* Get MUST have return space */
	ASSERT(set || (arg && len));
	if (!(set || (arg && len)))
		return BCME_BADARG;

	/* Set does NOT take qualifiers */
	ASSERT(!set || (!params && !plen));
	if (!(!set || (!params && !plen)))
		return BCME_BADARG;

	DHD_INFO(("%s: %s %s, len %d plen %d\n", __FUNCTION__,
	         name, (set ? "set" : "get"), len, plen));

	/* Look up var locally; if not found pass to host driver */
	if ((vi = bcm_iovar_lookup(dhdpcie_iovars, name)) == NULL) {
		goto exit;
	}

	if (MULTIBP_ENAB(bus->sih)) {
		if (vi->flags & DHD_IOVF_PWRREQ_BYPASS) {
			DHD_ERROR(("%s: Bypass pwr request\n", __FUNCTION__));
		} else {
			dhd_bus_pcie_pwr_req(bus);
		}
	}

	/* set up 'params' pointer in case this is a set command so that
	 * the convenience int and bool code can be common to set and get
	 */
	if (params == NULL) {
		params = arg;
		plen = len;
	}

	if (vi->type == IOVT_VOID)
		val_size = 0;
	else if (vi->type == IOVT_BUFFER)
		val_size = len;
	else
		/* all other types are integer sized */
		val_size = sizeof(int);

	actionid = set ? IOV_SVAL(vi->varid) : IOV_GVAL(vi->varid);
	bcmerror = dhdpcie_bus_doiovar(bus, vi, actionid, name, params, plen, arg, len, val_size);

exit:
	/* In DEVRESET_QUIESCE/DEVRESET_ON,
	 * this includes dongle re-attach which initialize pwr_req_ref count to 0 and
	 * causes pwr_req_ref count miss-match in pwr req clear function and hang.
	 * In this case, bypass pwr req clear.
	 */
	if (bcmerror == BCME_DNGL_DEVRESET) {
		bcmerror = BCME_OK;
	} else {
		if (MULTIBP_ENAB(bus->sih)) {
			if (vi && (vi->flags & DHD_IOVF_PWRREQ_BYPASS)) {
				DHD_ERROR(("%s: Bypass pwr request clear\n", __FUNCTION__));
			} else {
				dhd_bus_pcie_pwr_req_clear(bus);
			}
		}
	}
	return bcmerror;
} /* dhd_bus_iovar_op */

#ifdef BCM_BUZZZ
#include <bcm_buzzz.h>

int
dhd_buzzz_dump_cntrs(char *p, uint32 *core, uint32 *log,
	const int num_counters)
{
	int bytes = 0;
	uint32 ctr;
	uint32 curr[BCM_BUZZZ_COUNTERS_MAX], prev[BCM_BUZZZ_COUNTERS_MAX];
	uint32 delta[BCM_BUZZZ_COUNTERS_MAX];

	/* Compute elapsed counter values per counter event type */
	for (ctr = 0U; ctr < num_counters; ctr++) {
		prev[ctr] = core[ctr];
		curr[ctr] = *log++;
		core[ctr] = curr[ctr];  /* saved for next log */

		if (curr[ctr] < prev[ctr])
			delta[ctr] = curr[ctr] + (~0U - prev[ctr]);
		else
			delta[ctr] = (curr[ctr] - prev[ctr]);

		bytes += sprintf(p + bytes, "%12u ", delta[ctr]);
	}

	return bytes;
}

typedef union cm3_cnts { /* export this in bcm_buzzz.h */
	uint32 u32;
	uint8  u8[4];
	struct {
		uint8 cpicnt;
		uint8 exccnt;
		uint8 sleepcnt;
		uint8 lsucnt;
	};
} cm3_cnts_t;

int
dhd_bcm_buzzz_dump_cntrs6(char *p, uint32 *core, uint32 *log)
{
	int bytes = 0;

	uint32 cyccnt, instrcnt;
	cm3_cnts_t cm3_cnts;
	uint8 foldcnt;

	{   /* 32bit cyccnt */
		uint32 curr, prev, delta;
		prev = core[0]; curr = *log++; core[0] = curr;
		if (curr < prev)
			delta = curr + (~0U - prev);
		else
			delta = (curr - prev);

		bytes += sprintf(p + bytes, "%12u ", delta);
		cyccnt = delta;
	}

	{	/* Extract the 4 cnts: cpi, exc, sleep and lsu */
		int i;
		uint8 max8 = ~0;
		cm3_cnts_t curr, prev, delta;
		prev.u32 = core[1]; curr.u32 = * log++; core[1] = curr.u32;
		for (i = 0; i < 4; i++) {
			if (curr.u8[i] < prev.u8[i])
				delta.u8[i] = curr.u8[i] + (max8 - prev.u8[i]);
			else
				delta.u8[i] = (curr.u8[i] - prev.u8[i]);
			bytes += sprintf(p + bytes, "%4u ", delta.u8[i]);
		}
		cm3_cnts.u32 = delta.u32;
	}

	{   /* Extract the foldcnt from arg0 */
		uint8 curr, prev, delta, max8 = ~0;
		bcm_buzzz_arg0_t arg0; arg0.u32 = *log;
		prev = core[2]; curr = arg0.klog.cnt; core[2] = curr;
		if (curr < prev)
			delta = curr + (max8 - prev);
		else
			delta = (curr - prev);
		bytes += sprintf(p + bytes, "%4u ", delta);
		foldcnt = delta;
	}

	instrcnt = cyccnt - (cm3_cnts.u8[0] + cm3_cnts.u8[1] + cm3_cnts.u8[2]
		                 + cm3_cnts.u8[3]) + foldcnt;
	if (instrcnt > 0xFFFFFF00)
		bytes += sprintf(p + bytes, "[%10s] ", "~");
	else
		bytes += sprintf(p + bytes, "[%10u] ", instrcnt);
	return bytes;
}

int
dhd_buzzz_dump_log(char *p, uint32 *core, uint32 *log, bcm_buzzz_t *buzzz)
{
	int bytes = 0;
	bcm_buzzz_arg0_t arg0;
	static uint8 * fmt[] = BCM_BUZZZ_FMT_STRINGS;

	if (buzzz->counters == 6) {
		bytes += dhd_bcm_buzzz_dump_cntrs6(p, core, log);
		log += 2; /* 32bit cyccnt + (4 x 8bit) CM3 */
	} else {
		bytes += dhd_buzzz_dump_cntrs(p, core, log, buzzz->counters);
		log += buzzz->counters; /* (N x 32bit) CR4=3, CA7=4 */
	}

	/* Dump the logged arguments using the registered formats */
	arg0.u32 = *log++;

	switch (arg0.klog.args) {
		case 0:
			bytes += sprintf(p + bytes, fmt[arg0.klog.id]);
			break;
		case 1:
		{
			uint32 arg1 = *log++;
			bytes += sprintf(p + bytes, fmt[arg0.klog.id], arg1);
			break;
		}
		case 2:
		{
			uint32 arg1, arg2;
			arg1 = *log++; arg2 = *log++;
			bytes += sprintf(p + bytes, fmt[arg0.klog.id], arg1, arg2);
			break;
		}
		case 3:
		{
			uint32 arg1, arg2, arg3;
			arg1 = *log++; arg2 = *log++; arg3 = *log++;
			bytes += sprintf(p + bytes, fmt[arg0.klog.id], arg1, arg2, arg3);
			break;
		}
		case 4:
		{
			uint32 arg1, arg2, arg3, arg4;
			arg1 = *log++; arg2 = *log++;
			arg3 = *log++; arg4 = *log++;
			bytes += sprintf(p + bytes, fmt[arg0.klog.id], arg1, arg2, arg3, arg4);
			break;
		}
		default:
			printf("%s: Maximum one argument supported\n", __FUNCTION__);
			break;
	}

	bytes += sprintf(p + bytes, "\n");

	return bytes;
}

void dhd_buzzz_dump(bcm_buzzz_t *buzzz_p, void *buffer_p, char *p)
{
	int i;
	uint32 total, part1, part2, log_sz, core[BCM_BUZZZ_COUNTERS_MAX];
	void * log;

	for (i = 0; i < BCM_BUZZZ_COUNTERS_MAX; i++) {
		core[i] = 0;
	}

	log_sz = buzzz_p->log_sz;

	part1 = ((uint32)buzzz_p->cur - (uint32)buzzz_p->log) / log_sz;

	if (buzzz_p->wrap == TRUE) {
		part2 = ((uint32)buzzz_p->end - (uint32)buzzz_p->cur) / log_sz;
		total = (buzzz_p->buffer_sz - BCM_BUZZZ_LOGENTRY_MAXSZ) / log_sz;
	} else {
		part2 = 0U;
		total = buzzz_p->count;
	}

	if (total == 0U) {
		printf("%s: bcm_buzzz_dump total<%u> done\n", __FUNCTION__, total);
		return;
	} else {
		printf("%s: bcm_buzzz_dump total<%u> : part2<%u> + part1<%u>\n", __FUNCTION__,
		       total, part2, part1);
	}

	if (part2) {   /* with wrap */
		log = (void*)((size_t)buffer_p + (buzzz_p->cur - buzzz_p->log));
		while (part2--) {   /* from cur to end : part2 */
			p[0] = '\0';
			dhd_buzzz_dump_log(p, core, (uint32 *)log, buzzz_p);
			printf("%s", p);
			log = (void*)((size_t)log + buzzz_p->log_sz);
		}
	}

	log = (void*)buffer_p;
	while (part1--) {
		p[0] = '\0';
		dhd_buzzz_dump_log(p, core, (uint32 *)log, buzzz_p);
		printf("%s", p);
		log = (void*)((size_t)log + buzzz_p->log_sz);
	}

	printf("%s: bcm_buzzz_dump done.\n", __FUNCTION__);
}

int dhd_buzzz_dump_dngl(dhd_bus_t *bus)
{
	bcm_buzzz_t * buzzz_p = NULL;
	void * buffer_p = NULL;
	char * page_p = NULL;
	pciedev_shared_t *sh;
	int ret = 0;

	if (bus->dhd->busstate != DHD_BUS_DATA) {
		return BCME_UNSUPPORTED;
	}
	if ((page_p = (char *)MALLOC(bus->dhd->osh, 4096)) == NULL) {
		printf("%s: Page memory allocation failure\n", __FUNCTION__);
		goto done;
	}
	if ((buzzz_p = MALLOC(bus->dhd->osh, sizeof(bcm_buzzz_t))) == NULL) {
		printf("%s: BCM BUZZZ memory allocation failure\n", __FUNCTION__);
		goto done;
	}

	ret = dhdpcie_readshared(bus);
	if (ret < 0) {
		DHD_ERROR(("%s :Shared area read failed \n", __FUNCTION__));
		goto done;
	}

	sh = bus->pcie_sh;

	DHD_INFO(("%s buzzz:%08x\n", __FUNCTION__, sh->buzz_dbg_ptr));

	if (sh->buzz_dbg_ptr != 0U) {	/* Fetch and display dongle BUZZZ Trace */

		dhdpcie_bus_membytes(bus, FALSE, (ulong)sh->buzz_dbg_ptr,
		                     (uint8 *)buzzz_p, sizeof(bcm_buzzz_t));

		printf("BUZZZ[0x%08x]: log<0x%08x> cur<0x%08x> end<0x%08x> "
			"count<%u> status<%u> wrap<%u>\n"
			"cpu<0x%02X> counters<%u> group<%u> buffer_sz<%u> log_sz<%u>\n",
			(int)sh->buzz_dbg_ptr,
			(int)buzzz_p->log, (int)buzzz_p->cur, (int)buzzz_p->end,
			buzzz_p->count, buzzz_p->status, buzzz_p->wrap,
			buzzz_p->cpu_idcode, buzzz_p->counters, buzzz_p->group,
			buzzz_p->buffer_sz, buzzz_p->log_sz);

		if (buzzz_p->count == 0) {
			printf("%s: Empty dongle BUZZZ trace\n\n", __FUNCTION__);
			goto done;
		}

		/* Allocate memory for trace buffer and format strings */
		buffer_p = MALLOC(bus->dhd->osh, buzzz_p->buffer_sz);
		if (buffer_p == NULL) {
			printf("%s: Buffer memory allocation failure\n", __FUNCTION__);
			goto done;
		}

		/* Fetch the trace. format strings are exported via bcm_buzzz.h */
		dhdpcie_bus_membytes(bus, FALSE, (uint32)buzzz_p->log,   /* Trace */
		                     (uint8 *)buffer_p, buzzz_p->buffer_sz);

		/* Process and display the trace using formatted output */

		{
			int ctr;
			for (ctr = 0; ctr < buzzz_p->counters; ctr++) {
				printf("<Evt[%02X]> ", buzzz_p->eventid[ctr]);
			}
			printf("<code execution point>\n");
		}

		dhd_buzzz_dump(buzzz_p, buffer_p, page_p);

		printf("%s: ----- End of dongle BCM BUZZZ Trace -----\n\n", __FUNCTION__);

		MFREE(bus->dhd->osh, buffer_p, buzzz_p->buffer_sz); buffer_p = NULL;
	}

done:

	if (page_p)   MFREE(bus->dhd->osh, page_p, 4096);
	if (buzzz_p)  MFREE(bus->dhd->osh, buzzz_p, sizeof(bcm_buzzz_t));
	if (buffer_p) MFREE(bus->dhd->osh, buffer_p, buzzz_p->buffer_sz);

	return BCME_OK;
}
#endif /* BCM_BUZZZ */

#define PCIE_GEN2(sih) ((BUSTYPE((sih)->bustype) == PCI_BUS) &&	\
	((sih)->buscoretype == PCIE2_CORE_ID))

#define PCIE_FLR_CAPAB_BIT		28
#define PCIE_FUNCTION_LEVEL_RESET_BIT	15

/* Change delays for only QT HW, FPGA and silicon uses same delay */
#ifdef BCMQT_HW
#define DHD_FUNCTION_LEVEL_RESET_DELAY		300000u
#define DHD_SSRESET_STATUS_RETRY_DELAY	10000u
#else
#define DHD_FUNCTION_LEVEL_RESET_DELAY	70u	/* 70 msec delay */
#define DHD_SSRESET_STATUS_RETRY_DELAY	40u
#endif // endif
/*
 * Increase SSReset de-assert time to 8ms.
 * since it takes longer time if re-scan time on 4378B0.
 */
#define DHD_SSRESET_STATUS_RETRIES	200u

static void
dhdpcie_enum_reg_init(dhd_bus_t *bus)
{
	/* initialize Function control register (clear bit 4) to HW init value */
	si_corereg(bus->sih, bus->sih->buscoreidx,
		OFFSETOF(sbpcieregs_t, ftn_ctrl.control), ~0,
		PCIE_CPLCA_ENABLE | PCIE_DLY_PERST_TO_COE);

	/* clear IntMask */
	si_corereg(bus->sih, bus->sih->buscoreidx,
		OFFSETOF(sbpcieregs_t, ftn_ctrl.intmask), ~0, 0);
	/* clear IntStatus */
	si_corereg(bus->sih, bus->sih->buscoreidx,
		OFFSETOF(sbpcieregs_t, ftn_ctrl.intstatus), ~0,
		si_corereg(bus->sih, bus->sih->buscoreidx,
			OFFSETOF(sbpcieregs_t, ftn_ctrl.intstatus), 0, 0));

	/* clear MSIVector */
	si_corereg(bus->sih, bus->sih->buscoreidx,
		OFFSETOF(sbpcieregs_t, ftn_ctrl.msi_vector), ~0, 0);
	/* clear MSIIntMask */
	si_corereg(bus->sih, bus->sih->buscoreidx,
		OFFSETOF(sbpcieregs_t, ftn_ctrl.msi_intmask), ~0, 0);
	/* clear MSIIntStatus */
	si_corereg(bus->sih, bus->sih->buscoreidx,
		OFFSETOF(sbpcieregs_t, ftn_ctrl.msi_intstatus), ~0,
		si_corereg(bus->sih, bus->sih->buscoreidx,
			OFFSETOF(sbpcieregs_t, ftn_ctrl.msi_intstatus), 0, 0));

	/* clear PowerIntMask */
	si_corereg(bus->sih, bus->sih->buscoreidx,
		OFFSETOF(sbpcieregs_t, ftn_ctrl.pwr_intmask), ~0, 0);
	/* clear PowerIntStatus */
	si_corereg(bus->sih, bus->sih->buscoreidx,
		OFFSETOF(sbpcieregs_t, ftn_ctrl.pwr_intstatus), ~0,
		si_corereg(bus->sih, bus->sih->buscoreidx,
			OFFSETOF(sbpcieregs_t, ftn_ctrl.pwr_intstatus), 0, 0));

	/* clear MailboxIntMask */
	si_corereg(bus->sih, bus->sih->buscoreidx,
		OFFSETOF(sbpcieregs_t, ftn_ctrl.mbox_intmask), ~0, 0);
	/* clear MailboxInt */
	si_corereg(bus->sih, bus->sih->buscoreidx,
		OFFSETOF(sbpcieregs_t, ftn_ctrl.mbox_intstatus), ~0,
		si_corereg(bus->sih, bus->sih->buscoreidx,
			OFFSETOF(sbpcieregs_t, ftn_ctrl.mbox_intstatus), 0, 0));
}

int
dhd_bus_perform_flr(dhd_bus_t *bus, bool force_fail)
{
	uint flr_capab;
	uint val;
	int retry = 0;

	DHD_ERROR(("******** Perform FLR ********\n"));

	if (PCIE_ENUM_RESET_WAR_ENAB(bus->sih->buscorerev)) {
		if (bus->pcie_mailbox_mask != 0) {
			dhdpcie_bus_intr_disable(bus);
		}
		/* initialize F0 enum registers before FLR for rev66/67 */
		dhdpcie_enum_reg_init(bus);
	}

	/* Read PCIE_CFG_DEVICE_CAPABILITY bit 28 to check FLR capability */
	val = OSL_PCI_READ_CONFIG(bus->osh, PCIE_CFG_DEVICE_CAPABILITY, sizeof(val));
	flr_capab =  val & (1 << PCIE_FLR_CAPAB_BIT);
	DHD_INFO(("Read Device Capability: reg=0x%x read val=0x%x flr_capab=0x%x\n",
		PCIE_CFG_DEVICE_CAPABILITY, val, flr_capab));
	if (!flr_capab) {
	       DHD_ERROR(("Chip does not support FLR\n"));
	       return BCME_UNSUPPORTED;
	}

	/* Save pcie config space */
	DHD_INFO(("Save Pcie Config Space\n"));
	DHD_PCIE_CONFIG_SAVE(bus);

	/* Set bit 15 of PCIE_CFG_DEVICE_CONTROL */
	DHD_INFO(("Set PCIE_FUNCTION_LEVEL_RESET_BIT(%d) of PCIE_CFG_DEVICE_CONTROL(0x%x)\n",
		PCIE_FUNCTION_LEVEL_RESET_BIT, PCIE_CFG_DEVICE_CONTROL));
	val = OSL_PCI_READ_CONFIG(bus->osh, PCIE_CFG_DEVICE_CONTROL, sizeof(val));
	DHD_INFO(("read_config: reg=0x%x read val=0x%x\n", PCIE_CFG_DEVICE_CONTROL, val));
	val = val | (1 << PCIE_FUNCTION_LEVEL_RESET_BIT);
	DHD_INFO(("write_config: reg=0x%x write val=0x%x\n", PCIE_CFG_DEVICE_CONTROL, val));
	OSL_PCI_WRITE_CONFIG(bus->osh, PCIE_CFG_DEVICE_CONTROL, sizeof(val), val);

	/* wait for DHD_FUNCTION_LEVEL_RESET_DELAY msec */
	DHD_INFO(("Delay of %d msec\n", DHD_FUNCTION_LEVEL_RESET_DELAY));
	OSL_DELAY(DHD_FUNCTION_LEVEL_RESET_DELAY * 1000u);

	if (force_fail) {
		DHD_ERROR(("Set PCIE_SSRESET_DISABLE_BIT(%d) of PCIE_CFG_SUBSYSTEM_CONTROL(0x%x)\n",
			PCIE_SSRESET_DISABLE_BIT, PCIE_CFG_SUBSYSTEM_CONTROL));
		val = OSL_PCI_READ_CONFIG(bus->osh, PCIE_CFG_SUBSYSTEM_CONTROL, sizeof(val));
		DHD_ERROR(("read_config: reg=0x%x read val=0x%x\n", PCIE_CFG_SUBSYSTEM_CONTROL,
			val));
		val = val | (1 << PCIE_SSRESET_DISABLE_BIT);
		DHD_ERROR(("write_config: reg=0x%x write val=0x%x\n", PCIE_CFG_SUBSYSTEM_CONTROL,
			val));
		OSL_PCI_WRITE_CONFIG(bus->osh, PCIE_CFG_SUBSYSTEM_CONTROL, sizeof(val), val);

		val = OSL_PCI_READ_CONFIG(bus->osh, PCIE_CFG_SUBSYSTEM_CONTROL, sizeof(val));
		DHD_ERROR(("read_config: reg=0x%x read val=0x%x\n", PCIE_CFG_SUBSYSTEM_CONTROL,
			val));
	}

	/* Clear bit 15 of PCIE_CFG_DEVICE_CONTROL */
	DHD_INFO(("Clear PCIE_FUNCTION_LEVEL_RESET_BIT(%d) of PCIE_CFG_DEVICE_CONTROL(0x%x)\n",
		PCIE_FUNCTION_LEVEL_RESET_BIT, PCIE_CFG_DEVICE_CONTROL));
	val = OSL_PCI_READ_CONFIG(bus->osh, PCIE_CFG_DEVICE_CONTROL, sizeof(val));
	DHD_INFO(("read_config: reg=0x%x read val=0x%x\n", PCIE_CFG_DEVICE_CONTROL, val));
	val = val & ~(1 << PCIE_FUNCTION_LEVEL_RESET_BIT);
	DHD_INFO(("write_config: reg=0x%x write val=0x%x\n", PCIE_CFG_DEVICE_CONTROL, val));
	OSL_PCI_WRITE_CONFIG(bus->osh, PCIE_CFG_DEVICE_CONTROL, sizeof(val), val);

	/* Wait till bit 13 of PCIE_CFG_SUBSYSTEM_CONTROL is cleared */
	DHD_INFO(("Wait till PCIE_SSRESET_STATUS_BIT(%d) of PCIE_CFG_SUBSYSTEM_CONTROL(0x%x)"
		"is cleared\n",	PCIE_SSRESET_STATUS_BIT, PCIE_CFG_SUBSYSTEM_CONTROL));
	do {
		val = OSL_PCI_READ_CONFIG(bus->osh, PCIE_CFG_SUBSYSTEM_CONTROL, sizeof(val));
		DHD_ERROR(("read_config: reg=0x%x read val=0x%x\n",
			PCIE_CFG_SUBSYSTEM_CONTROL, val));
		val = val & (1 << PCIE_SSRESET_STATUS_BIT);
		OSL_DELAY(DHD_SSRESET_STATUS_RETRY_DELAY);
	} while (val && (retry++ < DHD_SSRESET_STATUS_RETRIES));

	if (val) {
		DHD_ERROR(("ERROR: reg=0x%x bit %d is not cleared\n",
			PCIE_CFG_SUBSYSTEM_CONTROL, PCIE_SSRESET_STATUS_BIT));
		/* User has to fire the IOVAR again, if force_fail is needed */
		if (force_fail) {
			bus->flr_force_fail = FALSE;
			DHD_ERROR(("%s cleared flr_force_fail flag\n", __FUNCTION__));
		}
		return BCME_DONGLE_DOWN;
	}

	/* Restore pcie config space */
	DHD_INFO(("Restore Pcie Config Space\n"));
	DHD_PCIE_CONFIG_RESTORE(bus);

	DHD_ERROR(("******** FLR Succedeed ********\n"));

	return BCME_OK;
}

#ifdef DHD_USE_BP_RESET
#define DHD_BP_RESET_ASPM_DISABLE_DELAY	500u	/* usec */

#define DHD_BP_RESET_STATUS_RETRY_DELAY	40u	/* usec */
#define DHD_BP_RESET_STATUS_RETRIES	50u

#define PCIE_CFG_SPROM_CTRL_SB_RESET_BIT	10
#define PCIE_CFG_CLOCK_CTRL_STATUS_BP_RESET_BIT	21
int
dhd_bus_perform_bp_reset(struct dhd_bus *bus)
{
	uint val;
	int retry = 0;
	uint dar_clk_ctrl_status_reg = DAR_CLK_CTRL(bus->sih->buscorerev);
	int ret = BCME_OK;
	bool cond;

	DHD_ERROR(("******** Perform BP reset ********\n"));

	/* Disable ASPM */
	DHD_INFO(("Disable ASPM: Clear bits(1-0) of PCIECFGREG_LINK_STATUS_CTRL(0x%x)\n",
		PCIECFGREG_LINK_STATUS_CTRL));
	val = OSL_PCI_READ_CONFIG(bus->osh, PCIECFGREG_LINK_STATUS_CTRL, sizeof(val));
	DHD_INFO(("read_config: reg=0x%x read val=0x%x\n", PCIECFGREG_LINK_STATUS_CTRL, val));
	val = val & (~PCIE_ASPM_ENAB);
	DHD_INFO(("write_config: reg=0x%x write val=0x%x\n", PCIECFGREG_LINK_STATUS_CTRL, val));
	OSL_PCI_WRITE_CONFIG(bus->osh, PCIECFGREG_LINK_STATUS_CTRL, sizeof(val), val);

	/* wait for delay usec */
	DHD_INFO(("Delay of %d usec\n", DHD_BP_RESET_ASPM_DISABLE_DELAY));
	OSL_DELAY(DHD_BP_RESET_ASPM_DISABLE_DELAY);

	/* Set bit 10 of PCIECFGREG_SPROM_CTRL */
	DHD_INFO(("Set PCIE_CFG_SPROM_CTRL_SB_RESET_BIT(%d) of PCIECFGREG_SPROM_CTRL(0x%x)\n",
		PCIE_CFG_SPROM_CTRL_SB_RESET_BIT, PCIECFGREG_SPROM_CTRL));
	val = OSL_PCI_READ_CONFIG(bus->osh, PCIECFGREG_SPROM_CTRL, sizeof(val));
	DHD_INFO(("read_config: reg=0x%x read val=0x%x\n", PCIECFGREG_SPROM_CTRL, val));
	val = val | (1 << PCIE_CFG_SPROM_CTRL_SB_RESET_BIT);
	DHD_INFO(("write_config: reg=0x%x write val=0x%x\n", PCIECFGREG_SPROM_CTRL, val));
	OSL_PCI_WRITE_CONFIG(bus->osh, PCIECFGREG_SPROM_CTRL, sizeof(val), val);

	/* Wait till bit backplane reset is ASSERTED i,e
	 * bit 10 of PCIECFGREG_SPROM_CTRL is cleared.
	 * Only after this, poll for 21st bit of DAR reg 0xAE0 is valid
	 * else DAR register will read previous old value
	 */
	DHD_INFO(("Wait till PCIE_CFG_SPROM_CTRL_SB_RESET_BIT(%d) of "
		"PCIECFGREG_SPROM_CTRL(0x%x) is cleared\n",
		PCIE_CFG_SPROM_CTRL_SB_RESET_BIT, PCIECFGREG_SPROM_CTRL));
	do {
		val = OSL_PCI_READ_CONFIG(bus->osh, PCIECFGREG_SPROM_CTRL, sizeof(val));
		DHD_INFO(("read_config: reg=0x%x read val=0x%x\n", PCIECFGREG_SPROM_CTRL, val));
		cond = val & (1 << PCIE_CFG_SPROM_CTRL_SB_RESET_BIT);
		OSL_DELAY(DHD_BP_RESET_STATUS_RETRY_DELAY);
	} while (cond && (retry++ < DHD_BP_RESET_STATUS_RETRIES));

	if (cond) {
		DHD_ERROR(("ERROR: reg=0x%x bit %d is not cleared\n",
			PCIECFGREG_SPROM_CTRL, PCIE_CFG_SPROM_CTRL_SB_RESET_BIT));
		ret = BCME_ERROR;
		goto aspm_enab;
	}

	/* Wait till bit 21 of dar_clk_ctrl_status_reg is cleared */
	DHD_INFO(("Wait till PCIE_CFG_CLOCK_CTRL_STATUS_BP_RESET_BIT(%d) of "
		"dar_clk_ctrl_status_reg(0x%x) is cleared\n",
		PCIE_CFG_CLOCK_CTRL_STATUS_BP_RESET_BIT, dar_clk_ctrl_status_reg));
	do {
		val = si_corereg(bus->sih, bus->sih->buscoreidx,
			dar_clk_ctrl_status_reg, 0, 0);
		DHD_INFO(("read_dar si_corereg: reg=0x%x read val=0x%x\n",
			dar_clk_ctrl_status_reg, val));
		cond = val & (1 << PCIE_CFG_CLOCK_CTRL_STATUS_BP_RESET_BIT);
		OSL_DELAY(DHD_BP_RESET_STATUS_RETRY_DELAY);
	} while (cond && (retry++ < DHD_BP_RESET_STATUS_RETRIES));

	if (cond) {
		DHD_ERROR(("ERROR: reg=0x%x bit %d is not cleared\n",
			dar_clk_ctrl_status_reg, PCIE_CFG_CLOCK_CTRL_STATUS_BP_RESET_BIT));
		ret = BCME_ERROR;
	}

aspm_enab:
	/* Enable ASPM */
	DHD_INFO(("Enable ASPM: set bit 1 of PCIECFGREG_LINK_STATUS_CTRL(0x%x)\n",
		PCIECFGREG_LINK_STATUS_CTRL));
	val = OSL_PCI_READ_CONFIG(bus->osh, PCIECFGREG_LINK_STATUS_CTRL, sizeof(val));
	DHD_INFO(("read_config: reg=0x%x read val=0x%x\n", PCIECFGREG_LINK_STATUS_CTRL, val));
	val = val | (PCIE_ASPM_L1_ENAB);
	DHD_INFO(("write_config: reg=0x%x write val=0x%x\n", PCIECFGREG_LINK_STATUS_CTRL, val));
	OSL_PCI_WRITE_CONFIG(bus->osh, PCIECFGREG_LINK_STATUS_CTRL, sizeof(val), val);

	DHD_ERROR(("******** BP reset Succedeed ********\n"));

	return ret;
}
#endif /* DHD_USE_BP_RESET */

int
dhd_bus_devreset(dhd_pub_t *dhdp, uint8 flag)
{
	dhd_bus_t *bus = dhdp->bus;
	int bcmerror = 0;
	unsigned long flags;
	unsigned long flags_bus;
#ifdef CONFIG_ARCH_MSM
	int retry = POWERUP_MAX_RETRY;
#endif /* CONFIG_ARCH_MSM */

	if (flag == TRUE) { /* Turn off WLAN */
		/* Removing Power */
		DHD_ERROR(("%s: == Power OFF ==\n", __FUNCTION__));
		DHD_ERROR(("%s: making dhdpub up FALSE\n", __FUNCTION__));
		bus->dhd->up = FALSE;

		/* wait for other contexts to finish -- if required a call
		* to OSL_DELAY for 1s can be added to give other contexts
		* a chance to finish
		*/
		dhdpcie_advertise_bus_cleanup(bus->dhd);

		if (bus->dhd->busstate != DHD_BUS_DOWN) {
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
			atomic_set(&bus->dhd->block_bus, TRUE);
			dhd_flush_rx_tx_wq(bus->dhd);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

#ifdef BCMPCIE_OOB_HOST_WAKE
			/* Clean up any pending host wake IRQ */
			dhd_bus_oob_intr_set(bus->dhd, FALSE);
			dhd_bus_oob_intr_unregister(bus->dhd);
#endif /* BCMPCIE_OOB_HOST_WAKE */
			dhd_os_wd_timer(dhdp, 0);
			dhd_bus_stop(bus, TRUE);
			if (bus->intr) {
				DHD_BUS_LOCK(bus->bus_lock, flags_bus);
				dhdpcie_bus_intr_disable(bus);
				DHD_BUS_UNLOCK(bus->bus_lock, flags_bus);
				dhdpcie_free_irq(bus);
			}
			dhd_deinit_bus_lock(bus);
			dhd_deinit_backplane_access_lock(bus);
			dhd_bus_release_dongle(bus);
			dhdpcie_bus_free_resource(bus);
			bcmerror = dhdpcie_bus_disable_device(bus);
			if (bcmerror) {
				DHD_ERROR(("%s: dhdpcie_bus_disable_device: %d\n",
					__FUNCTION__, bcmerror));
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
				atomic_set(&bus->dhd->block_bus, FALSE);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */
			}
			/* Clean up protocol data after Bus Master Enable bit clear
			 * so that host can safely unmap DMA and remove the allocated buffers
			 * from the PKTID MAP. Some Applicantion Processors supported
			 * System MMU triggers Kernel panic when they detect to attempt to
			 * DMA-unmapped memory access from the devices which use the
			 * System MMU. Therefore, Kernel panic can be happened since it is
			 * possible that dongle can access to DMA-unmapped memory after
			 * calling the dhd_prot_reset().
			 * For this reason, the dhd_prot_reset() and dhd_clear() functions
			 * should be located after the dhdpcie_bus_disable_device().
			 */
			dhd_prot_reset(dhdp);
			dhd_clear(dhdp);
#ifdef CONFIG_ARCH_MSM
			bcmerror = dhdpcie_bus_clock_stop(bus);
			if (bcmerror) {
				DHD_ERROR(("%s: host clock stop failed: %d\n",
					__FUNCTION__, bcmerror));
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
				atomic_set(&bus->dhd->block_bus, FALSE);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */
				goto done;
			}
#endif /* CONFIG_ARCH_MSM */
			DHD_GENERAL_LOCK(bus->dhd, flags);
			DHD_ERROR(("%s: making DHD_BUS_DOWN\n", __FUNCTION__));
			bus->dhd->busstate = DHD_BUS_DOWN;
			DHD_GENERAL_UNLOCK(bus->dhd, flags);
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
			atomic_set(&bus->dhd->block_bus, FALSE);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */
		} else {
			if (bus->intr) {
				dhdpcie_free_irq(bus);
			}
#ifdef BCMPCIE_OOB_HOST_WAKE
			/* Clean up any pending host wake IRQ */
			dhd_bus_oob_intr_set(bus->dhd, FALSE);
			dhd_bus_oob_intr_unregister(bus->dhd);
#endif /* BCMPCIE_OOB_HOST_WAKE */
			dhd_dpc_kill(bus->dhd);
			if (!bus->no_bus_init) {
				dhd_bus_release_dongle(bus);
				dhdpcie_bus_free_resource(bus);
				bcmerror = dhdpcie_bus_disable_device(bus);
				if (bcmerror) {
					DHD_ERROR(("%s: dhdpcie_bus_disable_device: %d\n",
						__FUNCTION__, bcmerror));
				}

				/* Clean up protocol data after Bus Master Enable bit clear
				 * so that host can safely unmap DMA and remove the allocated
				 * buffers from the PKTID MAP. Some Applicantion Processors
				 * supported System MMU triggers Kernel panic when they detect
				 * to attempt to DMA-unmapped memory access from the devices
				 * which use the System MMU.
				 * Therefore, Kernel panic can be happened since it is possible
				 * that dongle can access to DMA-unmapped memory after calling
				 * the dhd_prot_reset().
				 * For this reason, the dhd_prot_reset() and dhd_clear() functions
				 * should be located after the dhdpcie_bus_disable_device().
				 */
				dhd_prot_reset(dhdp);
				dhd_clear(dhdp);
			} else {
				bus->no_bus_init = FALSE;
			}
#ifdef CONFIG_ARCH_MSM
			bcmerror = dhdpcie_bus_clock_stop(bus);
			if (bcmerror) {
				DHD_ERROR(("%s: host clock stop failed: %d\n",
					__FUNCTION__, bcmerror));
				goto done;
			}
#endif  /* CONFIG_ARCH_MSM */
		}

		bus->dhd->dongle_reset = TRUE;
		DHD_ERROR(("%s:  WLAN OFF Done\n", __FUNCTION__));

	} else { /* Turn on WLAN */
		if (bus->dhd->busstate == DHD_BUS_DOWN) {
			/* Powering On */
			DHD_ERROR(("%s: == Power ON ==\n", __FUNCTION__));
#ifdef CONFIG_ARCH_MSM
			while (--retry) {
				bcmerror = dhdpcie_bus_clock_start(bus);
				if (!bcmerror) {
					DHD_ERROR(("%s: dhdpcie_bus_clock_start OK\n",
						__FUNCTION__));
					break;
				} else {
					OSL_SLEEP(10);
				}
			}

			if (bcmerror && !retry) {
				DHD_ERROR(("%s: host pcie clock enable failed: %d\n",
					__FUNCTION__, bcmerror));
				goto done;
			}
#if defined(DHD_CONTROL_PCIE_ASPM_WIFI_TURNON)
			dhd_bus_aspm_enable_rc_ep(bus, FALSE);
#endif /* DHD_CONTROL_PCIE_ASPM_WIFI_TURNON */
#endif /* CONFIG_ARCH_MSM */
			bus->is_linkdown = 0;
			bus->cto_triggered = 0;
			bcmerror = dhdpcie_bus_enable_device(bus);
			if (bcmerror) {
				DHD_ERROR(("%s: host configuration restore failed: %d\n",
					__FUNCTION__, bcmerror));
				goto done;
			}

			bcmerror = dhdpcie_bus_alloc_resource(bus);
			if (bcmerror) {
				DHD_ERROR(("%s: dhdpcie_bus_resource_alloc failed: %d\n",
					__FUNCTION__, bcmerror));
				goto done;
			}

			bcmerror = dhdpcie_bus_dongle_attach(bus);
			if (bcmerror) {
				DHD_ERROR(("%s: dhdpcie_bus_dongle_attach failed: %d\n",
					__FUNCTION__, bcmerror));
				goto done;
			}

			bcmerror = dhd_bus_request_irq(bus);
			if (bcmerror) {
				DHD_ERROR(("%s: dhd_bus_request_irq failed: %d\n",
					__FUNCTION__, bcmerror));
				goto done;
			}

			bus->dhd->dongle_reset = FALSE;

#if defined(DHD_CONTROL_PCIE_CPUCORE_WIFI_TURNON)
			dhd_irq_set_affinity(bus->dhd, cpumask_of(1));
#endif /* DHD_CONTROL_PCIE_CPUCORE_WIFI_TURNON */

			bcmerror = dhd_bus_start(dhdp);
			if (bcmerror) {
				DHD_ERROR(("%s: dhd_bus_start: %d\n",
					__FUNCTION__, bcmerror));
				goto done;
			}

			bus->dhd->up = TRUE;
			/* Renabling watchdog which is disabled in dhdpcie_advertise_bus_cleanup */
			if (bus->dhd->dhd_watchdog_ms_backup) {
				DHD_ERROR(("%s: Enabling wdtick after dhd init\n",
					__FUNCTION__));
				dhd_os_wd_timer(bus->dhd, bus->dhd->dhd_watchdog_ms_backup);
			}
			DHD_ERROR(("%s: WLAN Power On Done\n", __FUNCTION__));
		} else {
			DHD_ERROR(("%s: what should we do here\n", __FUNCTION__));
			goto done;
		}
	}

done:
	if (bcmerror) {
		DHD_GENERAL_LOCK(bus->dhd, flags);
		DHD_ERROR(("%s: making DHD_BUS_DOWN\n", __FUNCTION__));
		bus->dhd->busstate = DHD_BUS_DOWN;
		DHD_GENERAL_UNLOCK(bus->dhd, flags);
	}
	return bcmerror;
}

/* si_backplane_access() manages a shared resource - BAR0 mapping, hence its
 * calls shall be serialized. This wrapper function provides such serialization
 * and shall be used everywjer einstead of direct call of si_backplane_access()
 *
 * Linux DHD driver calls si_backplane_access() from 3 three contexts: tasklet
 * (that may call dhdpcie_sssr_dump() from dhdpcie_sssr_dump()), iovar
 * ("sbreg", "membyres", etc.) and procfs (used by GDB proxy). To avoid race
 * conditions calls of si_backplane_access() shall be serialized. Presence of
 * tasklet context implies that serialization shall b ebased on spinlock. Hence
 * Linux implementation of dhd_pcie_backplane_access_[un]lock() is
 * spinlock-based.
 *
 * Other platforms may add their own implementations of
 * dhd_pcie_backplane_access_[un]lock() as needed (e.g. if serialization is not
 * needed implementation might be empty)
 */
static uint
serialized_backplane_access(dhd_bus_t *bus, uint addr, uint size, uint *val, bool read)
{
	uint ret;
	unsigned long flags;
	DHD_BACKPLANE_ACCESS_LOCK(bus->backplane_access_lock, flags);
	ret = si_backplane_access(bus->sih, addr, size, val, read);
	DHD_BACKPLANE_ACCESS_UNLOCK(bus->backplane_access_lock, flags);
	return ret;
}

static int
dhdpcie_get_dma_ring_indices(dhd_pub_t *dhd)
{
	int h2d_support, d2h_support;

	d2h_support = dhd->dma_d2h_ring_upd_support ? 1 : 0;
	h2d_support = dhd->dma_h2d_ring_upd_support ? 1 : 0;
	return (d2h_support | (h2d_support << 1));

}
int
dhdpcie_set_dma_ring_indices(dhd_pub_t *dhd, int32 int_val)
{
	int bcmerror = 0;
	/* Can change it only during initialization/FW download */
	if (dhd->busstate == DHD_BUS_DOWN) {
		if ((int_val > 3) || (int_val < 0)) {
			DHD_ERROR(("Bad argument. Possible values: 0, 1, 2 & 3\n"));
			bcmerror = BCME_BADARG;
		} else {
			dhd->dma_d2h_ring_upd_support = (int_val & 1) ? TRUE : FALSE;
			dhd->dma_h2d_ring_upd_support = (int_val & 2) ? TRUE : FALSE;
			dhd->dma_ring_upd_overwrite = TRUE;
		}
	} else {
		DHD_ERROR(("%s: Can change only when bus down (before FW download)\n",
			__FUNCTION__));
		bcmerror = BCME_NOTDOWN;
	}

	return bcmerror;

}

/**
 * IOVAR handler of the DHD bus layer (in this case, the PCIe bus).
 *
 * @param actionid  e.g. IOV_SVAL(IOV_PCIEREG)
 * @param params    input buffer
 * @param plen      length in [bytes] of input buffer 'params'
 * @param arg       output buffer
 * @param len       length in [bytes] of output buffer 'arg'
 */
static int
dhdpcie_bus_doiovar(dhd_bus_t *bus, const bcm_iovar_t *vi, uint32 actionid, const char *name,
                void *params, int plen, void *arg, int len, int val_size)
{
	int bcmerror = 0;
	int32 int_val = 0;
	int32 int_val2 = 0;
	int32 int_val3 = 0;
	bool bool_val = 0;

	DHD_TRACE(("%s: Enter, action %d name %s params %p plen %d arg %p len %d val_size %d\n",
	           __FUNCTION__, actionid, name, params, plen, arg, len, val_size));

	if ((bcmerror = bcm_iovar_lencheck(vi, arg, len, IOV_ISSET(actionid))) != 0)
		goto exit;

	if (plen >= (int)sizeof(int_val))
		bcopy(params, &int_val, sizeof(int_val));

	if (plen >= (int)sizeof(int_val) * 2)
		bcopy((void*)((uintptr)params + sizeof(int_val)), &int_val2, sizeof(int_val2));

	if (plen >= (int)sizeof(int_val) * 3)
		bcopy((void*)((uintptr)params + 2 * sizeof(int_val)), &int_val3, sizeof(int_val3));

	bool_val = (int_val != 0) ? TRUE : FALSE;

	/* Check if dongle is in reset. If so, only allow DEVRESET iovars */
	if (bus->dhd->dongle_reset && !(actionid == IOV_SVAL(IOV_DEVRESET) ||
	                                actionid == IOV_GVAL(IOV_DEVRESET))) {
		bcmerror = BCME_NOTREADY;
		goto exit;
	}

	switch (actionid) {

	case IOV_SVAL(IOV_VARS):
		bcmerror = dhdpcie_downloadvars(bus, arg, len);
		break;
	case IOV_SVAL(IOV_PCIE_LPBK):
		bcmerror = dhdpcie_bus_lpback_req(bus, int_val);
		break;

	case IOV_SVAL(IOV_PCIE_DMAXFER): {
		dma_xfer_info_t *dmaxfer = (dma_xfer_info_t *)arg;

		if (!dmaxfer)
			return BCME_BADARG;
		if (dmaxfer->version != DHD_DMAXFER_VERSION)
			return BCME_VERSION;
		if (dmaxfer->length != sizeof(dma_xfer_info_t)) {
			return BCME_BADLEN;
		}

		bcmerror = dhdpcie_bus_dmaxfer_req(bus, dmaxfer->num_bytes,
				dmaxfer->src_delay, dmaxfer->dest_delay,
				dmaxfer->type, dmaxfer->core_num,
				dmaxfer->should_wait);

		if (dmaxfer->should_wait && bcmerror >= 0) {
			bcmerror = dhdmsgbuf_dmaxfer_status(bus->dhd, dmaxfer);
		}
		break;
	}

	case IOV_GVAL(IOV_PCIE_DMAXFER): {
		dma_xfer_info_t *dmaxfer = (dma_xfer_info_t *)params;
		if (!dmaxfer)
			return BCME_BADARG;
		if (dmaxfer->version != DHD_DMAXFER_VERSION)
			return BCME_VERSION;
		if (dmaxfer->length != sizeof(dma_xfer_info_t)) {
			return BCME_BADLEN;
		}
		bcmerror = dhdmsgbuf_dmaxfer_status(bus->dhd, dmaxfer);
		break;
	}

	case IOV_GVAL(IOV_PCIE_SUSPEND):
		int_val = (bus->dhd->busstate == DHD_BUS_SUSPEND) ? 1 : 0;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_PCIE_SUSPEND):
		if (bool_val) { /* Suspend */
			int ret;
			unsigned long flags;

			/*
			 * If some other context is busy, wait until they are done,
			 * before starting suspend
			 */
			ret = dhd_os_busbusy_wait_condition(bus->dhd,
				&bus->dhd->dhd_bus_busy_state, DHD_BUS_BUSY_IN_DHD_IOVAR);
			if (ret == 0) {
				DHD_ERROR(("%s:Wait Timedout, dhd_bus_busy_state = 0x%x\n",
					__FUNCTION__, bus->dhd->dhd_bus_busy_state));
				return BCME_BUSY;
			}

			DHD_GENERAL_LOCK(bus->dhd, flags);
			DHD_BUS_BUSY_SET_SUSPEND_IN_PROGRESS(bus->dhd);
			DHD_GENERAL_UNLOCK(bus->dhd, flags);
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
			dhdpcie_bus_suspend(bus, TRUE, TRUE);
#else
			dhdpcie_bus_suspend(bus, TRUE);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

			DHD_GENERAL_LOCK(bus->dhd, flags);
			DHD_BUS_BUSY_CLEAR_SUSPEND_IN_PROGRESS(bus->dhd);
			dhd_os_busbusy_wake(bus->dhd);
			DHD_GENERAL_UNLOCK(bus->dhd, flags);
		} else { /* Resume */
			unsigned long flags;
			DHD_GENERAL_LOCK(bus->dhd, flags);
			DHD_BUS_BUSY_SET_RESUME_IN_PROGRESS(bus->dhd);
			DHD_GENERAL_UNLOCK(bus->dhd, flags);

			dhdpcie_bus_suspend(bus, FALSE);

			DHD_GENERAL_LOCK(bus->dhd, flags);
			DHD_BUS_BUSY_CLEAR_RESUME_IN_PROGRESS(bus->dhd);
			dhd_os_busbusy_wake(bus->dhd);
			DHD_GENERAL_UNLOCK(bus->dhd, flags);
		}
		break;

	case IOV_GVAL(IOV_MEMSIZE):
		int_val = (int32)bus->ramsize;
		bcopy(&int_val, arg, val_size);
		break;

	/* Debug related. Dumps core registers or one of the dongle memory */
	case IOV_GVAL(IOV_DUMP_DONGLE):
	{
		dump_dongle_in_t ddi = *(dump_dongle_in_t*)params;
		dump_dongle_out_t *ddo = (dump_dongle_out_t*)arg;
		uint32 *p = ddo->val;
		const uint max_offset = 4096 - 1; /* one core contains max 4096/4 registers */

		if (plen < sizeof(ddi) || len < sizeof(ddo)) {
			bcmerror = BCME_BADARG;
			break;
		}

		switch (ddi.type) {
		case DUMP_DONGLE_COREREG:
			ddo->n_bytes = 0;

			if (si_setcoreidx(bus->sih, ddi.index) == NULL) {
				break; // beyond last core: core enumeration ended
			}

			ddo->address = si_addrspace(bus->sih, CORE_SLAVE_PORT_0, CORE_BASE_ADDR_0);
			ddo->address += ddi.offset; // BP address at which this dump starts

			ddo->id = si_coreid(bus->sih);
			ddo->rev = si_corerev(bus->sih);

			while (ddi.offset < max_offset &&
				sizeof(dump_dongle_out_t) + ddo->n_bytes < (uint)len) {
				*p++ = si_corereg(bus->sih, ddi.index, ddi.offset, 0, 0);
				ddi.offset += sizeof(uint32);
				ddo->n_bytes += sizeof(uint32);
			}
			break;
		default:
			// TODO: implement d11 SHM/TPL dumping
			bcmerror = BCME_BADARG;
			break;
		}
		break;
	}

	/* Debug related. Returns a string with dongle capabilities */
	case IOV_GVAL(IOV_DNGL_CAPS):
	{
		strncpy(arg, bus->dhd->fw_capabilities,
			MIN(strlen(bus->dhd->fw_capabilities), (size_t)len));
		((char*)arg)[len - 1] = '\0';
		break;
	}

#if defined(DEBUGGER) || defined(DHD_DSCOPE)
	case IOV_SVAL(IOV_GDB_SERVER):
		/* debugger_*() functions may sleep, so cannot hold spinlock */
		DHD_PERIM_UNLOCK(bus->dhd);
		if (int_val > 0) {
			debugger_init((void *) bus, &bus_ops, int_val, SI_ENUM_BASE(bus->sih));
		} else {
			debugger_close();
		}
		DHD_PERIM_LOCK(bus->dhd);
		break;
#endif /* DEBUGGER || DHD_DSCOPE */

#ifdef BCM_BUZZZ
	/* Dump dongle side buzzz trace to console */
	case IOV_GVAL(IOV_BUZZZ_DUMP):
		bcmerror = dhd_buzzz_dump_dngl(bus);
		break;
#endif /* BCM_BUZZZ */

	case IOV_SVAL(IOV_SET_DOWNLOAD_STATE):
		bcmerror = dhdpcie_bus_download_state(bus, bool_val);
		break;

	case IOV_GVAL(IOV_RAMSIZE):
		int_val = (int32)bus->ramsize;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_RAMSIZE):
		bus->ramsize = int_val;
		bus->orig_ramsize = int_val;
		break;

	case IOV_GVAL(IOV_RAMSTART):
		int_val = (int32)bus->dongle_ram_base;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_GVAL(IOV_CC_NVMSHADOW):
	{
		struct bcmstrbuf dump_b;

		bcm_binit(&dump_b, arg, len);
		bcmerror = dhdpcie_cc_nvmshadow(bus, &dump_b);
		break;
	}

	case IOV_GVAL(IOV_SLEEP_ALLOWED):
		bool_val = bus->sleep_allowed;
		bcopy(&bool_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_SLEEP_ALLOWED):
		bus->sleep_allowed = bool_val;
		break;

	case IOV_GVAL(IOV_DONGLEISOLATION):
		int_val = bus->dhd->dongle_isolation;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_DONGLEISOLATION):
		bus->dhd->dongle_isolation = bool_val;
		break;

	case IOV_GVAL(IOV_LTRSLEEPON_UNLOOAD):
		int_val = bus->ltrsleep_on_unload;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_LTRSLEEPON_UNLOOAD):
		bus->ltrsleep_on_unload = bool_val;
		break;

	case IOV_GVAL(IOV_DUMP_RINGUPD_BLOCK):
	{
		struct bcmstrbuf dump_b;
		bcm_binit(&dump_b, arg, len);
		bcmerror = dhd_prot_ringupd_dump(bus->dhd, &dump_b);
		break;
	}
	case IOV_GVAL(IOV_DMA_RINGINDICES):
	{
		int_val = dhdpcie_get_dma_ring_indices(bus->dhd);
		bcopy(&int_val, arg, sizeof(int_val));
		break;
	}
	case IOV_SVAL(IOV_DMA_RINGINDICES):
		bcmerror = dhdpcie_set_dma_ring_indices(bus->dhd, int_val);
		break;

	case IOV_GVAL(IOV_METADATA_DBG):
		int_val = dhd_prot_metadata_dbg_get(bus->dhd);
		bcopy(&int_val, arg, val_size);
		break;
	case IOV_SVAL(IOV_METADATA_DBG):
		dhd_prot_metadata_dbg_set(bus->dhd, (int_val != 0));
		break;

	case IOV_GVAL(IOV_RX_METADATALEN):
		int_val = dhd_prot_metadatalen_get(bus->dhd, TRUE);
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_RX_METADATALEN):
		if (int_val > 64) {
			bcmerror = BCME_BUFTOOLONG;
			break;
		}
		dhd_prot_metadatalen_set(bus->dhd, int_val, TRUE);
		break;

	case IOV_SVAL(IOV_TXP_THRESHOLD):
		dhd_prot_txp_threshold(bus->dhd, TRUE, int_val);
		break;

	case IOV_GVAL(IOV_TXP_THRESHOLD):
		int_val = dhd_prot_txp_threshold(bus->dhd, FALSE, int_val);
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_DB1_FOR_MB):
		if (int_val)
			bus->db1_for_mb = TRUE;
		else
			bus->db1_for_mb = FALSE;
		break;

	case IOV_GVAL(IOV_DB1_FOR_MB):
		if (bus->db1_for_mb)
			int_val = 1;
		else
			int_val = 0;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_GVAL(IOV_TX_METADATALEN):
		int_val = dhd_prot_metadatalen_get(bus->dhd, FALSE);
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_TX_METADATALEN):
		if (int_val > 64) {
			bcmerror = BCME_BUFTOOLONG;
			break;
		}
		dhd_prot_metadatalen_set(bus->dhd, int_val, FALSE);
		break;

	case IOV_SVAL(IOV_DEVRESET):
		switch (int_val) {
			case DHD_BUS_DEVRESET_ON:
				bcmerror = dhd_bus_devreset(bus->dhd, (uint8)int_val);
				break;
			case DHD_BUS_DEVRESET_OFF:
				bcmerror = dhd_bus_devreset(bus->dhd, (uint8)int_val);
				break;
			case DHD_BUS_DEVRESET_FLR:
				bcmerror = dhd_bus_perform_flr(bus, bus->flr_force_fail);
				break;
			case DHD_BUS_DEVRESET_FLR_FORCE_FAIL:
				bus->flr_force_fail = TRUE;
				break;
			default:
				DHD_ERROR(("%s: invalid argument for devreset\n", __FUNCTION__));
				break;
		}
		break;
	case IOV_SVAL(IOV_FORCE_FW_TRAP):
		if (bus->dhd->busstate == DHD_BUS_DATA)
			dhdpcie_fw_trap(bus);
		else {
			DHD_ERROR(("%s: Bus is NOT up\n", __FUNCTION__));
			bcmerror = BCME_NOTUP;
		}
		break;
	case IOV_GVAL(IOV_FLOW_PRIO_MAP):
		int_val = bus->dhd->flow_prio_map_type;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_FLOW_PRIO_MAP):
		int_val = (int32)dhd_update_flow_prio_map(bus->dhd, (uint8)int_val);
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_GVAL(IOV_TXBOUND):
		int_val = (int32)dhd_txbound;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_TXBOUND):
		dhd_txbound = (uint)int_val;
		break;

	case IOV_SVAL(IOV_H2D_MAILBOXDATA):
		dhdpcie_send_mb_data(bus, (uint)int_val);
		break;

	case IOV_SVAL(IOV_INFORINGS):
		dhd_prot_init_info_rings(bus->dhd);
		break;

	case IOV_SVAL(IOV_H2D_PHASE):
		if (bus->dhd->busstate != DHD_BUS_DOWN) {
			DHD_ERROR(("%s: Can change only when bus down (before FW download)\n",
				__FUNCTION__));
			bcmerror = BCME_NOTDOWN;
			break;
		}
		if (int_val)
			bus->dhd->h2d_phase_supported = TRUE;
		else
			bus->dhd->h2d_phase_supported = FALSE;
		break;

	case IOV_GVAL(IOV_H2D_PHASE):
		int_val = (int32) bus->dhd->h2d_phase_supported;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_H2D_ENABLE_TRAP_BADPHASE):
		if (bus->dhd->busstate != DHD_BUS_DOWN) {
			DHD_ERROR(("%s: Can change only when bus down (before FW download)\n",
				__FUNCTION__));
			bcmerror = BCME_NOTDOWN;
			break;
		}
		if (int_val)
			bus->dhd->force_dongletrap_on_bad_h2d_phase = TRUE;
		else
			bus->dhd->force_dongletrap_on_bad_h2d_phase = FALSE;
		break;
