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
