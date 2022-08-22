/*
 * DHD Bus Module for SDIO
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
 * $Id: dhd_sdio.c 825481 2019-06-14 10:06:03Z $
 */

#include <typedefs.h>
#include <osl.h>
#include <bcmsdh.h>

#include <bcmdefs.h>
#include <bcmutils.h>
#include <bcmendian.h>
#include <bcmdevs.h>

#include <siutils.h>
#include <hndpmu.h>
#include <hndsoc.h>
#include <bcmsdpcm.h>
#include <hnd_armtrap.h>
#include <hnd_cons.h>
#include <sbchipc.h>
#include <sbhnddma.h>

#include <sdio.h>
#ifdef BCMSPI
#include <spid.h>
#endif /* BCMSPI */
#include <sbsdio.h>
#include <sbsdpcmdev.h>
#include <bcmsdpcm.h>
#include <bcmsdbus.h>

#include <ethernet.h>
#include <802.1d.h>
#include <802.11.h>

#include <dngl_stats.h>
#include <dhd.h>
#include <dhd_bus.h>
#include <dhd_proto.h>
#include <dhd_dbg.h>
#include <dhdioctl.h>
#include <sdiovar.h>
#include <dhd_config.h>
#ifdef DHD_PKTDUMP_TOFW
#include <dhd_linux_pktdump.h>
#endif
#include <linux/mmc/sdio_func.h>
#include <dhd_linux.h>

#ifdef PROP_TXSTATUS
#include <dhd_wlfc.h>
#endif // endif
#ifdef DHDTCPACK_SUPPRESS
#include <dhd_ip.h>
#endif /* DHDTCPACK_SUPPRESS */

#ifdef BT_OVER_SDIO
#include <dhd_bt_interface.h>
#endif /* BT_OVER_SDIO */

#if defined(DEBUGGER) || defined(DHD_DSCOPE)
#include <debugger.h>
#endif /* DEBUGGER || DHD_DSCOPE */

bool dhd_mp_halting(dhd_pub_t *dhdp);
extern void bcmsdh_waitfor_iodrain(void *sdh);
extern void bcmsdh_reject_ioreqs(void *sdh, bool reject);
extern bool  bcmsdh_fatal_error(void *sdh);
static int dhdsdio_suspend(void *context);
static int dhdsdio_resume(void *context);

#ifndef DHDSDIO_MEM_DUMP_FNAME
#define DHDSDIO_MEM_DUMP_FNAME         "mem_dump"
#endif // endif

#define QLEN		(1024) /* bulk rx and tx queue lengths */
#define FCHI		(QLEN - 10)
#define FCLOW		(FCHI / 2)
#define PRIOMASK	7

#define F0_BLOCK_SIZE 32
#define TXRETRIES	2	/* # of retries for tx frames */
#define READ_FRM_CNT_RETRIES	3
#ifndef DHD_RXBOUND
#define DHD_RXBOUND	50	/* Default for max rx frames in one scheduling */
#endif // endif

#ifndef DHD_TXBOUND
#define DHD_TXBOUND	20	/* Default for max tx frames in one scheduling */
#endif // endif

#define DHD_TXMINMAX	1	/* Max tx frames if rx still pending */

#define MEMBLOCK	2048		/* Block size used for downloading of dongle image */
#define MAX_MEMBLOCK  (32 * 1024)	/* Block size used for downloading of dongle image */

#define MAX_DATA_BUF	(64 * 1024)	/* Must be large enough to hold biggest possible glom */
#define MAX_MEM_BUF	4096

#ifndef DHD_FIRSTREAD
#define DHD_FIRSTREAD   32
#endif // endif
#if !ISPOWEROF2(DHD_FIRSTREAD)
#error DHD_FIRSTREAD is not a power of 2!
#endif // endif

/* Total length of frame header for dongle protocol */
#define SDPCM_HDRLEN	(SDPCM_FRAMETAG_LEN + SDPCM_SWHEADER_LEN)
#define SDPCM_HDRLEN_TXGLOM	(SDPCM_HDRLEN + SDPCM_HWEXT_LEN)
#define MAX_TX_PKTCHAIN_CNT	SDPCM_MAXGLOM_SIZE

#ifdef SDTEST
#define SDPCM_RESERVE	(SDPCM_HDRLEN + SDPCM_TEST_HDRLEN + DHD_SDALIGN)
#else
#define SDPCM_RESERVE	(SDPCM_HDRLEN + DHD_SDALIGN)
#endif // endif

/* Space for header read, limit for data packets */
#ifndef MAX_HDR_READ
#define MAX_HDR_READ	32
#endif // endif
#if !ISPOWEROF2(MAX_HDR_READ)
#error MAX_HDR_READ is not a power of 2!
#endif // endif

#define MAX_RX_DATASZ	2048

/* Maximum milliseconds to wait for F2 to come up */
#define DHD_WAIT_F2RDY	3000

/* Maximum usec to wait for HTAVAIL to come up */
#define DHD_WAIT_HTAVAIL	10000

/* Bump up limit on waiting for HT to account for first startup;
 * if the image is doing a CRC calculation before programming the PMU
 * for HT availability, it could take a couple hundred ms more, so
 * max out at a 1 second (1000000us).
 */
#if (PMU_MAX_TRANSITION_DLY <= 1000000)
#undef PMU_MAX_TRANSITION_DLY
#ifdef NO_EXT32K
#define PMU_MAX_TRANSITION_DLY (1000000*5)
#else
#define PMU_MAX_TRANSITION_DLY 1000000
#endif
#endif // endif

/* hooks for limiting threshold custom tx num in rx processing */
#define DEFAULT_TXINRX_THRES    0
#ifndef CUSTOM_TXINRX_THRES
#define CUSTOM_TXINRX_THRES     DEFAULT_TXINRX_THRES
#endif // endif

/* Value for ChipClockCSR during initial setup */
#define DHD_INIT_CLKCTL1	(SBSDIO_FORCE_HW_CLKREQ_OFF | SBSDIO_ALP_AVAIL_REQ)
#define DHD_INIT_CLKCTL2	(SBSDIO_FORCE_HW_CLKREQ_OFF | SBSDIO_FORCE_ALP)

/* Flags for SDH calls */
#define F2SYNC	(SDIO_REQ_4BYTE | SDIO_REQ_FIXED)

/* Packet free applicable unconditionally for sdio and sdspi.  Conditional if
 * bufpool was present for gspi bus.
 */
#define PKTFREE2()		if ((bus->bus != SPI_BUS) || bus->usebufpool) \
					PKTFREE(bus->dhd->osh, pkt, FALSE);
DHD_SPINWAIT_SLEEP_INIT(sdioh_spinwait_sleep);

#ifdef SUPPORT_MULTIPLE_BOARD_REV_FROM_HW
extern unsigned int system_hw_rev;
#endif /* SUPPORT_MULTIPLE_BOARD_REV_FROM_HW */

/* Device console log buffer state */
#define CONSOLE_LINE_MAX	192
#define CONSOLE_BUFFER_MAX	8192
typedef struct dhd_console {
	uint		count;			/* Poll interval msec counter */
	uint		log_addr;		/* Log struct address (fixed) */
	hnd_log_t	log;			/* Log struct (host copy) */
	uint		bufsize;		/* Size of log buffer */
	uint8		*buf;			/* Log buffer (host copy) */
	uint		last;			/* Last buffer read index */
} dhd_console_t;

#define	REMAP_ENAB(bus)			((bus)->remap)
#define	REMAP_ISADDR(bus, a)		(((a) >= ((bus)->orig_ramsize)) && ((a) < ((bus)->ramsize)))
#define	KSO_ENAB(bus)			((bus)->kso)
#define	SR_ENAB(bus)			((bus)->_srenab)
#define	SLPAUTO_ENAB(bus)		((SR_ENAB(bus)) && ((bus)->_slpauto))

#define	MIN_RSRC_SR			0x3
#define	CORE_CAPEXT_ADDR_OFFSET		(0x64c)
#define	CORE_CAPEXT_SR_SUPPORTED_MASK	(1 << 1)
#define RCTL_MACPHY_DISABLE_MASK	(1 << 26)
#define RCTL_LOGIC_DISABLE_MASK		(1 << 27)

#define	OOB_WAKEUP_ENAB(bus)		((bus)->_oobwakeup)
#define	GPIO_DEV_SRSTATE		16	/* Host gpio17 mapped to device gpio0 SR state */
#define	GPIO_DEV_SRSTATE_TIMEOUT	320000	/* 320ms */
#define	GPIO_DEV_WAKEUP			17	/* Host gpio17 mapped to device gpio1 wakeup */
#define	CC_CHIPCTRL2_GPIO1_WAKEUP	(1  << 0)
#define	CC_CHIPCTRL3_SR_ENG_ENABLE	(1  << 2)
#define OVERFLOW_BLKSZ512_WM		96
#define OVERFLOW_BLKSZ512_MES		80

#define CC_PMUCC3	(0x3)

#ifdef DHD_UCODE_DOWNLOAD
/* Ucode host download related macros */
#define UCODE_DOWNLOAD_REQUEST  0xCAFECAFE
#define UCODE_DOWNLOAD_COMPLETE 0xABCDABCD
#endif /* DHD_UCODE_DOWNLOAD */

#if defined(BT_OVER_SDIO)
#define BTMEM_OFFSET			0x19000000
/* BIT0 => WLAN Power UP and BIT1=> WLAN Wake */
#define BT2WLAN_PWRUP_WAKE		0x03
#define BT2WLAN_PWRUP_ADDR		0x640894	/* This address is specific to 43012B0 */

#define BTFW_MAX_STR_LEN		600
#define BTFW_DOWNLOAD_BLK_SIZE		(BTFW_MAX_STR_LEN/2 + 8)

#define BTFW_ADDR_MODE_UNKNOWN		0
#define BTFW_ADDR_MODE_EXTENDED		1
#define BTFW_ADDR_MODE_SEGMENT		2
#define BTFW_ADDR_MODE_LINEAR32		3

#define BTFW_HEX_LINE_TYPE_DATA				0
#define BTFW_HEX_LINE_TYPE_END_OF_DATA			1
#define BTFW_HEX_LINE_TYPE_EXTENDED_SEGMENT_ADDRESS	2
#define BTFW_HEX_LINE_TYPE_EXTENDED_ADDRESS		4
#define BTFW_HEX_LINE_TYPE_ABSOLUTE_32BIT_ADDRESS	5

#endif /* defined (BT_OVER_SDIO) */

/* Private data for SDIO bus interaction */
typedef struct dhd_bus {
	dhd_pub_t	*dhd;

	bcmsdh_info_t	*sdh;			/* Handle for BCMSDH calls */
	si_t		*sih;			/* Handle for SI calls */
	char		*vars;			/* Variables (from CIS and/or other) */
	uint		varsz;			/* Size of variables buffer */
	uint32		sbaddr;			/* Current SB window pointer (-1, invalid) */

	sdpcmd_regs_t	*regs;			/* Registers for SDIO core */
	uint		sdpcmrev;		/* SDIO core revision */
	uint		armrev;			/* CPU core revision */
	uint		ramrev;			/* SOCRAM core revision */
	uint32		ramsize;		/* Size of RAM in SOCRAM (bytes) */
	uint32		orig_ramsize;		/* Size of RAM in SOCRAM (bytes) */
	uint32		srmemsize;		/* Size of SRMEM */

	uint32		bus;			/* gSPI or SDIO bus */
	uint32		bus_num;		/* bus number */
	uint32		slot_num;		/* slot ID */
	uint32		hostintmask;	/* Copy of Host Interrupt Mask */
	uint32		intstatus;		/* Intstatus bits (events) pending */
	bool		dpc_sched;		/* Indicates DPC schedule (intrpt rcvd) */
	bool		fcstate;		/* State of dongle flow-control */

	uint16		cl_devid;		/* cached devid for dhdsdio_probe_attach() */
	char		*fw_path;		/* module_param: path to firmware image */
	char		*nv_path;		/* module_param: path to nvram vars file */

	uint		blocksize;		/* Block size of SDIO transfers */
	uint		roundup;		/* Max roundup limit */

	struct pktq	txq;			/* Queue length used for flow-control */
	uint8		flowcontrol;		/* per prio flow control bitmask */
	uint8		tx_seq;			/* Transmit sequence number (next) */
	uint8		tx_max;			/* Maximum transmit sequence allowed */

#ifdef DYNAMIC_MAX_HDR_READ
	uint8		*hdrbufp;
#else
	uint8		hdrbuf[MAX_HDR_READ + DHD_SDALIGN];
#endif
	uint8		*rxhdr;			/* Header of current rx frame (in hdrbuf) */
	uint16		nextlen;		/* Next Read Len from last header */
	uint8		rx_seq;			/* Receive sequence number (expected) */
	bool		rxskip;			/* Skip receive (awaiting NAK ACK) */

	void		*glomd;			/* Packet containing glomming descriptor */
	void		*glom;			/* Packet chain for glommed superframe */
	uint		glomerr;		/* Glom packet read errors */

	uint8		*rxbuf;			/* Buffer for receiving control packets */
	uint		rxblen;			/* Allocated length of rxbuf */
	uint8		*rxctl;			/* Aligned pointer into rxbuf */
	uint8		*databuf;		/* Buffer for receiving big glom packet */
	uint8		*dataptr;		/* Aligned pointer into databuf */
	uint		rxlen;			/* Length of valid data in buffer */

	uint8		sdpcm_ver;		/* Bus protocol reported by dongle */

	bool		intr;			/* Use interrupts */
	bool		poll;			/* Use polling */
	bool		ipend;			/* Device interrupt is pending */
	bool		intdis;			/* Interrupts disabled by isr */
	uint 		intrcount;		/* Count of device interrupt callbacks */
	uint		lastintrs;		/* Count as of last watchdog timer */
	uint		spurious;		/* Count of spurious interrupts */
	uint		pollrate;		/* Ticks between device polls */
	uint		polltick;		/* Tick counter */
	uint		pollcnt;		/* Count of active polls */

	dhd_console_t	console;		/* Console output polling support */
	uint		console_addr;		/* Console address from shared struct */

	uint		regfails;		/* Count of R_REG/W_REG failures */

	uint		clkstate;		/* State of sd and backplane clock(s) */
	bool		activity;		/* Activity flag for clock down */
	int32		idletime;		/* Control for activity timeout */
	int32		idlecount;		/* Activity timeout counter */
	int32		idleclock;		/* How to set bus driver when idle */
	int32		sd_divisor;		/* Speed control to bus driver */
	int32		sd_mode;		/* Mode control to bus driver */
	int32		sd_rxchain;		/* If bcmsdh api accepts PKT chains */
	bool		use_rxchain;		/* If dhd should use PKT chains */
	bool		sleeping;		/* Is SDIO bus sleeping? */
#if defined(SUPPORT_P2P_GO_PS)
	wait_queue_head_t bus_sleep;
#endif /* LINUX && SUPPORT_P2P_GO_PS */
	bool		ctrl_wait;
	wait_queue_head_t ctrl_tx_wait;
	uint		rxflow_mode;		/* Rx flow control mode */
	bool		rxflow;			/* Is rx flow control on */
	uint		prev_rxlim_hit;		/* Is prev rx limit exceeded (per dpc schedule) */
	bool		alp_only;		/* Don't use HT clock (ALP only) */
	/* Field to decide if rx of control frames happen in rxbuf or lb-pool */
	bool		usebufpool;
	int32		txinrx_thres;	/* num of in-queued pkts */
	int32		dotxinrx;	/* tx first in dhdsdio_readframes */
#ifdef BCMSDIO_RXLIM_POST
	bool		rxlim_en;
	uint32		rxlim_addr;
#endif /* BCMSDIO_RXLIM_POST */
#ifdef SDTEST
	/* external loopback */
	bool		ext_loop;
	uint8		loopid;

	/* pktgen configuration */
	uint		pktgen_freq;		/* Ticks between bursts */
	uint		pktgen_count;		/* Packets to send each burst */
	uint		pktgen_print;		/* Bursts between count displays */
	uint		pktgen_total;		/* Stop after this many */
	uint		pktgen_minlen;		/* Minimum packet data len */
	uint		pktgen_maxlen;		/* Maximum packet data len */
	uint		pktgen_mode;		/* Configured mode: tx, rx, or echo */
	uint		pktgen_stop;		/* Number of tx failures causing stop */

	/* active pktgen fields */
	uint		pktgen_tick;		/* Tick counter for bursts */
	uint		pktgen_ptick;		/* Burst counter for printing */
	uint		pktgen_sent;		/* Number of test packets generated */
	uint		pktgen_rcvd;		/* Number of test packets received */
	uint		pktgen_prev_time;	/* Time at which previous stats where printed */
	uint		pktgen_prev_sent;	/* Number of test packets generated when
						 * previous stats were printed
						 */
	uint		pktgen_prev_rcvd;	/* Number of test packets received when
						 * previous stats were printed
						 */
	uint		pktgen_fail;		/* Number of failed send attempts */
	uint16		pktgen_len;		/* Length of next packet to send */
#define PKTGEN_RCV_IDLE     (0)
#define PKTGEN_RCV_ONGOING  (1)
	uint16		pktgen_rcv_state;		/* receive state */
	uint		pktgen_rcvd_rcvsession;	/* test pkts rcvd per rcv session. */
#endif /* SDTEST */

	/* Some additional counters */
	uint		tx_sderrs;		/* Count of tx attempts with sd errors */
	uint		fcqueued;		/* Tx packets that got queued */
	uint		rxrtx;			/* Count of rtx requests (NAK to dongle) */
	uint		rx_toolong;		/* Receive frames too long to receive */
	uint		rxc_errors;		/* SDIO errors when reading control frames */
	uint		rx_hdrfail;		/* SDIO errors on header reads */
	uint		rx_badhdr;		/* Bad received headers (roosync?) */
	uint		rx_badseq;		/* Mismatched rx sequence number */
	uint		fc_rcvd;		/* Number of flow-control events received */
	uint		fc_xoff;		/* Number which turned on flow-control */
	uint		fc_xon;			/* Number which turned off flow-control */
	uint		rxglomfail;		/* Failed deglom attempts */
	uint		rxglomframes;		/* Number of glom frames (superframes) */
	uint		rxglompkts;		/* Number of packets from glom frames */
	uint		f2rxhdrs;		/* Number of header reads */
	uint		f2rxdata;		/* Number of frame data reads */
	uint		f2txdata;		/* Number of f2 frame writes */
	uint		f1regdata;		/* Number of f1 register accesses */
	wake_counts_t	wake_counts;		/* Wake up counter */
#ifdef BCMSPI
	bool		dwordmode;
#endif /* BCMSPI */
#ifdef DHDENABLE_TAILPAD
	uint		tx_tailpad_chain;	/* Number of tail padding by chaining pad_pkt */
	uint		tx_tailpad_pktget;	/* Number of tail padding by new PKTGET */
#endif /* DHDENABLE_TAILPAD */
	uint8		*ctrl_frame_buf;
	uint32		ctrl_frame_len;
	bool		ctrl_frame_stat;
#ifndef BCMSPI
	uint32		rxint_mode;	/* rx interrupt mode */
#endif /* BCMSPI */
	bool		remap;		/* Contiguous 1MB RAM: 512K socram + 512K devram
					 * Available with socram rev 16
					 * Remap region not DMA-able
					 */
	bool		kso;
	bool		_slpauto;
	bool		_oobwakeup;
	bool		_srenab;
	bool        readframes;
	bool        reqbussleep;
	uint32		resetinstr;
	uint32		dongle_ram_base;

	void		*glom_pkt_arr[SDPCM_MAXGLOM_SIZE];	/* Array of pkts for glomming */
	uint32		txglom_cnt;	/* Number of pkts in the glom array */
	uint32		txglom_total_len;	/* Total length of pkts in glom array */
	bool		txglom_enable;	/* Flag to indicate whether tx glom is enabled/disabled */
	uint32		txglomsize;	/* Glom size limitation */
#ifdef DHDENABLE_TAILPAD
	void		*pad_pkt;
#endif /* DHDENABLE_TAILPAD */
	uint32		dongle_trap_addr; /* device trap addr location in device memory */
#if defined(BT_OVER_SDIO)
	char		*btfw_path;	/* module_param: path to BT firmware image */
	uint32		bt_use_count; /* Counter that tracks whether BT is using the bus */
#endif /* defined (BT_OVER_SDIO) */
	uint		txglomframes;	/* Number of tx glom frames (superframes) */
	uint		txglompkts;		/* Number of packets from tx glom frames */
#ifdef PKT_STATICS
	struct pkt_statics tx_statics;
#endif
	uint8		*membuf;		/* Buffer for dhdsdio_membytes */
#ifdef CONSOLE_DPC
	char		cons_cmd[16];
#endif
} dhd_bus_t;

/*
 * Whenever DHD_IDLE_IMMEDIATE condition is handled, we have to now check if
 * BT is active too. Instead of adding #ifdef code in all the places, we thought
 * of adding one macro check as part of the if condition that checks for DHD_IDLE_IMMEDIATE
 * In case of non BT over SDIO builds, this macro will always return TRUE. In case
 * of the builds where BT_OVER_SDIO is enabled, it will expand to a condition check
 * that checks if bt_use_count is zero. So this macro will return equate to 1 if
 * bt_use_count is 0, indicating that there are no active users and if bt_use_count
 * is non zero it would return 0 there by preventing the caller from executing the
 * sleep calls.
 */
#ifdef BT_OVER_SDIO
#define NO_OTHER_ACTIVE_BUS_USER(bus)		(bus->bt_use_count == 0)
#else
#define NO_OTHER_ACTIVE_BUS_USER(bus)		(1)
#endif /* BT_OVER_SDIO */

/* clkstate */
#define CLK_NONE	0
#define CLK_SDONLY	1
#define CLK_PENDING	2	/* Not used yet */
#define CLK_AVAIL	3

#define DHD_NOPMU(dhd)	(FALSE)

#if defined(BCMSDIOH_STD)
#define BLK_64_MAXTXGLOM 20
#endif /* BCMSDIOH_STD */

#ifdef DHD_DEBUG
static int qcount[NUMPRIO];
static int tx_packets[NUMPRIO];
#endif /* DHD_DEBUG */

/* Deferred transmit */
const uint dhd_deferred_tx = 1;

extern uint dhd_watchdog_ms;
extern uint sd_f1_blocksize;

#ifdef BCMSPI_ANDROID
extern uint *dhd_spi_lockcount;
#endif /* BCMSPI_ANDROID */

extern void dhd_os_wd_timer(void *bus, uint wdtick);
int dhd_enableOOB(dhd_pub_t *dhd, bool sleep);

#ifdef DHD_PM_CONTROL_FROM_FILE
extern bool g_pm_control;
#endif /* DHD_PM_CONTROL_FROM_FILE */

/* Tx/Rx bounds */
uint dhd_txbound;
uint dhd_rxbound;
uint dhd_txminmax = DHD_TXMINMAX;

/* override the RAM size if possible */
#define DONGLE_MIN_RAMSIZE (128 *1024)
int dhd_dongle_ramsize;

uint dhd_doflow = TRUE;
uint dhd_dpcpoll = FALSE;

module_param(dhd_doflow, uint, 0644);
module_param(dhd_dpcpoll, uint, 0644);

static bool dhd_alignctl;

static bool sd1idle;

static bool retrydata;
#define RETRYCHAN(chan) (((chan) == SDPCM_EVENT_CHANNEL) || retrydata)

#ifdef BCMSPI
/* At a watermark around 8 the spid hits underflow error. */
static uint watermark = 32;
static uint mesbusyctrl = 0;
#else
static uint watermark = 8;
static uint mesbusyctrl = 0;
#endif /* BCMSPI */
#ifdef DYNAMIC_MAX_HDR_READ
uint firstread = DHD_FIRSTREAD;
#else
static const uint firstread = DHD_FIRSTREAD;
#endif

/* Retry count for register access failures */
static const uint retry_limit = 2;

/* Force even SD lengths (some host controllers mess up on odd bytes) */
static bool forcealign;

#if defined(DEBUGGER)
static uint32 dhd_sdio_reg_read(struct dhd_bus *bus, ulong addr);
static void dhd_sdio_reg_write(struct dhd_bus *bus, ulong addr, uint32 val);

/** the debugger layer will call back into this (bus) layer to read/write dongle memory */
static struct dhd_dbg_bus_ops_s  bus_ops = {
	.read_u16 = NULL,
	.read_u32 = dhd_sdio_reg_read,
	.write_u32 = dhd_sdio_reg_write,
};
#endif /* DEBUGGER */

#define ALIGNMENT  4

#if (defined(OOB_INTR_ONLY) && defined(HW_OOB)) || defined(FORCE_WOWLAN)
extern void bcmsdh_enable_hw_oob_intr(void *sdh, bool enable);
#endif // endif

#if defined(OOB_INTR_ONLY) && defined(SDIO_ISR_THREAD)
#error OOB_INTR_ONLY is NOT working with SDIO_ISR_THREAD
#endif /* defined(OOB_INTR_ONLY) && defined(SDIO_ISR_THREAD) */
#define PKTALIGN(osh, p, len, align)					\
	do {								\
		uintptr datalign;						\
		datalign = (uintptr)PKTDATA((osh), (p));		\
		datalign = ROUNDUP(datalign, (align)) - datalign;	\
		ASSERT(datalign < (align));				\
		ASSERT(PKTLEN((osh), (p)) >= ((len) + datalign));	\
		if (datalign)						\
			PKTPULL((osh), (p), (uint)datalign);			\
		PKTSETLEN((osh), (p), (len));				\
	} while (0)

/* Limit on rounding up frames */
static const uint max_roundup = 512;

/* Try doing readahead */
static bool dhd_readahead;

#if defined(BCMSDIOH_TXGLOM_EXT)
bool
dhdsdio_is_dataok(dhd_bus_t *bus) {
	return (((uint8)(bus->tx_max - bus->tx_seq) - bus->dhd->conf->tx_max_offset > 1) && \
	(((uint8)(bus->tx_max - bus->tx_seq) & 0x80) == 0));
}

uint8
dhdsdio_get_databufcnt(dhd_bus_t *bus) {
	return ((uint8)(bus->tx_max - bus->tx_seq) - 1 - bus->dhd->conf->tx_max_offset);
}
#endif

/* To check if there's window offered */
#if defined(BCMSDIOH_TXGLOM_EXT)
#define DATAOK(bus) dhdsdio_is_dataok(bus)
#else
#define DATAOK(bus) \
	(((uint8)(bus->tx_max - bus->tx_seq) > 1) && \
	(((uint8)(bus->tx_max - bus->tx_seq) & 0x80) == 0))
#endif

/* To check if there's window offered for ctrl frame */
#define TXCTLOK(bus) \
	(((uint8)(bus->tx_max - bus->tx_seq) != 0) && \
	(((uint8)(bus->tx_max - bus->tx_seq) & 0x80) == 0))

/* Number of pkts available in dongle for data RX */
#if defined(BCMSDIOH_TXGLOM_EXT)
#define DATABUFCNT(bus) dhdsdio_get_databufcnt(bus)
#else
#define DATABUFCNT(bus) \
	((uint8)(bus->tx_max - bus->tx_seq) - 1)
#endif

/* Macros to get register read/write status */
/* NOTE: these assume a local dhdsdio_bus_t *bus! */
#define R_SDREG(regvar, regaddr, retryvar) \
do { \
	retryvar = 0; \
	do { \
		regvar = R_REG(bus->dhd->osh, regaddr); \
	} while (bcmsdh_regfail(bus->sdh) && (++retryvar <= retry_limit)); \
	if (retryvar) { \
		bus->regfails += (retryvar-1); \
		if (retryvar > retry_limit) { \
			DHD_ERROR(("%s: FAILED" #regvar "READ, LINE %d\n", \
			           __FUNCTION__, __LINE__)); \
			regvar = 0; \
		} \
	} \
} while (0)

#define W_SDREG(regval, regaddr, retryvar) \
do { \
	retryvar = 0; \
	do { \
		W_REG(bus->dhd->osh, regaddr, regval); \
	} while (bcmsdh_regfail(bus->sdh) && (++retryvar <= retry_limit)); \
	if (retryvar) { \
		bus->regfails += (retryvar-1); \
		if (retryvar > retry_limit) \
			DHD_ERROR(("%s: FAILED REGISTER WRITE, LINE %d\n", \
			           __FUNCTION__, __LINE__)); \
	} \
} while (0)

#define BUS_WAKE(bus) \
	do { \
		bus->idlecount = 0; \
		if ((bus)->sleeping) \
			dhdsdio_bussleep((bus), FALSE); \
	} while (0);

/*
 * pktavail interrupts from dongle to host can be managed in 3 different ways
 * whenever there is a packet available in dongle to transmit to host.
 *
 * Mode 0:	Dongle writes the software host mailbox and host is interrupted.
 * Mode 1:	(sdiod core rev >= 4)
 *		Device sets a new bit in the intstatus whenever there is a packet
 *		available in fifo.  Host can't clear this specific status bit until all the
 *		packets are read from the FIFO.  No need to ack dongle intstatus.
 * Mode 2:	(sdiod core rev >= 4)
 *		Device sets a bit in the intstatus, and host acks this by writing
 *		one to this bit.  Dongle won't generate anymore packet interrupts
 *		until host reads all the packets from the dongle and reads a zero to
 *		figure that there are no more packets.  No need to disable host ints.
 *		Need to ack the intstatus.
 */

#define SDIO_DEVICE_HMB_RXINT		0	/* default old way */
#define SDIO_DEVICE_RXDATAINT_MODE_0	1	/* from sdiod rev 4 */
#define SDIO_DEVICE_RXDATAINT_MODE_1	2	/* from sdiod rev 4 */

#ifdef BCMSPI

#define FRAME_AVAIL_MASK(bus) I_HMB_FRAME_IND

#define DHD_BUS			SPI_BUS

/* check packet-available-interrupt in piggybacked dstatus */
#define PKT_AVAILABLE(bus, intstatus)	(bcmsdh_get_dstatus(bus->sdh) & STATUS_F2_PKT_AVAILABLE)

#define HOSTINTMASK		(I_HMB_FC_CHANGE | I_HMB_HOST_INT)

#define GSPI_PR55150_BAILOUT									\
do {												\
	uint32 dstatussw = bcmsdh_get_dstatus((void *)bus->sdh);				\
	uint32 dstatushw = bcmsdh_cfg_read_word(bus->sdh, SDIO_FUNC_0, SPID_STATUS_REG, NULL);	\
	uint32 intstatuserr = 0;								\
	uint retries = 0;									\
												\
	R_SDREG(intstatuserr, &bus->regs->intstatus, retries);					\
	printf("dstatussw = 0x%x, dstatushw = 0x%x, intstatus = 0x%x\n",			\
	        dstatussw, dstatushw, intstatuserr); 						\
												\
	bus->nextlen = 0;									\
	*finished = TRUE;									\
} while (0)

#else /* BCMSDIO */

#define FRAME_AVAIL_MASK(bus) 	\
	((bus->rxint_mode == SDIO_DEVICE_HMB_RXINT) ? I_HMB_FRAME_IND : I_XMTDATA_AVAIL)

#define DHD_BUS			SDIO_BUS

#define PKT_AVAILABLE(bus, intstatus)	((intstatus) & (FRAME_AVAIL_MASK(bus)))

#define HOSTINTMASK		(I_HMB_SW_MASK | I_CHIPACTIVE)

#define GSPI_PR55150_BAILOUT

#endif /* BCMSPI */

#ifdef SDTEST
static void dhdsdio_testrcv(dhd_bus_t *bus, void *pkt, uint seq);
static void dhdsdio_sdtest_set(dhd_bus_t *bus, uint count);
#endif // endif

static int dhdsdio_checkdied(dhd_bus_t *bus, char *data, uint size);
#ifdef DHD_DEBUG
static int dhd_serialconsole(dhd_bus_t *bus, bool get, bool enable, int *bcmerror);
#endif /* DHD_DEBUG */

#if defined(DHD_FW_COREDUMP)
static int dhdsdio_mem_dump(dhd_bus_t *bus);
static int dhdsdio_get_mem_dump(dhd_bus_t *bus);
#endif /* DHD_FW_COREDUMP */
static int dhdsdio_devcap_set(dhd_bus_t *bus, uint8 cap);
static int dhdsdio_download_state(dhd_bus_t *bus, bool enter);

static void dhdsdio_release(dhd_bus_t *bus, osl_t *osh);
static void dhdsdio_release_malloc(dhd_bus_t *bus, osl_t *osh);
static void dhdsdio_disconnect(void *ptr);
static bool dhdsdio_chipmatch(uint16 chipid);
static bool dhdsdio_probe_attach(dhd_bus_t *bus, osl_t *osh, void *sdh,
                                 void * regsva, uint16  devid);
static bool dhdsdio_probe_malloc(dhd_bus_t *bus, osl_t *osh, void *sdh);
static bool dhdsdio_probe_init(dhd_bus_t *bus, osl_t *osh, void *sdh);
static void dhdsdio_release_dongle(dhd_bus_t *bus, osl_t *osh, bool dongle_isolation,
	bool reset_flag);

static void dhd_dongle_setramsize(struct dhd_bus *bus, int mem_size);
static int dhd_bcmsdh_recv_buf(dhd_bus_t *bus, uint32 addr, uint fn, uint flags,
	uint8 *buf, uint nbytes,
	void *pkt, bcmsdh_cmplt_fn_t complete, void *handle);
static int dhd_bcmsdh_send_buf(dhd_bus_t *bus, uint32 addr, uint fn, uint flags,
	uint8 *buf, uint nbytes,
	void *pkt, bcmsdh_cmplt_fn_t complete, void *handle, int max_retry);
static int dhdsdio_txpkt(dhd_bus_t *bus, uint chan, void** pkts, int num_pkt, bool free_pkt);
static int dhdsdio_txpkt_preprocess(dhd_bus_t *bus, void *pkt, int chan, int txseq,
	int prev_chain_total_len, bool last_chained_pkt,
	int *pad_pkt_len, void **new_pkt
#if defined(BCMSDIOH_TXGLOM_EXT)
	, int first_frame
#endif
);
static int dhdsdio_txpkt_postprocess(dhd_bus_t *bus, void *pkt);

static int dhdsdio_download_firmware(dhd_bus_t *bus, osl_t *osh, void *sdh);
static int _dhdsdio_download_firmware(dhd_bus_t *bus);

#ifdef DHD_UCODE_DOWNLOAD
static int dhdsdio_download_ucode_file(struct dhd_bus *bus, char *ucode_path);
#endif /* DHD_UCODE_DOWNLOAD */
static int dhdsdio_download_code_file(dhd_bus_t *bus, char *image_path);
static int dhdsdio_download_nvram(dhd_bus_t *bus);
static int dhdsdio_bussleep(dhd_bus_t *bus, bool sleep);
static int dhdsdio_clkctl(dhd_bus_t *bus, uint target, bool pendok);
static uint8 dhdsdio_sleepcsr_get(dhd_bus_t *bus);
static bool dhdsdio_dpc(dhd_bus_t *bus);
static int dhd_bcmsdh_send_buffer(void *bus, uint8 *frame, uint16 len);
static int dhdsdio_set_sdmode(dhd_bus_t *bus, int32 sd_mode);
static int dhdsdio_sdclk(dhd_bus_t *bus, bool on);
static void dhdsdio_advertise_bus_cleanup(dhd_pub_t *dhdp);
static void dhdsdio_advertise_bus_remove(dhd_pub_t *dhdp);

#if defined(BT_OVER_SDIO)
static int extract_hex_field(char * line, uint16 start_pos, uint16 num_chars, uint16 * value);
static int read_more_btbytes(struct dhd_bus *bus, void * file, char *line, int * addr_mode,
	uint16 * hi_addr, uint32 * dest_addr, uint8 *data_bytes, uint32 * num_bytes);
static int dhdsdio_download_btfw(struct dhd_bus *bus, osl_t *osh, void *sdh);
static int _dhdsdio_download_btfw(struct dhd_bus *bus);
#endif /* defined (BT_OVER_SDIO) */

#ifdef DHD_ULP
#include <dhd_ulp.h>
static int dhd_bus_ulp_reinit_fw(dhd_bus_t *bus);
#endif /* DHD_ULP */

#ifdef DHD_WAKE_STATUS
int bcmsdh_get_total_wake(bcmsdh_info_t *bcmsdh);
int bcmsdh_set_get_wake(bcmsdh_info_t *bcmsdh, int flag);
#endif /* DHD_WAKE_STATUS */

static void
dhdsdio_tune_fifoparam(struct dhd_bus *bus)
{
	int err;
	uint8 devctl, wm, mes;

	if (bus->sih->buscorerev >= 15) {
		/* See .ppt in PR for these recommended values */
		if (bus->blocksize == 512) {
			wm = OVERFLOW_BLKSZ512_WM;
			mes = OVERFLOW_BLKSZ512_MES;
		} else {
			mes = bus->blocksize/4;
			wm = bus->blocksize/4;
		}

		watermark = wm;
		mesbusyctrl = mes;
	} else {
		DHD_INFO(("skip fifotune: SdioRev(%d) is lower than minimal requested ver\n",
			bus->sih->buscorerev));
		return;
	}

	/* Update watermark */
	if (wm > 0) {
		bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1, SBSDIO_WATERMARK, wm, &err);

		devctl = bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1, SBSDIO_DEVICE_CTL, &err);
		devctl |= SBSDIO_DEVCTL_F2WM_ENAB;
		bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1, SBSDIO_DEVICE_CTL, devctl, &err);
	}

	/* Update MES */
	if (mes > 0) {
		bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_MESBUSYCTRL,
			(mes | SBSDIO_MESBUSYCTRL_ENAB), &err);
	}

	DHD_INFO(("Apply overflow WAR: 0x%02x 0x%02x 0x%02x\n",
		bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1, SBSDIO_DEVICE_CTL, &err),
		bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1, SBSDIO_WATERMARK, &err),
		bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_MESBUSYCTRL, &err)));
}

static void
dhd_dongle_setramsize(struct dhd_bus *bus, int mem_size)
{
	int32 min_size =  DONGLE_MIN_RAMSIZE;
	/* Restrict the ramsize to user specified limit */
	DHD_ERROR(("user: Restrict the dongle ram size to %d, min accepted %d\n",
		dhd_dongle_ramsize, min_size));
	if ((dhd_dongle_ramsize > min_size) &&
		(dhd_dongle_ramsize < (int32)bus->orig_ramsize))
		bus->ramsize = dhd_dongle_ramsize;
}

static int
dhdsdio_set_siaddr_window(dhd_bus_t *bus, uint32 address)
{
	int err = 0;
	bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_SBADDRLOW,
	                 (address >> 8) & SBSDIO_SBADDRLOW_MASK, &err);
	if (!err)
		bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_SBADDRMID,
		                 (address >> 16) & SBSDIO_SBADDRMID_MASK, &err);
	if (!err)
		bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_SBADDRHIGH,
		                 (address >> 24) & SBSDIO_SBADDRHIGH_MASK, &err);
	return err;
}

#ifdef BCMSPI
static void
dhdsdio_wkwlan(dhd_bus_t *bus, bool on)
{
	int err;
	uint32 regdata;
	bcmsdh_info_t *sdh = bus->sdh;

	if (bus->sih->buscoretype == SDIOD_CORE_ID) {
		/* wake up wlan function :WAKE_UP goes as ht_avail_request and alp_avail_request */
		regdata = bcmsdh_cfg_read_word(sdh, SDIO_FUNC_0, SPID_CONFIG, NULL);
		DHD_INFO(("F0 REG0 rd = 0x%x\n", regdata));

		if (on == TRUE)
			regdata |= WAKE_UP;
		else
			regdata &= ~WAKE_UP;

		bcmsdh_cfg_write_word(sdh, SDIO_FUNC_0, SPID_CONFIG, regdata, &err);
	}
}
#endif /* BCMSPI */

#ifdef USE_OOB_GPIO1
static int
dhdsdio_oobwakeup_init(dhd_bus_t *bus)
{
	uint32 val, addr, data;

	bcmsdh_gpioouten(bus->sdh, GPIO_DEV_WAKEUP);

	addr = SI_ENUM_BASE(bus->sih) + OFFSETOF(chipcregs_t, chipcontrol_addr);
	data = SI_ENUM_BASE(bus->sih) + OFFSETOF(chipcregs_t, chipcontrol_data);

	/* Set device for gpio1 wakeup */
	bcmsdh_reg_write(bus->sdh, addr, 4, 2);
	val = bcmsdh_reg_read(bus->sdh, data, 4);
	val |= CC_CHIPCTRL2_GPIO1_WAKEUP;
	bcmsdh_reg_write(bus->sdh, data, 4, val);

	bus->_oobwakeup = TRUE;

	return 0;
}
#endif /* USE_OOB_GPIO1 */

#ifndef BCMSPI
/*
 * Query if FW is in SR mode
 */
static bool
dhdsdio_sr_cap(dhd_bus_t *bus)
{
	bool cap = FALSE;
	uint32  core_capext, addr, data;

	if (bus->sih->chip == BCM43430_CHIP_ID ||
		bus->sih->chip == BCM43018_CHIP_ID) {
		/* check if fw initialized sr engine */
		addr = SI_ENUM_BASE(bus->sih) + OFFSETOF(chipcregs_t, sr_control1);
		if (bcmsdh_reg_read(bus->sdh, addr, 4) != 0)
			cap = TRUE;

		return cap;
	}
	if (
		0) {
			core_capext = FALSE;
	} else if ((bus->sih->chip == BCM4330_CHIP_ID) ||
		(bus->sih->chip == BCM43362_CHIP_ID) ||
		(BCM4347_CHIP(bus->sih->chip))) {
			core_capext = FALSE;
	} else if ((bus->sih->chip == BCM4335_CHIP_ID) ||
		(bus->sih->chip == BCM4339_CHIP_ID) ||
		BCM4345_CHIP(bus->sih->chip) ||
		(bus->sih->chip == BCM4354_CHIP_ID) ||
		(bus->sih->chip == BCM4358_CHIP_ID) ||
		(bus->sih->chip == BCM43569_CHIP_ID) ||
		(bus->sih->chip == BCM4371_CHIP_ID) ||
		(BCM4349_CHIP(bus->sih->chip))		||
		(bus->sih->chip == BCM4350_CHIP_ID) ||
		(bus->sih->chip == BCM4362_CHIP_ID) ||
		(bus->sih->chip == BCM43012_CHIP_ID) ||
		(bus->sih->chip == BCM43014_CHIP_ID) ||
		(bus->sih->chip == BCM43751_CHIP_ID) ||
		(bus->sih->chip == BCM43752_CHIP_ID)) {
		core_capext = TRUE;
	} else {
		core_capext = bcmsdh_reg_read(bus->sdh,
			si_get_pmu_reg_addr(bus->sih, OFFSETOF(chipcregs_t, core_cap_ext)),
			4);
		core_capext = (core_capext & CORE_CAPEXT_SR_SUPPORTED_MASK);
	}
	if (!(core_capext))
		return FALSE;

	if ((bus->sih->chip == BCM4335_CHIP_ID) ||
		(bus->sih->chip == BCM4339_CHIP_ID) ||
		BCM4345_CHIP(bus->sih->chip) ||
		(bus->sih->chip == BCM4354_CHIP_ID) ||
		(bus->sih->chip == BCM4358_CHIP_ID) ||
		(bus->sih->chip == BCM43569_CHIP_ID) ||
		(bus->sih->chip == BCM4371_CHIP_ID) ||
		(bus->sih->chip == BCM4350_CHIP_ID)) {
		uint32 enabval = 0;
		addr = SI_ENUM_BASE(bus->sih) + OFFSETOF(chipcregs_t, chipcontrol_addr);
		data = SI_ENUM_BASE(bus->sih) + OFFSETOF(chipcregs_t, chipcontrol_data);
		bcmsdh_reg_write(bus->sdh, addr, 4, CC_PMUCC3);
		enabval = bcmsdh_reg_read(bus->sdh, data, 4);

		if ((bus->sih->chip == BCM4350_CHIP_ID) ||
			BCM4345_CHIP(bus->sih->chip) ||
			(bus->sih->chip == BCM4354_CHIP_ID) ||
			(bus->sih->chip == BCM4358_CHIP_ID) ||
			(bus->sih->chip == BCM43569_CHIP_ID) ||
			(bus->sih->chip == BCM4371_CHIP_ID))
			enabval &= CC_CHIPCTRL3_SR_ENG_ENABLE;

		if (enabval)
			cap = TRUE;
	} else {
		data = bcmsdh_reg_read(bus->sdh,
			si_get_pmu_reg_addr(bus->sih, OFFSETOF(chipcregs_t, retention_ctl)),
			4);
		if ((data & (RCTL_MACPHY_DISABLE_MASK | RCTL_LOGIC_DISABLE_MASK)) == 0)
			cap = TRUE;
	}

	return cap;
}

static int
dhdsdio_sr_init(dhd_bus_t *bus)
{
	uint8 val;
	int err = 0;

	if (bus->sih->chip == BCM43012_CHIP_ID) {
		val = bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_WAKEUPCTRL, NULL);
		val |= 1 << SBSDIO_FUNC1_WCTRL_ALPWAIT_SHIFT;
		bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_WAKEUPCTRL,
			1 << SBSDIO_FUNC1_WCTRL_ALPWAIT_SHIFT, &err);
		val = bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_WAKEUPCTRL, NULL);
	} else {
		val = bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_WAKEUPCTRL, NULL);
		val |= 1 << SBSDIO_FUNC1_WCTRL_HTWAIT_SHIFT;
		bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_WAKEUPCTRL,
			1 << SBSDIO_FUNC1_WCTRL_HTWAIT_SHIFT, &err);
		val = bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_WAKEUPCTRL, NULL);
	}

#ifdef USE_CMD14
	/* Add CMD14 Support */
	dhdsdio_devcap_set(bus,
		(SDIOD_CCCR_BRCM_CARDCAP_CMD14_SUPPORT | SDIOD_CCCR_BRCM_CARDCAP_CMD14_EXT));
#endif /* USE_CMD14 */

	if (CHIPID(bus->sih->chip) == BCM43430_CHIP_ID ||
		CHIPID(bus->sih->chip) == BCM43018_CHIP_ID ||
		CHIPID(bus->sih->chip) == BCM4339_CHIP_ID ||
		CHIPID(bus->sih->chip) == BCM43012_CHIP_ID ||
		CHIPID(bus->sih->chip) == BCM4362_CHIP_ID ||
		CHIPID(bus->sih->chip) == BCM43014_CHIP_ID ||
		CHIPID(bus->sih->chip) == BCM43751_CHIP_ID ||
		CHIPID(bus->sih->chip) == BCM43752_CHIP_ID)
		dhdsdio_devcap_set(bus, SDIOD_CCCR_BRCM_CARDCAP_CMD_NODEC);

	if (bus->sih->chip == BCM43012_CHIP_ID) {
		bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1,
			SBSDIO_FUNC1_CHIPCLKCSR, SBSDIO_HT_AVAIL_REQ, &err);
	} else {
		bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1,
			SBSDIO_FUNC1_CHIPCLKCSR, SBSDIO_FORCE_HT, &err);
	}
	bus->_slpauto = dhd_slpauto ? TRUE : FALSE;

	bus->_srenab = TRUE;

	return 0;
}
#endif /* BCMSPI */

/*
 * FIX: Be sure KSO bit is enabled
 * Currently, it's defaulting to 0 which should be 1.
 */
static int
dhdsdio_clk_kso_init(dhd_bus_t *bus)
{
	uint8 val;
	int err = 0;

	/* set flag */
	bus->kso = TRUE;

	/*
	 * Enable KeepSdioOn (KSO) bit for normal operation
	 * Default is 0 (4334A0) so set it. Fixed in B0.
	 */
	val = bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_SLEEPCSR, NULL);
	if (!(val & SBSDIO_FUNC1_SLEEPCSR_KSO_MASK)) {
		val |= (SBSDIO_FUNC1_SLEEPCSR_KSO_EN << SBSDIO_FUNC1_SLEEPCSR_KSO_SHIFT);
		bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_SLEEPCSR, val, &err);
		if (err)
			DHD_ERROR(("%s: SBSDIO_FUNC1_SLEEPCSR err: 0x%x\n", __FUNCTION__, err));
	}

	return 0;
}

#define KSO_DBG(x)
#define KSO_WAIT_US 50
#define KSO_WAIT_MS 1
#define KSO_SLEEP_RETRY_COUNT 20
#define KSO_WAKE_RETRY_COUNT 100
#define ERROR_BCME_NODEVICE_MAX 1

#define DEFAULT_MAX_KSO_ATTEMPTS (PMU_MAX_TRANSITION_DLY/KSO_WAIT_US)
#ifndef CUSTOM_MAX_KSO_ATTEMPTS
#define CUSTOM_MAX_KSO_ATTEMPTS DEFAULT_MAX_KSO_ATTEMPTS
#endif // endif

static int
dhdsdio_clk_kso_enab(dhd_bus_t *bus, bool on)
{
	uint8 wr_val = 0, rd_val, cmp_val, bmask;
	int err = 0;
	int try_cnt = 0, try_max = CUSTOM_MAX_KSO_ATTEMPTS;
	struct dhd_conf *conf = bus->dhd->conf;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0))
	wifi_adapter_info_t *adapter = NULL;
	uint32 bus_type = -1, bus_num = -1, slot_num = -1;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) */

	KSO_DBG(("%s> op:%s\n", __FUNCTION__, (on ? "KSO_SET" : "KSO_CLR")));

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0))
	dhd_bus_get_ids(bus, &bus_type, &bus_num, &slot_num);
	adapter = dhd_wifi_platform_get_adapter(bus_type, bus_num, slot_num);
	sdio_retune_crc_disable(adapter->sdio_func);
	if (on)
		sdio_retune_hold_now(adapter->sdio_func);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) */

	wr_val |= (on << SBSDIO_FUNC1_SLEEPCSR_KSO_SHIFT);

	bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_SLEEPCSR, wr_val, &err);

	/* In case of 43012 chip, the chip could go down immediately after KSO bit is cleared.
	 * So the further reads of KSO register could fail. Thereby just bailing out immediately
	 * after clearing KSO bit, to avoid polling of KSO bit.
	 */
	if ((!on) && (bus->sih->chip == BCM43012_CHIP_ID)) {
		goto exit;
	}

	if (on) {
		cmp_val = SBSDIO_FUNC1_SLEEPCSR_KSO_MASK |  SBSDIO_FUNC1_SLEEPCSR_DEVON_MASK;
		bmask = cmp_val;

		OSL_SLEEP(3);

	} else {
		/* Put device to sleep, turn off  KSO  */
		cmp_val = 0;
		bmask = SBSDIO_FUNC1_SLEEPCSR_KSO_MASK;
	}

	if (conf->kso_try_max)
		try_max = conf->kso_try_max;
	do {
		rd_val = bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_SLEEPCSR, &err);
		if (((rd_val & bmask) == cmp_val) && !err)
			break;

		KSO_DBG(("%s> KSO wr/rd retry:%d, ERR:%x \n", __FUNCTION__, try_cnt, err));

		if (((try_cnt + 1) % KSO_SLEEP_RETRY_COUNT) == 0) {
			OSL_SLEEP(KSO_WAIT_MS);
		} else
			OSL_DELAY(KSO_WAIT_US);

		bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_SLEEPCSR, wr_val, &err);
	} while (try_cnt++ < try_max);

#ifdef KSO_DEBUG
	if (try_cnt > 0 && try_cnt <= 10)
		conf->kso_try_array[0] += 1;
	else if (try_cnt <= 50)
		conf->kso_try_array[1] += 1;
	else if (try_cnt <= 100)
		conf->kso_try_array[2] += 1;
	else if (try_cnt <= 200)
		conf->kso_try_array[3] += 1;
	else if (try_cnt <= 500)
		conf->kso_try_array[4] += 1;
	else if (try_cnt <= 1000)
		conf->kso_try_array[5] += 1;
	else if (try_cnt <= 2000)
		conf->kso_try_array[6] += 1;
	else if (try_cnt <= 5000)
		conf->kso_try_array[7] += 1;
	else if (try_cnt <= 10000)
		conf->kso_try_array[8] += 1;
	else
		conf->kso_try_array[9] += 1;
#endif
	if (try_cnt > 2)
		KSO_DBG(("%s> op:%s, try_cnt:%d, rd_val:%x, ERR:%x \n",
			__FUNCTION__, (on ? "KSO_SET" : "KSO_CLR"), try_cnt, rd_val, err));

	if (try_cnt > try_max)  {
		DHD_ERROR(("%s> op:%s, ERROR: try_cnt:%d, rd_val:%x, ERR:%x \n",
			__FUNCTION__, (on ? "KSO_SET" : "KSO_CLR"), try_cnt, rd_val, err));
#ifdef KSO_DEBUG
		{
			int i;
			printk(KERN_CONT DHD_LOG_PREFIXS);
			for (i=0; i<10; i++) {
				printk(KERN_CONT "[%d]: %d, ", i, conf->kso_try_array[i]);
		 	}
			printk("\n");
		}
#endif
	}

exit:
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0))
	if (on)
		sdio_retune_release(adapter->sdio_func);
	sdio_retune_crc_enable(adapter->sdio_func);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) */

	return err;
}

static int
dhdsdio_clk_kso_iovar(dhd_bus_t *bus, bool on)
{
	int err = 0;

	if (on == FALSE) {

		BUS_WAKE(bus);
		dhdsdio_clkctl(bus, CLK_AVAIL, FALSE);

		DHD_ERROR(("%s: KSO disable clk: 0x%x\n", __FUNCTION__,
			bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1,
			SBSDIO_FUNC1_CHIPCLKCSR, &err)));
		dhdsdio_clk_kso_enab(bus, FALSE);
	} else {
		DHD_ERROR(("%s: KSO enable\n", __FUNCTION__));

		/* Make sure we have SD bus access */
		if (bus->clkstate == CLK_NONE) {
			DHD_ERROR(("%s: Request SD clk\n", __FUNCTION__));
			dhdsdio_clkctl(bus, CLK_SDONLY, FALSE);
		}

		dhdsdio_clk_kso_enab(bus, TRUE);

		DHD_ERROR(("%s: sleepcsr: 0x%x\n", __FUNCTION__,
			dhdsdio_sleepcsr_get(bus)));
	}

	bus->kso = on;
	BCM_REFERENCE(err);

	return 0;
}

static uint8
dhdsdio_sleepcsr_get(dhd_bus_t *bus)
{
	int err = 0;
	uint8 val = 0;

	val = bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_SLEEPCSR, &err);
	if (err)
		DHD_TRACE(("Failed to read SLEEPCSR: %d\n", err));

	return val;
}

uint8
dhdsdio_devcap_get(dhd_bus_t *bus)
{
	return bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_0, SDIOD_CCCR_BRCM_CARDCAP, NULL);
}

static int
dhdsdio_devcap_set(dhd_bus_t *bus, uint8 cap)
{
	int err = 0;

	bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_0, SDIOD_CCCR_BRCM_CARDCAP, cap, &err);
	if (err)
		DHD_ERROR(("%s: devcap set err: 0x%x\n", __FUNCTION__, err));

	return 0;
}

static int
dhdsdio_clk_devsleep_iovar(dhd_bus_t *bus, bool on)
{
	int err = 0, retry;
	uint8 val;

	retry = 0;
	if (on == TRUE) {
		/* Enter Sleep */

		/* Be sure we request clk before going to sleep
		 * so we can wake-up with clk request already set
		 * else device can go back to sleep immediately
		 */
		if (!SLPAUTO_ENAB(bus))
			dhdsdio_clkctl(bus, CLK_AVAIL, FALSE);
		else {
			val = bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_CHIPCLKCSR, &err);
			if ((val & SBSDIO_CSR_MASK) == 0) {
				DHD_ERROR(("%s: No clock before enter sleep:0x%x\n",
					__FUNCTION__, val));

				/* Reset clock request */
				bcmsdh_cfg_write(bus->sdh, SDIO_FUNC_1, SBSDIO_FUNC1_CHIPCLKCSR,
					SBSDIO_ALP_AVAIL_REQ, &err);
				DHD_ERROR(("%s: clock before sleep:0x%x\n", __FUNCTION__,
					bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1,
					SBSDIO_FUNC1_CHIPCLKCSR, &err)));
			}
		}

		DHD_TRACE(("%s: clk before sleep: 0x%x\n", __FUNCTION__,
			bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1,
			SBSDIO_FUNC1_CHIPCLKCSR, &err)));
#ifdef USE_CMD14
		err = bcmsdh_sleep(bus->sdh, TRUE);
#else
		if ((SLPAUTO_ENAB(bus)) && (bus->idleclock == DHD_IDLE_STOP)) {
			if (sd1idle) {
				/* Change to SD1 mode */
				dhdsdio_set_sdmode(bus, 1);
			}
		}

		err = dhdsdio_clk_kso_enab(bus, FALSE);
		if (OOB_WAKEUP_ENAB(bus))
		{
			err = bcmsdh_gpioout(bus->sdh, GPIO_DEV_WAKEUP, FALSE);  /* GPIO_1 is off */
		}
#endif /* USE_CMD14 */

		if ((SLPAUTO_ENAB(bus)) && (bus->idleclock != DHD_IDLE_ACTIVE)) {
			DHD_TRACE(("%s: Turnoff SD clk\n", __FUNCTION__));
			/* Now remove the SD clock */
			err = dhdsdio_sdclk(bus, FALSE);
		}
	} else {
		/* Exit Sleep */
		/* Make sure we have SD bus access */
		if (bus->clkstate == CLK_NONE) {
			DHD_TRACE(("%s: Request SD clk\n", __FUNCTION__));
			dhdsdio_clkctl(bus, CLK_SDONLY, FALSE);
		}
#ifdef USE_CMD14
		err = bcmsdh_sleep(bus->sdh, FALSE);
		if (SLPAUTO_ENAB(bus) && (err != 0)) {
			OSL_DELAY(10000);
			DHD_TRACE(("%s: Resync device sleep\n", __FUNCTION__));

			/* Toggle sleep to resync with host and device */
			err = bcmsdh_sleep(bus->sdh, TRUE);
			OSL_DELAY(10000);
			err = bcmsdh_sleep(bus->sdh, FALSE);

			if (err) {
				OSL_DELAY(10000);
				DHD_ERROR(("%s: CMD14 exit failed again!\n", __FUNCTION__));

				/* Toggle sleep to resync with host and device */
				err = bcmsdh_sleep(bus->sdh, TRUE);
				OSL_DELAY(10000);
				err = bcmsdh_sleep(bus->sdh, FALSE);
				if (err) {
					DHD_ERROR(("%s: CMD14 exit failed twice!\n", __FUNCTION__));
					DHD_ERROR(("%s: FATAL: Device non-response!\n",
						__FUNCTION__));
					err = 0;
				}
			}
		}
#else
		if (OOB_WAKEUP_ENAB(bus))
		{
			err = bcmsdh_gpioout(bus->sdh, GPIO_DEV_WAKEUP, TRUE);  /* GPIO_1 is on */
		}
		do {
			err = dhdsdio_clk_kso_enab(bus, TRUE);
			if (err)
				OSL_SLEEP(10);
		} while ((err != 0) && (++retry < 3));

		if (err != 0) {
			DHD_ERROR(("ERROR: kso set failed retry: %d\n", retry));
#ifndef BT_OVER_SDIO
			err = 0; /* continue anyway */
#endif /* BT_OVER_SDIO */
		}

		if ((SLPAUTO_ENAB(bus)) && (bus->idleclock == DHD_IDLE_STOP)) {
			dhdsdio_set_sdmode(bus, bus->sd_mode);
		}
#endif /* !USE_CMD14 */

		if (err == 0) {
			uint8 csr;

			/* Wait for device ready during transition to wake-up */
			SPINWAIT_SLEEP(sdioh_spinwait_sleep,
				(((csr = dhdsdio_sleepcsr_get(bus)) &
				SBSDIO_FUNC1_SLEEPCSR_DEVON_MASK) !=
				(SBSDIO_FUNC1_SLEEPCSR_DEVON_MASK)), (20000));

			DHD_TRACE(("%s: ExitSleep sleepcsr: 0x%x\n", __FUNCTION__, csr));

			if (!(csr & SBSDIO_FUNC1_SLEEPCSR_DEVON_MASK)) {
				DHD_ERROR(("%s:ERROR: ExitSleep device NOT Ready! 0x%x\n",
					__FUNCTION__, csr));
				err = BCME_NODEVICE;
			}

			SPINWAIT_SLEEP(sdioh_spinwait_sleep,
				(((csr = bcmsdh_cfg_read(bus->sdh, SDIO_FUNC_1,
				SBSDIO_FUNC1_CHIPCLKCSR, &err)) & SBSDIO_HT_AVAIL) !=
				(SBSDIO_HT_AVAIL)), (DHD_WAIT_HTAVAIL));

			DHD_TRACE(("%s: SBSDIO_FUNC1_CHIPCLKCSR : 0x%x\n", __FUNCTION__, csr));
			if (!err && ((csr & SBSDIO_HT_AVAIL) != SBSDIO_HT_AVAIL)) {
				DHD_ERROR(("%s:ERROR: device NOT Ready! 0x%x\n",
					__FUNCTION__, csr));
				err = BCME_NODEVICE;
			}
		}
	}

	/* Update if successful */
	if (err == 0)
		bus->kso = on ? FALSE : TRUE;
	else {
		DHD_ERROR(("%s: Sleep request failed: kso:%d on:%d err:%d\n",
			__FUNCTION__, bus->kso, on, err));
		if (!on && retry > 2)
			bus->kso = FALSE;
	}

	return err;
}

/* Turn backplane clock on or off */
static int
dhdsdio_htclk(dhd_bus_t *bus, bool on, bool pendok)
{
#define HT_AVAIL_ERROR_MAX 10
	static int ht_avail_error = 0;
	int err;
	uint8 clkctl, clkreq, devctl;
	bcmsdh_info_t *sdh;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	clkctl = 0;
	sdh = bus->sdh;

	if (!KSO_ENAB(bus))
		return BCME_OK;

	if (SLPAUTO_ENAB(bus)) {
		bus->clkstate = (on ? CLK_AVAIL : CLK_SDONLY);
		return BCME_OK;
	}

	if (on) {
		/* Request HT Avail */
		clkreq = bus->alp_only ? SBSDIO_ALP_AVAIL_REQ : SBSDIO_HT_AVAIL_REQ;

#ifdef BCMSPI
		dhdsdio_wkwlan(bus, TRUE);
#endif /* BCMSPI */

		bcmsdh_cfg_write(sdh, SDIO_FUNC_1, SBSDIO_FUNC1_CHIPCLKCSR, clkreq, &err);
		if (err) {
			ht_avail_error++;
			if (ht_avail_error < HT_AVAIL_ERROR_MAX) {
				DHD_ERROR(("%s: HT Avail request error: %d\n", __FUNCTION__, err));
			}

			else if (ht_avail_error == HT_AVAIL_ERROR_MAX) {
				bus->dhd->hang_reason = HANG_REASON_HT_AVAIL_ERROR;
				dhd_os_send_hang_message(bus->dhd);
			}
			return BCME_ERROR;
		} else {
			ht_avail_error = 0;
		}

		/* Check current status */
		clkctl = bcmsdh_cfg_read(sdh, SDIO_FUNC_1, SBSDIO_FUNC1_CHIPCLKCSR, &err);
		if (err) {
			DHD_ERROR(("%s: HT Avail read error: %d\n", __FUNCTION__, err));
			return BCME_ERROR;
		}

#if !defined(OOB_INTR_ONLY)
		/* Go to pending and await interrupt if appropriate */
		if (!SBSDIO_CLKAV(clkctl, bus->alp_only) && pendok) {
			/* Allow only clock-available interrupt */
			devctl = bcmsdh_cfg_read(sdh, SDIO_FUNC_1, SBSDIO_DEVICE_CTL, &err);
			if (err) {
				DHD_ERROR(("%s: Devctl access error setting CA: %d\n",
				           __FUNCTION__, err));
				return BCME_ERROR;
			}

			devctl |= SBSDIO_DEVCTL_CA_INT_ONLY;
			bcmsdh_cfg_write(sdh, SDIO_FUNC_1, SBSDIO_DEVICE_CTL, devctl, &err);
			DHD_INFO(("CLKCTL: set PENDING\n"));
			bus->clkstate = CLK_PENDING;
			return BCME_OK;
		} else
#endif /* !defined (OOB_INTR_ONLY) */
		{
			if (bus->clkstate == CLK_PENDING) {
				/* Cancel CA-only interrupt filter */
				devctl = bcmsdh_cfg_read(sdh, SDIO_FUNC_1, SBSDIO_DEVICE_CTL, &err);
				devctl &= ~SBSDIO_DEVCTL_CA_INT_ONLY;
				bcmsdh_cfg_write(sdh, SDIO_FUNC_1, SBSDIO_DEVICE_CTL, devctl, &err);
			}
		}
#ifndef BCMSDIOLITE
		/* Otherwise, wait here (polling) for HT Avail */
		if (!SBSDIO_CLKAV(clkctl, bus->alp_only)) {
			SPINWAIT_SLEEP(sdioh_spinwait_sleep,
				((clkctl = bcmsdh_cfg_read(sdh, SDIO_FUNC_1,
			                                    SBSDIO_FUNC1_CHIPCLKCSR, &err)),
			          !SBSDIO_CLKAV(clkctl, bus->alp_only)), PMU_MAX_TRANSITION_DLY);
		}
		if (err) {
			DHD_ERROR(("%s: HT Avail request error: %d\n", __FUNCTION__, err));
			return BCME_ERROR;
		}
		if (!SBSDIO_CLKAV(clkctl, bus->alp_only)) {
			DHD_ERROR(("%s: HT Avail timeout (%d): clkctl 0x%02x\n",
			           __FUNCTION__, PMU_MAX_TRANSITION_DLY, clkctl));
			return BCME_ERROR;
		}
#endif /* BCMSDIOLITE */
		/* Mark clock available */
		bus->clkstate = CLK_AVAIL;
		DHD_INFO(("CLKCTL: turned ON\n"));

#if defined(DHD_DEBUG)
		if (bus->alp_only == TRUE) {
#if !defined(BCMLXSDMMC)
			if (!SBSDIO_ALPONLY(clkctl)) {
				DHD_ERROR(("%s: HT Clock, when ALP Only\n", __FUNCTION__));
			}
#endif /* !defined(BCMLXSDMMC) */
		} else {
			if (SBSDIO_ALPONLY(clkctl)) {
				DHD_ERROR(("%s: HT Clock should be on.\n", __FUNCTION__));
			}
		}
#endif /* defined (DHD_DEBUG) */

		bus->activity = TRUE;
#ifdef DHD_USE_IDLECOUNT
		bus->idlecount = 0;
#endif /* DHD_USE_IDLECOUNT */
	} else {
		clkreq = 0;

		if (bus->clkstate == CLK_PENDING) {
			/* Cancel CA-only interrupt filter */
			devctl = bcmsdh_cfg_read(sdh, SDIO_FUNC_1, SBSDIO_DEVICE_CTL, &err);
			devctl &= ~SBSDIO_DEVCTL_CA_INT_ONLY;
			bcmsdh_cfg_write(sdh, SDIO_FUNC_1, SBSDIO_DEVICE_CTL, devctl, &err);
		}

		bus->clkstate = CLK_SDONLY;
		if (!SR_ENAB(bus)) {
			bcmsdh_cfg_write(sdh, SDIO_FUNC_1, SBSDIO_FUNC1_CHIPCLKCSR, clkreq, &err);
			DHD_INFO(("CLKCTL: turned OFF\n"));
			if (err) {
				DHD_ERROR(("%s: Failed access turning clock off: %d\n",
				           __FUNCTION__, err));
				return BCME_ERROR;
			}
		}
#ifdef BCMSPI
			dhdsdio_wkwlan(bus, FALSE);
#endif /* BCMSPI */
	}
	return BCME_OK;
}

/* Change SD1/SD4 bus mode */
static int
dhdsdio_set_sdmode(dhd_bus_t *bus, int32 sd_mode)
{
	int err;

	err = bcmsdh_iovar_op(bus->sdh, "sd_mode", NULL, 0,
		&sd_mode, sizeof(sd_mode), TRUE);
	if (err) {
		DHD_ERROR(("%s: error changing sd_mode: %d\n",
			__FUNCTION__, err));
		return BCME_ERROR;
	}
	return BCME_OK;
}

/* Change idle/active SD state */
static int
dhdsdio_sdclk(dhd_bus_t *bus, bool on)
{
#ifndef BCMSPI
	int err;
	int32 iovalue;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (on) {
		if (bus->idleclock == DHD_IDLE_STOP) {
			/* Turn on clock and restore mode */
			iovalue = 1;
			err = bcmsdh_iovar_op(bus->sdh, "sd_clock", NULL, 0,
			                      &iovalue, sizeof(iovalue), TRUE);
			if (err) {
				DHD_ERROR(("%s: error enabling sd_clock: %d\n",
				           __FUNCTION__, err));
				return BCME_ERROR;
			}

		} else if (bus->idleclock != DHD_IDLE_ACTIVE) {
			/* Restore clock speed */
			iovalue = bus->sd_divisor;
			err = bcmsdh_iovar_op(bus->sdh, "sd_divisor", NULL, 0,
			                      &iovalue, sizeof(iovalue), TRUE);
			if (err) {
				DHD_ERROR(("%s: error restoring sd_divisor: %d\n",
				           __FUNCTION__, err));
				return BCME_ERROR;
			}
		}
		bus->clkstate = CLK_SDONLY;
	} else {
		/* Stop or slow the SD clock itself */
		if ((bus->sd_divisor == -1) || (bus->sd_mode == -1)) {
			DHD_TRACE(("%s: can't idle clock, divisor %d mode %d\n",
			           __FUNCTION__, bus->sd_divisor, bus->sd_mode));
			return BCME_ERROR;
		}
		if (bus->idleclock == DHD_IDLE_STOP) {
			iovalue = 0;
			err = bcmsdh_iovar_op(bus->sdh, "sd_clock", NULL, 0,
			                      &iovalue, sizeof(iovalue), TRUE);
			if (err) {
				DHD_ERROR(("%s: error disabling sd_clock: %d\n",
				           __FUNCTION__, err));
				return BCME_ERROR;
			}
		} else if (bus->idleclock != DHD_IDLE_ACTIVE) {
			/* Set divisor to idle value */
			iovalue = bus->idleclock;
			err = bcmsdh_iovar_op(bus->sdh, "sd_divisor", NULL, 0,
			                      &iovalue, sizeof(iovalue), TRUE);
			if (err) {
				DHD_ERROR(("%s: error changing sd_divisor: %d\n",
				           __FUNCTION__, err));
				return BCME_ERROR;
			}
		}
		bus->clkstate = CLK_NONE;
	}
#endif /* BCMSPI */

	return BCME_OK;
}

/* Transition SD and backplane clock readiness */
static int
dhdsdio_clkctl(dhd_bus_t *bus, uint target, bool pendok)
{
	int ret = BCME_OK;
#ifdef DHD_DEBUG
	uint oldstate = bus->clkstate;
#endif /* DHD_DEBUG */

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	/* Early exit if we're already there */
	if (bus->clkstate == target) {
		if (target == CLK_AVAIL) {
			dhd_os_wd_timer(bus->dhd, dhd_watchdog_ms);
			bus->activity = TRUE;
#ifdef DHD_USE_IDLECOUNT
			bus->idlecount = 0;
#endif /* DHD_USE_IDLECOUNT */
		}
		return ret;
	}

	switch (target) {
	case CLK_AVAIL:
		/* Make sure SD clock is available */
		if (bus->clkstate == CLK_NONE)
			dhdsdio_sdclk(bus, TRUE);
		/* Now request HT Avail on the backplane */
		ret = dhdsdio_htclk(bus, TRUE, pendok);
		if (ret == BCME_OK) {
			dhd_os_wd_timer(bus->dhd, dhd_watchdog_ms);
		bus->activity = TRUE;
#ifdef DHD_USE_IDLECOUNT
			bus->idlecount = 0;
#endif /* DHD_USE_IDLECOUNT */
		}
		break;

	case CLK_SDONLY:

#ifdef BT_OVER_SDIO
		/*
		 * If the request is to switch off Back plane clock,
		 * confirm that BT is inactive before doing so.
		 * If this call had come from Non Watchdog context any way
		 * the Watchdog would switch off the clock again when
		 * nothing is to be done & Bt has finished using the bus.
		 */
		if (bus->bt_use_count != 0) {
			DHD_INFO(("%s(): Req CLK_SDONLY, BT is active %d not switching off \r\n",
				__FUNCTION__, bus->bt_use_count));
			ret = BCME_OK;
			dhd_os_wd_timer(bus->dhd, dhd_watchdog_ms);
			break;
		}

		DHD_INFO(("%s(): Request CLK_NONE BT is NOT active switching off \r\n",
			__FUNCTION__));
#endif /* BT_OVER_SDIO */

		/* Remove HT request, or bring up SD clock */
		if (bus->clkstate == CLK_NONE)
			ret = dhdsdio_sdclk(bus, TRUE);
		else if (bus->clkstate == CLK_AVAIL)
			ret = dhdsdio_htclk(bus, FALSE, FALSE);
		else
			DHD_ERROR(("dhdsdio_clkctl: request for %d -> %d\n",
			           bus->clkstate, target));
		if (ret == BCME_OK) {
			dhd_os_wd_timer(bus->dhd, dhd_watchdog_ms);
		}
		break;

	case CLK_NONE:

#ifdef BT_OVER_SDIO
		/*
		 * If the request is to switch off Back plane clock,
		 * confirm that BT is inactive before doing so.
		 * If this call had come from Non Watchdog context any way
		 * the Watchdog would switch off the clock again when
		 * nothing is to be done & Bt has finished using the bus.
		 */
		if (bus->bt_use_count != 0) {
			DHD_INFO(("%s(): Request CLK_NONE BT is active %d not switching off \r\n",
				__FUNCTION__, bus->bt_use_count));
			ret = BCME_OK;
			break;
		}

		DHD_INFO(("%s(): Request CLK_NONE BT is NOT active switching off \r\n",
			__FUNCTION__));
#endif /* BT_OVER_SDIO */

		/* Make sure to remove HT request */
		if (bus->clkstate == CLK_AVAIL)
			ret = dhdsdio_htclk(bus, FALSE, FALSE);
		/* Now remove the SD clock */
		ret = dhdsdio_sdclk(bus, FALSE);
#ifdef DHD_DEBUG
		if (bus->dhd->dhd_console_ms == 0)
#endif /* DHD_DEBUG */
		if (bus->poll == 0)
			dhd_os_wd_timer(bus->dhd, 0);
		break;
	}
#ifdef DHD_DEBUG
	DHD_INFO(("dhdsdio_clkctl: %d -> %d\n", oldstate, bus->clkstate));
#endif /* DHD_DEBUG */

	return ret;
}

static int
dhdsdio_bussleep(dhd_bus_t *bus, bool sleep)
{
	int err = 0;
	bcmsdh_info_t *sdh = bus->sdh;
	sdpcmd_regs_t *regs = bus->regs;
	uint retries = 0;
#if defined(BCMSDIOH_STD)
	uint32 sd3_tuning_disable = FALSE;
#endif /* BCMSDIOH_STD */

	DHD_INFO(("dhdsdio_bussleep: request %s (currently %s)\n",
	         (sleep ? "SLEEP" : "WAKE"),
	          (bus->sleeping ? "SLEEP" : "WAKE")));

	if (bus->dhd->hang_was_sent)
		return BCME_ERROR;

	/* Done if we're already in the requested state */
	if (sleep == bus->sleeping)
		return BCME_OK;

	/* Going to sleep: set the alarm and turn off the lights... */
	if (sleep) {
		/* Don't sleep if something is pending */
#ifdef DHD_USE_IDLECOUNT
		if (bus->dpc_sched || bus->rxskip || pktq_n_pkts_tot(&bus->txq) ||
			bus->readframes || bus->ctrl_frame_stat)
#else
		if (bus->dpc_sched || bus->rxskip || pktq_n_pkts_tot(&bus->txq))
#endif /* DHD_USE_IDLECOUNT */
			return BCME_BUSY;

#ifdef BT_OVER_SDIO
		/*
		 * The following is the assumption based on which the hook is placed.
		 * From WLAN driver, either from the active contexts OR from the Watchdog contexts
		 * we will be attempting to Go to Sleep. AT that moment if we see that BT is still
		 * actively using the bus, we will return BCME_BUSY from here, but the bus->sleeping
		 * state would not have changed. So the caller can then schedule the Watchdog again
		 * which will come and attempt to sleep at a later point.
		 *
		 * In case if BT is the only one and is the last user, we don't switch off the clock
		 * immediately, we allow the WLAN to decide when to sleep i.e from the watchdog.
		 * Now if the watchdog becomes active and attempts to switch off the clock and if
		 * another WLAN context is active they are any way serialized with sdlock.
		 */
		if (bus->bt_use_count != 0) {
			DHD_INFO(("%s(): Cannot sleep BT is active \r\n", __FUNCTION__));
			return BCME_BUSY;
		}
#endif /* !BT_OVER_SDIO */

		if (!SLPAUTO_ENAB(bus)) {
			/* Disable SDIO interrupts (no longer interested) */
			bcmsdh_intr_disable(bus->sdh);

			/* Make sure the controller has the bus up */
			dhdsdio_clkctl(bus, CLK_AVAIL, FALSE);

			/* Tell device to start using OOB wakeup */
			W_SDREG(SMB_USE_OOB, &regs->tosbmailbox, retries);
			if (retries > retry_limit)
				DHD_ERROR(("CANNOT SIGNAL CHIP, WILL NOT WAKE UP!!\n"));

			/* Turn off our contribution to the HT clock request */
			dhdsdio_clkctl(bus, CLK_SDONLY, FALSE);

			bcmsdh_cfg_write(sdh, SDIO_FUNC_1, SBSDIO_FUNC1_CHIPCLKCSR,
				SBSDIO_FORCE_HW_CLKREQ_OFF, NULL);

			/* Isolate the bus */
			bcmsdh_cfg_write(sdh, SDIO_FUNC_1, SBSDIO_DEVICE_CTL,
					SBSDIO_DEVCTL_PADS_ISO, NULL);
		} else {
#ifdef FORCE_SWOOB_ENABLE
			/* Tell device to start using OOB wakeup */
			W_SDREG(SMB_USE_OOB, &regs->tosbmailbox, retries);
			if (retries > retry_limit)
				DHD_ERROR(("CANNOT SIGNAL CHIP, WILL NOT WAKE UP!!\n"));
#endif
			/* Leave interrupts enabled since device can exit sleep and
			 * interrupt host
			 */
			err = dhdsdio_clk_devsleep_iovar(bus, TRUE /* sleep */);
		}

		/* Change state */
		bus->sleeping = TRUE;
#if defined(BCMSDIOH_STD)
		sd3_tuning_disable = TRUE;
		err = bcmsdh_iovar_op(bus->sdh, "sd3_tuning_disable", NULL, 0,
			&sd3_tuning_disable, sizeof(sd3_tuning_disable), TRUE);
#endif /* BCMSDIOH_STD */
#if defined(SUPPORT_P2P_GO_PS)
		wake_up(&bus->bus_sleep);
#endif /* LINUX && SUPPORT_P2P_GO_PS */
	} else {
		/* Waking up: bus power up is ok, set local state */

		if (!SLPAUTO_ENAB(bus)) {
			bcmsdh_cfg_write(sdh, SDIO_FUNC_1, SBSDIO_FUNC1_CHIPCLKCSR, 0, &err);

			/* Force pad isolation off if possible (in case power never toggled) */
			bcmsdh_cfg_write(sdh, SDIO_FUNC_1, SBSDIO_DEVICE_CTL, 0, NULL);

			/* Make sure the controller has the bus up */
			dhdsdio_clkctl(bus, CLK_AVAIL, FALSE);

			/* Send misc interrupt to indicate OOB not needed */
			W_SDREG(0, &regs->tosbmailboxdata, retries);
			if (retries <= retry_limit)
				W_SDREG(SMB_DEV_INT, &regs->tosbmailbox, retries);

			if (retries > retry_limit)
				DHD_ERROR(("CANNOT SIGNAL CHIP TO CLEAR OOB!!\n"));

			/* Make sure we have SD bus access */
			dhdsdio_clkctl(bus, CLK_SDONLY, FALSE);

			/* Enable interrupts again */
			if (bus->intr && (bus->dhd->busstate == DHD_BUS_DATA)) {
				bus->intdis = FALSE;
				bcmsdh_intr_enable(bus->sdh);
			}
		} else {
			err = dhdsdio_clk_devsleep_iovar(bus, FALSE /* wake */);
#ifdef FORCE_SWOOB_ENABLE
			/* Send misc interrupt to indicate OOB not needed */
			W_SDREG(0, &regs->tosbmailboxdata, retries);
			if (retries <= retry_limit)
				W_SDREG(SMB_DEV_INT, &regs->tosbmailbox, retries);
#endif
#ifdef BT_OVER_SDIO
			if (err < 0) {
				struct net_device *net = NULL;
				dhd_pub_t *dhd = bus->dhd;
				net = dhd_idx2net(dhd, 0);
				if (net != NULL) {
					DHD_ERROR(("<< WIFI HANG by KSO Enabled failure\n"));
					dhd_os_sdunlock(dhd);
					net_os_send_hang_message(net);
					dhd_os_sdlock(dhd);
				} else {
					DHD_ERROR(("<< WIFI HANG Fail because net is NULL\n"));
				}
			}
#endif /* BT_OVER_SDIO */
		}

		if (err == 0) {
			/* Change state */
			bus->sleeping = FALSE;
#if defined(BCMSDIOH_STD)
			sd3_tuning_disable = FALSE;
			err = bcmsdh_iovar_op(bus->sdh, "sd3_tuning_disable", NULL, 0,
				&sd3_tuning_disable, sizeof(sd3_tuning_disable), TRUE);
#endif /* BCMSDIOH_STD */
		}
	}

	return err;
}

#ifdef BT_OVER_SDIO
/*
 * Call this function to Get the Clock running.
 * Assumes that the caller holds the sdlock.
 * bus - Pointer to the dhd_bus handle
 * can_wait - TRUE if the caller can wait until the clock becomes ready
 *            FALSE if the caller cannot wait
 */
int __dhdsdio_clk_enable(struct dhd_bus *bus, bus_owner_t owner, int can_wait)
{
	int ret = BCME_ERROR;

	BCM_REFERENCE(owner);

	bus->bt_use_count++;

	/*
	 * We can call BUS_WAKE, clkctl multiple times, both of the items
	 * have states and if its already ON, no new configuration is done
	 */

	/* Wake up the Dongle FW from SR */
	BUS_WAKE(bus);

	/*
	 * Make sure back plane ht clk is on
	 * CLK_AVAIL - Turn On both SD & HT clock
	 */
	ret = dhdsdio_clkctl(bus, CLK_AVAIL, can_wait);

	DHD_INFO(("%s():bt_use_count %d \r\n", __FUNCTION__,
		bus->bt_use_count));
	return ret;
}

/*
 * Call this function to relinquish the Clock.
 * Assumes that the caller holds the sdlock.
 * bus - Pointer to the dhd_bus handle
 * can_wait - TRUE if the caller can wait until the clock becomes ready
 *            FALSE if the caller cannot wait
 */
int __dhdsdio_clk_disable(struct dhd_bus *bus, bus_owner_t owner, int can_wait)
{
	int ret = BCME_ERROR;

	BCM_REFERENCE(owner);
	BCM_REFERENCE(can_wait);

	if (bus->bt_use_count == 0) {
		DHD_ERROR(("%s(): Clocks are already turned off \r\n",
			__FUNCTION__));
		return ret;
	}

	bus->bt_use_count--;

	/*
	 * When the SDIO Bus is shared between BT & WLAN, we turn Off the clock
	 * once the last user has relinqushed the same. But there are two schemes
	 * in that too. We consider WLAN as the  bus master (even if its not
	 * active). Even when the WLAN is OFF the DHD Watchdog is active.
	 * So this Bus Watchdog is the context whill put the Bus to sleep.
	 * Refer dhd_bus_watchdog function
	 */

	ret = BCME_OK;
	DHD_INFO(("%s():bt_use_count %d \r\n", __FUNCTION__,
		bus->bt_use_count));
	return ret;
}

void dhdsdio_reset_bt_use_count(struct dhd_bus *bus)
{
	/* reset bt use count */
	bus->bt_use_count = 0;
}
#endif /* BT_OVER_SDIO */

#ifdef USE_DYNAMIC_F2_BLKSIZE
int dhdsdio_func_blocksize(dhd_pub_t *dhd, int function_num, int block_size)
{
	int func_blk_size = function_num;
	int bcmerr = 0;
	int result;

	bcmerr = dhd_bus_iovar_op(dhd, "sd_blocksize", &func_blk_size,
		sizeof(int), &result, sizeof(int), IOV_GET);

	if (bcmerr != BCME_OK) {
		DHD_ERROR(("%s: Get F%d Block size error\n", __FUNCTION__, function_num));
		return BCME_ERROR;
	}

	if (result != block_size) {
		DHD_ERROR(("%s: F%d Block size set from %d to %d\n",
			__FUNCTION__, function_num, result, block_size));
		func_blk_size = function_num << 16 | block_size;
		bcmerr = dhd_bus_iovar_op(dhd, "sd_blocksize", NULL,
			0, &func_blk_size, sizeof(int32), IOV_SET);
		if (bcmerr != BCME_OK) {
			DHD_ERROR(("%s: Set F%d Block size error\n", __FUNCTION__, function_num));
			return BCME_ERROR;
		}
	}

	return BCME_OK;
}
#endif /* USE_DYNAMIC_F2_BLKSIZE */

#if defined(OOB_INTR_ONLY) || defined(BCMSPI_ANDROID) || defined(FORCE_WOWLAN)
void
dhd_enable_oob_intr(struct dhd_bus *bus, bool enable)
{
#if defined(BCMSPI_ANDROID)
	bcmsdh_intr_enable(bus->sdh);
#elif defined(HW_OOB) || defined(FORCE_WOWLAN)
	bcmsdh_enable_hw_oob_intr(bus->sdh, enable);
#else
	sdpcmd_regs_t *regs = bus->regs;
	uint retries = 0;

	dhdsdio_clkctl(bus, CLK_AVAIL, FALSE);
	if (enable == TRUE) {

		/* Tell device to start using OOB wakeup */
		W_SDREG(SMB_USE_OOB, &regs->tosbmailbox, retries);
		if (retries > retry_limit)
			DHD_ERROR(("CANNOT SIGNAL CHIP, WILL NOT WAKE UP!!\n"));

	} else {
		/* Send misc interrupt to indicate OOB not needed */
		W_SDREG(0, &regs->tosbmailboxdata, retries);
		if (retries <= retry_limit)
			W_SDREG(SMB_DEV_INT, &regs->tosbmailbox, retries);
	}

	/* Turn off our contribution to the HT clock request */
	dhdsdio_clkctl(bus, CLK_SDONLY, FALSE);
#endif /* !defined(HW_OOB) */
}
#endif /* defined(OOB_INTR_ONLY) || defined(BCMSPI_ANDROID) */

int
dhd_bus_txdata(struct dhd_bus *bus, void *pkt)
{
	int ret = BCME_ERROR;
	osl_t *osh;
	uint datalen, prec;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	osh = bus->dhd->osh;
	datalen = PKTLEN(osh, pkt);

#ifdef SDTEST
	/* Push the test header if doing loopback */
	if (bus->ext_loop) {
		uint8* data;
		PKTPUSH(osh, pkt, SDPCM_TEST_HDRLEN);
		data = PKTDATA(osh, pkt);
		*data++ = SDPCM_TEST_ECHOREQ;
		*data++ = (uint8)bus->loopid++;
		*data++ = (datalen >> 0);
		*data++ = (datalen >> 8);
		datalen += SDPCM_TEST_HDRLEN;
	}
#else /* SDTEST */
	BCM_REFERENCE(datalen);
#endif /* SDTEST */

#ifdef DHD_ULP
	dhd_ulp_set_path(bus->dhd, DHD_ULP_TX_DATA);
#endif /* DHD_ULP */

	prec = PRIO2PREC((PKTPRIO(pkt) & PRIOMASK));

	/* move from dhdsdio_sendfromq(), try to orphan skb early */
	if (bus->dhd->conf->orphan_move == 1)
		PKTORPHAN(pkt, bus->dhd->conf->tsq);

	/* Check for existing queue, current flow-control, pending event, or pending clock */
	if (dhd_deferred_tx || bus->fcstate || pktq_n_pkts_tot(&bus->txq) || bus->dpc_sched ||
	    (!DATAOK(bus)) || (bus->flowcontrol & NBITVAL(prec)) ||
	    (bus->clkstate != CLK_AVAIL)) {
		bool deq_ret;
		int pkq_len = 0;

		DHD_TRACE(("%s: deferring pktq len %d\n", __FUNCTION__,
			pktq_n_pkts_tot(&bus->txq)));
		bus->fcqueued++;

		/* Priority based enq */
		dhd_os_sdlock_txq(bus->dhd);
		deq_ret = dhd_prec_enq(bus->dhd, &bus->txq, pkt, prec);
		dhd_os_sdunlock_txq(bus->dhd);

		if (!deq_ret) {
#ifdef PROP_TXSTATUS
			if (DHD_PKTTAG_WLFCPKT(PKTTAG(pkt)) == 0)
#endif /* PROP_TXSTATUS */
			{
#ifdef DHDTCPACK_SUPPRESS
				if (dhd_tcpack_check_xmit(bus->dhd, pkt) == BCME_ERROR) {
					DHD_ERROR(("%s %d: tcpack_suppress ERROR!!! Stop using\n",
						__FUNCTION__, __LINE__));
					dhd_tcpack_suppress_set(bus->dhd, TCPACK_SUP_OFF);
				}
#endif /* DHDTCPACK_SUPPRESS */
				dhd_txcomplete(bus->dhd, pkt, FALSE);
				PKTFREE(osh, pkt, TRUE);
			}
			ret = BCME_NORESOURCE;
		} else
			ret = BCME_OK;

		if (dhd_doflow) {
			dhd_os_sdlock_txq(bus->dhd);
			pkq_len = pktq_n_pkts_tot(&bus->txq);
			dhd_os_sdunlock_txq(bus->dhd);
		}
		if (dhd_doflow && pkq_len >= FCHI) {
			bool wlfc_enabled = FALSE;
#ifdef PROP_TXSTATUS
			wlfc_enabled = (dhd_wlfc_flowcontrol(bus->dhd, ON, FALSE) !=
				WLFC_UNSUPPORTED);
#endif // endif
			if (!wlfc_enabled && dhd_doflow) {
				dhd_txflowcontrol(bus->dhd, ALL_INTERFACES, ON);
			}
		}

#ifdef DHD_DEBUG
		dhd_os_sdlock_txq(bus->dhd);
		if (pktqprec_n_pkts(&bus->txq, prec) > qcount[prec])
			qcount[prec] = pktqprec_n_pkts(&bus->txq, prec);
		dhd_os_sdunlock_txq(bus->dhd);
#endif // endif

		/* Schedule DPC if needed to send queued packet(s) */
		if (dhd_deferred_tx && !bus->dpc_sched) {
			if (bus->dhd->conf->deferred_tx_len) {
				if(dhd_os_wd_timer_enabled(bus->dhd) == FALSE) {
					bus->dpc_sched = TRUE;
					dhd_sched_dpc(bus->dhd);
				}
				if(pktq_n_pkts_tot(&bus->txq) >= bus->dhd->conf->deferred_tx_len &&
						dhd_os_wd_timer_enabled(bus->dhd) == FALSE) {
					bus->dpc_sched = TRUE;
					dhd_sched_dpc(bus->dhd);
				}
			} else {
				bus->dpc_sched = TRUE;
				dhd_sched_dpc(bus->dhd);
			}
		}
	} else {
		int chan = SDPCM_DATA_CHANNEL;

#ifdef SDTEST
		chan = (bus->ext_loop ? SDPCM_TEST_CHANNEL : SDPCM_DATA_CHANNEL);
#endif // endif
		/* Lock: we're about to use shared data/code (and SDIO) */
		dhd_os_sdlock(bus->dhd);

		/* Otherwise, send it now */
		BUS_WAKE(bus);
		/* Make sure back plane ht clk is on, no pending allowed */
		dhdsdio_clkctl(bus, CLK_AVAIL, TRUE);

		ret = dhdsdio_txpkt(bus, chan, &pkt, 1, TRUE);

		if (ret != BCME_OK)
			bus->dhd->tx_errors++;
		else
			bus->dhd->dstats.tx_bytes += datalen;

		if ((bus->idletime == DHD_IDLE_IMMEDIATE) && !bus->dpc_sched &&
				NO_OTHER_ACTIVE_BUS_USER(bus)) {
			bus->activity = FALSE;
			dhdsdio_bussleep(bus, TRUE);
			dhdsdio_clkctl(bus, CLK_NONE, FALSE);
		}

		dhd_os_sdunlock(bus->dhd);
	}

	return ret;
}

/* align packet data pointer and packet length to n-byte boundary, process packet headers,
 * a new packet may be allocated if there is not enough head and/or tail from for padding.
 * the caller is responsible for updating the glom size in the head packet (when glom is
 * used)
 *
 * pad_pkt_len: returns the length of extra padding needed from the padding packet, this parameter
 * is taken in tx glom mode only
 *
 * new_pkt: out, pointer of the new packet allocated due to insufficient head room for alignment
 * padding, NULL if not needed, the caller is responsible for freeing the new packet
 *
 * return: positive value - length of the packet, including head and tail padding
 *		   negative value - errors
 */
static int dhdsdio_txpkt_preprocess(dhd_bus_t *bus, void *pkt, int chan, int txseq,
	int prev_chain_total_len, bool last_chained_pkt,
	int *pad_pkt_len, void **new_pkt
#if defined(BCMSDIOH_TXGLOM_EXT)
	, int first_frame
#endif
)
{
	osl_t *osh;
	uint8 *frame;
	int pkt_len;
	int modulo;
	int head_padding;
	int tail_padding = 0;
	uint32 swheader;
	uint32 swhdr_offset;
	bool alloc_new_pkt = FALSE;
	uint8 sdpcm_hdrlen = bus->txglom_enable ? SDPCM_HDRLEN_TXGLOM : SDPCM_HDRLEN;
#ifdef PKT_STATICS
	uint16 len;
#endif

	*new_pkt = NULL;
	osh = bus->dhd->osh;

#ifdef DHDTCPACK_SUPPRESS
	if (dhd_tcpack_check_xmit(bus->dhd, pkt) == BCME_ERROR) {
		DHD_ERROR(("%s %d: tcpack_suppress ERROR!!! Stop using it\n",
			__FUNCTION__, __LINE__));
		dhd_tcpack_suppress_set(bus->dhd, TCPACK_SUP_OFF);
	}
#endif /* DHDTCPACK_SUPPRESS */

	/* Add space for the SDPCM hardware/software headers */
	PKTPUSH(osh, pkt, sdpcm_hdrlen);
	ASSERT(ISALIGNED((uintptr)PKTDATA(osh, pkt), 2));

	frame = (uint8*)PKTDATA(osh, pkt);
	pkt_len = (uint16)PKTLEN(osh, pkt);

#ifdef PKT_STATICS
	len = (uint16)PKTLEN(osh, pkt);
	switch(chan) {
		case SDPCM_CONTROL_CHANNEL:
			bus->tx_statics.ctrl_count++;
			bus->tx_statics.ctrl_size += len;
			break;
		case SDPCM_DATA_CHANNEL:
			bus->tx_statics.data_count++;
			bus->tx_statics.data_size += len;
			break;
		case SDPCM_GLOM_CHANNEL:
			bus->tx_statics.glom_count++;
			bus->tx_statics.glom_size += len;
			break;
		case SDPCM_EVENT_CHANNEL:
			bus->tx_statics.event_count++;
			bus->tx_statics.event_size += len;
			break;
		case SDPCM_TEST_CHANNEL:
			bus->tx_statics.test_count++;
			bus->tx_statics.test_size += len;
			break;

		default:
			break;
	}
#endif /* PKT_STATICS */
#ifdef DHD_DEBUG
	if (PKTPRIO(pkt) < ARRAYSIZE(tx_packets))
		tx_packets[PKTPRIO(pkt)]++;
#endif /* DHD_DEBUG */

	/* align the data pointer, allocate a new packet if there is not enough space (new
	 * packet data pointer will be aligned thus no padding will be needed)
	 */
	head_padding = (uintptr)frame % DHD_SDALIGN;
	if (PKTHEADROOM(osh, pkt) < head_padding) {
		head_padding = 0;
		alloc_new_pkt = TRUE;
	} else {
		uint cur_chain_total_len;
		int chain_tail_padding = 0;

		/* All packets need to be aligned by DHD_SDALIGN */
		modulo = (pkt_len + head_padding) % DHD_SDALIGN;
		tail_padding = modulo > 0 ? (DHD_SDALIGN - modulo) : 0;

		/* Total pkt chain length needs to be aligned by block size,
		 * unless it is a single pkt chain with total length less than one block size,
		 * which we prefer sending by byte mode.
		 *
		 * Do the chain alignment here if
		 * 1. This is the last pkt of the chain of multiple pkts or a single pkt.
		 * 2-1. This chain is of multiple pkts, or
		 * 2-2. This is a single pkt whose size is longer than one block size.
		 */
		cur_chain_total_len = prev_chain_total_len +
			(head_padding + pkt_len + tail_padding);
		if (last_chained_pkt && bus->blocksize != 0 &&
			(cur_chain_total_len > (int)bus->blocksize || prev_chain_total_len > 0)) {
			modulo = cur_chain_total_len % bus->blocksize;
			chain_tail_padding = modulo > 0 ? (bus->blocksize - modulo) : 0;
		}

#ifdef DHDENABLE_TAILPAD
		if (PKTTAILROOM(osh, pkt) < tail_padding) {
			/* We don't have tail room to align by DHD_SDALIGN */
			alloc_new_pkt = TRUE;
			bus->tx_tailpad_pktget++;
		} else if (PKTTAILROOM(osh, pkt) < tail_padding + chain_tail_padding) {
			/* We have tail room for tail_padding of this pkt itself, but not for
			 * total pkt chain alignment by block size.
			 * Use the padding packet to avoid memory copy if applicable,
			 * otherwise, just allocate a new pkt.
			 */
			if (bus->pad_pkt) {
				*pad_pkt_len = chain_tail_padding;
				bus->tx_tailpad_chain++;
			} else {
				alloc_new_pkt = TRUE;
				bus->tx_tailpad_pktget++;
			}
		} else
		/* This last pkt's tailroom is sufficient to hold both tail_padding
		 * of the pkt itself and chain_tail_padding of total pkt chain
		 */
#endif /* DHDENABLE_TAILPAD */
		tail_padding += chain_tail_padding;
	}

	DHD_INFO(("%s sdhdr len + orig_pkt_len %d h_pad %d t_pad %d pad_pkt_len %d\n",
		__FUNCTION__, pkt_len, head_padding, tail_padding, *pad_pkt_len));

	if (alloc_new_pkt) {
		void *tmp_pkt;
		int newpkt_size;
		int cur_total_len;

		ASSERT(*pad_pkt_len == 0);

		DHD_INFO(("%s allocating new packet for padding\n", __FUNCTION__));

		/* head pointer is aligned now, no padding needed */
		head_padding = 0;

		/* update the tail padding as it depends on the head padding, since a new packet is
		 * allocated, the head padding is non longer needed and packet length is chagned
		 */

		cur_total_len = prev_chain_total_len + pkt_len;
		if (last_chained_pkt && bus->blocksize != 0 &&
			(cur_total_len > (int)bus->blocksize || prev_chain_total_len > 0)) {
			modulo = cur_total_len % bus->blocksize;
			tail_padding = modulo > 0 ? (bus->blocksize - modulo) : 0;
		} else {
			modulo = pkt_len % DHD_SDALIGN;
			tail_padding = modulo > 0 ? (DHD_SDALIGN - modulo) : 0;
		}

		newpkt_size = PKTLEN(osh, pkt) + bus->blocksize + DHD_SDALIGN;
		bus->dhd->tx_realloc++;
		tmp_pkt = PKTGET(osh, newpkt_size, TRUE);
		if (tmp_pkt == NULL) {
			DHD_ERROR(("failed to alloc new %d byte packet\n", newpkt_size));
			return BCME_NOMEM;
		}
		PKTALIGN(osh, tmp_pkt, PKTLEN(osh, pkt), DHD_SDALIGN);
		bcopy(PKTDATA(osh, pkt), PKTDATA(osh, tmp_pkt), PKTLEN(osh, pkt));
		*new_pkt = tmp_pkt;
		pkt = tmp_pkt;
	}

	if (head_padding)
		PKTPUSH(osh, pkt, head_padding);

	frame = (uint8*)PKTDATA(osh, pkt);
	bzero(frame, head_padding + sdpcm_hdrlen);
	pkt_len = (uint16)PKTLEN(osh, pkt);

	/* the header has the followming format
	 * 4-byte HW frame tag: length, ~length (for glom this is the total length)
	 *
	 * 8-byte HW extesion flags (glom mode only) as the following:
	 *			2-byte packet length, excluding HW tag and padding
	 *			2-byte frame channel and frame flags (e.g. next frame following)
	 *			2-byte header length
	 *			2-byte tail padding size
	 *
	 * 8-byte SW frame tags as the following
	 *			4-byte flags: host tx seq, channel, data offset
	 *			4-byte flags: TBD
	 */

	swhdr_offset = SDPCM_FRAMETAG_LEN;

	/* hardware frame tag:
	 *
	 * in tx-glom mode, dongle only checks the hardware frame tag in the first
	 * packet and sees it as the total lenght of the glom (including tail padding),
	 * for each packet in the glom, the packet length needs to be updated, (see
	 * below PKTSETLEN)
	 *
	 * in non tx-glom mode, PKTLEN still need to include tail padding as to be
	 * referred to in sdioh_request_buffer(). The tail length will be excluded in
	 * dhdsdio_txpkt_postprocess().
	 */
#if defined(BCMSDIOH_TXGLOM_EXT)
	if (bus->dhd->conf->txglom_bucket_size)
		tail_padding = 0;
#endif
	*(uint16*)frame = (uint16)htol16(pkt_len);
	*(((uint16*)frame) + 1) = (uint16)htol16(~pkt_len);
	pkt_len += tail_padding;

	/* hardware extesion flags */
	if (bus->txglom_enable) {
		uint32 hwheader1;
		uint32 hwheader2;
#ifdef BCMSDIOH_TXGLOM_EXT
		uint32 act_len = pkt_len - tail_padding;
		uint32 real_pad = 0;
		if(bus->dhd->conf->txglom_ext && !last_chained_pkt) {
			tail_padding = 0;
			if(first_frame == 0) {
				// first pkt, add pad to bucket size - recv offset
				pkt_len = bus->dhd->conf->txglom_bucket_size - TXGLOM_RECV_OFFSET;
			} else {
				// add pad to bucket size
				pkt_len = bus->dhd->conf->txglom_bucket_size;
			}
			swhdr_offset += SDPCM_HWEXT_LEN;
			hwheader1 = (act_len - SDPCM_FRAMETAG_LEN) | (last_chained_pkt << 24);
			hwheader2 = (pkt_len - act_len) << 16;
			htol32_ua_store(hwheader1, frame + SDPCM_FRAMETAG_LEN);
			htol32_ua_store(hwheader2, frame + SDPCM_FRAMETAG_LEN + 4);
			real_pad = pkt_len - act_len;

			if (PKTTAILROOM(osh, pkt) < real_pad) {
				DHD_INFO(("%s : insufficient tailroom %d for %d real_pad\n", 
					__func__, (int)PKTTAILROOM(osh, pkt), real_pad));
				if (PKTPADTAILROOM(osh, pkt, real_pad)) {
					DHD_ERROR(("CHK1: padding error size %d\n", real_pad));
				} else
					frame = (uint8 *)PKTDATA(osh, pkt);
			}
		} else 
#endif
		{
			swhdr_offset += SDPCM_HWEXT_LEN;
			hwheader1 = (pkt_len - SDPCM_FRAMETAG_LEN - tail_padding) |
				(last_chained_pkt << 24);
			hwheader2 = (tail_padding) << 16;
			htol32_ua_store(hwheader1, frame + SDPCM_FRAMETAG_LEN);
			htol32_ua_store(hwheader2, frame + SDPCM_FRAMETAG_LEN + 4);
		}
	}
	PKTSETLEN((osh), (pkt), (pkt_len));

	/* software frame tags */
	swheader = ((chan << SDPCM_CHANNEL_SHIFT) & SDPCM_CHANNEL_MASK)
		| (txseq % SDPCM_SEQUENCE_WRAP) |
		(((head_padding + sdpcm_hdrlen) << SDPCM_DOFFSET_SHIFT) & SDPCM_DOFFSET_MASK);
	htol32_ua_store(swheader, frame + swhdr_offset);
	htol32_ua_store(0, frame + swhdr_offset + sizeof(swheader));

	return pkt_len;
}

static int dhdsdio_txpkt_postprocess(dhd_bus_t *bus, void *pkt)
{
	osl_t *osh;
	uint8 *frame;
	int data_offset;
	int tail_padding;
	int swhdr_offset = SDPCM_FRAMETAG_LEN + (bus->txglom_enable ? SDPCM_HWEXT_LEN : 0);

	(void)osh;
	osh = bus->dhd->osh;

	/* restore pkt buffer pointer, but keeps the header pushed by dhd_prot_hdrpush */
	frame = (uint8*)PKTDATA(osh, pkt);

	DHD_INFO(("%s PKTLEN before postprocess %d",
		__FUNCTION__, PKTLEN(osh, pkt)));

	/* PKTLEN still includes tail_padding, so exclude it.
	 * We shall have head_padding + original pkt_len for PKTLEN afterwards.
	 */
	if (bus->txglom_enable) {
		/* txglom pkts have tail_padding length in HW ext header */
		tail_padding = ltoh32_ua(frame + SDPCM_FRAMETAG_LEN + 4) >> 16;
		PKTSETLEN(osh, pkt, PKTLEN(osh, pkt) - tail_padding);
		DHD_INFO((" txglom pkt: tail_padding %d PKTLEN %d\n",
			tail_padding, PKTLEN(osh, pkt)));
	} else {
		/* non-txglom pkts have head_padding + original pkt length in HW frame tag.
		 * We cannot refer to this field for txglom pkts as the first pkt of the chain will
		 * have the field for the total length of the chain.
		 */
		PKTSETLEN(osh, pkt, *(uint16*)frame);
		DHD_INFO((" non-txglom pkt: HW frame tag len %d after PKTLEN %d\n",
			*(uint16*)frame, PKTLEN(osh, pkt)));
	}

	data_offset = ltoh32_ua(frame + swhdr_offset);
	data_offset = (data_offset & SDPCM_DOFFSET_MASK) >> SDPCM_DOFFSET_SHIFT;
	/* Get rid of sdpcm header + head_padding */
	PKTPULL(osh, pkt, data_offset);

	DHD_INFO(("%s data_offset %d, PKTLEN %d\n",
		__FUNCTION__, data_offset, PKTLEN(osh, pkt)));

	return BCME_OK;
}

static int dhdsdio_txpkt(dhd_bus_t *bus, uint chan, void** pkts, int num_pkt, bool free_pkt)
{
	int i;
	int ret = 0;
	osl_t *osh;
	bcmsdh_info_t *sdh;
	void *pkt = NULL;
	void *pkt_chain;
	int total_len = 0;
	void *head_pkt = NULL;
	void *prev_pkt = NULL;
	int pad_pkt_len = 0;
	int new_pkt_num = 0;
	void *new_pkts[MAX_TX_PKTCHAIN_CNT];
	bool wlfc_enabled = FALSE;

	if (bus->dhd->dongle_reset)
		return BCME_NOTREADY;

	if (num_pkt <= 0)
		return BCME_BADARG;

	sdh = bus->sdh;
	osh = bus->dhd->osh;
	/* init new_pkts[0] to make some compiler happy, not necessary as we check new_pkt_num */
	new_pkts[0] = NULL;

	for (i = 0; i < num_pkt; i++) {
		int pkt_len;
		bool last_pkt;
		void *new_pkt = NULL;

		pkt = pkts[i];
		ASSERT(pkt);
		last_pkt = (i == num_pkt - 1);
		pkt_len = dhdsdio_txpkt_preprocess(bus, pkt, chan, bus->tx_seq + i,
			total_len, last_pkt, &pad_pkt_len, &new_pkt
#if defined(BCMSDIOH_TXGLOM_EXT)
			, i
#endif
		);
		if (pkt_len <= 0)
			goto done;
		if (new_pkt) {
			pkt = new_pkt;
			new_pkts[new_pkt_num++] = new_pkt;
		}
		total_len += pkt_len;

		PKTSETNEXT(osh, pkt, NULL);
		/* insert the packet into the list */
		head_pkt ? PKTSETNEXT(osh, prev_pkt, pkt) : (head_pkt = pkt);
		prev_pkt = pkt;

	}

	/* Update the HW frame tag (total length) in the first pkt of the glom */
	if (bus->txglom_enable) {
		uint8 *frame;

		total_len += pad_pkt_len;
		frame = (uint8*)PKTDATA(osh, head_pkt);
		*(uint16*)frame = (uint16)htol16(total_len);
		*(((uint16*)frame) + 1) = (uint16)htol16(~total_len);

	}

#ifdef DHDENABLE_TAILPAD
	/* if a padding packet if needed, insert it to the end of the link list */
	if (pad_pkt_len) {
		PKTSETLEN(osh, bus->pad_pkt, pad_pkt_len);
		PKTSETNEXT(osh, pkt, bus->pad_pkt);
	}
#endif /* DHDENABLE_TAILPAD */

	/* dhd_bcmsdh_send_buf ignores the buffer pointer if he packet
	 * parameter is not NULL, for non packet chian we pass NULL pkt pointer
	 * so it will take the aligned length and buffer pointer.
	 */
	pkt_chain = PKTNEXT(osh, head_pkt) ? head_pkt : NULL;
#ifdef TPUT_MONITOR
	if ((bus->dhd->conf->data_drop_mode == TXPKT_DROP) && (total_len > 500))
		ret = BCME_OK;
	else
#endif
	ret = dhd_bcmsdh_send_buf(bus, bcmsdh_cur_sbwad(sdh), SDIO_FUNC_2, F2SYNC,
		PKTDATA(osh, head_pkt), total_len, pkt_chain, NULL, NULL, TXRETRIES);
	if (ret == BCME_OK)
		bus->tx_seq = (bus->tx_seq + num_pkt) % SDPCM_SEQUENCE_WRAP;

	/* if a padding packet was needed, remove it from the link list as it not a data pkt */
	if (pad_pkt_len && pkt)
		PKTSETNEXT(osh, pkt, NULL);

done:
	pkt = head_pkt;
	while (pkt) {
		void *pkt_next = PKTNEXT(osh, pkt);
		PKTSETNEXT(osh, pkt, NULL);
		dhdsdio_txpkt_postprocess(bus, pkt);
		pkt = pkt_next;
	}

	/* new packets might be allocated due to insufficient room for padding, but we
	 * still have to indicate the original packets to upper layer
	 */
	for (i = 0; i < num_pkt; i++) {
		pkt = pkts[i];
		wlfc_enabled = FALSE;
#ifdef PROP_TXSTATUS
		if (DHD_PKTTAG_WLFCPKT(PKTTAG(pkt))) {
			wlfc_enabled = (dhd_wlfc_txcomplete(bus->dhd, pkt, ret == 0) !=
				WLFC_UNSUPPORTED);
		}
#endif /* PROP_TXSTATUS */
		if (!wlfc_enabled) {
			PKTSETNEXT(osh, pkt, NULL);
			dhd_txcomplete(bus->dhd, pkt, ret != 0);
			if (free_pkt)
				PKTFREE(osh, pkt, TRUE);
		}
	}

	for (i = 0; i < new_pkt_num; i++)
		PKTFREE(osh, new_pkts[i], TRUE);

	return ret;
}

static uint
dhdsdio_sendfromq(dhd_bus_t *bus, uint maxframes)
{
	uint cnt = 0;
	uint8 tx_prec_map;
	uint16 txpktqlen = 0;
	uint32 intstatus = 0;
	uint retries = 0;
	osl_t *osh;
	dhd_pub_t *dhd = bus->dhd;
	sdpcmd_regs_t *regs = bus->regs;
#if defined(DHD_LOSSLESS_ROAMING) || defined(DHD_PKTDUMP_TOFW)
	uint8 *pktdata;
	struct ether_header *eh;
#ifdef BDC
	struct bdc_header *bdc_header;
	uint8 data_offset;
#endif // endif
#endif /* DHD_LOSSLESS_ROAMING */

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (!KSO_ENAB(bus)) {
		DHD_ERROR(("%s: Device asleep\n", __FUNCTION__));
		return BCME_NODEVICE;
	}

	osh = dhd->osh;
	tx_prec_map = ~bus->flowcontrol;
#ifdef DHD_LOSSLESS_ROAMING
	tx_prec_map &= dhd->dequeue_prec_map;
#endif /* DHD_LOSSLESS_ROAMING */
	for (cnt = 0; (cnt < maxframes) && DATAOK(bus);) {
		int i;
		int num_pkt = 1;
		void *pkts[MAX_TX_PKTCHAIN_CNT];
		int prec_out;
		uint datalen = 0;

		dhd_os_sdlock_txq(bus->dhd);
		if (bus->txglom_enable) {
			uint32 glomlimit = (uint32)bus->txglomsize;
#if defined(BCMSDIOH_STD)
			if (bus->blocksize == 64) {
				glomlimit = MIN((uint32)bus->txglomsize, BLK_64_MAXTXGLOM);
			}
#endif /* BCMSDIOH_STD */
			num_pkt = MIN((uint32)DATABUFCNT(bus), glomlimit);
			num_pkt = MIN(num_pkt, ARRAYSIZE(pkts));
		}
		num_pkt = MIN(num_pkt, pktq_mlen(&bus->txq, tx_prec_map));
		for (i = 0; i < num_pkt; i++) {
			pkts[i] = pktq_mdeq(&bus->txq, tx_prec_map, &prec_out);
			if (!pkts[i]) {
				DHD_ERROR(("%s: pktq_mlen non-zero when no pkt\n",
					__FUNCTION__));
				ASSERT(0);
				break;
			}
#if defined(DHD_LOSSLESS_ROAMING) || defined(DHD_PKTDUMP_TOFW)
			pktdata = (uint8 *)PKTDATA(osh, pkts[i]);
#ifdef BDC
			/* Skip BDC header */
			bdc_header = (struct bdc_header *)pktdata;
			data_offset = bdc_header->dataOffset;
			pktdata += BDC_HEADER_LEN + (data_offset << 2);
#endif // endif
			eh = (struct ether_header *)pktdata;
#ifdef DHD_LOSSLESS_ROAMING
			if (eh->ether_type == hton16(ETHER_TYPE_802_1X)) {
				uint8 prio = (uint8)PKTPRIO(pkts[i]);

				/* Restore to original priority for 802.1X packet */
				if (prio == PRIO_8021D_NC) {
					PKTSETPRIO(pkts[i], dhd->prio_8021x);
#ifdef BDC
					/* Restore to original priority in BDC header */
					bdc_header->priority =
						(dhd->prio_8021x & BDC_PRIORITY_MASK);
#endif // endif
				}
			}
#endif /* DHD_LOSSLESS_ROAMING */
#ifdef DHD_PKTDUMP_TOFW
			dhd_dump_pkt(bus->dhd, BDC_GET_IF_IDX(bdc_header), pktdata,
				(uint32)PKTLEN(bus->dhd->osh, pkts[i]), TRUE, NULL, NULL);
#endif
#endif /* DHD_LOSSLESS_ROAMING || DHD_8021X_DUMP */
			if (!bus->dhd->conf->orphan_move)
				PKTORPHAN(pkts[i], bus->dhd->conf->tsq);
			datalen += PKTLEN(osh, pkts[i]);
		}
		dhd_os_sdunlock_txq(bus->dhd);

		if (i == 0)
			break;
		if (dhdsdio_txpkt(bus, SDPCM_DATA_CHANNEL, pkts, i, TRUE) != BCME_OK)
			dhd->tx_errors++;
		else {
			dhd->dstats.tx_bytes += datalen;
			bus->txglomframes++;
			bus->txglompkts += num_pkt;
#ifdef PKT_STATICS
			bus->tx_statics.glom_cnt_us[num_pkt-1] =
				(bus->tx_statics.glom_cnt[num_pkt-1]*bus->tx_statics.glom_cnt_us[num_pkt-1]
				+ bcmsdh_get_spend_time(bus->sdh))/(bus->tx_statics.glom_cnt[num_pkt-1] + 1);
#endif
		}
		cnt += i;
#ifdef PKT_STATICS
		if (num_pkt) {
			bus->tx_statics.glom_cnt[num_pkt-1]++;
			if (num_pkt > bus->tx_statics.glom_max)
				bus->tx_statics.glom_max = num_pkt;
		}
#endif

		/* In poll mode, need to check for other events */
		if (!bus->intr && cnt)
		{
			/* Check device status, signal pending interrupt */
			R_SDREG(intstatus, &regs->intstatus, retries);
			bus->f2txdata++;
			if (bcmsdh_regfail(bus->sdh))
				break;
			if (intstatus & bus->hostintmask)
				bus->ipend = TRUE;
		}

	}

	if (dhd_doflow) {
		dhd_os_sdlock_txq(bus->dhd);
		txpktqlen = pktq_n_pkts_tot(&bus->txq);
		dhd_os_sdunlock_txq(bus->dhd);
	}

	/* Do flow-control if needed */
	if (dhd->up && (dhd->busstate == DHD_BUS_DATA) && (txpktqlen < FCLOW)) {
		bool wlfc_enabled = FALSE;
#ifdef PROP_TXSTATUS
		wlfc_enabled = (dhd_wlfc_flowcontrol(dhd, OFF, TRUE) != WLFC_UNSUPPORTED);
#endif // endif
		if (!wlfc_enabled && dhd_doflow && dhd->txoff) {
			dhd_txflowcontrol(dhd, ALL_INTERFACES, OFF);
		}
	}

	return cnt;
}

static void
dhdsdio_sendpendctl(dhd_bus_t *bus)
{
	bcmsdh_info_t *sdh = bus->sdh;
	int ret;
	uint8* frame_seq = bus->ctrl_frame_buf + SDPCM_FRAMETAG_LEN;

	if (bus->txglom_enable)
		frame_seq += SDPCM_HWEXT_LEN;

	if (*frame_seq != bus->tx_seq) {
		DHD_INFO(("%s IOCTL frame seq lag detected!"
			" frm_seq:%d != bus->tx_seq:%d, corrected\n",
			__FUNCTION__, *frame_seq, bus->tx_seq));
		*frame_seq = bus->tx_seq;
	}

	ret = dhd_bcmsdh_send_buf(bus, bcmsdh_cur_sbwad(sdh), SDIO_FUNC_2, F2SYNC,
		(uint8 *)bus->ctrl_frame_buf, (uint32)bus->ctrl_frame_len,
		NULL, NULL, NULL, 1);
	if (ret == BCME_OK)
		bus->tx_seq = (bus->tx_seq + 1) % SDPCM_SEQUENCE_WRAP;

	bus->ctrl_frame_stat = FALSE;
	dhd_wait_event_wakeup(bus->dhd);
}

int
dhd_bus_txctl(struct dhd_bus *bus, uchar *msg, uint msglen)
{
	static int err_nodevice = 0;
	uint8 *frame;
	uint16 len;
	uint32 swheader;
	uint8 doff = 0;
	int ret = -1;
	uint8 sdpcm_hdrlen = bus->txglom_enable ? SDPCM_HDRLEN_TXGLOM : SDPCM_HDRLEN;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (bus->dhd->dongle_reset)
		return -EIO;

	/* Back the pointer to make a room for bus header */
	frame = msg - sdpcm_hdrlen;
	len = (msglen += sdpcm_hdrlen);

	/* Add alignment padding (optional for ctl frames) */
	if (dhd_alignctl) {
		if ((doff = ((uintptr)frame % DHD_SDALIGN))) {
			frame -= doff;
			len += doff;
			msglen += doff;
			bzero(frame, doff + sdpcm_hdrlen);
		}
		ASSERT(doff < DHD_SDALIGN);
	}
	doff += sdpcm_hdrlen;

#ifndef BCMSPI
	/* Round send length to next SDIO block */
	if (bus->roundup && bus->blocksize && (len > bus->blocksize)) {
		uint16 pad = bus->blocksize - (len % bus->blocksize);
		if ((pad <= bus->roundup) && (pad < bus->blocksize))
			len += pad;
	} else if (len % DHD_SDALIGN) {
		len += DHD_SDALIGN - (len % DHD_SDALIGN);
	}
#endif /* BCMSPI */

	/* Satisfy length-alignment requirements */
	if (forcealign && (len & (ALIGNMENT - 1)))
		len = ROUNDUP(len, ALIGNMENT);

	ASSERT(ISALIGNED((uintptr)frame, 2));

	/* Need to lock here to protect txseq and SDIO tx calls */
	dhd_os_sdlock(bus->dhd);
	if (bus->dhd->conf->txctl_tmo_fix > 0 && !TXCTLOK(bus)) {
		bus->ctrl_wait = TRUE;
		dhd_os_sdunlock(bus->dhd);
		wait_event_interruptible_timeout(bus->ctrl_tx_wait, TXCTLOK(bus),
			msecs_to_jiffies(bus->dhd->conf->txctl_tmo_fix));
		dhd_os_sdlock(bus->dhd);
		bus->ctrl_wait = FALSE;
	}

	BUS_WAKE(bus);

	/* Make sure backplane clock is on */
	dhdsdio_clkctl(bus, CLK_AVAIL, FALSE);

	/* Hardware tag: 2 byte len followed by 2 byte ~len check (all LE) */
	*(uint16*)frame = htol16((uint16)msglen);
	*(((uint16*)frame) + 1) = htol16(~msglen);

	if (bus->txglom_enable) {
		uint32 hwheader1, hwheader2;
		/* Software tag: channel, sequence number, data offset */
		swheader = ((SDPCM_CONTROL_CHANNEL << SDPCM_CHANNEL_SHIFT) & SDPCM_CHANNEL_MASK)
				| bus->tx_seq
				| ((doff << SDPCM_DOFFSET_SHIFT) & SDPCM_DOFFSET_MASK);
		htol32_ua_store(swheader, frame + SDPCM_FRAMETAG_LEN + SDPCM_HWEXT_LEN);
		htol32_ua_store(0, frame + SDPCM_FRAMETAG_LEN
			+ SDPCM_HWEXT_LEN + sizeof(swheader));

		hwheader1 = (msglen - SDPCM_FRAMETAG_LEN) | (1 << 24);
		hwheader2 = (len - (msglen)) << 16;
		htol32_ua_store(hwheader1, frame + SDPCM_FRAMETAG_LEN);
		htol32_ua_store(hwheader2, frame + SDPCM_FRAMETAG_LEN + 4);

		*(uint16*)frame = htol16(len);
		*(((uint16*)frame) + 1) = htol16(~(len));
	} else {
		/* Software tag: channel, sequence number, data offset */
		swheader = ((SDPCM_CONTROL_CHANNEL << SDPCM_CHANNEL_SHIFT) & SDPCM_CHANNEL_MASK)
		        | bus->tx_seq | ((doff << SDPCM_DOFFSET_SHIFT) & SDPCM_DOFFSET_MASK);
		htol32_ua_store(swheader, frame + SDPCM_FRAMETAG_LEN);
		htol32_ua_store(0, frame + SDPCM_FRAMETAG_LEN + sizeof(swheader));
	}

#ifdef DHD_ULP
	dhd_ulp_set_path(bus->dhd, DHD_ULP_TX_CTRL);

	if (!TXCTLOK(bus) || !dhd_ulp_f2_ready(bus->dhd, bus->sdh))
#else
	if (!TXCTLOK(bus))
#endif // endif
	{
		DHD_INFO(("%s: No bus credit bus->tx_max %d, bus->tx_seq %d\n",
			__FUNCTION__, bus->tx_max, bus->tx_seq));
		bus->ctrl_frame_stat = TRUE;
		/* Send from dpc */
		bus->ctrl_frame_buf = frame;
		bus->ctrl_frame_len = len;

		if (!bus->dpc_sched) {
			bus->dpc_sched = TRUE;
			dhd_sched_dpc(bus->dhd);
		}
		if (bus->ctrl_frame_stat) {
			dhd_wait_for_event(bus->dhd, &bus->ctrl_frame_stat);
		}

		if (bus->ctrl_frame_stat == FALSE) {
			DHD_INFO(("%s: ctrl_frame_stat == FALSE\n", __FUNCTION__));
			ret = 0;
		} else {
			bus->dhd->txcnt_timeout++;
			if (!bus->dhd->hang_was_sent) {
				DHD_ERROR(("%s: ctrl_frame_stat == TRUE txcnt_timeout=%d\n",
					__FUNCTION__, bus->dhd->txcnt_timeout));
#ifdef BCMSDIO_RXLIM_POST
				DHD_ERROR(("%s: rxlim_en=%d, rxlim enable=%d, rxlim_addr=%d\n",
					__FUNCTION__,
					bus->dhd->conf->rxlim_en, bus->rxlim_en, bus->rxlim_addr));
#endif /* BCMSDIO_RXLIM_POST */
			}
#ifdef DHD_FW_COREDUMP
			/* Collect socram dump */
			if ((bus->dhd->memdump_enabled) &&
				(bus->dhd->txcnt_timeout >= MAX_CNTL_TX_TIMEOUT)) {
				/* collect core dump */
				bus->dhd->memdump_type = DUMP_TYPE_RESUMED_ON_TIMEOUT_TX;
				dhd_os_sdunlock(bus->dhd);
				dhd_bus_mem_dump(bus->dhd);
				dhd_os_sdlock(bus->dhd);
			}
#endif /* DHD_FW_COREDUMP */
			ret = -1;
			bus->ctrl_frame_stat = FALSE;
			goto done;
		}
	}
