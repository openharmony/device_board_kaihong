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
