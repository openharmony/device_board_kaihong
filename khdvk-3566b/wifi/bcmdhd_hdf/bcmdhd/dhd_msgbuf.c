/**
 * @file definition of host message ring functionality
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
 * $Id: dhd_msgbuf.c 825801 2019-06-17 10:51:10Z $
 */

#include <typedefs.h>
#include <osl.h>

#include <bcmutils.h>
#include <bcmmsgbuf.h>
#include <bcmendian.h>
#include <bcmstdlib_s.h>

#include <dngl_stats.h>
#include <dhd.h>
#include <dhd_proto.h>

#include <dhd_bus.h>

#include <dhd_dbg.h>
#include <siutils.h>
#include <dhd_debug.h>

#include <dhd_flowring.h>

#include <pcie_core.h>
#include <bcmpcie.h>
#include <dhd_pcie.h>
#include <dhd_config.h>

#if defined(DHD_LB)
#include <linux/cpu.h>
#include <bcm_ring.h>
#define DHD_LB_WORKQ_SZ			    (8192)
#define DHD_LB_WORKQ_SYNC           (16)
#define DHD_LB_WORK_SCHED           (DHD_LB_WORKQ_SYNC * 2)
#endif /* DHD_LB */

#include <etd.h>
#include <hnd_debug.h>
#include <bcmtlv.h>
#include <hnd_armtrap.h>
#include <dnglevent.h>

#ifdef DHD_EWPR_VER2
#include <dhd_bitpack.h>
#endif /* DHD_EWPR_VER2 */

extern char dhd_version[];
extern char fw_version[];

/**
 * Host configures a soft doorbell for d2h rings, by specifying a 32bit host
 * address where a value must be written. Host may also interrupt coalescing
 * on this soft doorbell.
 * Use Case: Hosts with network processors, may register with the dongle the
 * network processor's thread wakeup register and a value corresponding to the
 * core/thread context. Dongle will issue a write transaction <address,value>
 * to the PCIE RC which will need to be routed to the mapped register space, by
 * the host.
 */
/* #define DHD_D2H_SOFT_DOORBELL_SUPPORT */

/* Dependency Check */
#if defined(IOCTLRESP_USE_CONSTMEM) && defined(DHD_USE_STATIC_CTRLBUF)
#error "DHD_USE_STATIC_CTRLBUF is NOT working with DHD_USE_OSLPKT_FOR_RESPBUF"
#endif /* IOCTLRESP_USE_CONSTMEM && DHD_USE_STATIC_CTRLBUF */

#define RETRIES 2		/* # of retries to retrieve matching ioctl response */

#define DEFAULT_RX_BUFFERS_TO_POST	256
#define RXBUFPOST_THRESHOLD			32
#define RX_BUF_BURST				32 /* Rx buffers for MSDU Data */

#define DHD_STOP_QUEUE_THRESHOLD	200
#define DHD_START_QUEUE_THRESHOLD	100

#define RX_DMA_OFFSET		8 /* Mem2mem DMA inserts an extra 8 */
#define IOCT_RETBUF_SIZE	(RX_DMA_OFFSET + WLC_IOCTL_MAXLEN)

/* flags for ioctl pending status */
#define MSGBUF_IOCTL_ACK_PENDING	(1<<0)
#define MSGBUF_IOCTL_RESP_PENDING	(1<<1)

#define DHD_IOCTL_REQ_PKTBUFSZ		2048
#define MSGBUF_IOCTL_MAX_RQSTLEN	(DHD_IOCTL_REQ_PKTBUFSZ - H2DRING_CTRL_SUB_ITEMSIZE)

#define DMA_ALIGN_LEN		4

#define DMA_D2H_SCRATCH_BUF_LEN	8
#define DMA_XFER_LEN_LIMIT	0x400000

#ifdef BCM_HOST_BUF
#ifndef DMA_HOST_BUFFER_LEN
#define DMA_HOST_BUFFER_LEN	0x200000
#endif // endif
#endif /* BCM_HOST_BUF */

#define DHD_FLOWRING_IOCTL_BUFPOST_PKTSZ		8192

#define DHD_FLOWRING_DEFAULT_NITEMS_POSTED_H2D		1
#define DHD_FLOWRING_MAX_EVENTBUF_POST			32
#define DHD_FLOWRING_MAX_IOCTLRESPBUF_POST		8
#define DHD_H2D_INFORING_MAX_BUF_POST			32
#define DHD_MAX_TSBUF_POST			8

#define DHD_PROT_FUNCS	43

/* Length of buffer in host for bus throughput measurement */
#define DHD_BUS_TPUT_BUF_LEN 2048

#define TXP_FLUSH_NITEMS

/* optimization to write "n" tx items at a time to ring */
#define TXP_FLUSH_MAX_ITEMS_FLUSH_CNT	48

#define RING_NAME_MAX_LENGTH		24
#define CTRLSUB_HOSTTS_MEESAGE_SIZE		1024
/* Giving room before ioctl_trans_id rollsover. */
#define BUFFER_BEFORE_ROLLOVER 300

/* 512K memory + 32K registers */
#define SNAPSHOT_UPLOAD_BUF_SIZE	((512 + 32) * 1024)

struct msgbuf_ring; /* ring context for common and flow rings */

/**
 * PCIE D2H DMA Complete Sync Modes
 *
 * Firmware may interrupt the host, prior to the D2H Mem2Mem DMA completes into
 * Host system memory. A WAR using one of 3 approaches is needed:
 * 1. Dongle places a modulo-253 seqnum in last word of each D2H message
 * 2. XOR Checksum, with epoch# in each work item. Dongle builds an XOR checksum
 *    writes in the last word of each work item. Each work item has a seqnum
 *    number = sequence num % 253.
 *
 * 3. Read Barrier: Dongle does a host memory read access prior to posting an
 *    interrupt, ensuring that D2H data transfer indeed completed.
 * 4. Dongle DMA's all indices after producing items in the D2H ring, flushing
 *    ring contents before the indices.
 *
 * Host does not sync for DMA to complete with option #3 or #4, and a noop sync
 * callback (see dhd_prot_d2h_sync_none) may be bound.
 *
 * Dongle advertizes host side sync mechanism requirements.
 */

#define PCIE_D2H_SYNC_WAIT_TRIES    (512U)
#define PCIE_D2H_SYNC_NUM_OF_STEPS  (5U)
#define PCIE_D2H_SYNC_DELAY         (100UL)	/* in terms of usecs */

#define HWA_DB_TYPE_RXPOST	(0x0050)
#define HWA_DB_TYPE_TXCPLT	(0x0060)
#define HWA_DB_TYPE_RXCPLT	(0x0170)
#define HWA_DB_INDEX_VALUE(val)	((uint32)(val) << 16)

#define HWA_ENAB_BITMAP_RXPOST	(1U << 0)	/* 1A */
#define HWA_ENAB_BITMAP_RXCPLT	(1U << 1)	/* 2B */
#define HWA_ENAB_BITMAP_TXCPLT	(1U << 2)	/* 4B */

/**
 * Custom callback attached based upon D2H DMA Sync mode advertized by dongle.
 *
 * On success: return cmn_msg_hdr_t::msg_type
 * On failure: return 0 (invalid msg_type)
 */
typedef uint8 (* d2h_sync_cb_t)(dhd_pub_t *dhd, struct msgbuf_ring *ring,
                                volatile cmn_msg_hdr_t *msg, int msglen);

/**
 * Custom callback attached based upon D2H DMA Sync mode advertized by dongle.
 * For EDL messages.
 *
 * On success: return cmn_msg_hdr_t::msg_type
 * On failure: return 0 (invalid msg_type)
 */
#ifdef EWP_EDL
typedef int (* d2h_edl_sync_cb_t)(dhd_pub_t *dhd, struct msgbuf_ring *ring,
                                volatile cmn_msg_hdr_t *msg);
#endif /* EWP_EDL */

/*
 * +----------------------------------------------------------------------------
 *
 * RingIds and FlowId are not equivalent as ringids include D2H rings whereas
 * flowids do not.
 *
 * Dongle advertizes the max H2D rings, as max_sub_queues = 'N' which includes
 * the H2D common rings as well as the (N-BCMPCIE_H2D_COMMON_MSGRINGS) flowrings
 *
 * Here is a sample mapping for (based on PCIE Full Dongle Rev5) where,
 *  BCMPCIE_H2D_COMMON_MSGRINGS = 2, i.e. 2 H2D common rings,
 *  BCMPCIE_COMMON_MSGRINGS     = 5, i.e. include 3 D2H common rings.
 *
 *  H2D Control  Submit   RingId = 0        FlowId = 0 reserved never allocated
 *  H2D RxPost   Submit   RingId = 1        FlowId = 1 reserved never allocated
 *
 *  D2H Control  Complete RingId = 2
 *  D2H Transmit Complete RingId = 3
 *  D2H Receive  Complete RingId = 4
 *
 *  H2D TxPost   FLOWRING RingId = 5         FlowId = 2     (1st flowring)
 *  H2D TxPost   FLOWRING RingId = 6         FlowId = 3     (2nd flowring)
 *  H2D TxPost   FLOWRING RingId = 5 + (N-1) FlowId = (N-1) (Nth flowring)
 *
 * When TxPost FlowId(s) are allocated, the FlowIds [0..FLOWID_RESERVED) are
 * unused, where FLOWID_RESERVED is BCMPCIE_H2D_COMMON_MSGRINGS.
 *
 * Example: when a system supports 4 bc/mc and 128 uc flowrings, with
 * BCMPCIE_H2D_COMMON_MSGRINGS = 2, and BCMPCIE_H2D_COMMON_MSGRINGS = 5, and the
 * FlowId values would be in the range [2..133] and the corresponding
 * RingId values would be in the range [5..136].
 *
 * The flowId allocator, may chose to, allocate Flowids:
 *   bc/mc (per virtual interface) in one consecutive range [2..(2+VIFS))
 *   X# of uc flowids in consecutive ranges (per station Id), where X is the
 *   packet's access category (e.g. 4 uc flowids per station).
 *
 * CAUTION:
 * When DMA indices array feature is used, RingId=5, corresponding to the 0th
 * FLOWRING, will actually use the FlowId as index into the H2D DMA index,
 * since the FlowId truly represents the index in the H2D DMA indices array.
 *
 * Likewise, in the D2H direction, the RingId - BCMPCIE_H2D_COMMON_MSGRINGS,
 * will represent the index in the D2H DMA indices array.
 *
 * +----------------------------------------------------------------------------
 */

/* First TxPost Flowring Id */
#define DHD_FLOWRING_START_FLOWID   BCMPCIE_H2D_COMMON_MSGRINGS

/* Determine whether a ringid belongs to a TxPost flowring */
#define DHD_IS_FLOWRING(ringid, max_flow_rings) \
	((ringid) >= BCMPCIE_COMMON_MSGRINGS && \
	(ringid) < ((max_flow_rings) + BCMPCIE_COMMON_MSGRINGS))

/* Convert a H2D TxPost FlowId to a MsgBuf RingId */
#define DHD_FLOWID_TO_RINGID(flowid) \
	(BCMPCIE_COMMON_MSGRINGS + ((flowid) - BCMPCIE_H2D_COMMON_MSGRINGS))

/* Convert a MsgBuf RingId to a H2D TxPost FlowId */
#define DHD_RINGID_TO_FLOWID(ringid) \
	(BCMPCIE_H2D_COMMON_MSGRINGS + ((ringid) - BCMPCIE_COMMON_MSGRINGS))

/* Convert a H2D MsgBuf RingId to an offset index into the H2D DMA indices array
 * This may be used for the H2D DMA WR index array or H2D DMA RD index array or
 * any array of H2D rings.
 */
#define DHD_H2D_RING_OFFSET(ringid) \
	(((ringid) >= BCMPCIE_COMMON_MSGRINGS) ? DHD_RINGID_TO_FLOWID(ringid) : (ringid))

/* Convert a H2D MsgBuf Flowring Id to an offset index into the H2D DMA indices array
 * This may be used for IFRM.
 */
#define DHD_H2D_FRM_FLOW_RING_OFFSET(ringid) \
	((ringid) - BCMPCIE_COMMON_MSGRINGS)

/* Convert a D2H MsgBuf RingId to an offset index into the D2H DMA indices array
 * This may be used for the D2H DMA WR index array or D2H DMA RD index array or
 * any array of D2H rings.
 * d2h debug ring is located at the end, i.e. after all the tx flow rings and h2d debug ring
 * max_h2d_rings: total number of h2d rings
 */
#define DHD_D2H_RING_OFFSET(ringid, max_h2d_rings) \
	((ringid) > (max_h2d_rings) ? \
		((ringid) - max_h2d_rings) : \
		((ringid) - BCMPCIE_H2D_COMMON_MSGRINGS))

/* Convert a D2H DMA Indices Offset to a RingId */
#define DHD_D2H_RINGID(offset) \
	((offset) + BCMPCIE_H2D_COMMON_MSGRINGS)

#define DHD_DMAH_NULL      ((void*)NULL)

/*
 * Pad a DMA-able buffer by an additional cachline. If the end of the DMA-able
 * buffer does not occupy the entire cacheline, and another object is placed
 * following the DMA-able buffer, data corruption may occur if the DMA-able
 * buffer is used to DMAing into (e.g. D2H direction), when HW cache coherency
 * is not available.
 */
#if defined(L1_CACHE_BYTES)
#define DHD_DMA_PAD        (L1_CACHE_BYTES)
#else
#define DHD_DMA_PAD        (128)
#endif // endif

/*
 * +----------------------------------------------------------------------------
 * Flowring Pool
 *
 * Unlike common rings, which are attached very early on (dhd_prot_attach),
 * flowrings are dynamically instantiated. Moreover, flowrings may require a
 * larger DMA-able buffer. To avoid issues with fragmented cache coherent
 * DMA-able memory, a pre-allocated pool of msgbuf_ring_t is allocated once.
 * The DMA-able buffers are attached to these pre-allocated msgbuf_ring.
 *
 * Each DMA-able buffer may be allocated independently, or may be carved out
 * of a single large contiguous region that is registered with the protocol
 * layer into flowrings_dma_buf. On a 64bit platform, this contiguous region
 * may not span 0x00000000FFFFFFFF (avoid dongle side 64bit ptr arithmetic).
 *
 * No flowring pool action is performed in dhd_prot_attach(), as the number
 * of h2d rings is not yet known.
 *
 * In dhd_prot_init(), the dongle advertized number of h2d rings is used to
 * determine the number of flowrings required, and a pool of msgbuf_rings are
 * allocated and a DMA-able buffer (carved or allocated) is attached.
 * See: dhd_prot_flowrings_pool_attach()
 *
 * A flowring msgbuf_ring object may be fetched from this pool during flowring
 * creation, using the flowid. Likewise, flowrings may be freed back into the
 * pool on flowring deletion.
 * See: dhd_prot_flowrings_pool_fetch(), dhd_prot_flowrings_pool_release()
 *
 * In dhd_prot_detach(), the flowring pool is detached. The DMA-able buffers
 * are detached (returned back to the carved region or freed), and the pool of
 * msgbuf_ring and any objects allocated against it are freed.
 * See: dhd_prot_flowrings_pool_detach()
 *
 * In dhd_prot_reset(), the flowring pool is simply reset by returning it to a
 * state as-if upon an attach. All DMA-able buffers are retained.
 * Following a dhd_prot_reset(), in a subsequent dhd_prot_init(), the flowring
 * pool attach will notice that the pool persists and continue to use it. This
 * will avoid the case of a fragmented DMA-able region.
 *
 * +----------------------------------------------------------------------------
 */

/* Conversion of a flowid to a flowring pool index */
#define DHD_FLOWRINGS_POOL_OFFSET(flowid) \
	((flowid) - BCMPCIE_H2D_COMMON_MSGRINGS)

/* Fetch the msgbuf_ring_t from the flowring pool given a flowid */
#define DHD_RING_IN_FLOWRINGS_POOL(prot, flowid) \
	(msgbuf_ring_t*)((prot)->h2d_flowrings_pool) + \
	    DHD_FLOWRINGS_POOL_OFFSET(flowid)

/* Traverse each flowring in the flowring pool, assigning ring and flowid */
#define FOREACH_RING_IN_FLOWRINGS_POOL(prot, ring, flowid, total_flowrings) \
	for ((flowid) = DHD_FLOWRING_START_FLOWID, \
		(ring) = DHD_RING_IN_FLOWRINGS_POOL(prot, flowid); \
		 (flowid) < ((total_flowrings) + DHD_FLOWRING_START_FLOWID); \
		 (ring)++, (flowid)++)

/* Used in loopback tests */
typedef struct dhd_dmaxfer {
	dhd_dma_buf_t srcmem;
	dhd_dma_buf_t dstmem;
	uint32        srcdelay;
	uint32        destdelay;
	uint32        len;
	bool          in_progress;
	uint64        start_usec;
	uint64        time_taken;
	uint32        d11_lpbk;
	int           status;
} dhd_dmaxfer_t;

/**
 * msgbuf_ring : This object manages the host side ring that includes a DMA-able
 * buffer, the WR and RD indices, ring parameters such as max number of items
 * an length of each items, and other miscellaneous runtime state.
 * A msgbuf_ring may be used to represent a H2D or D2H common ring or a
 * H2D TxPost ring as specified in the PCIE FullDongle Spec.
 * Ring parameters are conveyed to the dongle, which maintains its own peer end
 * ring state. Depending on whether the DMA Indices feature is supported, the
 * host will update the WR/RD index in the DMA indices array in host memory or
 * directly in dongle memory.
 */
typedef struct msgbuf_ring {
	bool           inited;
	uint16         idx;       /* ring id */
	uint16         rd;        /* read index */
	uint16         curr_rd;   /* read index for debug */
	uint16         wr;        /* write index */
	uint16         max_items; /* maximum number of items in ring */
	uint16         item_len;  /* length of each item in the ring */
	sh_addr_t      base_addr; /* LITTLE ENDIAN formatted: base address */
	dhd_dma_buf_t  dma_buf;   /* DMA-able buffer: pa, va, len, dmah, secdma */
	uint32         seqnum;    /* next expected item's sequence number */
#ifdef TXP_FLUSH_NITEMS
	void           *start_addr;
	/* # of messages on ring not yet announced to dongle */
	uint16         pend_items_count;
#endif /* TXP_FLUSH_NITEMS */

	uint8   ring_type;
	uint16  hwa_db_type;	  /* hwa type non-zero for Data path rings */
	uint8   n_completion_ids;
	bool    create_pending;
	uint16  create_req_id;
	uint8   current_phase;
	uint16	compeltion_ring_ids[MAX_COMPLETION_RING_IDS_ASSOCIATED];
	uchar		name[RING_NAME_MAX_LENGTH];
	uint32		ring_mem_allocated;
	void	*ring_lock;
} msgbuf_ring_t;

#define DHD_RING_BGN_VA(ring)           ((ring)->dma_buf.va)
#define DHD_RING_END_VA(ring) \
	((uint8 *)(DHD_RING_BGN_VA((ring))) + \
	 (((ring)->max_items - 1) * (ring)->item_len))

/* This can be overwritten by module parameter defined in dhd_linux.c
 * or by dhd iovar h2d_max_txpost.
 */
int h2d_max_txpost = H2DRING_TXPOST_MAX_ITEM;

/** DHD protocol handle. Is an opaque type to other DHD software layers. */
typedef struct dhd_prot {
	osl_t *osh;		/* OSL handle */
	uint16 rxbufpost_sz;
	uint16 rxbufpost;
	uint16 max_rxbufpost;
	uint16 max_eventbufpost;
	uint16 max_ioctlrespbufpost;
	uint16 max_tsbufpost;
	uint16 max_infobufpost;
	uint16 infobufpost;
	uint16 cur_event_bufs_posted;
	uint16 cur_ioctlresp_bufs_posted;
	uint16 cur_ts_bufs_posted;

	/* Flow control mechanism based on active transmits pending */
	osl_atomic_t active_tx_count; /* increments/decrements on every packet tx/tx_status */
	uint16 h2d_max_txpost;
	uint16 txp_threshold;  /* optimization to write "n" tx items at a time to ring */

	/* MsgBuf Ring info: has a dhd_dma_buf that is dynamically allocated */
	msgbuf_ring_t h2dring_ctrl_subn; /* H2D ctrl message submission ring */
	msgbuf_ring_t h2dring_rxp_subn; /* H2D RxBuf post ring */
	msgbuf_ring_t d2hring_ctrl_cpln; /* D2H ctrl completion ring */
	msgbuf_ring_t d2hring_tx_cpln; /* D2H Tx complete message ring */
	msgbuf_ring_t d2hring_rx_cpln; /* D2H Rx complete message ring */
	msgbuf_ring_t *h2dring_info_subn; /* H2D info submission ring */
	msgbuf_ring_t *d2hring_info_cpln; /* D2H info completion ring */
	msgbuf_ring_t *d2hring_edl; /* D2H Enhanced Debug Lane (EDL) ring */

	msgbuf_ring_t *h2d_flowrings_pool; /* Pool of preallocated flowings */
	dhd_dma_buf_t flowrings_dma_buf; /* Contiguous DMA buffer for flowrings */
	uint16        h2d_rings_total; /* total H2D (common rings + flowrings) */

	uint32		rx_dataoffset;

	dhd_mb_ring_t	mb_ring_fn;	/* called when dongle needs to be notified of new msg */
	dhd_mb_ring_2_t	mb_2_ring_fn;	/* called when dongle needs to be notified of new msg */

	/* ioctl related resources */
	uint8 ioctl_state;
	int16 ioctl_status;		/* status returned from dongle */
	uint16 ioctl_resplen;
	dhd_ioctl_recieved_status_t ioctl_received;
	uint curr_ioctl_cmd;
	dhd_dma_buf_t	retbuf;		/* For holding ioctl response */
	dhd_dma_buf_t	ioctbuf;	/* For holding ioctl request */

	dhd_dma_buf_t	d2h_dma_scratch_buf;	/* For holding d2h scratch */

	/* DMA-able arrays for holding WR and RD indices */
	uint32          rw_index_sz; /* Size of a RD or WR index in dongle */
	dhd_dma_buf_t   h2d_dma_indx_wr_buf;	/* Array of H2D WR indices */
	dhd_dma_buf_t	h2d_dma_indx_rd_buf;	/* Array of H2D RD indices */
	dhd_dma_buf_t	d2h_dma_indx_wr_buf;	/* Array of D2H WR indices */
	dhd_dma_buf_t	d2h_dma_indx_rd_buf;	/* Array of D2H RD indices */
	dhd_dma_buf_t h2d_ifrm_indx_wr_buf;	/* Array of H2D WR indices for ifrm */

	dhd_dma_buf_t	host_bus_throughput_buf; /* bus throughput measure buffer */

	dhd_dma_buf_t   *flowring_buf;    /* pool of flow ring buf */
	uint32			flowring_num;

	d2h_sync_cb_t d2h_sync_cb; /* Sync on D2H DMA done: SEQNUM or XORCSUM */
#ifdef EWP_EDL
	d2h_edl_sync_cb_t d2h_edl_sync_cb; /* Sync on EDL D2H DMA done: SEQNUM or XORCSUM */
#endif /* EWP_EDL */
	ulong d2h_sync_wait_max; /* max number of wait loops to receive one msg */
	ulong d2h_sync_wait_tot; /* total wait loops */

	dhd_dmaxfer_t	dmaxfer; /* for test/DMA loopback */

	uint16		ioctl_seq_no;
	uint16		data_seq_no;
	uint16		ioctl_trans_id;
	void		*pktid_ctrl_map; /* a pktid maps to a packet and its metadata */
	void		*pktid_rx_map;	/* pktid map for rx path */
	void		*pktid_tx_map;	/* pktid map for tx path */
	bool		metadata_dbg;
	void		*pktid_map_handle_ioctl;
#ifdef DHD_MAP_PKTID_LOGGING
	void		*pktid_dma_map;	/* pktid map for DMA MAP */
	void		*pktid_dma_unmap; /* pktid map for DMA UNMAP */
#endif /* DHD_MAP_PKTID_LOGGING */
	uint32		pktid_depleted_cnt;	/* pktid depleted count */
	/* netif tx queue stop count */
	uint8		pktid_txq_stop_cnt;
	/* netif tx queue start count */
	uint8		pktid_txq_start_cnt;
	uint64		ioctl_fillup_time;	/* timestamp for ioctl fillup */
	uint64		ioctl_ack_time;		/* timestamp for ioctl ack */
	uint64		ioctl_cmplt_time;	/* timestamp for ioctl completion */

	/* Applications/utilities can read tx and rx metadata using IOVARs */
	uint16		rx_metadata_offset;
	uint16		tx_metadata_offset;

#if defined(DHD_D2H_SOFT_DOORBELL_SUPPORT)
	/* Host's soft doorbell configuration */
	bcmpcie_soft_doorbell_t soft_doorbell[BCMPCIE_D2H_COMMON_MSGRINGS];
#endif /* DHD_D2H_SOFT_DOORBELL_SUPPORT */

	/* Work Queues to be used by the producer and the consumer, and threshold
	 * when the WRITE index must be synced to consumer's workq
	 */
#if defined(DHD_LB_TXC)
	uint32 tx_compl_prod_sync ____cacheline_aligned;
	bcm_workq_t tx_compl_prod, tx_compl_cons;
#endif /* DHD_LB_TXC */
#if defined(DHD_LB_RXC)
	uint32 rx_compl_prod_sync ____cacheline_aligned;
	bcm_workq_t rx_compl_prod, rx_compl_cons;
#endif /* DHD_LB_RXC */

	dhd_dma_buf_t	fw_trap_buf; /* firmware trap buffer */

	uint32  host_ipc_version; /* Host sypported IPC rev */
	uint32  device_ipc_version; /* FW supported IPC rev */
	uint32  active_ipc_version; /* Host advertised IPC rev */
	dhd_dma_buf_t   hostts_req_buf; /* For holding host timestamp request buf */
	bool    hostts_req_buf_inuse;
	bool    rx_ts_log_enabled;
	bool    tx_ts_log_enabled;
	bool no_retry;
	bool no_aggr;
	bool fixed_rate;
	dhd_dma_buf_t	host_scb_buf;	/* scb host offload buffer */
#ifdef DHD_HP2P
	msgbuf_ring_t *d2hring_hp2p_txcpl; /* D2H HPP Tx completion ring */
	msgbuf_ring_t *d2hring_hp2p_rxcpl; /* D2H HPP Rx completion ring */
#endif /* DHD_HP2P */
	bool no_tx_resource;
} dhd_prot_t;

#ifdef DHD_EWPR_VER2
#define HANG_INFO_BASE64_BUFFER_SIZE 640
#endif // endif

#ifdef DHD_DUMP_PCIE_RINGS
static
int dhd_ring_write(dhd_pub_t *dhd, msgbuf_ring_t *ring, void *file,
	const void *user_buf, unsigned long *file_posn);
#ifdef EWP_EDL
static
int dhd_edl_ring_hdr_write(dhd_pub_t *dhd, msgbuf_ring_t *ring, void *file, const void *user_buf,
	unsigned long *file_posn);
#endif /* EWP_EDL */
#endif /* DHD_DUMP_PCIE_RINGS */

extern bool dhd_timesync_delay_post_bufs(dhd_pub_t *dhdp);
extern void dhd_schedule_dmaxfer_free(dhd_pub_t* dhdp, dmaxref_mem_map_t *dmmap);
/* Convert a dmaaddr_t to a base_addr with htol operations */
static INLINE void dhd_base_addr_htolpa(sh_addr_t *base_addr, dmaaddr_t pa);

/* APIs for managing a DMA-able buffer */
static int  dhd_dma_buf_audit(dhd_pub_t *dhd, dhd_dma_buf_t *dma_buf);
static void dhd_dma_buf_reset(dhd_pub_t *dhd, dhd_dma_buf_t *dma_buf);

/* msgbuf ring management */
static int dhd_prot_ring_attach(dhd_pub_t *dhd, msgbuf_ring_t *ring,
	const char *name, uint16 max_items, uint16 len_item, uint16 ringid);
static void dhd_prot_ring_init(dhd_pub_t *dhd, msgbuf_ring_t *ring);
static void dhd_prot_ring_reset(dhd_pub_t *dhd, msgbuf_ring_t *ring);
static void dhd_prot_ring_detach(dhd_pub_t *dhd, msgbuf_ring_t *ring);
static void dhd_prot_process_fw_timestamp(dhd_pub_t *dhd, void* buf);

/* Pool of pre-allocated msgbuf_ring_t with DMA-able buffers for Flowrings */
static int  dhd_prot_flowrings_pool_attach(dhd_pub_t *dhd);
static void dhd_prot_flowrings_pool_reset(dhd_pub_t *dhd);
static void dhd_prot_flowrings_pool_detach(dhd_pub_t *dhd);

/* Fetch and Release a flowring msgbuf_ring from flowring  pool */
static msgbuf_ring_t *dhd_prot_flowrings_pool_fetch(dhd_pub_t *dhd,
	uint16 flowid);
/* see also dhd_prot_flowrings_pool_release() in dhd_prot.h */

/* Producer: Allocate space in a msgbuf ring */
static void* dhd_prot_alloc_ring_space(dhd_pub_t *dhd, msgbuf_ring_t *ring,
	uint16 nitems, uint16 *alloced, bool exactly_nitems);
static void* dhd_prot_get_ring_space(msgbuf_ring_t *ring, uint16 nitems,
	uint16 *alloced, bool exactly_nitems);

/* Consumer: Determine the location where the next message may be consumed */
static uint8* dhd_prot_get_read_addr(dhd_pub_t *dhd, msgbuf_ring_t *ring,
	uint32 *available_len);

/* Producer (WR index update) or Consumer (RD index update) indication */
static void dhd_prot_ring_write_complete(dhd_pub_t *dhd, msgbuf_ring_t *ring,
	void *p, uint16 len);
static void dhd_prot_upd_read_idx(dhd_pub_t *dhd, msgbuf_ring_t *ring);

static INLINE int dhd_prot_dma_indx_alloc(dhd_pub_t *dhd, uint8 type,
	dhd_dma_buf_t *dma_buf, uint32 bufsz);

/* Set/Get a RD or WR index in the array of indices */
/* See also: dhd_prot_dma_indx_init() */
void dhd_prot_dma_indx_set(dhd_pub_t *dhd, uint16 new_index, uint8 type,
	uint16 ringid);
static uint16 dhd_prot_dma_indx_get(dhd_pub_t *dhd, uint8 type, uint16 ringid);

/* Locate a packet given a pktid */
static INLINE void *dhd_prot_packet_get(dhd_pub_t *dhd, uint32 pktid, uint8 pkttype,
	bool free_pktid);
/* Locate a packet given a PktId and free it. */
static INLINE void dhd_prot_packet_free(dhd_pub_t *dhd, void *pkt, uint8 pkttype, bool send);

static int dhd_msgbuf_query_ioctl(dhd_pub_t *dhd, int ifidx, uint cmd,
	void *buf, uint len, uint8 action);
static int dhd_msgbuf_set_ioctl(dhd_pub_t *dhd, int ifidx, uint cmd,
	void *buf, uint len, uint8 action);
static int dhd_msgbuf_wait_ioctl_cmplt(dhd_pub_t *dhd, uint32 len, void *buf);
static int dhd_fillup_ioct_reqst(dhd_pub_t *dhd, uint16 len, uint cmd,
	void *buf, int ifidx);

/* Post buffers for Rx, control ioctl response and events */
static uint16 dhd_msgbuf_rxbuf_post_ctrlpath(dhd_pub_t *dhd, uint8 msgid, uint32 max_to_post);
static void dhd_msgbuf_rxbuf_post_ioctlresp_bufs(dhd_pub_t *pub);
static void dhd_msgbuf_rxbuf_post_event_bufs(dhd_pub_t *pub);
static void dhd_msgbuf_rxbuf_post(dhd_pub_t *dhd, bool use_rsv_pktid);
static int dhd_prot_rxbuf_post(dhd_pub_t *dhd, uint16 count, bool use_rsv_pktid);
static int dhd_msgbuf_rxbuf_post_ts_bufs(dhd_pub_t *pub);

static void dhd_prot_return_rxbuf(dhd_pub_t *dhd, uint32 pktid, uint32 rxcnt);

/* D2H Message handling */
static int dhd_prot_process_msgtype(dhd_pub_t *dhd, msgbuf_ring_t *ring, uint8 *buf, uint32 len);

/* D2H Message handlers */
static void dhd_prot_noop(dhd_pub_t *dhd, void *msg);
static void dhd_prot_txstatus_process(dhd_pub_t *dhd, void *msg);
static void dhd_prot_ioctcmplt_process(dhd_pub_t *dhd, void *msg);
static void dhd_prot_ioctack_process(dhd_pub_t *dhd, void *msg);
static void dhd_prot_ringstatus_process(dhd_pub_t *dhd, void *msg);
static void dhd_prot_genstatus_process(dhd_pub_t *dhd, void *msg);
static void dhd_prot_event_process(dhd_pub_t *dhd, void *msg);

/* Loopback test with dongle */
static void dmaxfer_free_dmaaddr(dhd_pub_t *dhd, dhd_dmaxfer_t *dma);
static int dmaxfer_prepare_dmaaddr(dhd_pub_t *dhd, uint len, uint srcdelay,
	uint destdelay, dhd_dmaxfer_t *dma);
static void dhd_msgbuf_dmaxfer_process(dhd_pub_t *dhd, void *msg);

/* Flowring management communication with dongle */
static void dhd_prot_flow_ring_create_response_process(dhd_pub_t *dhd, void *msg);
static void dhd_prot_flow_ring_delete_response_process(dhd_pub_t *dhd, void *msg);
static void dhd_prot_flow_ring_flush_response_process(dhd_pub_t *dhd, void *msg);
static void dhd_prot_process_flow_ring_resume_response(dhd_pub_t *dhd, void* msg);
static void dhd_prot_process_flow_ring_suspend_response(dhd_pub_t *dhd, void* msg);

/* Monitor Mode */
#ifdef WL_MONITOR
extern bool dhd_monitor_enabled(dhd_pub_t *dhd, int ifidx);
extern void dhd_rx_mon_pkt(dhd_pub_t *dhdp, host_rxbuf_cmpl_t* msg, void *pkt, int ifidx);
#endif /* WL_MONITOR */

/* Configure a soft doorbell per D2H ring */
static void dhd_msgbuf_ring_config_d2h_soft_doorbell(dhd_pub_t *dhd);
static void dhd_prot_process_d2h_ring_config_complete(dhd_pub_t *dhd, void *msg);
static void dhd_prot_process_d2h_ring_create_complete(dhd_pub_t *dhd, void *buf);
static void dhd_prot_process_h2d_ring_create_complete(dhd_pub_t *dhd, void *buf);
static void dhd_prot_process_infobuf_complete(dhd_pub_t *dhd, void* buf);
static void dhd_prot_process_d2h_mb_data(dhd_pub_t *dhd, void* buf);
static void dhd_prot_detach_info_rings(dhd_pub_t *dhd);
#ifdef DHD_HP2P
static void dhd_prot_detach_hp2p_rings(dhd_pub_t *dhd);
#endif /* DHD_HP2P */
#ifdef EWP_EDL
static void dhd_prot_detach_edl_rings(dhd_pub_t *dhd);
#endif // endif
static void dhd_prot_process_d2h_host_ts_complete(dhd_pub_t *dhd, void* buf);
static void dhd_prot_process_snapshot_complete(dhd_pub_t *dhd, void *buf);

#ifdef DHD_HP2P
static void dhd_update_hp2p_rxstats(dhd_pub_t *dhd, host_rxbuf_cmpl_t *rxstatus);
static void dhd_update_hp2p_txstats(dhd_pub_t *dhd, host_txbuf_cmpl_t *txstatus);
static void dhd_calc_hp2p_burst(dhd_pub_t *dhd, msgbuf_ring_t *ring, uint16 flowid);
static void dhd_update_hp2p_txdesc(dhd_pub_t *dhd, host_txbuf_post_t *txdesc);
#endif // endif
typedef void (*dhd_msgbuf_func_t)(dhd_pub_t *dhd, void *msg);

/** callback functions for messages generated by the dongle */
#define MSG_TYPE_INVALID 0

static dhd_msgbuf_func_t table_lookup[DHD_PROT_FUNCS] = {
	dhd_prot_noop, /* 0 is MSG_TYPE_INVALID */
	dhd_prot_genstatus_process, /* MSG_TYPE_GEN_STATUS */
	dhd_prot_ringstatus_process, /* MSG_TYPE_RING_STATUS */
	NULL,
	dhd_prot_flow_ring_create_response_process, /* MSG_TYPE_FLOW_RING_CREATE_CMPLT */
	NULL,
	dhd_prot_flow_ring_delete_response_process, /* MSG_TYPE_FLOW_RING_DELETE_CMPLT */
	NULL,
	dhd_prot_flow_ring_flush_response_process, /* MSG_TYPE_FLOW_RING_FLUSH_CMPLT */
	NULL,
	dhd_prot_ioctack_process, /* MSG_TYPE_IOCTLPTR_REQ_ACK */
	NULL,
	dhd_prot_ioctcmplt_process, /* MSG_TYPE_IOCTL_CMPLT */
	NULL,
	dhd_prot_event_process, /* MSG_TYPE_WL_EVENT */
	NULL,
	dhd_prot_txstatus_process, /* MSG_TYPE_TX_STATUS */
	NULL,
	NULL,	/* MSG_TYPE_RX_CMPLT use dedicated handler */
	NULL,
	dhd_msgbuf_dmaxfer_process, /* MSG_TYPE_LPBK_DMAXFER_CMPLT */
	NULL, /* MSG_TYPE_FLOW_RING_RESUME */
	dhd_prot_process_flow_ring_resume_response, /* MSG_TYPE_FLOW_RING_RESUME_CMPLT */
	NULL, /* MSG_TYPE_FLOW_RING_SUSPEND */
	dhd_prot_process_flow_ring_suspend_response, /* MSG_TYPE_FLOW_RING_SUSPEND_CMPLT */
	NULL, /* MSG_TYPE_INFO_BUF_POST */
	dhd_prot_process_infobuf_complete, /* MSG_TYPE_INFO_BUF_CMPLT */
	NULL, /* MSG_TYPE_H2D_RING_CREATE */
	NULL, /* MSG_TYPE_D2H_RING_CREATE */
	dhd_prot_process_h2d_ring_create_complete, /* MSG_TYPE_H2D_RING_CREATE_CMPLT */
	dhd_prot_process_d2h_ring_create_complete, /* MSG_TYPE_D2H_RING_CREATE_CMPLT */
	NULL, /* MSG_TYPE_H2D_RING_CONFIG */
	NULL, /* MSG_TYPE_D2H_RING_CONFIG */
	NULL, /* MSG_TYPE_H2D_RING_CONFIG_CMPLT */
	dhd_prot_process_d2h_ring_config_complete, /* MSG_TYPE_D2H_RING_CONFIG_CMPLT */
	NULL, /* MSG_TYPE_H2D_MAILBOX_DATA */
	dhd_prot_process_d2h_mb_data, /* MSG_TYPE_D2H_MAILBOX_DATA */
	NULL,	/* MSG_TYPE_TIMSTAMP_BUFPOST */
	NULL,	/* MSG_TYPE_HOSTTIMSTAMP */
	dhd_prot_process_d2h_host_ts_complete,	/* MSG_TYPE_HOSTTIMSTAMP_CMPLT */
	dhd_prot_process_fw_timestamp,	/* MSG_TYPE_FIRMWARE_TIMESTAMP */
	NULL,	/* MSG_TYPE_SNAPSHOT_UPLOAD */
	dhd_prot_process_snapshot_complete,	/* MSG_TYPE_SNAPSHOT_CMPLT */
};

#ifdef DHD_RX_CHAINING

#define PKT_CTF_CHAINABLE(dhd, ifidx, evh, prio, h_sa, h_da, h_prio) \
	(dhd_wet_chainable(dhd) && \
	dhd_rx_pkt_chainable((dhd), (ifidx)) && \
	!ETHER_ISNULLDEST(((struct ether_header *)(evh))->ether_dhost) && \
	!ETHER_ISMULTI(((struct ether_header *)(evh))->ether_dhost) && \
	!eacmp((h_da), ((struct ether_header *)(evh))->ether_dhost) && \
	!eacmp((h_sa), ((struct ether_header *)(evh))->ether_shost) && \
	((h_prio) == (prio)) && (dhd_ctf_hotbrc_check((dhd), (evh), (ifidx))) && \
	((((struct ether_header *)(evh))->ether_type == HTON16(ETHER_TYPE_IP)) || \
	(((struct ether_header *)(evh))->ether_type == HTON16(ETHER_TYPE_IPV6))))

static INLINE void BCMFASTPATH dhd_rxchain_reset(rxchain_info_t *rxchain);
static void BCMFASTPATH dhd_rxchain_frame(dhd_pub_t *dhd, void *pkt, uint ifidx);
static void BCMFASTPATH dhd_rxchain_commit(dhd_pub_t *dhd);

#define DHD_PKT_CTF_MAX_CHAIN_LEN	64

#endif /* DHD_RX_CHAINING */

#define DHD_LPBKDTDUMP_ON()	(dhd_msg_level & DHD_LPBKDTDUMP_VAL)

static void dhd_prot_h2d_sync_init(dhd_pub_t *dhd);

bool
dhd_prot_is_cmpl_ring_empty(dhd_pub_t *dhd, void *prot_info)
{
	msgbuf_ring_t *flow_ring = (msgbuf_ring_t *)prot_info;
	uint16 rd, wr;
	bool ret;

	if (dhd->dma_d2h_ring_upd_support) {
		wr = flow_ring->wr;
	} else {
		dhd_bus_cmn_readshared(dhd->bus, &wr, RING_WR_UPD, flow_ring->idx);
	}
	if (dhd->dma_h2d_ring_upd_support) {
		rd = flow_ring->rd;
	} else {
		dhd_bus_cmn_readshared(dhd->bus, &rd, RING_RD_UPD, flow_ring->idx);
	}
	ret = (wr == rd) ? TRUE : FALSE;
	return ret;
}

void
dhd_prot_dump_ring_ptrs(void *prot_info)
{
	msgbuf_ring_t *ring = (msgbuf_ring_t *)prot_info;
	DHD_ERROR(("%s curr_rd: %d rd: %d wr: %d \n", __FUNCTION__,
		ring->curr_rd, ring->rd, ring->wr));
}

uint16
dhd_prot_get_h2d_max_txpost(dhd_pub_t *dhd)
{
	return (uint16)h2d_max_txpost;
}
void
dhd_prot_set_h2d_max_txpost(dhd_pub_t *dhd, uint16 max_txpost)
{
	h2d_max_txpost = max_txpost;
}
/**
 * D2H DMA to completion callback handlers. Based on the mode advertised by the
 * dongle through the PCIE shared region, the appropriate callback will be
 * registered in the proto layer to be invoked prior to precessing any message
 * from a D2H DMA ring. If the dongle uses a read barrier or another mode that
 * does not require host participation, then a noop callback handler will be
 * bound that simply returns the msg_type.
 */
static void dhd_prot_d2h_sync_livelock(dhd_pub_t *dhd, uint32 msg_seqnum, msgbuf_ring_t *ring,
                                       uint32 tries, volatile uchar *msg, int msglen);
static uint8 dhd_prot_d2h_sync_seqnum(dhd_pub_t *dhd, msgbuf_ring_t *ring,
                                      volatile cmn_msg_hdr_t *msg, int msglen);
static uint8 dhd_prot_d2h_sync_xorcsum(dhd_pub_t *dhd, msgbuf_ring_t *ring,
                                       volatile cmn_msg_hdr_t *msg, int msglen);
static uint8 dhd_prot_d2h_sync_none(dhd_pub_t *dhd, msgbuf_ring_t *ring,
                                    volatile cmn_msg_hdr_t *msg, int msglen);
static void dhd_prot_d2h_sync_init(dhd_pub_t *dhd);
static int dhd_send_d2h_ringcreate(dhd_pub_t *dhd, msgbuf_ring_t *ring_to_create,
	uint16 ring_type, uint32 id);
static int dhd_send_h2d_ringcreate(dhd_pub_t *dhd, msgbuf_ring_t *ring_to_create,
	uint8 type, uint32 id);

/**
 * dhd_prot_d2h_sync_livelock - when the host determines that a DMA transfer has
 * not completed, a livelock condition occurs. Host will avert this livelock by
 * dropping this message and moving to the next. This dropped message can lead
 * to a packet leak, or even something disastrous in the case the dropped
 * message happens to be a control response.
 * Here we will log this condition. One may choose to reboot the dongle.
 *
 */
static void
dhd_prot_d2h_sync_livelock(dhd_pub_t *dhd, uint32 msg_seqnum, msgbuf_ring_t *ring, uint32 tries,
                           volatile uchar *msg, int msglen)
{
	uint32 ring_seqnum = ring->seqnum;

	if (dhd_query_bus_erros(dhd)) {
		return;
	}

	DHD_ERROR((
		"LIVELOCK DHD<%p> ring<%s> msg_seqnum<%u> ring_seqnum<%u:%u> tries<%u> max<%lu>"
		" tot<%lu> dma_buf va<%p> msg<%p> curr_rd<%d> rd<%d> wr<%d>\n",
		dhd, ring->name, msg_seqnum, ring_seqnum, ring_seqnum% D2H_EPOCH_MODULO, tries,
		dhd->prot->d2h_sync_wait_max, dhd->prot->d2h_sync_wait_tot,
		ring->dma_buf.va, msg, ring->curr_rd, ring->rd, ring->wr));

	dhd_prhex("D2H MsgBuf Failure", msg, msglen, DHD_ERROR_VAL);

	/* Try to resume if already suspended or suspend in progress */

	/* Skip if still in suspended or suspend in progress */
	if (DHD_BUS_CHECK_SUSPEND_OR_ANY_SUSPEND_IN_PROGRESS(dhd)) {
		DHD_ERROR(("%s: bus is in suspend(%d) or suspending(0x%x) state, so skip\n",
			__FUNCTION__, dhd->busstate, dhd->dhd_bus_busy_state));
		goto exit;
	}

	dhd_bus_dump_console_buffer(dhd->bus);
	dhd_prot_debug_info_print(dhd);

#ifdef DHD_FW_COREDUMP
	if (dhd->memdump_enabled) {
		/* collect core dump */
		dhd->memdump_type = DUMP_TYPE_BY_LIVELOCK;
		dhd_bus_mem_dump(dhd);
	}
#endif /* DHD_FW_COREDUMP */

exit:
	dhd_schedule_reset(dhd);

	dhd->livelock_occured = TRUE;
}

/**
 * dhd_prot_d2h_sync_seqnum - Sync on a D2H DMA completion using the SEQNUM
 * mode. Sequence number is always in the last word of a message.
 */
static uint8 BCMFASTPATH
dhd_prot_d2h_sync_seqnum(dhd_pub_t *dhd, msgbuf_ring_t *ring,
                         volatile cmn_msg_hdr_t *msg, int msglen)
{
	uint32 tries;
	uint32 ring_seqnum = ring->seqnum % D2H_EPOCH_MODULO;
	int num_words = msglen / sizeof(uint32); /* num of 32bit words */
	volatile uint32 *marker = (volatile uint32 *)msg + (num_words - 1); /* last word */
	dhd_prot_t *prot = dhd->prot;
	uint32 msg_seqnum;
	uint32 step = 0;
	uint32 delay = PCIE_D2H_SYNC_DELAY;
	uint32 total_tries = 0;

	ASSERT(msglen == ring->item_len);

	BCM_REFERENCE(delay);
	/*
	 * For retries we have to make some sort of stepper algorithm.
	 * We see that every time when the Dongle comes out of the D3
	 * Cold state, the first D2H mem2mem DMA takes more time to
	 * complete, leading to livelock issues.
	 *
	 * Case 1 - Apart from Host CPU some other bus master is
	 * accessing the DDR port, probably page close to the ring
	 * so, PCIE does not get a change to update the memory.
	 * Solution - Increase the number of tries.
	 *
	 * Case 2 - The 50usec delay given by the Host CPU is not
	 * sufficient for the PCIe RC to start its work.
	 * In this case the breathing time of 50usec given by
	 * the Host CPU is not sufficient.
	 * Solution: Increase the delay in a stepper fashion.
	 * This is done to ensure that there are no
	 * unwanted extra delay introdcued in normal conditions.
	 */
	for (step = 1; step <= PCIE_D2H_SYNC_NUM_OF_STEPS; step++) {
		for (tries = 0; tries < PCIE_D2H_SYNC_WAIT_TRIES; tries++) {
			msg_seqnum = *marker;
			if (ltoh32(msg_seqnum) == ring_seqnum) { /* dma upto last word done */
				ring->seqnum++; /* next expected sequence number */
				/* Check for LIVELOCK induce flag, which is set by firing
				 * dhd iovar to induce LIVELOCK error. If flag is set,
				 * MSG_TYPE_INVALID is returned, which results in to LIVELOCK error.
				 */
				if (dhd->dhd_induce_error != DHD_INDUCE_LIVELOCK) {
					goto dma_completed;
				}
			}

			total_tries = (uint32)(((step-1) * PCIE_D2H_SYNC_WAIT_TRIES) + tries);

			if (total_tries > prot->d2h_sync_wait_max)
				prot->d2h_sync_wait_max = total_tries;

			OSL_CACHE_INV(msg, msglen); /* invalidate and try again */
			OSL_CPU_RELAX(); /* CPU relax for msg_seqnum  value to update */
			OSL_DELAY(delay * step); /* Add stepper delay */

		} /* for PCIE_D2H_SYNC_WAIT_TRIES */
	} /* for PCIE_D2H_SYNC_NUM_OF_STEPS */

	dhd_prot_d2h_sync_livelock(dhd, msg_seqnum, ring, total_tries,
		(volatile uchar *) msg, msglen);

	ring->seqnum++; /* skip this message ... leak of a pktid */
	return MSG_TYPE_INVALID; /* invalid msg_type 0 -> noop callback */

dma_completed:

	prot->d2h_sync_wait_tot += tries;
	return msg->msg_type;
}

/**
 * dhd_prot_d2h_sync_xorcsum - Sync on a D2H DMA completion using the XORCSUM
 * mode. The xorcsum is placed in the last word of a message. Dongle will also
 * place a seqnum in the epoch field of the cmn_msg_hdr.
 */
static uint8 BCMFASTPATH
dhd_prot_d2h_sync_xorcsum(dhd_pub_t *dhd, msgbuf_ring_t *ring,
                          volatile cmn_msg_hdr_t *msg, int msglen)
{
	uint32 tries;
	uint32 prot_checksum = 0; /* computed checksum */
	int num_words = msglen / sizeof(uint32); /* num of 32bit words */
	uint8 ring_seqnum = ring->seqnum % D2H_EPOCH_MODULO;
	dhd_prot_t *prot = dhd->prot;
	uint32 step = 0;
	uint32 delay = PCIE_D2H_SYNC_DELAY;
	uint32 total_tries = 0;

	ASSERT(msglen == ring->item_len);

	BCM_REFERENCE(delay);
	/*
	 * For retries we have to make some sort of stepper algorithm.
	 * We see that every time when the Dongle comes out of the D3
	 * Cold state, the first D2H mem2mem DMA takes more time to
	 * complete, leading to livelock issues.
	 *
	 * Case 1 - Apart from Host CPU some other bus master is
	 * accessing the DDR port, probably page close to the ring
	 * so, PCIE does not get a change to update the memory.
	 * Solution - Increase the number of tries.
	 *
	 * Case 2 - The 50usec delay given by the Host CPU is not
	 * sufficient for the PCIe RC to start its work.
	 * In this case the breathing time of 50usec given by
	 * the Host CPU is not sufficient.
	 * Solution: Increase the delay in a stepper fashion.
	 * This is done to ensure that there are no
	 * unwanted extra delay introdcued in normal conditions.
	 */
	for (step = 1; step <= PCIE_D2H_SYNC_NUM_OF_STEPS; step++) {
		for (tries = 0; tries < PCIE_D2H_SYNC_WAIT_TRIES; tries++) {
			/* First verify if the seqnumber has been update,
			 * if yes, then only check xorcsum.
			 * Once seqnum and xorcsum is proper that means
			 * complete message has arrived.
			 */
			if (msg->epoch == ring_seqnum) {
				prot_checksum = bcm_compute_xor32((volatile uint32 *)msg,
					num_words);
				if (prot_checksum == 0U) { /* checksum is OK */
					ring->seqnum++; /* next expected sequence number */
					/* Check for LIVELOCK induce flag, which is set by firing
					 * dhd iovar to induce LIVELOCK error. If flag is set,
					 * MSG_TYPE_INVALID is returned, which results in to
					 * LIVELOCK error.
					 */
					if (dhd->dhd_induce_error != DHD_INDUCE_LIVELOCK) {
						goto dma_completed;
					}
				}
			}

			total_tries = ((step-1) * PCIE_D2H_SYNC_WAIT_TRIES) + tries;

			if (total_tries > prot->d2h_sync_wait_max)
				prot->d2h_sync_wait_max = total_tries;

			OSL_CACHE_INV(msg, msglen); /* invalidate and try again */
			OSL_CPU_RELAX(); /* CPU relax for msg_seqnum  value to update */
			OSL_DELAY(delay * step); /* Add stepper delay */

		} /* for PCIE_D2H_SYNC_WAIT_TRIES */
	} /* for PCIE_D2H_SYNC_NUM_OF_STEPS */

	DHD_ERROR(("%s: prot_checksum = 0x%x\n", __FUNCTION__, prot_checksum));
	dhd_prot_d2h_sync_livelock(dhd, msg->epoch, ring, total_tries,
		(volatile uchar *) msg, msglen);

	ring->seqnum++; /* skip this message ... leak of a pktid */
	return MSG_TYPE_INVALID; /* invalid msg_type 0 -> noop callback */

dma_completed:

	prot->d2h_sync_wait_tot += tries;
	return msg->msg_type;
}

/**
 * dhd_prot_d2h_sync_none - Dongle ensure that the DMA will complete and host
 * need to try to sync. This noop sync handler will be bound when the dongle
 * advertises that neither the SEQNUM nor XORCSUM mode of DMA sync is required.
 */
static uint8 BCMFASTPATH
dhd_prot_d2h_sync_none(dhd_pub_t *dhd, msgbuf_ring_t *ring,
                       volatile cmn_msg_hdr_t *msg, int msglen)
{
	/* Check for LIVELOCK induce flag, which is set by firing
	* dhd iovar to induce LIVELOCK error. If flag is set,
	* MSG_TYPE_INVALID is returned, which results in to LIVELOCK error.
	*/
	if (dhd->dhd_induce_error == DHD_INDUCE_LIVELOCK) {
		DHD_ERROR(("%s: Inducing livelock\n", __FUNCTION__));
		return MSG_TYPE_INVALID;
	} else {
		return msg->msg_type;
	}
}

#ifdef EWP_EDL
/**
 * dhd_prot_d2h_sync_edl - Sync on a D2H DMA completion by validating the cmn_msg_hdr_t
 * header values at both the beginning and end of the payload.
 * The cmn_msg_hdr_t is placed at the start and end of the payload
 * in each work item in the EDL ring.
 * Dongle will place a seqnum inside the cmn_msg_hdr_t 'epoch' field
 * and the length of the payload in the 'request_id' field.
 * Structure of each work item in the EDL ring:
 * | cmn_msg_hdr_t | payload (var len) | cmn_msg_hdr_t |
 * NOTE: - it was felt that calculating xorcsum for the entire payload (max length of 1648 bytes) is
 * too costly on the dongle side and might take up too many ARM cycles,
 * hence the xorcsum sync method is not being used for EDL ring.
 */
static int
BCMFASTPATH(dhd_prot_d2h_sync_edl)(dhd_pub_t *dhd, msgbuf_ring_t *ring,
                          volatile cmn_msg_hdr_t *msg)
{
	uint32 tries;
	int msglen = 0, len = 0;
	uint32 ring_seqnum = ring->seqnum % D2H_EPOCH_MODULO;
	dhd_prot_t *prot = dhd->prot;
	uint32 step = 0;
	uint32 delay = PCIE_D2H_SYNC_DELAY;
	uint32 total_tries = 0;
	volatile cmn_msg_hdr_t *trailer = NULL;
	volatile uint8 *buf = NULL;
	bool valid_msg = FALSE;

	BCM_REFERENCE(delay);
	/*
	 * For retries we have to make some sort of stepper algorithm.
	 * We see that every time when the Dongle comes out of the D3
	 * Cold state, the first D2H mem2mem DMA takes more time to
	 * complete, leading to livelock issues.
	 *
	 * Case 1 - Apart from Host CPU some other bus master is
	 * accessing the DDR port, probably page close to the ring
	 * so, PCIE does not get a change to update the memory.
	 * Solution - Increase the number of tries.
	 *
	 * Case 2 - The 50usec delay given by the Host CPU is not
	 * sufficient for the PCIe RC to start its work.
	 * In this case the breathing time of 50usec given by
	 * the Host CPU is not sufficient.
	 * Solution: Increase the delay in a stepper fashion.
	 * This is done to ensure that there are no
	 * unwanted extra delay introdcued in normal conditions.
	 */
	for (step = 1; step <= PCIE_D2H_SYNC_NUM_OF_STEPS; step++) {
		for (tries = 0; tries < PCIE_D2H_SYNC_WAIT_TRIES; tries++) {
			/* First verify if the seqnumber has been updated,
			 * if yes, only then validate the header and trailer.
			 * Once seqnum, header and trailer have been validated, it means
			 * that the complete message has arrived.
			 */
			valid_msg = FALSE;
			if (msg->epoch == ring_seqnum &&
				msg->msg_type == MSG_TYPE_INFO_PYLD &&
				msg->request_id > 0 &&
				msg->request_id <= ring->item_len) {
				/* proceed to check trailer only if header is valid */
				buf = (volatile uint8 *)msg;
				msglen = sizeof(cmn_msg_hdr_t) + msg->request_id;
				buf += msglen;
				if (msglen + sizeof(cmn_msg_hdr_t) <= ring->item_len) {
					trailer = (volatile cmn_msg_hdr_t *)buf;
					valid_msg = (trailer->epoch == ring_seqnum) &&
						(trailer->msg_type == msg->msg_type) &&
						(trailer->request_id == msg->request_id);
					if (!valid_msg) {
						DHD_TRACE(("%s:invalid trailer! seqnum=%u;reqid=%u"
						" expected, seqnum=%u; reqid=%u. Retrying... \n",
						__FUNCTION__, trailer->epoch, trailer->request_id,
						msg->epoch, msg->request_id));
					}
				} else {
					DHD_TRACE(("%s: invalid payload length (%u)! Retrying.. \n",
						__FUNCTION__, msg->request_id));
				}

				if (valid_msg) {
					/* data is OK */
					ring->seqnum++; /* next expected sequence number */
					if (dhd->dhd_induce_error != DHD_INDUCE_LIVELOCK) {
						goto dma_completed;
					}
				}
			} else {
				DHD_TRACE(("%s: wrong hdr, seqnum expected %u, got %u."
					" msg_type=0x%x, request_id=%u."
					" Retrying...\n",
					__FUNCTION__, ring_seqnum, msg->epoch,
					msg->msg_type, msg->request_id));
			}

			total_tries = ((step-1) * PCIE_D2H_SYNC_WAIT_TRIES) + tries;

			if (total_tries > prot->d2h_sync_wait_max)
				prot->d2h_sync_wait_max = total_tries;

			OSL_CACHE_INV(msg, msglen); /* invalidate and try again */
			OSL_CPU_RELAX(); /* CPU relax for msg_seqnum  value to update */
			OSL_DELAY(delay * step); /* Add stepper delay */

		} /* for PCIE_D2H_SYNC_WAIT_TRIES */
	} /* for PCIE_D2H_SYNC_NUM_OF_STEPS */

	DHD_ERROR(("%s: EDL header check fails !\n", __FUNCTION__));
	DHD_ERROR(("%s: header: seqnum=%u; expected-seqnum=%u"
		" msgtype=0x%x; expected-msgtype=0x%x"
		" length=%u; expected-max-length=%u", __FUNCTION__,
		msg->epoch, ring_seqnum, msg->msg_type, MSG_TYPE_INFO_PYLD,
		msg->request_id, ring->item_len));
	dhd_prhex("msg header bytes: ", (volatile uchar *)msg, sizeof(*msg), DHD_ERROR_VAL);
	if (trailer && msglen > 0 &&
			(msglen + sizeof(cmn_msg_hdr_t)) <= ring->item_len) {
		DHD_ERROR(("%s: trailer: seqnum=%u; expected-seqnum=%u"
			" msgtype=0x%x; expected-msgtype=0x%x"
			" length=%u; expected-length=%u", __FUNCTION__,
			trailer->epoch, ring_seqnum, trailer->msg_type, MSG_TYPE_INFO_PYLD,
			trailer->request_id, msg->request_id));
		dhd_prhex("msg trailer bytes: ", (volatile uchar *)trailer,
			sizeof(*trailer), DHD_ERROR_VAL);
	}

	if ((msglen + sizeof(cmn_msg_hdr_t)) <= ring->item_len)
		len = msglen + sizeof(cmn_msg_hdr_t);
	else
		len = ring->item_len;

	dhd_prot_d2h_sync_livelock(dhd, msg->epoch, ring, total_tries,
		(volatile uchar *) msg, len);

	ring->seqnum++; /* skip this message */
	return BCME_ERROR; /* invalid msg_type 0 -> noop callback */

dma_completed:
	DHD_TRACE(("%s: EDL header check pass, seqnum=%u; reqid=%u\n", __FUNCTION__,
		msg->epoch, msg->request_id));

	prot->d2h_sync_wait_tot += tries;
	return BCME_OK;
}

/**
 * dhd_prot_d2h_sync_edl_none - Dongle ensure that the DMA will complete and host
 * need to try to sync. This noop sync handler will be bound when the dongle
 * advertises that neither the SEQNUM nor XORCSUM mode of DMA sync is required.
 */
static int BCMFASTPATH
dhd_prot_d2h_sync_edl_none(dhd_pub_t *dhd, msgbuf_ring_t *ring,
                       volatile cmn_msg_hdr_t *msg)
{
	/* Check for LIVELOCK induce flag, which is set by firing
	* dhd iovar to induce LIVELOCK error. If flag is set,
	* MSG_TYPE_INVALID is returned, which results in to LIVELOCK error.
	*/
	if (dhd->dhd_induce_error == DHD_INDUCE_LIVELOCK) {
		DHD_ERROR(("%s: Inducing livelock\n", __FUNCTION__));
		return BCME_ERROR;
	} else {
		if (msg->msg_type == MSG_TYPE_INFO_PYLD)
			return BCME_OK;
		else
			return msg->msg_type;
	}
}
#endif /* EWP_EDL */

INLINE void
dhd_wakeup_ioctl_event(dhd_pub_t *dhd, dhd_ioctl_recieved_status_t reason)
{
	/* To synchronize with the previous memory operations call wmb() */
	OSL_SMP_WMB();
	dhd->prot->ioctl_received = reason;
	/* Call another wmb() to make sure before waking up the other event value gets updated */
	OSL_SMP_WMB();
	dhd_os_ioctl_resp_wake(dhd);
}

/**
 * dhd_prot_d2h_sync_init - Setup the host side DMA sync mode based on what
 * dongle advertizes.
 */
static void
dhd_prot_d2h_sync_init(dhd_pub_t *dhd)
{
	dhd_prot_t *prot = dhd->prot;
	prot->d2h_sync_wait_max = 0UL;
	prot->d2h_sync_wait_tot = 0UL;

	prot->d2hring_ctrl_cpln.seqnum = D2H_EPOCH_INIT_VAL;
	prot->d2hring_ctrl_cpln.current_phase = BCMPCIE_CMNHDR_PHASE_BIT_INIT;

	prot->d2hring_tx_cpln.seqnum = D2H_EPOCH_INIT_VAL;
	prot->d2hring_tx_cpln.current_phase = BCMPCIE_CMNHDR_PHASE_BIT_INIT;

	prot->d2hring_rx_cpln.seqnum = D2H_EPOCH_INIT_VAL;
	prot->d2hring_rx_cpln.current_phase = BCMPCIE_CMNHDR_PHASE_BIT_INIT;

	if (HWA_ACTIVE(dhd)) {
		prot->d2hring_tx_cpln.hwa_db_type =
			(dhd->bus->hwa_enab_bmap & HWA_ENAB_BITMAP_TXCPLT) ? HWA_DB_TYPE_TXCPLT : 0;
		prot->d2hring_rx_cpln.hwa_db_type =
			(dhd->bus->hwa_enab_bmap & HWA_ENAB_BITMAP_RXCPLT) ? HWA_DB_TYPE_RXCPLT : 0;
		DHD_ERROR(("%s: TXCPLT hwa_db_type:0x%x RXCPLT hwa_db_type:0x%x\n",
			__FUNCTION__, prot->d2hring_tx_cpln.hwa_db_type,
			prot->d2hring_rx_cpln.hwa_db_type));
	}

	if (dhd->d2h_sync_mode & PCIE_SHARED_D2H_SYNC_SEQNUM) {
		prot->d2h_sync_cb = dhd_prot_d2h_sync_seqnum;
#ifdef EWP_EDL
		prot->d2h_edl_sync_cb = dhd_prot_d2h_sync_edl;
#endif /* EWP_EDL */
		DHD_ERROR(("%s(): D2H sync mechanism is SEQNUM \r\n", __FUNCTION__));
	} else if (dhd->d2h_sync_mode & PCIE_SHARED_D2H_SYNC_XORCSUM) {
		prot->d2h_sync_cb = dhd_prot_d2h_sync_xorcsum;
#ifdef EWP_EDL
		prot->d2h_edl_sync_cb = dhd_prot_d2h_sync_edl;
#endif /* EWP_EDL */
		DHD_ERROR(("%s(): D2H sync mechanism is XORCSUM \r\n", __FUNCTION__));
	} else {
		prot->d2h_sync_cb = dhd_prot_d2h_sync_none;
#ifdef EWP_EDL
		prot->d2h_edl_sync_cb = dhd_prot_d2h_sync_edl_none;
#endif /* EWP_EDL */
		DHD_ERROR(("%s(): D2H sync mechanism is NONE \r\n", __FUNCTION__));
	}
}

/**
 * dhd_prot_h2d_sync_init - Per H2D common ring, setup the msgbuf ring seqnum
 */
static void
dhd_prot_h2d_sync_init(dhd_pub_t *dhd)
{
	dhd_prot_t *prot = dhd->prot;
	prot->h2dring_rxp_subn.seqnum = H2D_EPOCH_INIT_VAL;

	if (HWA_ACTIVE(dhd)) {
		prot->h2dring_rxp_subn.hwa_db_type =
			(dhd->bus->hwa_enab_bmap & HWA_ENAB_BITMAP_RXPOST) ? HWA_DB_TYPE_RXPOST : 0;
		DHD_ERROR(("%s: RXPOST hwa_db_type:0x%x\n",
			__FUNCTION__, prot->d2hring_tx_cpln.hwa_db_type));
	}

	prot->h2dring_rxp_subn.current_phase = 0;

	prot->h2dring_ctrl_subn.seqnum = H2D_EPOCH_INIT_VAL;
	prot->h2dring_ctrl_subn.current_phase = 0;
}

/* +-----------------  End of PCIE DHD H2D DMA SYNC ------------------------+ */

/*
 * +---------------------------------------------------------------------------+
 * PCIE DMA-able buffer. Sets up a dhd_dma_buf_t object, which includes the
 * virtual and physical address, the buffer lenght and the DMA handler.
 * A secdma handler is also included in the dhd_dma_buf object.
 * +---------------------------------------------------------------------------+
 */

static INLINE void
dhd_base_addr_htolpa(sh_addr_t *base_addr, dmaaddr_t pa)
{
	base_addr->low_addr = htol32(PHYSADDRLO(pa));
	base_addr->high_addr = htol32(PHYSADDRHI(pa));
}

/**
 * dhd_dma_buf_audit - Any audits on a DHD DMA Buffer.
 */
static int
dhd_dma_buf_audit(dhd_pub_t *dhd, dhd_dma_buf_t *dma_buf)
{
	uint32 pa_lowaddr, end; /* dongle uses 32bit ptr arithmetic */
	ASSERT(dma_buf);
	pa_lowaddr = PHYSADDRLO(dma_buf->pa);
	ASSERT(PHYSADDRLO(dma_buf->pa) || PHYSADDRHI(dma_buf->pa));
	ASSERT(ISALIGNED(pa_lowaddr, DMA_ALIGN_LEN));
	ASSERT(dma_buf->len != 0);

	/* test 32bit offset arithmetic over dma buffer for loss of carry-over */
	end = (pa_lowaddr + dma_buf->len); /* end address */

	if ((end & 0xFFFFFFFF) < (pa_lowaddr & 0xFFFFFFFF)) { /* exclude carryover */
		DHD_ERROR(("%s: dma_buf %x len %d spans dongle 32bit ptr arithmetic\n",
			__FUNCTION__, pa_lowaddr, dma_buf->len));
		return BCME_ERROR;
	}

	return BCME_OK;
}

/**
 * dhd_dma_buf_alloc - Allocate a cache coherent DMA-able buffer.
 * returns BCME_OK=0 on success
 * returns non-zero negative error value on failure.
 */
int
dhd_dma_buf_alloc(dhd_pub_t *dhd, dhd_dma_buf_t *dma_buf, uint32 buf_len)
{
	uint32 dma_pad = 0;
	osl_t *osh = dhd->osh;
	uint16 dma_align = DMA_ALIGN_LEN;
	uint32 rem = 0;

	ASSERT(dma_buf != NULL);
	ASSERT(dma_buf->va == NULL);
	ASSERT(dma_buf->len == 0);

	/* Pad the buffer length to align to cacheline size. */
	rem = (buf_len % DHD_DMA_PAD);
	dma_pad = rem ? (DHD_DMA_PAD - rem) : 0;

	dma_buf->va = DMA_ALLOC_CONSISTENT(osh, buf_len + dma_pad,
		dma_align, &dma_buf->_alloced, &dma_buf->pa, &dma_buf->dmah);

	if (dma_buf->va == NULL) {
		DHD_ERROR(("%s: buf_len %d, no memory available\n",
			__FUNCTION__, buf_len));
		return BCME_NOMEM;
	}

	dma_buf->len = buf_len; /* not including padded len */

	if (dhd_dma_buf_audit(dhd, dma_buf) != BCME_OK) { /* audit dma buf */
		dhd_dma_buf_free(dhd, dma_buf);
		return BCME_ERROR;
	}

	dhd_dma_buf_reset(dhd, dma_buf); /* zero out and cache flush */

	return BCME_OK;
}

/**
 * dhd_dma_buf_reset - Reset a cache coherent DMA-able buffer.
 */
static void
dhd_dma_buf_reset(dhd_pub_t *dhd, dhd_dma_buf_t *dma_buf)
{
	if ((dma_buf == NULL) || (dma_buf->va == NULL))
		return;

	(void)dhd_dma_buf_audit(dhd, dma_buf);

	/* Zero out the entire buffer and cache flush */
	memset((void*)dma_buf->va, 0, dma_buf->len);
	OSL_CACHE_FLUSH((void *)dma_buf->va, dma_buf->len);
}

/**
 * dhd_dma_buf_free - Free a DMA-able buffer that was previously allocated using
 * dhd_dma_buf_alloc().
 */
void
dhd_dma_buf_free(dhd_pub_t *dhd, dhd_dma_buf_t *dma_buf)
{
	osl_t *osh = dhd->osh;

	ASSERT(dma_buf);

	if (dma_buf->va == NULL)
		return; /* Allow for free invocation, when alloc failed */

	/* DEBUG: dhd_dma_buf_reset(dhd, dma_buf) */
	(void)dhd_dma_buf_audit(dhd, dma_buf);

	/* dma buffer may have been padded at allocation */
	DMA_FREE_CONSISTENT(osh, dma_buf->va, dma_buf->_alloced,
		dma_buf->pa, dma_buf->dmah);

	memset(dma_buf, 0, sizeof(dhd_dma_buf_t));
}

/**
 * dhd_dma_buf_init - Initialize a dhd_dma_buf with speicifed values.
 * Do not use dhd_dma_buf_init to zero out a dhd_dma_buf_t object. Use memset 0.
 */
void
dhd_dma_buf_init(dhd_pub_t *dhd, void *dhd_dma_buf,
	void *va, uint32 len, dmaaddr_t pa, void *dmah, void *secdma)
{
	dhd_dma_buf_t *dma_buf;
	ASSERT(dhd_dma_buf);
	dma_buf = (dhd_dma_buf_t *)dhd_dma_buf;
	dma_buf->va = va;
	dma_buf->len = len;
	dma_buf->pa = pa;
	dma_buf->dmah = dmah;
	dma_buf->secdma = secdma;

	/* Audit user defined configuration */
	(void)dhd_dma_buf_audit(dhd, dma_buf);
}

/* +------------------  End of PCIE DHD DMA BUF ADT ------------------------+ */

/*
 * +---------------------------------------------------------------------------+
 * DHD_MAP_PKTID_LOGGING
 * Logging the PKTID and DMA map/unmap information for the SMMU fault issue
 * debugging in customer platform.
 * +---------------------------------------------------------------------------+
 */

#ifdef DHD_MAP_PKTID_LOGGING
typedef struct dhd_pktid_log_item {
	dmaaddr_t pa;		/* DMA bus address */
	uint64 ts_nsec;		/* Timestamp: nsec */
	uint32 size;		/* DMA map/unmap size */
	uint32 pktid;		/* Packet ID */
	uint8 pkttype;		/* Packet Type */
	uint8 rsvd[7];		/* Reserved for future use */
} dhd_pktid_log_item_t;

typedef struct dhd_pktid_log {
	uint32 items;		/* number of total items */
	uint32 index;		/* index of pktid_log_item */
	dhd_pktid_log_item_t map[0];	/* metadata storage */
} dhd_pktid_log_t;

typedef void * dhd_pktid_log_handle_t; /* opaque handle to pktid log */

#define	MAX_PKTID_LOG				(2048)
#define DHD_PKTID_LOG_ITEM_SZ			(sizeof(dhd_pktid_log_item_t))
#define DHD_PKTID_LOG_SZ(items)			(uint32)((sizeof(dhd_pktid_log_t)) + \
					((DHD_PKTID_LOG_ITEM_SZ) * (items)))

#define DHD_PKTID_LOG_INIT(dhd, hdl)		dhd_pktid_logging_init((dhd), (hdl))
#define DHD_PKTID_LOG_FINI(dhd, hdl)		dhd_pktid_logging_fini((dhd), (hdl))
#define DHD_PKTID_LOG(dhd, hdl, pa, pktid, len, pkttype)	\
	dhd_pktid_logging((dhd), (hdl), (pa), (pktid), (len), (pkttype))
#define DHD_PKTID_LOG_DUMP(dhd)			dhd_pktid_logging_dump((dhd))

static dhd_pktid_log_handle_t *
dhd_pktid_logging_init(dhd_pub_t *dhd, uint32 num_items)
{
	dhd_pktid_log_t *log;
	uint32 log_size;

	log_size = DHD_PKTID_LOG_SZ(num_items);
	log = (dhd_pktid_log_t *)MALLOCZ(dhd->osh, log_size);
	if (log == NULL) {
		DHD_ERROR(("%s: MALLOC failed for size %d\n",
			__FUNCTION__, log_size));
		return (dhd_pktid_log_handle_t *)NULL;
	}

	log->items = num_items;
	log->index = 0;

	return (dhd_pktid_log_handle_t *)log; /* opaque handle */
}

static void
dhd_pktid_logging_fini(dhd_pub_t *dhd, dhd_pktid_log_handle_t *handle)
{
	dhd_pktid_log_t *log;
	uint32 log_size;

	if (handle == NULL) {
		DHD_ERROR(("%s: handle is NULL\n", __FUNCTION__));
		return;
	}

	log = (dhd_pktid_log_t *)handle;
	log_size = DHD_PKTID_LOG_SZ(log->items);
	MFREE(dhd->osh, handle, log_size);
}

static void
dhd_pktid_logging(dhd_pub_t *dhd, dhd_pktid_log_handle_t *handle, dmaaddr_t pa,
	uint32 pktid, uint32 len, uint8 pkttype)
{
	dhd_pktid_log_t *log;
	uint32 idx;

	if (handle == NULL) {
		DHD_ERROR(("%s: handle is NULL\n", __FUNCTION__));
		return;
	}

	log = (dhd_pktid_log_t *)handle;
	idx = log->index;
	log->map[idx].ts_nsec = OSL_LOCALTIME_NS();
	log->map[idx].pa = pa;
	log->map[idx].pktid = pktid;
	log->map[idx].size = len;
	log->map[idx].pkttype = pkttype;
	log->index = (idx + 1) % (log->items);	/* update index */
}

void
dhd_pktid_logging_dump(dhd_pub_t *dhd)
{
	dhd_prot_t *prot = dhd->prot;
	dhd_pktid_log_t *map_log, *unmap_log;
	uint64 ts_sec, ts_usec;

	if (prot == NULL) {
		DHD_ERROR(("%s: prot is NULL\n", __FUNCTION__));
		return;
	}

	map_log = (dhd_pktid_log_t *)(prot->pktid_dma_map);
	unmap_log = (dhd_pktid_log_t *)(prot->pktid_dma_unmap);
	OSL_GET_LOCALTIME(&ts_sec, &ts_usec);
	if (map_log && unmap_log) {
		DHD_ERROR(("%s: map_idx=%d unmap_idx=%d "
			"current time=[%5lu.%06lu]\n", __FUNCTION__,
			map_log->index, unmap_log->index,
			(unsigned long)ts_sec, (unsigned long)ts_usec));
		DHD_ERROR(("%s: pktid_map_log(pa)=0x%llx size=%d, "
			"pktid_unmap_log(pa)=0x%llx size=%d\n", __FUNCTION__,
			(uint64)__virt_to_phys((ulong)(map_log->map)),
			(uint32)(DHD_PKTID_LOG_ITEM_SZ * map_log->items),
			(uint64)__virt_to_phys((ulong)(unmap_log->map)),
			(uint32)(DHD_PKTID_LOG_ITEM_SZ * unmap_log->items)));
	}
}
#endif /* DHD_MAP_PKTID_LOGGING */

/* +-----------------  End of DHD_MAP_PKTID_LOGGING -----------------------+ */

/*
 * +---------------------------------------------------------------------------+
 * PktId Map: Provides a native packet pointer to unique 32bit PktId mapping.
 * Main purpose is to save memory on the dongle, has other purposes as well.
 * The packet id map, also includes storage for some packet parameters that
 * may be saved. A native packet pointer along with the parameters may be saved
 * and a unique 32bit pkt id will be returned. Later, the saved packet pointer
 * and the metadata may be retrieved using the previously allocated packet id.
 * +---------------------------------------------------------------------------+
 */
#define DHD_PCIE_PKTID
#define MAX_CTRL_PKTID		(1024) /* Maximum number of pktids supported */
#define MAX_RX_PKTID		(1024)
#define MAX_TX_PKTID		(3072 * 12)

/* On Router, the pktptr serves as a pktid. */

#if defined(PROP_TXSTATUS) && !defined(DHD_PCIE_PKTID)
#error "PKTIDMAP must be supported with PROP_TXSTATUS/WLFC"
#endif // endif

/* Enum for marking the buffer color based on usage */
typedef enum dhd_pkttype {
	PKTTYPE_DATA_TX = 0,
	PKTTYPE_DATA_RX,
	PKTTYPE_IOCTL_RX,
	PKTTYPE_EVENT_RX,
	PKTTYPE_INFO_RX,
	/* dhd_prot_pkt_free no check, if pktid reserved and no space avail case */
	PKTTYPE_NO_CHECK,
	PKTTYPE_TSBUF_RX
} dhd_pkttype_t;

#define DHD_PKTID_MIN_AVAIL_COUNT		512U
#define DHD_PKTID_DEPLETED_MAX_COUNT		(DHD_PKTID_MIN_AVAIL_COUNT * 2U)
#define DHD_PKTID_INVALID			(0U)
#define DHD_IOCTL_REQ_PKTID			(0xFFFE)
#define DHD_FAKE_PKTID				(0xFACE)
#define DHD_H2D_DBGRING_REQ_PKTID		0xFFFD
#define DHD_D2H_DBGRING_REQ_PKTID		0xFFFC
#define DHD_H2D_HOSTTS_REQ_PKTID		0xFFFB
#define DHD_H2D_BTLOGRING_REQ_PKTID		0xFFFA
#define DHD_D2H_BTLOGRING_REQ_PKTID		0xFFF9
#define DHD_H2D_SNAPSHOT_UPLOAD_REQ_PKTID	0xFFF8
#ifdef DHD_HP2P
#define DHD_D2H_HPPRING_TXREQ_PKTID		0xFFF7
#define DHD_D2H_HPPRING_RXREQ_PKTID		0xFFF6
#endif /* DHD_HP2P */

#define IS_FLOWRING(ring) \
	((strncmp(ring->name, "h2dflr", sizeof("h2dflr"))) == (0))

typedef void * dhd_pktid_map_handle_t; /* opaque handle to a pktid map */

/* Construct a packet id mapping table, returning an opaque map handle */
static dhd_pktid_map_handle_t *dhd_pktid_map_init(dhd_pub_t *dhd, uint32 num_items);

/* Destroy a packet id mapping table, freeing all packets active in the table */
static void dhd_pktid_map_fini(dhd_pub_t *dhd, dhd_pktid_map_handle_t *map);

#define DHD_NATIVE_TO_PKTID_INIT(dhd, items) dhd_pktid_map_init((dhd), (items))
#define DHD_NATIVE_TO_PKTID_RESET(dhd, map)  dhd_pktid_map_reset((dhd), (map))
#define DHD_NATIVE_TO_PKTID_FINI(dhd, map)   dhd_pktid_map_fini((dhd), (map))
#define DHD_NATIVE_TO_PKTID_FINI_IOCTL(osh, map)  dhd_pktid_map_fini_ioctl((osh), (map))

#ifdef MACOSX_DHD
#undef DHD_PCIE_PKTID
#define DHD_PCIE_PKTID 1
#endif /* MACOSX_DHD */

#if defined(DHD_PCIE_PKTID)
#if defined(MACOSX_DHD)
#define IOCTLRESP_USE_CONSTMEM
static void free_ioctl_return_buffer(dhd_pub_t *dhd, dhd_dma_buf_t *retbuf);
static int  alloc_ioctl_return_buffer(dhd_pub_t *dhd, dhd_dma_buf_t *retbuf);
#endif // endif

/* Determine number of pktids that are available */
static INLINE uint32 dhd_pktid_map_avail_cnt(dhd_pktid_map_handle_t *handle);

/* Allocate a unique pktid against which a pkt and some metadata is saved */
static INLINE uint32 dhd_pktid_map_reserve(dhd_pub_t *dhd, dhd_pktid_map_handle_t *handle,
	void *pkt, dhd_pkttype_t pkttype);
static INLINE void dhd_pktid_map_save(dhd_pub_t *dhd, dhd_pktid_map_handle_t *handle,
	void *pkt, uint32 nkey, dmaaddr_t pa, uint32 len, uint8 dma,
	void *dmah, void *secdma, dhd_pkttype_t pkttype);
static uint32 dhd_pktid_map_alloc(dhd_pub_t *dhd, dhd_pktid_map_handle_t *map,
	void *pkt, dmaaddr_t pa, uint32 len, uint8 dma,
	void *dmah, void *secdma, dhd_pkttype_t pkttype);
/* Return an allocated pktid, retrieving previously saved pkt and metadata */
static void *dhd_pktid_map_free(dhd_pub_t *dhd, dhd_pktid_map_handle_t *map,
	uint32 id, dmaaddr_t *pa, uint32 *len, void **dmah,
	void **secdma, dhd_pkttype_t pkttype, bool rsv_locker);

/*
 * DHD_PKTID_AUDIT_ENABLED: Audit of PktIds in DHD for duplicate alloc and frees
 *
 * DHD_PKTID_AUDIT_MAP: Audit the LIFO or FIFO PktIdMap allocator
 * DHD_PKTID_AUDIT_RING: Audit the pktid during producer/consumer ring operation
 *
 * CAUTION: When DHD_PKTID_AUDIT_ENABLED is defined,
 *    either DHD_PKTID_AUDIT_MAP or DHD_PKTID_AUDIT_RING may be selected.
 */
#if defined(DHD_PKTID_AUDIT_ENABLED)
#define USE_DHD_PKTID_AUDIT_LOCK 1
/* Audit the pktidmap allocator */
/* #define DHD_PKTID_AUDIT_MAP */

/* Audit the pktid during production/consumption of workitems */
#define DHD_PKTID_AUDIT_RING

#if defined(DHD_PKTID_AUDIT_MAP) && defined(DHD_PKTID_AUDIT_RING)
#error "May only enabled audit of MAP or RING, at a time."
#endif /* DHD_PKTID_AUDIT_MAP && DHD_PKTID_AUDIT_RING */

#define DHD_DUPLICATE_ALLOC     1
#define DHD_DUPLICATE_FREE      2
#define DHD_TEST_IS_ALLOC       3
#define DHD_TEST_IS_FREE        4

typedef enum dhd_pktid_map_type {
	DHD_PKTID_MAP_TYPE_CTRL = 1,
	DHD_PKTID_MAP_TYPE_TX,
	DHD_PKTID_MAP_TYPE_RX,
	DHD_PKTID_MAP_TYPE_UNKNOWN
} dhd_pktid_map_type_t;

#ifdef USE_DHD_PKTID_AUDIT_LOCK
#define DHD_PKTID_AUDIT_LOCK_INIT(osh)          dhd_os_spin_lock_init(osh)
#define DHD_PKTID_AUDIT_LOCK_DEINIT(osh, lock)  dhd_os_spin_lock_deinit(osh, lock)
#define DHD_PKTID_AUDIT_LOCK(lock)              dhd_os_spin_lock(lock)
#define DHD_PKTID_AUDIT_UNLOCK(lock, flags)     dhd_os_spin_unlock(lock, flags)
#else
#define DHD_PKTID_AUDIT_LOCK_INIT(osh)          (void *)(1)
#define DHD_PKTID_AUDIT_LOCK_DEINIT(osh, lock)  do { /* noop */ } while (0)
#define DHD_PKTID_AUDIT_LOCK(lock)              0
#define DHD_PKTID_AUDIT_UNLOCK(lock, flags)     do { /* noop */ } while (0)
#endif /* !USE_DHD_PKTID_AUDIT_LOCK */

#endif /* DHD_PKTID_AUDIT_ENABLED */

#define USE_DHD_PKTID_LOCK   1

#ifdef USE_DHD_PKTID_LOCK
#define DHD_PKTID_LOCK_INIT(osh)                dhd_os_spin_lock_init(osh)
#define DHD_PKTID_LOCK_DEINIT(osh, lock)        dhd_os_spin_lock_deinit(osh, lock)
#define DHD_PKTID_LOCK(lock, flags)             (flags) = dhd_os_spin_lock(lock)
#define DHD_PKTID_UNLOCK(lock, flags)           dhd_os_spin_unlock(lock, flags)
#else
#define DHD_PKTID_LOCK_INIT(osh)                (void *)(1)
#define DHD_PKTID_LOCK_DEINIT(osh, lock)	\
	do { \
		BCM_REFERENCE(osh); \
		BCM_REFERENCE(lock); \
	} while (0)
#define DHD_PKTID_LOCK(lock)                    0
#define DHD_PKTID_UNLOCK(lock, flags)           \
	do { \
		BCM_REFERENCE(lock); \
		BCM_REFERENCE(flags); \
	} while (0)
#endif /* !USE_DHD_PKTID_LOCK */

typedef enum dhd_locker_state {
	LOCKER_IS_FREE,
	LOCKER_IS_BUSY,
	LOCKER_IS_RSVD
} dhd_locker_state_t;

/* Packet metadata saved in packet id mapper */

typedef struct dhd_pktid_item {
	dhd_locker_state_t state;  /* tag a locker to be free, busy or reserved */
	uint8       dir;      /* dma map direction (Tx=flush or Rx=invalidate) */
	dhd_pkttype_t pkttype; /* pktlists are maintained based on pkttype */
	uint16      len;      /* length of mapped packet's buffer */
	void        *pkt;     /* opaque native pointer to a packet */
	dmaaddr_t   pa;       /* physical address of mapped packet's buffer */
	void        *dmah;    /* handle to OS specific DMA map */
	void		*secdma;
} dhd_pktid_item_t;

typedef uint32 dhd_pktid_key_t;

typedef struct dhd_pktid_map {
	uint32      items;    /* total items in map */
	uint32      avail;    /* total available items */
	int         failures; /* lockers unavailable count */
	/* Spinlock to protect dhd_pktid_map in process/tasklet context */
	void        *pktid_lock; /* Used when USE_DHD_PKTID_LOCK is defined */

#if defined(DHD_PKTID_AUDIT_ENABLED)
	void		*pktid_audit_lock;
	struct bcm_mwbmap *pktid_audit; /* multi word bitmap based audit */
#endif /* DHD_PKTID_AUDIT_ENABLED */
	dhd_pktid_key_t	*keys; /* map_items +1 unique pkt ids */
	dhd_pktid_item_t lockers[0];           /* metadata storage */
} dhd_pktid_map_t;

/*
 * PktId (Locker) #0 is never allocated and is considered invalid.
 *
 * On request for a pktid, a value DHD_PKTID_INVALID must be treated as a
 * depleted pktid pool and must not be used by the caller.
 *
 * Likewise, a caller must never free a pktid of value DHD_PKTID_INVALID.
 */

#define DHD_PKTID_FREE_LOCKER           (FALSE)
#define DHD_PKTID_RSV_LOCKER            (TRUE)

#define DHD_PKTID_ITEM_SZ               (sizeof(dhd_pktid_item_t))
#define DHD_PKIDMAP_ITEMS(items)        (items)
#define DHD_PKTID_MAP_SZ(items)         (sizeof(dhd_pktid_map_t) + \
	                                     (DHD_PKTID_ITEM_SZ * ((items) + 1)))
#define DHD_PKTIDMAP_KEYS_SZ(items)     (sizeof(dhd_pktid_key_t) * ((items) + 1))

#define DHD_NATIVE_TO_PKTID_RESET_IOCTL(dhd, map)  dhd_pktid_map_reset_ioctl((dhd), (map))

/* Convert a packet to a pktid, and save pkt pointer in busy locker */
#define DHD_NATIVE_TO_PKTID_RSV(dhd, map, pkt, pkttype)    \
	dhd_pktid_map_reserve((dhd), (map), (pkt), (pkttype))
/* Reuse a previously reserved locker to save packet params */
#define DHD_NATIVE_TO_PKTID_SAVE(dhd, map, pkt, nkey, pa, len, dir, dmah, secdma, pkttype) \
	dhd_pktid_map_save((dhd), (map), (void *)(pkt), (nkey), (pa), (uint32)(len), \
		(uint8)(dir), (void *)(dmah), (void *)(secdma), \
		(dhd_pkttype_t)(pkttype))
/* Convert a packet to a pktid, and save packet params in locker */
#define DHD_NATIVE_TO_PKTID(dhd, map, pkt, pa, len, dir, dmah, secdma, pkttype) \
	dhd_pktid_map_alloc((dhd), (map), (void *)(pkt), (pa), (uint32)(len), \
		(uint8)(dir), (void *)(dmah), (void *)(secdma), \
		(dhd_pkttype_t)(pkttype))

/* Convert pktid to a packet, and free the locker */
#define DHD_PKTID_TO_NATIVE(dhd, map, pktid, pa, len, dmah, secdma, pkttype) \
	dhd_pktid_map_free((dhd), (map), (uint32)(pktid), \
		(dmaaddr_t *)&(pa), (uint32 *)&(len), (void **)&(dmah), \
		(void **)&(secdma), (dhd_pkttype_t)(pkttype), DHD_PKTID_FREE_LOCKER)

/* Convert the pktid to a packet, empty locker, but keep it reserved */
#define DHD_PKTID_TO_NATIVE_RSV(dhd, map, pktid, pa, len, dmah, secdma, pkttype) \
	dhd_pktid_map_free((dhd), (map), (uint32)(pktid), \
	                   (dmaaddr_t *)&(pa), (uint32 *)&(len), (void **)&(dmah), \
	                   (void **)&(secdma), (dhd_pkttype_t)(pkttype), DHD_PKTID_RSV_LOCKER)

#define DHD_PKTID_AVAIL(map)                 dhd_pktid_map_avail_cnt(map)

#if defined(DHD_PKTID_AUDIT_ENABLED)

static int
dhd_get_pktid_map_type(dhd_pub_t *dhd, dhd_pktid_map_t *pktid_map)
{
	dhd_prot_t *prot = dhd->prot;
	int pktid_map_type;

	if (pktid_map == prot->pktid_ctrl_map) {
		pktid_map_type = DHD_PKTID_MAP_TYPE_CTRL;
	} else if (pktid_map == prot->pktid_tx_map) {
		pktid_map_type = DHD_PKTID_MAP_TYPE_TX;
	} else if (pktid_map == prot->pktid_rx_map) {
		pktid_map_type = DHD_PKTID_MAP_TYPE_RX;
	} else {
		pktid_map_type = DHD_PKTID_MAP_TYPE_UNKNOWN;
	}

	return pktid_map_type;
}
