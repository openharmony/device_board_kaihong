/*
 * DHD PROP_TXSTATUS Module.
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
 * $Id: dhd_wlfc.c 743239 2018-01-25 08:33:18Z $
 *
 */

#include <typedefs.h>
#include <osl.h>

#include <bcmutils.h>
#include <bcmendian.h>

#include <dngl_stats.h>
#include <dhd.h>

#include <dhd_bus.h>

#include <dhd_dbg.h>
#include <dhd_config.h>
#include <wl_android.h>

#ifdef PROP_TXSTATUS /* a form of flow control between host and dongle */
#include <wlfc_proto.h>
#include <dhd_wlfc.h>
#endif // endif

#ifdef DHDTCPACK_SUPPRESS
#include <dhd_ip.h>
#endif /* DHDTCPACK_SUPPRESS */

/*
 * wlfc naming and lock rules:
 *
 * 1. Private functions name like _dhd_wlfc_XXX, declared as static and avoid wlfc lock operation.
 * 2. Public functions name like dhd_wlfc_XXX, use wlfc lock if needed.
 * 3. Non-Proptxstatus module call public functions only and avoid wlfc lock operation.
 *
 */

#if defined(DHD_WLFC_THREAD)
#define WLFC_THREAD_QUICK_RETRY_WAIT_MS    10      /* 10 msec */
#define WLFC_THREAD_RETRY_WAIT_MS          10000   /* 10 sec */
#endif /* defined (DHD_WLFC_THREAD) */

#ifdef PROP_TXSTATUS

#define DHD_WLFC_QMON_COMPLETE(entry)

/** reordering related */

#if defined(DHD_WLFC_THREAD)
static void
_dhd_wlfc_thread_wakeup(dhd_pub_t *dhdp)
{
	dhdp->wlfc_thread_go = TRUE;
	wake_up_interruptible(&dhdp->wlfc_wqhead);
}
#endif /* DHD_WLFC_THREAD */

static uint16
_dhd_wlfc_adjusted_seq(void* p, uint8 current_seq)
{
	uint16 seq;

	if (!p) {
		return 0xffff;
	}

	seq = WL_TXSTATUS_GET_FREERUNCTR(DHD_PKTTAG_H2DTAG(PKTTAG(p)));
	if (seq < current_seq) {
		/* wrap around */
		seq += 256;
	}

	return seq;
}

/**
 * Enqueue a caller supplied packet on a caller supplied precedence queue, optionally reorder
 * suppressed packets.
 *    @param[in] pq       caller supplied packet queue to enqueue the packet on
 *    @param[in] prec     precedence of the to-be-queued packet
 *    @param[in] p        transmit packet to enqueue
 *    @param[in] qHead    if TRUE, enqueue to head instead of tail. Used to maintain d11 seq order.
 *    @param[in] current_seq
 *    @param[in] reOrder  reOrder on odd precedence (=suppress queue)
 */
static void
_dhd_wlfc_prec_enque(struct pktq *pq, int prec, void* p, bool qHead,
	uint8 current_seq, bool reOrder)
{
	struct pktq_prec *q;
	uint16 seq, seq2;
	void *p2, *p2_prev;

	if (!p)
		return;

	ASSERT(prec >= 0 && prec < pq->num_prec);
	ASSERT(PKTLINK(p) == NULL);		/* queueing chains not allowed */

	ASSERT(!pktq_full(pq));
	ASSERT(!pktqprec_full(pq, prec));

	q = &pq->q[prec];

	if (q->head == NULL) {
		/* empty queue */
		q->head = p;
		q->tail = p;
	} else {
		if (reOrder && (prec & 1)) {
			seq = _dhd_wlfc_adjusted_seq(p, current_seq);
			p2 = qHead ? q->head : q->tail;
			seq2 = _dhd_wlfc_adjusted_seq(p2, current_seq);

			if ((qHead &&((seq+1) > seq2)) || (!qHead && ((seq2+1) > seq))) {
				/* need reorder */
				p2 = q->head;
				p2_prev = NULL;
				seq2 = _dhd_wlfc_adjusted_seq(p2, current_seq);

				while (seq > seq2) {
					p2_prev = p2;
					p2 = PKTLINK(p2);
					if (!p2) {
						break;
					}
					seq2 = _dhd_wlfc_adjusted_seq(p2, current_seq);
				}

				if (p2_prev == NULL) {
					/* insert head */
					PKTSETLINK(p, q->head);
					q->head = p;
				} else if (p2 == NULL) {
					/* insert tail */
					PKTSETLINK(p2_prev, p);
					q->tail = p;
				} else {
					/* insert after p2_prev */
					PKTSETLINK(p, PKTLINK(p2_prev));
					PKTSETLINK(p2_prev, p);
				}
				goto exit;
			}
		}

		if (qHead) {
			PKTSETLINK(p, q->head);
			q->head = p;
		} else {
			PKTSETLINK(q->tail, p);
			q->tail = p;
		}
	}

exit:

	q->n_pkts++;
	pq->n_pkts_tot++;

	if (pq->hi_prec < prec)
		pq->hi_prec = (uint8)prec;
} /* _dhd_wlfc_prec_enque */

/**
 * Create a place to store all packet pointers submitted to the firmware until a status comes back,
 * suppress or otherwise.
 *
 * hang-er: noun, a contrivance on which things are hung, as a hook.
 */
/** @deprecated soon */
static void*
_dhd_wlfc_hanger_create(dhd_pub_t *dhd, int max_items)
{
	int i;
	wlfc_hanger_t* hanger;

	/* allow only up to a specific size for now */
	ASSERT(max_items == WLFC_HANGER_MAXITEMS);

	if ((hanger = (wlfc_hanger_t*)DHD_OS_PREALLOC(dhd, DHD_PREALLOC_DHD_WLFC_HANGER,
		WLFC_HANGER_SIZE(max_items))) == NULL) {
		return NULL;
	}
	memset(hanger, 0, WLFC_HANGER_SIZE(max_items));
	hanger->max_items = max_items;

	for (i = 0; i < hanger->max_items; i++) {
		hanger->items[i].state = WLFC_HANGER_ITEM_STATE_FREE;
	}
	return hanger;
}

/** @deprecated soon */
static int
_dhd_wlfc_hanger_delete(dhd_pub_t *dhd, void* hanger)
{
	wlfc_hanger_t* h = (wlfc_hanger_t*)hanger;

	if (h) {
		DHD_OS_PREFREE(dhd, h, WLFC_HANGER_SIZE(h->max_items));
		return BCME_OK;
	}
	return BCME_BADARG;
}

/** @deprecated soon */
static uint16
_dhd_wlfc_hanger_get_free_slot(void* hanger)
{
	uint32 i;
	wlfc_hanger_t* h = (wlfc_hanger_t*)hanger;

	if (h) {
		i = h->slot_pos + 1;
		if (i == h->max_items) {
			i = 0;
		}
		while (i != h->slot_pos) {
			if (h->items[i].state == WLFC_HANGER_ITEM_STATE_FREE) {
				h->slot_pos = i;
				return (uint16)i;
			}
			i++;
			if (i == h->max_items)
				i = 0;
		}
		h->failed_slotfind++;
	}
	return WLFC_HANGER_MAXITEMS;
}

/** @deprecated soon */
static int
_dhd_wlfc_hanger_get_genbit(void* hanger, void* pkt, uint32 slot_id, int* gen)
{
	int rc = BCME_OK;
	wlfc_hanger_t* h = (wlfc_hanger_t*)hanger;

	*gen = 0xff;

	/* this packet was not pushed at the time it went to the firmware */
	if (slot_id == WLFC_HANGER_MAXITEMS)
		return BCME_NOTFOUND;

	if (h) {
		if (h->items[slot_id].state != WLFC_HANGER_ITEM_STATE_FREE) {
			*gen = h->items[slot_id].gen;
		}
		else {
			DHD_ERROR(("Error: %s():%d item not used\n",
				__FUNCTION__, __LINE__));
			rc = BCME_NOTFOUND;
		}

	} else {
		rc = BCME_BADARG;
	}

	return rc;
}

/** @deprecated soon */
static int
_dhd_wlfc_hanger_pushpkt(void* hanger, void* pkt, uint32 slot_id)
{
	int rc = BCME_OK;
	wlfc_hanger_t* h = (wlfc_hanger_t*)hanger;

	if (h && (slot_id < WLFC_HANGER_MAXITEMS)) {
		if (h->items[slot_id].state == WLFC_HANGER_ITEM_STATE_FREE) {
			h->items[slot_id].state = WLFC_HANGER_ITEM_STATE_INUSE;
			h->items[slot_id].pkt = pkt;
			h->items[slot_id].pkt_state = 0;
			h->items[slot_id].pkt_txstatus = 0;
			h->pushed++;
		} else {
			h->failed_to_push++;
			rc = BCME_NOTFOUND;
		}
	} else {
		rc = BCME_BADARG;
	}

	return rc;
}

/** @deprecated soon */
static int
_dhd_wlfc_hanger_poppkt(void* hanger, uint32 slot_id, void** pktout, bool remove_from_hanger)
{
	int rc = BCME_OK;
	wlfc_hanger_t* h = (wlfc_hanger_t*)hanger;

	*pktout = NULL;

	/* this packet was not pushed at the time it went to the firmware */
	if (slot_id == WLFC_HANGER_MAXITEMS)
		return BCME_NOTFOUND;

	if (h) {
		if (h->items[slot_id].state != WLFC_HANGER_ITEM_STATE_FREE) {
			*pktout = h->items[slot_id].pkt;
			if (remove_from_hanger) {
				h->items[slot_id].state =
					WLFC_HANGER_ITEM_STATE_FREE;
				h->items[slot_id].pkt = NULL;
				h->items[slot_id].gen = 0xff;
				h->items[slot_id].identifier = 0;
				h->popped++;
			}
		} else {
			h->failed_to_pop++;
			rc = BCME_NOTFOUND;
		}
	} else {
		rc = BCME_BADARG;
	}

	return rc;
}

/** @deprecated soon */
static int
_dhd_wlfc_hanger_mark_suppressed(void* hanger, uint32 slot_id, uint8 gen)
{
	int rc = BCME_OK;
	wlfc_hanger_t* h = (wlfc_hanger_t*)hanger;

	/* this packet was not pushed at the time it went to the firmware */
	if (slot_id == WLFC_HANGER_MAXITEMS)
		return BCME_NOTFOUND;
	if (h) {
		h->items[slot_id].gen = gen;
		if (h->items[slot_id].state == WLFC_HANGER_ITEM_STATE_INUSE) {
			h->items[slot_id].state = WLFC_HANGER_ITEM_STATE_INUSE_SUPPRESSED;
		} else {
			rc = BCME_BADARG;
		}
	} else {
		rc = BCME_BADARG;
	}

	return rc;
}

/** remove reference of specific packet in hanger */
/** @deprecated soon */
static bool
_dhd_wlfc_hanger_remove_reference(wlfc_hanger_t* h, void* pkt)
{
	int i;

	if (!h || !pkt) {
		return FALSE;
	}

	i = WL_TXSTATUS_GET_HSLOT(DHD_PKTTAG_H2DTAG(PKTTAG(pkt)));

	if ((i < h->max_items) && (pkt == h->items[i].pkt)) {
		if (h->items[i].state == WLFC_HANGER_ITEM_STATE_INUSE_SUPPRESSED) {
			h->items[i].state = WLFC_HANGER_ITEM_STATE_FREE;
			h->items[i].pkt = NULL;
			h->items[i].gen = 0xff;
			h->items[i].identifier = 0;
			return TRUE;
		} else {
			DHD_ERROR(("Error: %s():%d item not suppressed\n",
				__FUNCTION__, __LINE__));
		}
	}

	return FALSE;
}

/** afq = At Firmware Queue, queue containing packets pending in the dongle */
static int
_dhd_wlfc_enque_afq(athost_wl_status_info_t* ctx, void *p)
{
	wlfc_mac_descriptor_t* entry;
	uint16 entry_idx = WL_TXSTATUS_GET_HSLOT(DHD_PKTTAG_H2DTAG(PKTTAG(p)));
	uint8 prec = DHD_PKTTAG_FIFO(PKTTAG(p));

	if (entry_idx < WLFC_MAC_DESC_TABLE_SIZE)
		entry  = &ctx->destination_entries.nodes[entry_idx];
	else if (entry_idx < (WLFC_MAC_DESC_TABLE_SIZE + WLFC_MAX_IFNUM))
		entry = &ctx->destination_entries.interfaces[entry_idx - WLFC_MAC_DESC_TABLE_SIZE];
	else
		entry = &ctx->destination_entries.other;

	pktq_penq(&entry->afq, prec, p);

	return BCME_OK;
}

/** afq = At Firmware Queue, queue containing packets pending in the dongle */
static int
_dhd_wlfc_deque_afq(athost_wl_status_info_t* ctx, uint16 hslot, uint8 hcnt, uint8 prec,
	void **pktout)
{
	wlfc_mac_descriptor_t *entry;
	struct pktq *pq;
	struct pktq_prec *q;
	void *p, *b;

	if (!ctx) {
		DHD_ERROR(("%s: ctx(%p), pktout(%p)\n", __FUNCTION__, ctx, pktout));
		return BCME_BADARG;
	}

	if (pktout) {
		*pktout = NULL;
	}

	ASSERT(hslot < (WLFC_MAC_DESC_TABLE_SIZE + WLFC_MAX_IFNUM + 1));

	if (hslot < WLFC_MAC_DESC_TABLE_SIZE)
		entry  = &ctx->destination_entries.nodes[hslot];
	else if (hslot < (WLFC_MAC_DESC_TABLE_SIZE + WLFC_MAX_IFNUM))
		entry = &ctx->destination_entries.interfaces[hslot - WLFC_MAC_DESC_TABLE_SIZE];
	else
		entry = &ctx->destination_entries.other;

	pq = &entry->afq;

	ASSERT(prec < pq->num_prec);

	q = &pq->q[prec];

	b = NULL;
	p = q->head;

	while (p && (hcnt != WL_TXSTATUS_GET_FREERUNCTR(DHD_PKTTAG_H2DTAG(PKTTAG(p)))))
	{
		b = p;
		p = PKTLINK(p);
	}

	if (p == NULL) {
		/* none is matched */
		if (b) {
			DHD_ERROR(("%s: can't find matching seq(%d)\n", __FUNCTION__, hcnt));
		} else {
			DHD_ERROR(("%s: queue is empty\n", __FUNCTION__));
		}

		return BCME_ERROR;
	}

	bcm_pkt_validate_chk(p);

	if (!b) {
		/* head packet is matched */
		if ((q->head = PKTLINK(p)) == NULL) {
			q->tail = NULL;
		}
	} else {
		/* middle packet is matched */
		DHD_INFO(("%s: out of order, seq(%d), head_seq(%d)\n", __FUNCTION__, hcnt,
			WL_TXSTATUS_GET_FREERUNCTR(DHD_PKTTAG_H2DTAG(PKTTAG(q->head)))));
		ctx->stats.ooo_pkts[prec]++;
		PKTSETLINK(b, PKTLINK(p));
		if (PKTLINK(p) == NULL) {
			q->tail = b;
		}
	}

	q->n_pkts--;
	pq->n_pkts_tot--;

#ifdef WL_TXQ_STALL
	q->dequeue_count++;
#endif // endif

	PKTSETLINK(p, NULL);

	if (pktout) {
		*pktout = p;
	}

	return BCME_OK;
} /* _dhd_wlfc_deque_afq */

/**
 * Flow control information piggy backs on packets, in the form of one or more TLVs. This function
 * pushes one or more TLVs onto a packet that is going to be sent towards the dongle.
 *
 *     @param[in]     ctx
 *     @param[in/out] packet
 *     @param[in]     tim_signal TRUE if parameter 'tim_bmp' is valid
 *     @param[in]     tim_bmp
 *     @param[in]     mac_handle
 *     @param[in]     htodtag
 *     @param[in]     htodseq d11 seqno for seqno reuse, only used if 'seq reuse' was agreed upon
 *                    earlier between host and firmware.
 *     @param[in]     skip_wlfc_hdr
 */
static int
_dhd_wlfc_pushheader(athost_wl_status_info_t* ctx, void** packet, bool tim_signal,
	uint8 tim_bmp, uint8 mac_handle, uint32 htodtag, uint16 htodseq, bool skip_wlfc_hdr)
{
	uint32 wl_pktinfo = 0;
	uint8* wlh;
	uint8 dataOffset = 0;
	uint8 fillers;
	uint8 tim_signal_len = 0;
	dhd_pub_t *dhdp = (dhd_pub_t *)ctx->dhdp;

	struct bdc_header *h;
	void *p = *packet;

	if (skip_wlfc_hdr)
		goto push_bdc_hdr;

	if (tim_signal) {
		tim_signal_len = TLV_HDR_LEN + WLFC_CTL_VALUE_LEN_PENDING_TRAFFIC_BMP;
	}

	/* +2 is for Type[1] and Len[1] in TLV, plus TIM signal */
	dataOffset = WLFC_CTL_VALUE_LEN_PKTTAG + TLV_HDR_LEN + tim_signal_len;
	if (WLFC_GET_REUSESEQ(dhdp->wlfc_mode)) {
		dataOffset += WLFC_CTL_VALUE_LEN_SEQ;
	}

	fillers = ROUNDUP(dataOffset, 4) - dataOffset;
	dataOffset += fillers;

	PKTPUSH(ctx->osh, p, dataOffset);
	wlh = (uint8*) PKTDATA(ctx->osh, p);

	wl_pktinfo = htol32(htodtag);

	wlh[TLV_TAG_OFF] = WLFC_CTL_TYPE_PKTTAG;
	wlh[TLV_LEN_OFF] = WLFC_CTL_VALUE_LEN_PKTTAG;
	memcpy(&wlh[TLV_HDR_LEN] /* dst */, &wl_pktinfo, sizeof(uint32));

	if (WLFC_GET_REUSESEQ(dhdp->wlfc_mode)) {
		uint16 wl_seqinfo = htol16(htodseq);
		wlh[TLV_LEN_OFF] += WLFC_CTL_VALUE_LEN_SEQ;
		memcpy(&wlh[TLV_HDR_LEN + WLFC_CTL_VALUE_LEN_PKTTAG], &wl_seqinfo,
			WLFC_CTL_VALUE_LEN_SEQ);
	}

	if (tim_signal_len) {
		wlh[dataOffset - fillers - tim_signal_len ] =
			WLFC_CTL_TYPE_PENDING_TRAFFIC_BMP;
		wlh[dataOffset - fillers - tim_signal_len + 1] =
			WLFC_CTL_VALUE_LEN_PENDING_TRAFFIC_BMP;
		wlh[dataOffset - fillers - tim_signal_len + 2] = mac_handle;
		wlh[dataOffset - fillers - tim_signal_len + 3] = tim_bmp;
	}
	if (fillers)
		memset(&wlh[dataOffset - fillers], WLFC_CTL_TYPE_FILLER, fillers);

push_bdc_hdr:
	PKTPUSH(ctx->osh, p, BDC_HEADER_LEN);
	h = (struct bdc_header *)PKTDATA(ctx->osh, p);
	h->flags = (BDC_PROTO_VER << BDC_FLAG_VER_SHIFT);
	if (PKTSUMNEEDED(p))
		h->flags |= BDC_FLAG_SUM_NEEDED;

	h->priority = (PKTPRIO(p) & BDC_PRIORITY_MASK);
	h->flags2 = 0;
	h->dataOffset = dataOffset >> 2;
	BDC_SET_IF_IDX(h, DHD_PKTTAG_IF(PKTTAG(p)));
	*packet = p;
	return BCME_OK;
} /* _dhd_wlfc_pushheader */

/**
 * Removes (PULLs) flow control related headers from the caller supplied packet, is invoked eg
 * when a packet is about to be freed.
 */
static int
_dhd_wlfc_pullheader(athost_wl_status_info_t* ctx, void* pktbuf)
{
	struct bdc_header *h;

	if (PKTLEN(ctx->osh, pktbuf) < BDC_HEADER_LEN) {
		DHD_ERROR(("%s: rx data too short (%d < %d)\n", __FUNCTION__,
		           PKTLEN(ctx->osh, pktbuf), BDC_HEADER_LEN));
		return BCME_ERROR;
	}
	h = (struct bdc_header *)PKTDATA(ctx->osh, pktbuf);

	/* pull BDC header */
	PKTPULL(ctx->osh, pktbuf, BDC_HEADER_LEN);

	if (PKTLEN(ctx->osh, pktbuf) < (uint)(h->dataOffset << 2)) {
		DHD_ERROR(("%s: rx data too short (%d < %d)\n", __FUNCTION__,
		           PKTLEN(ctx->osh, pktbuf), (h->dataOffset << 2)));
		return BCME_ERROR;
	}

	/* pull wl-header */
	PKTPULL(ctx->osh, pktbuf, (h->dataOffset << 2));
	return BCME_OK;
}

/**
 * @param[in/out] p packet
 */
static wlfc_mac_descriptor_t*
_dhd_wlfc_find_table_entry(athost_wl_status_info_t* ctx, void* p)
{
	int i;
	wlfc_mac_descriptor_t* table = ctx->destination_entries.nodes;
	uint8 ifid = DHD_PKTTAG_IF(PKTTAG(p));
	uint8* dstn = DHD_PKTTAG_DSTN(PKTTAG(p));
	wlfc_mac_descriptor_t* entry = DHD_PKTTAG_ENTRY(PKTTAG(p));
	int iftype = ctx->destination_entries.interfaces[ifid].iftype;

	/* saved one exists, return it */
	if (entry)
		return entry;

	/* Multicast destination, STA and P2P clients get the interface entry.
	 * STA/GC gets the Mac Entry for TDLS destinations, TDLS destinations
	 * have their own entry.
	 */
	if ((iftype == WLC_E_IF_ROLE_STA || ETHER_ISMULTI(dstn) ||
		iftype == WLC_E_IF_ROLE_P2P_CLIENT) &&
		(ctx->destination_entries.interfaces[ifid].occupied)) {
			entry = &ctx->destination_entries.interfaces[ifid];
	}

	if (entry && ETHER_ISMULTI(dstn)) {
		DHD_PKTTAG_SET_ENTRY(PKTTAG(p), entry);
		return entry;
	}

	for (i = 0; i < WLFC_MAC_DESC_TABLE_SIZE; i++) {
		if (table[i].occupied) {
			if (table[i].interface_id == ifid) {
				if (!memcmp(table[i].ea, dstn, ETHER_ADDR_LEN)) {
					entry = &table[i];
					break;
				}
			}
		}
	}

	if (entry == NULL)
		entry = &ctx->destination_entries.other;

	DHD_PKTTAG_SET_ENTRY(PKTTAG(p), entry);

	return entry;
} /* _dhd_wlfc_find_table_entry */

/**
 * In case a packet must be dropped (because eg the queues are full), various tallies have to be
 * be updated. Called from several other functions.
 *     @param[in] dhdp pointer to public DHD structure
 *     @param[in] prec precedence of the packet
 *     @param[in] p    the packet to be dropped
 *     @param[in] bPktInQ TRUE if packet is part of a queue
 */
static int
_dhd_wlfc_prec_drop(dhd_pub_t *dhdp, int prec, void* p, bool bPktInQ)
{
	athost_wl_status_info_t* ctx;
	void *pout = NULL;

	ASSERT(dhdp && p);
	if (prec < 0 || prec >= WLFC_PSQ_PREC_COUNT) {
		ASSERT(0);
		return BCME_BADARG;
	}

	ctx = (athost_wl_status_info_t*)dhdp->wlfc_state;

	if (!WLFC_GET_AFQ(dhdp->wlfc_mode) && (prec & 1)) {
		/* suppressed queue, need pop from hanger */
		_dhd_wlfc_hanger_poppkt(ctx->hanger, WL_TXSTATUS_GET_HSLOT(DHD_PKTTAG_H2DTAG
					(PKTTAG(p))), &pout, TRUE);
		ASSERT(p == pout);
	}

	if (!(prec & 1)) {
#ifdef DHDTCPACK_SUPPRESS
		/* pkt in delayed q, so fake push BDC header for
		 * dhd_tcpack_check_xmit() and dhd_txcomplete().
		 */
		_dhd_wlfc_pushheader(ctx, &p, FALSE, 0, 0, 0, 0, TRUE);

		/* This packet is about to be freed, so remove it from tcp_ack_info_tbl
		 * This must be one of...
		 * 1. A pkt already in delayQ is evicted by another pkt with higher precedence
		 * in _dhd_wlfc_prec_enq_with_drop()
		 * 2. A pkt could not be enqueued to delayQ because it is full,
		 * in _dhd_wlfc_enque_delayq().
		 * 3. A pkt could not be enqueued to delayQ because it is full,
		 * in _dhd_wlfc_rollback_packet_toq().
		 */
		if (dhd_tcpack_check_xmit(dhdp, p) == BCME_ERROR) {
			DHD_ERROR(("%s %d: tcpack_suppress ERROR!!!"
				" Stop using it\n",
				__FUNCTION__, __LINE__));
			dhd_tcpack_suppress_set(dhdp, TCPACK_SUP_OFF);
		}
#endif /* DHDTCPACK_SUPPRESS */
	}

	if (bPktInQ) {
		ctx->pkt_cnt_in_q[DHD_PKTTAG_IF(PKTTAG(p))][prec>>1]--;
		ctx->pkt_cnt_per_ac[prec>>1]--;
		ctx->pkt_cnt_in_psq--;
	}

	ctx->pkt_cnt_in_drv[DHD_PKTTAG_IF(PKTTAG(p))][DHD_PKTTAG_FIFO(PKTTAG(p))]--;
	ctx->stats.pktout++;
	ctx->stats.drop_pkts[prec]++;

	dhd_txcomplete(dhdp, p, FALSE);
	PKTFREE(ctx->osh, p, TRUE);

	return 0;
} /* _dhd_wlfc_prec_drop */

/**
 * Called when eg the host handed a new packet over to the driver, or when the dongle reported
 * that a packet could currently not be transmitted (=suppressed). This function enqueues a transmit
 * packet in the host driver to be (re)transmitted at a later opportunity.
 *     @param[in] dhdp pointer to public DHD structure
 *     @param[in] qHead When TRUE, queue packet at head instead of tail, to preserve d11 sequence
 */
static bool
_dhd_wlfc_prec_enq_with_drop(dhd_pub_t *dhdp, struct pktq *pq, void *pkt, int prec, bool qHead,
	uint8 current_seq)
{
	void *p = NULL;
	int eprec = -1;		/* precedence to evict from */
	athost_wl_status_info_t* ctx;

	ASSERT(dhdp && pq && pkt);
	ASSERT(prec >= 0 && prec < pq->num_prec);

	ctx = (athost_wl_status_info_t*)dhdp->wlfc_state;

	/* Fast case, precedence queue is not full and we are also not
	 * exceeding total queue length
	 */
	if (!pktqprec_full(pq, prec) && !pktq_full(pq)) {
		goto exit;
	}

	/* Determine precedence from which to evict packet, if any */
	if (pktqprec_full(pq, prec)) {
		eprec = prec;
	} else if (pktq_full(pq)) {
		p = pktq_peek_tail(pq, &eprec);
		if (!p) {
			DHD_ERROR(("Error: %s():%d\n", __FUNCTION__, __LINE__));
			return FALSE;
		}
		if ((eprec > prec) || (eprec < 0)) {
			if (!pktqprec_empty(pq, prec)) {
				eprec = prec;
			} else {
				return FALSE;
			}
		}
	}

	/* Evict if needed */
	if (eprec >= 0) {
		/* Detect queueing to unconfigured precedence */
		ASSERT(!pktqprec_empty(pq, eprec));
		/* Evict all fragmented frames */
		dhd_prec_drop_pkts(dhdp, pq, eprec, _dhd_wlfc_prec_drop);
	}

exit:
	/* Enqueue */
	_dhd_wlfc_prec_enque(pq, prec, pkt, qHead, current_seq,
		WLFC_GET_REORDERSUPP(dhdp->wlfc_mode));
	ctx->pkt_cnt_in_q[DHD_PKTTAG_IF(PKTTAG(pkt))][prec>>1]++;
	ctx->pkt_cnt_per_ac[prec>>1]++;
	ctx->pkt_cnt_in_psq++;

	return TRUE;
} /* _dhd_wlfc_prec_enq_with_drop */

/**
 * Called during eg the 'committing' of a transmit packet from the OS layer to a lower layer, in
 * the event that this 'commit' failed.
 */
static int
_dhd_wlfc_rollback_packet_toq(athost_wl_status_info_t* ctx,
	void* p, ewlfc_packet_state_t pkt_type, uint32 hslot)
{
	/*
	 * put the packet back to the head of queue
	 * - suppressed packet goes back to suppress sub-queue
	 * - pull out the header, if new or delayed packet
	 *
	 * Note: hslot is used only when header removal is done.
	 */
	wlfc_mac_descriptor_t* entry;
	int rc = BCME_OK;
	int prec, fifo_id;

	entry = _dhd_wlfc_find_table_entry(ctx, p);
	prec = DHD_PKTTAG_FIFO(PKTTAG(p));
	fifo_id = prec << 1;
	if (pkt_type == eWLFC_PKTTYPE_SUPPRESSED)
		fifo_id += 1;
	if (entry != NULL) {
		/*
		if this packet did not count against FIFO credit, it must have
		taken a requested_credit from the firmware (for pspoll etc.)
		*/
		if ((prec != AC_COUNT) && !DHD_PKTTAG_CREDITCHECK(PKTTAG(p)))
			entry->requested_credit++;

		if (pkt_type == eWLFC_PKTTYPE_DELAYED) {
			/* decrement sequence count */
			WLFC_DECR_SEQCOUNT(entry, prec);
			/* remove header first */
			rc = _dhd_wlfc_pullheader(ctx, p);
			if (rc != BCME_OK) {
				DHD_ERROR(("Error: %s():%d\n", __FUNCTION__, __LINE__));
				goto exit;
			}
		}

		if (_dhd_wlfc_prec_enq_with_drop(ctx->dhdp, &entry->psq, p, fifo_id, TRUE,
			WLFC_SEQCOUNT(entry, fifo_id>>1))
			== FALSE) {
			/* enque failed */
			DHD_ERROR(("Error: %s():%d, fifo_id(%d)\n",
				__FUNCTION__, __LINE__, fifo_id));
			rc = BCME_ERROR;
		}
	} else {
		DHD_ERROR(("Error: %s():%d\n", __FUNCTION__, __LINE__));
		rc = BCME_ERROR;
	}

exit:
	if (rc != BCME_OK) {
		ctx->stats.rollback_failed++;
		_dhd_wlfc_prec_drop(ctx->dhdp, fifo_id, p, FALSE);
	} else {
		ctx->stats.rollback++;
	}

	return rc;
} /* _dhd_wlfc_rollback_packet_toq */

/** Returns TRUE if host OS -> DHD flow control is allowed on the caller supplied interface */
static bool
_dhd_wlfc_allow_fc(athost_wl_status_info_t* ctx, uint8 ifid)
{
	int prec, ac_traffic = WLFC_NO_TRAFFIC;

	for (prec = 0; prec < AC_COUNT; prec++) {
		if (ctx->pkt_cnt_in_drv[ifid][prec] > 0) {
			if (ac_traffic == WLFC_NO_TRAFFIC)
				ac_traffic = prec + 1;
			else if (ac_traffic != (prec + 1))
				ac_traffic = WLFC_MULTI_TRAFFIC;
		}
	}

	if (ac_traffic >= 1 && ac_traffic <= AC_COUNT) {
		/* single AC (BE/BK/VI/VO) in queue */
		if (ctx->allow_fc) {
			return TRUE;
		} else {
			uint32 delta;
			uint32 curr_t = OSL_SYSUPTIME();

			if (ctx->fc_defer_timestamp == 0) {
				/* first single ac scenario */
				ctx->fc_defer_timestamp = curr_t;
				return FALSE;
			}

			/* single AC duration, this handles wrap around, e.g. 1 - ~0 = 2. */
			delta = curr_t - ctx->fc_defer_timestamp;
			if (delta >= WLFC_FC_DEFER_PERIOD_MS) {
				ctx->allow_fc = TRUE;
			}
		}
	} else {
		/* multiple ACs or BCMC in queue */
		ctx->allow_fc = FALSE;
		ctx->fc_defer_timestamp = 0;
	}

	return ctx->allow_fc;
} /* _dhd_wlfc_allow_fc */

/**
 * Starts or stops the flow of transmit packets from the host OS towards the DHD, depending on
 * low/high watermarks.
 */
static void
_dhd_wlfc_flow_control_check(athost_wl_status_info_t* ctx, struct pktq* pq, uint8 if_id)
{
	dhd_pub_t *dhdp;

	ASSERT(ctx);

	dhdp = (dhd_pub_t *)ctx->dhdp;
	ASSERT(dhdp);

	if (dhdp->skip_fc && dhdp->skip_fc((void *)dhdp, if_id))
		return;

	if ((ctx->hostif_flow_state[if_id] == OFF) && !_dhd_wlfc_allow_fc(ctx, if_id))
		return;

	if ((pq->n_pkts_tot <= WLFC_FLOWCONTROL_LOWATER) && (ctx->hostif_flow_state[if_id] == ON)) {
		/* start traffic */
		ctx->hostif_flow_state[if_id] = OFF;
		/*
		WLFC_DBGMESG(("qlen:%02d, if:%02d, ->OFF, start traffic %s()\n",
		pq->n_pkts_tot, if_id, __FUNCTION__));
		*/
		WLFC_DBGMESG(("F"));

		dhd_txflowcontrol(dhdp, if_id, OFF);

		ctx->toggle_host_if = 0;
	}

	if (pq->n_pkts_tot >= WLFC_FLOWCONTROL_HIWATER && ctx->hostif_flow_state[if_id] == OFF) {
		/* stop traffic */
		ctx->hostif_flow_state[if_id] = ON;
		/*
		WLFC_DBGMESG(("qlen:%02d, if:%02d, ->ON, stop traffic   %s()\n",
		pq->n_pkts_tot, if_id, __FUNCTION__));
		*/
		WLFC_DBGMESG(("N"));

		dhd_txflowcontrol(dhdp, if_id, ON);

		ctx->host_ifidx = if_id;
		ctx->toggle_host_if = 1;
	}

	return;
} /* _dhd_wlfc_flow_control_check */

static int
_dhd_wlfc_send_signalonly_packet(athost_wl_status_info_t* ctx, wlfc_mac_descriptor_t* entry,
	uint8 ta_bmp)
{
	int rc = BCME_OK;
	void* p = NULL;
	int dummylen = ((dhd_pub_t *)ctx->dhdp)->hdrlen+ 16;
	dhd_pub_t *dhdp = (dhd_pub_t *)ctx->dhdp;

	if (dhdp->proptxstatus_txoff) {
		rc = BCME_NORESOURCE;
		return rc;
	}

	/* allocate a dummy packet */
	p = PKTGET(ctx->osh, dummylen, TRUE);
	if (p) {
		PKTPULL(ctx->osh, p, dummylen);
		DHD_PKTTAG_SET_H2DTAG(PKTTAG(p), 0);
		_dhd_wlfc_pushheader(ctx, &p, TRUE, ta_bmp, entry->mac_handle, 0, 0, FALSE);
		DHD_PKTTAG_SETSIGNALONLY(PKTTAG(p), 1);
		DHD_PKTTAG_WLFCPKT_SET(PKTTAG(p), 1);
#ifdef PROP_TXSTATUS_DEBUG
		ctx->stats.signal_only_pkts_sent++;
#endif // endif

#if defined(BCMPCIE)
		rc = dhd_bus_txdata(dhdp->bus, p, ctx->host_ifidx);
#else
		rc = dhd_bus_txdata(dhdp->bus, p);
#endif // endif
		if (rc != BCME_OK) {
			_dhd_wlfc_pullheader(ctx, p);
			PKTFREE(ctx->osh, p, TRUE);
		}
	} else {
		DHD_ERROR(("%s: couldn't allocate new %d-byte packet\n",
		           __FUNCTION__, dummylen));
		rc = BCME_NOMEM;
		dhdp->tx_pktgetfail++;
	}

	return rc;
} /* _dhd_wlfc_send_signalonly_packet */

/**
 * Called on eg receiving 'mac close' indication from dongle. Updates the per-MAC administration
 * maintained in caller supplied parameter 'entry'.
 *
 *    @param[in/out] entry  administration about a remote MAC entity
 *    @param[in]     prec   precedence queue for this remote MAC entitity
 *
 * Return value: TRUE if traffic availability changed
 */
static bool
_dhd_wlfc_traffic_pending_check(athost_wl_status_info_t* ctx, wlfc_mac_descriptor_t* entry,
	int prec)
{
	bool rc = FALSE;

	if (entry->state == WLFC_STATE_CLOSE) {
		if ((pktqprec_n_pkts(&entry->psq, (prec << 1)) == 0) &&
			(pktqprec_n_pkts(&entry->psq, ((prec << 1) + 1)) == 0)) {
			/* no packets in both 'normal' and 'suspended' queues */
			if (entry->traffic_pending_bmp & NBITVAL(prec)) {
				rc = TRUE;
				entry->traffic_pending_bmp =
					entry->traffic_pending_bmp & ~ NBITVAL(prec);
			}
		} else {
			/* packets are queued in host for transmission to dongle */
			if (!(entry->traffic_pending_bmp & NBITVAL(prec))) {
				rc = TRUE;
				entry->traffic_pending_bmp =
					entry->traffic_pending_bmp | NBITVAL(prec);
			}
		}
	}

	if (rc) {
		/* request a TIM update to firmware at the next piggyback opportunity */
		if (entry->traffic_lastreported_bmp != entry->traffic_pending_bmp) {
			entry->send_tim_signal = 1;
			_dhd_wlfc_send_signalonly_packet(ctx, entry, entry->traffic_pending_bmp);
			entry->traffic_lastreported_bmp = entry->traffic_pending_bmp;
			entry->send_tim_signal = 0;
		} else {
			rc = FALSE;
		}
	}

	return rc;
} /* _dhd_wlfc_traffic_pending_check */

/**
 * Called on receiving a 'd11 suppressed' or 'wl suppressed' tx status from the firmware. Enqueues
 * the packet to transmit to firmware again at a later opportunity.
 */
static int
_dhd_wlfc_enque_suppressed(athost_wl_status_info_t* ctx, int prec, void* p)
{
	wlfc_mac_descriptor_t* entry;

	entry = _dhd_wlfc_find_table_entry(ctx, p);
	if (entry == NULL) {
		DHD_ERROR(("Error: %s():%d\n", __FUNCTION__, __LINE__));
		return BCME_NOTFOUND;
	}
	/*
	- suppressed packets go to sub_queue[2*prec + 1] AND
	- delayed packets go to sub_queue[2*prec + 0] to ensure
	order of delivery.
	*/
	if (_dhd_wlfc_prec_enq_with_drop(ctx->dhdp, &entry->psq, p, ((prec << 1) + 1), FALSE,
		WLFC_SEQCOUNT(entry, prec))
		== FALSE) {
		ctx->stats.delayq_full_error++;
		/* WLFC_DBGMESG(("Error: %s():%d\n", __FUNCTION__, __LINE__)); */
		WLFC_DBGMESG(("s"));
		return BCME_ERROR;
	}

	/* A packet has been pushed, update traffic availability bitmap, if applicable */
	_dhd_wlfc_traffic_pending_check(ctx, entry, prec);
	_dhd_wlfc_flow_control_check(ctx, &entry->psq, DHD_PKTTAG_IF(PKTTAG(p)));
	return BCME_OK;
}

/**
 * Called when a transmit packet is about to be 'committed' from the OS layer to a lower layer
 * towards the dongle (eg the DBUS layer). Updates wlfc administration. May modify packet.
 *
 *     @param[in/out] ctx    driver specific flow control administration
 *     @param[in/out] entry  The remote MAC entity for which the packet is destined.
 *     @param[in/out] packet Packet to send. This function optionally adds TLVs to the packet.
 *     @param[in] header_needed True if packet is 'new' to flow control
 *     @param[out] slot Handle to container in which the packet was 'parked'
 */
static int
_dhd_wlfc_pretx_pktprocess(athost_wl_status_info_t* ctx,
	wlfc_mac_descriptor_t* entry, void** packet, int header_needed, uint32* slot)
{
	int rc = BCME_OK;
	int hslot = WLFC_HANGER_MAXITEMS;
	bool send_tim_update = FALSE;
	uint32 htod = 0;
	uint16 htodseq = 0;
	uint8 free_ctr;
	int gen = 0xff;
	dhd_pub_t *dhdp = (dhd_pub_t *)ctx->dhdp;
	void * p = *packet;

	*slot = hslot;

	if (entry == NULL) {
		entry = _dhd_wlfc_find_table_entry(ctx, p);
	}

	if (entry == NULL) {
		DHD_ERROR(("Error: %s():%d\n", __FUNCTION__, __LINE__));
		return BCME_ERROR;
	}

	if (entry->send_tim_signal) {
		/* sends a traffic indication bitmap to the dongle */
		send_tim_update = TRUE;
		entry->send_tim_signal = 0;
		entry->traffic_lastreported_bmp = entry->traffic_pending_bmp;
	}

	if (header_needed) {
		if (WLFC_GET_AFQ(dhdp->wlfc_mode)) {
			hslot = (uint)(entry - &ctx->destination_entries.nodes[0]);
		} else {
			hslot = _dhd_wlfc_hanger_get_free_slot(ctx->hanger);
		}
		gen = entry->generation;
		free_ctr = WLFC_SEQCOUNT(entry, DHD_PKTTAG_FIFO(PKTTAG(p)));
	} else {
		if (WLFC_GET_REUSESEQ(dhdp->wlfc_mode)) {
			htodseq = DHD_PKTTAG_H2DSEQ(PKTTAG(p));
		}

		hslot = WL_TXSTATUS_GET_HSLOT(DHD_PKTTAG_H2DTAG(PKTTAG(p)));

		if (WLFC_GET_REORDERSUPP(dhdp->wlfc_mode)) {
			gen = entry->generation;
		} else if (WLFC_GET_AFQ(dhdp->wlfc_mode)) {
			gen = WL_TXSTATUS_GET_GENERATION(DHD_PKTTAG_H2DTAG(PKTTAG(p)));
		} else {
			_dhd_wlfc_hanger_get_genbit(ctx->hanger, p, hslot, &gen);
		}

		free_ctr = WL_TXSTATUS_GET_FREERUNCTR(DHD_PKTTAG_H2DTAG(PKTTAG(p)));
		/* remove old header */
		_dhd_wlfc_pullheader(ctx, p);
	}

	if (hslot >= WLFC_HANGER_MAXITEMS) {
		DHD_ERROR(("Error: %s():no hanger slot available\n", __FUNCTION__));
		return BCME_ERROR;
	}

	WL_TXSTATUS_SET_FREERUNCTR(htod, free_ctr);
	WL_TXSTATUS_SET_HSLOT(htod, hslot);
	WL_TXSTATUS_SET_FIFO(htod, DHD_PKTTAG_FIFO(PKTTAG(p)));
	WL_TXSTATUS_SET_FLAGS(htod, WLFC_PKTFLAG_PKTFROMHOST);
	WL_TXSTATUS_SET_GENERATION(htod, gen);
	DHD_PKTTAG_SETPKTDIR(PKTTAG(p), 1);

	if (!DHD_PKTTAG_CREDITCHECK(PKTTAG(p))) {
		/*
		Indicate that this packet is being sent in response to an
		explicit request from the firmware side.
		*/
		WLFC_PKTFLAG_SET_PKTREQUESTED(htod);
	} else {
		WLFC_PKTFLAG_CLR_PKTREQUESTED(htod);
	}

	rc = _dhd_wlfc_pushheader(ctx, &p, send_tim_update,
		entry->traffic_lastreported_bmp, entry->mac_handle, htod, htodseq, FALSE);
	if (rc == BCME_OK) {
		DHD_PKTTAG_SET_H2DTAG(PKTTAG(p), htod);

		if (!WLFC_GET_AFQ(dhdp->wlfc_mode)) {
			wlfc_hanger_t *h = (wlfc_hanger_t*)(ctx->hanger);
			if (header_needed) {
				/*
				a new header was created for this packet.
				push to hanger slot and scrub q. Since bus
				send succeeded, increment seq number as well.
				*/
				rc = _dhd_wlfc_hanger_pushpkt(ctx->hanger, p, hslot);
				if (rc == BCME_OK) {
#ifdef PROP_TXSTATUS_DEBUG
					h->items[hslot].push_time =
						OSL_SYSUPTIME();
#endif // endif
				} else {
					DHD_ERROR(("%s() hanger_pushpkt() failed, rc: %d\n",
						__FUNCTION__, rc));
				}
			} else {
				/* clear hanger state */
				if (((wlfc_hanger_t*)(ctx->hanger))->items[hslot].pkt != p)
					DHD_ERROR(("%s() pkt not match: cur %p, hanger pkt %p\n",
						__FUNCTION__, p, h->items[hslot].pkt));
				ASSERT(h->items[hslot].pkt == p);
				bcm_object_feature_set(h->items[hslot].pkt,
					BCM_OBJECT_FEATURE_PKT_STATE, 0);
				h->items[hslot].pkt_state = 0;
				h->items[hslot].pkt_txstatus = 0;
				h->items[hslot].state = WLFC_HANGER_ITEM_STATE_INUSE;
			}
		}

		if ((rc == BCME_OK) && header_needed) {
			/* increment free running sequence count */
			WLFC_INCR_SEQCOUNT(entry, DHD_PKTTAG_FIFO(PKTTAG(p)));
		}
	}
	*slot = hslot;
	*packet = p;
	return rc;
} /* _dhd_wlfc_pretx_pktprocess */

/**
 * A remote wireless mac may be temporarily 'closed' due to power management. Returns '1' if remote
 * mac is in the 'open' state, otherwise '0'.
 */
static int
_dhd_wlfc_is_destination_open(athost_wl_status_info_t* ctx,
	wlfc_mac_descriptor_t* entry, int prec)
{
	wlfc_mac_descriptor_t* interfaces = ctx->destination_entries.interfaces;

	if (entry->interface_id >= WLFC_MAX_IFNUM) {
		ASSERT(&ctx->destination_entries.other == entry);
		return 1;
	}

	if (interfaces[entry->interface_id].iftype ==
		WLC_E_IF_ROLE_P2P_GO) {
		/* - destination interface is of type p2p GO.
		For a p2pGO interface, if the destination is OPEN but the interface is
		CLOSEd, do not send traffic. But if the dstn is CLOSEd while there is
		destination-specific-credit left send packets. This is because the
		firmware storing the destination-specific-requested packet in queue.
		*/
		if ((entry->state == WLFC_STATE_CLOSE) && (entry->requested_credit == 0) &&
			(entry->requested_packet == 0)) {
			return 0;
		}
	}

	/* AP, p2p_go -> unicast desc entry, STA/p2p_cl -> interface desc. entry */
	if ((((entry->state == WLFC_STATE_CLOSE) ||
		(interfaces[entry->interface_id].state == WLFC_STATE_CLOSE)) &&
		(entry->requested_credit == 0) &&
		(entry->requested_packet == 0)) ||
		(!(entry->ac_bitmap & (1 << prec)))) {
		return 0;
	}

	return 1;
} /* _dhd_wlfc_is_destination_open */

/**
 * Dequeues a suppressed or delayed packet from a queue
 *    @param[in/out] ctx          Driver specific flow control administration
 *    @param[in]  prec            Precedence of queue to dequeue from
 *    @param[out] ac_credit_spent Boolean, returns 0 or 1
 *    @param[out] needs_hdr       Boolean, returns 0 or 1
 *    @param[out] entry_out       The remote MAC for which the packet is destined
 *    @param[in]  only_no_credit  If TRUE, searches all entries instead of just the active ones
 *
 * Return value: the dequeued packet
 */
static void*
_dhd_wlfc_deque_delayedq(athost_wl_status_info_t* ctx, int prec,
	uint8* ac_credit_spent, uint8* needs_hdr, wlfc_mac_descriptor_t** entry_out,
	bool only_no_credit)
{
	wlfc_mac_descriptor_t* entry;
	int total_entries;
	void* p = NULL;
	int i;
	uint8 credit_spent = ((prec == AC_COUNT) && !ctx->bcmc_credit_supported) ? 0 : 1;

	*entry_out = NULL;
	/* most cases a packet will count against FIFO credit */
	*ac_credit_spent = credit_spent;

	/* search all entries, include nodes as well as interfaces */
	if (only_no_credit) {
		total_entries = ctx->requested_entry_count;
	} else {
		total_entries = ctx->active_entry_count;
	}

	for (i = 0; i < total_entries; i++) {
		if (only_no_credit) {
			entry = ctx->requested_entry[i];
		} else {
			entry = ctx->active_entry_head;
			/* move head to ensure fair round-robin */
			ctx->active_entry_head = ctx->active_entry_head->next;
		}
		ASSERT(entry);

		if (entry->occupied && _dhd_wlfc_is_destination_open(ctx, entry, prec) &&
#ifdef PROPTX_MAXCOUNT
			(entry->transit_count < entry->transit_maxcount) &&
#endif /* PROPTX_MAXCOUNT */
			(entry->transit_count < WL_TXSTATUS_FREERUNCTR_MASK) &&
			(!entry->suppressed)) {
			*ac_credit_spent = credit_spent;
			if (entry->state == WLFC_STATE_CLOSE) {
				*ac_credit_spent = 0;
			}

			/* higher precedence will be picked up first,
			 * i.e. suppressed packets before delayed ones
			 */
			p = pktq_pdeq(&entry->psq, PSQ_SUP_IDX(prec));
			*needs_hdr = 0;
			if (p == NULL) {
				/* De-Q from delay Q */
				p = pktq_pdeq(&entry->psq, PSQ_DLY_IDX(prec));
				*needs_hdr = 1;
			}

			if (p != NULL) {
				bcm_pkt_validate_chk(p);
				/* did the packet come from suppress sub-queue? */
				if (entry->requested_credit > 0) {
					entry->requested_credit--;
#ifdef PROP_TXSTATUS_DEBUG
					entry->dstncredit_sent_packets++;
#endif // endif
				} else if (entry->requested_packet > 0) {
					entry->requested_packet--;
					DHD_PKTTAG_SETONETIMEPKTRQST(PKTTAG(p));
				}

				*entry_out = entry;
				ctx->pkt_cnt_in_q[DHD_PKTTAG_IF(PKTTAG(p))][prec]--;
				ctx->pkt_cnt_per_ac[prec]--;
				ctx->pkt_cnt_in_psq--;
				_dhd_wlfc_flow_control_check(ctx, &entry->psq,
					DHD_PKTTAG_IF(PKTTAG(p)));
				/*
				 * A packet has been picked up, update traffic availability bitmap,
				 * if applicable.
				 */
				_dhd_wlfc_traffic_pending_check(ctx, entry, prec);
				return p;
			}
		}
	}
	return NULL;
} /* _dhd_wlfc_deque_delayedq */

/** Enqueues caller supplied packet on either a 'suppressed' or 'delayed' queue */
static int
_dhd_wlfc_enque_delayq(athost_wl_status_info_t* ctx, void* pktbuf, int prec)
{
	wlfc_mac_descriptor_t* entry;

	if (pktbuf != NULL) {
		entry = _dhd_wlfc_find_table_entry(ctx, pktbuf);
		if (entry == NULL) {
			DHD_ERROR(("Error: %s():%d\n", __FUNCTION__, __LINE__));
			return BCME_ERROR;
		}

		/*
		- suppressed packets go to sub_queue[2*prec + 1] AND
		- delayed packets go to sub_queue[2*prec + 0] to ensure
		order of delivery.
		*/
		if (_dhd_wlfc_prec_enq_with_drop(ctx->dhdp, &entry->psq, pktbuf, (prec << 1),
			FALSE, WLFC_SEQCOUNT(entry, prec))
			== FALSE) {
			WLFC_DBGMESG(("D"));
			ctx->stats.delayq_full_error++;
			return BCME_ERROR;
		}

		/* A packet has been pushed, update traffic availability bitmap, if applicable */
		_dhd_wlfc_traffic_pending_check(ctx, entry, prec);
	}

	return BCME_OK;
} /* _dhd_wlfc_enque_delayq */

/** Returns TRUE if caller supplied packet is destined for caller supplied interface */
static bool _dhd_wlfc_ifpkt_fn(void* p, void *p_ifid)
{
	if (!p || !p_ifid)
		return FALSE;

	return (DHD_PKTTAG_WLFCPKT(PKTTAG(p))&& (*((uint8 *)p_ifid) == DHD_PKTTAG_IF(PKTTAG(p))));
}

/** Returns TRUE if caller supplied packet is destined for caller supplied remote MAC */
static bool _dhd_wlfc_entrypkt_fn(void* p, void *entry)
{
	if (!p || !entry)
		return FALSE;

	return (DHD_PKTTAG_WLFCPKT(PKTTAG(p))&& (entry == DHD_PKTTAG_ENTRY(PKTTAG(p))));
}

static void
_dhd_wlfc_return_implied_credit(athost_wl_status_info_t* wlfc, void* pkt)
{
	dhd_pub_t *dhdp;
	bool credit_return = FALSE;

	if (!wlfc || !pkt) {
		return;
	}

	dhdp = (dhd_pub_t *)(wlfc->dhdp);
	if (dhdp && (dhdp->proptxstatus_mode == WLFC_FCMODE_IMPLIED_CREDIT) &&
		DHD_PKTTAG_CREDITCHECK(PKTTAG(pkt))) {
		int lender, credit_returned = 0;
		uint8 fifo_id = DHD_PKTTAG_FIFO(PKTTAG(pkt));

		credit_return = TRUE;

		/* Note that borrower is fifo_id */
		/* Return credits to highest priority lender first */
		for (lender = AC_COUNT; lender >= 0; lender--) {
			if (wlfc->credits_borrowed[fifo_id][lender] > 0) {
				wlfc->FIFO_credit[lender]++;
				wlfc->credits_borrowed[fifo_id][lender]--;
				credit_returned = 1;
				break;
			}
		}

		if (!credit_returned) {
			wlfc->FIFO_credit[fifo_id]++;
		}
	}

	BCM_REFERENCE(credit_return);
#if defined(DHD_WLFC_THREAD)
	if (credit_return) {
		_dhd_wlfc_thread_wakeup(dhdp);
	}
#endif /* defined(DHD_WLFC_THREAD) */
}

/** Removes and frees a packet from the hanger. Called during eg tx complete. */
static void
_dhd_wlfc_hanger_free_pkt(athost_wl_status_info_t* wlfc, uint32 slot_id, uint8 pkt_state,
	int pkt_txstatus)
{
	wlfc_hanger_t* hanger;
	wlfc_hanger_item_t* item;

	if (!wlfc)
		return;

	hanger = (wlfc_hanger_t*)wlfc->hanger;
	if (!hanger)
		return;

	if (slot_id == WLFC_HANGER_MAXITEMS)
		return;

	item = &hanger->items[slot_id];

	if (item->pkt) {
		item->pkt_state |= pkt_state;
		if (pkt_txstatus != -1)
			item->pkt_txstatus = (uint8)pkt_txstatus;
		bcm_object_feature_set(item->pkt, BCM_OBJECT_FEATURE_PKT_STATE, item->pkt_state);
		if (item->pkt_state == WLFC_HANGER_PKT_STATE_COMPLETE) {
			void *p = NULL;
			void *pkt = item->pkt;
			uint8 old_state = item->state;
			int ret = _dhd_wlfc_hanger_poppkt(wlfc->hanger, slot_id, &p, TRUE);
			BCM_REFERENCE(ret);
			BCM_REFERENCE(pkt);
			ASSERT((ret == BCME_OK) && p && (pkt == p));
			if (old_state == WLFC_HANGER_ITEM_STATE_INUSE_SUPPRESSED) {
				printf("ERROR: free a suppressed pkt %p state %d pkt_state %d\n",
					pkt, old_state, item->pkt_state);
			}
			ASSERT(old_state != WLFC_HANGER_ITEM_STATE_INUSE_SUPPRESSED);

			/* free packet */
			wlfc->pkt_cnt_in_drv[DHD_PKTTAG_IF(PKTTAG(p))]
				[DHD_PKTTAG_FIFO(PKTTAG(p))]--;
			wlfc->stats.pktout++;
			dhd_txcomplete((dhd_pub_t *)wlfc->dhdp, p, item->pkt_txstatus);
			PKTFREE(wlfc->osh, p, TRUE);
		}
	} else {
		/* free slot */
		if (item->state == WLFC_HANGER_ITEM_STATE_FREE)
			DHD_ERROR(("Error: %s():%d Multiple TXSTATUS or BUSRETURNED: %d (%d)\n",
			    __FUNCTION__, __LINE__, item->pkt_state, pkt_state));
		item->state = WLFC_HANGER_ITEM_STATE_FREE;
	}
} /* _dhd_wlfc_hanger_free_pkt */

/** Called during eg detach() */
static void
_dhd_wlfc_pktq_flush(athost_wl_status_info_t* ctx, struct pktq *pq,
	bool dir, f_processpkt_t fn, void *arg, q_type_t q_type)
{
	int prec;
	dhd_pub_t *dhdp = (dhd_pub_t *)ctx->dhdp;

	ASSERT(dhdp);

	/* Optimize flush, if pktq len = 0, just return.
	 * pktq len of 0 means pktq's prec q's are all empty.
	 */
	if (pq->n_pkts_tot == 0) {
		return;
	}

	for (prec = 0; prec < pq->num_prec; prec++) {
		struct pktq_prec *q;
		void *p, *prev = NULL;

		q = &pq->q[prec];
		p = q->head;
		while (p) {
			bcm_pkt_validate_chk(p);
			if (fn == NULL || (*fn)(p, arg)) {
				bool head = (p == q->head);
				if (head)
					q->head = PKTLINK(p);
				else
					PKTSETLINK(prev, PKTLINK(p));
				if (q_type == Q_TYPE_PSQ) {
					if (!WLFC_GET_AFQ(dhdp->wlfc_mode) && (prec & 1)) {
						_dhd_wlfc_hanger_remove_reference(ctx->hanger, p);
					}
					ctx->pkt_cnt_in_q[DHD_PKTTAG_IF(PKTTAG(p))][prec>>1]--;
					ctx->pkt_cnt_per_ac[prec>>1]--;
					ctx->pkt_cnt_in_psq--;
					ctx->stats.cleanup_psq_cnt++;
					if (!(prec & 1)) {
						/* pkt in delayed q, so fake push BDC header for
						 * dhd_tcpack_check_xmit() and dhd_txcomplete().
						 */
						_dhd_wlfc_pushheader(ctx, &p, FALSE, 0, 0,
							0, 0, TRUE);
#ifdef DHDTCPACK_SUPPRESS
						if (dhd_tcpack_check_xmit(dhdp, p) == BCME_ERROR) {
							DHD_ERROR(("%s %d: tcpack_suppress ERROR!!!"
								" Stop using it\n",
								__FUNCTION__, __LINE__));
							dhd_tcpack_suppress_set(dhdp,
								TCPACK_SUP_OFF);
						}
#endif /* DHDTCPACK_SUPPRESS */
					}
				} else if (q_type == Q_TYPE_AFQ) {
					wlfc_mac_descriptor_t* entry =
						_dhd_wlfc_find_table_entry(ctx, p);
					if (entry->transit_count)
						entry->transit_count--;
					if (entry->suppr_transit_count) {
						entry->suppr_transit_count--;
						if (entry->suppressed &&
							(!entry->onbus_pkts_count) &&
							(!entry->suppr_transit_count))
							entry->suppressed = FALSE;
					}
					_dhd_wlfc_return_implied_credit(ctx, p);
					ctx->stats.cleanup_fw_cnt++;
				}
				PKTSETLINK(p, NULL);
				if (dir) {
					ctx->pkt_cnt_in_drv[DHD_PKTTAG_IF(PKTTAG(p))][prec>>1]--;
					ctx->stats.pktout++;
					dhd_txcomplete(dhdp, p, FALSE);
				}
				PKTFREE(ctx->osh, p, dir);

				q->n_pkts--;
				pq->n_pkts_tot--;
#ifdef WL_TXQ_STALL
				q->dequeue_count++;
#endif // endif

				p = (head ? q->head : PKTLINK(prev));
			} else {
				prev = p;
				p = PKTLINK(p);
			}
		}

		if (q->head == NULL) {
			ASSERT(q->n_pkts == 0);
			q->tail = NULL;
		}

	}

	if (fn == NULL)
		ASSERT(pq->n_pkts_tot == 0);
} /* _dhd_wlfc_pktq_flush */

#ifndef BCMDBUS
/** !BCMDBUS specific function. Dequeues a packet from the caller supplied queue. */
static void*
_dhd_wlfc_pktq_pdeq_with_fn(struct pktq *pq, int prec, f_processpkt_t fn, void *arg)
{
	struct pktq_prec *q;
	void *p, *prev = NULL;

	ASSERT(prec >= 0 && prec < pq->num_prec);

	q = &pq->q[prec];
	p = q->head;

	while (p) {
		if (fn == NULL || (*fn)(p, arg)) {
			break;
		} else {
			prev = p;
			p = PKTLINK(p);
		}
	}
	if (p == NULL)
		return NULL;

	bcm_pkt_validate_chk(p);

	if (prev == NULL) {
		if ((q->head = PKTLINK(p)) == NULL) {
			q->tail = NULL;
		}
	} else {
		PKTSETLINK(prev, PKTLINK(p));
		if (q->tail == p) {
			q->tail = prev;
		}
	}

	q->n_pkts--;

	pq->n_pkts_tot--;

#ifdef WL_TXQ_STALL
	q->dequeue_count++;
#endif // endif

	PKTSETLINK(p, NULL);

	return p;
}

/** !BCMDBUS specific function */
static void
_dhd_wlfc_cleanup_txq(dhd_pub_t *dhd, f_processpkt_t fn, void *arg)
{
	int prec;
	void *pkt = NULL, *head = NULL, *tail = NULL;
	struct pktq *txq = (struct pktq *)dhd_bus_txq(dhd->bus);
	athost_wl_status_info_t* wlfc = (athost_wl_status_info_t*)dhd->wlfc_state;
	wlfc_hanger_t* h = (wlfc_hanger_t*)wlfc->hanger;
	wlfc_mac_descriptor_t* entry;

	dhd_os_sdlock_txq(dhd);
	for (prec = 0; prec < txq->num_prec; prec++) {
		while ((pkt = _dhd_wlfc_pktq_pdeq_with_fn(txq, prec, fn, arg))) {
#ifdef DHDTCPACK_SUPPRESS
			if (dhd_tcpack_check_xmit(dhd, pkt) == BCME_ERROR) {
				DHD_ERROR(("%s %d: tcpack_suppress ERROR!!! Stop using it\n",
					__FUNCTION__, __LINE__));
				dhd_tcpack_suppress_set(dhd, TCPACK_SUP_OFF);
			}
#endif /* DHDTCPACK_SUPPRESS */
			if (!head) {
				head = pkt;
			}
			if (tail) {
				PKTSETLINK(tail, pkt);
			}
			tail = pkt;
		}
	}
	dhd_os_sdunlock_txq(dhd);

	while ((pkt = head)) {
		head = PKTLINK(pkt);
		PKTSETLINK(pkt, NULL);
		entry = _dhd_wlfc_find_table_entry(wlfc, pkt);

		if (!WLFC_GET_AFQ(dhd->wlfc_mode) &&
			!_dhd_wlfc_hanger_remove_reference(h, pkt)) {
			DHD_ERROR(("%s: can't find pkt(%p) in hanger, free it anyway\n",
				__FUNCTION__, pkt));
		}
		if (entry->transit_count)
			entry->transit_count--;
		if (entry->suppr_transit_count) {
			entry->suppr_transit_count--;
			if (entry->suppressed &&
				(!entry->onbus_pkts_count) &&
				(!entry->suppr_transit_count))
				entry->suppressed = FALSE;
		}
		_dhd_wlfc_return_implied_credit(wlfc, pkt);
		wlfc->pkt_cnt_in_drv[DHD_PKTTAG_IF(PKTTAG(pkt))][DHD_PKTTAG_FIFO(PKTTAG(pkt))]--;
		wlfc->stats.pktout++;
		wlfc->stats.cleanup_txq_cnt++;
		dhd_txcomplete(dhd, pkt, FALSE);
		PKTFREE(wlfc->osh, pkt, TRUE);
	}
} /* _dhd_wlfc_cleanup_txq */
#endif /* !BCMDBUS */

/** called during eg detach */
void
_dhd_wlfc_cleanup(dhd_pub_t *dhd, f_processpkt_t fn, void *arg)
{
	int i;
	int total_entries;
	athost_wl_status_info_t* wlfc = (athost_wl_status_info_t*)dhd->wlfc_state;
	wlfc_mac_descriptor_t* table;
	wlfc_hanger_t* h = (wlfc_hanger_t*)wlfc->hanger;

	wlfc->stats.cleanup_txq_cnt = 0;
	wlfc->stats.cleanup_psq_cnt = 0;
	wlfc->stats.cleanup_fw_cnt = 0;

	/*
	*  flush sequence should be txq -> psq -> hanger/afq, hanger has to be last one
	*/
#ifndef BCMDBUS
	/* flush bus->txq */
	_dhd_wlfc_cleanup_txq(dhd, fn, arg);
#endif /* !BCMDBUS */

	/* flush psq, search all entries, include nodes as well as interfaces */
	total_entries = sizeof(wlfc->destination_entries)/sizeof(wlfc_mac_descriptor_t);
	table = (wlfc_mac_descriptor_t*)&wlfc->destination_entries;

	for (i = 0; i < total_entries; i++) {
		if (table[i].occupied) {
			/* release packets held in PSQ (both delayed and suppressed) */
			if (table[i].psq.n_pkts_tot) {
				WLFC_DBGMESG(("%s(): PSQ[%d].len = %d\n",
					__FUNCTION__, i, table[i].psq.n_pkts_tot));
				_dhd_wlfc_pktq_flush(wlfc, &table[i].psq, TRUE,
					fn, arg, Q_TYPE_PSQ);
			}

			/* free packets held in AFQ */
			if (WLFC_GET_AFQ(dhd->wlfc_mode) && (table[i].afq.n_pkts_tot)) {
				_dhd_wlfc_pktq_flush(wlfc, &table[i].afq, TRUE,
					fn, arg, Q_TYPE_AFQ);
			}

			if ((fn == NULL) && (&table[i] != &wlfc->destination_entries.other)) {
				table[i].occupied = 0;
				if (table[i].transit_count || table[i].suppr_transit_count) {
					DHD_ERROR(("%s: table[%d] transit(%d), suppr_tansit(%d)\n",
						__FUNCTION__, i,
						table[i].transit_count,
						table[i].suppr_transit_count));
				}
			}
		}
	}

	/*
		. flush remained pkt in hanger queue, not in bus->txq nor psq.
		. the remained pkt was successfully downloaded to dongle already.
		. hanger slot state cannot be set to free until receive txstatus update.
	*/
	if (!WLFC_GET_AFQ(dhd->wlfc_mode)) {
		for (i = 0; i < h->max_items; i++) {
			if ((h->items[i].state == WLFC_HANGER_ITEM_STATE_INUSE) ||
				(h->items[i].state == WLFC_HANGER_ITEM_STATE_INUSE_SUPPRESSED)) {
				if (fn == NULL || (*fn)(h->items[i].pkt, arg)) {
					h->items[i].state = WLFC_HANGER_ITEM_STATE_FLUSHED;
				}
			}
		}
	}

	return;
} /* _dhd_wlfc_cleanup */

/** Called after eg the dongle signalled a new remote MAC that it connected with to the DHD */
static int
_dhd_wlfc_mac_entry_update(athost_wl_status_info_t* ctx, wlfc_mac_descriptor_t* entry,
	uint8 action, uint8 ifid, uint8 iftype, uint8* ea,
	f_processpkt_t fn, void *arg)
{
	int rc = BCME_OK;

	if ((action == eWLFC_MAC_ENTRY_ACTION_ADD) || (action == eWLFC_MAC_ENTRY_ACTION_UPDATE)) {
		entry->occupied = 1;
		entry->state = WLFC_STATE_OPEN;
		entry->requested_credit = 0;
		entry->interface_id = ifid;
		entry->iftype = iftype;
		entry->ac_bitmap = 0xff; /* update this when handling APSD */

		/* for an interface entry we may not care about the MAC address */
		if (ea != NULL)
			memcpy(&entry->ea[0], ea, ETHER_ADDR_LEN);

		if (action == eWLFC_MAC_ENTRY_ACTION_ADD) {
			entry->suppressed = FALSE;
			entry->transit_count = 0;
#if defined(WL_EXT_IAPSTA) && defined(PROPTX_MAXCOUNT)
			entry->transit_maxcount = wl_ext_get_wlfc_maxcount(ctx->dhdp, ifid);
#endif /* PROPTX_MAXCOUNT */
			entry->suppr_transit_count = 0;
			entry->onbus_pkts_count = 0;
		}

		if (action == eWLFC_MAC_ENTRY_ACTION_ADD) {
			dhd_pub_t *dhdp = (dhd_pub_t *)(ctx->dhdp);

			pktq_init(&entry->psq, WLFC_PSQ_PREC_COUNT, WLFC_PSQ_LEN);
			_dhd_wlfc_flow_control_check(ctx, &entry->psq, ifid);

			if (WLFC_GET_AFQ(dhdp->wlfc_mode)) {
				pktq_init(&entry->afq, WLFC_AFQ_PREC_COUNT, WLFC_PSQ_LEN);
			}

			if (entry->next == NULL) {
				/* not linked to anywhere, add to tail */
				if (ctx->active_entry_head) {
					entry->prev = ctx->active_entry_head->prev;
					ctx->active_entry_head->prev->next = entry;
					ctx->active_entry_head->prev = entry;
					entry->next = ctx->active_entry_head;
				} else {
					ASSERT(ctx->active_entry_count == 0);
					entry->prev = entry->next = entry;
					ctx->active_entry_head = entry;
				}
				ctx->active_entry_count++;
			} else {
				DHD_ERROR(("%s():%d, entry(%d)\n", __FUNCTION__, __LINE__,
					(int)(entry - &ctx->destination_entries.nodes[0])));
			}
		}
	} else if (action == eWLFC_MAC_ENTRY_ACTION_DEL) {
		/* When the entry is deleted, the packets that are queued in the entry must be
		   cleanup. The cleanup action should be before the occupied is set as 0.
		*/
		_dhd_wlfc_cleanup(ctx->dhdp, fn, arg);
		_dhd_wlfc_flow_control_check(ctx, &entry->psq, ifid);

		entry->occupied = 0;
		entry->state = WLFC_STATE_CLOSE;
		memset(&entry->ea[0], 0, ETHER_ADDR_LEN);

		if (entry->next) {
			/* not floating, remove from Q */
			if (ctx->active_entry_count <= 1) {
				/* last item */
				ctx->active_entry_head = NULL;
				ctx->active_entry_count = 0;
			} else {
				entry->prev->next = entry->next;
				entry->next->prev = entry->prev;
				if (entry == ctx->active_entry_head) {
					ctx->active_entry_head = entry->next;
				}
				ctx->active_entry_count--;
			}
			entry->next = entry->prev = NULL;
		} else {
			DHD_ERROR(("Error: %s():%d\n", __FUNCTION__, __LINE__));
		}
	}
	return rc;
} /* _dhd_wlfc_mac_entry_update */
