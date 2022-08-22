// SPDX-License-Identifier: GPL-2.0
/*
 * xHCI host controller driver
 *
 * Copyright (C) 2008 Intel Corp.
 *
 * Author: Sarah Sharp
 * Some code borrowed from the Linux EHCI driver.
 */

/*
 * Ring initialization rules:
 * 1. Each segment is initialized to zero, except for link TRBs.
 * 2. Ring cycle state = 0.  This represents Producer Cycle State (PCS) or
 *    Consumer Cycle State (CCS), depending on ring function.
 * 3. Enqueue pointer = dequeue pointer = address of first TRB in the segment.
 *
 * Ring behavior rules:
 * 1. A ring is empty if enqueue == dequeue.  This means there will always be at
 *    least one free TRB in the ring.  This is useful if you want to turn that
 *    into a link TRB and expand the ring.
 * 2. When incrementing an enqueue or dequeue pointer, if the next TRB is a
 *    link TRB, then load the pointer with the address in the link TRB.  If the
 *    link TRB had its toggle bit set, you may need to update the ring cycle
 *    state (see cycle bit rules).  You may have to do this multiple times
 *    until you reach a non-link TRB.
 * 3. A ring is full if enqueue++ (for the definition of increment above)
 *    equals the dequeue pointer.
 *
 * Cycle bit rules:
 * 1. When a consumer increments a dequeue pointer and encounters a toggle bit
 *    in a link TRB, it must toggle the ring cycle state.
 * 2. When a producer increments an enqueue pointer and encounters a toggle bit
 *    in a link TRB, it must toggle the ring cycle state.
 *
 * Producer rules:
 * 1. Check if ring is full before you enqueue.
 * 2. Write the ring cycle state to the cycle bit in the TRB you're enqueuing.
 *    Update enqueue pointer between each write (which may update the ring
 *    cycle state).
 * 3. Notify consumer.  If SW is producer, it rings the doorbell for command
 *    and endpoint rings.  If HC is the producer for the event ring,
 *    and it generates an interrupt according to interrupt modulation rules.
 *
 * Consumer rules:
 * 1. Check if TRB belongs to you.  If the cycle bit == your ring cycle state,
 *    the TRB is owned by the consumer.
 * 2. Update dequeue pointer (which may update the ring cycle state) and
 *    continue processing TRBs until you reach a TRB which is not owned by you.
 * 3. Notify the producer.  SW is the consumer for the event ring, and it
 *   updates event ring dequeue pointer.  HC is the consumer for the command and
 *   endpoint rings; it generates events on the event ring for these.
 */

#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include "xhci.h"
#include "xhci-trace.h"

static int queue_command(struct xhci_hcd *xhci, struct xhci_command *cmd,
			 u32 field1, u32 field2,
			 u32 field3, u32 field4, bool command_must_succeed);

/*
 * Returns zero if the TRB isn't in this segment, otherwise it returns the DMA
 * address of the TRB.
 */
dma_addr_t xhci_trb_virt_to_dma(struct xhci_segment *seg,
		union xhci_trb *trb)
{
	unsigned long segment_offset;

	if (!seg || !trb || trb < seg->trbs)
		return 0;
	/* offset in TRBs */
	segment_offset = trb - seg->trbs;
	if (segment_offset >= TRBS_PER_SEGMENT)
		return 0;
	return seg->dma + (segment_offset * sizeof(*trb));
}
EXPORT_SYMBOL_GPL(xhci_trb_virt_to_dma);

static bool trb_is_noop(union xhci_trb *trb)
{
	return TRB_TYPE_NOOP_LE32(trb->generic.field[3]);
}

static bool trb_is_link(union xhci_trb *trb)
{
	return TRB_TYPE_LINK_LE32(trb->link.control);
}

static bool last_trb_on_seg(struct xhci_segment *seg, union xhci_trb *trb)
{
	return trb == &seg->trbs[TRBS_PER_SEGMENT - 1];
}

static bool last_trb_on_ring(struct xhci_ring *ring,
			struct xhci_segment *seg, union xhci_trb *trb)
{
	return last_trb_on_seg(seg, trb) && (seg->next == ring->first_seg);
}

static bool link_trb_toggles_cycle(union xhci_trb *trb)
{
	return le32_to_cpu(trb->link.control) & LINK_TOGGLE;
}

static bool last_td_in_urb(struct xhci_td *td)
{
	struct urb_priv *urb_priv = td->urb->hcpriv;

	return urb_priv->num_tds_done == urb_priv->num_tds;
}

static void inc_td_cnt(struct urb *urb)
{
	struct urb_priv *urb_priv = urb->hcpriv;

	urb_priv->num_tds_done++;
}

static void trb_to_noop(union xhci_trb *trb, u32 noop_type)
{
	if (trb_is_link(trb)) {
		/* unchain chained link TRBs */
		trb->link.control &= cpu_to_le32(~TRB_CHAIN);
	} else {
		trb->generic.field[0] = 0;
		trb->generic.field[1] = 0;
		trb->generic.field[2] = 0;
		/* Preserve only the cycle bit of this TRB */
		trb->generic.field[3] &= cpu_to_le32(TRB_CYCLE);
		trb->generic.field[3] |= cpu_to_le32(TRB_TYPE(noop_type));
	}
}

/* Updates trb to point to the next TRB in the ring, and updates seg if the next
 * TRB is in a new segment.  This does not skip over link TRBs, and it does not
 * effect the ring dequeue or enqueue pointers.
 */
static void next_trb(struct xhci_hcd *xhci,
		struct xhci_ring *ring,
		struct xhci_segment **seg,
		union xhci_trb **trb)
{
	if (trb_is_link(*trb)) {
		*seg = (*seg)->next;
		*trb = ((*seg)->trbs);
	} else {
		(*trb)++;
	}
}

/*
 * See Cycle bit rules. SW is the consumer for the event ring only.
 */
void inc_deq(struct xhci_hcd *xhci, struct xhci_ring *ring)
{
	unsigned int link_trb_count = 0;

	/* event ring doesn't have link trbs, check for last trb */
	if (ring->type == TYPE_EVENT) {
		if (!last_trb_on_seg(ring->deq_seg, ring->dequeue)) {
			ring->dequeue++;
			goto out;
		}
		if (last_trb_on_ring(ring, ring->deq_seg, ring->dequeue))
			ring->cycle_state ^= 1;
		ring->deq_seg = ring->deq_seg->next;
		ring->dequeue = ring->deq_seg->trbs;
		goto out;
	}

	/* All other rings have link trbs */
	if (!trb_is_link(ring->dequeue)) {
		if (last_trb_on_seg(ring->deq_seg, ring->dequeue)) {
			xhci_warn(xhci, "Missing link TRB at end of segment\n");
		} else {
			ring->dequeue++;
			ring->num_trbs_free++;
		}
	}

	while (trb_is_link(ring->dequeue)) {
		ring->deq_seg = ring->deq_seg->next;
		ring->dequeue = ring->deq_seg->trbs;

		if (link_trb_count++ > ring->num_segs) {
			xhci_warn(xhci, "Ring is an endless link TRB loop\n");
			break;
		}
	}
out:
	trace_xhci_inc_deq(ring);

	return;
}

/*
 * See Cycle bit rules. SW is the consumer for the event ring only.
 *
 * If we've just enqueued a TRB that is in the middle of a TD (meaning the
 * chain bit is set), then set the chain bit in all the following link TRBs.
 * If we've enqueued the last TRB in a TD, make sure the following link TRBs
 * have their chain bit cleared (so that each Link TRB is a separate TD).
 *
 * Section 6.4.4.1 of the 0.95 spec says link TRBs cannot have the chain bit
 * set, but other sections talk about dealing with the chain bit set.  This was
 * fixed in the 0.96 specification errata, but we have to assume that all 0.95
 * xHCI hardware can't handle the chain bit being cleared on a link TRB.
 *
 * @more_trbs_coming:	Will you enqueue more TRBs before calling
 *			prepare_transfer()?
 */
static void inc_enq(struct xhci_hcd *xhci, struct xhci_ring *ring,
			bool more_trbs_coming)
{
	u32 chain;
	union xhci_trb *next;
	unsigned int link_trb_count = 0;

	chain = le32_to_cpu(ring->enqueue->generic.field[3]) & TRB_CHAIN;
	/* If this is not event ring, there is one less usable TRB */
	if (!trb_is_link(ring->enqueue))
		ring->num_trbs_free--;

	if (last_trb_on_seg(ring->enq_seg, ring->enqueue)) {
		xhci_err(xhci, "Tried to move enqueue past ring segment\n");
		return;
	}

	next = ++(ring->enqueue);

	/* Update the dequeue pointer further if that was a link TRB */
	while (trb_is_link(next)) {

		/*
		 * If the caller doesn't plan on enqueueing more TDs before
		 * ringing the doorbell, then we don't want to give the link TRB
		 * to the hardware just yet. We'll give the link TRB back in
		 * prepare_ring() just before we enqueue the TD at the top of
		 * the ring.
		 */
		if (!chain && !more_trbs_coming)
			break;

		/* If we're not dealing with 0.95 hardware or isoc rings on
		 * AMD 0.96 host, carry over the chain bit of the previous TRB
		 * (which may mean the chain bit is cleared).
		 */
		if (!(ring->type == TYPE_ISOC &&
		      (xhci->quirks & XHCI_AMD_0x96_HOST)) &&
		    !xhci_link_trb_quirk(xhci)) {
			next->link.control &= cpu_to_le32(~TRB_CHAIN);
			next->link.control |= cpu_to_le32(chain);
		}
		/* Give this link TRB to the hardware */
		wmb();
		next->link.control ^= cpu_to_le32(TRB_CYCLE);

		/* Toggle the cycle bit after the last ring segment. */
		if (link_trb_toggles_cycle(next))
			ring->cycle_state ^= 1;

		ring->enq_seg = ring->enq_seg->next;
		ring->enqueue = ring->enq_seg->trbs;
		next = ring->enqueue;

		if (link_trb_count++ > ring->num_segs) {
			xhci_warn(xhci, "%s: Ring link TRB loop\n", __func__);
			break;
		}
	}

	trace_xhci_inc_enq(ring);
}

/*
 * Check to see if there's room to enqueue num_trbs on the ring and make sure
 * enqueue pointer will not advance into dequeue segment. See rules above.
 */
static inline int room_on_ring(struct xhci_hcd *xhci, struct xhci_ring *ring,
		unsigned int num_trbs)
{
	int num_trbs_in_deq_seg;

	if (ring->num_trbs_free < num_trbs)
		return 0;

	if (ring->type != TYPE_COMMAND && ring->type != TYPE_EVENT) {
		num_trbs_in_deq_seg = ring->dequeue - ring->deq_seg->trbs;
		if (ring->num_trbs_free < num_trbs + num_trbs_in_deq_seg)
			return 0;
	}

	return 1;
}

/* Ring the host controller doorbell after placing a command on the ring */
void xhci_ring_cmd_db(struct xhci_hcd *xhci)
{
	if (!(xhci->cmd_ring_state & CMD_RING_STATE_RUNNING))
		return;

	xhci_dbg(xhci, "// Ding dong!\n");

	trace_xhci_ring_host_doorbell(0, DB_VALUE_HOST);

	writel(DB_VALUE_HOST, &xhci->dba->doorbell[0]);
	/* Flush PCI posted writes */
	readl(&xhci->dba->doorbell[0]);
}
EXPORT_SYMBOL_GPL(xhci_ring_cmd_db);

static bool xhci_mod_cmd_timer(struct xhci_hcd *xhci, unsigned long delay)
{
	return mod_delayed_work(system_wq, &xhci->cmd_timer, delay);
}

static struct xhci_command *xhci_next_queued_cmd(struct xhci_hcd *xhci)
{
	return list_first_entry_or_null(&xhci->cmd_list, struct xhci_command,
					cmd_list);
}

/*
 * Turn all commands on command ring with status set to "aborted" to no-op trbs.
 * If there are other commands waiting then restart the ring and kick the timer.
 * This must be called with command ring stopped and xhci->lock held.
 */
static void xhci_handle_stopped_cmd_ring(struct xhci_hcd *xhci,
					 struct xhci_command *cur_cmd)
{
	struct xhci_command *i_cmd;

	/* Turn all aborted commands in list to no-ops, then restart */
	list_for_each_entry(i_cmd, &xhci->cmd_list, cmd_list) {

		if (i_cmd->status != COMP_COMMAND_ABORTED)
			continue;

		i_cmd->status = COMP_COMMAND_RING_STOPPED;

		xhci_dbg(xhci, "Turn aborted command %p to no-op\n",
			 i_cmd->command_trb);

		trb_to_noop(i_cmd->command_trb, TRB_CMD_NOOP);

		/*
		 * caller waiting for completion is called when command
		 *  completion event is received for these no-op commands
		 */
	}

	xhci->cmd_ring_state = CMD_RING_STATE_RUNNING;

	/* ring command ring doorbell to restart the command ring */
	if ((xhci->cmd_ring->dequeue != xhci->cmd_ring->enqueue) &&
	    !(xhci->xhc_state & XHCI_STATE_DYING)) {
		xhci->current_cmd = cur_cmd;
		xhci_mod_cmd_timer(xhci, XHCI_CMD_DEFAULT_TIMEOUT);
		xhci_ring_cmd_db(xhci);
	}
}

/* Must be called with xhci->lock held, releases and aquires lock back */
static int xhci_abort_cmd_ring(struct xhci_hcd *xhci, unsigned long flags)
{
	u32 temp_32;
	int ret;

	xhci_dbg(xhci, "Abort command ring\n");

	reinit_completion(&xhci->cmd_ring_stop_completion);

	/*
	 * The control bits like command stop, abort are located in lower
	 * dword of the command ring control register. Limit the write
	 * to the lower dword to avoid corrupting the command ring pointer
	 * in case if the command ring is stopped by the time upper dword
	 * is written.
	 */
	temp_32 = readl(&xhci->op_regs->cmd_ring);
	writel(temp_32 | CMD_RING_ABORT, &xhci->op_regs->cmd_ring);

	/* Section 4.6.1.2 of xHCI 1.0 spec says software should also time the
	 * completion of the Command Abort operation. If CRR is not negated in 5
	 * seconds then driver handles it as if host died (-ENODEV).
	 * In the future we should distinguish between -ENODEV and -ETIMEDOUT
	 * and try to recover a -ETIMEDOUT with a host controller reset.
	 */
	ret = xhci_handshake(&xhci->op_regs->cmd_ring,
			CMD_RING_RUNNING, 0, 5 * 1000 * 1000);
	if (ret < 0) {
		xhci_err(xhci, "Abort failed to stop command ring: %d\n", ret);
		xhci_halt(xhci);
		xhci_hc_died(xhci);
		return ret;
	}
	/*
	 * Writing the CMD_RING_ABORT bit should cause a cmd completion event,
	 * however on some host hw the CMD_RING_RUNNING bit is correctly cleared
	 * but the completion event in never sent. Wait 2 secs (arbitrary
	 * number) to handle those cases after negation of CMD_RING_RUNNING.
	 */
	spin_unlock_irqrestore(&xhci->lock, flags);
	ret = wait_for_completion_timeout(&xhci->cmd_ring_stop_completion,
					  msecs_to_jiffies(2000));
	spin_lock_irqsave(&xhci->lock, flags);
	if (!ret) {
		xhci_dbg(xhci, "No stop event for abort, ring start fail?\n");
		xhci_cleanup_command_queue(xhci);
	} else {
		xhci_handle_stopped_cmd_ring(xhci, xhci_next_queued_cmd(xhci));
	}
	return 0;
}

void xhci_ring_ep_doorbell(struct xhci_hcd *xhci,
		unsigned int slot_id,
		unsigned int ep_index,
		unsigned int stream_id)
{
	__le32 __iomem *db_addr = &xhci->dba->doorbell[slot_id];
	struct xhci_virt_ep *ep = &xhci->devs[slot_id]->eps[ep_index];
	unsigned int ep_state = ep->ep_state;

	/* Don't ring the doorbell for this endpoint if there are pending
	 * cancellations because we don't want to interrupt processing.
	 * We don't want to restart any stream rings if there's a set dequeue
	 * pointer command pending because the device can choose to start any
	 * stream once the endpoint is on the HW schedule.
	 */
	if ((ep_state & EP_STOP_CMD_PENDING) || (ep_state & SET_DEQ_PENDING) ||
	    (ep_state & EP_HALTED) || (ep_state & EP_CLEARING_TT))
		return;

	trace_xhci_ring_ep_doorbell(slot_id, DB_VALUE(ep_index, stream_id));

	writel(DB_VALUE(ep_index, stream_id), db_addr);
	/* flush the write */
	readl(db_addr);
}

/* Ring the doorbell for any rings with pending URBs */
static void ring_doorbell_for_active_rings(struct xhci_hcd *xhci,
		unsigned int slot_id,
		unsigned int ep_index)
{
	unsigned int stream_id;
	struct xhci_virt_ep *ep;

	ep = &xhci->devs[slot_id]->eps[ep_index];

	/* A ring has pending URBs if its TD list is not empty */
	if (!(ep->ep_state & EP_HAS_STREAMS)) {
		if (ep->ring && !(list_empty(&ep->ring->td_list)))
			xhci_ring_ep_doorbell(xhci, slot_id, ep_index, 0);
		return;
	}

	for (stream_id = 1; stream_id < ep->stream_info->num_streams;
			stream_id++) {
		struct xhci_stream_info *stream_info = ep->stream_info;
		if (!list_empty(&stream_info->stream_rings[stream_id]->td_list))
			xhci_ring_ep_doorbell(xhci, slot_id, ep_index,
						stream_id);
	}
}

void xhci_ring_doorbell_for_active_rings(struct xhci_hcd *xhci,
		unsigned int slot_id,
		unsigned int ep_index)
{
	ring_doorbell_for_active_rings(xhci, slot_id, ep_index);
}

static struct xhci_virt_ep *xhci_get_virt_ep(struct xhci_hcd *xhci,
					     unsigned int slot_id,
					     unsigned int ep_index)
{
	if (slot_id == 0 || slot_id >= MAX_HC_SLOTS) {
		xhci_warn(xhci, "Invalid slot_id %u\n", slot_id);
		return NULL;
	}
	if (ep_index >= EP_CTX_PER_DEV) {
		xhci_warn(xhci, "Invalid endpoint index %u\n", ep_index);
		return NULL;
	}
	if (!xhci->devs[slot_id]) {
		xhci_warn(xhci, "No xhci virt device for slot_id %u\n", slot_id);
		return NULL;
	}

	return &xhci->devs[slot_id]->eps[ep_index];
}

static struct xhci_ring *xhci_virt_ep_to_ring(struct xhci_hcd *xhci,
					      struct xhci_virt_ep *ep,
					      unsigned int stream_id)
{
	/* common case, no streams */
	if (!(ep->ep_state & EP_HAS_STREAMS))
		return ep->ring;

	if (!ep->stream_info)
		return NULL;

	if (stream_id == 0 || stream_id >= ep->stream_info->num_streams) {
		xhci_warn(xhci, "Invalid stream_id %u request for slot_id %u ep_index %u\n",
			  stream_id, ep->vdev->slot_id, ep->ep_index);
		return NULL;
	}

	return ep->stream_info->stream_rings[stream_id];
}

/* Get the right ring for the given slot_id, ep_index and stream_id.
 * If the endpoint supports streams, boundary check the URB's stream ID.
 * If the endpoint doesn't support streams, return the singular endpoint ring.
 */
struct xhci_ring *xhci_triad_to_transfer_ring(struct xhci_hcd *xhci,
		unsigned int slot_id, unsigned int ep_index,
		unsigned int stream_id)
{
	struct xhci_virt_ep *ep;

	ep = xhci_get_virt_ep(xhci, slot_id, ep_index);
	if (!ep)
		return NULL;

	return xhci_virt_ep_to_ring(xhci, ep, stream_id);
}


/*
 * Get the hw dequeue pointer xHC stopped on, either directly from the
 * endpoint context, or if streams are in use from the stream context.
 * The returned hw_dequeue contains the lowest four bits with cycle state
 * and possbile stream context type.
 */
static u64 xhci_get_hw_deq(struct xhci_hcd *xhci, struct xhci_virt_device *vdev,
			   unsigned int ep_index, unsigned int stream_id)
{
	struct xhci_ep_ctx *ep_ctx;
	struct xhci_stream_ctx *st_ctx;
	struct xhci_virt_ep *ep;

	ep = &vdev->eps[ep_index];

	if (ep->ep_state & EP_HAS_STREAMS) {
		st_ctx = &ep->stream_info->stream_ctx_array[stream_id];
		return le64_to_cpu(st_ctx->stream_ring);
	}
	ep_ctx = xhci_get_ep_ctx(xhci, vdev->out_ctx, ep_index);
	return le64_to_cpu(ep_ctx->deq);
}

static int xhci_move_dequeue_past_td(struct xhci_hcd *xhci,
				unsigned int slot_id, unsigned int ep_index,
				unsigned int stream_id, struct xhci_td *td)
{
	struct xhci_virt_device *dev = xhci->devs[slot_id];
	struct xhci_virt_ep *ep = &dev->eps[ep_index];
	struct xhci_ring *ep_ring;
	struct xhci_command *cmd;
	struct xhci_segment *new_seg;
	union xhci_trb *new_deq;
	int new_cycle;
	dma_addr_t addr;
	u64 hw_dequeue;
	bool cycle_found = false;
	bool td_last_trb_found = false;
	u32 trb_sct = 0;
	int ret;

	ep_ring = xhci_triad_to_transfer_ring(xhci, slot_id,
			ep_index, stream_id);
	if (!ep_ring) {
		xhci_warn(xhci, "WARN can't find new dequeue, invalid stream ID %u\n",
			  stream_id);
		return -ENODEV;
	}
	/*
	 * A cancelled TD can complete with a stall if HW cached the trb.
	 * In this case driver can't find td, but if the ring is empty we
	 * can move the dequeue pointer to the current enqueue position.
	 * We shouldn't hit this anymore as cached cancelled TRBs are given back
	 * after clearing the cache, but be on the safe side and keep it anyway
	 */
	if (!td) {
		if (list_empty(&ep_ring->td_list)) {
			new_seg = ep_ring->enq_seg;
			new_deq = ep_ring->enqueue;
			new_cycle = ep_ring->cycle_state;
			xhci_dbg(xhci, "ep ring empty, Set new dequeue = enqueue");
			goto deq_found;
		} else {
			xhci_warn(xhci, "Can't find new dequeue state, missing td\n");
			return -EINVAL;
		}
	}

	hw_dequeue = xhci_get_hw_deq(xhci, dev, ep_index, stream_id);
	new_seg = ep_ring->deq_seg;
	new_deq = ep_ring->dequeue;
	new_cycle = hw_dequeue & 0x1;

	/*
	 * We want to find the pointer, segment and cycle state of the new trb
	 * (the one after current TD's last_trb). We know the cycle state at
	 * hw_dequeue, so walk the ring until both hw_dequeue and last_trb are
	 * found.
	 */
	do {
		if (!cycle_found && xhci_trb_virt_to_dma(new_seg, new_deq)
		    == (dma_addr_t)(hw_dequeue & ~0xf)) {
			cycle_found = true;
			if (td_last_trb_found)
				break;
		}
		if (new_deq == td->last_trb)
			td_last_trb_found = true;

		if (cycle_found && trb_is_link(new_deq) &&
		    link_trb_toggles_cycle(new_deq))
