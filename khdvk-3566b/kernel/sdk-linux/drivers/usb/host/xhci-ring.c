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
			new_cycle ^= 0x1;

		next_trb(xhci, ep_ring, &new_seg, &new_deq);

		/* Search wrapped around, bail out */
		if (new_deq == ep->ring->dequeue) {
			xhci_err(xhci, "Error: Failed finding new dequeue state\n");
			return -EINVAL;
		}

	} while (!cycle_found || !td_last_trb_found);

deq_found:

	/* Don't update the ring cycle state for the producer (us). */
	addr = xhci_trb_virt_to_dma(new_seg, new_deq);
	if (addr == 0) {
		xhci_warn(xhci, "Can't find dma of new dequeue ptr\n");
		xhci_warn(xhci, "deq seg = %p, deq ptr = %p\n", new_seg, new_deq);
		return -EINVAL;
	}

	if ((ep->ep_state & SET_DEQ_PENDING)) {
		xhci_warn(xhci, "Set TR Deq already pending, don't submit for 0x%pad\n",
			  &addr);
		return -EBUSY;
	}

	/* This function gets called from contexts where it cannot sleep */
	cmd = xhci_alloc_command(xhci, false, GFP_ATOMIC);
	if (!cmd) {
		xhci_warn(xhci, "Can't alloc Set TR Deq cmd 0x%pad\n", &addr);
		return -ENOMEM;
	}

	if (stream_id)
		trb_sct = SCT_FOR_TRB(SCT_PRI_TR);
	ret = queue_command(xhci, cmd,
		lower_32_bits(addr) | trb_sct | new_cycle,
		upper_32_bits(addr),
		STREAM_ID_FOR_TRB(stream_id), SLOT_ID_FOR_TRB(slot_id) |
		EP_ID_FOR_TRB(ep_index) | TRB_TYPE(TRB_SET_DEQ), false);
	if (ret < 0) {
		xhci_free_command(xhci, cmd);
		return ret;
	}
	ep->queued_deq_seg = new_seg;
	ep->queued_deq_ptr = new_deq;

	xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
		       "Set TR Deq ptr 0x%llx, cycle %u\n", addr, new_cycle);

	/* Stop the TD queueing code from ringing the doorbell until
	 * this command completes.  The HC won't set the dequeue pointer
	 * if the ring is running, and ringing the doorbell starts the
	 * ring running.
	 */
	ep->ep_state |= SET_DEQ_PENDING;
	xhci_ring_cmd_db(xhci);
	return 0;
}

/* flip_cycle means flip the cycle bit of all but the first and last TRB.
 * (The last TRB actually points to the ring enqueue pointer, which is not part
 * of this TD.)  This is used to remove partially enqueued isoc TDs from a ring.
 */
static void td_to_noop(struct xhci_hcd *xhci, struct xhci_ring *ep_ring,
		       struct xhci_td *td, bool flip_cycle)
{
	struct xhci_segment *seg	= td->start_seg;
	union xhci_trb *trb		= td->first_trb;

	while (1) {
		trb_to_noop(trb, TRB_TR_NOOP);

		/* flip cycle if asked to */
		if (flip_cycle && trb != td->first_trb && trb != td->last_trb)
			trb->generic.field[3] ^= cpu_to_le32(TRB_CYCLE);

		if (trb == td->last_trb)
			break;

		next_trb(xhci, ep_ring, &seg, &trb);
	}
}

static void xhci_stop_watchdog_timer_in_irq(struct xhci_hcd *xhci,
		struct xhci_virt_ep *ep)
{
	ep->ep_state &= ~EP_STOP_CMD_PENDING;
	/* Can't del_timer_sync in interrupt */
	del_timer(&ep->stop_cmd_timer);
}

/*
 * Must be called with xhci->lock held in interrupt context,
 * releases and re-acquires xhci->lock
 */
static void xhci_giveback_urb_in_irq(struct xhci_hcd *xhci,
				     struct xhci_td *cur_td, int status)
{
	struct urb	*urb		= cur_td->urb;
	struct urb_priv	*urb_priv	= urb->hcpriv;
	struct usb_hcd	*hcd		= bus_to_hcd(urb->dev->bus);

	if (usb_pipetype(urb->pipe) == PIPE_ISOCHRONOUS) {
		xhci_to_hcd(xhci)->self.bandwidth_isoc_reqs--;
		if (xhci_to_hcd(xhci)->self.bandwidth_isoc_reqs	== 0) {
			if (xhci->quirks & XHCI_AMD_PLL_FIX)
				usb_amd_quirk_pll_enable();
		}
	}
	xhci_urb_free_priv(urb_priv);
	usb_hcd_unlink_urb_from_ep(hcd, urb);
	trace_xhci_urb_giveback(urb);
	usb_hcd_giveback_urb(hcd, urb, status);
}

static void xhci_unmap_td_bounce_buffer(struct xhci_hcd *xhci,
		struct xhci_ring *ring, struct xhci_td *td)
{
	struct device *dev = xhci_to_hcd(xhci)->self.controller;
	struct xhci_segment *seg = td->bounce_seg;
	struct urb *urb = td->urb;
	size_t len;

	if (!ring || !seg || !urb)
		return;

	if (usb_urb_dir_out(urb)) {
		dma_unmap_single(dev, seg->bounce_dma, ring->bounce_buf_len,
				 DMA_TO_DEVICE);
		return;
	}

	dma_unmap_single(dev, seg->bounce_dma, ring->bounce_buf_len,
			 DMA_FROM_DEVICE);
	/* for in tranfers we need to copy the data from bounce to sg */
	if (urb->num_sgs) {
		len = sg_pcopy_from_buffer(urb->sg, urb->num_sgs, seg->bounce_buf,
					   seg->bounce_len, seg->bounce_offs);
		if (len != seg->bounce_len)
			xhci_warn(xhci, "WARN Wrong bounce buffer read length: %zu != %d\n",
				  len, seg->bounce_len);
	} else {
		memcpy(urb->transfer_buffer + seg->bounce_offs, seg->bounce_buf,
		       seg->bounce_len);
	}
	seg->bounce_len = 0;
	seg->bounce_offs = 0;
}

static int xhci_td_cleanup(struct xhci_hcd *xhci, struct xhci_td *td,
			   struct xhci_ring *ep_ring, int status)
{
	struct urb *urb = NULL;

	/* Clean up the endpoint's TD list */
	urb = td->urb;

	/* if a bounce buffer was used to align this td then unmap it */
	xhci_unmap_td_bounce_buffer(xhci, ep_ring, td);

	/* Do one last check of the actual transfer length.
	 * If the host controller said we transferred more data than the buffer
	 * length, urb->actual_length will be a very big number (since it's
	 * unsigned).  Play it safe and say we didn't transfer anything.
	 */
	if (urb->actual_length > urb->transfer_buffer_length) {
		xhci_warn(xhci, "URB req %u and actual %u transfer length mismatch\n",
			  urb->transfer_buffer_length, urb->actual_length);
		urb->actual_length = 0;
		status = 0;
	}
	/* TD might be removed from td_list if we are giving back a cancelled URB */
	if (!list_empty(&td->td_list))
		list_del_init(&td->td_list);
	/* Giving back a cancelled URB, or if a slated TD completed anyway */
	if (!list_empty(&td->cancelled_td_list))
		list_del_init(&td->cancelled_td_list);

	inc_td_cnt(urb);
	/* Giveback the urb when all the tds are completed */
	if (last_td_in_urb(td)) {
		if ((urb->actual_length != urb->transfer_buffer_length &&
		     (urb->transfer_flags & URB_SHORT_NOT_OK)) ||
		    (status != 0 && !usb_endpoint_xfer_isoc(&urb->ep->desc)))
			xhci_dbg(xhci, "Giveback URB %p, len = %d, expected = %d, status = %d\n",
				 urb, urb->actual_length,
				 urb->transfer_buffer_length, status);

		/* set isoc urb status to 0 just as EHCI, UHCI, and OHCI */
		if (usb_pipetype(urb->pipe) == PIPE_ISOCHRONOUS)
			status = 0;
		xhci_giveback_urb_in_irq(xhci, td, status);
	}

	return 0;
}


/* Complete the cancelled URBs we unlinked from td_list. */
static void xhci_giveback_invalidated_tds(struct xhci_virt_ep *ep)
{
	struct xhci_ring *ring;
	struct xhci_td *td, *tmp_td;

	list_for_each_entry_safe(td, tmp_td, &ep->cancelled_td_list,
				 cancelled_td_list) {

		ring = xhci_urb_to_transfer_ring(ep->xhci, td->urb);

		if (td->cancel_status == TD_CLEARED)
			xhci_td_cleanup(ep->xhci, td, ring, td->status);

		if (ep->xhci->xhc_state & XHCI_STATE_DYING)
			return;
	}
}

static int xhci_reset_halted_ep(struct xhci_hcd *xhci, unsigned int slot_id,
				unsigned int ep_index, enum xhci_ep_reset_type reset_type)
{
	struct xhci_command *command;
	int ret = 0;

	command = xhci_alloc_command(xhci, false, GFP_ATOMIC);
	if (!command) {
		ret = -ENOMEM;
		goto done;
	}

	ret = xhci_queue_reset_ep(xhci, command, slot_id, ep_index, reset_type);
done:
	if (ret)
		xhci_err(xhci, "ERROR queuing reset endpoint for slot %d ep_index %d, %d\n",
			 slot_id, ep_index, ret);
	return ret;
}

static int xhci_handle_halted_endpoint(struct xhci_hcd *xhci,
				struct xhci_virt_ep *ep, unsigned int stream_id,
				struct xhci_td *td,
				enum xhci_ep_reset_type reset_type)
{
	unsigned int slot_id = ep->vdev->slot_id;
	int err;

	/*
	 * Avoid resetting endpoint if link is inactive. Can cause host hang.
	 * Device will be reset soon to recover the link so don't do anything
	 */
	if (ep->vdev->flags & VDEV_PORT_ERROR)
		return -ENODEV;

	/* add td to cancelled list and let reset ep handler take care of it */
	if (reset_type == EP_HARD_RESET) {
		ep->ep_state |= EP_HARD_CLEAR_TOGGLE;
		if (td && list_empty(&td->cancelled_td_list)) {
			list_add_tail(&td->cancelled_td_list, &ep->cancelled_td_list);
			td->cancel_status = TD_HALTED;
		}
	}

	if (ep->ep_state & EP_HALTED) {
		xhci_dbg(xhci, "Reset ep command already pending\n");
		return 0;
	}

	err = xhci_reset_halted_ep(xhci, slot_id, ep->ep_index, reset_type);
	if (err)
		return err;

	ep->ep_state |= EP_HALTED;

	xhci_ring_cmd_db(xhci);

	return 0;
}

/*
 * Fix up the ep ring first, so HW stops executing cancelled TDs.
 * We have the xHCI lock, so nothing can modify this list until we drop it.
 * We're also in the event handler, so we can't get re-interrupted if another
 * Stop Endpoint command completes.
 *
 * only call this when ring is not in a running state
 */

static int xhci_invalidate_cancelled_tds(struct xhci_virt_ep *ep)
{
	struct xhci_hcd		*xhci;
	struct xhci_td		*td = NULL;
	struct xhci_td		*tmp_td = NULL;
	struct xhci_td		*cached_td = NULL;
	struct xhci_ring	*ring;
	u64			hw_deq;
	unsigned int		slot_id = ep->vdev->slot_id;
	int			err;

	xhci = ep->xhci;

	list_for_each_entry_safe(td, tmp_td, &ep->cancelled_td_list, cancelled_td_list) {
		xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
				"Removing canceled TD starting at 0x%llx (dma).",
				(unsigned long long)xhci_trb_virt_to_dma(
					td->start_seg, td->first_trb));
		list_del_init(&td->td_list);
		ring = xhci_urb_to_transfer_ring(xhci, td->urb);
		if (!ring) {
			xhci_warn(xhci, "WARN Cancelled URB %p has invalid stream ID %u.\n",
				  td->urb, td->urb->stream_id);
			continue;
		}
		/*
		 * If a ring stopped on the TD we need to cancel then we have to
		 * move the xHC endpoint ring dequeue pointer past this TD.
		 * Rings halted due to STALL may show hw_deq is past the stalled
		 * TD, but still require a set TR Deq command to flush xHC cache.
		 */
		hw_deq = xhci_get_hw_deq(xhci, ep->vdev, ep->ep_index,
					 td->urb->stream_id);
		hw_deq &= ~0xf;

		if (td->cancel_status == TD_HALTED) {
			cached_td = td;
		} else if (trb_in_td(xhci, td->start_seg, td->first_trb,
			      td->last_trb, hw_deq, false)) {
			switch (td->cancel_status) {
			case TD_CLEARED: /* TD is already no-op */
			case TD_CLEARING_CACHE: /* set TR deq command already queued */
				break;
			case TD_DIRTY: /* TD is cached, clear it */
			case TD_HALTED:
				/* FIXME  stream case, several stopped rings */
				cached_td = td;
				break;
			}
		} else {
			td_to_noop(xhci, ring, td, false);
			td->cancel_status = TD_CLEARED;
		}
	}
	if (cached_td) {
		cached_td->cancel_status = TD_CLEARING_CACHE;

		err = xhci_move_dequeue_past_td(xhci, slot_id, ep->ep_index,
						cached_td->urb->stream_id,
						cached_td);
		/* Failed to move past cached td, try just setting it noop */
		if (err) {
			td_to_noop(xhci, ring, cached_td, false);
			cached_td->cancel_status = TD_CLEARED;
		}
		cached_td = NULL;
	}
	return 0;
}

/*
 * Returns the TD the endpoint ring halted on.
 * Only call for non-running rings without streams.
 */
static struct xhci_td *find_halted_td(struct xhci_virt_ep *ep)
{
	struct xhci_td	*td;
	u64		hw_deq;

	if (!list_empty(&ep->ring->td_list)) { /* Not streams compatible */
		hw_deq = xhci_get_hw_deq(ep->xhci, ep->vdev, ep->ep_index, 0);
		hw_deq &= ~0xf;
		td = list_first_entry(&ep->ring->td_list, struct xhci_td, td_list);
		if (trb_in_td(ep->xhci, td->start_seg, td->first_trb,
				td->last_trb, hw_deq, false))
			return td;
	}
	return NULL;
}

/*
 * When we get a command completion for a Stop Endpoint Command, we need to
 * unlink any cancelled TDs from the ring.  There are two ways to do that:
 *
 *  1. If the HW was in the middle of processing the TD that needs to be
 *     cancelled, then we must move the ring's dequeue pointer past the last TRB
 *     in the TD with a Set Dequeue Pointer Command.
 *  2. Otherwise, we turn all the TRBs in the TD into No-op TRBs (with the chain
 *     bit cleared) so that the HW will skip over them.
 */
static void xhci_handle_cmd_stop_ep(struct xhci_hcd *xhci, int slot_id,
				    union xhci_trb *trb, u32 comp_code)
{
	unsigned int ep_index;
	struct xhci_virt_ep *ep;
	struct xhci_ep_ctx *ep_ctx;
	struct xhci_td *td = NULL;
	enum xhci_ep_reset_type reset_type;
	struct xhci_command *command;
	int err;

	if (unlikely(TRB_TO_SUSPEND_PORT(le32_to_cpu(trb->generic.field[3])))) {
		if (!xhci->devs[slot_id])
			xhci_warn(xhci, "Stop endpoint command completion for disabled slot %u\n",
				  slot_id);
		return;
	}

	ep_index = TRB_TO_EP_INDEX(le32_to_cpu(trb->generic.field[3]));
	ep = xhci_get_virt_ep(xhci, slot_id, ep_index);
	if (!ep)
		return;

	ep_ctx = xhci_get_ep_ctx(xhci, ep->vdev->out_ctx, ep_index);

	trace_xhci_handle_cmd_stop_ep(ep_ctx);

	if (comp_code == COMP_CONTEXT_STATE_ERROR) {
	/*
	 * If stop endpoint command raced with a halting endpoint we need to
	 * reset the host side endpoint first.
	 * If the TD we halted on isn't cancelled the TD should be given back
	 * with a proper error code, and the ring dequeue moved past the TD.
	 * If streams case we can't find hw_deq, or the TD we halted on so do a
	 * soft reset.
	 *
	 * Proper error code is unknown here, it would be -EPIPE if device side
	 * of enadpoit halted (aka STALL), and -EPROTO if not (transaction error)
	 * We use -EPROTO, if device is stalled it should return a stall error on
	 * next transfer, which then will return -EPIPE, and device side stall is
	 * noted and cleared by class driver.
	 */
		switch (GET_EP_CTX_STATE(ep_ctx)) {
		case EP_STATE_HALTED:
			xhci_dbg(xhci, "Stop ep completion raced with stall, reset ep\n");
			if (ep->ep_state & EP_HAS_STREAMS) {
				reset_type = EP_SOFT_RESET;
			} else {
				reset_type = EP_HARD_RESET;
				td = find_halted_td(ep);
				if (td)
					td->status = -EPROTO;
			}
			/* reset ep, reset handler cleans up cancelled tds */
			err = xhci_handle_halted_endpoint(xhci, ep, 0, td,
							  reset_type);
			if (err)
				break;
			xhci_stop_watchdog_timer_in_irq(xhci, ep);
			return;
		case EP_STATE_RUNNING:
			/* Race, HW handled stop ep cmd before ep was running */
			command = xhci_alloc_command(xhci, false, GFP_ATOMIC);
			if (!command)
				xhci_stop_watchdog_timer_in_irq(xhci, ep);

			mod_timer(&ep->stop_cmd_timer,
				  jiffies + XHCI_STOP_EP_CMD_TIMEOUT * HZ);
			xhci_queue_stop_endpoint(xhci, command, slot_id, ep_index, 0);
			xhci_ring_cmd_db(xhci);

			return;
		default:
			break;
		}
	}
	/* will queue a set TR deq if stopped on a cancelled, uncleared TD */
	xhci_invalidate_cancelled_tds(ep);
	xhci_stop_watchdog_timer_in_irq(xhci, ep);

	/* Otherwise ring the doorbell(s) to restart queued transfers */
	xhci_giveback_invalidated_tds(ep);
	ring_doorbell_for_active_rings(xhci, slot_id, ep_index);
}

static void xhci_kill_ring_urbs(struct xhci_hcd *xhci, struct xhci_ring *ring)
{
	struct xhci_td *cur_td;
	struct xhci_td *tmp;

	list_for_each_entry_safe(cur_td, tmp, &ring->td_list, td_list) {
		list_del_init(&cur_td->td_list);

		if (!list_empty(&cur_td->cancelled_td_list))
			list_del_init(&cur_td->cancelled_td_list);

		xhci_unmap_td_bounce_buffer(xhci, ring, cur_td);

		inc_td_cnt(cur_td->urb);
		if (last_td_in_urb(cur_td))
			xhci_giveback_urb_in_irq(xhci, cur_td, -ESHUTDOWN);
	}
}

static void xhci_kill_endpoint_urbs(struct xhci_hcd *xhci,
		int slot_id, int ep_index)
{
	struct xhci_td *cur_td;
	struct xhci_td *tmp;
	struct xhci_virt_ep *ep;
	struct xhci_ring *ring;

	ep = &xhci->devs[slot_id]->eps[ep_index];
	if ((ep->ep_state & EP_HAS_STREAMS) ||
			(ep->ep_state & EP_GETTING_NO_STREAMS)) {
		int stream_id;

		for (stream_id = 1; stream_id < ep->stream_info->num_streams;
				stream_id++) {
			ring = ep->stream_info->stream_rings[stream_id];
			if (!ring)
				continue;

			xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
					"Killing URBs for slot ID %u, ep index %u, stream %u",
					slot_id, ep_index, stream_id);
			xhci_kill_ring_urbs(xhci, ring);
		}
	} else {
		ring = ep->ring;
		if (!ring)
			return;
		xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
				"Killing URBs for slot ID %u, ep index %u",
				slot_id, ep_index);
		xhci_kill_ring_urbs(xhci, ring);
	}

	list_for_each_entry_safe(cur_td, tmp, &ep->cancelled_td_list,
			cancelled_td_list) {
		list_del_init(&cur_td->cancelled_td_list);
		inc_td_cnt(cur_td->urb);

		if (last_td_in_urb(cur_td))
			xhci_giveback_urb_in_irq(xhci, cur_td, -ESHUTDOWN);
	}
}

/*
 * host controller died, register read returns 0xffffffff
 * Complete pending commands, mark them ABORTED.
 * URBs need to be given back as usb core might be waiting with device locks
 * held for the URBs to finish during device disconnect, blocking host remove.
 *
 * Call with xhci->lock held.
 * lock is relased and re-acquired while giving back urb.
 */
void xhci_hc_died(struct xhci_hcd *xhci)
{
	int i, j;

	if (xhci->xhc_state & XHCI_STATE_DYING)
		return;

	xhci_err(xhci, "xHCI host controller not responding, assume dead\n");
	xhci->xhc_state |= XHCI_STATE_DYING;

	xhci_cleanup_command_queue(xhci);

	/* return any pending urbs, remove may be waiting for them */
	for (i = 0; i <= HCS_MAX_SLOTS(xhci->hcs_params1); i++) {
		if (!xhci->devs[i])
			continue;
		for (j = 0; j < 31; j++)
			xhci_kill_endpoint_urbs(xhci, i, j);
	}

	/* inform usb core hc died if PCI remove isn't already handling it */
	if (!(xhci->xhc_state & XHCI_STATE_REMOVING))
		usb_hc_died(xhci_to_hcd(xhci));
}

/* Watchdog timer function for when a stop endpoint command fails to complete.
 * In this case, we assume the host controller is broken or dying or dead.  The
 * host may still be completing some other events, so we have to be careful to
 * let the event ring handler and the URB dequeueing/enqueueing functions know
 * through xhci->state.
 *
 * The timer may also fire if the host takes a very long time to respond to the
 * command, and the stop endpoint command completion handler cannot delete the
 * timer before the timer function is called.  Another endpoint cancellation may
 * sneak in before the timer function can grab the lock, and that may queue
 * another stop endpoint command and add the timer back.  So we cannot use a
 * simple flag to say whether there is a pending stop endpoint command for a
 * particular endpoint.
 *
 * Instead we use a combination of that flag and checking if a new timer is
 * pending.
 */
void xhci_stop_endpoint_command_watchdog(struct timer_list *t)
{
	struct xhci_virt_ep *ep = from_timer(ep, t, stop_cmd_timer);
	struct xhci_hcd *xhci = ep->xhci;
	unsigned long flags;
	u32 usbsts;
	char str[XHCI_MSG_MAX];

	spin_lock_irqsave(&xhci->lock, flags);

	/* bail out if cmd completed but raced with stop ep watchdog timer.*/
	if (!(ep->ep_state & EP_STOP_CMD_PENDING) ||
	    timer_pending(&ep->stop_cmd_timer)) {
		spin_unlock_irqrestore(&xhci->lock, flags);
		xhci_dbg(xhci, "Stop EP timer raced with cmd completion, exit");
		return;
	}
	usbsts = readl(&xhci->op_regs->status);

	xhci_warn(xhci, "xHCI host not responding to stop endpoint command.\n");
	xhci_warn(xhci, "USBSTS:%s\n", xhci_decode_usbsts(str, usbsts));

	ep->ep_state &= ~EP_STOP_CMD_PENDING;

	xhci_halt(xhci);

	/*
	 * handle a stop endpoint cmd timeout as if host died (-ENODEV).
	 * In the future we could distinguish between -ENODEV and -ETIMEDOUT
	 * and try to recover a -ETIMEDOUT with a host controller reset
	 */
	xhci_hc_died(xhci);

	spin_unlock_irqrestore(&xhci->lock, flags);
	xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
			"xHCI host controller is dead.");
}

static void update_ring_for_set_deq_completion(struct xhci_hcd *xhci,
		struct xhci_virt_device *dev,
		struct xhci_ring *ep_ring,
		unsigned int ep_index)
{
	union xhci_trb *dequeue_temp;
	int num_trbs_free_temp;
	bool revert = false;

	num_trbs_free_temp = ep_ring->num_trbs_free;
	dequeue_temp = ep_ring->dequeue;

	/* If we get two back-to-back stalls, and the first stalled transfer
	 * ends just before a link TRB, the dequeue pointer will be left on
	 * the link TRB by the code in the while loop.  So we have to update
	 * the dequeue pointer one segment further, or we'll jump off
	 * the segment into la-la-land.
	 */
	if (trb_is_link(ep_ring->dequeue)) {
		ep_ring->deq_seg = ep_ring->deq_seg->next;
		ep_ring->dequeue = ep_ring->deq_seg->trbs;
	}

	while (ep_ring->dequeue != dev->eps[ep_index].queued_deq_ptr) {
		/* We have more usable TRBs */
		ep_ring->num_trbs_free++;
		ep_ring->dequeue++;
		if (trb_is_link(ep_ring->dequeue)) {
			if (ep_ring->dequeue ==
					dev->eps[ep_index].queued_deq_ptr)
				break;
			ep_ring->deq_seg = ep_ring->deq_seg->next;
			ep_ring->dequeue = ep_ring->deq_seg->trbs;
		}
		if (ep_ring->dequeue == dequeue_temp) {
			revert = true;
			break;
		}
	}

	if (revert) {
		xhci_dbg(xhci, "Unable to find new dequeue pointer\n");
		ep_ring->num_trbs_free = num_trbs_free_temp;
	}
}

/*
 * When we get a completion for a Set Transfer Ring Dequeue Pointer command,
 * we need to clear the set deq pending flag in the endpoint ring state, so that
 * the TD queueing code can ring the doorbell again.  We also need to ring the
 * endpoint doorbell to restart the ring, but only if there aren't more
 * cancellations pending.
 */
static void xhci_handle_cmd_set_deq(struct xhci_hcd *xhci, int slot_id,
		union xhci_trb *trb, u32 cmd_comp_code)
{
	unsigned int ep_index;
	unsigned int stream_id;
	struct xhci_ring *ep_ring;
	struct xhci_virt_ep *ep;
	struct xhci_ep_ctx *ep_ctx;
	struct xhci_slot_ctx *slot_ctx;
	struct xhci_td *td, *tmp_td;

	ep_index = TRB_TO_EP_INDEX(le32_to_cpu(trb->generic.field[3]));
	stream_id = TRB_TO_STREAM_ID(le32_to_cpu(trb->generic.field[2]));
	ep = xhci_get_virt_ep(xhci, slot_id, ep_index);
	if (!ep)
		return;

	ep_ring = xhci_virt_ep_to_ring(xhci, ep, stream_id);
	if (!ep_ring) {
		xhci_warn(xhci, "WARN Set TR deq ptr command for freed stream ID %u\n",
				stream_id);
		/* XXX: Harmless??? */
		goto cleanup;
	}

	ep_ctx = xhci_get_ep_ctx(xhci, ep->vdev->out_ctx, ep_index);
	slot_ctx = xhci_get_slot_ctx(xhci, ep->vdev->out_ctx);
	trace_xhci_handle_cmd_set_deq(slot_ctx);
	trace_xhci_handle_cmd_set_deq_ep(ep_ctx);

	if (cmd_comp_code != COMP_SUCCESS) {
		unsigned int ep_state;
		unsigned int slot_state;

		switch (cmd_comp_code) {
		case COMP_TRB_ERROR:
			xhci_warn(xhci, "WARN Set TR Deq Ptr cmd invalid because of stream ID configuration\n");
			break;
		case COMP_CONTEXT_STATE_ERROR:
			xhci_warn(xhci, "WARN Set TR Deq Ptr cmd failed due to incorrect slot or ep state.\n");
			ep_state = GET_EP_CTX_STATE(ep_ctx);
			slot_state = le32_to_cpu(slot_ctx->dev_state);
			slot_state = GET_SLOT_STATE(slot_state);
			xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
					"Slot state = %u, EP state = %u",
					slot_state, ep_state);
			break;
		case COMP_SLOT_NOT_ENABLED_ERROR:
			xhci_warn(xhci, "WARN Set TR Deq Ptr cmd failed because slot %u was not enabled.\n",
					slot_id);
			break;
		default:
			xhci_warn(xhci, "WARN Set TR Deq Ptr cmd with unknown completion code of %u.\n",
					cmd_comp_code);
			break;
		}
		/* OK what do we do now?  The endpoint state is hosed, and we
		 * should never get to this point if the synchronization between
		 * queueing, and endpoint state are correct.  This might happen
		 * if the device gets disconnected after we've finished
		 * cancelling URBs, which might not be an error...
		 */
	} else {
		u64 deq;
		/* 4.6.10 deq ptr is written to the stream ctx for streams */
		if (ep->ep_state & EP_HAS_STREAMS) {
			struct xhci_stream_ctx *ctx =
				&ep->stream_info->stream_ctx_array[stream_id];
			deq = le64_to_cpu(ctx->stream_ring) & SCTX_DEQ_MASK;
		} else {
			deq = le64_to_cpu(ep_ctx->deq) & ~EP_CTX_CYCLE_MASK;
		}
		xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
			"Successful Set TR Deq Ptr cmd, deq = @%08llx", deq);
		if (xhci_trb_virt_to_dma(ep->queued_deq_seg,
					 ep->queued_deq_ptr) == deq) {
			/* Update the ring's dequeue segment and dequeue pointer
			 * to reflect the new position.
			 */
			update_ring_for_set_deq_completion(xhci, ep->vdev,
				ep_ring, ep_index);
		} else {
			xhci_warn(xhci, "Mismatch between completed Set TR Deq Ptr command & xHCI internal state.\n");
			xhci_warn(xhci, "ep deq seg = %p, deq ptr = %p\n",
				  ep->queued_deq_seg, ep->queued_deq_ptr);
		}
	}
	/* HW cached TDs cleared from cache, give them back */
	list_for_each_entry_safe(td, tmp_td, &ep->cancelled_td_list,
				 cancelled_td_list) {
		ep_ring = xhci_urb_to_transfer_ring(ep->xhci, td->urb);
		if (td->cancel_status == TD_CLEARING_CACHE) {
			td->cancel_status = TD_CLEARED;
			xhci_td_cleanup(ep->xhci, td, ep_ring, td->status);
		}
	}
cleanup:
	ep->ep_state &= ~SET_DEQ_PENDING;
	ep->queued_deq_seg = NULL;
	ep->queued_deq_ptr = NULL;
	/* Restart any rings with pending URBs */
	ring_doorbell_for_active_rings(xhci, slot_id, ep_index);
}

static void xhci_handle_cmd_reset_ep(struct xhci_hcd *xhci, int slot_id,
		union xhci_trb *trb, u32 cmd_comp_code)
{
	struct xhci_virt_ep *ep;
	struct xhci_ep_ctx *ep_ctx;
	unsigned int ep_index;

	ep_index = TRB_TO_EP_INDEX(le32_to_cpu(trb->generic.field[3]));
	ep = xhci_get_virt_ep(xhci, slot_id, ep_index);
	if (!ep)
		return;

	ep_ctx = xhci_get_ep_ctx(xhci, ep->vdev->out_ctx, ep_index);
	trace_xhci_handle_cmd_reset_ep(ep_ctx);

	/* This command will only fail if the endpoint wasn't halted,
	 * but we don't care.
	 */
	xhci_dbg_trace(xhci, trace_xhci_dbg_reset_ep,
		"Ignoring reset ep completion code of %u", cmd_comp_code);

	/* Cleanup cancelled TDs as ep is stopped. May queue a Set TR Deq cmd */
	xhci_invalidate_cancelled_tds(ep);

	if (xhci->quirks & XHCI_RESET_EP_QUIRK)
		xhci_dbg(xhci, "Note: Removed workaround to queue config ep for this hw");
	/* Clear our internal halted state */
	ep->ep_state &= ~EP_HALTED;

	xhci_giveback_invalidated_tds(ep);

	/* if this was a soft reset, then restart */
	if ((le32_to_cpu(trb->generic.field[3])) & TRB_TSP)
		ring_doorbell_for_active_rings(xhci, slot_id, ep_index);
}

static void xhci_handle_cmd_enable_slot(struct xhci_hcd *xhci, int slot_id,
		struct xhci_command *command, u32 cmd_comp_code)
{
	if (cmd_comp_code == COMP_SUCCESS)
		command->slot_id = slot_id;
	else
		command->slot_id = 0;
}

static void xhci_handle_cmd_disable_slot(struct xhci_hcd *xhci, int slot_id)
{
	struct xhci_virt_device *virt_dev;
	struct xhci_slot_ctx *slot_ctx;

	virt_dev = xhci->devs[slot_id];
	if (!virt_dev)
		return;

	slot_ctx = xhci_get_slot_ctx(xhci, virt_dev->out_ctx);
	trace_xhci_handle_cmd_disable_slot(slot_ctx);

	if (xhci->quirks & XHCI_EP_LIMIT_QUIRK)
		/* Delete default control endpoint resources */
		xhci_free_device_endpoint_resources(xhci, virt_dev, true);
	xhci_free_virt_device(xhci, slot_id);
}

static void xhci_handle_cmd_config_ep(struct xhci_hcd *xhci, int slot_id,
		u32 cmd_comp_code)
{
	struct xhci_virt_device *virt_dev;
	struct xhci_input_control_ctx *ctrl_ctx;
	struct xhci_ep_ctx *ep_ctx;
	unsigned int ep_index;
	unsigned int ep_state;
	u32 add_flags, drop_flags;

	/*
	 * Configure endpoint commands can come from the USB core
	 * configuration or alt setting changes, or because the HW
	 * needed an extra configure endpoint command after a reset
	 * endpoint command or streams were being configured.
	 * If the command was for a halted endpoint, the xHCI driver
	 * is not waiting on the configure endpoint command.
	 */
	virt_dev = xhci->devs[slot_id];
	if (!virt_dev)
		return;
	ctrl_ctx = xhci_get_input_control_ctx(virt_dev->in_ctx);
	if (!ctrl_ctx) {
		xhci_warn(xhci, "Could not get input context, bad type.\n");
		return;
	}

	add_flags = le32_to_cpu(ctrl_ctx->add_flags);
	drop_flags = le32_to_cpu(ctrl_ctx->drop_flags);
	/* Input ctx add_flags are the endpoint index plus one */
	ep_index = xhci_last_valid_endpoint(add_flags) - 1;

	ep_ctx = xhci_get_ep_ctx(xhci, virt_dev->out_ctx, ep_index);
	trace_xhci_handle_cmd_config_ep(ep_ctx);

	/* A usb_set_interface() call directly after clearing a halted
	 * condition may race on this quirky hardware.  Not worth
	 * worrying about, since this is prototype hardware.  Not sure
	 * if this will work for streams, but streams support was
	 * untested on this prototype.
	 */
	if (xhci->quirks & XHCI_RESET_EP_QUIRK &&
			ep_index != (unsigned int) -1 &&
			add_flags - SLOT_FLAG == drop_flags) {
		ep_state = virt_dev->eps[ep_index].ep_state;
		if (!(ep_state & EP_HALTED))
			return;
		xhci_dbg_trace(xhci, trace_xhci_dbg_quirks,
				"Completed config ep cmd - "
				"last ep index = %d, state = %d",
				ep_index, ep_state);
		/* Clear internal halted state and restart ring(s) */
		virt_dev->eps[ep_index].ep_state &= ~EP_HALTED;
		ring_doorbell_for_active_rings(xhci, slot_id, ep_index);
		return;
	}
	return;
}

static void xhci_handle_cmd_addr_dev(struct xhci_hcd *xhci, int slot_id)
{
	struct xhci_virt_device *vdev;
	struct xhci_slot_ctx *slot_ctx;

	vdev = xhci->devs[slot_id];
	if (!vdev)
		return;
	slot_ctx = xhci_get_slot_ctx(xhci, vdev->out_ctx);
	trace_xhci_handle_cmd_addr_dev(slot_ctx);
}

static void xhci_handle_cmd_reset_dev(struct xhci_hcd *xhci, int slot_id)
{
	struct xhci_virt_device *vdev;
	struct xhci_slot_ctx *slot_ctx;

	vdev = xhci->devs[slot_id];
	if (!vdev) {
		xhci_warn(xhci, "Reset device command completion for disabled slot %u\n",
			  slot_id);
		return;
	}
	slot_ctx = xhci_get_slot_ctx(xhci, vdev->out_ctx);
	trace_xhci_handle_cmd_reset_dev(slot_ctx);

	xhci_dbg(xhci, "Completed reset device command.\n");
}

static void xhci_handle_cmd_nec_get_fw(struct xhci_hcd *xhci,
		struct xhci_event_cmd *event)
{
	if (!(xhci->quirks & XHCI_NEC_HOST)) {
		xhci_warn(xhci, "WARN NEC_GET_FW command on non-NEC host\n");
		return;
	}
	xhci_dbg_trace(xhci, trace_xhci_dbg_quirks,
			"NEC firmware version %2x.%02x",
			NEC_FW_MAJOR(le32_to_cpu(event->status)),
			NEC_FW_MINOR(le32_to_cpu(event->status)));
}

static void xhci_complete_del_and_free_cmd(struct xhci_command *cmd, u32 status)
{
	list_del(&cmd->cmd_list);

	if (cmd->completion) {
		cmd->status = status;
		complete(cmd->completion);
	} else {
		kfree(cmd);
	}
}

void xhci_cleanup_command_queue(struct xhci_hcd *xhci)
{
	struct xhci_command *cur_cmd, *tmp_cmd;
	xhci->current_cmd = NULL;
	list_for_each_entry_safe(cur_cmd, tmp_cmd, &xhci->cmd_list, cmd_list)
		xhci_complete_del_and_free_cmd(cur_cmd, COMP_COMMAND_ABORTED);
}

void xhci_handle_command_timeout(struct work_struct *work)
{
	struct xhci_hcd *xhci;
	unsigned long flags;
	u64 hw_ring_state;

	xhci = container_of(to_delayed_work(work), struct xhci_hcd, cmd_timer);

	spin_lock_irqsave(&xhci->lock, flags);

	/*
	 * If timeout work is pending, or current_cmd is NULL, it means we
	 * raced with command completion. Command is handled so just return.
	 */
	if (!xhci->current_cmd || delayed_work_pending(&xhci->cmd_timer)) {
		spin_unlock_irqrestore(&xhci->lock, flags);
		return;
	}
	/* mark this command to be cancelled */
	xhci->current_cmd->status = COMP_COMMAND_ABORTED;

	/* Make sure command ring is running before aborting it */
	hw_ring_state = xhci_read_64(xhci, &xhci->op_regs->cmd_ring);
	if (hw_ring_state == ~(u64)0) {
		xhci_hc_died(xhci);
		goto time_out_completed;
	}

	if ((xhci->cmd_ring_state & CMD_RING_STATE_RUNNING) &&
	    (hw_ring_state & CMD_RING_RUNNING))  {
		/* Prevent new doorbell, and start command abort */
		xhci->cmd_ring_state = CMD_RING_STATE_ABORTED;
		xhci_dbg(xhci, "Command timeout\n");
		xhci_abort_cmd_ring(xhci, flags);
		goto time_out_completed;
	}

	/* host removed. Bail out */
	if (xhci->xhc_state & XHCI_STATE_REMOVING) {
		xhci_dbg(xhci, "host removed, ring start fail?\n");
		xhci_cleanup_command_queue(xhci);

		goto time_out_completed;
	}

	/* command timeout on stopped ring, ring can't be aborted */
	xhci_dbg(xhci, "Command timeout on stopped ring\n");
	xhci_handle_stopped_cmd_ring(xhci, xhci->current_cmd);

time_out_completed:
	spin_unlock_irqrestore(&xhci->lock, flags);
	return;
}

static void handle_cmd_completion(struct xhci_hcd *xhci,
		struct xhci_event_cmd *event)
{
	unsigned int slot_id = TRB_TO_SLOT_ID(le32_to_cpu(event->flags));
	u64 cmd_dma;
	dma_addr_t cmd_dequeue_dma;
	u32 cmd_comp_code;
	union xhci_trb *cmd_trb;
	struct xhci_command *cmd;
	u32 cmd_type;

	if (slot_id >= MAX_HC_SLOTS) {
		xhci_warn(xhci, "Invalid slot_id %u\n", slot_id);
		return;
	}

	cmd_dma = le64_to_cpu(event->cmd_trb);
	cmd_trb = xhci->cmd_ring->dequeue;

	trace_xhci_handle_command(xhci->cmd_ring, &cmd_trb->generic);

	cmd_dequeue_dma = xhci_trb_virt_to_dma(xhci->cmd_ring->deq_seg,
			cmd_trb);
	/*
	 * Check whether the completion event is for our internal kept
	 * command.
	 */
	if (!cmd_dequeue_dma || cmd_dma != (u64)cmd_dequeue_dma) {
		xhci_warn(xhci,
			  "ERROR mismatched command completion event\n");
		return;
	}

	cmd = list_first_entry(&xhci->cmd_list, struct xhci_command, cmd_list);

	cancel_delayed_work(&xhci->cmd_timer);

	cmd_comp_code = GET_COMP_CODE(le32_to_cpu(event->status));

	/* If CMD ring stopped we own the trbs between enqueue and dequeue */
	if (cmd_comp_code == COMP_COMMAND_RING_STOPPED) {
		complete_all(&xhci->cmd_ring_stop_completion);
		return;
	}

	if (cmd->command_trb != xhci->cmd_ring->dequeue) {
		xhci_err(xhci,
			 "Command completion event does not match command\n");
		return;
	}

	/*
	 * Host aborted the command ring, check if the current command was
	 * supposed to be aborted, otherwise continue normally.
	 * The command ring is stopped now, but the xHC will issue a Command
	 * Ring Stopped event which will cause us to restart it.
	 */
	if (cmd_comp_code == COMP_COMMAND_ABORTED) {
		xhci->cmd_ring_state = CMD_RING_STATE_STOPPED;
		if (cmd->status == COMP_COMMAND_ABORTED) {
			if (xhci->current_cmd == cmd)
				xhci->current_cmd = NULL;
			goto event_handled;
		}
	}

	cmd_type = TRB_FIELD_TO_TYPE(le32_to_cpu(cmd_trb->generic.field[3]));
	switch (cmd_type) {
	case TRB_ENABLE_SLOT:
		xhci_handle_cmd_enable_slot(xhci, slot_id, cmd, cmd_comp_code);
		break;
	case TRB_DISABLE_SLOT:
		xhci_handle_cmd_disable_slot(xhci, slot_id);
		break;
	case TRB_CONFIG_EP:
		if (!cmd->completion)
			xhci_handle_cmd_config_ep(xhci, slot_id, cmd_comp_code);
		break;
	case TRB_EVAL_CONTEXT:
		break;
	case TRB_ADDR_DEV:
		xhci_handle_cmd_addr_dev(xhci, slot_id);
		break;
	case TRB_STOP_RING:
		WARN_ON(slot_id != TRB_TO_SLOT_ID(
				le32_to_cpu(cmd_trb->generic.field[3])));
		if (!cmd->completion)
			xhci_handle_cmd_stop_ep(xhci, slot_id, cmd_trb,
						cmd_comp_code);
		break;
	case TRB_SET_DEQ:
		WARN_ON(slot_id != TRB_TO_SLOT_ID(
				le32_to_cpu(cmd_trb->generic.field[3])));
		xhci_handle_cmd_set_deq(xhci, slot_id, cmd_trb, cmd_comp_code);
		break;
	case TRB_CMD_NOOP:
		/* Is this an aborted command turned to NO-OP? */
		if (cmd->status == COMP_COMMAND_RING_STOPPED)
			cmd_comp_code = COMP_COMMAND_RING_STOPPED;
		break;
	case TRB_RESET_EP:
		WARN_ON(slot_id != TRB_TO_SLOT_ID(
				le32_to_cpu(cmd_trb->generic.field[3])));
		xhci_handle_cmd_reset_ep(xhci, slot_id, cmd_trb, cmd_comp_code);
		break;
	case TRB_RESET_DEV:
		/* SLOT_ID field in reset device cmd completion event TRB is 0.
		 * Use the SLOT_ID from the command TRB instead (xhci 4.6.11)
		 */
		slot_id = TRB_TO_SLOT_ID(
				le32_to_cpu(cmd_trb->generic.field[3]));
		xhci_handle_cmd_reset_dev(xhci, slot_id);
		break;
	case TRB_NEC_GET_FW:
		xhci_handle_cmd_nec_get_fw(xhci, event);
		break;
	default:
		/* Skip over unknown commands on the event ring */
		xhci_info(xhci, "INFO unknown command type %d\n", cmd_type);
		break;
	}

	/* restart timer if this wasn't the last command */
	if (!list_is_singular(&xhci->cmd_list)) {
		xhci->current_cmd = list_first_entry(&cmd->cmd_list,
						struct xhci_command, cmd_list);
		xhci_mod_cmd_timer(xhci, XHCI_CMD_DEFAULT_TIMEOUT);
	} else if (xhci->current_cmd == cmd) {
		xhci->current_cmd = NULL;
	}

event_handled:
	xhci_complete_del_and_free_cmd(cmd, cmd_comp_code);

	inc_deq(xhci, xhci->cmd_ring);
}

static void handle_vendor_event(struct xhci_hcd *xhci,
				union xhci_trb *event, u32 trb_type)
{
	xhci_dbg(xhci, "Vendor specific event TRB type = %u\n", trb_type);
	if (trb_type == TRB_NEC_CMD_COMP && (xhci->quirks & XHCI_NEC_HOST))
		handle_cmd_completion(xhci, &event->event_cmd);
}

static void handle_device_notification(struct xhci_hcd *xhci,
		union xhci_trb *event)
{
	u32 slot_id;
	struct usb_device *udev;

	slot_id = TRB_TO_SLOT_ID(le32_to_cpu(event->generic.field[3]));
	if (!xhci->devs[slot_id]) {
		xhci_warn(xhci, "Device Notification event for "
				"unused slot %u\n", slot_id);
		return;
	}

	xhci_dbg(xhci, "Device Wake Notification event for slot ID %u\n",
			slot_id);
	udev = xhci->devs[slot_id]->udev;
	if (udev && udev->parent)
		usb_wakeup_notification(udev->parent, udev->portnum);
}

/*
 * Quirk hanlder for errata seen on Cavium ThunderX2 processor XHCI
 * Controller.
 * As per ThunderX2errata-129 USB 2 device may come up as USB 1
 * If a connection to a USB 1 device is followed by another connection
 * to a USB 2 device.
 *
 * Reset the PHY after the USB device is disconnected if device speed
 * is less than HCD_USB3.
 * Retry the reset sequence max of 4 times checking the PLL lock status.
 *
 */
static void xhci_cavium_reset_phy_quirk(struct xhci_hcd *xhci)
{
	struct usb_hcd *hcd = xhci_to_hcd(xhci);
	u32 pll_lock_check;
	u32 retry_count = 4;

	do {
		/* Assert PHY reset */
		writel(0x6F, hcd->regs + 0x1048);
		udelay(10);
		/* De-assert the PHY reset */
		writel(0x7F, hcd->regs + 0x1048);
		udelay(200);
		pll_lock_check = readl(hcd->regs + 0x1070);
	} while (!(pll_lock_check & 0x1) && --retry_count);
}

static void handle_port_status(struct xhci_hcd *xhci,
		union xhci_trb *event)
{
	struct usb_hcd *hcd;
	u32 port_id;
	u32 portsc, cmd_reg;
	int max_ports;
	int slot_id;
	unsigned int hcd_portnum;
	struct xhci_bus_state *bus_state;
	bool bogus_port_status = false;
	struct xhci_port *port;

	/* Port status change events always have a successful completion code */
	if (GET_COMP_CODE(le32_to_cpu(event->generic.field[2])) != COMP_SUCCESS)
		xhci_warn(xhci,
			  "WARN: xHC returned failed port status event\n");

	port_id = GET_PORT_ID(le32_to_cpu(event->generic.field[0]));
	max_ports = HCS_MAX_PORTS(xhci->hcs_params1);

	if ((port_id <= 0) || (port_id > max_ports)) {
		xhci_warn(xhci, "Port change event with invalid port ID %d\n",
			  port_id);
		inc_deq(xhci, xhci->event_ring);
		return;
	}

	port = &xhci->hw_ports[port_id - 1];
	if (!port || !port->rhub || port->hcd_portnum == DUPLICATE_ENTRY) {
		xhci_warn(xhci, "Port change event, no port for port ID %u\n",
			  port_id);
		bogus_port_status = true;
		goto cleanup;
	}

	/* We might get interrupts after shared_hcd is removed */
	if (port->rhub == &xhci->usb3_rhub && xhci->shared_hcd == NULL) {
		xhci_dbg(xhci, "ignore port event for removed USB3 hcd\n");
		bogus_port_status = true;
		goto cleanup;
	}

	hcd = port->rhub->hcd;
	bus_state = &port->rhub->bus_state;
	hcd_portnum = port->hcd_portnum;
	portsc = readl(port->addr);

	xhci_dbg(xhci, "Port change event, %d-%d, id %d, portsc: 0x%x\n",
		 hcd->self.busnum, hcd_portnum + 1, port_id, portsc);

	trace_xhci_handle_port_status(hcd_portnum, portsc);

	if (hcd->state == HC_STATE_SUSPENDED) {
		xhci_dbg(xhci, "resume root hub\n");
		usb_hcd_resume_root_hub(hcd);
	}

	if (hcd->speed >= HCD_USB3 &&
	    (portsc & PORT_PLS_MASK) == XDEV_INACTIVE) {
		slot_id = xhci_find_slot_id_by_port(hcd, xhci, hcd_portnum + 1);
		if (slot_id && xhci->devs[slot_id])
			xhci->devs[slot_id]->flags |= VDEV_PORT_ERROR;
	}

	if ((portsc & PORT_PLC) && (portsc & PORT_PLS_MASK) == XDEV_RESUME) {
		xhci_dbg(xhci, "port resume event for port %d\n", port_id);

		cmd_reg = readl(&xhci->op_regs->command);
		if (!(cmd_reg & CMD_RUN)) {
			xhci_warn(xhci, "xHC is not running.\n");
			goto cleanup;
		}

		if (DEV_SUPERSPEED_ANY(portsc)) {
			xhci_dbg(xhci, "remote wake SS port %d\n", port_id);
			/* Set a flag to say the port signaled remote wakeup,
			 * so we can tell the difference between the end of
			 * device and host initiated resume.
			 */
			bus_state->port_remote_wakeup |= 1 << hcd_portnum;
			xhci_test_and_clear_bit(xhci, port, PORT_PLC);
			usb_hcd_start_port_resume(&hcd->self, hcd_portnum);
			xhci_set_link_state(xhci, port, XDEV_U0);
			/* Need to wait until the next link state change
			 * indicates the device is actually in U0.
			 */
			bogus_port_status = true;
			goto cleanup;
		} else if (!test_bit(hcd_portnum, &bus_state->resuming_ports)) {
			xhci_dbg(xhci, "resume HS port %d\n", port_id);
			bus_state->resume_done[hcd_portnum] = jiffies +
				msecs_to_jiffies(USB_RESUME_TIMEOUT);
			set_bit(hcd_portnum, &bus_state->resuming_ports);
			/* Do the rest in GetPortStatus after resume time delay.
			 * Avoid polling roothub status before that so that a
			 * usb device auto-resume latency around ~40ms.
			 */
			set_bit(HCD_FLAG_POLL_RH, &hcd->flags);
			mod_timer(&hcd->rh_timer,
				  bus_state->resume_done[hcd_portnum]);
			usb_hcd_start_port_resume(&hcd->self, hcd_portnum);
			bogus_port_status = true;
		}
	}

	if ((portsc & PORT_PLC) &&
	    DEV_SUPERSPEED_ANY(portsc) &&
	    ((portsc & PORT_PLS_MASK) == XDEV_U0 ||
	     (portsc & PORT_PLS_MASK) == XDEV_U1 ||
	     (portsc & PORT_PLS_MASK) == XDEV_U2)) {
		xhci_dbg(xhci, "resume SS port %d finished\n", port_id);
		complete(&bus_state->u3exit_done[hcd_portnum]);
		/* We've just brought the device into U0/1/2 through either the
		 * Resume state after a device remote wakeup, or through the
		 * U3Exit state after a host-initiated resume.  If it's a device
		 * initiated remote wake, don't pass up the link state change,
		 * so the roothub behavior is consistent with external
		 * USB 3.0 hub behavior.
		 */
		slot_id = xhci_find_slot_id_by_port(hcd, xhci, hcd_portnum + 1);
		if (slot_id && xhci->devs[slot_id])
			xhci_ring_device(xhci, slot_id);
		if (bus_state->port_remote_wakeup & (1 << hcd_portnum)) {
			xhci_test_and_clear_bit(xhci, port, PORT_PLC);
			usb_wakeup_notification(hcd->self.root_hub,
					hcd_portnum + 1);
			bogus_port_status = true;
			goto cleanup;
		}
	}

	/*
	 * Check to see if xhci-hub.c is waiting on RExit to U0 transition (or
	 * RExit to a disconnect state).  If so, let the the driver know it's
	 * out of the RExit state.
	 */
	if (!DEV_SUPERSPEED_ANY(portsc) && hcd->speed < HCD_USB3 &&
			test_and_clear_bit(hcd_portnum,
				&bus_state->rexit_ports)) {
		complete(&bus_state->rexit_done[hcd_portnum]);
		bogus_port_status = true;
		goto cleanup;
	}

	if (hcd->speed < HCD_USB3) {
		xhci_test_and_clear_bit(xhci, port, PORT_PLC);
		if ((xhci->quirks & XHCI_RESET_PLL_ON_DISCONNECT) &&
		    (portsc & PORT_CSC) && !(portsc & PORT_CONNECT))
			xhci_cavium_reset_phy_quirk(xhci);
	}

cleanup:
	/* Update event ring dequeue pointer before dropping the lock */
	inc_deq(xhci, xhci->event_ring);

	/* Don't make the USB core poll the roothub if we got a bad port status
	 * change event.  Besides, at that point we can't tell which roothub
	 * (USB 2.0 or USB 3.0) to kick.
	 */
	if (bogus_port_status)
		return;

	/*
	 * xHCI port-status-change events occur when the "or" of all the
	 * status-change bits in the portsc register changes from 0 to 1.
	 * New status changes won't cause an event if any other change
	 * bits are still set.  When an event occurs, switch over to
	 * polling to avoid losing status changes.
	 */
	xhci_dbg(xhci, "%s: starting port polling.\n", __func__);
	set_bit(HCD_FLAG_POLL_RH, &hcd->flags);
	spin_unlock(&xhci->lock);
	/* Pass this up to the core */
	usb_hcd_poll_rh_status(hcd);
	spin_lock(&xhci->lock);
}

/*
 * This TD is defined by the TRBs starting at start_trb in start_seg and ending
 * at end_trb, which may be in another segment.  If the suspect DMA address is a
 * TRB in this TD, this function returns that TRB's segment.  Otherwise it
 * returns 0.
 */
struct xhci_segment *trb_in_td(struct xhci_hcd *xhci,
		struct xhci_segment *start_seg,
		union xhci_trb	*start_trb,
		union xhci_trb	*end_trb,
		dma_addr_t	suspect_dma,
		bool		debug)
{
	dma_addr_t start_dma;
	dma_addr_t end_seg_dma;
	dma_addr_t end_trb_dma;
	struct xhci_segment *cur_seg;

	start_dma = xhci_trb_virt_to_dma(start_seg, start_trb);
	cur_seg = start_seg;

	do {
		if (start_dma == 0)
			return NULL;
		/* We may get an event for a Link TRB in the middle of a TD */
		end_seg_dma = xhci_trb_virt_to_dma(cur_seg,
				&cur_seg->trbs[TRBS_PER_SEGMENT - 1]);
		/* If the end TRB isn't in this segment, this is set to 0 */
		end_trb_dma = xhci_trb_virt_to_dma(cur_seg, end_trb);

		if (debug)
			xhci_warn(xhci,
				"Looking for event-dma %016llx trb-start %016llx trb-end %016llx seg-start %016llx seg-end %016llx\n",
				(unsigned long long)suspect_dma,
				(unsigned long long)start_dma,
				(unsigned long long)end_trb_dma,
				(unsigned long long)cur_seg->dma,
				(unsigned long long)end_seg_dma);

		if (end_trb_dma > 0) {
			/* The end TRB is in this segment, so suspect should be here */
			if (start_dma <= end_trb_dma) {
				if (suspect_dma >= start_dma && suspect_dma <= end_trb_dma)
					return cur_seg;
			} else {
				/* Case for one segment with
				 * a TD wrapped around to the top
				 */
				if ((suspect_dma >= start_dma &&
							suspect_dma <= end_seg_dma) ||
						(suspect_dma >= cur_seg->dma &&
						 suspect_dma <= end_trb_dma))
					return cur_seg;
			}
			return NULL;
		} else {
			/* Might still be somewhere in this segment */
			if (suspect_dma >= start_dma && suspect_dma <= end_seg_dma)
				return cur_seg;
		}
		cur_seg = cur_seg->next;
		start_dma = xhci_trb_virt_to_dma(cur_seg, &cur_seg->trbs[0]);
	} while (cur_seg != start_seg);

	return NULL;
}

static void xhci_clear_hub_tt_buffer(struct xhci_hcd *xhci, struct xhci_td *td,
		struct xhci_virt_ep *ep)
{
	/*
	 * As part of low/full-speed endpoint-halt processing
	 * we must clear the TT buffer (USB 2.0 specification 11.17.5).
	 */
	if (td->urb->dev->tt && !usb_pipeint(td->urb->pipe) &&
	    (td->urb->dev->tt->hub != xhci_to_hcd(xhci)->self.root_hub) &&
	    !(ep->ep_state & EP_CLEARING_TT)) {
		ep->ep_state |= EP_CLEARING_TT;
		td->urb->ep->hcpriv = td->urb->dev;
		if (usb_hub_clear_tt_buffer(td->urb))
			ep->ep_state &= ~EP_CLEARING_TT;
	}
}

/* Check if an error has halted the endpoint ring.  The class driver will
 * cleanup the halt for a non-default control endpoint if we indicate a stall.
 * However, a babble and other errors also halt the endpoint ring, and the class
 * driver won't clear the halt in that case, so we need to issue a Set Transfer
 * Ring Dequeue Pointer command manually.
 */
static int xhci_requires_manual_halt_cleanup(struct xhci_hcd *xhci,
		struct xhci_ep_ctx *ep_ctx,
		unsigned int trb_comp_code)
{
	/* TRB completion codes that may require a manual halt cleanup */
	if (trb_comp_code == COMP_USB_TRANSACTION_ERROR ||
			trb_comp_code == COMP_BABBLE_DETECTED_ERROR ||
			trb_comp_code == COMP_SPLIT_TRANSACTION_ERROR)
		/* The 0.95 spec says a babbling control endpoint
		 * is not halted. The 0.96 spec says it is.  Some HW
		 * claims to be 0.95 compliant, but it halts the control
		 * endpoint anyway.  Check if a babble halted the
		 * endpoint.
		 */
		if (GET_EP_CTX_STATE(ep_ctx) == EP_STATE_HALTED)
			return 1;

	return 0;
}

int xhci_is_vendor_info_code(struct xhci_hcd *xhci, unsigned int trb_comp_code)
{
	if (trb_comp_code >= 224 && trb_comp_code <= 255) {
		/* Vendor defined "informational" completion code,
		 * treat as not-an-error.
		 */
		xhci_dbg(xhci, "Vendor defined info completion code %u\n",
				trb_comp_code);
		xhci_dbg(xhci, "Treating code as success.\n");
		return 1;
	}
	return 0;
}

static int finish_td(struct xhci_hcd *xhci, struct xhci_virt_ep *ep,
		     struct xhci_ring *ep_ring, struct xhci_td *td,
		     u32 trb_comp_code)
{
	struct xhci_ep_ctx *ep_ctx;

	ep_ctx = xhci_get_ep_ctx(xhci, ep->vdev->out_ctx, ep->ep_index);

	switch (trb_comp_code) {
	case COMP_STOPPED_LENGTH_INVALID:
	case COMP_STOPPED_SHORT_PACKET:
	case COMP_STOPPED:
		/*
		 * The "Stop Endpoint" completion will take care of any
		 * stopped TDs. A stopped TD may be restarted, so don't update
		 * the ring dequeue pointer or take this TD off any lists yet.
		 */
		return 0;
	case COMP_USB_TRANSACTION_ERROR:
	case COMP_BABBLE_DETECTED_ERROR:
	case COMP_SPLIT_TRANSACTION_ERROR:
		/*
		 * If endpoint context state is not halted we might be
		 * racing with a reset endpoint command issued by a unsuccessful
		 * stop endpoint completion (context error). In that case the
		 * td should be on the cancelled list, and EP_HALTED flag set.
		 *
		 * Or then it's not halted due to the 0.95 spec stating that a
		 * babbling control endpoint should not halt. The 0.96 spec
		 * again says it should.  Some HW claims to be 0.95 compliant,
		 * but it halts the control endpoint anyway.
		 */
		if (GET_EP_CTX_STATE(ep_ctx) != EP_STATE_HALTED) {
			/*
			 * If EP_HALTED is set and TD is on the cancelled list
			 * the TD and dequeue pointer will be handled by reset
			 * ep command completion
			 */
			if ((ep->ep_state & EP_HALTED) &&
			    !list_empty(&td->cancelled_td_list)) {
				xhci_dbg(xhci, "Already resolving halted ep for 0x%llx\n",
					 (unsigned long long)xhci_trb_virt_to_dma(
						 td->start_seg, td->first_trb));
				return 0;
			}
			/* endpoint not halted, don't reset it */
			break;
		}
		/* Almost same procedure as for STALL_ERROR below */
		xhci_clear_hub_tt_buffer(xhci, td, ep);
		xhci_handle_halted_endpoint(xhci, ep, ep_ring->stream_id, td,
					    EP_HARD_RESET);
		return 0;
	case COMP_STALL_ERROR:
		/*
		 * xhci internal endpoint state will go to a "halt" state for
		 * any stall, including default control pipe protocol stall.
		 * To clear the host side halt we need to issue a reset endpoint
		 * command, followed by a set dequeue command to move past the
		 * TD.
		 * Class drivers clear the device side halt from a functional
		 * stall later. Hub TT buffer should only be cleared for FS/LS
		 * devices behind HS hubs for functional stalls.
		 */
		if (ep->ep_index != 0)
			xhci_clear_hub_tt_buffer(xhci, td, ep);

		xhci_handle_halted_endpoint(xhci, ep, ep_ring->stream_id, td,
					    EP_HARD_RESET);

		return 0; /* xhci_handle_halted_endpoint marked td cancelled */
	default:
		break;
	}

	/* Update ring dequeue pointer */
	ep_ring->dequeue = td->last_trb;
	ep_ring->deq_seg = td->last_trb_seg;
	ep_ring->num_trbs_free += td->num_trbs - 1;
	inc_deq(xhci, ep_ring);

	return xhci_td_cleanup(xhci, td, ep_ring, td->status);
}

/* sum trb lengths from ring dequeue up to stop_trb, _excluding_ stop_trb */
static int sum_trb_lengths(struct xhci_hcd *xhci, struct xhci_ring *ring,
			   union xhci_trb *stop_trb)
{
	u32 sum;
	union xhci_trb *trb = ring->dequeue;
	struct xhci_segment *seg = ring->deq_seg;

	for (sum = 0; trb != stop_trb; next_trb(xhci, ring, &seg, &trb)) {
		if (!trb_is_noop(trb) && !trb_is_link(trb))
			sum += TRB_LEN(le32_to_cpu(trb->generic.field[2]));
	}
	return sum;
}

/*
 * Process control tds, update urb status and actual_length.
 */
static int process_ctrl_td(struct xhci_hcd *xhci, struct xhci_virt_ep *ep,
		struct xhci_ring *ep_ring,  struct xhci_td *td,
			   union xhci_trb *ep_trb, struct xhci_transfer_event *event)
{
	struct xhci_ep_ctx *ep_ctx;
	u32 trb_comp_code;
	u32 remaining, requested;
	u32 trb_type;

	trb_type = TRB_FIELD_TO_TYPE(le32_to_cpu(ep_trb->generic.field[3]));
	ep_ctx = xhci_get_ep_ctx(xhci, ep->vdev->out_ctx, ep->ep_index);
	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));
	requested = td->urb->transfer_buffer_length;
	remaining = EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));

	switch (trb_comp_code) {
	case COMP_SUCCESS:
		if (trb_type != TRB_STATUS) {
			xhci_warn(xhci, "WARN: Success on ctrl %s TRB without IOC set?\n",
				  (trb_type == TRB_DATA) ? "data" : "setup");
			td->status = -ESHUTDOWN;
			break;
		}
		td->status = 0;
		break;
	case COMP_SHORT_PACKET:
		td->status = 0;
		break;
	case COMP_STOPPED_SHORT_PACKET:
		if (trb_type == TRB_DATA || trb_type == TRB_NORMAL)
			td->urb->actual_length = remaining;
		else
			xhci_warn(xhci, "WARN: Stopped Short Packet on ctrl setup or status TRB\n");
		goto finish_td;
	case COMP_STOPPED:
		switch (trb_type) {
		case TRB_SETUP:
			td->urb->actual_length = 0;
			goto finish_td;
		case TRB_DATA:
		case TRB_NORMAL:
			td->urb->actual_length = requested - remaining;
			goto finish_td;
		case TRB_STATUS:
			td->urb->actual_length = requested;
			goto finish_td;
		default:
			xhci_warn(xhci, "WARN: unexpected TRB Type %d\n",
				  trb_type);
			goto finish_td;
		}
	case COMP_STOPPED_LENGTH_INVALID:
		goto finish_td;
	default:
		if (!xhci_requires_manual_halt_cleanup(xhci,
						       ep_ctx, trb_comp_code))
			break;
		xhci_dbg(xhci, "TRB error %u, halted endpoint index = %u\n",
			 trb_comp_code, ep->ep_index);
		fallthrough;
	case COMP_STALL_ERROR:
		/* Did we transfer part of the data (middle) phase? */
		if (trb_type == TRB_DATA || trb_type == TRB_NORMAL)
			td->urb->actual_length = requested - remaining;
		else if (!td->urb_length_set)
			td->urb->actual_length = 0;
		goto finish_td;
	}

	/* stopped at setup stage, no data transferred */
	if (trb_type == TRB_SETUP)
		goto finish_td;

	/*
	 * if on data stage then update the actual_length of the URB and flag it
	 * as set, so it won't be overwritten in the event for the last TRB.
	 */
	if (trb_type == TRB_DATA ||
		trb_type == TRB_NORMAL) {
		td->urb_length_set = true;
		td->urb->actual_length = requested - remaining;
		xhci_dbg(xhci, "Waiting for status stage event\n");
		return 0;
	}

	/* at status stage */
	if (!td->urb_length_set)
		td->urb->actual_length = requested;

finish_td:
	return finish_td(xhci, ep, ep_ring, td, trb_comp_code);
}

/*
 * Process isochronous tds, update urb packet status and actual_length.
 */
static int process_isoc_td(struct xhci_hcd *xhci, struct xhci_virt_ep *ep,
		struct xhci_ring *ep_ring, struct xhci_td *td,
		union xhci_trb *ep_trb, struct xhci_transfer_event *event)
{
	struct urb_priv *urb_priv;
	int idx;
	struct usb_iso_packet_descriptor *frame;
	u32 trb_comp_code;
	bool sum_trbs_for_length = false;
	u32 remaining, requested, ep_trb_len;
	int short_framestatus;

	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));
	urb_priv = td->urb->hcpriv;
	idx = urb_priv->num_tds_done;
	frame = &td->urb->iso_frame_desc[idx];
	requested = frame->length;
	remaining = EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));
	ep_trb_len = TRB_LEN(le32_to_cpu(ep_trb->generic.field[2]));
	short_framestatus = td->urb->transfer_flags & URB_SHORT_NOT_OK ?
		-EREMOTEIO : 0;

	/* handle completion code */
	switch (trb_comp_code) {
	case COMP_SUCCESS:
		if (remaining) {
			frame->status = short_framestatus;
			if (xhci->quirks & XHCI_TRUST_TX_LENGTH)
				sum_trbs_for_length = true;
			break;
		}
		frame->status = 0;
		break;
	case COMP_SHORT_PACKET:
		frame->status = short_framestatus;
		sum_trbs_for_length = true;
		break;
	case COMP_BANDWIDTH_OVERRUN_ERROR:
		frame->status = -ECOMM;
		break;
	case COMP_ISOCH_BUFFER_OVERRUN:
	case COMP_BABBLE_DETECTED_ERROR:
		frame->status = -EOVERFLOW;
		break;
	case COMP_INCOMPATIBLE_DEVICE_ERROR:
	case COMP_STALL_ERROR:
		frame->status = -EPROTO;
		break;
	case COMP_USB_TRANSACTION_ERROR:
		frame->status = -EPROTO;
		if (ep_trb != td->last_trb)
			return 0;
		break;
	case COMP_STOPPED:
		sum_trbs_for_length = true;
		break;
	case COMP_STOPPED_SHORT_PACKET:
		/* field normally containing residue now contains tranferred */
		frame->status = short_framestatus;
		requested = remaining;
		break;
	case COMP_STOPPED_LENGTH_INVALID:
		requested = 0;
		remaining = 0;
		break;
	default:
		sum_trbs_for_length = true;
		frame->status = -1;
		break;
	}

	if (sum_trbs_for_length)
		frame->actual_length = sum_trb_lengths(xhci, ep->ring, ep_trb) +
			ep_trb_len - remaining;
	else
		frame->actual_length = requested;

	td->urb->actual_length += frame->actual_length;

	return finish_td(xhci, ep, ep_ring, td, trb_comp_code);
}

static int skip_isoc_td(struct xhci_hcd *xhci, struct xhci_td *td,
			struct xhci_virt_ep *ep, int status)
{
	struct urb_priv *urb_priv;
	struct usb_iso_packet_descriptor *frame;
	int idx;

	urb_priv = td->urb->hcpriv;
	idx = urb_priv->num_tds_done;
	frame = &td->urb->iso_frame_desc[idx];

	/* The transfer is partly done. */
	frame->status = -EXDEV;

	/* calc actual length */
	frame->actual_length = 0;

	/* Update ring dequeue pointer */
	ep->ring->dequeue = td->last_trb;
	ep->ring->deq_seg = td->last_trb_seg;
	ep->ring->num_trbs_free += td->num_trbs - 1;
	inc_deq(xhci, ep->ring);

	return xhci_td_cleanup(xhci, td, ep->ring, status);
}

/*
 * Process bulk and interrupt tds, update urb status and actual_length.
 */
static int process_bulk_intr_td(struct xhci_hcd *xhci, struct xhci_virt_ep *ep,
		struct xhci_ring *ep_ring, struct xhci_td *td,
		union xhci_trb *ep_trb, struct xhci_transfer_event *event)
{
	struct xhci_slot_ctx *slot_ctx;
	u32 trb_comp_code;
	u32 remaining, requested, ep_trb_len;

	slot_ctx = xhci_get_slot_ctx(xhci, ep->vdev->out_ctx);
	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));
	remaining = EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));
	ep_trb_len = TRB_LEN(le32_to_cpu(ep_trb->generic.field[2]));
	requested = td->urb->transfer_buffer_length;

	switch (trb_comp_code) {
	case COMP_SUCCESS:
		ep_ring->err_count = 0;
		/* handle success with untransferred data as short packet */
		if (ep_trb != td->last_trb || remaining) {
			xhci_warn(xhci, "WARN Successful completion on short TX\n");
			xhci_dbg(xhci, "ep %#x - asked for %d bytes, %d bytes untransferred\n",
				 td->urb->ep->desc.bEndpointAddress,
				 requested, remaining);
		}
		td->status = 0;
		break;
	case COMP_SHORT_PACKET:
		xhci_dbg(xhci, "ep %#x - asked for %d bytes, %d bytes untransferred\n",
			 td->urb->ep->desc.bEndpointAddress,
			 requested, remaining);
		td->status = 0;
		break;
	case COMP_STOPPED_SHORT_PACKET:
		td->urb->actual_length = remaining;
		goto finish_td;
	case COMP_STOPPED_LENGTH_INVALID:
		/* stopped on ep trb with invalid length, exclude it */
		ep_trb_len	= 0;
		remaining	= 0;
		break;
	case COMP_USB_TRANSACTION_ERROR:
		if (xhci->quirks & XHCI_NO_SOFT_RETRY ||
		    (ep_ring->err_count++ > MAX_SOFT_RETRY) ||
		    le32_to_cpu(slot_ctx->tt_info) & TT_SLOT)
			break;

		td->status = 0;

		xhci_handle_halted_endpoint(xhci, ep, ep_ring->stream_id, td,
					    EP_SOFT_RESET);
		return 0;
	default:
		/* do nothing */
		break;
	}

	if (ep_trb == td->last_trb)
		td->urb->actual_length = requested - remaining;
	else
		td->urb->actual_length =
			sum_trb_lengths(xhci, ep_ring, ep_trb) +
			ep_trb_len - remaining;
finish_td:
	if (remaining > requested) {
		xhci_warn(xhci, "bad transfer trb length %d in event trb\n",
			  remaining);
		td->urb->actual_length = 0;
	}

	return finish_td(xhci, ep, ep_ring, td, trb_comp_code);
}

/*
 * If this function returns an error condition, it means it got a Transfer
 * event with a corrupted Slot ID, Endpoint ID, or TRB DMA address.
 * At this point, the host controller is probably hosed and should be reset.
 */
static int handle_tx_event(struct xhci_hcd *xhci,
		struct xhci_transfer_event *event)
{
	struct xhci_virt_ep *ep;
	struct xhci_ring *ep_ring;
	unsigned int slot_id;
	int ep_index;
	struct xhci_td *td = NULL;
	dma_addr_t ep_trb_dma;
	struct xhci_segment *ep_seg;
	union xhci_trb *ep_trb;
	int status = -EINPROGRESS;
	struct xhci_ep_ctx *ep_ctx;
	struct list_head *tmp;
	u32 trb_comp_code;
	int td_num = 0;
	bool handling_skipped_tds = false;

	slot_id = TRB_TO_SLOT_ID(le32_to_cpu(event->flags));
	ep_index = TRB_TO_EP_ID(le32_to_cpu(event->flags)) - 1;
	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));
	ep_trb_dma = le64_to_cpu(event->buffer);

	ep = xhci_get_virt_ep(xhci, slot_id, ep_index);
	if (!ep) {
		xhci_err(xhci, "ERROR Invalid Transfer event\n");
		goto err_out;
	}

	ep_ring = xhci_dma_to_transfer_ring(ep, ep_trb_dma);
	ep_ctx = xhci_get_ep_ctx(xhci, ep->vdev->out_ctx, ep_index);

	if (GET_EP_CTX_STATE(ep_ctx) == EP_STATE_DISABLED) {
		xhci_err(xhci,
			 "ERROR Transfer event for disabled endpoint slot %u ep %u\n",
			  slot_id, ep_index);
		goto err_out;
	}

	/* Some transfer events don't always point to a trb, see xhci 4.17.4 */
	if (!ep_ring) {
		switch (trb_comp_code) {
		case COMP_STALL_ERROR:
		case COMP_USB_TRANSACTION_ERROR:
		case COMP_INVALID_STREAM_TYPE_ERROR:
		case COMP_INVALID_STREAM_ID_ERROR:
			xhci_handle_halted_endpoint(xhci, ep, 0, NULL,
						    EP_SOFT_RESET);
			goto cleanup;
		case COMP_RING_UNDERRUN:
		case COMP_RING_OVERRUN:
		case COMP_STOPPED_LENGTH_INVALID:
			goto cleanup;
		default:
			xhci_err(xhci, "ERROR Transfer event for unknown stream ring slot %u ep %u\n",
				 slot_id, ep_index);
			goto err_out;
		}
	}

	/* Count current td numbers if ep->skip is set */
	if (ep->skip) {
