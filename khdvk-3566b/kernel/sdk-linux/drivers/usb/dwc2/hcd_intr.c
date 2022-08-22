// SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause)
/*
 * hcd_intr.c - DesignWare HS OTG Controller host-mode interrupt handling
 *
 * Copyright (C) 2004-2013 Synopsys, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the above-listed copyright holders may not be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file contains the interrupt handlers for Host mode
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/usb.h>

#include <linux/usb/hcd.h>
#include <linux/usb/ch11.h>

#include "core.h"
#include "hcd.h"

/*
 * If we get this many NAKs on a split transaction we'll slow down
 * retransmission.  A 1 here means delay after the first NAK.
 */
#define DWC2_NAKS_BEFORE_DELAY		3

/* This function is for debug only */
static void dwc2_track_missed_sofs(struct dwc2_hsotg *hsotg)
{
	u16 curr_frame_number = hsotg->frame_number;
	u16 expected = dwc2_frame_num_inc(hsotg->last_frame_num, 1);

	if (expected != curr_frame_number)
		dwc2_sch_vdbg(hsotg, "MISSED SOF %04x != %04x\n",
			      expected, curr_frame_number);

#ifdef CONFIG_USB_DWC2_TRACK_MISSED_SOFS
	if (hsotg->frame_num_idx < FRAME_NUM_ARRAY_SIZE) {
		if (expected != curr_frame_number) {
			hsotg->frame_num_array[hsotg->frame_num_idx] =
					curr_frame_number;
			hsotg->last_frame_num_array[hsotg->frame_num_idx] =
					hsotg->last_frame_num;
			hsotg->frame_num_idx++;
		}
	} else if (!hsotg->dumped_frame_num_array) {
		int i;

		dev_info(hsotg->dev, "Frame     Last Frame\n");
		dev_info(hsotg->dev, "-----     ----------\n");
		for (i = 0; i < FRAME_NUM_ARRAY_SIZE; i++) {
			dev_info(hsotg->dev, "0x%04x    0x%04x\n",
				 hsotg->frame_num_array[i],
				 hsotg->last_frame_num_array[i]);
		}
		hsotg->dumped_frame_num_array = 1;
	}
#endif
	hsotg->last_frame_num = curr_frame_number;
}

static void dwc2_hc_handle_tt_clear(struct dwc2_hsotg *hsotg,
				    struct dwc2_host_chan *chan,
				    struct dwc2_qtd *qtd)
{
	struct usb_device *root_hub = dwc2_hsotg_to_hcd(hsotg)->self.root_hub;
	struct urb *usb_urb;

	if (!chan->qh)
		return;

	if (chan->qh->dev_speed == USB_SPEED_HIGH)
		return;

	if (!qtd->urb)
		return;

	usb_urb = qtd->urb->priv;
	if (!usb_urb || !usb_urb->dev || !usb_urb->dev->tt)
		return;

	/*
	 * The root hub doesn't really have a TT, but Linux thinks it
	 * does because how could you have a "high speed hub" that
	 * directly talks directly to low speed devices without a TT?
	 * It's all lies.  Lies, I tell you.
	 */
	if (usb_urb->dev->tt->hub == root_hub)
		return;

	if (qtd->urb->status != -EPIPE && qtd->urb->status != -EREMOTEIO) {
		chan->qh->tt_buffer_dirty = 1;
		if (usb_hub_clear_tt_buffer(usb_urb))
			/* Clear failed; let's hope things work anyway */
			chan->qh->tt_buffer_dirty = 0;
	}
}

/*
 * Handles the start-of-frame interrupt in host mode. Non-periodic
 * transactions may be queued to the DWC_otg controller for the current
 * (micro)frame. Periodic transactions may be queued to the controller
 * for the next (micro)frame.
 */
static void dwc2_sof_intr(struct dwc2_hsotg *hsotg)
{
	struct list_head *qh_entry;
	struct dwc2_qh *qh;
	enum dwc2_transaction_type tr_type;

	/* Clear interrupt */
	dwc2_writel(hsotg, GINTSTS_SOF, GINTSTS);

#ifdef DEBUG_SOF
	dev_vdbg(hsotg->dev, "--Start of Frame Interrupt--\n");
#endif

	hsotg->frame_number = dwc2_hcd_get_frame_number(hsotg);

	dwc2_track_missed_sofs(hsotg);

	/* Determine whether any periodic QHs should be executed */
	qh_entry = hsotg->periodic_sched_inactive.next;
	while (qh_entry != &hsotg->periodic_sched_inactive) {
		qh = list_entry(qh_entry, struct dwc2_qh, qh_list_entry);
		qh_entry = qh_entry->next;
		if (dwc2_frame_num_le(qh->next_active_frame,
				      hsotg->frame_number)) {
			dwc2_sch_vdbg(hsotg, "QH=%p ready fn=%04x, nxt=%04x\n",
				      qh, hsotg->frame_number,
				      qh->next_active_frame);

			/*
			 * Move QH to the ready list to be executed next
			 * (micro)frame
			 */
			list_move_tail(&qh->qh_list_entry,
				       &hsotg->periodic_sched_ready);
		}
	}
	tr_type = dwc2_hcd_select_transactions(hsotg);
	if (tr_type != DWC2_TRANSACTION_NONE)
		dwc2_hcd_queue_transactions(hsotg, tr_type);
}

/*
 * Handles the Rx FIFO Level Interrupt, which indicates that there is
 * at least one packet in the Rx FIFO. The packets are moved from the FIFO to
 * memory if the DWC_otg controller is operating in Slave mode.
 */
static void dwc2_rx_fifo_level_intr(struct dwc2_hsotg *hsotg)
{
	u32 grxsts, chnum, bcnt, dpid, pktsts;
	struct dwc2_host_chan *chan;

	if (dbg_perio())
		dev_vdbg(hsotg->dev, "--RxFIFO Level Interrupt--\n");

	grxsts = dwc2_readl(hsotg, GRXSTSP);
	chnum = (grxsts & GRXSTS_HCHNUM_MASK) >> GRXSTS_HCHNUM_SHIFT;
	chan = hsotg->hc_ptr_array[chnum];
	if (!chan) {
		dev_err(hsotg->dev, "Unable to get corresponding channel\n");
		return;
	}

	bcnt = (grxsts & GRXSTS_BYTECNT_MASK) >> GRXSTS_BYTECNT_SHIFT;
	dpid = (grxsts & GRXSTS_DPID_MASK) >> GRXSTS_DPID_SHIFT;
	pktsts = (grxsts & GRXSTS_PKTSTS_MASK) >> GRXSTS_PKTSTS_SHIFT;

	/* Packet Status */
	if (dbg_perio()) {
		dev_vdbg(hsotg->dev, "    Ch num = %d\n", chnum);
		dev_vdbg(hsotg->dev, "    Count = %d\n", bcnt);
		dev_vdbg(hsotg->dev, "    DPID = %d, chan.dpid = %d\n", dpid,
			 chan->data_pid_start);
		dev_vdbg(hsotg->dev, "    PStatus = %d\n", pktsts);
	}

	switch (pktsts) {
	case GRXSTS_PKTSTS_HCHIN:
		/* Read the data into the host buffer */
		if (bcnt > 0) {
			dwc2_read_packet(hsotg, chan->xfer_buf, bcnt);

			/* Update the HC fields for the next packet received */
			chan->xfer_count += bcnt;
			chan->xfer_buf += bcnt;
		}
		break;
	case GRXSTS_PKTSTS_HCHIN_XFER_COMP:
	case GRXSTS_PKTSTS_DATATOGGLEERR:
	case GRXSTS_PKTSTS_HCHHALTED:
		/* Handled in interrupt, just ignore data */
		break;
	default:
		dev_err(hsotg->dev,
			"RxFIFO Level Interrupt: Unknown status %d\n", pktsts);
		break;
	}
}

/*
 * This interrupt occurs when the non-periodic Tx FIFO is half-empty. More
 * data packets may be written to the FIFO for OUT transfers. More requests
 * may be written to the non-periodic request queue for IN transfers. This
 * interrupt is enabled only in Slave mode.
 */
static void dwc2_np_tx_fifo_empty_intr(struct dwc2_hsotg *hsotg)
{
	dev_vdbg(hsotg->dev, "--Non-Periodic TxFIFO Empty Interrupt--\n");
	dwc2_hcd_queue_transactions(hsotg, DWC2_TRANSACTION_NON_PERIODIC);
}

/*
 * This interrupt occurs when the periodic Tx FIFO is half-empty. More data
 * packets may be written to the FIFO for OUT transfers. More requests may be
 * written to the periodic request queue for IN transfers. This interrupt is
 * enabled only in Slave mode.
 */
static void dwc2_perio_tx_fifo_empty_intr(struct dwc2_hsotg *hsotg)
{
	if (dbg_perio())
		dev_vdbg(hsotg->dev, "--Periodic TxFIFO Empty Interrupt--\n");
	dwc2_hcd_queue_transactions(hsotg, DWC2_TRANSACTION_PERIODIC);
}

static void dwc2_hprt0_enable(struct dwc2_hsotg *hsotg, u32 hprt0,
			      u32 *hprt0_modify)
{
	struct dwc2_core_params *params = &hsotg->params;
	int do_reset = 0;
	u32 usbcfg;
	u32 prtspd;
	u32 hcfg;
	u32 fslspclksel;
	u32 hfir;

	dev_vdbg(hsotg->dev, "%s(%p)\n", __func__, hsotg);

	/* Every time when port enables calculate HFIR.FrInterval */
	hfir = dwc2_readl(hsotg, HFIR);
	hfir &= ~HFIR_FRINT_MASK;
	hfir |= dwc2_calc_frame_interval(hsotg) << HFIR_FRINT_SHIFT &
		HFIR_FRINT_MASK;
	dwc2_writel(hsotg, hfir, HFIR);

	/* Check if we need to adjust the PHY clock speed for low power */
	if (!params->host_support_fs_ls_low_power) {
		/* Port has been enabled, set the reset change flag */
		hsotg->flags.b.port_reset_change = 1;
		return;
	}

	usbcfg = dwc2_readl(hsotg, GUSBCFG);
	prtspd = (hprt0 & HPRT0_SPD_MASK) >> HPRT0_SPD_SHIFT;

	if (prtspd == HPRT0_SPD_LOW_SPEED || prtspd == HPRT0_SPD_FULL_SPEED) {
		/* Low power */
		if (!(usbcfg & GUSBCFG_PHY_LP_CLK_SEL)) {
			/* Set PHY low power clock select for FS/LS devices */
			usbcfg |= GUSBCFG_PHY_LP_CLK_SEL;
			dwc2_writel(hsotg, usbcfg, GUSBCFG);
			do_reset = 1;
		}

		hcfg = dwc2_readl(hsotg, HCFG);
		fslspclksel = (hcfg & HCFG_FSLSPCLKSEL_MASK) >>
			      HCFG_FSLSPCLKSEL_SHIFT;

		if (prtspd == HPRT0_SPD_LOW_SPEED &&
		    params->host_ls_low_power_phy_clk) {
			/* 6 MHZ */
			dev_vdbg(hsotg->dev,
				 "FS_PHY programming HCFG to 6 MHz\n");
			if (fslspclksel != HCFG_FSLSPCLKSEL_6_MHZ) {
				fslspclksel = HCFG_FSLSPCLKSEL_6_MHZ;
				hcfg &= ~HCFG_FSLSPCLKSEL_MASK;
				hcfg |= fslspclksel << HCFG_FSLSPCLKSEL_SHIFT;
				dwc2_writel(hsotg, hcfg, HCFG);
				do_reset = 1;
			}
		} else {
			/* 48 MHZ */
			dev_vdbg(hsotg->dev,
				 "FS_PHY programming HCFG to 48 MHz\n");
			if (fslspclksel != HCFG_FSLSPCLKSEL_48_MHZ) {
				fslspclksel = HCFG_FSLSPCLKSEL_48_MHZ;
				hcfg &= ~HCFG_FSLSPCLKSEL_MASK;
				hcfg |= fslspclksel << HCFG_FSLSPCLKSEL_SHIFT;
				dwc2_writel(hsotg, hcfg, HCFG);
				do_reset = 1;
			}
		}
	} else {
		/* Not low power */
		if (usbcfg & GUSBCFG_PHY_LP_CLK_SEL) {
			usbcfg &= ~GUSBCFG_PHY_LP_CLK_SEL;
			dwc2_writel(hsotg, usbcfg, GUSBCFG);
			do_reset = 1;
		}
	}

	if (do_reset) {
		*hprt0_modify |= HPRT0_RST;
		dwc2_writel(hsotg, *hprt0_modify, HPRT0);
		queue_delayed_work(hsotg->wq_otg, &hsotg->reset_work,
				   msecs_to_jiffies(60));
	} else {
		/* Port has been enabled, set the reset change flag */
		hsotg->flags.b.port_reset_change = 1;
	}
}

/*
 * There are multiple conditions that can cause a port interrupt. This function
 * determines which interrupt conditions have occurred and handles them
 * appropriately.
 */
static void dwc2_port_intr(struct dwc2_hsotg *hsotg)
{
	u32 hprt0;
	u32 hprt0_modify;

	dev_vdbg(hsotg->dev, "--Port Interrupt--\n");

	hprt0 = dwc2_readl(hsotg, HPRT0);
	hprt0_modify = hprt0;

	/*
	 * Clear appropriate bits in HPRT0 to clear the interrupt bit in
	 * GINTSTS
	 */
	hprt0_modify &= ~(HPRT0_ENA | HPRT0_CONNDET | HPRT0_ENACHG |
			  HPRT0_OVRCURRCHG);

	/*
	 * Port Connect Detected
	 * Set flag and clear if detected
	 */
	if (hprt0 & HPRT0_CONNDET) {
		dwc2_writel(hsotg, hprt0_modify | HPRT0_CONNDET, HPRT0);

		dev_vdbg(hsotg->dev,
			 "--Port Interrupt HPRT0=0x%08x Port Connect Detected--\n",
			 hprt0);
		dwc2_hcd_connect(hsotg);

		/*
		 * The Hub driver asserts a reset when it sees port connect
		 * status change flag
		 */
	}

	/*
	 * Port Enable Changed
	 * Clear if detected - Set internal flag if disabled
	 */
	if (hprt0 & HPRT0_ENACHG) {
		dwc2_writel(hsotg, hprt0_modify | HPRT0_ENACHG, HPRT0);
		dev_vdbg(hsotg->dev,
			 "  --Port Interrupt HPRT0=0x%08x Port Enable Changed (now %d)--\n",
			 hprt0, !!(hprt0 & HPRT0_ENA));
		if (hprt0 & HPRT0_ENA) {
			hsotg->new_connection = true;
			dwc2_hprt0_enable(hsotg, hprt0, &hprt0_modify);
		} else {
			hsotg->flags.b.port_enable_change = 1;
			if (hsotg->params.dma_desc_fs_enable) {
				u32 hcfg;

				hsotg->params.dma_desc_enable = false;
				hsotg->new_connection = false;
				hcfg = dwc2_readl(hsotg, HCFG);
				hcfg &= ~HCFG_DESCDMA;
				dwc2_writel(hsotg, hcfg, HCFG);
			}
		}
	}

	/* Overcurrent Change Interrupt */
	if (hprt0 & HPRT0_OVRCURRCHG) {
		dwc2_writel(hsotg, hprt0_modify | HPRT0_OVRCURRCHG,
			    HPRT0);
		dev_vdbg(hsotg->dev,
			 "  --Port Interrupt HPRT0=0x%08x Port Overcurrent Changed--\n",
			 hprt0);
		hsotg->flags.b.port_over_current_change = 1;
	}
}

/*
 * Gets the actual length of a transfer after the transfer halts. halt_status
 * holds the reason for the halt.
 *
 * For IN transfers where halt_status is DWC2_HC_XFER_COMPLETE, *short_read
 * is set to 1 upon return if less than the requested number of bytes were
 * transferred. short_read may also be NULL on entry, in which case it remains
 * unchanged.
 */
static u32 dwc2_get_actual_xfer_length(struct dwc2_hsotg *hsotg,
				       struct dwc2_host_chan *chan, int chnum,
				       struct dwc2_qtd *qtd,
				       enum dwc2_halt_status halt_status,
				       int *short_read)
{
	u32 hctsiz, count, length;

	hctsiz = dwc2_readl(hsotg, HCTSIZ(chnum));

	if (halt_status == DWC2_HC_XFER_COMPLETE) {
		if (chan->ep_is_in) {
			count = (hctsiz & TSIZ_XFERSIZE_MASK) >>
				TSIZ_XFERSIZE_SHIFT;
			length = chan->xfer_len - count;
			if (short_read)
				*short_read = (count != 0);
		} else if (chan->qh->do_split) {
			length = qtd->ssplit_out_xfer_count;
		} else {
			length = chan->xfer_len;
		}
	} else {
		/*
		 * Must use the hctsiz.pktcnt field to determine how much data
		 * has been transferred. This field reflects the number of
		 * packets that have been transferred via the USB. This is
		 * always an integral number of packets if the transfer was
		 * halted before its normal completion. (Can't use the
		 * hctsiz.xfersize field because that reflects the number of
		 * bytes transferred via the AHB, not the USB).
		 */
		count = (hctsiz & TSIZ_PKTCNT_MASK) >> TSIZ_PKTCNT_SHIFT;
		length = (chan->start_pkt_count - count) * chan->max_packet;
	}

	return length;
}

/**
 * dwc2_update_urb_state() - Updates the state of the URB after a Transfer
 * Complete interrupt on the host channel. Updates the actual_length field
 * of the URB based on the number of bytes transferred via the host channel.
 * Sets the URB status if the data transfer is finished.
 *
 * @hsotg: Programming view of the DWC_otg controller
 * @chan: Programming view of host channel
 * @chnum: Channel number
 * @urb: Processing URB
 * @qtd: Queue transfer descriptor
 *
 * Return: 1 if the data transfer specified by the URB is completely finished,
 * 0 otherwise
 */
static int dwc2_update_urb_state(struct dwc2_hsotg *hsotg,
				 struct dwc2_host_chan *chan, int chnum,
				 struct dwc2_hcd_urb *urb,
				 struct dwc2_qtd *qtd)
{
	u32 hctsiz;
	int xfer_done = 0;
	int short_read = 0;
	int xfer_length = dwc2_get_actual_xfer_length(hsotg, chan, chnum, qtd,
						      DWC2_HC_XFER_COMPLETE,
						      &short_read);

	if (urb->actual_length + xfer_length > urb->length) {
		dev_dbg(hsotg->dev, "%s(): trimming xfer length\n", __func__);
		xfer_length = urb->length - urb->actual_length;
	}

	dev_vdbg(hsotg->dev, "urb->actual_length=%d xfer_length=%d\n",
		 urb->actual_length, xfer_length);
	urb->actual_length += xfer_length;

	if (xfer_length && chan->ep_type == USB_ENDPOINT_XFER_BULK &&
	    (urb->flags & URB_SEND_ZERO_PACKET) &&
	    urb->actual_length >= urb->length &&
	    !(urb->length % chan->max_packet)) {
		xfer_done = 0;
	} else if (short_read || urb->actual_length >= urb->length) {
		xfer_done = 1;
		urb->status = 0;
	}

	hctsiz = dwc2_readl(hsotg, HCTSIZ(chnum));
	dev_vdbg(hsotg->dev, "DWC_otg: %s: %s, channel %d\n",
		 __func__, (chan->ep_is_in ? "IN" : "OUT"), chnum);
	dev_vdbg(hsotg->dev, "  chan->xfer_len %d\n", chan->xfer_len);
	dev_vdbg(hsotg->dev, "  hctsiz.xfersize %d\n",
		 (hctsiz & TSIZ_XFERSIZE_MASK) >> TSIZ_XFERSIZE_SHIFT);
	dev_vdbg(hsotg->dev, "  urb->transfer_buffer_length %d\n", urb->length);
	dev_vdbg(hsotg->dev, "  urb->actual_length %d\n", urb->actual_length);
	dev_vdbg(hsotg->dev, "  short_read %d, xfer_done %d\n", short_read,
		 xfer_done);

	return xfer_done;
}

/*
 * Save the starting data toggle for the next transfer. The data toggle is
 * saved in the QH for non-control transfers and it's saved in the QTD for
 * control transfers.
 */
void dwc2_hcd_save_data_toggle(struct dwc2_hsotg *hsotg,
			       struct dwc2_host_chan *chan, int chnum,
			       struct dwc2_qtd *qtd)
{
	u32 hctsiz = dwc2_readl(hsotg, HCTSIZ(chnum));
	u32 pid = (hctsiz & TSIZ_SC_MC_PID_MASK) >> TSIZ_SC_MC_PID_SHIFT;

	if (chan->ep_type != USB_ENDPOINT_XFER_CONTROL) {
		if (WARN(!chan || !chan->qh,
			 "chan->qh must be specified for non-control eps\n"))
			return;

		if (pid == TSIZ_SC_MC_PID_DATA0)
			chan->qh->data_toggle = DWC2_HC_PID_DATA0;
		else
			chan->qh->data_toggle = DWC2_HC_PID_DATA1;
	} else {
		if (WARN(!qtd,
			 "qtd must be specified for control eps\n"))
			return;

		if (pid == TSIZ_SC_MC_PID_DATA0)
			qtd->data_toggle = DWC2_HC_PID_DATA0;
		else
			qtd->data_toggle = DWC2_HC_PID_DATA1;
	}
}

/**
 * dwc2_update_isoc_urb_state() - Updates the state of an Isochronous URB when
 * the transfer is stopped for any reason. The fields of the current entry in
 * the frame descriptor array are set based on the transfer state and the input
 * halt_status. Completes the Isochronous URB if all the URB frames have been
 * completed.
 *
 * @hsotg: Programming view of the DWC_otg controller
 * @chan: Programming view of host channel
 * @chnum: Channel number
 * @halt_status: Reason for halting a host channel
 * @qtd: Queue transfer descriptor
 *
 * Return: DWC2_HC_XFER_COMPLETE if there are more frames remaining to be
 * transferred in the URB. Otherwise return DWC2_HC_XFER_URB_COMPLETE.
 */
static enum dwc2_halt_status dwc2_update_isoc_urb_state(
		struct dwc2_hsotg *hsotg, struct dwc2_host_chan *chan,
		int chnum, struct dwc2_qtd *qtd,
		enum dwc2_halt_status halt_status)
{
	struct dwc2_hcd_iso_packet_desc *frame_desc;
	struct dwc2_hcd_urb *urb = qtd->urb;

	if (!urb)
		return DWC2_HC_XFER_NO_HALT_STATUS;

	frame_desc = &urb->iso_descs[qtd->isoc_frame_index];

	switch (halt_status) {
	case DWC2_HC_XFER_COMPLETE:
		frame_desc->status = 0;
		frame_desc->actual_length = dwc2_get_actual_xfer_length(hsotg,
					chan, chnum, qtd, halt_status, NULL);
		break;
	case DWC2_HC_XFER_FRAME_OVERRUN:
		urb->error_count++;
		if (chan->ep_is_in)
			frame_desc->status = -ENOSR;
		else
			frame_desc->status = -ECOMM;
		frame_desc->actual_length = 0;
		break;
	case DWC2_HC_XFER_BABBLE_ERR:
		urb->error_count++;
		frame_desc->status = -EOVERFLOW;
		/* Don't need to update actual_length in this case */
		break;
	case DWC2_HC_XFER_XACT_ERR:
		urb->error_count++;
		frame_desc->status = -EPROTO;
		frame_desc->actual_length = dwc2_get_actual_xfer_length(hsotg,
					chan, chnum, qtd, halt_status, NULL);

		/* Skip whole frame */
		if (chan->qh->do_split &&
		    chan->ep_type == USB_ENDPOINT_XFER_ISOC && chan->ep_is_in &&
		    hsotg->params.host_dma) {
			qtd->complete_split = 0;
			qtd->isoc_split_offset = 0;
		}

		break;
	default:
		dev_err(hsotg->dev, "Unhandled halt_status (%d)\n",
			halt_status);
		break;
	}

	if (++qtd->isoc_frame_index == urb->packet_count) {
		/*
		 * urb->status is not used for isoc transfers. The individual
		 * frame_desc statuses are used instead.
		 */
		dwc2_host_complete(hsotg, qtd, 0);
		halt_status = DWC2_HC_XFER_URB_COMPLETE;
	} else {
		halt_status = DWC2_HC_XFER_COMPLETE;
	}

	return halt_status;
}

/*
 * Frees the first QTD in the QH's list if free_qtd is 1. For non-periodic
 * QHs, removes the QH from the active non-periodic schedule. If any QTDs are
 * still linked to the QH, the QH is added to the end of the inactive
 * non-periodic schedule. For periodic QHs, removes the QH from the periodic
 * schedule if no more QTDs are linked to the QH.
 */
static void dwc2_deactivate_qh(struct dwc2_hsotg *hsotg, struct dwc2_qh *qh,
			       int free_qtd)
{
	int continue_split = 0;
	struct dwc2_qtd *qtd;

	if (dbg_qh(qh))
		dev_vdbg(hsotg->dev, "  %s(%p,%p,%d)\n", __func__,
			 hsotg, qh, free_qtd);

	if (list_empty(&qh->qtd_list)) {
		dev_dbg(hsotg->dev, "## QTD list empty ##\n");
		goto no_qtd;
	}

	qtd = list_first_entry(&qh->qtd_list, struct dwc2_qtd, qtd_list_entry);

	if (qtd->complete_split)
		continue_split = 1;
	else if (qtd->isoc_split_pos == DWC2_HCSPLT_XACTPOS_MID ||
		 qtd->isoc_split_pos == DWC2_HCSPLT_XACTPOS_END)
		continue_split = 1;

	if (free_qtd) {
		dwc2_hcd_qtd_unlink_and_free(hsotg, qtd, qh);
		continue_split = 0;
	}

no_qtd:
	qh->channel = NULL;
	dwc2_hcd_qh_deactivate(hsotg, qh, continue_split);
}

/**
 * dwc2_release_channel() - Releases a host channel for use by other transfers
 *
 * @hsotg:       The HCD state structure
 * @chan:        The host channel to release
 * @qtd:         The QTD associated with the host channel. This QTD may be
 *               freed if the transfer is complete or an error has occurred.
 * @halt_status: Reason the channel is being released. This status
 *               determines the actions taken by this function.
 *
 * Also attempts to select and queue more transactions since at least one host
 * channel is available.
 */
static void dwc2_release_channel(struct dwc2_hsotg *hsotg,
				 struct dwc2_host_chan *chan,
				 struct dwc2_qtd *qtd,
				 enum dwc2_halt_status halt_status)
{
	enum dwc2_transaction_type tr_type;
	u32 haintmsk;
	int free_qtd = 0;

	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev, "  %s: channel %d, halt_status %d\n",
			 __func__, chan->hc_num, halt_status);

	switch (halt_status) {
	case DWC2_HC_XFER_URB_COMPLETE:
		free_qtd = 1;
		break;
	case DWC2_HC_XFER_AHB_ERR:
	case DWC2_HC_XFER_STALL:
	case DWC2_HC_XFER_BABBLE_ERR:
		free_qtd = 1;
		break;
	case DWC2_HC_XFER_XACT_ERR:
		if (qtd && qtd->error_count >= 3) {
			dev_vdbg(hsotg->dev,
				 "  Complete URB with transaction error\n");
			free_qtd = 1;
			dwc2_host_complete(hsotg, qtd, -EPROTO);
		}
		break;
	case DWC2_HC_XFER_URB_DEQUEUE:
		/*
		 * The QTD has already been removed and the QH has been
		 * deactivated. Don't want to do anything except release the
		 * host channel and try to queue more transfers.
		 */
		goto cleanup;
	case DWC2_HC_XFER_PERIODIC_INCOMPLETE:
		dev_vdbg(hsotg->dev, "  Complete URB with I/O error\n");
		free_qtd = 1;
		dwc2_host_complete(hsotg, qtd, -EIO);
		break;
	case DWC2_HC_XFER_NO_HALT_STATUS:
	default:
		break;
	}

	dwc2_deactivate_qh(hsotg, chan->qh, free_qtd);

cleanup:
	/*
	 * Release the host channel for use by other transfers. The cleanup
	 * function clears the channel interrupt enables and conditions, so
	 * there's no need to clear the Channel Halted interrupt separately.
	 */
	if (!list_empty(&chan->hc_list_entry))
		list_del(&chan->hc_list_entry);
	dwc2_hc_cleanup(hsotg, chan);
	list_add_tail(&chan->hc_list_entry, &hsotg->free_hc_list);

	if (hsotg->params.uframe_sched) {
		hsotg->available_host_channels++;
	} else {
		switch (chan->ep_type) {
		case USB_ENDPOINT_XFER_CONTROL:
		case USB_ENDPOINT_XFER_BULK:
			hsotg->non_periodic_channels--;
			break;
		default:
			/*
			 * Don't release reservations for periodic channels
			 * here. That's done when a periodic transfer is
			 * descheduled (i.e. when the QH is removed from the
			 * periodic schedule).
			 */
			break;
		}
	}

	haintmsk = dwc2_readl(hsotg, HAINTMSK);
	haintmsk &= ~(1 << chan->hc_num);
	dwc2_writel(hsotg, haintmsk, HAINTMSK);

	/* Try to queue more transfers now that there's a free channel */
	tr_type = dwc2_hcd_select_transactions(hsotg);
	if (tr_type != DWC2_TRANSACTION_NONE)
		dwc2_hcd_queue_transactions(hsotg, tr_type);
}

/*
 * Halts a host channel. If the channel cannot be halted immediately because
 * the request queue is full, this function ensures that the FIFO empty
 * interrupt for the appropriate queue is enabled so that the halt request can
 * be queued when there is space in the request queue.
 *
 * This function may also be called in DMA mode. In that case, the channel is
 * simply released since the core always halts the channel automatically in
 * DMA mode.
 */
static void dwc2_halt_channel(struct dwc2_hsotg *hsotg,
			      struct dwc2_host_chan *chan, struct dwc2_qtd *qtd,
			      enum dwc2_halt_status halt_status)
{
	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev, "%s()\n", __func__);

	if (hsotg->params.host_dma) {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "DMA enabled\n");
		dwc2_release_channel(hsotg, chan, qtd, halt_status);
		return;
	}

	/* Slave mode processing */
	dwc2_hc_halt(hsotg, chan, halt_status);

	if (chan->halt_on_queue) {
		u32 gintmsk;

		dev_vdbg(hsotg->dev, "Halt on queue\n");
		if (chan->ep_type == USB_ENDPOINT_XFER_CONTROL ||
		    chan->ep_type == USB_ENDPOINT_XFER_BULK) {
			dev_vdbg(hsotg->dev, "control/bulk\n");
			/*
			 * Make sure the Non-periodic Tx FIFO empty interrupt
			 * is enabled so that the non-periodic schedule will
			 * be processed
			 */
			gintmsk = dwc2_readl(hsotg, GINTMSK);
			gintmsk |= GINTSTS_NPTXFEMP;
			dwc2_writel(hsotg, gintmsk, GINTMSK);
		} else {
			dev_vdbg(hsotg->dev, "isoc/intr\n");
			/*
			 * Move the QH from the periodic queued schedule to
			 * the periodic assigned schedule. This allows the
			 * halt to be queued when the periodic schedule is
			 * processed.
			 */
			list_move_tail(&chan->qh->qh_list_entry,
				       &hsotg->periodic_sched_assigned);

			/*
			 * Make sure the Periodic Tx FIFO Empty interrupt is
			 * enabled so that the periodic schedule will be
			 * processed
			 */
			gintmsk = dwc2_readl(hsotg, GINTMSK);
			gintmsk |= GINTSTS_PTXFEMP;
			dwc2_writel(hsotg, gintmsk, GINTMSK);
		}
	}
}

/*
 * Performs common cleanup for non-periodic transfers after a Transfer
 * Complete interrupt. This function should be called after any endpoint type
 * specific handling is finished to release the host channel.
 */
static void dwc2_complete_non_periodic_xfer(struct dwc2_hsotg *hsotg,
					    struct dwc2_host_chan *chan,
					    int chnum, struct dwc2_qtd *qtd,
					    enum dwc2_halt_status halt_status)
{
	dev_vdbg(hsotg->dev, "%s()\n", __func__);

	qtd->error_count = 0;

	if (chan->hcint & HCINTMSK_NYET) {
		/*
		 * Got a NYET on the last transaction of the transfer. This
		 * means that the endpoint should be in the PING state at the
		 * beginning of the next transfer.
		 */
		dev_vdbg(hsotg->dev, "got NYET\n");
		chan->qh->ping_state = 1;
	}

	/*
	 * Always halt and release the host channel to make it available for
	 * more transfers. There may still be more phases for a control
	 * transfer or more data packets for a bulk transfer at this point,
	 * but the host channel is still halted. A channel will be reassigned
	 * to the transfer when the non-periodic schedule is processed after
	 * the channel is released. This allows transactions to be queued
	 * properly via dwc2_hcd_queue_transactions, which also enables the
	 * Tx FIFO Empty interrupt if necessary.
	 */
	if (chan->ep_is_in) {
		/*
		 * IN transfers in Slave mode require an explicit disable to
		 * halt the channel. (In DMA mode, this call simply releases
		 * the channel.)
		 */
		dwc2_halt_channel(hsotg, chan, qtd, halt_status);
	} else {
		/*
		 * The channel is automatically disabled by the core for OUT
		 * transfers in Slave mode
		 */
		dwc2_release_channel(hsotg, chan, qtd, halt_status);
	}
}

/*
 * Performs common cleanup for periodic transfers after a Transfer Complete
 * interrupt. This function should be called after any endpoint type specific
 * handling is finished to release the host channel.
 */
static void dwc2_complete_periodic_xfer(struct dwc2_hsotg *hsotg,
					struct dwc2_host_chan *chan, int chnum,
					struct dwc2_qtd *qtd,
					enum dwc2_halt_status halt_status)
{
	u32 hctsiz = dwc2_readl(hsotg, HCTSIZ(chnum));

	qtd->error_count = 0;

	if (!chan->ep_is_in || (hctsiz & TSIZ_PKTCNT_MASK) == 0)
		/* Core halts channel in these cases */
		dwc2_release_channel(hsotg, chan, qtd, halt_status);
	else
		/* Flush any outstanding requests from the Tx queue */
		dwc2_halt_channel(hsotg, chan, qtd, halt_status);
}

static int dwc2_xfercomp_isoc_split_in(struct dwc2_hsotg *hsotg,
				       struct dwc2_host_chan *chan, int chnum,
				       struct dwc2_qtd *qtd)
{
	struct dwc2_hcd_iso_packet_desc *frame_desc;
	u32 len;
	u32 hctsiz;
	u32 pid;

	if (!qtd->urb)
		return 0;

	frame_desc = &qtd->urb->iso_descs[qtd->isoc_frame_index];
	len = dwc2_get_actual_xfer_length(hsotg, chan, chnum, qtd,
					  DWC2_HC_XFER_COMPLETE, NULL);
	if (!len && !qtd->isoc_split_offset) {
		qtd->complete_split = 0;
		return 0;
	}

	frame_desc->actual_length += len;

	if (chan->align_buf) {
		dev_vdbg(hsotg->dev, "non-aligned buffer\n");
		dma_unmap_single(hsotg->dev, chan->qh->dw_align_buf_dma,
				 DWC2_KMEM_UNALIGNED_BUF_SIZE, DMA_FROM_DEVICE);
		memcpy(qtd->urb->buf + (chan->xfer_dma - qtd->urb->dma),
		       chan->qh->dw_align_buf, len);
	}

	qtd->isoc_split_offset += len;

	hctsiz = dwc2_readl(hsotg, HCTSIZ(chnum));
	pid = (hctsiz & TSIZ_SC_MC_PID_MASK) >> TSIZ_SC_MC_PID_SHIFT;

	if (frame_desc->actual_length >= frame_desc->length || pid == 0) {
		frame_desc->status = 0;
		qtd->isoc_frame_index++;
		qtd->complete_split = 0;
		qtd->isoc_split_offset = 0;
	}

	if (qtd->isoc_frame_index == qtd->urb->packet_count) {
		dwc2_host_complete(hsotg, qtd, 0);
		dwc2_release_channel(hsotg, chan, qtd,
				     DWC2_HC_XFER_URB_COMPLETE);
	} else {
		dwc2_release_channel(hsotg, chan, qtd,
				     DWC2_HC_XFER_NO_HALT_STATUS);
	}

	return 1;	/* Indicates that channel released */
}

/*
 * Handles a host channel Transfer Complete interrupt. This handler may be
 * called in either DMA mode or Slave mode.
 */
static void dwc2_hc_xfercomp_intr(struct dwc2_hsotg *hsotg,
				  struct dwc2_host_chan *chan, int chnum,
				  struct dwc2_qtd *qtd)
{
	struct dwc2_hcd_urb *urb = qtd->urb;
	enum dwc2_halt_status halt_status = DWC2_HC_XFER_COMPLETE;
	int pipe_type;
	int urb_xfer_done;

	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev,
			 "--Host Channel %d Interrupt: Transfer Complete--\n",
			 chnum);

	if (!urb)
		goto handle_xfercomp_done;

	pipe_type = dwc2_hcd_get_pipe_type(&urb->pipe_info);

	if (hsotg->params.dma_desc_enable) {
		dwc2_hcd_complete_xfer_ddma(hsotg, chan, chnum, halt_status);
		if (pipe_type == USB_ENDPOINT_XFER_ISOC)
			/* Do not disable the interrupt, just clear it */
			return;
		goto handle_xfercomp_done;
	}

	/* Handle xfer complete on CSPLIT */
	if (chan->qh->do_split) {
		if (chan->ep_type == USB_ENDPOINT_XFER_ISOC && chan->ep_is_in &&
		    hsotg->params.host_dma) {
			if (qtd->complete_split &&
			    dwc2_xfercomp_isoc_split_in(hsotg, chan, chnum,
							qtd))
				goto handle_xfercomp_done;
		} else {
			qtd->complete_split = 0;
		}
	}

	/* Update the QTD and URB states */
	switch (pipe_type) {
	case USB_ENDPOINT_XFER_CONTROL:
		switch (qtd->control_phase) {
		case DWC2_CONTROL_SETUP:
			if (urb->length > 0)
				qtd->control_phase = DWC2_CONTROL_DATA;
			else
				qtd->control_phase = DWC2_CONTROL_STATUS;
			dev_vdbg(hsotg->dev,
				 "  Control setup transaction done\n");
			halt_status = DWC2_HC_XFER_COMPLETE;
			break;
		case DWC2_CONTROL_DATA:
			urb_xfer_done = dwc2_update_urb_state(hsotg, chan,
							      chnum, urb, qtd);
			if (urb_xfer_done) {
				qtd->control_phase = DWC2_CONTROL_STATUS;
				dev_vdbg(hsotg->dev,
					 "  Control data transfer done\n");
			} else {
				dwc2_hcd_save_data_toggle(hsotg, chan, chnum,
							  qtd);
			}
			halt_status = DWC2_HC_XFER_COMPLETE;
			break;
		case DWC2_CONTROL_STATUS:
			dev_vdbg(hsotg->dev, "  Control transfer complete\n");
			if (urb->status == -EINPROGRESS)
				urb->status = 0;
			dwc2_host_complete(hsotg, qtd, urb->status);
			halt_status = DWC2_HC_XFER_URB_COMPLETE;
			break;
		}

		dwc2_complete_non_periodic_xfer(hsotg, chan, chnum, qtd,
						halt_status);
		break;
	case USB_ENDPOINT_XFER_BULK:
		dev_vdbg(hsotg->dev, "  Bulk transfer complete\n");
		urb_xfer_done = dwc2_update_urb_state(hsotg, chan, chnum, urb,
						      qtd);
		if (urb_xfer_done) {
			dwc2_host_complete(hsotg, qtd, urb->status);
			halt_status = DWC2_HC_XFER_URB_COMPLETE;
		} else {
			halt_status = DWC2_HC_XFER_COMPLETE;
		}

		dwc2_hcd_save_data_toggle(hsotg, chan, chnum, qtd);
		dwc2_complete_non_periodic_xfer(hsotg, chan, chnum, qtd,
						halt_status);
		break;
	case USB_ENDPOINT_XFER_INT:
		dev_vdbg(hsotg->dev, "  Interrupt transfer complete\n");
		urb_xfer_done = dwc2_update_urb_state(hsotg, chan, chnum, urb,
						      qtd);

		/*
		 * Interrupt URB is done on the first transfer complete
		 * interrupt
		 */
		if (urb_xfer_done) {
			dwc2_host_complete(hsotg, qtd, urb->status);
			halt_status = DWC2_HC_XFER_URB_COMPLETE;
		} else {
			halt_status = DWC2_HC_XFER_COMPLETE;
		}

		dwc2_hcd_save_data_toggle(hsotg, chan, chnum, qtd);
		dwc2_complete_periodic_xfer(hsotg, chan, chnum, qtd,
					    halt_status);
		break;
	case USB_ENDPOINT_XFER_ISOC:
		if (dbg_perio())
			dev_vdbg(hsotg->dev, "  Isochronous transfer complete\n");
		if (qtd->isoc_split_pos == DWC2_HCSPLT_XACTPOS_ALL)
			halt_status = dwc2_update_isoc_urb_state(hsotg, chan,
							chnum, qtd,
							DWC2_HC_XFER_COMPLETE);
		dwc2_complete_periodic_xfer(hsotg, chan, chnum, qtd,
					    halt_status);
		break;
	}

handle_xfercomp_done:
	disable_hc_int(hsotg, chnum, HCINTMSK_XFERCOMPL);
}

/*
 * Handles a host channel STALL interrupt. This handler may be called in
 * either DMA mode or Slave mode.
 */
static void dwc2_hc_stall_intr(struct dwc2_hsotg *hsotg,
			       struct dwc2_host_chan *chan, int chnum,
			       struct dwc2_qtd *qtd)
{
	struct dwc2_hcd_urb *urb = qtd->urb;
	int pipe_type;

	dev_dbg(hsotg->dev, "--Host Channel %d Interrupt: STALL Received--\n",
		chnum);

	if (hsotg->params.dma_desc_enable) {
		dwc2_hcd_complete_xfer_ddma(hsotg, chan, chnum,
					    DWC2_HC_XFER_STALL);
		goto handle_stall_done;
	}

	if (!urb)
		goto handle_stall_halt;

	pipe_type = dwc2_hcd_get_pipe_type(&urb->pipe_info);

	if (pipe_type == USB_ENDPOINT_XFER_CONTROL)
		dwc2_host_complete(hsotg, qtd, -EPIPE);

	if (pipe_type == USB_ENDPOINT_XFER_BULK ||
	    pipe_type == USB_ENDPOINT_XFER_INT) {
		dwc2_host_complete(hsotg, qtd, -EPIPE);
		/*
		 * USB protocol requires resetting the data toggle for bulk
		 * and interrupt endpoints when a CLEAR_FEATURE(ENDPOINT_HALT)
		 * setup command is issued to the endpoint. Anticipate the
		 * CLEAR_FEATURE command since a STALL has occurred and reset
		 * the data toggle now.
		 */
		chan->qh->data_toggle = 0;
	}

handle_stall_halt:
	dwc2_halt_channel(hsotg, chan, qtd, DWC2_HC_XFER_STALL);

handle_stall_done:
	disable_hc_int(hsotg, chnum, HCINTMSK_STALL);
}

/*
 * Updates the state of the URB when a transfer has been stopped due to an
 * abnormal condition before the transfer completes. Modifies the
 * actual_length field of the URB to reflect the number of bytes that have
 * actually been transferred via the host channel.
 */
static void dwc2_update_urb_state_abn(struct dwc2_hsotg *hsotg,
				      struct dwc2_host_chan *chan, int chnum,
				      struct dwc2_hcd_urb *urb,
				      struct dwc2_qtd *qtd,
				      enum dwc2_halt_status halt_status)
{
	u32 xfer_length = dwc2_get_actual_xfer_length(hsotg, chan, chnum,
						      qtd, halt_status, NULL);
	u32 hctsiz;

	if (urb->actual_length + xfer_length > urb->length) {
		dev_warn(hsotg->dev, "%s(): trimming xfer length\n", __func__);
		if (urb->length & 0x3)
			xfer_length = 0;
		else
			xfer_length = urb->length - urb->actual_length;
	}

	urb->actual_length += xfer_length;

	hctsiz = dwc2_readl(hsotg, HCTSIZ(chnum));
	dev_vdbg(hsotg->dev, "DWC_otg: %s: %s, channel %d\n",
		 __func__, (chan->ep_is_in ? "IN" : "OUT"), chnum);
	dev_vdbg(hsotg->dev, "  chan->start_pkt_count %d\n",
		 chan->start_pkt_count);
	dev_vdbg(hsotg->dev, "  hctsiz.pktcnt %d\n",
		 (hctsiz & TSIZ_PKTCNT_MASK) >> TSIZ_PKTCNT_SHIFT);
	dev_vdbg(hsotg->dev, "  chan->max_packet %d\n", chan->max_packet);
	dev_vdbg(hsotg->dev, "  bytes_transferred %d\n",
		 xfer_length);
	dev_vdbg(hsotg->dev, "  urb->actual_length %d\n",
		 urb->actual_length);
	dev_vdbg(hsotg->dev, "  urb->transfer_buffer_length %d\n",
		 urb->length);
}

/*
 * Handles a host channel NAK interrupt. This handler may be called in either
 * DMA mode or Slave mode.
 */
static void dwc2_hc_nak_intr(struct dwc2_hsotg *hsotg,
			     struct dwc2_host_chan *chan, int chnum,
			     struct dwc2_qtd *qtd)
{
	if (!qtd) {
		dev_dbg(hsotg->dev, "%s: qtd is NULL\n", __func__);
		return;
	}

	if (!qtd->urb) {
		dev_dbg(hsotg->dev, "%s: qtd->urb is NULL\n", __func__);
		return;
	}

	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev, "--Host Channel %d Interrupt: NAK Received--\n",
			 chnum);

	/*
	 * Handle NAK for IN/OUT SSPLIT/CSPLIT transfers, bulk, control, and
	 * interrupt. Re-start the SSPLIT transfer.
	 *
	 * Normally for non-periodic transfers we'll retry right away, but to
	 * avoid interrupt storms we'll wait before retrying if we've got
	 * several NAKs. If we didn't do this we'd retry directly from the
	 * interrupt handler and could end up quickly getting another
	 * interrupt (another NAK), which we'd retry. Note that we do not
	 * delay retries for IN parts of control requests, as those are expected
	 * to complete fairly quickly, and if we delay them we risk confusing
	 * the device and cause it issue STALL.
	 *
	 * Note that in DMA mode software only gets involved to re-send NAKed
	 * transfers for split transactions, so we only need to apply this
	 * delaying logic when handling splits. In non-DMA mode presumably we
	 * might want a similar delay if someone can demonstrate this problem
	 * affects that code path too.
	 */
	if (chan->do_split) {
		if (chan->complete_split)
			qtd->error_count = 0;
		qtd->complete_split = 0;
		qtd->num_naks++;
		qtd->qh->want_wait = qtd->num_naks >= DWC2_NAKS_BEFORE_DELAY &&
				!(chan->ep_type == USB_ENDPOINT_XFER_CONTROL &&
				  chan->ep_is_in);
		dwc2_halt_channel(hsotg, chan, qtd, DWC2_HC_XFER_NAK);
		goto handle_nak_done;
	}

	switch (dwc2_hcd_get_pipe_type(&qtd->urb->pipe_info)) {
	case USB_ENDPOINT_XFER_CONTROL:
	case USB_ENDPOINT_XFER_BULK:
		if (hsotg->params.host_dma && chan->ep_is_in) {
			/*
			 * NAK interrupts are enabled on bulk/control IN
			 * transfers in DMA mode for the sole purpose of
			 * resetting the error count after a transaction error
			 * occurs. The core will continue transferring data.
			 */
			qtd->error_count = 0;
			break;
		}

		/*
		 * NAK interrupts normally occur during OUT transfers in DMA
		 * or Slave mode. For IN transfers, more requests will be
		 * queued as request queue space is available.
		 */
		qtd->error_count = 0;

		if (!chan->qh->ping_state) {
			dwc2_update_urb_state_abn(hsotg, chan, chnum, qtd->urb,
						  qtd, DWC2_HC_XFER_NAK);
			dwc2_hcd_save_data_toggle(hsotg, chan, chnum, qtd);

			if (chan->speed == USB_SPEED_HIGH)
				chan->qh->ping_state = 1;
		}

		/*
		 * Halt the channel so the transfer can be re-started from
		 * the appropriate point or the PING protocol will
		 * start/continue
		 */
		dwc2_halt_channel(hsotg, chan, qtd, DWC2_HC_XFER_NAK);
		break;
	case USB_ENDPOINT_XFER_INT:
		qtd->error_count = 0;
		dwc2_halt_channel(hsotg, chan, qtd, DWC2_HC_XFER_NAK);
		break;
