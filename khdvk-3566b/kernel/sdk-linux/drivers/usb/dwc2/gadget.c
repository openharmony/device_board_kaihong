// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Copyright 2008 Openmoko, Inc.
 * Copyright 2008 Simtec Electronics
 *      Ben Dooks <ben@simtec.co.uk>
 *      http://armlinux.simtec.co.uk/
 *
 * S3C USB2.0 High-speed / OtG driver
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/of_platform.h>

#include <linux/usb/ch9.h>
#include <linux/usb/gadget.h>
#include <linux/usb/phy.h>
#include <linux/usb/composite.h>


#include "core.h"
#include "hw.h"

/* conversion functions */
static inline struct dwc2_hsotg_req *our_req(struct usb_request *req)
{
	return container_of(req, struct dwc2_hsotg_req, req);
}

static inline struct dwc2_hsotg_ep *our_ep(struct usb_ep *ep)
{
	return container_of(ep, struct dwc2_hsotg_ep, ep);
}

static inline struct dwc2_hsotg *to_hsotg(struct usb_gadget *gadget)
{
	return container_of(gadget, struct dwc2_hsotg, gadget);
}

static inline void dwc2_set_bit(struct dwc2_hsotg *hsotg, u32 offset, u32 val)
{
	dwc2_writel(hsotg, dwc2_readl(hsotg, offset) | val, offset);
}

static inline void dwc2_clear_bit(struct dwc2_hsotg *hsotg, u32 offset, u32 val)
{
	dwc2_writel(hsotg, dwc2_readl(hsotg, offset) & ~val, offset);
}

static inline struct dwc2_hsotg_ep *index_to_ep(struct dwc2_hsotg *hsotg,
						u32 ep_index, u32 dir_in)
{
	if (dir_in)
		return hsotg->eps_in[ep_index];
	else
		return hsotg->eps_out[ep_index];
}

/* forward declaration of functions */
static void dwc2_hsotg_dump(struct dwc2_hsotg *hsotg);

/**
 * using_dma - return the DMA status of the driver.
 * @hsotg: The driver state.
 *
 * Return true if we're using DMA.
 *
 * Currently, we have the DMA support code worked into everywhere
 * that needs it, but the AMBA DMA implementation in the hardware can
 * only DMA from 32bit aligned addresses. This means that gadgets such
 * as the CDC Ethernet cannot work as they often pass packets which are
 * not 32bit aligned.
 *
 * Unfortunately the choice to use DMA or not is global to the controller
 * and seems to be only settable when the controller is being put through
 * a core reset. This means we either need to fix the gadgets to take
 * account of DMA alignment, or add bounce buffers (yuerk).
 *
 * g_using_dma is set depending on dts flag.
 */
static inline bool using_dma(struct dwc2_hsotg *hsotg)
{
	return hsotg->params.g_dma;
}

/*
 * using_desc_dma - return the descriptor DMA status of the driver.
 * @hsotg: The driver state.
 *
 * Return true if we're using descriptor DMA.
 */
static inline bool using_desc_dma(struct dwc2_hsotg *hsotg)
{
	return hsotg->params.g_dma_desc;
}

/**
 * dwc2_gadget_incr_frame_num - Increments the targeted frame number.
 * @hs_ep: The endpoint
 *
 * This function will also check if the frame number overruns DSTS_SOFFN_LIMIT.
 * If an overrun occurs it will wrap the value and set the frame_overrun flag.
 */
static inline void dwc2_gadget_incr_frame_num(struct dwc2_hsotg_ep *hs_ep)
{
	struct dwc2_hsotg *hsotg = hs_ep->parent;
	u16 limit = DSTS_SOFFN_LIMIT;

	if (hsotg->gadget.speed != USB_SPEED_HIGH)
		limit >>= 3;

	hs_ep->target_frame += hs_ep->interval;
	if (hs_ep->target_frame > limit) {
		hs_ep->frame_overrun = true;
		hs_ep->target_frame &= limit;
	} else {
		hs_ep->frame_overrun = false;
	}
}

/**
 * dwc2_gadget_dec_frame_num_by_one - Decrements the targeted frame number
 *                                    by one.
 * @hs_ep: The endpoint.
 *
 * This function used in service interval based scheduling flow to calculate
 * descriptor frame number filed value. For service interval mode frame
 * number in descriptor should point to last (u)frame in the interval.
 *
 */
static inline void dwc2_gadget_dec_frame_num_by_one(struct dwc2_hsotg_ep *hs_ep)
{
	struct dwc2_hsotg *hsotg = hs_ep->parent;
	u16 limit = DSTS_SOFFN_LIMIT;

	if (hsotg->gadget.speed != USB_SPEED_HIGH)
		limit >>= 3;

	if (hs_ep->target_frame)
		hs_ep->target_frame -= 1;
	else
		hs_ep->target_frame = limit;
}

/**
 * dwc2_hsotg_en_gsint - enable one or more of the general interrupt
 * @hsotg: The device state
 * @ints: A bitmask of the interrupts to enable
 */
static void dwc2_hsotg_en_gsint(struct dwc2_hsotg *hsotg, u32 ints)
{
	u32 gsintmsk = dwc2_readl(hsotg, GINTMSK);
	u32 new_gsintmsk;

	new_gsintmsk = gsintmsk | ints;

	if (new_gsintmsk != gsintmsk) {
		dev_dbg(hsotg->dev, "gsintmsk now 0x%08x\n", new_gsintmsk);
		dwc2_writel(hsotg, new_gsintmsk, GINTMSK);
	}
}

/**
 * dwc2_hsotg_disable_gsint - disable one or more of the general interrupt
 * @hsotg: The device state
 * @ints: A bitmask of the interrupts to enable
 */
static void dwc2_hsotg_disable_gsint(struct dwc2_hsotg *hsotg, u32 ints)
{
	u32 gsintmsk = dwc2_readl(hsotg, GINTMSK);
	u32 new_gsintmsk;

	new_gsintmsk = gsintmsk & ~ints;

	if (new_gsintmsk != gsintmsk)
		dwc2_writel(hsotg, new_gsintmsk, GINTMSK);
}

/**
 * dwc2_hsotg_ctrl_epint - enable/disable an endpoint irq
 * @hsotg: The device state
 * @ep: The endpoint index
 * @dir_in: True if direction is in.
 * @en: The enable value, true to enable
 *
 * Set or clear the mask for an individual endpoint's interrupt
 * request.
 */
static void dwc2_hsotg_ctrl_epint(struct dwc2_hsotg *hsotg,
				  unsigned int ep, unsigned int dir_in,
				 unsigned int en)
{
	unsigned long flags;
	u32 bit = 1 << ep;
	u32 daint;

	if (!dir_in)
		bit <<= 16;

	local_irq_save(flags);
	daint = dwc2_readl(hsotg, DAINTMSK);
	if (en)
		daint |= bit;
	else
		daint &= ~bit;
	dwc2_writel(hsotg, daint, DAINTMSK);
	local_irq_restore(flags);
}

/**
 * dwc2_hsotg_tx_fifo_count - return count of TX FIFOs in device mode
 *
 * @hsotg: Programming view of the DWC_otg controller
 */
int dwc2_hsotg_tx_fifo_count(struct dwc2_hsotg *hsotg)
{
	if (hsotg->hw_params.en_multiple_tx_fifo)
		/* In dedicated FIFO mode we need count of IN EPs */
		return hsotg->hw_params.num_dev_in_eps;
	else
		/* In shared FIFO mode we need count of Periodic IN EPs */
		return hsotg->hw_params.num_dev_perio_in_ep;
}

/**
 * dwc2_hsotg_tx_fifo_total_depth - return total FIFO depth available for
 * device mode TX FIFOs
 *
 * @hsotg: Programming view of the DWC_otg controller
 */
int dwc2_hsotg_tx_fifo_total_depth(struct dwc2_hsotg *hsotg)
{
	int addr;
	int tx_addr_max;
	u32 np_tx_fifo_size;

	np_tx_fifo_size = min_t(u32, hsotg->hw_params.dev_nperio_tx_fifo_size,
				hsotg->params.g_np_tx_fifo_size);

	/* Get Endpoint Info Control block size in DWORDs. */
	tx_addr_max = hsotg->hw_params.total_fifo_size;

	addr = hsotg->params.g_rx_fifo_size + np_tx_fifo_size;
	if (tx_addr_max <= addr)
		return 0;

	return tx_addr_max - addr;
}

/**
 * dwc2_gadget_wkup_alert_handler - Handler for WKUP_ALERT interrupt
 *
 * @hsotg: Programming view of the DWC_otg controller
 *
 */
static void dwc2_gadget_wkup_alert_handler(struct dwc2_hsotg *hsotg)
{
	u32 gintsts2;
	u32 gintmsk2;

	gintsts2 = dwc2_readl(hsotg, GINTSTS2);
	gintmsk2 = dwc2_readl(hsotg, GINTMSK2);
	gintsts2 &= gintmsk2;

	if (gintsts2 & GINTSTS2_WKUP_ALERT_INT) {
		dev_dbg(hsotg->dev, "%s: Wkup_Alert_Int\n", __func__);
		dwc2_set_bit(hsotg, GINTSTS2, GINTSTS2_WKUP_ALERT_INT);
		dwc2_set_bit(hsotg, DCTL, DCTL_RMTWKUPSIG);
	}
}

/**
 * dwc2_hsotg_tx_fifo_average_depth - returns average depth of device mode
 * TX FIFOs
 *
 * @hsotg: Programming view of the DWC_otg controller
 */
int dwc2_hsotg_tx_fifo_average_depth(struct dwc2_hsotg *hsotg)
{
	int tx_fifo_count;
	int tx_fifo_depth;

	tx_fifo_depth = dwc2_hsotg_tx_fifo_total_depth(hsotg);

	tx_fifo_count = dwc2_hsotg_tx_fifo_count(hsotg);

	if (!tx_fifo_count)
		return tx_fifo_depth;
	else
		return tx_fifo_depth / tx_fifo_count;
}

/**
 * dwc2_hsotg_init_fifo - initialise non-periodic FIFOs
 * @hsotg: The device instance.
 */
static void dwc2_hsotg_init_fifo(struct dwc2_hsotg *hsotg)
{
	unsigned int ep;
	unsigned int addr;
	int timeout;

	u32 val;
	u32 *txfsz = hsotg->params.g_tx_fifo_size;

	/* Reset fifo map if not correctly cleared during previous session */
	WARN_ON(hsotg->fifo_map);
	hsotg->fifo_map = 0;

	/* set RX/NPTX FIFO sizes */
	dwc2_writel(hsotg, hsotg->params.g_rx_fifo_size, GRXFSIZ);
	dwc2_writel(hsotg, (hsotg->params.g_rx_fifo_size <<
		    FIFOSIZE_STARTADDR_SHIFT) |
		    (hsotg->params.g_np_tx_fifo_size << FIFOSIZE_DEPTH_SHIFT),
		    GNPTXFSIZ);

	/*
	 * arange all the rest of the TX FIFOs, as some versions of this
	 * block have overlapping default addresses. This also ensures
	 * that if the settings have been changed, then they are set to
	 * known values.
	 */

	/* start at the end of the GNPTXFSIZ, rounded up */
	addr = hsotg->params.g_rx_fifo_size + hsotg->params.g_np_tx_fifo_size;

	/*
	 * Configure fifos sizes from provided configuration and assign
	 * them to endpoints dynamically according to maxpacket size value of
	 * given endpoint.
	 */
	for (ep = 1; ep < MAX_EPS_CHANNELS; ep++) {
		if (!txfsz[ep])
			continue;
		val = addr;
		val |= txfsz[ep] << FIFOSIZE_DEPTH_SHIFT;
		WARN_ONCE(addr + txfsz[ep] > hsotg->fifo_mem,
			  "insufficient fifo memory");
		addr += txfsz[ep];

		dwc2_writel(hsotg, val, DPTXFSIZN(ep));
		val = dwc2_readl(hsotg, DPTXFSIZN(ep));
	}

	dwc2_writel(hsotg, hsotg->hw_params.total_fifo_size |
		    addr << GDFIFOCFG_EPINFOBASE_SHIFT,
		    GDFIFOCFG);
	/*
	 * according to p428 of the design guide, we need to ensure that
	 * all fifos are flushed before continuing
	 */

	dwc2_writel(hsotg, GRSTCTL_TXFNUM(0x10) | GRSTCTL_TXFFLSH |
	       GRSTCTL_RXFFLSH, GRSTCTL);

	/* wait until the fifos are both flushed */
	timeout = 100;
	while (1) {
		val = dwc2_readl(hsotg, GRSTCTL);

		if ((val & (GRSTCTL_TXFFLSH | GRSTCTL_RXFFLSH)) == 0)
			break;

		if (--timeout == 0) {
			dev_err(hsotg->dev,
				"%s: timeout flushing fifos (GRSTCTL=%08x)\n",
				__func__, val);
			break;
		}

		udelay(1);
	}

	dev_dbg(hsotg->dev, "FIFOs reset, timeout at %d\n", timeout);
}

/**
 * dwc2_hsotg_ep_alloc_request - allocate USB rerequest structure
 * @ep: USB endpoint to allocate request for.
 * @flags: Allocation flags
 *
 * Allocate a new USB request structure appropriate for the specified endpoint
 */
static struct usb_request *dwc2_hsotg_ep_alloc_request(struct usb_ep *ep,
						       gfp_t flags)
{
	struct dwc2_hsotg_req *req;

	req = kzalloc(sizeof(*req), flags);
	if (!req)
		return NULL;

	INIT_LIST_HEAD(&req->queue);

	return &req->req;
}

/**
 * is_ep_periodic - return true if the endpoint is in periodic mode.
 * @hs_ep: The endpoint to query.
 *
 * Returns true if the endpoint is in periodic mode, meaning it is being
 * used for an Interrupt or ISO transfer.
 */
static inline int is_ep_periodic(struct dwc2_hsotg_ep *hs_ep)
{
	return hs_ep->periodic;
}

/**
 * dwc2_hsotg_unmap_dma - unmap the DMA memory being used for the request
 * @hsotg: The device state.
 * @hs_ep: The endpoint for the request
 * @hs_req: The request being processed.
 *
 * This is the reverse of dwc2_hsotg_map_dma(), called for the completion
 * of a request to ensure the buffer is ready for access by the caller.
 */
static void dwc2_hsotg_unmap_dma(struct dwc2_hsotg *hsotg,
				 struct dwc2_hsotg_ep *hs_ep,
				struct dwc2_hsotg_req *hs_req)
{
	struct usb_request *req = &hs_req->req;

	usb_gadget_unmap_request(&hsotg->gadget, req, hs_ep->map_dir);
}

/*
 * dwc2_gadget_alloc_ctrl_desc_chains - allocate DMA descriptor chains
 * for Control endpoint
 * @hsotg: The device state.
 *
 * This function will allocate 4 descriptor chains for EP 0: 2 for
 * Setup stage, per one for IN and OUT data/status transactions.
 */
static int dwc2_gadget_alloc_ctrl_desc_chains(struct dwc2_hsotg *hsotg)
{
	hsotg->setup_desc[0] =
		dmam_alloc_coherent(hsotg->dev,
				    sizeof(struct dwc2_dma_desc),
				    &hsotg->setup_desc_dma[0],
				    GFP_KERNEL);
	if (!hsotg->setup_desc[0])
		goto fail;

	hsotg->setup_desc[1] =
		dmam_alloc_coherent(hsotg->dev,
				    sizeof(struct dwc2_dma_desc),
				    &hsotg->setup_desc_dma[1],
				    GFP_KERNEL);
	if (!hsotg->setup_desc[1])
		goto fail;

	hsotg->ctrl_in_desc =
		dmam_alloc_coherent(hsotg->dev,
				    sizeof(struct dwc2_dma_desc),
				    &hsotg->ctrl_in_desc_dma,
				    GFP_KERNEL);
	if (!hsotg->ctrl_in_desc)
		goto fail;

	hsotg->ctrl_out_desc =
		dmam_alloc_coherent(hsotg->dev,
				    sizeof(struct dwc2_dma_desc),
				    &hsotg->ctrl_out_desc_dma,
				    GFP_KERNEL);
	if (!hsotg->ctrl_out_desc)
		goto fail;

	return 0;

fail:
	return -ENOMEM;
}

/**
 * dwc2_hsotg_write_fifo - write packet Data to the TxFIFO
 * @hsotg: The controller state.
 * @hs_ep: The endpoint we're going to write for.
 * @hs_req: The request to write data for.
 *
 * This is called when the TxFIFO has some space in it to hold a new
 * transmission and we have something to give it. The actual setup of
 * the data size is done elsewhere, so all we have to do is to actually
 * write the data.
 *
 * The return value is zero if there is more space (or nothing was done)
 * otherwise -ENOSPC is returned if the FIFO space was used up.
 *
 * This routine is only needed for PIO
 */
static int dwc2_hsotg_write_fifo(struct dwc2_hsotg *hsotg,
				 struct dwc2_hsotg_ep *hs_ep,
				struct dwc2_hsotg_req *hs_req)
{
	bool periodic = is_ep_periodic(hs_ep);
	u32 gnptxsts = dwc2_readl(hsotg, GNPTXSTS);
	int buf_pos = hs_req->req.actual;
	int to_write = hs_ep->size_loaded;
	void *data;
	int can_write;
	int pkt_round;
	int max_transfer;

	to_write -= (buf_pos - hs_ep->last_load);

	/* if there's nothing to write, get out early */
	if (to_write == 0)
		return 0;

	if (periodic && !hsotg->dedicated_fifos) {
		u32 epsize = dwc2_readl(hsotg, DIEPTSIZ(hs_ep->index));
		int size_left;
		int size_done;

		/*
		 * work out how much data was loaded so we can calculate
		 * how much data is left in the fifo.
		 */

		size_left = DXEPTSIZ_XFERSIZE_GET(epsize);

		/*
		 * if shared fifo, we cannot write anything until the
		 * previous data has been completely sent.
		 */
		if (hs_ep->fifo_load != 0) {
			dwc2_hsotg_en_gsint(hsotg, GINTSTS_PTXFEMP);
			return -ENOSPC;
		}

		dev_dbg(hsotg->dev, "%s: left=%d, load=%d, fifo=%d, size %d\n",
			__func__, size_left,
			hs_ep->size_loaded, hs_ep->fifo_load, hs_ep->fifo_size);

		/* how much of the data has moved */
		size_done = hs_ep->size_loaded - size_left;

		/* how much data is left in the fifo */
		can_write = hs_ep->fifo_load - size_done;
		dev_dbg(hsotg->dev, "%s: => can_write1=%d\n",
			__func__, can_write);

		can_write = hs_ep->fifo_size - can_write;
		dev_dbg(hsotg->dev, "%s: => can_write2=%d\n",
			__func__, can_write);

		if (can_write <= 0) {
			dwc2_hsotg_en_gsint(hsotg, GINTSTS_PTXFEMP);
			return -ENOSPC;
		}
	} else if (hsotg->dedicated_fifos && hs_ep->index != 0) {
		can_write = dwc2_readl(hsotg,
				       DTXFSTS(hs_ep->fifo_index));

		can_write &= 0xffff;
		can_write *= 4;
	} else {
		if (GNPTXSTS_NP_TXQ_SPC_AVAIL_GET(gnptxsts) == 0) {
			dev_dbg(hsotg->dev,
				"%s: no queue slots available (0x%08x)\n",
				__func__, gnptxsts);

			dwc2_hsotg_en_gsint(hsotg, GINTSTS_NPTXFEMP);
			return -ENOSPC;
		}

		can_write = GNPTXSTS_NP_TXF_SPC_AVAIL_GET(gnptxsts);
		can_write *= 4;	/* fifo size is in 32bit quantities. */
	}

	max_transfer = hs_ep->ep.maxpacket * hs_ep->mc;

	dev_dbg(hsotg->dev, "%s: GNPTXSTS=%08x, can=%d, to=%d, max_transfer %d\n",
		__func__, gnptxsts, can_write, to_write, max_transfer);

	/*
	 * limit to 512 bytes of data, it seems at least on the non-periodic
	 * FIFO, requests of >512 cause the endpoint to get stuck with a
	 * fragment of the end of the transfer in it.
	 */
	if (can_write > 512 && !periodic)
		can_write = 512;

	/*
	 * limit the write to one max-packet size worth of data, but allow
	 * the transfer to return that it did not run out of fifo space
	 * doing it.
	 */
	if (to_write > max_transfer) {
		to_write = max_transfer;

		/* it's needed only when we do not use dedicated fifos */
		if (!hsotg->dedicated_fifos)
			dwc2_hsotg_en_gsint(hsotg,
					    periodic ? GINTSTS_PTXFEMP :
					   GINTSTS_NPTXFEMP);
	}

	/* see if we can write data */

	if (to_write > can_write) {
		to_write = can_write;
		pkt_round = to_write % max_transfer;

		/*
		 * Round the write down to an
		 * exact number of packets.
		 *
		 * Note, we do not currently check to see if we can ever
		 * write a full packet or not to the FIFO.
		 */

		if (pkt_round)
			to_write -= pkt_round;

		/*
		 * enable correct FIFO interrupt to alert us when there
		 * is more room left.
		 */

		/* it's needed only when we do not use dedicated fifos */
		if (!hsotg->dedicated_fifos)
			dwc2_hsotg_en_gsint(hsotg,
					    periodic ? GINTSTS_PTXFEMP :
					   GINTSTS_NPTXFEMP);
	}

	dev_dbg(hsotg->dev, "write %d/%d, can_write %d, done %d\n",
		to_write, hs_req->req.length, can_write, buf_pos);

	if (to_write <= 0)
		return -ENOSPC;

	hs_req->req.actual = buf_pos + to_write;
	hs_ep->total_data += to_write;

	if (periodic)
		hs_ep->fifo_load += to_write;

	to_write = DIV_ROUND_UP(to_write, 4);
	data = hs_req->req.buf + buf_pos;

	dwc2_writel_rep(hsotg, EPFIFO(hs_ep->index), data, to_write);

	return (to_write >= can_write) ? -ENOSPC : 0;
}

/**
 * get_ep_limit - get the maximum data legnth for this endpoint
 * @hs_ep: The endpoint
 *
 * Return the maximum data that can be queued in one go on a given endpoint
 * so that transfers that are too long can be split.
 */
static unsigned int get_ep_limit(struct dwc2_hsotg_ep *hs_ep)
{
	int index = hs_ep->index;
	unsigned int maxsize;
	unsigned int maxpkt;

	if (index != 0) {
		maxsize = DXEPTSIZ_XFERSIZE_LIMIT + 1;
		maxpkt = DXEPTSIZ_PKTCNT_LIMIT + 1;
	} else {
		maxsize = 64 + 64;
		if (hs_ep->dir_in)
			maxpkt = DIEPTSIZ0_PKTCNT_LIMIT + 1;
		else
			maxpkt = 2;
	}

	/* we made the constant loading easier above by using +1 */
	maxpkt--;
	maxsize--;

	/*
	 * constrain by packet count if maxpkts*pktsize is greater
	 * than the length register size.
	 */

	if ((maxpkt * hs_ep->ep.maxpacket) < maxsize)
		maxsize = maxpkt * hs_ep->ep.maxpacket;

	return maxsize;
}

/**
 * dwc2_hsotg_read_frameno - read current frame number
 * @hsotg: The device instance
 *
 * Return the current frame number
 */
static u32 dwc2_hsotg_read_frameno(struct dwc2_hsotg *hsotg)
{
	u32 dsts;

	dsts = dwc2_readl(hsotg, DSTS);
	dsts &= DSTS_SOFFN_MASK;
	dsts >>= DSTS_SOFFN_SHIFT;

	return dsts;
}

/**
 * dwc2_gadget_get_chain_limit - get the maximum data payload value of the
 * DMA descriptor chain prepared for specific endpoint
 * @hs_ep: The endpoint
 *
 * Return the maximum data that can be queued in one go on a given endpoint
 * depending on its descriptor chain capacity so that transfers that
 * are too long can be split.
 */
static unsigned int dwc2_gadget_get_chain_limit(struct dwc2_hsotg_ep *hs_ep)
{
	const struct usb_endpoint_descriptor *ep_desc = hs_ep->ep.desc;
	int is_isoc = hs_ep->isochronous;
	unsigned int maxsize;
	u32 mps = hs_ep->ep.maxpacket;
	int dir_in = hs_ep->dir_in;

	if (is_isoc)
		maxsize = (hs_ep->dir_in ? DEV_DMA_ISOC_TX_NBYTES_LIMIT :
					   DEV_DMA_ISOC_RX_NBYTES_LIMIT) *
					   MAX_DMA_DESC_NUM_HS_ISOC;
	else
		maxsize = DEV_DMA_NBYTES_LIMIT * MAX_DMA_DESC_NUM_GENERIC;

	/* Interrupt OUT EP with mps not multiple of 4 */
	if (hs_ep->index)
		if (usb_endpoint_xfer_int(ep_desc) && !dir_in && (mps % 4))
			maxsize = mps * MAX_DMA_DESC_NUM_GENERIC;

	return maxsize;
}

/*
 * dwc2_gadget_get_desc_params - get DMA descriptor parameters.
 * @hs_ep: The endpoint
 * @mask: RX/TX bytes mask to be defined
 *
 * Returns maximum data payload for one descriptor after analyzing endpoint
 * characteristics.
 * DMA descriptor transfer bytes limit depends on EP type:
 * Control out - MPS,
 * Isochronous - descriptor rx/tx bytes bitfield limit,
 * Control In/Bulk/Interrupt - multiple of mps. This will allow to not
 * have concatenations from various descriptors within one packet.
 * Interrupt OUT - if mps not multiple of 4 then a single packet corresponds
 * to a single descriptor.
 *
 * Selects corresponding mask for RX/TX bytes as well.
 */
static u32 dwc2_gadget_get_desc_params(struct dwc2_hsotg_ep *hs_ep, u32 *mask)
{
	const struct usb_endpoint_descriptor *ep_desc = hs_ep->ep.desc;
	u32 mps = hs_ep->ep.maxpacket;
	int dir_in = hs_ep->dir_in;
	u32 desc_size = 0;

	if (!hs_ep->index && !dir_in) {
		desc_size = mps;
		*mask = DEV_DMA_NBYTES_MASK;
	} else if (hs_ep->isochronous) {
		if (dir_in) {
			desc_size = DEV_DMA_ISOC_TX_NBYTES_LIMIT;
			*mask = DEV_DMA_ISOC_TX_NBYTES_MASK;
		} else {
			desc_size = DEV_DMA_ISOC_RX_NBYTES_LIMIT;
			*mask = DEV_DMA_ISOC_RX_NBYTES_MASK;
		}
	} else {
		desc_size = DEV_DMA_NBYTES_LIMIT;
		*mask = DEV_DMA_NBYTES_MASK;

		/* Round down desc_size to be mps multiple */
		desc_size -= desc_size % mps;
	}

	/* Interrupt OUT EP with mps not multiple of 4 */
	if (hs_ep->index)
		if (usb_endpoint_xfer_int(ep_desc) && !dir_in && (mps % 4)) {
			desc_size = mps;
			*mask = DEV_DMA_NBYTES_MASK;
		}

	return desc_size;
}

static void dwc2_gadget_fill_nonisoc_xfer_ddma_one(struct dwc2_hsotg_ep *hs_ep,
						 struct dwc2_dma_desc **desc,
						 dma_addr_t dma_buff,
						 unsigned int len,
						 bool true_last)
{
	int dir_in = hs_ep->dir_in;
	u32 mps = hs_ep->ep.maxpacket;
	u32 maxsize = 0;
	u32 offset = 0;
	u32 mask = 0;
	int i;

	maxsize = dwc2_gadget_get_desc_params(hs_ep, &mask);

	hs_ep->desc_count = (len / maxsize) +
				((len % maxsize) ? 1 : 0);
	if (len == 0)
		hs_ep->desc_count = 1;

	for (i = 0; i < hs_ep->desc_count; ++i) {
		(*desc)->status = 0;
		(*desc)->status |= (DEV_DMA_BUFF_STS_HBUSY
				 << DEV_DMA_BUFF_STS_SHIFT);

		if (len > maxsize) {
			if (!hs_ep->index && !dir_in)
				(*desc)->status |= (DEV_DMA_L | DEV_DMA_IOC);

			(*desc)->status |=
				maxsize << DEV_DMA_NBYTES_SHIFT & mask;
			(*desc)->buf = dma_buff + offset;

			len -= maxsize;
			offset += maxsize;
		} else {
			if (true_last)
				(*desc)->status |= (DEV_DMA_L | DEV_DMA_IOC);

			if (dir_in)
				(*desc)->status |= (len % mps) ? DEV_DMA_SHORT :
					((hs_ep->send_zlp && true_last) ?
					DEV_DMA_SHORT : 0);

			(*desc)->status |=
				len << DEV_DMA_NBYTES_SHIFT & mask;
			(*desc)->buf = dma_buff + offset;
		}

		(*desc)->status &= ~DEV_DMA_BUFF_STS_MASK;
		(*desc)->status |= (DEV_DMA_BUFF_STS_HREADY
				 << DEV_DMA_BUFF_STS_SHIFT);
		(*desc)++;
	}
}

/*
 * dwc2_gadget_config_nonisoc_xfer_ddma - prepare non ISOC DMA desc chain.
 * @hs_ep: The endpoint
 * @ureq: Request to transfer
 * @offset: offset in bytes
 * @len: Length of the transfer
 *
 * This function will iterate over descriptor chain and fill its entries
 * with corresponding information based on transfer data.
 */
static void dwc2_gadget_config_nonisoc_xfer_ddma(struct dwc2_hsotg_ep *hs_ep,
						 dma_addr_t dma_buff,
						 unsigned int len)
{
	struct usb_request *ureq = NULL;
	struct dwc2_dma_desc *desc = hs_ep->desc_list;
	struct scatterlist *sg;
	int i;
	u8 desc_count = 0;

	if (hs_ep->req)
		ureq = &hs_ep->req->req;

	/* non-DMA sg buffer */
	if (!ureq || !ureq->num_sgs) {
		dwc2_gadget_fill_nonisoc_xfer_ddma_one(hs_ep, &desc,
			dma_buff, len, true);
		return;
	}

	/* DMA sg buffer */
	for_each_sg(ureq->sg, sg, ureq->num_sgs, i) {
		dwc2_gadget_fill_nonisoc_xfer_ddma_one(hs_ep, &desc,
			sg_dma_address(sg) + sg->offset, sg_dma_len(sg),
			sg_is_last(sg));
		desc_count += hs_ep->desc_count;
	}

	hs_ep->desc_count = desc_count;
}

/*
 * dwc2_gadget_fill_isoc_desc - fills next isochronous descriptor in chain.
 * @hs_ep: The isochronous endpoint.
 * @dma_buff: usb requests dma buffer.
 * @len: usb request transfer length.
 *
 * Fills next free descriptor with the data of the arrived usb request,
 * frame info, sets Last and IOC bits increments next_desc. If filled
 * descriptor is not the first one, removes L bit from the previous descriptor
 * status.
 */
static int dwc2_gadget_fill_isoc_desc(struct dwc2_hsotg_ep *hs_ep,
				      dma_addr_t dma_buff, unsigned int len)
{
	struct dwc2_dma_desc *desc;
	struct dwc2_hsotg *hsotg = hs_ep->parent;
	u32 index;
	u32 mask = 0;
	u8 pid = 0;

	dwc2_gadget_get_desc_params(hs_ep, &mask);

	index = hs_ep->next_desc;
	desc = &hs_ep->desc_list[index];

	/* Check if descriptor chain full */
	if ((desc->status >> DEV_DMA_BUFF_STS_SHIFT) ==
	    DEV_DMA_BUFF_STS_HREADY) {
		dev_dbg(hsotg->dev, "%s: desc chain full\n", __func__);
		return 1;
	}

	/* Clear L bit of previous desc if more than one entries in the chain */
	if (hs_ep->next_desc)
		hs_ep->desc_list[index - 1].status &= ~DEV_DMA_L;

	dev_dbg(hsotg->dev, "%s: Filling ep %d, dir %s isoc desc # %d\n",
		__func__, hs_ep->index, hs_ep->dir_in ? "in" : "out", index);

	desc->status = 0;
	desc->status |= (DEV_DMA_BUFF_STS_HBUSY	<< DEV_DMA_BUFF_STS_SHIFT);

	desc->buf = dma_buff;
	desc->status |= (DEV_DMA_L | DEV_DMA_IOC |
			 ((len << DEV_DMA_NBYTES_SHIFT) & mask));

	if (hs_ep->dir_in) {
		if (len)
			pid = DIV_ROUND_UP(len, hs_ep->ep.maxpacket);
		else
			pid = 1;
		desc->status |= ((pid << DEV_DMA_ISOC_PID_SHIFT) &
				 DEV_DMA_ISOC_PID_MASK) |
				((len % hs_ep->ep.maxpacket) ?
				 DEV_DMA_SHORT : 0) |
				((hs_ep->target_frame <<
				  DEV_DMA_ISOC_FRNUM_SHIFT) &
				 DEV_DMA_ISOC_FRNUM_MASK);
	}

	desc->status &= ~DEV_DMA_BUFF_STS_MASK;
	desc->status |= (DEV_DMA_BUFF_STS_HREADY << DEV_DMA_BUFF_STS_SHIFT);

	/* Increment frame number by interval for IN */
	if (hs_ep->dir_in)
		dwc2_gadget_incr_frame_num(hs_ep);

	/* Update index of last configured entry in the chain */
	hs_ep->next_desc++;
	if (hs_ep->next_desc >= MAX_DMA_DESC_NUM_HS_ISOC)
		hs_ep->next_desc = 0;

	return 0;
}

/*
 * dwc2_gadget_start_isoc_ddma - start isochronous transfer in DDMA
 * @hs_ep: The isochronous endpoint.
 *
 * Prepare descriptor chain for isochronous endpoints. Afterwards
 * write DMA address to HW and enable the endpoint.
 */
static void dwc2_gadget_start_isoc_ddma(struct dwc2_hsotg_ep *hs_ep)
{
	struct dwc2_hsotg *hsotg = hs_ep->parent;
	struct dwc2_hsotg_req *hs_req, *treq;
	int index = hs_ep->index;
	int ret;
	int i;
	u32 dma_reg;
	u32 depctl;
	u32 ctrl;
	struct dwc2_dma_desc *desc;

	if (list_empty(&hs_ep->queue)) {
		hs_ep->target_frame = TARGET_FRAME_INITIAL;
		dev_dbg(hsotg->dev, "%s: No requests in queue\n", __func__);
		return;
	}

	/* Initialize descriptor chain by Host Busy status */
	for (i = 0; i < MAX_DMA_DESC_NUM_HS_ISOC; i++) {
		desc = &hs_ep->desc_list[i];
		desc->status = 0;
		desc->status |= (DEV_DMA_BUFF_STS_HBUSY
				    << DEV_DMA_BUFF_STS_SHIFT);
	}

	hs_ep->next_desc = 0;
	list_for_each_entry_safe(hs_req, treq, &hs_ep->queue, queue) {
		dma_addr_t dma_addr = hs_req->req.dma;

		if (hs_req->req.num_sgs) {
			WARN_ON(hs_req->req.num_sgs > 1);
			dma_addr = sg_dma_address(hs_req->req.sg);
		}
		ret = dwc2_gadget_fill_isoc_desc(hs_ep, dma_addr,
						 hs_req->req.length);
		if (ret)
			break;
	}

	hs_ep->compl_desc = 0;
	depctl = hs_ep->dir_in ? DIEPCTL(index) : DOEPCTL(index);
	dma_reg = hs_ep->dir_in ? DIEPDMA(index) : DOEPDMA(index);

	/* write descriptor chain address to control register */
	dwc2_writel(hsotg, hs_ep->desc_list_dma, dma_reg);

	ctrl = dwc2_readl(hsotg, depctl);
	ctrl |= DXEPCTL_EPENA | DXEPCTL_CNAK;
	dwc2_writel(hsotg, ctrl, depctl);
}

static bool dwc2_gadget_target_frame_elapsed(struct dwc2_hsotg_ep *hs_ep);
static void dwc2_hsotg_complete_request(struct dwc2_hsotg *hsotg,
					struct dwc2_hsotg_ep *hs_ep,
				       struct dwc2_hsotg_req *hs_req,
				       int result);

/**
 * dwc2_hsotg_start_req - start a USB request from an endpoint's queue
 * @hsotg: The controller state.
 * @hs_ep: The endpoint to process a request for
 * @hs_req: The request to start.
 * @continuing: True if we are doing more for the current request.
 *
 * Start the given request running by setting the endpoint registers
 * appropriately, and writing any data to the FIFOs.
 */
static void dwc2_hsotg_start_req(struct dwc2_hsotg *hsotg,
				 struct dwc2_hsotg_ep *hs_ep,
				struct dwc2_hsotg_req *hs_req,
				bool continuing)
{
	struct usb_request *ureq = &hs_req->req;
	int index = hs_ep->index;
	int dir_in = hs_ep->dir_in;
	u32 epctrl_reg;
	u32 epsize_reg;
	u32 epsize;
	u32 ctrl;
	unsigned int length;
	unsigned int packets;
	unsigned int maxreq;
	unsigned int dma_reg;

	if (index != 0) {
		if (hs_ep->req && !continuing) {
			dev_err(hsotg->dev, "%s: active request\n", __func__);
			WARN_ON(1);
			return;
		} else if (hs_ep->req != hs_req && continuing) {
			dev_err(hsotg->dev,
				"%s: continue different req\n", __func__);
			WARN_ON(1);
			return;
		}
	}

	dma_reg = dir_in ? DIEPDMA(index) : DOEPDMA(index);
	epctrl_reg = dir_in ? DIEPCTL(index) : DOEPCTL(index);
	epsize_reg = dir_in ? DIEPTSIZ(index) : DOEPTSIZ(index);

	dev_dbg(hsotg->dev, "%s: DxEPCTL=0x%08x, ep %d, dir %s\n",
		__func__, dwc2_readl(hsotg, epctrl_reg), index,
		hs_ep->dir_in ? "in" : "out");

	/* If endpoint is stalled, we will restart request later */
	ctrl = dwc2_readl(hsotg, epctrl_reg);

	if (index && ctrl & DXEPCTL_STALL) {
		dev_warn(hsotg->dev, "%s: ep%d is stalled\n", __func__, index);
		return;
	}

	length = ureq->length - ureq->actual;
	dev_dbg(hsotg->dev, "ureq->length:%d ureq->actual:%d\n",
		ureq->length, ureq->actual);

	if (!using_desc_dma(hsotg))
		maxreq = get_ep_limit(hs_ep);
	else
		maxreq = dwc2_gadget_get_chain_limit(hs_ep);

	if (length > maxreq) {
		int round = maxreq % hs_ep->ep.maxpacket;

		dev_dbg(hsotg->dev, "%s: length %d, max-req %d, r %d\n",
			__func__, length, maxreq, round);

		/* round down to multiple of packets */
		if (round)
			maxreq -= round;

		length = maxreq;
	}

	if (length)
		packets = DIV_ROUND_UP(length, hs_ep->ep.maxpacket);
	else
		packets = 1;	/* send one packet if length is zero. */

	if (dir_in && index != 0)
		if (hs_ep->isochronous)
			epsize = DXEPTSIZ_MC(packets);
		else
			epsize = DXEPTSIZ_MC(1);
	else
		epsize = 0;

	/*
	 * zero length packet should be programmed on its own and should not
	 * be counted in DIEPTSIZ.PktCnt with other packets.
	 */
	if (dir_in && ureq->zero && !continuing) {
		/* Test if zlp is actually required. */
		if ((ureq->length >= hs_ep->ep.maxpacket) &&
		    !(ureq->length % hs_ep->ep.maxpacket))
			hs_ep->send_zlp = 1;
	}

	epsize |= DXEPTSIZ_PKTCNT(packets);
	epsize |= DXEPTSIZ_XFERSIZE(length);

	dev_dbg(hsotg->dev, "%s: %d@%d/%d, 0x%08x => 0x%08x\n",
		__func__, packets, length, ureq->length, epsize, epsize_reg);

	/* store the request as the current one we're doing */
	hs_ep->req = hs_req;

	if (using_desc_dma(hsotg)) {
		u32 offset = 0;
		u32 mps = hs_ep->ep.maxpacket;

		/* Adjust length: EP0 - MPS, other OUT EPs - multiple of MPS */
		if (!dir_in) {
			if (!index)
				length = mps;
			else if (length % mps)
				length += (mps - (length % mps));
		}

		if (continuing)
			offset = ureq->actual;

		/* Fill DDMA chain entries */
		dwc2_gadget_config_nonisoc_xfer_ddma(hs_ep, ureq->dma + offset,
						     length);

		/* write descriptor chain address to control register */
		dwc2_writel(hsotg, hs_ep->desc_list_dma, dma_reg);

		dev_dbg(hsotg->dev, "%s: %08x pad => 0x%08x\n",
			__func__, (u32)hs_ep->desc_list_dma, dma_reg);
	} else {
		/* write size / packets */
		dwc2_writel(hsotg, epsize, epsize_reg);

		if (using_dma(hsotg) && !continuing && (length != 0)) {
			/*
			 * write DMA address to control register, buffer
			 * already synced by dwc2_hsotg_ep_queue().
			 */

			dwc2_writel(hsotg, ureq->dma, dma_reg);

			dev_dbg(hsotg->dev, "%s: %pad => 0x%08x\n",
				__func__, &ureq->dma, dma_reg);
		}
	}

	if (hs_ep->isochronous) {
		if (!dwc2_gadget_target_frame_elapsed(hs_ep)) {
			if (hs_ep->interval == 1) {
				if (hs_ep->target_frame & 0x1)
					ctrl |= DXEPCTL_SETODDFR;
				else
					ctrl |= DXEPCTL_SETEVENFR;
			}
			ctrl |= DXEPCTL_CNAK;
		} else {
			hs_req->req.frame_number = hs_ep->target_frame;
			hs_req->req.actual = 0;
			dwc2_hsotg_complete_request(hsotg, hs_ep, hs_req, -ENODATA);
			return;
		}
	}

	ctrl |= DXEPCTL_EPENA;	/* ensure ep enabled */

	dev_dbg(hsotg->dev, "ep0 state:%d\n", hsotg->ep0_state);

	/* For Setup request do not clear NAK */
	if (!(index == 0 && hsotg->ep0_state == DWC2_EP0_SETUP))
		ctrl |= DXEPCTL_CNAK;	/* clear NAK set by core */

	dev_dbg(hsotg->dev, "%s: DxEPCTL=0x%08x\n", __func__, ctrl);
	dwc2_writel(hsotg, ctrl, epctrl_reg);

	/*
	 * set these, it seems that DMA support increments past the end
	 * of the packet buffer so we need to calculate the length from
	 * this information.
	 */
	hs_ep->size_loaded = length;
	hs_ep->last_load = ureq->actual;

	if (dir_in && !using_dma(hsotg)) {
		/* set these anyway, we may need them for non-periodic in */
		hs_ep->fifo_load = 0;

		dwc2_hsotg_write_fifo(hsotg, hs_ep, hs_req);
	}

	/*
	 * Note, trying to clear the NAK here causes problems with transmit
	 * on the S3C6400 ending up with the TXFIFO becoming full.
	 */

	/* check ep is enabled */
	if (!(dwc2_readl(hsotg, epctrl_reg) & DXEPCTL_EPENA))
		dev_dbg(hsotg->dev,
			"ep%d: failed to become enabled (DXEPCTL=0x%08x)?\n",
			 index, dwc2_readl(hsotg, epctrl_reg));

	dev_dbg(hsotg->dev, "%s: DXEPCTL=0x%08x\n",
		__func__, dwc2_readl(hsotg, epctrl_reg));

	/* enable ep interrupts */
	dwc2_hsotg_ctrl_epint(hsotg, hs_ep->index, hs_ep->dir_in, 1);
}

/**
 * dwc2_hsotg_map_dma - map the DMA memory being used for the request
 * @hsotg: The device state.
 * @hs_ep: The endpoint the request is on.
 * @req: The request being processed.
 *
 * We've been asked to queue a request, so ensure that the memory buffer
 * is correctly setup for DMA. If we've been passed an extant DMA address
 * then ensure the buffer has been synced to memory. If our buffer has no
 * DMA memory, then we map the memory and mark our request to allow us to
 * cleanup on completion.
 */
static int dwc2_hsotg_map_dma(struct dwc2_hsotg *hsotg,
			      struct dwc2_hsotg_ep *hs_ep,
			     struct usb_request *req)
{
	int ret;

	hs_ep->map_dir = hs_ep->dir_in;
	ret = usb_gadget_map_request(&hsotg->gadget, req, hs_ep->dir_in);
	if (ret)
		goto dma_error;

	return 0;

dma_error:
	dev_err(hsotg->dev, "%s: failed to map buffer %p, %d bytes\n",
		__func__, req->buf, req->length);

	return -EIO;
}

static int dwc2_hsotg_handle_unaligned_buf_start(struct dwc2_hsotg *hsotg,
						 struct dwc2_hsotg_ep *hs_ep,
						 struct dwc2_hsotg_req *hs_req)
{
	void *req_buf = hs_req->req.buf;

	/* If dma is not being used or buffer is aligned */
	if (!using_dma(hsotg) || !((long)req_buf & 3))
		return 0;

	WARN_ON(hs_req->saved_req_buf);

	dev_dbg(hsotg->dev, "%s: %s: buf=%p length=%d\n", __func__,
		hs_ep->ep.name, req_buf, hs_req->req.length);

	hs_req->req.buf = kmalloc(hs_req->req.length, GFP_ATOMIC);
	if (!hs_req->req.buf) {
		hs_req->req.buf = req_buf;
		dev_err(hsotg->dev,
			"%s: unable to allocate memory for bounce buffer\n",
			__func__);
		return -ENOMEM;
	}

	/* Save actual buffer */
	hs_req->saved_req_buf = req_buf;

	if (hs_ep->dir_in)
		memcpy(hs_req->req.buf, req_buf, hs_req->req.length);
	return 0;
}

static void
dwc2_hsotg_handle_unaligned_buf_complete(struct dwc2_hsotg *hsotg,
					 struct dwc2_hsotg_ep *hs_ep,
					 struct dwc2_hsotg_req *hs_req)
{
	/* If dma is not being used or buffer was aligned */
	if (!using_dma(hsotg) || !hs_req->saved_req_buf)
		return;

	dev_dbg(hsotg->dev, "%s: %s: status=%d actual-length=%d\n", __func__,
		hs_ep->ep.name, hs_req->req.status, hs_req->req.actual);

	/* Copy data from bounce buffer on successful out transfer */
	if (!hs_ep->dir_in && !hs_req->req.status)
		memcpy(hs_req->saved_req_buf, hs_req->req.buf,
		       hs_req->req.actual);

	/* Free bounce buffer */
	kfree(hs_req->req.buf);

	hs_req->req.buf = hs_req->saved_req_buf;
	hs_req->saved_req_buf = NULL;
}

/**
 * dwc2_gadget_target_frame_elapsed - Checks target frame
 * @hs_ep: The driver endpoint to check
 *
 * Returns 1 if targeted frame elapsed. If returned 1 then we need to drop
 * corresponding transfer.
 */
static bool dwc2_gadget_target_frame_elapsed(struct dwc2_hsotg_ep *hs_ep)
{
	struct dwc2_hsotg *hsotg = hs_ep->parent;
	u32 target_frame = hs_ep->target_frame;
	u32 current_frame = hsotg->frame_number;
	bool frame_overrun = hs_ep->frame_overrun;
	u16 limit = DSTS_SOFFN_LIMIT;

	if (hsotg->gadget.speed != USB_SPEED_HIGH)
		limit >>= 3;

	if (!frame_overrun && current_frame >= target_frame)
		return true;

	if (frame_overrun && current_frame >= target_frame &&
	    ((current_frame - target_frame) < limit / 2))
		return true;

	return false;
}

/*
 * dwc2_gadget_set_ep0_desc_chain - Set EP's desc chain pointers
 * @hsotg: The driver state
 * @hs_ep: the ep descriptor chain is for
 *
 * Called to update EP0 structure's pointers depend on stage of
 * control transfer.
 */
static int dwc2_gadget_set_ep0_desc_chain(struct dwc2_hsotg *hsotg,
					  struct dwc2_hsotg_ep *hs_ep)
{
	switch (hsotg->ep0_state) {
	case DWC2_EP0_SETUP:
	case DWC2_EP0_STATUS_OUT:
		hs_ep->desc_list = hsotg->setup_desc[0];
		hs_ep->desc_list_dma = hsotg->setup_desc_dma[0];
		break;
	case DWC2_EP0_DATA_IN:
	case DWC2_EP0_STATUS_IN:
		hs_ep->desc_list = hsotg->ctrl_in_desc;
		hs_ep->desc_list_dma = hsotg->ctrl_in_desc_dma;
		break;
	case DWC2_EP0_DATA_OUT:
		hs_ep->desc_list = hsotg->ctrl_out_desc;
		hs_ep->desc_list_dma = hsotg->ctrl_out_desc_dma;
		break;
	default:
		dev_err(hsotg->dev, "invalid EP 0 state in queue %d\n",
			hsotg->ep0_state);
		return -EINVAL;
	}

	return 0;
}

static int dwc2_hsotg_ep_queue(struct usb_ep *ep, struct usb_request *req,
			       gfp_t gfp_flags)
{
	struct dwc2_hsotg_req *hs_req = our_req(req);
	struct dwc2_hsotg_ep *hs_ep = our_ep(ep);
	struct dwc2_hsotg *hs = hs_ep->parent;
	bool first;
	int ret;
	u32 maxsize = 0;
	u32 mask = 0;


	dev_dbg(hs->dev, "%s: req %p: %d@%p, noi=%d, zero=%d, snok=%d\n",
		ep->name, req, req->length, req->buf, req->no_interrupt,
		req->zero, req->short_not_ok);

	/* Prevent new request submission when controller is suspended */
	if (hs->lx_state != DWC2_L0) {
		dev_dbg(hs->dev, "%s: submit request only in active state\n",
			__func__);
		return -EAGAIN;
	}

	/* initialise status of the request */
	INIT_LIST_HEAD(&hs_req->queue);
	req->actual = 0;
	req->status = -EINPROGRESS;

	/* Don't queue ISOC request if length greater than mps*mc */
	if (hs_ep->isochronous &&
	    req->length > (hs_ep->mc * hs_ep->ep.maxpacket)) {
		dev_err(hs->dev, "req length > maxpacket*mc\n");
		return -EINVAL;
	}

	/* In DDMA mode for ISOC's don't queue request if length greater
	 * than descriptor limits.
	 */
	if (using_desc_dma(hs) && hs_ep->isochronous) {
		maxsize = dwc2_gadget_get_desc_params(hs_ep, &mask);
		if (hs_ep->dir_in && req->length > maxsize) {
			dev_err(hs->dev, "wrong length %d (maxsize=%d)\n",
				req->length, maxsize);
			return -EINVAL;
		}

		if (!hs_ep->dir_in && req->length > hs_ep->ep.maxpacket) {
			dev_err(hs->dev, "ISOC OUT: wrong length %d (mps=%d)\n",
				req->length, hs_ep->ep.maxpacket);
			return -EINVAL;
		}
	}

	ret = dwc2_hsotg_handle_unaligned_buf_start(hs, hs_ep, hs_req);
	if (ret)
		return ret;

	/* if we're using DMA, sync the buffers as necessary */
	if (using_dma(hs)) {
		ret = dwc2_hsotg_map_dma(hs, hs_ep, req);
		if (ret)
			return ret;
	}
	/* If using descriptor DMA configure EP0 descriptor chain pointers */
	if (using_desc_dma(hs) && !hs_ep->index) {
		ret = dwc2_gadget_set_ep0_desc_chain(hs, hs_ep);
		if (ret)
			return ret;
	}

	first = list_empty(&hs_ep->queue);
	list_add_tail(&hs_req->queue, &hs_ep->queue);

	/*
	 * Handle DDMA isochronous transfers separately - just add new entry
	 * to the descriptor chain.
	 * Transfer will be started once SW gets either one of NAK or
	 * OutTknEpDis interrupts.
	 */
	if (using_desc_dma(hs) && hs_ep->isochronous) {
		if (hs_ep->target_frame != TARGET_FRAME_INITIAL) {
			dma_addr_t dma_addr = hs_req->req.dma;

			if (hs_req->req.num_sgs) {
				WARN_ON(hs_req->req.num_sgs > 1);
				dma_addr = sg_dma_address(hs_req->req.sg);
			}
			dwc2_gadget_fill_isoc_desc(hs_ep, dma_addr,
						   hs_req->req.length);
		}
		return 0;
	}

	/* Change EP direction if status phase request is after data out */
	if (!hs_ep->index && !req->length && !hs_ep->dir_in &&
	    hs->ep0_state == DWC2_EP0_DATA_OUT)
		hs_ep->dir_in = 1;

	if (first) {
		if (!hs_ep->isochronous) {
			dwc2_hsotg_start_req(hs, hs_ep, hs_req, false);
			return 0;
		}

		/* Update current frame number value. */
		hs->frame_number = dwc2_hsotg_read_frameno(hs);
		while (dwc2_gadget_target_frame_elapsed(hs_ep)) {
			dwc2_gadget_incr_frame_num(hs_ep);
			/* Update current frame number value once more as it
			 * changes here.
			 */
			hs->frame_number = dwc2_hsotg_read_frameno(hs);
		}

		if (hs_ep->target_frame != TARGET_FRAME_INITIAL)
			dwc2_hsotg_start_req(hs, hs_ep, hs_req, false);
	}
	return 0;
}

static int dwc2_hsotg_ep_queue_lock(struct usb_ep *ep, struct usb_request *req,
				    gfp_t gfp_flags)
{
	struct dwc2_hsotg_ep *hs_ep = our_ep(ep);
	struct dwc2_hsotg *hs = hs_ep->parent;
	unsigned long flags = 0;
	int ret = 0;

	spin_lock_irqsave(&hs->lock, flags);
	ret = dwc2_hsotg_ep_queue(ep, req, gfp_flags);
	spin_unlock_irqrestore(&hs->lock, flags);

	return ret;
}

static void dwc2_hsotg_ep_free_request(struct usb_ep *ep,
				       struct usb_request *req)
{
	struct dwc2_hsotg_req *hs_req = our_req(req);

	kfree(hs_req);
}

/**
 * dwc2_hsotg_complete_oursetup - setup completion callback
 * @ep: The endpoint the request was on.
 * @req: The request completed.
 *
 * Called on completion of any requests the driver itself
 * submitted that need cleaning up.
 */
static void dwc2_hsotg_complete_oursetup(struct usb_ep *ep,
					 struct usb_request *req)
{
	struct dwc2_hsotg_ep *hs_ep = our_ep(ep);
	struct dwc2_hsotg *hsotg = hs_ep->parent;

	dev_dbg(hsotg->dev, "%s: ep %p, req %p\n", __func__, ep, req);

	dwc2_hsotg_ep_free_request(ep, req);
}

/**
 * ep_from_windex - convert control wIndex value to endpoint
 * @hsotg: The driver state.
 * @windex: The control request wIndex field (in host order).
 *
 * Convert the given wIndex into a pointer to an driver endpoint
 * structure, or return NULL if it is not a valid endpoint.
 */
static struct dwc2_hsotg_ep *ep_from_windex(struct dwc2_hsotg *hsotg,
					    u32 windex)
{
	int dir = (windex & USB_DIR_IN) ? 1 : 0;
	int idx = windex & 0x7F;

	if (windex >= 0x100)
		return NULL;

	if (idx > hsotg->num_of_eps)
		return NULL;

	return index_to_ep(hsotg, idx, dir);
}

/**
 * dwc2_hsotg_set_test_mode - Enable usb Test Modes
 * @hsotg: The driver state.
 * @testmode: requested usb test mode
 * Enable usb Test Mode requested by the Host.
 */
int dwc2_hsotg_set_test_mode(struct dwc2_hsotg *hsotg, int testmode)
{
	int dctl = dwc2_readl(hsotg, DCTL);

	dctl &= ~DCTL_TSTCTL_MASK;
	switch (testmode) {
	case USB_TEST_J:
	case USB_TEST_K:
	case USB_TEST_SE0_NAK:
	case USB_TEST_PACKET:
	case USB_TEST_FORCE_ENABLE:
		dctl |= testmode << DCTL_TSTCTL_SHIFT;
		break;
	default:
		return -EINVAL;
	}
	dwc2_writel(hsotg, dctl, DCTL);
	return 0;
}

/**
 * dwc2_hsotg_send_reply - send reply to control request
 * @hsotg: The device state
 * @ep: Endpoint 0
 * @buff: Buffer for request
 * @length: Length of reply.
 *
 * Create a request and queue it on the given endpoint. This is useful as
 * an internal method of sending replies to certain control requests, etc.
 */
static int dwc2_hsotg_send_reply(struct dwc2_hsotg *hsotg,
				 struct dwc2_hsotg_ep *ep,
				void *buff,
				int length)
{
	struct usb_request *req;
	int ret;

	dev_dbg(hsotg->dev, "%s: buff %p, len %d\n", __func__, buff, length);

	req = dwc2_hsotg_ep_alloc_request(&ep->ep, GFP_ATOMIC);
	hsotg->ep0_reply = req;
	if (!req) {
		dev_warn(hsotg->dev, "%s: cannot alloc req\n", __func__);
		return -ENOMEM;
	}

	req->buf = hsotg->ep0_buff;
	req->length = length;
	/*
	 * zero flag is for sending zlp in DATA IN stage. It has no impact on
	 * STATUS stage.
	 */
	req->zero = 0;
	req->complete = dwc2_hsotg_complete_oursetup;

	if (length)
		memcpy(req->buf, buff, length);

	ret = dwc2_hsotg_ep_queue(&ep->ep, req, GFP_ATOMIC);
	if (ret) {
		dev_warn(hsotg->dev, "%s: cannot queue req\n", __func__);
		return ret;
	}

	return 0;
}

/**
 * dwc2_hsotg_process_req_status - process request GET_STATUS
 * @hsotg: The device state
 * @ctrl: USB control request
 */
static int dwc2_hsotg_process_req_status(struct dwc2_hsotg *hsotg,
					 struct usb_ctrlrequest *ctrl)
{
	struct dwc2_hsotg_ep *ep0 = hsotg->eps_out[0];
	struct dwc2_hsotg_ep *ep;
	__le16 reply;
	u16 status;
	int ret;

	dev_dbg(hsotg->dev, "%s: USB_REQ_GET_STATUS\n", __func__);

	if (!ep0->dir_in) {
		dev_warn(hsotg->dev, "%s: direction out?\n", __func__);
		return -EINVAL;
	}

	switch (ctrl->bRequestType & USB_RECIP_MASK) {
	case USB_RECIP_DEVICE:
		status = hsotg->gadget.is_selfpowered <<
			 USB_DEVICE_SELF_POWERED;
		status |= hsotg->remote_wakeup_allowed <<
			  USB_DEVICE_REMOTE_WAKEUP;
		reply = cpu_to_le16(status);
		break;

	case USB_RECIP_INTERFACE:
		/* currently, the data result should be zero */
		reply = cpu_to_le16(0);
		break;

	case USB_RECIP_ENDPOINT:
		ep = ep_from_windex(hsotg, le16_to_cpu(ctrl->wIndex));
		if (!ep)
			return -ENOENT;

		reply = cpu_to_le16(ep->halted ? 1 : 0);
		break;

	default:
		return 0;
	}

	if (le16_to_cpu(ctrl->wLength) != 2)
		return -EINVAL;

	ret = dwc2_hsotg_send_reply(hsotg, ep0, &reply, 2);
	if (ret) {
		dev_err(hsotg->dev, "%s: failed to send reply\n", __func__);
		return ret;
	}

	return 1;
}

static int dwc2_hsotg_ep_sethalt(struct usb_ep *ep, int value, bool now);

/**
 * get_ep_head - return the first request on the endpoint
 * @hs_ep: The controller endpoint to get
 *
 * Get the first request on the endpoint.
 */
static struct dwc2_hsotg_req *get_ep_head(struct dwc2_hsotg_ep *hs_ep)
{
	return list_first_entry_or_null(&hs_ep->queue, struct dwc2_hsotg_req,
					queue);
}

/**
 * dwc2_gadget_start_next_request - Starts next request from ep queue
 * @hs_ep: Endpoint structure
 *
 * If queue is empty and EP is ISOC-OUT - unmasks OUTTKNEPDIS which is masked
 * in its handler. Hence we need to unmask it here to be able to do
 * resynchronization.
 */
static void dwc2_gadget_start_next_request(struct dwc2_hsotg_ep *hs_ep)
{
	struct dwc2_hsotg *hsotg = hs_ep->parent;
	int dir_in = hs_ep->dir_in;
	struct dwc2_hsotg_req *hs_req;

	if (!list_empty(&hs_ep->queue)) {
		hs_req = get_ep_head(hs_ep);
		dwc2_hsotg_start_req(hsotg, hs_ep, hs_req, false);
		return;
	}
	if (!hs_ep->isochronous)
		return;

	if (dir_in) {
		dev_dbg(hsotg->dev, "%s: No more ISOC-IN requests\n",
			__func__);
	} else {
		dev_dbg(hsotg->dev, "%s: No more ISOC-OUT requests\n",
			__func__);
	}
}

/**
 * dwc2_hsotg_process_req_feature - process request {SET,CLEAR}_FEATURE
 * @hsotg: The device state
 * @ctrl: USB control request
 */
static int dwc2_hsotg_process_req_feature(struct dwc2_hsotg *hsotg,
					  struct usb_ctrlrequest *ctrl)
{
	struct dwc2_hsotg_ep *ep0 = hsotg->eps_out[0];
	struct dwc2_hsotg_req *hs_req;
	bool set = (ctrl->bRequest == USB_REQ_SET_FEATURE);
	struct dwc2_hsotg_ep *ep;
	int ret;
	bool halted;
	u32 recip;
	u32 wValue;
	u32 wIndex;

	dev_dbg(hsotg->dev, "%s: %s_FEATURE\n",
		__func__, set ? "SET" : "CLEAR");

	wValue = le16_to_cpu(ctrl->wValue);
	wIndex = le16_to_cpu(ctrl->wIndex);
	recip = ctrl->bRequestType & USB_RECIP_MASK;

	switch (recip) {
	case USB_RECIP_DEVICE:
		switch (wValue) {
		case USB_DEVICE_REMOTE_WAKEUP:
			if (set)
				hsotg->remote_wakeup_allowed = 1;
			else
				hsotg->remote_wakeup_allowed = 0;
			break;

		case USB_DEVICE_TEST_MODE:
			if ((wIndex & 0xff) != 0)
				return -EINVAL;
			if (!set)
				return -EINVAL;

			hsotg->test_mode = wIndex >> 8;
			break;
		default:
			return -ENOENT;
		}

		ret = dwc2_hsotg_send_reply(hsotg, ep0, NULL, 0);
		if (ret) {
			dev_err(hsotg->dev,
				"%s: failed to send reply\n", __func__);
			return ret;
		}
		break;

	case USB_RECIP_ENDPOINT:
		ep = ep_from_windex(hsotg, wIndex);
		if (!ep) {
			dev_dbg(hsotg->dev, "%s: no endpoint for 0x%04x\n",
				__func__, wIndex);
			return -ENOENT;
		}

		switch (wValue) {
		case USB_ENDPOINT_HALT:
			halted = ep->halted;

			dwc2_hsotg_ep_sethalt(&ep->ep, set, true);

			ret = dwc2_hsotg_send_reply(hsotg, ep0, NULL, 0);
			if (ret) {
				dev_err(hsotg->dev,
					"%s: failed to send reply\n", __func__);
				return ret;
			}

			/*
			 * we have to complete all requests for ep if it was
			 * halted, and the halt was cleared by CLEAR_FEATURE
			 */

			if (!set && halted) {
				/*
				 * If we have request in progress,
				 * then complete it
				 */
				if (ep->req) {
					hs_req = ep->req;
					ep->req = NULL;
					list_del_init(&hs_req->queue);
					if (hs_req->req.complete) {
						spin_unlock(&hsotg->lock);
						usb_gadget_giveback_request(
							&ep->ep, &hs_req->req);
						spin_lock(&hsotg->lock);
					}
				}

				/* If we have pending request, then start it */
				if (!ep->req)
					dwc2_gadget_start_next_request(ep);
			}

			break;

		default:
			return -ENOENT;
		}
		break;
	default:
		return -ENOENT;
	}
	return 1;
}

static void dwc2_hsotg_enqueue_setup(struct dwc2_hsotg *hsotg);

/**
 * dwc2_hsotg_stall_ep0 - stall ep0
 * @hsotg: The device state
 *
 * Set stall for ep0 as response for setup request.
 */
static void dwc2_hsotg_stall_ep0(struct dwc2_hsotg *hsotg)
{
	struct dwc2_hsotg_ep *ep0 = hsotg->eps_out[0];
	u32 reg;
	u32 ctrl;

	dev_dbg(hsotg->dev, "ep0 stall (dir=%d)\n", ep0->dir_in);
	reg = (ep0->dir_in) ? DIEPCTL0 : DOEPCTL0;

	/*
	 * DxEPCTL_Stall will be cleared by EP once it has
	 * taken effect, so no need to clear later.
	 */

	ctrl = dwc2_readl(hsotg, reg);
	ctrl |= DXEPCTL_STALL;
	ctrl |= DXEPCTL_CNAK;
	dwc2_writel(hsotg, ctrl, reg);

	dev_dbg(hsotg->dev,
		"written DXEPCTL=0x%08x to %08x (DXEPCTL=0x%08x)\n",
		ctrl, reg, dwc2_readl(hsotg, reg));

	 /*
	  * complete won't be called, so we enqueue
	  * setup request here
	  */
	 dwc2_hsotg_enqueue_setup(hsotg);
}

/**
 * dwc2_hsotg_process_control - process a control request
 * @hsotg: The device state
 * @ctrl: The control request received
 *
 * The controller has received the SETUP phase of a control request, and
 * needs to work out what to do next (and whether to pass it on to the
 * gadget driver).
 */
static void dwc2_hsotg_process_control(struct dwc2_hsotg *hsotg,
				       struct usb_ctrlrequest *ctrl)
{
	struct dwc2_hsotg_ep *ep0 = hsotg->eps_out[0];
	int ret = 0;
	u32 dcfg;

	dev_dbg(hsotg->dev,
		"ctrl Type=%02x, Req=%02x, V=%04x, I=%04x, L=%04x\n",
		ctrl->bRequestType, ctrl->bRequest, ctrl->wValue,
		ctrl->wIndex, ctrl->wLength);

	if (ctrl->wLength == 0) {
		ep0->dir_in = 1;
		hsotg->ep0_state = DWC2_EP0_STATUS_IN;
	} else if (ctrl->bRequestType & USB_DIR_IN) {
		ep0->dir_in = 1;
		hsotg->ep0_state = DWC2_EP0_DATA_IN;
	} else {
		ep0->dir_in = 0;
		hsotg->ep0_state = DWC2_EP0_DATA_OUT;
	}

	if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD) {
		switch (ctrl->bRequest) {
		case USB_REQ_SET_ADDRESS:
			hsotg->connected = 1;
			dcfg = dwc2_readl(hsotg, DCFG);
			dcfg &= ~DCFG_DEVADDR_MASK;
			dcfg |= (le16_to_cpu(ctrl->wValue) <<
				 DCFG_DEVADDR_SHIFT) & DCFG_DEVADDR_MASK;
			dwc2_writel(hsotg, dcfg, DCFG);

			dev_info(hsotg->dev, "new address %d\n", ctrl->wValue);

			ret = dwc2_hsotg_send_reply(hsotg, ep0, NULL, 0);
			return;

		case USB_REQ_GET_STATUS:
			ret = dwc2_hsotg_process_req_status(hsotg, ctrl);
			break;

		case USB_REQ_CLEAR_FEATURE:
		case USB_REQ_SET_FEATURE:
			ret = dwc2_hsotg_process_req_feature(hsotg, ctrl);
			break;
		}
	}

	/* as a fallback, try delivering it to the driver to deal with */

	if (ret == 0 && hsotg->driver) {
		spin_unlock(&hsotg->lock);
		ret = hsotg->driver->setup(&hsotg->gadget, ctrl);
		spin_lock(&hsotg->lock);
		if (ret < 0)
			dev_dbg(hsotg->dev, "driver->setup() ret %d\n", ret);
	}

	hsotg->delayed_status = false;
	if (ret == USB_GADGET_DELAYED_STATUS)
		hsotg->delayed_status = true;

	/*
	 * the request is either unhandlable, or is not formatted correctly
	 * so respond with a STALL for the status stage to indicate failure.
	 */

	if (ret < 0)
		dwc2_hsotg_stall_ep0(hsotg);
}

/**
 * dwc2_hsotg_complete_setup - completion of a setup transfer
 * @ep: The endpoint the request was on.
 * @req: The request completed.
 *
 * Called on completion of any requests the driver itself submitted for
 * EP0 setup packets
 */
static void dwc2_hsotg_complete_setup(struct usb_ep *ep,
				      struct usb_request *req)
{
	struct dwc2_hsotg_ep *hs_ep = our_ep(ep);
	struct dwc2_hsotg *hsotg = hs_ep->parent;

	if (req->status < 0) {
		dev_dbg(hsotg->dev, "%s: failed %d\n", __func__, req->status);
		return;
	}

	spin_lock(&hsotg->lock);
	if (req->actual == 0)
		dwc2_hsotg_enqueue_setup(hsotg);
	else
		dwc2_hsotg_process_control(hsotg, req->buf);
	spin_unlock(&hsotg->lock);
}

/**
 * dwc2_hsotg_enqueue_setup - start a request for EP0 packets
 * @hsotg: The device state.
 *
 * Enqueue a request on EP0 if necessary to received any SETUP packets
 * received from the host.
 */
static void dwc2_hsotg_enqueue_setup(struct dwc2_hsotg *hsotg)
{
	struct usb_request *req = hsotg->ctrl_req;
	struct dwc2_hsotg_req *hs_req = our_req(req);
	int ret;

	dev_dbg(hsotg->dev, "%s: queueing setup request\n", __func__);

	req->zero = 0;
	req->length = 8;
	req->buf = hsotg->ctrl_buff;
	req->complete = dwc2_hsotg_complete_setup;

	if (!list_empty(&hs_req->queue)) {
		dev_dbg(hsotg->dev, "%s already queued???\n", __func__);
		return;
	}

	hsotg->eps_out[0]->dir_in = 0;
	hsotg->eps_out[0]->send_zlp = 0;
	hsotg->ep0_state = DWC2_EP0_SETUP;

	ret = dwc2_hsotg_ep_queue(&hsotg->eps_out[0]->ep, req, GFP_ATOMIC);
	if (ret < 0) {
		dev_err(hsotg->dev, "%s: failed queue (%d)\n", __func__, ret);
		/*
		 * Don't think there's much we can do other than watch the
		 * driver fail.
		 */
	}
}

static void dwc2_hsotg_program_zlp(struct dwc2_hsotg *hsotg,
				   struct dwc2_hsotg_ep *hs_ep)
{
	u32 ctrl;
	u8 index = hs_ep->index;
	u32 epctl_reg = hs_ep->dir_in ? DIEPCTL(index) : DOEPCTL(index);
	u32 epsiz_reg = hs_ep->dir_in ? DIEPTSIZ(index) : DOEPTSIZ(index);

	if (hs_ep->dir_in)
		dev_dbg(hsotg->dev, "Sending zero-length packet on ep%d\n",
			index);
	else
		dev_dbg(hsotg->dev, "Receiving zero-length packet on ep%d\n",
			index);
	if (using_desc_dma(hsotg)) {
		/* Not specific buffer needed for ep0 ZLP */
		dma_addr_t dma = hs_ep->desc_list_dma;

		if (!index)
			dwc2_gadget_set_ep0_desc_chain(hsotg, hs_ep);

		dwc2_gadget_config_nonisoc_xfer_ddma(hs_ep, dma, 0);
	} else {
		dwc2_writel(hsotg, DXEPTSIZ_MC(1) | DXEPTSIZ_PKTCNT(1) |
			    DXEPTSIZ_XFERSIZE(0),
			    epsiz_reg);
	}

	ctrl = dwc2_readl(hsotg, epctl_reg);
	ctrl |= DXEPCTL_CNAK;  /* clear NAK set by core */
	ctrl |= DXEPCTL_EPENA; /* ensure ep enabled */
	ctrl |= DXEPCTL_USBACTEP;
	dwc2_writel(hsotg, ctrl, epctl_reg);
}

/**
 * dwc2_hsotg_complete_request - complete a request given to us
 * @hsotg: The device state.
 * @hs_ep: The endpoint the request was on.
 * @hs_req: The request to complete.
 * @result: The result code (0 => Ok, otherwise errno)
 *
 * The given request has finished, so call the necessary completion
 * if it has one and then look to see if we can start a new request
 * on the endpoint.
 *
 * Note, expects the ep to already be locked as appropriate.
 */
static void dwc2_hsotg_complete_request(struct dwc2_hsotg *hsotg,
					struct dwc2_hsotg_ep *hs_ep,
				       struct dwc2_hsotg_req *hs_req,
				       int result)
{
	if (!hs_req) {
		dev_dbg(hsotg->dev, "%s: nothing to complete?\n", __func__);
		return;
	}

	dev_dbg(hsotg->dev, "complete: ep %p %s, req %p, %d => %p\n",
		hs_ep, hs_ep->ep.name, hs_req, result, hs_req->req.complete);

	/*
	 * only replace the status if we've not already set an error
	 * from a previous transaction
	 */

	if (hs_req->req.status == -EINPROGRESS)
		hs_req->req.status = result;

	if (using_dma(hsotg))
		dwc2_hsotg_unmap_dma(hsotg, hs_ep, hs_req);

	dwc2_hsotg_handle_unaligned_buf_complete(hsotg, hs_ep, hs_req);

	hs_ep->req = NULL;
	list_del_init(&hs_req->queue);

	/*
	 * call the complete request with the locks off, just in case the
	 * request tries to queue more work for this endpoint.
	 */

	if (hs_req->req.complete) {
		spin_unlock(&hsotg->lock);
		usb_gadget_giveback_request(&hs_ep->ep, &hs_req->req);
		spin_lock(&hsotg->lock);
	}

	/* In DDMA don't need to proceed to starting of next ISOC request */
	if (using_desc_dma(hsotg) && hs_ep->isochronous)
		return;

	/*
	 * Look to see if there is anything else to do. Note, the completion
	 * of the previous request may have caused a new request to be started
	 * so be careful when doing this.
	 */

	if (!hs_ep->req && result >= 0)
		dwc2_gadget_start_next_request(hs_ep);
}

/*
 * dwc2_gadget_complete_isoc_request_ddma - complete an isoc request in DDMA
 * @hs_ep: The endpoint the request was on.
 *
 * Get first request from the ep queue, determine descriptor on which complete
 * happened. SW discovers which descriptor currently in use by HW, adjusts
 * dma_address and calculates index of completed descriptor based on the value
 * of DEPDMA register. Update actual length of request, giveback to gadget.
 */
static void dwc2_gadget_complete_isoc_request_ddma(struct dwc2_hsotg_ep *hs_ep)
{
	struct dwc2_hsotg *hsotg = hs_ep->parent;
	struct dwc2_hsotg_req *hs_req;
	struct usb_request *ureq;
	u32 desc_sts;
	u32 mask;

	desc_sts = hs_ep->desc_list[hs_ep->compl_desc].status;

	/* Process only descriptors with buffer status set to DMA done */
	while ((desc_sts & DEV_DMA_BUFF_STS_MASK) >>
		DEV_DMA_BUFF_STS_SHIFT == DEV_DMA_BUFF_STS_DMADONE) {

		hs_req = get_ep_head(hs_ep);
		if (!hs_req) {
			dev_warn(hsotg->dev, "%s: ISOC EP queue empty\n", __func__);
			return;
		}
		ureq = &hs_req->req;

		/* Check completion status */
		if ((desc_sts & DEV_DMA_STS_MASK) >> DEV_DMA_STS_SHIFT ==
			DEV_DMA_STS_SUCC) {
			mask = hs_ep->dir_in ? DEV_DMA_ISOC_TX_NBYTES_MASK :
				DEV_DMA_ISOC_RX_NBYTES_MASK;
			ureq->actual = ureq->length - ((desc_sts & mask) >>
				DEV_DMA_ISOC_NBYTES_SHIFT);

			/* Adjust actual len for ISOC Out if len is
			 * not align of 4
			 */
			if (!hs_ep->dir_in && ureq->length & 0x3)
				ureq->actual += 4 - (ureq->length & 0x3);

			/* Set actual frame number for completed transfers */
			ureq->frame_number =
				(desc_sts & DEV_DMA_ISOC_FRNUM_MASK) >>
				DEV_DMA_ISOC_FRNUM_SHIFT;
		}

		dwc2_hsotg_complete_request(hsotg, hs_ep, hs_req, 0);

		hs_ep->compl_desc++;
		if (hs_ep->compl_desc > (MAX_DMA_DESC_NUM_HS_ISOC - 1))
			hs_ep->compl_desc = 0;
		desc_sts = hs_ep->desc_list[hs_ep->compl_desc].status;
	}
}

/*
 * dwc2_gadget_handle_isoc_bna - handle BNA interrupt for ISOC.
 * @hs_ep: The isochronous endpoint.
 *
 * If EP ISOC OUT then need to flush RX FIFO to remove source of BNA
 * interrupt. Reset target frame and next_desc to allow to start
 * ISOC's on NAK interrupt for IN direction or on OUTTKNEPDIS
 * interrupt for OUT direction.
 */
static void dwc2_gadget_handle_isoc_bna(struct dwc2_hsotg_ep *hs_ep)
{
	struct dwc2_hsotg *hsotg = hs_ep->parent;

	if (!hs_ep->dir_in)
		dwc2_flush_rx_fifo(hsotg);
	dwc2_hsotg_complete_request(hsotg, hs_ep, get_ep_head(hs_ep), 0);

	hs_ep->target_frame = TARGET_FRAME_INITIAL;
	hs_ep->next_desc = 0;
	hs_ep->compl_desc = 0;
}

/**
 * dwc2_hsotg_rx_data - receive data from the FIFO for an endpoint
 * @hsotg: The device state.
 * @ep_idx: The endpoint index for the data
 * @size: The size of data in the fifo, in bytes
 *
 * The FIFO status shows there is data to read from the FIFO for a given
 * endpoint, so sort out whether we need to read the data into a request
 * that has been made for that endpoint.
 */
static void dwc2_hsotg_rx_data(struct dwc2_hsotg *hsotg, int ep_idx, int size)
{
	struct dwc2_hsotg_ep *hs_ep = hsotg->eps_out[ep_idx];
	struct dwc2_hsotg_req *hs_req = hs_ep->req;
	int to_read;
	int max_req;
	int read_ptr;

	if (!hs_req) {
		u32 epctl = dwc2_readl(hsotg, DOEPCTL(ep_idx));
		int ptr;

		dev_dbg(hsotg->dev,
			"%s: FIFO %d bytes on ep%d but no req (DXEPCTl=0x%08x)\n",
			 __func__, size, ep_idx, epctl);

		/* dump the data from the FIFO, we've nothing we can do */
		for (ptr = 0; ptr < size; ptr += 4)
			(void)dwc2_readl(hsotg, EPFIFO(ep_idx));

		return;
	}

	to_read = size;
	read_ptr = hs_req->req.actual;
	max_req = hs_req->req.length - read_ptr;

	dev_dbg(hsotg->dev, "%s: read %d/%d, done %d/%d\n",
		__func__, to_read, max_req, read_ptr, hs_req->req.length);

	if (to_read > max_req) {
		/*
		 * more data appeared than we where willing
		 * to deal with in this request.
		 */

		/* currently we don't deal this */
		WARN_ON_ONCE(1);
	}

	hs_ep->total_data += to_read;
	hs_req->req.actual += to_read;
	to_read = DIV_ROUND_UP(to_read, 4);

	/*
	 * note, we might over-write the buffer end by 3 bytes depending on
	 * alignment of the data.
	 */
	dwc2_readl_rep(hsotg, EPFIFO(ep_idx),
		       hs_req->req.buf + read_ptr, to_read);
}

/**
 * dwc2_hsotg_ep0_zlp - send/receive zero-length packet on control endpoint
 * @hsotg: The device instance
 * @dir_in: If IN zlp
 *
 * Generate a zero-length IN packet request for terminating a SETUP
 * transaction.
 *
 * Note, since we don't write any data to the TxFIFO, then it is
 * currently believed that we do not need to wait for any space in
 * the TxFIFO.
 */
static void dwc2_hsotg_ep0_zlp(struct dwc2_hsotg *hsotg, bool dir_in)
{
	/* eps_out[0] is used in both directions */
	hsotg->eps_out[0]->dir_in = dir_in;
	hsotg->ep0_state = dir_in ? DWC2_EP0_STATUS_IN : DWC2_EP0_STATUS_OUT;

	dwc2_hsotg_program_zlp(hsotg, hsotg->eps_out[0]);
}

/*
 * dwc2_gadget_get_xfersize_ddma - get transferred bytes amount from desc
 * @hs_ep - The endpoint on which transfer went
 *
 * Iterate over endpoints descriptor chain and get info on bytes remained
 * in DMA descriptors after transfer has completed. Used for non isoc EPs.
 */
static unsigned int dwc2_gadget_get_xfersize_ddma(struct dwc2_hsotg_ep *hs_ep)
{
	const struct usb_endpoint_descriptor *ep_desc = hs_ep->ep.desc;
	struct dwc2_hsotg *hsotg = hs_ep->parent;
	unsigned int bytes_rem = 0;
	unsigned int bytes_rem_correction = 0;
	struct dwc2_dma_desc *desc = hs_ep->desc_list;
	int i;
	u32 status;
	u32 mps = hs_ep->ep.maxpacket;
	int dir_in = hs_ep->dir_in;

	if (!desc)
		return -EINVAL;

	/* Interrupt OUT EP with mps not multiple of 4 */
	if (hs_ep->index)
		if (usb_endpoint_xfer_int(ep_desc) && !dir_in && (mps % 4))
			bytes_rem_correction = 4 - (mps % 4);

	for (i = 0; i < hs_ep->desc_count; ++i) {
		status = desc->status;
		bytes_rem += status & DEV_DMA_NBYTES_MASK;
		bytes_rem -= bytes_rem_correction;

		if (status & DEV_DMA_STS_MASK)
			dev_err(hsotg->dev, "descriptor %d closed with %x\n",
				i, status & DEV_DMA_STS_MASK);

		if (status & DEV_DMA_L)
			break;

		desc++;
	}

	return bytes_rem;
}

/**
 * dwc2_hsotg_handle_outdone - handle receiving OutDone/SetupDone from RXFIFO
 * @hsotg: The device instance
 * @epnum: The endpoint received from
 *
 * The RXFIFO has delivered an OutDone event, which means that the data
 * transfer for an OUT endpoint has been completed, either by a short
 * packet or by the finish of a transfer.
 */
static void dwc2_hsotg_handle_outdone(struct dwc2_hsotg *hsotg, int epnum)
{
	u32 epsize = dwc2_readl(hsotg, DOEPTSIZ(epnum));
	struct dwc2_hsotg_ep *hs_ep = hsotg->eps_out[epnum];
	struct dwc2_hsotg_req *hs_req = hs_ep->req;
	struct usb_request *req = &hs_req->req;
	unsigned int size_left = DXEPTSIZ_XFERSIZE_GET(epsize);
	int result = 0;

	if (!hs_req) {
		dev_dbg(hsotg->dev, "%s: no request active\n", __func__);
		return;
	}

	if (epnum == 0 && hsotg->ep0_state == DWC2_EP0_STATUS_OUT) {
		dev_dbg(hsotg->dev, "zlp packet received\n");
		dwc2_hsotg_complete_request(hsotg, hs_ep, hs_req, 0);
		dwc2_hsotg_enqueue_setup(hsotg);
		return;
	}

	if (using_desc_dma(hsotg))
		size_left = dwc2_gadget_get_xfersize_ddma(hs_ep);

	if (using_dma(hsotg)) {
		unsigned int size_done;

		/*
		 * Calculate the size of the transfer by checking how much
		 * is left in the endpoint size register and then working it
		 * out from the amount we loaded for the transfer.
		 *
		 * We need to do this as DMA pointers are always 32bit aligned
		 * so may overshoot/undershoot the transfer.
		 */

		size_done = hs_ep->size_loaded - size_left;
		size_done += hs_ep->last_load;

		req->actual = size_done;
	}

	/* if there is more request to do, schedule new transfer */
	if (req->actual < req->length && size_left == 0) {
		dwc2_hsotg_start_req(hsotg, hs_ep, hs_req, true);
		return;
	}

	if (req->actual < req->length && req->short_not_ok) {
		dev_dbg(hsotg->dev, "%s: got %d/%d (short not ok) => error\n",
			__func__, req->actual, req->length);

		/*
		 * todo - what should we return here? there's no one else
		 * even bothering to check the status.
		 */
	}

	/* DDMA IN status phase will start from StsPhseRcvd interrupt */
	if (!using_desc_dma(hsotg) && epnum == 0 &&
	    hsotg->ep0_state == DWC2_EP0_DATA_OUT) {
		/* Move to STATUS IN */
		if (!hsotg->delayed_status)
			dwc2_hsotg_ep0_zlp(hsotg, true);
	}

	/* Set actual frame number for completed transfers */
	if (!using_desc_dma(hsotg) && hs_ep->isochronous) {
		req->frame_number = hs_ep->target_frame;
		dwc2_gadget_incr_frame_num(hs_ep);
	}

	dwc2_hsotg_complete_request(hsotg, hs_ep, hs_req, result);
}

/**
 * dwc2_hsotg_handle_rx - RX FIFO has data
 * @hsotg: The device instance
 *
 * The IRQ handler has detected that the RX FIFO has some data in it
 * that requires processing, so find out what is in there and do the
 * appropriate read.
 *
 * The RXFIFO is a true FIFO, the packets coming out are still in packet
 * chunks, so if you have x packets received on an endpoint you'll get x
 * FIFO events delivered, each with a packet's worth of data in it.
 *
 * When using DMA, we should not be processing events from the RXFIFO
 * as the actual data should be sent to the memory directly and we turn
 * on the completion interrupts to get notifications of transfer completion.
 */
static void dwc2_hsotg_handle_rx(struct dwc2_hsotg *hsotg)
{
	u32 grxstsr = dwc2_readl(hsotg, GRXSTSP);
	u32 epnum, status, size;

	WARN_ON(using_dma(hsotg));

	epnum = grxstsr & GRXSTS_EPNUM_MASK;
	status = grxstsr & GRXSTS_PKTSTS_MASK;

	size = grxstsr & GRXSTS_BYTECNT_MASK;
	size >>= GRXSTS_BYTECNT_SHIFT;

	dev_dbg(hsotg->dev, "%s: GRXSTSP=0x%08x (%d@%d)\n",
		__func__, grxstsr, size, epnum);

	switch ((status & GRXSTS_PKTSTS_MASK) >> GRXSTS_PKTSTS_SHIFT) {
	case GRXSTS_PKTSTS_GLOBALOUTNAK:
		dev_dbg(hsotg->dev, "GLOBALOUTNAK\n");
		break;

	case GRXSTS_PKTSTS_OUTDONE:
		dev_dbg(hsotg->dev, "OutDone (Frame=0x%08x)\n",
			dwc2_hsotg_read_frameno(hsotg));

		if (!using_dma(hsotg))
			dwc2_hsotg_handle_outdone(hsotg, epnum);
		break;

	case GRXSTS_PKTSTS_SETUPDONE:
		dev_dbg(hsotg->dev,
			"SetupDone (Frame=0x%08x, DOPEPCTL=0x%08x)\n",
			dwc2_hsotg_read_frameno(hsotg),
			dwc2_readl(hsotg, DOEPCTL(0)));
		/*
		 * Call dwc2_hsotg_handle_outdone here if it was not called from
		 * GRXSTS_PKTSTS_OUTDONE. That is, if the core didn't
		 * generate GRXSTS_PKTSTS_OUTDONE for setup packet.
		 */
		if (hsotg->ep0_state == DWC2_EP0_SETUP)
			dwc2_hsotg_handle_outdone(hsotg, epnum);
		break;

	case GRXSTS_PKTSTS_OUTRX:
		dwc2_hsotg_rx_data(hsotg, epnum, size);
		break;

	case GRXSTS_PKTSTS_SETUPRX:
		dev_dbg(hsotg->dev,
			"SetupRX (Frame=0x%08x, DOPEPCTL=0x%08x)\n",
			dwc2_hsotg_read_frameno(hsotg),
			dwc2_readl(hsotg, DOEPCTL(0)));

		WARN_ON(hsotg->ep0_state != DWC2_EP0_SETUP);

		dwc2_hsotg_rx_data(hsotg, epnum, size);
		break;

	default:
		dev_warn(hsotg->dev, "%s: unknown status %08x\n",
			 __func__, grxstsr);

		dwc2_hsotg_dump(hsotg);
		break;
	}
}

/**
 * dwc2_hsotg_ep0_mps - turn max packet size into register setting
 * @mps: The maximum packet size in bytes.
 */
static u32 dwc2_hsotg_ep0_mps(unsigned int mps)
{
	switch (mps) {
	case 64:
		return D0EPCTL_MPS_64;
	case 32:
		return D0EPCTL_MPS_32;
	case 16:
		return D0EPCTL_MPS_16;
	case 8:
		return D0EPCTL_MPS_8;
	}

	/* bad max packet size, warn and return invalid result */
	WARN_ON(1);
	return (u32)-1;
}

/**
 * dwc2_hsotg_set_ep_maxpacket - set endpoint's max-packet field
 * @hsotg: The driver state.
 * @ep: The index number of the endpoint
 * @mps: The maximum packet size in bytes
 * @mc: The multicount value
 * @dir_in: True if direction is in.
 *
 * Configure the maximum packet size for the given endpoint, updating
 * the hardware control registers to reflect this.
 */
static void dwc2_hsotg_set_ep_maxpacket(struct dwc2_hsotg *hsotg,
					unsigned int ep, unsigned int mps,
					unsigned int mc, unsigned int dir_in)
{
	struct dwc2_hsotg_ep *hs_ep;
	u32 reg;

	hs_ep = index_to_ep(hsotg, ep, dir_in);
	if (!hs_ep)
		return;

	if (ep == 0) {
		u32 mps_bytes = mps;

		/* EP0 is a special case */
		mps = dwc2_hsotg_ep0_mps(mps_bytes);
		if (mps > 3)
			goto bad_mps;
		hs_ep->ep.maxpacket = mps_bytes;
		hs_ep->mc = 1;
	} else {
		if (mps > 1024)
			goto bad_mps;
		hs_ep->mc = mc;
		if (mc > 3)
			goto bad_mps;
		hs_ep->ep.maxpacket = mps;
	}

	if (dir_in) {
		reg = dwc2_readl(hsotg, DIEPCTL(ep));
		reg &= ~DXEPCTL_MPS_MASK;
		reg |= mps;
		dwc2_writel(hsotg, reg, DIEPCTL(ep));
	} else {
		reg = dwc2_readl(hsotg, DOEPCTL(ep));
		reg &= ~DXEPCTL_MPS_MASK;
		reg |= mps;
		dwc2_writel(hsotg, reg, DOEPCTL(ep));
	}

	return;

bad_mps:
	dev_err(hsotg->dev, "ep%d: bad mps of %d\n", ep, mps);
}

/**
 * dwc2_hsotg_txfifo_flush - flush Tx FIFO
 * @hsotg: The driver state
 * @idx: The index for the endpoint (0..15)
 */
static void dwc2_hsotg_txfifo_flush(struct dwc2_hsotg *hsotg, unsigned int idx)
{
	dwc2_writel(hsotg, GRSTCTL_TXFNUM(idx) | GRSTCTL_TXFFLSH,
		    GRSTCTL);

	/* wait until the fifo is flushed */
	if (dwc2_hsotg_wait_bit_clear(hsotg, GRSTCTL, GRSTCTL_TXFFLSH, 100))
		dev_warn(hsotg->dev, "%s: timeout flushing fifo GRSTCTL_TXFFLSH\n",
			 __func__);
}

/**
 * dwc2_hsotg_trytx - check to see if anything needs transmitting
 * @hsotg: The driver state
 * @hs_ep: The driver endpoint to check.
 *
 * Check to see if there is a request that has data to send, and if so
 * make an attempt to write data into the FIFO.
 */
static int dwc2_hsotg_trytx(struct dwc2_hsotg *hsotg,
			    struct dwc2_hsotg_ep *hs_ep)
{
	struct dwc2_hsotg_req *hs_req = hs_ep->req;

	if (!hs_ep->dir_in || !hs_req) {
		/**
		 * if request is not enqueued, we disable interrupts
		 * for endpoints, excepting ep0
		 */
		if (hs_ep->index != 0)
			dwc2_hsotg_ctrl_epint(hsotg, hs_ep->index,
					      hs_ep->dir_in, 0);
		return 0;
	}

	if (hs_req->req.actual < hs_req->req.length) {
		dev_dbg(hsotg->dev, "trying to write more for ep%d\n",
			hs_ep->index);
		return dwc2_hsotg_write_fifo(hsotg, hs_ep, hs_req);
	}

	return 0;
}

/**
 * dwc2_hsotg_complete_in - complete IN transfer
 * @hsotg: The device state.
 * @hs_ep: The endpoint that has just completed.
 *
 * An IN transfer has been completed, update the transfer's state and then
 * call the relevant completion routines.
 */
static void dwc2_hsotg_complete_in(struct dwc2_hsotg *hsotg,
				   struct dwc2_hsotg_ep *hs_ep)
{
	struct dwc2_hsotg_req *hs_req = hs_ep->req;
	u32 epsize = dwc2_readl(hsotg, DIEPTSIZ(hs_ep->index));
	int size_left, size_done;

	if (!hs_req) {
		dev_dbg(hsotg->dev, "XferCompl but no req\n");
		return;
	}

	/* Finish ZLP handling for IN EP0 transactions */
	if (hs_ep->index == 0 && hsotg->ep0_state == DWC2_EP0_STATUS_IN) {
		dev_dbg(hsotg->dev, "zlp packet sent\n");

		/*
		 * While send zlp for DWC2_EP0_STATUS_IN EP direction was
		 * changed to IN. Change back to complete OUT transfer request
		 */
		hs_ep->dir_in = 0;

		dwc2_hsotg_complete_request(hsotg, hs_ep, hs_req, 0);
		if (hsotg->test_mode) {
			int ret;

			ret = dwc2_hsotg_set_test_mode(hsotg, hsotg->test_mode);
			if (ret < 0) {
				dev_dbg(hsotg->dev, "Invalid Test #%d\n",
					hsotg->test_mode);
				dwc2_hsotg_stall_ep0(hsotg);
				return;
			}
		}
		dwc2_hsotg_enqueue_setup(hsotg);
		return;
	}

	/*
	 * Calculate the size of the transfer by checking how much is left
	 * in the endpoint size register and then working it out from
	 * the amount we loaded for the transfer.
	 *
	 * We do this even for DMA, as the transfer may have incremented
	 * past the end of the buffer (DMA transfers are always 32bit
	 * aligned).
	 */
	if (using_desc_dma(hsotg)) {
		size_left = dwc2_gadget_get_xfersize_ddma(hs_ep);
		if (size_left < 0)
			dev_err(hsotg->dev, "error parsing DDMA results %d\n",
				size_left);
	} else {
		size_left = DXEPTSIZ_XFERSIZE_GET(epsize);
	}

	size_done = hs_ep->size_loaded - size_left;
	size_done += hs_ep->last_load;

	if (hs_req->req.actual != size_done)
		dev_dbg(hsotg->dev, "%s: adjusting size done %d => %d\n",
			__func__, hs_req->req.actual, size_done);

	hs_req->req.actual = size_done;
	dev_dbg(hsotg->dev, "req->length:%d req->actual:%d req->zero:%d\n",
		hs_req->req.length, hs_req->req.actual, hs_req->req.zero);

	if (!size_left && hs_req->req.actual < hs_req->req.length) {
		dev_dbg(hsotg->dev, "%s trying more for req...\n", __func__);
		dwc2_hsotg_start_req(hsotg, hs_ep, hs_req, true);
		return;
	}

	/* Zlp for all endpoints in non DDMA, for ep0 only in DATA IN stage */
	if (hs_ep->send_zlp) {
		hs_ep->send_zlp = 0;
		if (!using_desc_dma(hsotg)) {
			dwc2_hsotg_program_zlp(hsotg, hs_ep);
			/* transfer will be completed on next complete interrupt */
			return;
		}
	}

	if (hs_ep->index == 0 && hsotg->ep0_state == DWC2_EP0_DATA_IN) {
		/* Move to STATUS OUT */
		dwc2_hsotg_ep0_zlp(hsotg, false);
		return;
	}

	/* Set actual frame number for completed transfers */
	if (!using_desc_dma(hsotg) && hs_ep->isochronous) {
		hs_req->req.frame_number = hs_ep->target_frame;
		dwc2_gadget_incr_frame_num(hs_ep);
	}

	dwc2_hsotg_complete_request(hsotg, hs_ep, hs_req, 0);
}

/**
 * dwc2_gadget_read_ep_interrupts - reads interrupts for given ep
 * @hsotg: The device state.
 * @idx: Index of ep.
 * @dir_in: Endpoint direction 1-in 0-out.
 *
 * Reads for endpoint with given index and direction, by masking
 * epint_reg with coresponding mask.
 */
static u32 dwc2_gadget_read_ep_interrupts(struct dwc2_hsotg *hsotg,
					  unsigned int idx, int dir_in)
{
	u32 epmsk_reg = dir_in ? DIEPMSK : DOEPMSK;
	u32 epint_reg = dir_in ? DIEPINT(idx) : DOEPINT(idx);
	u32 ints;
	u32 mask;
	u32 diepempmsk;

	mask = dwc2_readl(hsotg, epmsk_reg);
	diepempmsk = dwc2_readl(hsotg, DIEPEMPMSK);
	mask |= ((diepempmsk >> idx) & 0x1) ? DIEPMSK_TXFIFOEMPTY : 0;
	mask |= DXEPINT_SETUP_RCVD;

	ints = dwc2_readl(hsotg, epint_reg);
	ints &= mask;
	return ints;
}

/**
 * dwc2_gadget_handle_ep_disabled - handle DXEPINT_EPDISBLD
 * @hs_ep: The endpoint on which interrupt is asserted.
 *
 * This interrupt indicates that the endpoint has been disabled per the
 * application's request.
 *
 * For IN endpoints flushes txfifo, in case of BULK clears DCTL_CGNPINNAK,
 * in case of ISOC completes current request.
 *
 * For ISOC-OUT endpoints completes expired requests. If there is remaining
 * request starts it.
 */
static void dwc2_gadget_handle_ep_disabled(struct dwc2_hsotg_ep *hs_ep)
{
	struct dwc2_hsotg *hsotg = hs_ep->parent;
	struct dwc2_hsotg_req *hs_req;
	unsigned char idx = hs_ep->index;
	int dir_in = hs_ep->dir_in;
	u32 epctl_reg = dir_in ? DIEPCTL(idx) : DOEPCTL(idx);
	int dctl = dwc2_readl(hsotg, DCTL);

	dev_dbg(hsotg->dev, "%s: EPDisbld\n", __func__);

	if (dir_in) {
		int epctl = dwc2_readl(hsotg, epctl_reg);

		dwc2_hsotg_txfifo_flush(hsotg, hs_ep->fifo_index);

		if ((epctl & DXEPCTL_STALL) && (epctl & DXEPCTL_EPTYPE_BULK)) {
			int dctl = dwc2_readl(hsotg, DCTL);

			dctl |= DCTL_CGNPINNAK;
			dwc2_writel(hsotg, dctl, DCTL);
		}
	} else {

		if (dctl & DCTL_GOUTNAKSTS) {
			dctl |= DCTL_CGOUTNAK;
			dwc2_writel(hsotg, dctl, DCTL);
		}
	}

	if (!hs_ep->isochronous)
		return;

	if (list_empty(&hs_ep->queue)) {
		dev_dbg(hsotg->dev, "%s: complete_ep 0x%p, ep->queue empty!\n",
			__func__, hs_ep);
		return;
	}

	do {
		hs_req = get_ep_head(hs_ep);
		if (hs_req) {
			hs_req->req.frame_number = hs_ep->target_frame;
			hs_req->req.actual = 0;
			dwc2_hsotg_complete_request(hsotg, hs_ep, hs_req,
						    -ENODATA);
		}
		dwc2_gadget_incr_frame_num(hs_ep);
		/* Update current frame number value. */
		hsotg->frame_number = dwc2_hsotg_read_frameno(hsotg);
	} while (dwc2_gadget_target_frame_elapsed(hs_ep));
}

/**
 * dwc2_gadget_handle_out_token_ep_disabled - handle DXEPINT_OUTTKNEPDIS
 * @ep: The endpoint on which interrupt is asserted.
 *
 * This is starting point for ISOC-OUT transfer, synchronization done with
 * first out token received from host while corresponding EP is disabled.
 *
 * Device does not know initial frame in which out token will come. For this
 * HW generates OUTTKNEPDIS - out token is received while EP is disabled. Upon
 * getting this interrupt SW starts calculation for next transfer frame.
 */
static void dwc2_gadget_handle_out_token_ep_disabled(struct dwc2_hsotg_ep *ep)
{
	struct dwc2_hsotg *hsotg = ep->parent;
	struct dwc2_hsotg_req *hs_req;
	int dir_in = ep->dir_in;

	if (dir_in || !ep->isochronous)
		return;

	if (using_desc_dma(hsotg)) {
		if (ep->target_frame == TARGET_FRAME_INITIAL) {
			/* Start first ISO Out */
			ep->target_frame = hsotg->frame_number;
			dwc2_gadget_start_isoc_ddma(ep);
		}
		return;
	}

	if (ep->target_frame == TARGET_FRAME_INITIAL) {
		u32 ctrl;

		ep->target_frame = hsotg->frame_number;
		if (ep->interval > 1) {
			ctrl = dwc2_readl(hsotg, DOEPCTL(ep->index));
			if (ep->target_frame & 0x1)
				ctrl |= DXEPCTL_SETODDFR;
			else
				ctrl |= DXEPCTL_SETEVENFR;

			dwc2_writel(hsotg, ctrl, DOEPCTL(ep->index));
		}
	}

	while (dwc2_gadget_target_frame_elapsed(ep)) {
		hs_req = get_ep_head(ep);
		if (hs_req) {
			hs_req->req.frame_number = ep->target_frame;
			hs_req->req.actual = 0;
			dwc2_hsotg_complete_request(hsotg, ep, hs_req, -ENODATA);
		}

		dwc2_gadget_incr_frame_num(ep);
		/* Update current frame number value. */
		hsotg->frame_number = dwc2_hsotg_read_frameno(hsotg);
	}

	if (!ep->req)
		dwc2_gadget_start_next_request(ep);

}

static void dwc2_hsotg_ep_stop_xfr(struct dwc2_hsotg *hsotg,
				   struct dwc2_hsotg_ep *hs_ep);

/**
 * dwc2_gadget_handle_nak - handle NAK interrupt
 * @hs_ep: The endpoint on which interrupt is asserted.
 *
 * This is starting point for ISOC-IN transfer, synchronization done with
 * first IN token received from host while corresponding EP is disabled.
 *
 * Device does not know when first one token will arrive from host. On first
 * token arrival HW generates 2 interrupts: 'in token received while FIFO empty'
 * and 'NAK'. NAK interrupt for ISOC-IN means that token has arrived and ZLP was
 * sent in response to that as there was no data in FIFO. SW is basing on this
 * interrupt to obtain frame in which token has come and then based on the
 * interval calculates next frame for transfer.
 */
static void dwc2_gadget_handle_nak(struct dwc2_hsotg_ep *hs_ep)
{
	struct dwc2_hsotg *hsotg = hs_ep->parent;
	struct dwc2_hsotg_req *hs_req;
	int dir_in = hs_ep->dir_in;
	u32 ctrl;

	if (!dir_in || !hs_ep->isochronous)
		return;

	if (hs_ep->target_frame == TARGET_FRAME_INITIAL) {

		if (using_desc_dma(hsotg)) {
			hs_ep->target_frame = hsotg->frame_number;
			dwc2_gadget_incr_frame_num(hs_ep);

			/* In service interval mode target_frame must
			 * be set to last (u)frame of the service interval.
			 */
			if (hsotg->params.service_interval) {
				/* Set target_frame to the first (u)frame of
				 * the service interval
				 */
				hs_ep->target_frame &= ~hs_ep->interval + 1;

				/* Set target_frame to the last (u)frame of
				 * the service interval
				 */
				dwc2_gadget_incr_frame_num(hs_ep);
				dwc2_gadget_dec_frame_num_by_one(hs_ep);
			}

			dwc2_gadget_start_isoc_ddma(hs_ep);
			return;
		}

		hs_ep->target_frame = hsotg->frame_number;
		if (hs_ep->interval > 1) {
			u32 ctrl = dwc2_readl(hsotg,
					      DIEPCTL(hs_ep->index));
			if (hs_ep->target_frame & 0x1)
				ctrl |= DXEPCTL_SETODDFR;
			else
				ctrl |= DXEPCTL_SETEVENFR;

			dwc2_writel(hsotg, ctrl, DIEPCTL(hs_ep->index));
		}
	}

	if (using_desc_dma(hsotg))
		return;

	ctrl = dwc2_readl(hsotg, DIEPCTL(hs_ep->index));
	if (ctrl & DXEPCTL_EPENA)
		dwc2_hsotg_ep_stop_xfr(hsotg, hs_ep);
	else
		dwc2_hsotg_txfifo_flush(hsotg, hs_ep->fifo_index);

	while (dwc2_gadget_target_frame_elapsed(hs_ep)) {
		hs_req = get_ep_head(hs_ep);
		if (hs_req) {
			hs_req->req.frame_number = hs_ep->target_frame;
			hs_req->req.actual = 0;
			dwc2_hsotg_complete_request(hsotg, hs_ep, hs_req, -ENODATA);
		}

		dwc2_gadget_incr_frame_num(hs_ep);
		/* Update current frame number value. */
		hsotg->frame_number = dwc2_hsotg_read_frameno(hsotg);
	}

	if (!hs_ep->req)
		dwc2_gadget_start_next_request(hs_ep);
}

/**
 * dwc2_hsotg_epint - handle an in/out endpoint interrupt
 * @hsotg: The driver state
 * @idx: The index for the endpoint (0..15)
 * @dir_in: Set if this is an IN endpoint
 *
 * Process and clear any interrupt pending for an individual endpoint
 */
static void dwc2_hsotg_epint(struct dwc2_hsotg *hsotg, unsigned int idx,
			     int dir_in)
{
	struct dwc2_hsotg_ep *hs_ep = index_to_ep(hsotg, idx, dir_in);
	u32 epint_reg = dir_in ? DIEPINT(idx) : DOEPINT(idx);
	u32 epctl_reg = dir_in ? DIEPCTL(idx) : DOEPCTL(idx);
	u32 epsiz_reg = dir_in ? DIEPTSIZ(idx) : DOEPTSIZ(idx);
	u32 ints;

	ints = dwc2_gadget_read_ep_interrupts(hsotg, idx, dir_in);

	/* Clear endpoint interrupts */
	dwc2_writel(hsotg, ints, epint_reg);

	if (!hs_ep) {
		dev_err(hsotg->dev, "%s:Interrupt for unconfigured ep%d(%s)\n",
			__func__, idx, dir_in ? "in" : "out");
		return;
	}

	dev_dbg(hsotg->dev, "%s: ep%d(%s) DxEPINT=0x%08x\n",
		__func__, idx, dir_in ? "in" : "out", ints);

	/* Don't process XferCompl interrupt if it is a setup packet */
	if (idx == 0 && (ints & (DXEPINT_SETUP | DXEPINT_SETUP_RCVD)))
		ints &= ~DXEPINT_XFERCOMPL;

	/*
	 * Don't process XferCompl interrupt in DDMA if EP0 is still in SETUP
	 * stage and xfercomplete was generated without SETUP phase done
	 * interrupt. SW should parse received setup packet only after host's
	 * exit from setup phase of control transfer.
	 */
	if (using_desc_dma(hsotg) && idx == 0 && !hs_ep->dir_in &&
	    hsotg->ep0_state == DWC2_EP0_SETUP && !(ints & DXEPINT_SETUP))
		ints &= ~DXEPINT_XFERCOMPL;

	if (ints & DXEPINT_XFERCOMPL) {
		dev_dbg(hsotg->dev,
			"%s: XferCompl: DxEPCTL=0x%08x, DXEPTSIZ=%08x\n",
			__func__, dwc2_readl(hsotg, epctl_reg),
			dwc2_readl(hsotg, epsiz_reg));

		/* In DDMA handle isochronous requests separately */
		if (using_desc_dma(hsotg) && hs_ep->isochronous) {
			dwc2_gadget_complete_isoc_request_ddma(hs_ep);
		} else if (dir_in) {
			/*
			 * We get OutDone from the FIFO, so we only
			 * need to look at completing IN requests here
			 * if operating slave mode
			 */
			if (!hs_ep->isochronous || !(ints & DXEPINT_NAKINTRPT))
				dwc2_hsotg_complete_in(hsotg, hs_ep);

			if (idx == 0 && !hs_ep->req)
				dwc2_hsotg_enqueue_setup(hsotg);
		} else if (using_dma(hsotg)) {
			/*
			 * We're using DMA, we need to fire an OutDone here
			 * as we ignore the RXFIFO.
			 */
			if (!hs_ep->isochronous || !(ints & DXEPINT_OUTTKNEPDIS))
				dwc2_hsotg_handle_outdone(hsotg, idx);
		}
	}

	if (ints & DXEPINT_EPDISBLD)
		dwc2_gadget_handle_ep_disabled(hs_ep);

	if (ints & DXEPINT_OUTTKNEPDIS)
		dwc2_gadget_handle_out_token_ep_disabled(hs_ep);

	if (ints & DXEPINT_NAKINTRPT)
		dwc2_gadget_handle_nak(hs_ep);

	if (ints & DXEPINT_AHBERR)
		dev_dbg(hsotg->dev, "%s: AHBErr\n", __func__);

	if (ints & DXEPINT_SETUP) {  /* Setup or Timeout */
		dev_dbg(hsotg->dev, "%s: Setup/Timeout\n",  __func__);

		if (using_dma(hsotg) && idx == 0) {
			/*
			 * this is the notification we've received a
			 * setup packet. In non-DMA mode we'd get this
			 * from the RXFIFO, instead we need to process
			 * the setup here.
			 */

			if (dir_in)
				WARN_ON_ONCE(1);
			else
				dwc2_hsotg_handle_outdone(hsotg, 0);
		}
	}

	if (ints & DXEPINT_STSPHSERCVD) {
		dev_dbg(hsotg->dev, "%s: StsPhseRcvd\n", __func__);

		/* Safety check EP0 state when STSPHSERCVD asserted */
		if (hsotg->ep0_state == DWC2_EP0_DATA_OUT) {
			/* Move to STATUS IN for DDMA */
			if (using_desc_dma(hsotg)) {
				if (!hsotg->delayed_status)
					dwc2_hsotg_ep0_zlp(hsotg, true);
				else
				/* In case of 3 stage Control Write with delayed
				 * status, when Status IN transfer started
				 * before STSPHSERCVD asserted, NAKSTS bit not
				 * cleared by CNAK in dwc2_hsotg_start_req()
				 * function. Clear now NAKSTS to allow complete
				 * transfer.
				 */
					dwc2_set_bit(hsotg, DIEPCTL(0),
						     DXEPCTL_CNAK);
			}
		}

	}

	if (ints & DXEPINT_BACK2BACKSETUP)
		dev_dbg(hsotg->dev, "%s: B2BSetup/INEPNakEff\n", __func__);

	if (ints & DXEPINT_BNAINTR) {
		dev_dbg(hsotg->dev, "%s: BNA interrupt\n", __func__);
		if (hs_ep->isochronous)
			dwc2_gadget_handle_isoc_bna(hs_ep);
	}

	if (dir_in && !hs_ep->isochronous) {
		/* not sure if this is important, but we'll clear it anyway */
		if (ints & DXEPINT_INTKNTXFEMP) {
			dev_dbg(hsotg->dev, "%s: ep%d: INTknTXFEmpMsk\n",
				__func__, idx);
		}

		/* this probably means something bad is happening */
		if (ints & DXEPINT_INTKNEPMIS) {
			dev_warn(hsotg->dev, "%s: ep%d: INTknEP\n",
				 __func__, idx);
		}

		/* FIFO has space or is empty (see GAHBCFG) */
		if (hsotg->dedicated_fifos &&
		    ints & DXEPINT_TXFEMP) {
			dev_dbg(hsotg->dev, "%s: ep%d: TxFIFOEmpty\n",
				__func__, idx);
			if (!using_dma(hsotg))
				dwc2_hsotg_trytx(hsotg, hs_ep);
		}
	}
}

/**
 * dwc2_hsotg_irq_enumdone - Handle EnumDone interrupt (enumeration done)
 * @hsotg: The device state.
 *
 * Handle updating the device settings after the enumeration phase has
 * been completed.
 */
static void dwc2_hsotg_irq_enumdone(struct dwc2_hsotg *hsotg)
{
	u32 dsts = dwc2_readl(hsotg, DSTS);
	int ep0_mps = 0, ep_mps = 8;

	/*
	 * This should signal the finish of the enumeration phase
	 * of the USB handshaking, so we should now know what rate
	 * we connected at.
	 */

	dev_dbg(hsotg->dev, "EnumDone (DSTS=0x%08x)\n", dsts);

	/*
	 * note, since we're limited by the size of transfer on EP0, and
	 * it seems IN transfers must be a even number of packets we do
	 * not advertise a 64byte MPS on EP0.
	 */

	/* catch both EnumSpd_FS and EnumSpd_FS48 */
	switch ((dsts & DSTS_ENUMSPD_MASK) >> DSTS_ENUMSPD_SHIFT) {
	case DSTS_ENUMSPD_FS:
	case DSTS_ENUMSPD_FS48:
		hsotg->gadget.speed = USB_SPEED_FULL;
		ep0_mps = EP0_MPS_LIMIT;
		ep_mps = 1023;
		break;

	case DSTS_ENUMSPD_HS:
		hsotg->gadget.speed = USB_SPEED_HIGH;
		ep0_mps = EP0_MPS_LIMIT;
		ep_mps = 1024;
		break;

	case DSTS_ENUMSPD_LS:
		hsotg->gadget.speed = USB_SPEED_LOW;
		ep0_mps = 8;
		ep_mps = 8;
		/*
		 * note, we don't actually support LS in this driver at the
		 * moment, and the documentation seems to imply that it isn't
		 * supported by the PHYs on some of the devices.
		 */
		break;
	}
	dev_info(hsotg->dev, "new device is %s\n",
		 usb_speed_string(hsotg->gadget.speed));

	/*
