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
