// SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause)
/*
 * hcd.c - DesignWare HS OTG Controller host-mode routines
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
 * This file contains the core HCD code, and implements the Linux hc_driver
 * API
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/usb.h>

#include <linux/usb/hcd.h>
#include <linux/usb/ch11.h>

#include "core.h"
#include "hcd.h"

static void dwc2_port_resume(struct dwc2_hsotg *hsotg);

/*
 * =========================================================================
 *  Host Core Layer Functions
 * =========================================================================
 */

/**
 * dwc2_enable_common_interrupts() - Initializes the commmon interrupts,
 * used in both device and host modes
 *
 * @hsotg: Programming view of the DWC_otg controller
 */
static void dwc2_enable_common_interrupts(struct dwc2_hsotg *hsotg)
{
	u32 intmsk;

	/* Clear any pending OTG Interrupts */
	dwc2_writel(hsotg, 0xffffffff, GOTGINT);

	/* Clear any pending interrupts */
	dwc2_writel(hsotg, 0xffffffff, GINTSTS);

	/* Enable the interrupts in the GINTMSK */
	intmsk = GINTSTS_MODEMIS | GINTSTS_OTGINT;

	if (!hsotg->params.host_dma)
		intmsk |= GINTSTS_RXFLVL;
	if (!hsotg->params.external_id_pin_ctl)
		intmsk |= GINTSTS_CONIDSTSCHNG;

	intmsk |= GINTSTS_WKUPINT | GINTSTS_USBSUSP |
		  GINTSTS_SESSREQINT;

	if (dwc2_is_device_mode(hsotg) && hsotg->params.lpm)
		intmsk |= GINTSTS_LPMTRANRCVD;

	dwc2_writel(hsotg, intmsk, GINTMSK);
}

static int dwc2_gahbcfg_init(struct dwc2_hsotg *hsotg)
{
	u32 ahbcfg = dwc2_readl(hsotg, GAHBCFG);

	switch (hsotg->hw_params.arch) {
	case GHWCFG2_EXT_DMA_ARCH:
		dev_err(hsotg->dev, "External DMA Mode not supported\n");
		return -EINVAL;

	case GHWCFG2_INT_DMA_ARCH:
		dev_dbg(hsotg->dev, "Internal DMA Mode\n");
		if (hsotg->params.ahbcfg != -1) {
			ahbcfg &= GAHBCFG_CTRL_MASK;
			ahbcfg |= hsotg->params.ahbcfg &
				  ~GAHBCFG_CTRL_MASK;
		}
		break;

	case GHWCFG2_SLAVE_ONLY_ARCH:
	default:
		dev_dbg(hsotg->dev, "Slave Only Mode\n");
		break;
	}

	if (hsotg->params.host_dma)
		ahbcfg |= GAHBCFG_DMA_EN;
	else
		hsotg->params.dma_desc_enable = false;

	dwc2_writel(hsotg, ahbcfg, GAHBCFG);

	return 0;
}

static void dwc2_gusbcfg_init(struct dwc2_hsotg *hsotg)
{
	u32 usbcfg;

	usbcfg = dwc2_readl(hsotg, GUSBCFG);
	usbcfg &= ~(GUSBCFG_HNPCAP | GUSBCFG_SRPCAP);

	switch (hsotg->hw_params.op_mode) {
	case GHWCFG2_OP_MODE_HNP_SRP_CAPABLE:
		if (hsotg->params.otg_cap ==
				DWC2_CAP_PARAM_HNP_SRP_CAPABLE)
			usbcfg |= GUSBCFG_HNPCAP;
		if (hsotg->params.otg_cap !=
				DWC2_CAP_PARAM_NO_HNP_SRP_CAPABLE)
			usbcfg |= GUSBCFG_SRPCAP;
		break;

	case GHWCFG2_OP_MODE_SRP_ONLY_CAPABLE:
	case GHWCFG2_OP_MODE_SRP_CAPABLE_DEVICE:
	case GHWCFG2_OP_MODE_SRP_CAPABLE_HOST:
		if (hsotg->params.otg_cap !=
				DWC2_CAP_PARAM_NO_HNP_SRP_CAPABLE)
			usbcfg |= GUSBCFG_SRPCAP;
		break;

	case GHWCFG2_OP_MODE_NO_HNP_SRP_CAPABLE:
	case GHWCFG2_OP_MODE_NO_SRP_CAPABLE_DEVICE:
	case GHWCFG2_OP_MODE_NO_SRP_CAPABLE_HOST:
	default:
		break;
	}

	dwc2_writel(hsotg, usbcfg, GUSBCFG);
}

static int dwc2_vbus_supply_init(struct dwc2_hsotg *hsotg)
{
	if (hsotg->vbus_supply)
		return regulator_enable(hsotg->vbus_supply);

	return 0;
}

static int dwc2_vbus_supply_exit(struct dwc2_hsotg *hsotg)
{
	if (hsotg->vbus_supply)
		return regulator_disable(hsotg->vbus_supply);

	return 0;
}

/**
 * dwc2_enable_host_interrupts() - Enables the Host mode interrupts
 *
 * @hsotg: Programming view of DWC_otg controller
 */
static void dwc2_enable_host_interrupts(struct dwc2_hsotg *hsotg)
{
	u32 intmsk;

	dev_dbg(hsotg->dev, "%s()\n", __func__);

	/* Disable all interrupts */
	dwc2_writel(hsotg, 0, GINTMSK);
	dwc2_writel(hsotg, 0, HAINTMSK);

	/* Enable the common interrupts */
	dwc2_enable_common_interrupts(hsotg);

	/* Enable host mode interrupts without disturbing common interrupts */
	intmsk = dwc2_readl(hsotg, GINTMSK);
	intmsk |= GINTSTS_DISCONNINT | GINTSTS_PRTINT | GINTSTS_HCHINT;
	dwc2_writel(hsotg, intmsk, GINTMSK);
}

/**
 * dwc2_disable_host_interrupts() - Disables the Host Mode interrupts
 *
 * @hsotg: Programming view of DWC_otg controller
 */
static void dwc2_disable_host_interrupts(struct dwc2_hsotg *hsotg)
{
	u32 intmsk = dwc2_readl(hsotg, GINTMSK);

	/* Disable host mode interrupts without disturbing common interrupts */
	intmsk &= ~(GINTSTS_SOF | GINTSTS_PRTINT | GINTSTS_HCHINT |
		    GINTSTS_PTXFEMP | GINTSTS_NPTXFEMP | GINTSTS_DISCONNINT);
	dwc2_writel(hsotg, intmsk, GINTMSK);
}

/*
 * dwc2_calculate_dynamic_fifo() - Calculates the default fifo size
 * For system that have a total fifo depth that is smaller than the default
 * RX + TX fifo size.
 *
 * @hsotg: Programming view of DWC_otg controller
 */
static void dwc2_calculate_dynamic_fifo(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *params = &hsotg->params;
	struct dwc2_hw_params *hw = &hsotg->hw_params;
	u32 rxfsiz, nptxfsiz, ptxfsiz, total_fifo_size;

	total_fifo_size = hw->total_fifo_size;
	rxfsiz = params->host_rx_fifo_size;
	nptxfsiz = params->host_nperio_tx_fifo_size;
	ptxfsiz = params->host_perio_tx_fifo_size;

	/*
	 * Will use Method 2 defined in the DWC2 spec: minimum FIFO depth
	 * allocation with support for high bandwidth endpoints. Synopsys
	 * defines MPS(Max Packet size) for a periodic EP=1024, and for
	 * non-periodic as 512.
	 */
	if (total_fifo_size < (rxfsiz + nptxfsiz + ptxfsiz)) {
		/*
		 * For Buffer DMA mode/Scatter Gather DMA mode
		 * 2 * ((Largest Packet size / 4) + 1 + 1) + n
		 * with n = number of host channel.
		 * 2 * ((1024/4) + 2) = 516
		 */
		rxfsiz = 516 + hw->host_channels;

		/*
		 * min non-periodic tx fifo depth
		 * 2 * (largest non-periodic USB packet used / 4)
		 * 2 * (512/4) = 256
		 */
		nptxfsiz = 256;

		/*
		 * min periodic tx fifo depth
		 * (largest packet size*MC)/4
		 * (1024 * 3)/4 = 768
		 */
		ptxfsiz = 768;

		params->host_rx_fifo_size = rxfsiz;
		params->host_nperio_tx_fifo_size = nptxfsiz;
		params->host_perio_tx_fifo_size = ptxfsiz;
	}

	/*
	 * If the summation of RX, NPTX and PTX fifo sizes is still
	 * bigger than the total_fifo_size, then we have a problem.
	 *
	 * We won't be able to allocate as many endpoints. Right now,
	 * we're just printing an error message, but ideally this FIFO
	 * allocation algorithm would be improved in the future.
	 *
	 * FIXME improve this FIFO allocation algorithm.
	 */
	if (unlikely(total_fifo_size < (rxfsiz + nptxfsiz + ptxfsiz)))
		dev_err(hsotg->dev, "invalid fifo sizes\n");
}

static void dwc2_config_fifos(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *params = &hsotg->params;
	u32 nptxfsiz, hptxfsiz, dfifocfg, grxfsiz;

	if (!params->enable_dynamic_fifo)
		return;

	dwc2_calculate_dynamic_fifo(hsotg);

	/* Rx FIFO */
	grxfsiz = dwc2_readl(hsotg, GRXFSIZ);
	dev_dbg(hsotg->dev, "initial grxfsiz=%08x\n", grxfsiz);
	grxfsiz &= ~GRXFSIZ_DEPTH_MASK;
	grxfsiz |= params->host_rx_fifo_size <<
		   GRXFSIZ_DEPTH_SHIFT & GRXFSIZ_DEPTH_MASK;
	dwc2_writel(hsotg, grxfsiz, GRXFSIZ);
	dev_dbg(hsotg->dev, "new grxfsiz=%08x\n",
		dwc2_readl(hsotg, GRXFSIZ));

	/* Non-periodic Tx FIFO */
	dev_dbg(hsotg->dev, "initial gnptxfsiz=%08x\n",
		dwc2_readl(hsotg, GNPTXFSIZ));
	nptxfsiz = params->host_nperio_tx_fifo_size <<
		   FIFOSIZE_DEPTH_SHIFT & FIFOSIZE_DEPTH_MASK;
	nptxfsiz |= params->host_rx_fifo_size <<
		    FIFOSIZE_STARTADDR_SHIFT & FIFOSIZE_STARTADDR_MASK;
	dwc2_writel(hsotg, nptxfsiz, GNPTXFSIZ);
	dev_dbg(hsotg->dev, "new gnptxfsiz=%08x\n",
		dwc2_readl(hsotg, GNPTXFSIZ));

	/* Periodic Tx FIFO */
	dev_dbg(hsotg->dev, "initial hptxfsiz=%08x\n",
		dwc2_readl(hsotg, HPTXFSIZ));
	hptxfsiz = params->host_perio_tx_fifo_size <<
		   FIFOSIZE_DEPTH_SHIFT & FIFOSIZE_DEPTH_MASK;
	hptxfsiz |= (params->host_rx_fifo_size +
		     params->host_nperio_tx_fifo_size) <<
		    FIFOSIZE_STARTADDR_SHIFT & FIFOSIZE_STARTADDR_MASK;
	dwc2_writel(hsotg, hptxfsiz, HPTXFSIZ);
	dev_dbg(hsotg->dev, "new hptxfsiz=%08x\n",
		dwc2_readl(hsotg, HPTXFSIZ));

	if (hsotg->params.en_multiple_tx_fifo &&
	    hsotg->hw_params.snpsid >= DWC2_CORE_REV_2_91a) {
		/*
		 * This feature was implemented in 2.91a version
		 * Global DFIFOCFG calculation for Host mode -
		 * include RxFIFO, NPTXFIFO and HPTXFIFO
		 */
		dfifocfg = dwc2_readl(hsotg, GDFIFOCFG);
		dfifocfg &= ~GDFIFOCFG_EPINFOBASE_MASK;
		dfifocfg |= (params->host_rx_fifo_size +
			     params->host_nperio_tx_fifo_size +
			     params->host_perio_tx_fifo_size) <<
			    GDFIFOCFG_EPINFOBASE_SHIFT &
			    GDFIFOCFG_EPINFOBASE_MASK;
		dwc2_writel(hsotg, dfifocfg, GDFIFOCFG);
	}
}

/**
 * dwc2_calc_frame_interval() - Calculates the correct frame Interval value for
 * the HFIR register according to PHY type and speed
 *
 * @hsotg: Programming view of DWC_otg controller
 *
 * NOTE: The caller can modify the value of the HFIR register only after the
 * Port Enable bit of the Host Port Control and Status register (HPRT.EnaPort)
 * has been set
 */
u32 dwc2_calc_frame_interval(struct dwc2_hsotg *hsotg)
{
	u32 usbcfg;
	u32 hprt0;
	int clock = 60;	/* default value */

	usbcfg = dwc2_readl(hsotg, GUSBCFG);
	hprt0 = dwc2_readl(hsotg, HPRT0);

	if (!(usbcfg & GUSBCFG_PHYSEL) && (usbcfg & GUSBCFG_ULPI_UTMI_SEL) &&
	    !(usbcfg & GUSBCFG_PHYIF16))
		clock = 60;
	if ((usbcfg & GUSBCFG_PHYSEL) && hsotg->hw_params.fs_phy_type ==
	    GHWCFG2_FS_PHY_TYPE_SHARED_ULPI)
		clock = 48;
	if (!(usbcfg & GUSBCFG_PHY_LP_CLK_SEL) && !(usbcfg & GUSBCFG_PHYSEL) &&
	    !(usbcfg & GUSBCFG_ULPI_UTMI_SEL) && (usbcfg & GUSBCFG_PHYIF16))
		clock = 30;
	if (!(usbcfg & GUSBCFG_PHY_LP_CLK_SEL) && !(usbcfg & GUSBCFG_PHYSEL) &&
	    !(usbcfg & GUSBCFG_ULPI_UTMI_SEL) && !(usbcfg & GUSBCFG_PHYIF16))
		clock = 60;
	if ((usbcfg & GUSBCFG_PHY_LP_CLK_SEL) && !(usbcfg & GUSBCFG_PHYSEL) &&
	    !(usbcfg & GUSBCFG_ULPI_UTMI_SEL) && (usbcfg & GUSBCFG_PHYIF16))
		clock = 48;
	if ((usbcfg & GUSBCFG_PHYSEL) && !(usbcfg & GUSBCFG_PHYIF16) &&
	    hsotg->hw_params.fs_phy_type == GHWCFG2_FS_PHY_TYPE_SHARED_UTMI)
		clock = 48;
	if ((usbcfg & GUSBCFG_PHYSEL) &&
	    hsotg->hw_params.fs_phy_type == GHWCFG2_FS_PHY_TYPE_DEDICATED)
		clock = 48;

	if ((hprt0 & HPRT0_SPD_MASK) >> HPRT0_SPD_SHIFT == HPRT0_SPD_HIGH_SPEED)
		/* High speed case */
		return 125 * clock - 1;

	/* FS/LS case */
	return 1000 * clock - 1;
}

/**
 * dwc2_read_packet() - Reads a packet from the Rx FIFO into the destination
 * buffer
 *
 * @hsotg: Programming view of DWC_otg controller
 * @dest:    Destination buffer for the packet
 * @bytes:   Number of bytes to copy to the destination
 */
void dwc2_read_packet(struct dwc2_hsotg *hsotg, u8 *dest, u16 bytes)
{
	u32 *data_buf = (u32 *)dest;
	int word_count = (bytes + 3) / 4;
	int i;

	/*
	 * Todo: Account for the case where dest is not dword aligned. This
	 * requires reading data from the FIFO into a u32 temp buffer, then
	 * moving it into the data buffer.
	 */

	dev_vdbg(hsotg->dev, "%s(%p,%p,%d)\n", __func__, hsotg, dest, bytes);

	for (i = 0; i < word_count; i++, data_buf++)
		*data_buf = dwc2_readl(hsotg, HCFIFO(0));
}

/**
 * dwc2_dump_channel_info() - Prints the state of a host channel
 *
 * @hsotg: Programming view of DWC_otg controller
 * @chan:  Pointer to the channel to dump
 *
 * Must be called with interrupt disabled and spinlock held
 *
 * NOTE: This function will be removed once the peripheral controller code
 * is integrated and the driver is stable
 */
static void dwc2_dump_channel_info(struct dwc2_hsotg *hsotg,
				   struct dwc2_host_chan *chan)
{
#ifdef VERBOSE_DEBUG
	int num_channels = hsotg->params.host_channels;
	struct dwc2_qh *qh;
	u32 hcchar;
	u32 hcsplt;
	u32 hctsiz;
	u32 hc_dma;
	int i;

	if (!chan)
		return;

	hcchar = dwc2_readl(hsotg, HCCHAR(chan->hc_num));
	hcsplt = dwc2_readl(hsotg, HCSPLT(chan->hc_num));
	hctsiz = dwc2_readl(hsotg, HCTSIZ(chan->hc_num));
	hc_dma = dwc2_readl(hsotg, HCDMA(chan->hc_num));

	dev_dbg(hsotg->dev, "  Assigned to channel %p:\n", chan);
	dev_dbg(hsotg->dev, "    hcchar 0x%08x, hcsplt 0x%08x\n",
		hcchar, hcsplt);
	dev_dbg(hsotg->dev, "    hctsiz 0x%08x, hc_dma 0x%08x\n",
		hctsiz, hc_dma);
	dev_dbg(hsotg->dev, "    dev_addr: %d, ep_num: %d, ep_is_in: %d\n",
		chan->dev_addr, chan->ep_num, chan->ep_is_in);
	dev_dbg(hsotg->dev, "    ep_type: %d\n", chan->ep_type);
	dev_dbg(hsotg->dev, "    max_packet: %d\n", chan->max_packet);
	dev_dbg(hsotg->dev, "    data_pid_start: %d\n", chan->data_pid_start);
	dev_dbg(hsotg->dev, "    xfer_started: %d\n", chan->xfer_started);
	dev_dbg(hsotg->dev, "    halt_status: %d\n", chan->halt_status);
	dev_dbg(hsotg->dev, "    xfer_buf: %p\n", chan->xfer_buf);
	dev_dbg(hsotg->dev, "    xfer_dma: %08lx\n",
		(unsigned long)chan->xfer_dma);
	dev_dbg(hsotg->dev, "    xfer_len: %d\n", chan->xfer_len);
	dev_dbg(hsotg->dev, "    qh: %p\n", chan->qh);
	dev_dbg(hsotg->dev, "  NP inactive sched:\n");
	list_for_each_entry(qh, &hsotg->non_periodic_sched_inactive,
			    qh_list_entry)
		dev_dbg(hsotg->dev, "    %p\n", qh);
	dev_dbg(hsotg->dev, "  NP waiting sched:\n");
	list_for_each_entry(qh, &hsotg->non_periodic_sched_waiting,
			    qh_list_entry)
		dev_dbg(hsotg->dev, "    %p\n", qh);
	dev_dbg(hsotg->dev, "  NP active sched:\n");
	list_for_each_entry(qh, &hsotg->non_periodic_sched_active,
			    qh_list_entry)
		dev_dbg(hsotg->dev, "    %p\n", qh);
	dev_dbg(hsotg->dev, "  Channels:\n");
	for (i = 0; i < num_channels; i++) {
		struct dwc2_host_chan *chan = hsotg->hc_ptr_array[i];

		dev_dbg(hsotg->dev, "    %2d: %p\n", i, chan);
	}
#endif /* VERBOSE_DEBUG */
}

static int _dwc2_hcd_start(struct usb_hcd *hcd);

static void dwc2_host_start(struct dwc2_hsotg *hsotg)
{
	struct usb_hcd *hcd = dwc2_hsotg_to_hcd(hsotg);

	hcd->self.is_b_host = dwc2_hcd_is_b_host(hsotg);
	_dwc2_hcd_start(hcd);
}

static void dwc2_host_disconnect(struct dwc2_hsotg *hsotg)
{
	struct usb_hcd *hcd = dwc2_hsotg_to_hcd(hsotg);

	hcd->self.is_b_host = 0;
}

static void dwc2_host_hub_info(struct dwc2_hsotg *hsotg, void *context,
			       int *hub_addr, int *hub_port)
{
	struct urb *urb = context;

	if (urb->dev->tt)
		*hub_addr = urb->dev->tt->hub->devnum;
	else
		*hub_addr = 0;
	*hub_port = urb->dev->ttport;
}

/*
 * =========================================================================
 *  Low Level Host Channel Access Functions
 * =========================================================================
 */

static void dwc2_hc_enable_slave_ints(struct dwc2_hsotg *hsotg,
				      struct dwc2_host_chan *chan)
{
	u32 hcintmsk = HCINTMSK_CHHLTD;

	switch (chan->ep_type) {
	case USB_ENDPOINT_XFER_CONTROL:
	case USB_ENDPOINT_XFER_BULK:
		dev_vdbg(hsotg->dev, "control/bulk\n");
		hcintmsk |= HCINTMSK_XFERCOMPL;
		hcintmsk |= HCINTMSK_STALL;
		hcintmsk |= HCINTMSK_XACTERR;
		hcintmsk |= HCINTMSK_DATATGLERR;
		if (chan->ep_is_in) {
			hcintmsk |= HCINTMSK_BBLERR;
		} else {
			hcintmsk |= HCINTMSK_NAK;
			hcintmsk |= HCINTMSK_NYET;
			if (chan->do_ping)
				hcintmsk |= HCINTMSK_ACK;
		}

		if (chan->do_split) {
			hcintmsk |= HCINTMSK_NAK;
			if (chan->complete_split)
				hcintmsk |= HCINTMSK_NYET;
			else
				hcintmsk |= HCINTMSK_ACK;
		}

		if (chan->error_state)
			hcintmsk |= HCINTMSK_ACK;
		break;

	case USB_ENDPOINT_XFER_INT:
		if (dbg_perio())
			dev_vdbg(hsotg->dev, "intr\n");
		hcintmsk |= HCINTMSK_XFERCOMPL;
		hcintmsk |= HCINTMSK_NAK;
		hcintmsk |= HCINTMSK_STALL;
		hcintmsk |= HCINTMSK_XACTERR;
		hcintmsk |= HCINTMSK_DATATGLERR;
		hcintmsk |= HCINTMSK_FRMOVRUN;

		if (chan->ep_is_in)
			hcintmsk |= HCINTMSK_BBLERR;
		if (chan->error_state)
			hcintmsk |= HCINTMSK_ACK;
		if (chan->do_split) {
			if (chan->complete_split)
				hcintmsk |= HCINTMSK_NYET;
			else
				hcintmsk |= HCINTMSK_ACK;
		}
		break;

	case USB_ENDPOINT_XFER_ISOC:
		if (dbg_perio())
			dev_vdbg(hsotg->dev, "isoc\n");
		hcintmsk |= HCINTMSK_XFERCOMPL;
		hcintmsk |= HCINTMSK_FRMOVRUN;
		hcintmsk |= HCINTMSK_ACK;

		if (chan->ep_is_in) {
			hcintmsk |= HCINTMSK_XACTERR;
			hcintmsk |= HCINTMSK_BBLERR;
		}
		break;
	default:
		dev_err(hsotg->dev, "## Unknown EP type ##\n");
		break;
	}

	dwc2_writel(hsotg, hcintmsk, HCINTMSK(chan->hc_num));
	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev, "set HCINTMSK to %08x\n", hcintmsk);
}

static void dwc2_hc_enable_dma_ints(struct dwc2_hsotg *hsotg,
				    struct dwc2_host_chan *chan)
{
	u32 hcintmsk = HCINTMSK_CHHLTD;

	/*
	 * For Descriptor DMA mode core halts the channel on AHB error.
	 * Interrupt is not required.
	 */
	if (!hsotg->params.dma_desc_enable) {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "desc DMA disabled\n");
		hcintmsk |= HCINTMSK_AHBERR;
	} else {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "desc DMA enabled\n");
		if (chan->ep_type == USB_ENDPOINT_XFER_ISOC)
			hcintmsk |= HCINTMSK_XFERCOMPL;
	}

	if (chan->error_state && !chan->do_split &&
	    chan->ep_type != USB_ENDPOINT_XFER_ISOC) {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "setting ACK\n");
		hcintmsk |= HCINTMSK_ACK;
		if (chan->ep_is_in) {
			hcintmsk |= HCINTMSK_DATATGLERR;
			if (chan->ep_type != USB_ENDPOINT_XFER_INT)
				hcintmsk |= HCINTMSK_NAK;
		}
	}

	dwc2_writel(hsotg, hcintmsk, HCINTMSK(chan->hc_num));
	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev, "set HCINTMSK to %08x\n", hcintmsk);
}

static void dwc2_hc_enable_ints(struct dwc2_hsotg *hsotg,
				struct dwc2_host_chan *chan)
{
	u32 intmsk;

	if (hsotg->params.host_dma) {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "DMA enabled\n");
		dwc2_hc_enable_dma_ints(hsotg, chan);
	} else {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "DMA disabled\n");
		dwc2_hc_enable_slave_ints(hsotg, chan);
	}

	/* Enable the top level host channel interrupt */
	intmsk = dwc2_readl(hsotg, HAINTMSK);
	intmsk |= 1 << chan->hc_num;
	dwc2_writel(hsotg, intmsk, HAINTMSK);
	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev, "set HAINTMSK to %08x\n", intmsk);

	/* Make sure host channel interrupts are enabled */
	intmsk = dwc2_readl(hsotg, GINTMSK);
	intmsk |= GINTSTS_HCHINT;
	dwc2_writel(hsotg, intmsk, GINTMSK);
	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev, "set GINTMSK to %08x\n", intmsk);
}

/**
 * dwc2_hc_init() - Prepares a host channel for transferring packets to/from
 * a specific endpoint
 *
 * @hsotg: Programming view of DWC_otg controller
 * @chan:  Information needed to initialize the host channel
 *
 * The HCCHARn register is set up with the characteristics specified in chan.
 * Host channel interrupts that may need to be serviced while this transfer is
 * in progress are enabled.
 */
static void dwc2_hc_init(struct dwc2_hsotg *hsotg, struct dwc2_host_chan *chan)
{
	u8 hc_num = chan->hc_num;
	u32 hcintmsk;
	u32 hcchar;
	u32 hcsplt = 0;

	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev, "%s()\n", __func__);

	/* Clear old interrupt conditions for this host channel */
	hcintmsk = 0xffffffff;
	hcintmsk &= ~HCINTMSK_RESERVED14_31;
	dwc2_writel(hsotg, hcintmsk, HCINT(hc_num));

	/* Enable channel interrupts required for this transfer */
	dwc2_hc_enable_ints(hsotg, chan);

	/*
	 * Program the HCCHARn register with the endpoint characteristics for
	 * the current transfer
	 */
	hcchar = chan->dev_addr << HCCHAR_DEVADDR_SHIFT & HCCHAR_DEVADDR_MASK;
	hcchar |= chan->ep_num << HCCHAR_EPNUM_SHIFT & HCCHAR_EPNUM_MASK;
	if (chan->ep_is_in)
		hcchar |= HCCHAR_EPDIR;
	if (chan->speed == USB_SPEED_LOW)
		hcchar |= HCCHAR_LSPDDEV;
	hcchar |= chan->ep_type << HCCHAR_EPTYPE_SHIFT & HCCHAR_EPTYPE_MASK;
	hcchar |= chan->max_packet << HCCHAR_MPS_SHIFT & HCCHAR_MPS_MASK;
	dwc2_writel(hsotg, hcchar, HCCHAR(hc_num));
	if (dbg_hc(chan)) {
		dev_vdbg(hsotg->dev, "set HCCHAR(%d) to %08x\n",
			 hc_num, hcchar);

		dev_vdbg(hsotg->dev, "%s: Channel %d\n",
			 __func__, hc_num);
		dev_vdbg(hsotg->dev, "	 Dev Addr: %d\n",
			 chan->dev_addr);
		dev_vdbg(hsotg->dev, "	 Ep Num: %d\n",
			 chan->ep_num);
		dev_vdbg(hsotg->dev, "	 Is In: %d\n",
			 chan->ep_is_in);
		dev_vdbg(hsotg->dev, "	 Is Low Speed: %d\n",
			 chan->speed == USB_SPEED_LOW);
		dev_vdbg(hsotg->dev, "	 Ep Type: %d\n",
			 chan->ep_type);
		dev_vdbg(hsotg->dev, "	 Max Pkt: %d\n",
			 chan->max_packet);
	}

	/* Program the HCSPLT register for SPLITs */
	if (chan->do_split) {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev,
				 "Programming HC %d with split --> %s\n",
				 hc_num,
				 chan->complete_split ? "CSPLIT" : "SSPLIT");
		if (chan->complete_split)
			hcsplt |= HCSPLT_COMPSPLT;
		hcsplt |= chan->xact_pos << HCSPLT_XACTPOS_SHIFT &
			  HCSPLT_XACTPOS_MASK;
		hcsplt |= chan->hub_addr << HCSPLT_HUBADDR_SHIFT &
			  HCSPLT_HUBADDR_MASK;
		hcsplt |= chan->hub_port << HCSPLT_PRTADDR_SHIFT &
			  HCSPLT_PRTADDR_MASK;
		if (dbg_hc(chan)) {
			dev_vdbg(hsotg->dev, "	  comp split %d\n",
				 chan->complete_split);
			dev_vdbg(hsotg->dev, "	  xact pos %d\n",
				 chan->xact_pos);
			dev_vdbg(hsotg->dev, "	  hub addr %d\n",
				 chan->hub_addr);
			dev_vdbg(hsotg->dev, "	  hub port %d\n",
				 chan->hub_port);
			dev_vdbg(hsotg->dev, "	  is_in %d\n",
				 chan->ep_is_in);
			dev_vdbg(hsotg->dev, "	  Max Pkt %d\n",
				 chan->max_packet);
			dev_vdbg(hsotg->dev, "	  xferlen %d\n",
				 chan->xfer_len);
		}
	}

	dwc2_writel(hsotg, hcsplt, HCSPLT(hc_num));
}

/**
 * dwc2_hc_halt() - Attempts to halt a host channel
 *
 * @hsotg:       Controller register interface
 * @chan:        Host channel to halt
 * @halt_status: Reason for halting the channel
 *
 * This function should only be called in Slave mode or to abort a transfer in
 * either Slave mode or DMA mode. Under normal circumstances in DMA mode, the
 * controller halts the channel when the transfer is complete or a condition
 * occurs that requires application intervention.
 *
 * In slave mode, checks for a free request queue entry, then sets the Channel
 * Enable and Channel Disable bits of the Host Channel Characteristics
 * register of the specified channel to intiate the halt. If there is no free
 * request queue entry, sets only the Channel Disable bit of the HCCHARn
 * register to flush requests for this channel. In the latter case, sets a
 * flag to indicate that the host channel needs to be halted when a request
 * queue slot is open.
 *
 * In DMA mode, always sets the Channel Enable and Channel Disable bits of the
 * HCCHARn register. The controller ensures there is space in the request
 * queue before submitting the halt request.
 *
 * Some time may elapse before the core flushes any posted requests for this
 * host channel and halts. The Channel Halted interrupt handler completes the
 * deactivation of the host channel.
 */
void dwc2_hc_halt(struct dwc2_hsotg *hsotg, struct dwc2_host_chan *chan,
		  enum dwc2_halt_status halt_status)
{
	u32 nptxsts, hptxsts, hcchar;

	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev, "%s()\n", __func__);

	/*
	 * In buffer DMA or external DMA mode channel can't be halted
	 * for non-split periodic channels. At the end of the next
	 * uframe/frame (in the worst case), the core generates a channel
	 * halted and disables the channel automatically.
	 */
	if ((hsotg->params.host_dma && !hsotg->params.dma_desc_enable) ||
	    hsotg->hw_params.arch == GHWCFG2_EXT_DMA_ARCH) {
		if (!chan->do_split &&
		    (chan->ep_type == USB_ENDPOINT_XFER_ISOC ||
		     chan->ep_type == USB_ENDPOINT_XFER_INT) &&
		    (halt_status == DWC2_HC_XFER_URB_DEQUEUE)) {
			chan->halt_status = halt_status;
			dev_err(hsotg->dev, "%s() Channel can't be halted\n",
				__func__);
			return;
		}
	}

	if (halt_status == DWC2_HC_XFER_NO_HALT_STATUS)
		dev_err(hsotg->dev, "!!! halt_status = %d !!!\n", halt_status);

	if (halt_status == DWC2_HC_XFER_URB_DEQUEUE ||
	    halt_status == DWC2_HC_XFER_AHB_ERR) {
		/*
		 * Disable all channel interrupts except Ch Halted. The QTD
		 * and QH state associated with this transfer has been cleared
		 * (in the case of URB_DEQUEUE), so the channel needs to be
		 * shut down carefully to prevent crashes.
		 */
		u32 hcintmsk = HCINTMSK_CHHLTD;

		dev_vdbg(hsotg->dev, "dequeue/error\n");
		dwc2_writel(hsotg, hcintmsk, HCINTMSK(chan->hc_num));

		/*
		 * Make sure no other interrupts besides halt are currently
		 * pending. Handling another interrupt could cause a crash due
		 * to the QTD and QH state.
		 */
		dwc2_writel(hsotg, ~hcintmsk, HCINT(chan->hc_num));

		/*
		 * Make sure the halt status is set to URB_DEQUEUE or AHB_ERR
		 * even if the channel was already halted for some other
		 * reason
		 */
		chan->halt_status = halt_status;

		hcchar = dwc2_readl(hsotg, HCCHAR(chan->hc_num));
		if (!(hcchar & HCCHAR_CHENA)) {
			/*
			 * The channel is either already halted or it hasn't
			 * started yet. In DMA mode, the transfer may halt if
			 * it finishes normally or a condition occurs that
			 * requires driver intervention. Don't want to halt
			 * the channel again. In either Slave or DMA mode,
			 * it's possible that the transfer has been assigned
			 * to a channel, but not started yet when an URB is
			 * dequeued. Don't want to halt a channel that hasn't
			 * started yet.
			 */
			return;
		}
	}
	if (chan->halt_pending) {
		/*
		 * A halt has already been issued for this channel. This might
		 * happen when a transfer is aborted by a higher level in
		 * the stack.
		 */
		dev_vdbg(hsotg->dev,
			 "*** %s: Channel %d, chan->halt_pending already set ***\n",
			 __func__, chan->hc_num);
		return;
	}

	hcchar = dwc2_readl(hsotg, HCCHAR(chan->hc_num));

	/* No need to set the bit in DDMA for disabling the channel */
	/* TODO check it everywhere channel is disabled */
	if (!hsotg->params.dma_desc_enable) {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "desc DMA disabled\n");
		hcchar |= HCCHAR_CHENA;
	} else {
		if (dbg_hc(chan))
			dev_dbg(hsotg->dev, "desc DMA enabled\n");
	}
	hcchar |= HCCHAR_CHDIS;

	if (!hsotg->params.host_dma) {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "DMA not enabled\n");
		hcchar |= HCCHAR_CHENA;

		/* Check for space in the request queue to issue the halt */
		if (chan->ep_type == USB_ENDPOINT_XFER_CONTROL ||
		    chan->ep_type == USB_ENDPOINT_XFER_BULK) {
			dev_vdbg(hsotg->dev, "control/bulk\n");
			nptxsts = dwc2_readl(hsotg, GNPTXSTS);
			if ((nptxsts & TXSTS_QSPCAVAIL_MASK) == 0) {
				dev_vdbg(hsotg->dev, "Disabling channel\n");
				hcchar &= ~HCCHAR_CHENA;
			}
		} else {
			if (dbg_perio())
				dev_vdbg(hsotg->dev, "isoc/intr\n");
			hptxsts = dwc2_readl(hsotg, HPTXSTS);
			if ((hptxsts & TXSTS_QSPCAVAIL_MASK) == 0 ||
			    hsotg->queuing_high_bandwidth) {
				if (dbg_perio())
					dev_vdbg(hsotg->dev, "Disabling channel\n");
				hcchar &= ~HCCHAR_CHENA;
			}
		}
	} else {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "DMA enabled\n");
	}

	dwc2_writel(hsotg, hcchar, HCCHAR(chan->hc_num));
	chan->halt_status = halt_status;

	if (hcchar & HCCHAR_CHENA) {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "Channel enabled\n");
		chan->halt_pending = 1;
		chan->halt_on_queue = 0;
	} else {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "Channel disabled\n");
		chan->halt_on_queue = 1;
	}

	if (dbg_hc(chan)) {
		dev_vdbg(hsotg->dev, "%s: Channel %d\n", __func__,
			 chan->hc_num);
		dev_vdbg(hsotg->dev, "	 hcchar: 0x%08x\n",
			 hcchar);
		dev_vdbg(hsotg->dev, "	 halt_pending: %d\n",
			 chan->halt_pending);
		dev_vdbg(hsotg->dev, "	 halt_on_queue: %d\n",
			 chan->halt_on_queue);
		dev_vdbg(hsotg->dev, "	 halt_status: %d\n",
			 chan->halt_status);
	}
}

/**
 * dwc2_hc_cleanup() - Clears the transfer state for a host channel
 *
 * @hsotg: Programming view of DWC_otg controller
 * @chan:  Identifies the host channel to clean up
 *
 * This function is normally called after a transfer is done and the host
 * channel is being released
 */
void dwc2_hc_cleanup(struct dwc2_hsotg *hsotg, struct dwc2_host_chan *chan)
{
	u32 hcintmsk;

	chan->xfer_started = 0;

	list_del_init(&chan->split_order_list_entry);

	/*
	 * Clear channel interrupt enables and any unhandled channel interrupt
	 * conditions
	 */
	dwc2_writel(hsotg, 0, HCINTMSK(chan->hc_num));
	hcintmsk = 0xffffffff;
	hcintmsk &= ~HCINTMSK_RESERVED14_31;
	dwc2_writel(hsotg, hcintmsk, HCINT(chan->hc_num));
}

/**
 * dwc2_hc_set_even_odd_frame() - Sets the channel property that indicates in
 * which frame a periodic transfer should occur
 *
 * @hsotg:  Programming view of DWC_otg controller
 * @chan:   Identifies the host channel to set up and its properties
 * @hcchar: Current value of the HCCHAR register for the specified host channel
 *
 * This function has no effect on non-periodic transfers
 */
static void dwc2_hc_set_even_odd_frame(struct dwc2_hsotg *hsotg,
				       struct dwc2_host_chan *chan, u32 *hcchar)
{
	if (chan->ep_type == USB_ENDPOINT_XFER_INT ||
	    chan->ep_type == USB_ENDPOINT_XFER_ISOC) {
		int host_speed;
		int xfer_ns;
		int xfer_us;
		int bytes_in_fifo;
		u16 fifo_space;
		u16 frame_number;
		u16 wire_frame;

		/*
		 * Try to figure out if we're an even or odd frame. If we set
		 * even and the current frame number is even the the transfer
		 * will happen immediately.  Similar if both are odd. If one is
		 * even and the other is odd then the transfer will happen when
		 * the frame number ticks.
		 *
		 * There's a bit of a balancing act to get this right.
		 * Sometimes we may want to send data in the current frame (AK
		 * right away).  We might want to do this if the frame number
		 * _just_ ticked, but we might also want to do this in order
		 * to continue a split transaction that happened late in a
		 * microframe (so we didn't know to queue the next transfer
		 * until the frame number had ticked).  The problem is that we
		 * need a lot of knowledge to know if there's actually still
		 * time to send things or if it would be better to wait until
		 * the next frame.
		 *
		 * We can look at how much time is left in the current frame
		 * and make a guess about whether we'll have time to transfer.
		 * We'll do that.
		 */

		/* Get speed host is running at */
		host_speed = (chan->speed != USB_SPEED_HIGH &&
			      !chan->do_split) ? chan->speed : USB_SPEED_HIGH;

		/* See how many bytes are in the periodic FIFO right now */
		fifo_space = (dwc2_readl(hsotg, HPTXSTS) &
			      TXSTS_FSPCAVAIL_MASK) >> TXSTS_FSPCAVAIL_SHIFT;
		bytes_in_fifo = sizeof(u32) *
				(hsotg->params.host_perio_tx_fifo_size -
				 fifo_space);

		/*
		 * Roughly estimate bus time for everything in the periodic
		 * queue + our new transfer.  This is "rough" because we're
		 * using a function that makes takes into account IN/OUT
		 * and INT/ISO and we're just slamming in one value for all
		 * transfers.  This should be an over-estimate and that should
		 * be OK, but we can probably tighten it.
		 */
		xfer_ns = usb_calc_bus_time(host_speed, false, false,
					    chan->xfer_len + bytes_in_fifo);
		xfer_us = NS_TO_US(xfer_ns);

		/* See what frame number we'll be at by the time we finish */
		frame_number = dwc2_hcd_get_future_frame_number(hsotg, xfer_us);

		/* This is when we were scheduled to be on the wire */
		wire_frame = dwc2_frame_num_inc(chan->qh->next_active_frame, 1);

		/*
		 * If we'd finish _after_ the frame we're scheduled in then
		 * it's hopeless.  Just schedule right away and hope for the
		 * best.  Note that it _might_ be wise to call back into the
		 * scheduler to pick a better frame, but this is better than
		 * nothing.
		 */
		if (dwc2_frame_num_gt(frame_number, wire_frame)) {
			dwc2_sch_vdbg(hsotg,
				      "QH=%p EO MISS fr=%04x=>%04x (%+d)\n",
				      chan->qh, wire_frame, frame_number,
				      dwc2_frame_num_dec(frame_number,
							 wire_frame));
			wire_frame = frame_number;

			/*
			 * We picked a different frame number; communicate this
			 * back to the scheduler so it doesn't try to schedule
			 * another in the same frame.
			 *
			 * Remember that next_active_frame is 1 before the wire
			 * frame.
			 */
			chan->qh->next_active_frame =
				dwc2_frame_num_dec(frame_number, 1);
		}

		if (wire_frame & 1)
			*hcchar |= HCCHAR_ODDFRM;
		else
			*hcchar &= ~HCCHAR_ODDFRM;
	}
}

static void dwc2_set_pid_isoc(struct dwc2_host_chan *chan)
{
	/* Set up the initial PID for the transfer */
	if (chan->speed == USB_SPEED_HIGH) {
		if (chan->ep_is_in) {
			if (chan->multi_count == 1)
				chan->data_pid_start = DWC2_HC_PID_DATA0;
			else if (chan->multi_count == 2)
				chan->data_pid_start = DWC2_HC_PID_DATA1;
			else
				chan->data_pid_start = DWC2_HC_PID_DATA2;
		} else {
			if (chan->multi_count == 1)
				chan->data_pid_start = DWC2_HC_PID_DATA0;
			else
				chan->data_pid_start = DWC2_HC_PID_MDATA;
		}
	} else {
		chan->data_pid_start = DWC2_HC_PID_DATA0;
	}
}

/**
 * dwc2_hc_write_packet() - Writes a packet into the Tx FIFO associated with
 * the Host Channel
 *
 * @hsotg: Programming view of DWC_otg controller
 * @chan:  Information needed to initialize the host channel
 *
 * This function should only be called in Slave mode. For a channel associated
 * with a non-periodic EP, the non-periodic Tx FIFO is written. For a channel
 * associated with a periodic EP, the periodic Tx FIFO is written.
 *
 * Upon return the xfer_buf and xfer_count fields in chan are incremented by
 * the number of bytes written to the Tx FIFO.
 */
static void dwc2_hc_write_packet(struct dwc2_hsotg *hsotg,
				 struct dwc2_host_chan *chan)
{
	u32 i;
	u32 remaining_count;
	u32 byte_count;
	u32 dword_count;
	u32 *data_buf = (u32 *)chan->xfer_buf;

	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev, "%s()\n", __func__);

	remaining_count = chan->xfer_len - chan->xfer_count;
	if (remaining_count > chan->max_packet)
		byte_count = chan->max_packet;
	else
		byte_count = remaining_count;

	dword_count = (byte_count + 3) / 4;

	if (((unsigned long)data_buf & 0x3) == 0) {
		/* xfer_buf is DWORD aligned */
		for (i = 0; i < dword_count; i++, data_buf++)
			dwc2_writel(hsotg, *data_buf, HCFIFO(chan->hc_num));
	} else {
		/* xfer_buf is not DWORD aligned */
		for (i = 0; i < dword_count; i++, data_buf++) {
			u32 data = data_buf[0] | data_buf[1] << 8 |
				   data_buf[2] << 16 | data_buf[3] << 24;
			dwc2_writel(hsotg, data, HCFIFO(chan->hc_num));
		}
	}

	chan->xfer_count += byte_count;
	chan->xfer_buf += byte_count;
}

/**
 * dwc2_hc_do_ping() - Starts a PING transfer
 *
 * @hsotg: Programming view of DWC_otg controller
 * @chan:  Information needed to initialize the host channel
 *
 * This function should only be called in Slave mode. The Do Ping bit is set in
 * the HCTSIZ register, then the channel is enabled.
 */
static void dwc2_hc_do_ping(struct dwc2_hsotg *hsotg,
			    struct dwc2_host_chan *chan)
{
	u32 hcchar;
	u32 hctsiz;

	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev, "%s: Channel %d\n", __func__,
			 chan->hc_num);

	hctsiz = TSIZ_DOPNG;
	hctsiz |= 1 << TSIZ_PKTCNT_SHIFT;
	dwc2_writel(hsotg, hctsiz, HCTSIZ(chan->hc_num));

	hcchar = dwc2_readl(hsotg, HCCHAR(chan->hc_num));
	hcchar |= HCCHAR_CHENA;
	hcchar &= ~HCCHAR_CHDIS;
	dwc2_writel(hsotg, hcchar, HCCHAR(chan->hc_num));
}

/**
 * dwc2_hc_start_transfer() - Does the setup for a data transfer for a host
 * channel and starts the transfer
 *
 * @hsotg: Programming view of DWC_otg controller
 * @chan:  Information needed to initialize the host channel. The xfer_len value
 *         may be reduced to accommodate the max widths of the XferSize and
 *         PktCnt fields in the HCTSIZn register. The multi_count value may be
 *         changed to reflect the final xfer_len value.
 *
 * This function may be called in either Slave mode or DMA mode. In Slave mode,
 * the caller must ensure that there is sufficient space in the request queue
 * and Tx Data FIFO.
 *
 * For an OUT transfer in Slave mode, it loads a data packet into the
 * appropriate FIFO. If necessary, additional data packets are loaded in the
 * Host ISR.
 *
 * For an IN transfer in Slave mode, a data packet is requested. The data
 * packets are unloaded from the Rx FIFO in the Host ISR. If necessary,
 * additional data packets are requested in the Host ISR.
 *
 * For a PING transfer in Slave mode, the Do Ping bit is set in the HCTSIZ
 * register along with a packet count of 1 and the channel is enabled. This
 * causes a single PING transaction to occur. Other fields in HCTSIZ are
 * simply set to 0 since no data transfer occurs in this case.
 *
 * For a PING transfer in DMA mode, the HCTSIZ register is initialized with
 * all the information required to perform the subsequent data transfer. In
 * addition, the Do Ping bit is set in the HCTSIZ register. In this case, the
 * controller performs the entire PING protocol, then starts the data
 * transfer.
 */
static void dwc2_hc_start_transfer(struct dwc2_hsotg *hsotg,
				   struct dwc2_host_chan *chan)
{
	u32 max_hc_xfer_size = hsotg->params.max_transfer_size;
	u16 max_hc_pkt_count = hsotg->params.max_packet_count;
	u32 hcchar;
	u32 hctsiz = 0;
	u16 num_packets;
	u32 ec_mc;

	if (dbg_hc(chan))
		dev_vdbg(hsotg->dev, "%s()\n", __func__);

	if (chan->do_ping) {
		if (!hsotg->params.host_dma) {
			if (dbg_hc(chan))
				dev_vdbg(hsotg->dev, "ping, no DMA\n");
			dwc2_hc_do_ping(hsotg, chan);
			chan->xfer_started = 1;
			return;
		}

		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "ping, DMA\n");

		hctsiz |= TSIZ_DOPNG;
	}

	if (chan->do_split) {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "split\n");
		num_packets = 1;

		if (chan->complete_split && !chan->ep_is_in)
			/*
			 * For CSPLIT OUT Transfer, set the size to 0 so the
			 * core doesn't expect any data written to the FIFO
			 */
			chan->xfer_len = 0;
		else if (chan->ep_is_in || chan->xfer_len > chan->max_packet)
			chan->xfer_len = chan->max_packet;
		else if (!chan->ep_is_in && chan->xfer_len > 188)
			chan->xfer_len = 188;

		hctsiz |= chan->xfer_len << TSIZ_XFERSIZE_SHIFT &
			  TSIZ_XFERSIZE_MASK;

		/* For split set ec_mc for immediate retries */
		if (chan->ep_type == USB_ENDPOINT_XFER_INT ||
		    chan->ep_type == USB_ENDPOINT_XFER_ISOC)
			ec_mc = 3;
		else
			ec_mc = 1;
	} else {
		if (dbg_hc(chan))
			dev_vdbg(hsotg->dev, "no split\n");
		/*
		 * Ensure that the transfer length and packet count will fit
		 * in the widths allocated for them in the HCTSIZn register
