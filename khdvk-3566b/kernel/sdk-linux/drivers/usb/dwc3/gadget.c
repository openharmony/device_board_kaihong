// SPDX-License-Identifier: GPL-2.0
/*
 * gadget.c - DesignWare USB3 DRD Controller Gadget Framework Link
 *
 * Copyright (C) 2010-2011 Texas Instruments Incorporated - https://www.ti.com
 *
 * Authors: Felipe Balbi <balbi@ti.com>,
 *	    Sebastian Andrzej Siewior <bigeasy@linutronix.de>
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/dma-mapping.h>

#include <linux/usb/ch9.h>
#include <linux/usb/gadget.h>

#include "debug.h"
#include "core.h"
#include "gadget.h"
#include "io.h"

#define DWC3_ALIGN_FRAME(d, n)	(((d)->frame_number + ((d)->interval * (n))) \
					& ~((d)->interval - 1))

/**
 * dwc3_gadget_set_test_mode - enables usb2 test modes
 * @dwc: pointer to our context structure
 * @mode: the mode to set (J, K SE0 NAK, Force Enable)
 *
 * Caller should take care of locking. This function will return 0 on
 * success or -EINVAL if wrong Test Selector is passed.
 */
int dwc3_gadget_set_test_mode(struct dwc3 *dwc, int mode)
{
	u32		reg;

	reg = dwc3_readl(dwc->regs, DWC3_DCTL);
	reg &= ~DWC3_DCTL_TSTCTRL_MASK;

	switch (mode) {
	case USB_TEST_J:
	case USB_TEST_K:
	case USB_TEST_SE0_NAK:
	case USB_TEST_PACKET:
	case USB_TEST_FORCE_ENABLE:
		reg |= mode << 1;
		break;
	default:
		return -EINVAL;
	}

	dwc3_gadget_dctl_write_safe(dwc, reg);

	return 0;
}

/**
 * dwc3_gadget_get_link_state - gets current state of usb link
 * @dwc: pointer to our context structure
 *
 * Caller should take care of locking. This function will
 * return the link state on success (>= 0) or -ETIMEDOUT.
 */
int dwc3_gadget_get_link_state(struct dwc3 *dwc)
{
	u32		reg;

	reg = dwc3_readl(dwc->regs, DWC3_DSTS);

	return DWC3_DSTS_USBLNKST(reg);
}

/**
 * dwc3_gadget_set_link_state - sets usb link to a particular state
 * @dwc: pointer to our context structure
 * @state: the state to put link into
 *
 * Caller should take care of locking. This function will
 * return 0 on success or -ETIMEDOUT.
 */
int dwc3_gadget_set_link_state(struct dwc3 *dwc, enum dwc3_link_state state)
{
	int		retries = 10000;
	u32		reg;

	/*
	 * Wait until device controller is ready. Only applies to 1.94a and
	 * later RTL.
	 */
	if (!DWC3_VER_IS_PRIOR(DWC3, 194A)) {
		while (--retries) {
			reg = dwc3_readl(dwc->regs, DWC3_DSTS);
			if (reg & DWC3_DSTS_DCNRD)
				udelay(5);
			else
				break;
		}

		if (retries <= 0)
			return -ETIMEDOUT;
	}

	reg = dwc3_readl(dwc->regs, DWC3_DCTL);
	reg &= ~DWC3_DCTL_ULSTCHNGREQ_MASK;

	/* set no action before sending new link state change */
	dwc3_writel(dwc->regs, DWC3_DCTL, reg);

	/* set requested state */
	reg |= DWC3_DCTL_ULSTCHNGREQ(state);
	dwc3_writel(dwc->regs, DWC3_DCTL, reg);

	/*
	 * The following code is racy when called from dwc3_gadget_wakeup,
	 * and is not needed, at least on newer versions
	 */
	if (!DWC3_VER_IS_PRIOR(DWC3, 194A))
		return 0;

	/* wait for a change in DSTS */
	retries = 10000;
	while (--retries) {
		reg = dwc3_readl(dwc->regs, DWC3_DSTS);

		if (DWC3_DSTS_USBLNKST(reg) == state)
			return 0;

		udelay(5);
	}

	return -ETIMEDOUT;
}

/**
 * dwc3_ep_inc_trb - increment a trb index.
 * @index: Pointer to the TRB index to increment.
 *
 * The index should never point to the link TRB. After incrementing,
 * if it is point to the link TRB, wrap around to the beginning. The
 * link TRB is always at the last TRB entry.
 */
static void dwc3_ep_inc_trb(u8 *index)
{
	(*index)++;
	if (*index == (DWC3_TRB_NUM - 1))
		*index = 0;
}

/**
 * dwc3_ep_inc_enq - increment endpoint's enqueue pointer
 * @dep: The endpoint whose enqueue pointer we're incrementing
 */
static void dwc3_ep_inc_enq(struct dwc3_ep *dep)
{
	dwc3_ep_inc_trb(&dep->trb_enqueue);
}

/**
 * dwc3_ep_inc_deq - increment endpoint's dequeue pointer
 * @dep: The endpoint whose enqueue pointer we're incrementing
 */
static void dwc3_ep_inc_deq(struct dwc3_ep *dep)
{
	dwc3_ep_inc_trb(&dep->trb_dequeue);
}

static void dwc3_gadget_del_and_unmap_request(struct dwc3_ep *dep,
		struct dwc3_request *req, int status)
{
	struct dwc3			*dwc = dep->dwc;

	list_del(&req->list);
	req->remaining = 0;
	req->needs_extra_trb = false;

	if (req->request.status == -EINPROGRESS)
		req->request.status = status;

	if (req->trb)
		usb_gadget_unmap_request_by_dev(dwc->sysdev,
				&req->request, req->direction);

	req->trb = NULL;
	trace_dwc3_gadget_giveback(req);

	if (dep->number > 1)
		pm_runtime_put(dwc->dev);
}

/**
 * dwc3_gadget_giveback - call struct usb_request's ->complete callback
 * @dep: The endpoint to whom the request belongs to
 * @req: The request we're giving back
 * @status: completion code for the request
 *
 * Must be called with controller's lock held and interrupts disabled. This
 * function will unmap @req and call its ->complete() callback to notify upper
 * layers that it has completed.
 */
void dwc3_gadget_giveback(struct dwc3_ep *dep, struct dwc3_request *req,
		int status)
{
	struct dwc3			*dwc = dep->dwc;

	dwc3_gadget_del_and_unmap_request(dep, req, status);
	req->status = DWC3_REQUEST_STATUS_COMPLETED;

	spin_unlock(&dwc->lock);
	usb_gadget_giveback_request(&dep->endpoint, &req->request);
	spin_lock(&dwc->lock);
}

/**
 * dwc3_send_gadget_generic_command - issue a generic command for the controller
 * @dwc: pointer to the controller context
 * @cmd: the command to be issued
 * @param: command parameter
 *
 * Caller should take care of locking. Issue @cmd with a given @param to @dwc
 * and wait for its completion.
 */
int dwc3_send_gadget_generic_command(struct dwc3 *dwc, unsigned int cmd,
		u32 param)
{
	u32		timeout = 500;
	int		status = 0;
	int		ret = 0;
	u32		reg;

	dwc3_writel(dwc->regs, DWC3_DGCMDPAR, param);
	dwc3_writel(dwc->regs, DWC3_DGCMD, cmd | DWC3_DGCMD_CMDACT);

	do {
		reg = dwc3_readl(dwc->regs, DWC3_DGCMD);
		if (!(reg & DWC3_DGCMD_CMDACT)) {
			status = DWC3_DGCMD_STATUS(reg);
			if (status)
				ret = -EINVAL;
			break;
		}
	} while (--timeout);

	if (!timeout) {
		ret = -ETIMEDOUT;
		status = -ETIMEDOUT;
	}

	trace_dwc3_gadget_generic_cmd(cmd, param, status);

	return ret;
}

static int __dwc3_gadget_wakeup(struct dwc3 *dwc);

/**
 * dwc3_send_gadget_ep_cmd - issue an endpoint command
 * @dep: the endpoint to which the command is going to be issued
 * @cmd: the command to be issued
 * @params: parameters to the command
 *
 * Caller should handle locking. This function will issue @cmd with given
 * @params to @dep and wait for its completion.
 */
int dwc3_send_gadget_ep_cmd(struct dwc3_ep *dep, unsigned int cmd,
		struct dwc3_gadget_ep_cmd_params *params)
{
	const struct usb_endpoint_descriptor *desc = dep->endpoint.desc;
	struct dwc3		*dwc = dep->dwc;
	u32			timeout = 5000;
	u32			saved_config = 0;
	u32			reg;

	int			cmd_status = 0;
	int			ret = -EINVAL;

	/*
	 * When operating in USB 2.0 speeds (HS/FS), if GUSB2PHYCFG.ENBLSLPM or
	 * GUSB2PHYCFG.SUSPHY is set, it must be cleared before issuing an
	 * endpoint command.
	 *
	 * Save and clear both GUSB2PHYCFG.ENBLSLPM and GUSB2PHYCFG.SUSPHY
	 * settings. Restore them after the command is completed.
	 *
	 * DWC_usb3 3.30a and DWC_usb31 1.90a programming guide section 3.2.2
	 */
	if (dwc->gadget->speed <= USB_SPEED_HIGH) {
		reg = dwc3_readl(dwc->regs, DWC3_GUSB2PHYCFG(0));
		if (unlikely(reg & DWC3_GUSB2PHYCFG_SUSPHY)) {
			saved_config |= DWC3_GUSB2PHYCFG_SUSPHY;
			reg &= ~DWC3_GUSB2PHYCFG_SUSPHY;
		}

		if (reg & DWC3_GUSB2PHYCFG_ENBLSLPM) {
			saved_config |= DWC3_GUSB2PHYCFG_ENBLSLPM;
			reg &= ~DWC3_GUSB2PHYCFG_ENBLSLPM;
		}

		if (saved_config)
			dwc3_writel(dwc->regs, DWC3_GUSB2PHYCFG(0), reg);
	}

	if (DWC3_DEPCMD_CMD(cmd) == DWC3_DEPCMD_STARTTRANSFER) {
		int link_state;

		link_state = dwc3_gadget_get_link_state(dwc);
		if (link_state == DWC3_LINK_STATE_U1 ||
		    link_state == DWC3_LINK_STATE_U2 ||
		    link_state == DWC3_LINK_STATE_U3) {
			ret = __dwc3_gadget_wakeup(dwc);
			dev_WARN_ONCE(dwc->dev, ret, "wakeup failed --> %d\n",
					ret);
		}
	}

	dwc3_writel(dep->regs, DWC3_DEPCMDPAR0, params->param0);
	dwc3_writel(dep->regs, DWC3_DEPCMDPAR1, params->param1);
	dwc3_writel(dep->regs, DWC3_DEPCMDPAR2, params->param2);

	/*
	 * Synopsys Databook 2.60a states in section 6.3.2.5.6 of that if we're
	 * not relying on XferNotReady, we can make use of a special "No
	 * Response Update Transfer" command where we should clear both CmdAct
	 * and CmdIOC bits.
	 *
	 * With this, we don't need to wait for command completion and can
	 * straight away issue further commands to the endpoint.
	 *
	 * NOTICE: We're making an assumption that control endpoints will never
	 * make use of Update Transfer command. This is a safe assumption
	 * because we can never have more than one request at a time with
	 * Control Endpoints. If anybody changes that assumption, this chunk
	 * needs to be updated accordingly.
	 */
	if (DWC3_DEPCMD_CMD(cmd) == DWC3_DEPCMD_UPDATETRANSFER &&
			!usb_endpoint_xfer_isoc(desc))
		cmd &= ~(DWC3_DEPCMD_CMDIOC | DWC3_DEPCMD_CMDACT);
	else
		cmd |= DWC3_DEPCMD_CMDACT;

	dwc3_writel(dep->regs, DWC3_DEPCMD, cmd);
	do {
		reg = dwc3_readl(dep->regs, DWC3_DEPCMD);
		if (!(reg & DWC3_DEPCMD_CMDACT)) {
			cmd_status = DWC3_DEPCMD_STATUS(reg);

			switch (cmd_status) {
			case 0:
				ret = 0;
				break;
			case DEPEVT_TRANSFER_NO_RESOURCE:
				dev_WARN(dwc->dev, "No resource for %s\n",
					 dep->name);
				ret = -EINVAL;
				break;
			case DEPEVT_TRANSFER_BUS_EXPIRY:
				/*
				 * SW issues START TRANSFER command to
				 * isochronous ep with future frame interval. If
				 * future interval time has already passed when
				 * core receives the command, it will respond
				 * with an error status of 'Bus Expiry'.
				 *
				 * Instead of always returning -EINVAL, let's
				 * give a hint to the gadget driver that this is
				 * the case by returning -EAGAIN.
				 */
				ret = -EAGAIN;
				break;
			default:
				dev_WARN(dwc->dev, "UNKNOWN cmd status\n");
			}

			break;
		}
	} while (--timeout);

	if (timeout == 0) {
		ret = -ETIMEDOUT;
		cmd_status = -ETIMEDOUT;
	}

	trace_dwc3_gadget_ep_cmd(dep, cmd, params, cmd_status);

	if (DWC3_DEPCMD_CMD(cmd) == DWC3_DEPCMD_STARTTRANSFER) {
		if (ret == 0)
			dep->flags |= DWC3_EP_TRANSFER_STARTED;

		if (ret != -ETIMEDOUT)
			dwc3_gadget_ep_get_transfer_index(dep);
	}

	if (saved_config) {
		reg = dwc3_readl(dwc->regs, DWC3_GUSB2PHYCFG(0));
		reg |= saved_config;
		dwc3_writel(dwc->regs, DWC3_GUSB2PHYCFG(0), reg);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(dwc3_send_gadget_ep_cmd);

static int dwc3_send_clear_stall_ep_cmd(struct dwc3_ep *dep)
{
	struct dwc3 *dwc = dep->dwc;
	struct dwc3_gadget_ep_cmd_params params;
	u32 cmd = DWC3_DEPCMD_CLEARSTALL;

	/*
	 * As of core revision 2.60a the recommended programming model
	 * is to set the ClearPendIN bit when issuing a Clear Stall EP
	 * command for IN endpoints. This is to prevent an issue where
	 * some (non-compliant) hosts may not send ACK TPs for pending
	 * IN transfers due to a mishandled error condition. Synopsys
	 * STAR 9000614252.
	 */
	if (dep->direction &&
	    !DWC3_VER_IS_PRIOR(DWC3, 260A) &&
	    (dwc->gadget->speed >= USB_SPEED_SUPER))
		cmd |= DWC3_DEPCMD_CLEARPENDIN;

	memset(&params, 0, sizeof(params));

	return dwc3_send_gadget_ep_cmd(dep, cmd, &params);
}

static dma_addr_t dwc3_trb_dma_offset(struct dwc3_ep *dep,
		struct dwc3_trb *trb)
{
	u32		offset = (char *) trb - (char *) dep->trb_pool;

	return dep->trb_pool_dma + offset;
}

static int dwc3_alloc_trb_pool(struct dwc3_ep *dep)
{
	struct dwc3		*dwc = dep->dwc;

	if (dep->trb_pool)
		return 0;

	dep->trb_pool = dma_alloc_coherent(dwc->sysdev,
			sizeof(struct dwc3_trb) * DWC3_TRB_NUM,
			&dep->trb_pool_dma, GFP_KERNEL);
	if (!dep->trb_pool) {
		dev_err(dep->dwc->dev, "failed to allocate trb pool for %s\n",
				dep->name);
		return -ENOMEM;
	}

	return 0;
}

static void dwc3_free_trb_pool(struct dwc3_ep *dep)
{
	struct dwc3		*dwc = dep->dwc;

	dma_free_coherent(dwc->sysdev, sizeof(struct dwc3_trb) * DWC3_TRB_NUM,
			dep->trb_pool, dep->trb_pool_dma);

	dep->trb_pool = NULL;
	dep->trb_pool_dma = 0;
}

static int dwc3_gadget_set_xfer_resource(struct dwc3_ep *dep)
{
	struct dwc3_gadget_ep_cmd_params params;

	memset(&params, 0x00, sizeof(params));

	params.param0 = DWC3_DEPXFERCFG_NUM_XFER_RES(1);

	return dwc3_send_gadget_ep_cmd(dep, DWC3_DEPCMD_SETTRANSFRESOURCE,
			&params);
}

/**
 * dwc3_gadget_start_config - configure ep resources
 * @dep: endpoint that is being enabled
 *
 * Issue a %DWC3_DEPCMD_DEPSTARTCFG command to @dep. After the command's
 * completion, it will set Transfer Resource for all available endpoints.
 *
 * The assignment of transfer resources cannot perfectly follow the data book
 * due to the fact that the controller driver does not have all knowledge of the
 * configuration in advance. It is given this information piecemeal by the
 * composite gadget framework after every SET_CONFIGURATION and
 * SET_INTERFACE. Trying to follow the databook programming model in this
 * scenario can cause errors. For two reasons:
 *
 * 1) The databook says to do %DWC3_DEPCMD_DEPSTARTCFG for every
 * %USB_REQ_SET_CONFIGURATION and %USB_REQ_SET_INTERFACE (8.1.5). This is
 * incorrect in the scenario of multiple interfaces.
 *
 * 2) The databook does not mention doing more %DWC3_DEPCMD_DEPXFERCFG for new
 * endpoint on alt setting (8.1.6).
 *
 * The following simplified method is used instead:
 *
 * All hardware endpoints can be assigned a transfer resource and this setting
 * will stay persistent until either a core reset or hibernation. So whenever we
 * do a %DWC3_DEPCMD_DEPSTARTCFG(0) we can go ahead and do
 * %DWC3_DEPCMD_DEPXFERCFG for every hardware endpoint as well. We are
 * guaranteed that there are as many transfer resources as endpoints.
 *
 * This function is called for each endpoint when it is being enabled but is
 * triggered only when called for EP0-out, which always happens first, and which
 * should only happen in one of the above conditions.
 */
static int dwc3_gadget_start_config(struct dwc3_ep *dep)
{
	struct dwc3_gadget_ep_cmd_params params;
	struct dwc3		*dwc;
	u32			cmd;
	int			i;
	int			ret;

	if (dep->number)
		return 0;

	memset(&params, 0x00, sizeof(params));
	cmd = DWC3_DEPCMD_DEPSTARTCFG;
	dwc = dep->dwc;

	ret = dwc3_send_gadget_ep_cmd(dep, cmd, &params);
	if (ret)
		return ret;

	for (i = 0; i < DWC3_ENDPOINTS_NUM; i++) {
		struct dwc3_ep *dep = dwc->eps[i];

		if (!dep)
			continue;

		ret = dwc3_gadget_set_xfer_resource(dep);
		if (ret)
			return ret;
	}

	return 0;
}

static int dwc3_gadget_set_ep_config(struct dwc3_ep *dep, unsigned int action)
{
	const struct usb_ss_ep_comp_descriptor *comp_desc;
	const struct usb_endpoint_descriptor *desc;
	struct dwc3_gadget_ep_cmd_params params;
	struct dwc3 *dwc = dep->dwc;

	comp_desc = dep->endpoint.comp_desc;
	desc = dep->endpoint.desc;

	memset(&params, 0x00, sizeof(params));

	params.param0 = DWC3_DEPCFG_EP_TYPE(usb_endpoint_type(desc))
		| DWC3_DEPCFG_MAX_PACKET_SIZE(usb_endpoint_maxp(desc));

	/* Burst size is only needed in SuperSpeed mode */
	if (dwc->gadget->speed >= USB_SPEED_SUPER) {
		u32 burst = dep->endpoint.maxburst;

		params.param0 |= DWC3_DEPCFG_BURST_SIZE(burst - 1);
	}

	params.param0 |= action;
	if (action == DWC3_DEPCFG_ACTION_RESTORE)
		params.param2 |= dep->saved_state;

	if (usb_endpoint_xfer_control(desc))
		params.param1 = DWC3_DEPCFG_XFER_COMPLETE_EN;

	if (dep->number <= 1 || usb_endpoint_xfer_isoc(desc))
		params.param1 |= DWC3_DEPCFG_XFER_NOT_READY_EN;

	if (usb_ss_max_streams(comp_desc) && usb_endpoint_xfer_bulk(desc)) {
		params.param1 |= DWC3_DEPCFG_STREAM_CAPABLE
			| DWC3_DEPCFG_XFER_COMPLETE_EN
			| DWC3_DEPCFG_STREAM_EVENT_EN;
		dep->stream_capable = true;
	}

	if (!usb_endpoint_xfer_control(desc))
		params.param1 |= DWC3_DEPCFG_XFER_IN_PROGRESS_EN;

	/*
	 * We are doing 1:1 mapping for endpoints, meaning
	 * Physical Endpoints 2 maps to Logical Endpoint 2 and
	 * so on. We consider the direction bit as part of the physical
	 * endpoint number. So USB endpoint 0x81 is 0x03.
	 */
	params.param1 |= DWC3_DEPCFG_EP_NUMBER(dep->number);

	/*
	 * We must use the lower 16 TX FIFOs even though
	 * HW might have more
	 */
	if (dep->direction)
		params.param0 |= DWC3_DEPCFG_FIFO_NUMBER(dep->number >> 1);

	if (desc->bInterval) {
		u8 bInterval_m1;

		/*
		 * Valid range for DEPCFG.bInterval_m1 is from 0 to 13.
		 *
		 * NOTE: The programming guide incorrectly stated bInterval_m1
		 * must be set to 0 when operating in fullspeed. Internally the
		 * controller does not have this limitation. See DWC_usb3x
		 * programming guide section 3.2.2.1.
		 */
		bInterval_m1 = min_t(u8, desc->bInterval - 1, 13);

		if (usb_endpoint_type(desc) == USB_ENDPOINT_XFER_INT &&
		    dwc->gadget->speed == USB_SPEED_FULL)
			dep->interval = desc->bInterval;
		else
			dep->interval = 1 << (desc->bInterval - 1);

		params.param1 |= DWC3_DEPCFG_BINTERVAL_M1(bInterval_m1);
	}

	return dwc3_send_gadget_ep_cmd(dep, DWC3_DEPCMD_SETEPCONFIG, &params);
}

/**
 * dwc3_gadget_calc_tx_fifo_size - calculates the txfifo size value
 * @dwc: pointer to the DWC3 context
 * @nfifos: number of fifos to calculate for
 *
 * Calculates the size value based on the equation below:
 *
 * DWC3 revision 280A and prior:
 * fifo_size = mult * (max_packet / mdwidth) + 1;
 *
 * DWC3 revision 290A and onwards:
 * fifo_size = mult * ((max_packet + mdwidth)/mdwidth + 1) + 1
 *
 * The max packet size is set to 1024, as the txfifo requirements mainly apply
 * to super speed USB use cases.  However, it is safe to overestimate the fifo
 * allocations for other scenarios, i.e. high speed USB.
 */
static int dwc3_gadget_calc_tx_fifo_size(struct dwc3 *dwc, int mult)
{
	int max_packet = 1024;
	int fifo_size;
	int mdwidth;

	mdwidth = dwc3_mdwidth(dwc);

	/* MDWIDTH is represented in bits, we need it in bytes */
	mdwidth >>= 3;

	if (DWC3_VER_IS_PRIOR(DWC3, 290A))
		fifo_size = mult * (max_packet / mdwidth) + 1;
	else
		fifo_size = mult * ((max_packet + mdwidth) / mdwidth) + 1;
	return fifo_size;
}

/**
 * dwc3_gadget_clear_tx_fifo_size - Clears txfifo allocation
 * @dwc: pointer to the DWC3 context
 *
 * Iterates through all the endpoint registers and clears the previous txfifo
 * allocations.
 */
void dwc3_gadget_clear_tx_fifos(struct dwc3 *dwc)
{
	struct dwc3_ep *dep;
	int fifo_depth;
	int size;
	int num;

	if (!dwc->do_fifo_resize)
		return;

	/* Read ep0IN related TXFIFO size */
	dep = dwc->eps[1];
	size = dwc3_readl(dwc->regs, DWC3_GTXFIFOSIZ(0));
	if (DWC3_IP_IS(DWC3))
		fifo_depth = DWC3_GTXFIFOSIZ_TXFDEP(size);
	else
		fifo_depth = DWC31_GTXFIFOSIZ_TXFDEP(size);

	dwc->last_fifo_depth = fifo_depth;
	/* Clear existing TXFIFO for all IN eps except ep0 */
	for (num = 3; num < min_t(int, dwc->num_eps, DWC3_ENDPOINTS_NUM);
	     num += 2) {
		dep = dwc->eps[num];
		/* Don't change TXFRAMNUM on usb31 version */
		size = DWC3_IP_IS(DWC3) ? 0 :
			dwc3_readl(dwc->regs, DWC3_GTXFIFOSIZ(num >> 1)) &
				   DWC31_GTXFIFOSIZ_TXFRAMNUM;

		dwc3_writel(dwc->regs, DWC3_GTXFIFOSIZ(num >> 1), size);
		dep->flags &= ~DWC3_EP_TXFIFO_RESIZED;
	}
	dwc->num_ep_resized = 0;
}

/*
 * dwc3_gadget_resize_tx_fifos - reallocate fifo spaces for current use-case
 * @dwc: pointer to our context structure
 *
 * This function will a best effort FIFO allocation in order
 * to improve FIFO usage and throughput, while still allowing
 * us to enable as many endpoints as possible.
 *
 * Keep in mind that this operation will be highly dependent
 * on the configured size for RAM1 - which contains TxFifo -,
 * the amount of endpoints enabled on coreConsultant tool, and
 * the width of the Master Bus.
 *
 * In general, FIFO depths are represented with the following equation:
 *
 * fifo_size = mult * ((max_packet + mdwidth)/mdwidth + 1) + 1
 *
 * In conjunction with dwc3_gadget_check_config(), this resizing logic will
 * ensure that all endpoints will have enough internal memory for one max
 * packet per endpoint.
 */
static int dwc3_gadget_resize_tx_fifos(struct dwc3_ep *dep)
{
	struct dwc3 *dwc = dep->dwc;
	int fifo_0_start;
	int ram1_depth;
	int fifo_size;
	int min_depth;
	int num_in_ep;
	int remaining;
	int num_fifos = 1;
	int fifo;
	int tmp;

	if (!dwc->do_fifo_resize)
		return 0;

	/* resize IN endpoints except ep0 */
	if (!usb_endpoint_dir_in(dep->endpoint.desc) || dep->number <= 1)
		return 0;

	/* bail if already resized */
	if (dep->flags & DWC3_EP_TXFIFO_RESIZED)
		return 0;

	ram1_depth = DWC3_RAM1_DEPTH(dwc->hwparams.hwparams7);

	if ((dep->endpoint.maxburst > 1 &&
	     usb_endpoint_xfer_bulk(dep->endpoint.desc)) ||
	    usb_endpoint_xfer_isoc(dep->endpoint.desc))
		num_fifos = 3;

	if (dep->endpoint.maxburst > 6 &&
	    usb_endpoint_xfer_bulk(dep->endpoint.desc) && DWC3_IP_IS(DWC31))
		num_fifos = dwc->tx_fifo_resize_max_num;

	/* FIFO size for a single buffer */
	fifo = dwc3_gadget_calc_tx_fifo_size(dwc, 1);

	/* Calculate the number of remaining EPs w/o any FIFO */
	num_in_ep = dwc->max_cfg_eps;
	num_in_ep -= dwc->num_ep_resized;

	/* Reserve at least one FIFO for the number of IN EPs */
	min_depth = num_in_ep * (fifo + 1);
	remaining = ram1_depth - min_depth - dwc->last_fifo_depth;
	remaining = max_t(int, 0, remaining);
	/*
	 * We've already reserved 1 FIFO per EP, so check what we can fit in
	 * addition to it.  If there is not enough remaining space, allocate
	 * all the remaining space to the EP.
	 */
	fifo_size = (num_fifos - 1) * fifo;
	if (remaining < fifo_size)
		fifo_size = remaining;

	fifo_size += fifo;
	/* Last increment according to the TX FIFO size equation */
	fifo_size++;

	/* Check if TXFIFOs start at non-zero addr */
	tmp = dwc3_readl(dwc->regs, DWC3_GTXFIFOSIZ(0));
	fifo_0_start = DWC3_GTXFIFOSIZ_TXFSTADDR(tmp);

	fifo_size |= (fifo_0_start + (dwc->last_fifo_depth << 16));
	if (DWC3_IP_IS(DWC3))
		dwc->last_fifo_depth += DWC3_GTXFIFOSIZ_TXFDEP(fifo_size);
	else
		dwc->last_fifo_depth += DWC31_GTXFIFOSIZ_TXFDEP(fifo_size);

	/* Check fifo size allocation doesn't exceed available RAM size. */
	if (dwc->last_fifo_depth >= ram1_depth) {
		dev_err(dwc->dev, "Fifosize(%d) > RAM size(%d) %s depth:%d\n",
			dwc->last_fifo_depth, ram1_depth,
			dep->endpoint.name, fifo_size);
		if (DWC3_IP_IS(DWC3))
			fifo_size = DWC3_GTXFIFOSIZ_TXFDEP(fifo_size);
		else
			fifo_size = DWC31_GTXFIFOSIZ_TXFDEP(fifo_size);

		dwc->last_fifo_depth -= fifo_size;
		return -ENOMEM;
	}

	dwc3_writel(dwc->regs, DWC3_GTXFIFOSIZ(dep->number >> 1), fifo_size);
	dep->flags |= DWC3_EP_TXFIFO_RESIZED;
	dwc->num_ep_resized++;

	return 0;
}

/**
 * __dwc3_gadget_ep_enable - initializes a hw endpoint
 * @dep: endpoint to be initialized
 * @action: one of INIT, MODIFY or RESTORE
 *
 * Caller should take care of locking. Execute all necessary commands to
 * initialize a HW endpoint so it can be used by a gadget driver.
 */
static int __dwc3_gadget_ep_enable(struct dwc3_ep *dep, unsigned int action)
{
	const struct usb_endpoint_descriptor *desc = dep->endpoint.desc;
	struct dwc3		*dwc = dep->dwc;

	u32			reg;
	int			ret;

	if (!(dep->flags & DWC3_EP_ENABLED)) {
		ret = dwc3_gadget_resize_tx_fifos(dep);
		if (ret)
			return ret;

		ret = dwc3_gadget_start_config(dep);
		if (ret)
			return ret;
	}

	ret = dwc3_gadget_set_ep_config(dep, action);
	if (ret)
		return ret;

	if (!(dep->flags & DWC3_EP_ENABLED)) {
		struct dwc3_trb	*trb_st_hw;
		struct dwc3_trb	*trb_link;

		dep->type = usb_endpoint_type(desc);
		dep->flags |= DWC3_EP_ENABLED;

		reg = dwc3_readl(dwc->regs, DWC3_DALEPENA);
		reg |= DWC3_DALEPENA_EP(dep->number);
		dwc3_writel(dwc->regs, DWC3_DALEPENA, reg);

		if (usb_endpoint_xfer_control(desc))
			goto out;

		/* Initialize the TRB ring */
		dep->trb_dequeue = 0;
		dep->trb_enqueue = 0;
		memset(dep->trb_pool, 0,
		       sizeof(struct dwc3_trb) * DWC3_TRB_NUM);

		/* Link TRB. The HWO bit is never reset */
		trb_st_hw = &dep->trb_pool[0];

		trb_link = &dep->trb_pool[DWC3_TRB_NUM - 1];
		trb_link->bpl = lower_32_bits(dwc3_trb_dma_offset(dep, trb_st_hw));
		trb_link->bph = upper_32_bits(dwc3_trb_dma_offset(dep, trb_st_hw));
		trb_link->ctrl |= DWC3_TRBCTL_LINK_TRB;
		trb_link->ctrl |= DWC3_TRB_CTRL_HWO;
	}

	/*
	 * Issue StartTransfer here with no-op TRB so we can always rely on No
	 * Response Update Transfer command.
	 */
	if (usb_endpoint_xfer_bulk(desc) ||
			usb_endpoint_xfer_int(desc)) {
		struct dwc3_gadget_ep_cmd_params params;
		struct dwc3_trb	*trb;
		dma_addr_t trb_dma;
		u32 cmd;

		memset(&params, 0, sizeof(params));
		trb = &dep->trb_pool[0];
		trb_dma = dwc3_trb_dma_offset(dep, trb);

		params.param0 = upper_32_bits(trb_dma);
		params.param1 = lower_32_bits(trb_dma);

		cmd = DWC3_DEPCMD_STARTTRANSFER;

		ret = dwc3_send_gadget_ep_cmd(dep, cmd, &params);
		if (ret < 0)
			return ret;

		if (dep->stream_capable) {
			/*
			 * For streams, at start, there maybe a race where the
			 * host primes the endpoint before the function driver
			 * queues a request to initiate a stream. In that case,
			 * the controller will not see the prime to generate the
			 * ERDY and start stream. To workaround this, issue a
			 * no-op TRB as normal, but end it immediately. As a
			 * result, when the function driver queues the request,
			 * the next START_TRANSFER command will cause the
			 * controller to generate an ERDY to initiate the
			 * stream.
			 */
			dwc3_stop_active_transfer(dep, true, true);

			/*
			 * All stream eps will reinitiate stream on NoStream
			 * rejection until we can determine that the host can
			 * prime after the first transfer.
			 *
			 * However, if the controller is capable of
			 * TXF_FLUSH_BYPASS, then IN direction endpoints will
			 * automatically restart the stream without the driver
			 * initiation.
			 */
			if (!dep->direction ||
			    !(dwc->hwparams.hwparams9 &
			      DWC3_GHWPARAMS9_DEV_TXF_FLUSH_BYPASS))
				dep->flags |= DWC3_EP_FORCE_RESTART_STREAM;
		}
	}

out:
	trace_dwc3_gadget_ep_enable(dep);

	return 0;
}

static void dwc3_remove_requests(struct dwc3 *dwc, struct dwc3_ep *dep)
{
	struct dwc3_request		*req;

	dwc3_stop_active_transfer(dep, true, false);

	/* - giveback all requests to gadget driver */
	while (!list_empty(&dep->started_list)) {
		req = next_request(&dep->started_list);

		dwc3_gadget_giveback(dep, req, -ESHUTDOWN);
	}

	while (!list_empty(&dep->pending_list)) {
		req = next_request(&dep->pending_list);

		dwc3_gadget_giveback(dep, req, -ESHUTDOWN);
	}

	while (!list_empty(&dep->cancelled_list)) {
		req = next_request(&dep->cancelled_list);

		dwc3_gadget_giveback(dep, req, -ESHUTDOWN);
	}
}

/**
 * __dwc3_gadget_ep_disable - disables a hw endpoint
 * @dep: the endpoint to disable
 *
 * This function undoes what __dwc3_gadget_ep_enable did and also removes
 * requests which are currently being processed by the hardware and those which
 * are not yet scheduled.
 *
 * Caller should take care of locking.
 */
static int __dwc3_gadget_ep_disable(struct dwc3_ep *dep)
{
	struct dwc3		*dwc = dep->dwc;
	u32			reg;

	trace_dwc3_gadget_ep_disable(dep);

	/* make sure HW endpoint isn't stalled */
	if (dep->flags & DWC3_EP_STALL)
		__dwc3_gadget_ep_set_halt(dep, 0, false);

	reg = dwc3_readl(dwc->regs, DWC3_DALEPENA);
	reg &= ~DWC3_DALEPENA_EP(dep->number);
	dwc3_writel(dwc->regs, DWC3_DALEPENA, reg);

	/* Clear out the ep descriptors for non-ep0 */
	if (dep->number > 1) {
		dep->endpoint.comp_desc = NULL;
		dep->endpoint.desc = NULL;
	}

	dwc3_remove_requests(dwc, dep);

	dep->stream_capable = false;
	dep->type = 0;
	dep->flags &= DWC3_EP_TXFIFO_RESIZED;

	return 0;
}

/* -------------------------------------------------------------------------- */

static int dwc3_gadget_ep0_enable(struct usb_ep *ep,
		const struct usb_endpoint_descriptor *desc)
{
	return -EINVAL;
}

static int dwc3_gadget_ep0_disable(struct usb_ep *ep)
{
	return -EINVAL;
}

/* -------------------------------------------------------------------------- */

static int dwc3_gadget_ep_enable(struct usb_ep *ep,
		const struct usb_endpoint_descriptor *desc)
{
	struct dwc3_ep			*dep;
	struct dwc3			*dwc;
	unsigned long			flags;
	int				ret;

	if (!ep || !desc || desc->bDescriptorType != USB_DT_ENDPOINT) {
		pr_debug("dwc3: invalid parameters\n");
		return -EINVAL;
	}

	if (!desc->wMaxPacketSize) {
		pr_debug("dwc3: missing wMaxPacketSize\n");
		return -EINVAL;
	}

	dep = to_dwc3_ep(ep);
	dwc = dep->dwc;

	if (dev_WARN_ONCE(dwc->dev, dep->flags & DWC3_EP_ENABLED,
					"%s is already enabled\n",
					dep->name))
		return 0;

	spin_lock_irqsave(&dwc->lock, flags);
	ret = __dwc3_gadget_ep_enable(dep, DWC3_DEPCFG_ACTION_INIT);
	spin_unlock_irqrestore(&dwc->lock, flags);

	return ret;
}

static int dwc3_gadget_ep_disable(struct usb_ep *ep)
{
	struct dwc3_ep			*dep;
	struct dwc3			*dwc;
	unsigned long			flags;
	int				ret;

	if (!ep) {
		pr_debug("dwc3: invalid parameters\n");
		return -EINVAL;
	}

	dep = to_dwc3_ep(ep);
	dwc = dep->dwc;

	if (dev_WARN_ONCE(dwc->dev, !(dep->flags & DWC3_EP_ENABLED),
					"%s is already disabled\n",
					dep->name))
		return 0;

	spin_lock_irqsave(&dwc->lock, flags);
	ret = __dwc3_gadget_ep_disable(dep);
	spin_unlock_irqrestore(&dwc->lock, flags);

	return ret;
}

static struct usb_request *dwc3_gadget_ep_alloc_request(struct usb_ep *ep,
		gfp_t gfp_flags)
{
	struct dwc3_request		*req;
	struct dwc3_ep			*dep = to_dwc3_ep(ep);

	req = kzalloc(sizeof(*req), gfp_flags);
	if (!req)
		return NULL;

	req->direction	= dep->direction;
	req->epnum	= dep->number;
	req->dep	= dep;
	req->status	= DWC3_REQUEST_STATUS_UNKNOWN;

	trace_dwc3_alloc_request(req);

	return &req->request;
}

static void dwc3_gadget_ep_free_request(struct usb_ep *ep,
		struct usb_request *request)
{
	struct dwc3_request		*req = to_dwc3_request(request);

	trace_dwc3_free_request(req);
	kfree(req);
}

/**
 * dwc3_ep_prev_trb - returns the previous TRB in the ring
 * @dep: The endpoint with the TRB ring
 * @index: The index of the current TRB in the ring
 *
 * Returns the TRB prior to the one pointed to by the index. If the
 * index is 0, we will wrap backwards, skip the link TRB, and return
 * the one just before that.
 */
static struct dwc3_trb *dwc3_ep_prev_trb(struct dwc3_ep *dep, u8 index)
{
	u8 tmp = index;

	if (!tmp)
		tmp = DWC3_TRB_NUM - 1;

	return &dep->trb_pool[tmp - 1];
}

static u32 dwc3_calc_trbs_left(struct dwc3_ep *dep)
{
	u8			trbs_left;

	/*
	 * If the enqueue & dequeue are equal then the TRB ring is either full
	 * or empty. It's considered full when there are DWC3_TRB_NUM-1 of TRBs
	 * pending to be processed by the driver.
	 */
	if (dep->trb_enqueue == dep->trb_dequeue) {
		/*
		 * If there is any request remained in the started_list at
		 * this point, that means there is no TRB available.
		 */
		if (!list_empty(&dep->started_list))
			return 0;

		return DWC3_TRB_NUM - 1;
	}

	trbs_left = dep->trb_dequeue - dep->trb_enqueue;
	trbs_left &= (DWC3_TRB_NUM - 1);

	if (dep->trb_dequeue < dep->trb_enqueue)
		trbs_left--;

	return trbs_left;
}

static void __dwc3_prepare_one_trb(struct dwc3_ep *dep, struct dwc3_trb *trb,
		dma_addr_t dma, unsigned int length, unsigned int chain,
		unsigned int node, unsigned int stream_id,
		unsigned int short_not_ok, unsigned int no_interrupt,
		unsigned int is_last, bool must_interrupt)
{
	struct dwc3		*dwc = dep->dwc;
	struct usb_gadget	*gadget = dwc->gadget;
	enum usb_device_speed	speed = gadget->speed;

	trb->size = DWC3_TRB_SIZE_LENGTH(length);
	trb->bpl = lower_32_bits(dma);
	trb->bph = upper_32_bits(dma);

	switch (usb_endpoint_type(dep->endpoint.desc)) {
	case USB_ENDPOINT_XFER_CONTROL:
		trb->ctrl = DWC3_TRBCTL_CONTROL_SETUP;
		break;

	case USB_ENDPOINT_XFER_ISOC:
		if (!node) {
			trb->ctrl = DWC3_TRBCTL_ISOCHRONOUS_FIRST;

			/*
			 * USB Specification 2.0 Section 5.9.2 states that: "If
			 * there is only a single transaction in the microframe,
			 * only a DATA0 data packet PID is used.  If there are
			 * two transactions per microframe, DATA1 is used for
			 * the first transaction data packet and DATA0 is used
			 * for the second transaction data packet.  If there are
			 * three transactions per microframe, DATA2 is used for
			 * the first transaction data packet, DATA1 is used for
			 * the second, and DATA0 is used for the third."
			 *
			 * IOW, we should satisfy the following cases:
			 *
			 * 1) length <= maxpacket
			 *	- DATA0
			 *
			 * 2) maxpacket < length <= (2 * maxpacket)
			 *	- DATA1, DATA0
			 *
			 * 3) (2 * maxpacket) < length <= (3 * maxpacket)
			 *	- DATA2, DATA1, DATA0
			 */
			if (speed == USB_SPEED_HIGH) {
				struct usb_ep *ep = &dep->endpoint;
				unsigned int mult = 2;
				unsigned int maxp = usb_endpoint_maxp(ep->desc);

				if (length <= (2 * maxp))
					mult--;

				if (length <= maxp)
					mult--;

				trb->size |= DWC3_TRB_SIZE_PCM1(mult);
			}
		} else {
			trb->ctrl = DWC3_TRBCTL_ISOCHRONOUS;
		}

		/* always enable Interrupt on Missed ISOC */
		trb->ctrl |= DWC3_TRB_CTRL_ISP_IMI;
		break;

	case USB_ENDPOINT_XFER_BULK:
	case USB_ENDPOINT_XFER_INT:
		trb->ctrl = DWC3_TRBCTL_NORMAL;
		break;
	default:
		/*
		 * This is only possible with faulty memory because we
		 * checked it already :)
		 */
		dev_WARN(dwc->dev, "Unknown endpoint type %d\n",
				usb_endpoint_type(dep->endpoint.desc));
	}

	/*
	 * Enable Continue on Short Packet
	 * when endpoint is not a stream capable
	 */
	if (usb_endpoint_dir_out(dep->endpoint.desc)) {
		if (!dep->stream_capable)
			trb->ctrl |= DWC3_TRB_CTRL_CSP;

		if (short_not_ok)
			trb->ctrl |= DWC3_TRB_CTRL_ISP_IMI;
	}

	if ((!no_interrupt && !chain) || must_interrupt)
		trb->ctrl |= DWC3_TRB_CTRL_IOC;

	if (chain)
		trb->ctrl |= DWC3_TRB_CTRL_CHN;
	else if (dep->stream_capable && is_last)
		trb->ctrl |= DWC3_TRB_CTRL_LST;

	if (usb_endpoint_xfer_bulk(dep->endpoint.desc) && dep->stream_capable)
		trb->ctrl |= DWC3_TRB_CTRL_SID_SOFN(stream_id);

	trb->ctrl |= DWC3_TRB_CTRL_HWO;

	dwc3_ep_inc_enq(dep);

	trace_dwc3_prepare_trb(dep, trb);
}

/**
 * dwc3_prepare_one_trb - setup one TRB from one request
 * @dep: endpoint for which this request is prepared
 * @req: dwc3_request pointer
 * @trb_length: buffer size of the TRB
 * @chain: should this TRB be chained to the next?
 * @node: only for isochronous endpoints. First TRB needs different type.
 * @use_bounce_buffer: set to use bounce buffer
 * @must_interrupt: set to interrupt on TRB completion
 */
static void dwc3_prepare_one_trb(struct dwc3_ep *dep,
		struct dwc3_request *req, unsigned int trb_length,
		unsigned int chain, unsigned int node, bool use_bounce_buffer,
		bool must_interrupt)
{
	struct dwc3_trb		*trb;
	dma_addr_t		dma;
	unsigned int		stream_id = req->request.stream_id;
	unsigned int		short_not_ok = req->request.short_not_ok;
	unsigned int		no_interrupt = req->request.no_interrupt;
	unsigned int		is_last = req->request.is_last;

	if (use_bounce_buffer)
		dma = dep->dwc->bounce_addr;
	else if (req->request.num_sgs > 0)
		dma = sg_dma_address(req->start_sg);
	else
		dma = req->request.dma;

	trb = &dep->trb_pool[dep->trb_enqueue];

	if (!req->trb) {
		dwc3_gadget_move_started_request(req);
		req->trb = trb;
		req->trb_dma = dwc3_trb_dma_offset(dep, trb);
	}

	req->num_trbs++;

	__dwc3_prepare_one_trb(dep, trb, dma, trb_length, chain, node,
			stream_id, short_not_ok, no_interrupt, is_last,
			must_interrupt);
}

static bool dwc3_needs_extra_trb(struct dwc3_ep *dep, struct dwc3_request *req)
{
	unsigned int maxp = usb_endpoint_maxp(dep->endpoint.desc);
	unsigned int rem = req->request.length % maxp;

	if ((req->request.length && req->request.zero && !rem &&
			!usb_endpoint_xfer_isoc(dep->endpoint.desc)) ||
			(!req->direction && rem))
		return true;

	return false;
}

/**
 * dwc3_prepare_last_sg - prepare TRBs for the last SG entry
 * @dep: The endpoint that the request belongs to
 * @req: The request to prepare
 * @entry_length: The last SG entry size
 * @node: Indicates whether this is not the first entry (for isoc only)
 *
 * Return the number of TRBs prepared.
 */
static int dwc3_prepare_last_sg(struct dwc3_ep *dep,
		struct dwc3_request *req, unsigned int entry_length,
		unsigned int node)
{
	unsigned int maxp = usb_endpoint_maxp(dep->endpoint.desc);
	unsigned int rem = req->request.length % maxp;
	unsigned int num_trbs = 1;

	if (dwc3_needs_extra_trb(dep, req))
		num_trbs++;

	if (dwc3_calc_trbs_left(dep) < num_trbs)
		return 0;

	req->needs_extra_trb = num_trbs > 1;

	/* Prepare a normal TRB */
	if (req->direction || req->request.length)
		dwc3_prepare_one_trb(dep, req, entry_length,
				req->needs_extra_trb, node, false, false);

	/* Prepare extra TRBs for ZLP and MPS OUT transfer alignment */
	if ((!req->direction && !req->request.length) || req->needs_extra_trb)
		dwc3_prepare_one_trb(dep, req,
				req->direction ? 0 : maxp - rem,
				false, 1, true, false);

	return num_trbs;
}

static int dwc3_prepare_trbs_sg(struct dwc3_ep *dep,
		struct dwc3_request *req)
{
	struct scatterlist *sg = req->start_sg;
	struct scatterlist *s;
	int		i;
	unsigned int length = req->request.length;
	unsigned int remaining = req->request.num_mapped_sgs
		- req->num_queued_sgs;
	unsigned int num_trbs = req->num_trbs;
	bool needs_extra_trb = dwc3_needs_extra_trb(dep, req);

	/*
	 * If we resume preparing the request, then get the remaining length of
	 * the request and resume where we left off.
	 */
	for_each_sg(req->request.sg, s, req->num_queued_sgs, i)
		length -= sg_dma_len(s);

	for_each_sg(sg, s, remaining, i) {
		unsigned int num_trbs_left = dwc3_calc_trbs_left(dep);
		unsigned int trb_length;
		bool must_interrupt = false;
		bool last_sg = false;

		trb_length = min_t(unsigned int, length, sg_dma_len(s));

		length -= trb_length;

		/*
		 * IOMMU driver is coalescing the list of sgs which shares a
		 * page boundary into one and giving it to USB driver. With
		 * this the number of sgs mapped is not equal to the number of
		 * sgs passed. So mark the chain bit to false if it isthe last
		 * mapped sg.
		 */
		if ((i == remaining - 1) || !length)
			last_sg = true;

		if (!num_trbs_left)
			break;

		if (last_sg) {
			if (!dwc3_prepare_last_sg(dep, req, trb_length, i))
				break;
		} else {
			/*
			 * Look ahead to check if we have enough TRBs for the
			 * next SG entry. If not, set interrupt on this TRB to
			 * resume preparing the next SG entry when more TRBs are
			 * free.
			 */
			if (num_trbs_left == 1 || (needs_extra_trb &&
					num_trbs_left <= 2 &&
					sg_dma_len(sg_next(s)) >= length))
				must_interrupt = true;

			dwc3_prepare_one_trb(dep, req, trb_length, 1, i, false,
					must_interrupt);
		}

		/*
		 * There can be a situation where all sgs in sglist are not
		 * queued because of insufficient trb number. To handle this
		 * case, update start_sg to next sg to be queued, so that
		 * we have free trbs we can continue queuing from where we
		 * previously stopped
		 */
		if (!last_sg)
			req->start_sg = sg_next(s);

		req->num_queued_sgs++;
		req->num_pending_sgs--;

		/*
		 * The number of pending SG entries may not correspond to the
		 * number of mapped SG entries. If all the data are queued, then
		 * don't include unused SG entries.
		 */
		if (length == 0) {
			req->num_pending_sgs = 0;
			break;
		}

		if (must_interrupt)
			break;
	}

	return req->num_trbs - num_trbs;
}

static int dwc3_prepare_trbs_linear(struct dwc3_ep *dep,
		struct dwc3_request *req)
{
	return dwc3_prepare_last_sg(dep, req, req->request.length, 0);
}

/*
 * dwc3_prepare_trbs - setup TRBs from requests
 * @dep: endpoint for which requests are being prepared
 *
 * The function goes through the requests list and sets up TRBs for the
 * transfers. The function returns once there are no more TRBs available or
 * it runs out of requests.
 *
 * Returns the number of TRBs prepared or negative errno.
 */
static int dwc3_prepare_trbs(struct dwc3_ep *dep)
{
	struct dwc3_request	*req, *n;
	int			ret = 0;

	BUILD_BUG_ON_NOT_POWER_OF_2(DWC3_TRB_NUM);

	/*
	 * We can get in a situation where there's a request in the started list
	 * but there weren't enough TRBs to fully kick it in the first time
	 * around, so it has been waiting for more TRBs to be freed up.
	 *
	 * In that case, we should check if we have a request with pending_sgs
	 * in the started list and prepare TRBs for that request first,
	 * otherwise we will prepare TRBs completely out of order and that will
	 * break things.
	 */
	list_for_each_entry(req, &dep->started_list, list) {
		if (req->num_pending_sgs > 0) {
			ret = dwc3_prepare_trbs_sg(dep, req);
			if (!ret || req->num_pending_sgs)
				return ret;
		}

		if (!dwc3_calc_trbs_left(dep))
			return ret;

		/*
		 * Don't prepare beyond a transfer. In DWC_usb32, its transfer
		 * burst capability may try to read and use TRBs beyond the
		 * active transfer instead of stopping.
		 */
		if (dep->stream_capable && req->request.is_last)
			return ret;
	}

	list_for_each_entry_safe(req, n, &dep->pending_list, list) {
		struct dwc3	*dwc = dep->dwc;

		ret = usb_gadget_map_request_by_dev(dwc->sysdev, &req->request,
						    dep->direction);
		if (ret)
			return ret;

		req->sg			= req->request.sg;
		req->start_sg		= req->sg;
		req->num_queued_sgs	= 0;
		req->num_pending_sgs	= req->request.num_mapped_sgs;

		if (req->num_pending_sgs > 0) {
			ret = dwc3_prepare_trbs_sg(dep, req);
			if (req->num_pending_sgs)
				return ret;
		} else {
			ret = dwc3_prepare_trbs_linear(dep, req);
		}

		if (!ret || !dwc3_calc_trbs_left(dep))
			return ret;

		/*
		 * Don't prepare beyond a transfer. In DWC_usb32, its transfer
		 * burst capability may try to read and use TRBs beyond the
		 * active transfer instead of stopping.
		 */
		if (dep->stream_capable && req->request.is_last)
			return ret;
	}

	return ret;
}

static void dwc3_gadget_ep_cleanup_cancelled_requests(struct dwc3_ep *dep);

static int __dwc3_gadget_kick_transfer(struct dwc3_ep *dep)
{
	struct dwc3_gadget_ep_cmd_params params;
	struct dwc3_request		*req;
	int				starting;
	int				ret;
	u32				cmd;

	/*
	 * Note that it's normal to have no new TRBs prepared (i.e. ret == 0).
	 * This happens when we need to stop and restart a transfer such as in
	 * the case of reinitiating a stream or retrying an isoc transfer.
	 */
	ret = dwc3_prepare_trbs(dep);
	if (ret < 0)
		return ret;

	starting = !(dep->flags & DWC3_EP_TRANSFER_STARTED);

	/*
	 * If there's no new TRB prepared and we don't need to restart a
	 * transfer, there's no need to update the transfer.
	 */
	if (!ret && !starting)
		return ret;

	req = next_request(&dep->started_list);
	if (!req) {
		dep->flags |= DWC3_EP_PENDING_REQUEST;
		return 0;
	}

	memset(&params, 0, sizeof(params));

	if (starting) {
		params.param0 = upper_32_bits(req->trb_dma);
		params.param1 = lower_32_bits(req->trb_dma);
		cmd = DWC3_DEPCMD_STARTTRANSFER;

		if (dep->stream_capable)
			cmd |= DWC3_DEPCMD_PARAM(req->request.stream_id);

		if (usb_endpoint_xfer_isoc(dep->endpoint.desc))
			cmd |= DWC3_DEPCMD_PARAM(dep->frame_number);
	} else {
		cmd = DWC3_DEPCMD_UPDATETRANSFER |
			DWC3_DEPCMD_PARAM(dep->resource_index);
	}

	ret = dwc3_send_gadget_ep_cmd(dep, cmd, &params);
	if (ret < 0) {
		struct dwc3_request *tmp;

		if (ret == -EAGAIN)
			return ret;

		dwc3_stop_active_transfer(dep, true, true);

		list_for_each_entry_safe(req, tmp, &dep->started_list, list)
			dwc3_gadget_move_cancelled_request(req, DWC3_REQUEST_STATUS_DEQUEUED);

		/* If ep isn't started, then there's no end transfer pending */
		if (!(dep->flags & DWC3_EP_END_TRANSFER_PENDING))
			dwc3_gadget_ep_cleanup_cancelled_requests(dep);

		return ret;
	}

	if (dep->stream_capable && req->request.is_last)
		dep->flags |= DWC3_EP_WAIT_TRANSFER_COMPLETE;

	return 0;
}

static int __dwc3_gadget_get_frame(struct dwc3 *dwc)
{
	u32			reg;

	reg = dwc3_readl(dwc->regs, DWC3_DSTS);
	return DWC3_DSTS_SOFFN(reg);
}

/**
 * dwc3_gadget_start_isoc_quirk - workaround invalid frame number
 * @dep: isoc endpoint
 *
 * This function tests for the correct combination of BIT[15:14] from the 16-bit
 * microframe number reported by the XferNotReady event for the future frame
 * number to start the isoc transfer.
 *
 * In DWC_usb31 version 1.70a-ea06 and prior, for highspeed and fullspeed
 * isochronous IN, BIT[15:14] of the 16-bit microframe number reported by the
 * XferNotReady event are invalid. The driver uses this number to schedule the
 * isochronous transfer and passes it to the START TRANSFER command. Because
 * this number is invalid, the command may fail. If BIT[15:14] matches the
 * internal 16-bit microframe, the START TRANSFER command will pass and the
 * transfer will start at the scheduled time, if it is off by 1, the command
 * will still pass, but the transfer will start 2 seconds in the future. For all
 * other conditions, the START TRANSFER command will fail with bus-expiry.
 *
 * In order to workaround this issue, we can test for the correct combination of
 * BIT[15:14] by sending START TRANSFER commands with different values of
 * BIT[15:14]: 'b00, 'b01, 'b10, and 'b11. Each combination is 2^14 uframe apart
 * (or 2 seconds). 4 seconds into the future will result in a bus-expiry status.
 * As the result, within the 4 possible combinations for BIT[15:14], there will
 * be 2 successful and 2 failure START COMMAND status. One of the 2 successful
 * command status will result in a 2-second delay start. The smaller BIT[15:14]
 * value is the correct combination.
 *
 * Since there are only 4 outcomes and the results are ordered, we can simply
 * test 2 START TRANSFER commands with BIT[15:14] combinations 'b00 and 'b01 to
 * deduce the smaller successful combination.
 *
 * Let test0 = test status for combination 'b00 and test1 = test status for 'b01
 * of BIT[15:14]. The correct combination is as follow:
 *
 * if test0 fails and test1 passes, BIT[15:14] is 'b01
 * if test0 fails and test1 fails, BIT[15:14] is 'b10
 * if test0 passes and test1 fails, BIT[15:14] is 'b11
 * if test0 passes and test1 passes, BIT[15:14] is 'b00
 *
 * Synopsys STAR 9001202023: Wrong microframe number for isochronous IN
 * endpoints.
 */
static int dwc3_gadget_start_isoc_quirk(struct dwc3_ep *dep)
{
	int cmd_status = 0;
	bool test0;
	bool test1;

	while (dep->combo_num < 2) {
		struct dwc3_gadget_ep_cmd_params params;
		u32 test_frame_number;
		u32 cmd;

		/*
		 * Check if we can start isoc transfer on the next interval or
		 * 4 uframes in the future with BIT[15:14] as dep->combo_num
		 */
		test_frame_number = dep->frame_number & DWC3_FRNUMBER_MASK;
		test_frame_number |= dep->combo_num << 14;
		test_frame_number += max_t(u32, 4, dep->interval);

		params.param0 = upper_32_bits(dep->dwc->bounce_addr);
		params.param1 = lower_32_bits(dep->dwc->bounce_addr);

		cmd = DWC3_DEPCMD_STARTTRANSFER;
		cmd |= DWC3_DEPCMD_PARAM(test_frame_number);
		cmd_status = dwc3_send_gadget_ep_cmd(dep, cmd, &params);

		/* Redo if some other failure beside bus-expiry is received */
		if (cmd_status && cmd_status != -EAGAIN) {
			dep->start_cmd_status = 0;
			dep->combo_num = 0;
			return 0;
		}

		/* Store the first test status */
		if (dep->combo_num == 0)
			dep->start_cmd_status = cmd_status;

		dep->combo_num++;

		/*
		 * End the transfer if the START_TRANSFER command is successful
		 * to wait for the next XferNotReady to test the command again
		 */
		if (cmd_status == 0) {
			dwc3_stop_active_transfer(dep, true, true);
			return 0;
		}
	}

	/* test0 and test1 are both completed at this point */
	test0 = (dep->start_cmd_status == 0);
	test1 = (cmd_status == 0);

	if (!test0 && test1)
		dep->combo_num = 1;
	else if (!test0 && !test1)
		dep->combo_num = 2;
	else if (test0 && !test1)
		dep->combo_num = 3;
	else if (test0 && test1)
		dep->combo_num = 0;

	dep->frame_number &= DWC3_FRNUMBER_MASK;
	dep->frame_number |= dep->combo_num << 14;
	dep->frame_number += max_t(u32, 4, dep->interval);

	/* Reinitialize test variables */
	dep->start_cmd_status = 0;
	dep->combo_num = 0;

	return __dwc3_gadget_kick_transfer(dep);
}

static int __dwc3_gadget_start_isoc(struct dwc3_ep *dep)
{
	const struct usb_endpoint_descriptor *desc = dep->endpoint.desc;
	struct dwc3 *dwc = dep->dwc;
	int ret;
	int i;

	if (list_empty(&dep->pending_list) &&
	    list_empty(&dep->started_list)) {
		dep->flags |= DWC3_EP_PENDING_REQUEST;
		return -EAGAIN;
	}

	if (!dwc->dis_start_transfer_quirk &&
	    (DWC3_VER_IS_PRIOR(DWC31, 170A) ||
	     DWC3_VER_TYPE_IS_WITHIN(DWC31, 170A, EA01, EA06))) {
		if (dwc->gadget->speed <= USB_SPEED_HIGH && dep->direction)
			return dwc3_gadget_start_isoc_quirk(dep);
	}

	if (desc->bInterval <= 14 &&
	    dwc->gadget->speed >= USB_SPEED_HIGH) {
		u32 frame = __dwc3_gadget_get_frame(dwc);
		bool rollover = frame <
				(dep->frame_number & DWC3_FRNUMBER_MASK);

		/*
		 * frame_number is set from XferNotReady and may be already
		 * out of date. DSTS only provides the lower 14 bit of the
		 * current frame number. So add the upper two bits of
		 * frame_number and handle a possible rollover.
		 * This will provide the correct frame_number unless more than
		 * rollover has happened since XferNotReady.
		 */

		dep->frame_number = (dep->frame_number & ~DWC3_FRNUMBER_MASK) |
				     frame;
		if (rollover)
			dep->frame_number += BIT(14);
	}

	for (i = 0; i < DWC3_ISOC_MAX_RETRIES; i++) {
		dep->frame_number = DWC3_ALIGN_FRAME(dep, i + 1);

		ret = __dwc3_gadget_kick_transfer(dep);
		if (ret != -EAGAIN)
			break;
	}

	/*
	 * After a number of unsuccessful start attempts due to bus-expiry
	 * status, issue END_TRANSFER command and retry on the next XferNotReady
	 * event.
	 */
	if (ret == -EAGAIN) {
		struct dwc3_gadget_ep_cmd_params params;
		u32 cmd;

		cmd = DWC3_DEPCMD_ENDTRANSFER |
			DWC3_DEPCMD_CMDIOC |
			DWC3_DEPCMD_PARAM(dep->resource_index);

		dep->resource_index = 0;
		memset(&params, 0, sizeof(params));

		ret = dwc3_send_gadget_ep_cmd(dep, cmd, &params);
		if (!ret)
			dep->flags |= DWC3_EP_END_TRANSFER_PENDING;
	}

	return ret;
}

static int __dwc3_gadget_ep_queue(struct dwc3_ep *dep, struct dwc3_request *req)
{
	struct dwc3		*dwc = dep->dwc;

	if (!dep->endpoint.desc || !dwc->pullups_connected || !dwc->connected) {
		dev_dbg(dwc->dev, "%s: can't queue to disabled endpoint\n",
				dep->name);
		return -ESHUTDOWN;
	}

	if (WARN(req->dep != dep, "request %pK belongs to '%s'\n",
				&req->request, req->dep->name))
		return -EINVAL;

	if (WARN(req->status < DWC3_REQUEST_STATUS_COMPLETED,
				"%s: request %pK already in flight\n",
				dep->name, &req->request))
		return -EINVAL;

	pm_runtime_get(dwc->dev);

	req->request.actual	= 0;
	req->request.status	= -EINPROGRESS;

	trace_dwc3_ep_queue(req);

	list_add_tail(&req->list, &dep->pending_list);
	req->status = DWC3_REQUEST_STATUS_QUEUED;

	if (dep->flags & DWC3_EP_WAIT_TRANSFER_COMPLETE)
		return 0;

	/*
	 * Start the transfer only after the END_TRANSFER is completed
	 * and endpoint STALL is cleared.
	 */
	if ((dep->flags & DWC3_EP_END_TRANSFER_PENDING) ||
	    (dep->flags & DWC3_EP_WEDGE) ||
	    (dep->flags & DWC3_EP_STALL)) {
		dep->flags |= DWC3_EP_DELAY_START;
		return 0;
	}

	/*
	 * NOTICE: Isochronous endpoints should NEVER be prestarted. We must
	 * wait for a XferNotReady event so we will know what's the current
	 * (micro-)frame number.
	 *
	 * Without this trick, we are very, very likely gonna get Bus Expiry
	 * errors which will force us issue EndTransfer command.
	 */
	if (usb_endpoint_xfer_isoc(dep->endpoint.desc)) {
		if (!(dep->flags & DWC3_EP_PENDING_REQUEST) &&
				!(dep->flags & DWC3_EP_TRANSFER_STARTED))
			return 0;

		if ((dep->flags & DWC3_EP_PENDING_REQUEST)) {
			if (!(dep->flags & DWC3_EP_TRANSFER_STARTED))
				return __dwc3_gadget_start_isoc(dep);
		}
	}

	__dwc3_gadget_kick_transfer(dep);

	return 0;
}

static int dwc3_gadget_ep_queue(struct usb_ep *ep, struct usb_request *request,
	gfp_t gfp_flags)
{
	struct dwc3_request		*req = to_dwc3_request(request);
	struct dwc3_ep			*dep = to_dwc3_ep(ep);
	struct dwc3			*dwc = dep->dwc;

	unsigned long			flags;

	int				ret;

	spin_lock_irqsave(&dwc->lock, flags);
	ret = __dwc3_gadget_ep_queue(dep, req);
	spin_unlock_irqrestore(&dwc->lock, flags);

	return ret;
}

static void dwc3_gadget_ep_skip_trbs(struct dwc3_ep *dep, struct dwc3_request *req)
{
	int i;

	/* If req->trb is not set, then the request has not started */
	if (!req->trb)
		return;

	/*
	 * If request was already started, this means we had to
	 * stop the transfer. With that we also need to ignore
	 * all TRBs used by the request, however TRBs can only
	 * be modified after completion of END_TRANSFER
	 * command. So what we do here is that we wait for
	 * END_TRANSFER completion and only after that, we jump
	 * over TRBs by clearing HWO and incrementing dequeue
	 * pointer.
	 */
	for (i = 0; i < req->num_trbs; i++) {
		struct dwc3_trb *trb;

		trb = &dep->trb_pool[dep->trb_dequeue];
		trb->ctrl &= ~DWC3_TRB_CTRL_HWO;
		dwc3_ep_inc_deq(dep);
	}

	req->num_trbs = 0;
}

static void dwc3_gadget_ep_cleanup_cancelled_requests(struct dwc3_ep *dep)
{
	struct dwc3_request		*req;
	struct dwc3_request		*tmp;
	struct dwc3			*dwc = dep->dwc;

	list_for_each_entry_safe(req, tmp, &dep->cancelled_list, list) {
		dwc3_gadget_ep_skip_trbs(dep, req);
		switch (req->status) {
		case DWC3_REQUEST_STATUS_DISCONNECTED:
			dwc3_gadget_giveback(dep, req, -ESHUTDOWN);
			break;
		case DWC3_REQUEST_STATUS_DEQUEUED:
			dwc3_gadget_giveback(dep, req, -ECONNRESET);
			break;
		case DWC3_REQUEST_STATUS_STALLED:
			dwc3_gadget_giveback(dep, req, -EPIPE);
			break;
		default:
			dev_err(dwc->dev, "request cancelled with wrong reason:%d\n", req->status);
			dwc3_gadget_giveback(dep, req, -ECONNRESET);
			break;
		}
	}
}

static int dwc3_gadget_ep_dequeue(struct usb_ep *ep,
		struct usb_request *request)
{
	struct dwc3_request		*req = to_dwc3_request(request);
	struct dwc3_request		*r = NULL;

	struct dwc3_ep			*dep = to_dwc3_ep(ep);
	struct dwc3			*dwc = dep->dwc;

	unsigned long			flags;
	int				ret = 0;

	trace_dwc3_ep_dequeue(req);

	spin_lock_irqsave(&dwc->lock, flags);

	list_for_each_entry(r, &dep->cancelled_list, list) {
		if (r == req)
			goto out;
	}

	list_for_each_entry(r, &dep->pending_list, list) {
		if (r == req) {
			dwc3_gadget_giveback(dep, req, -ECONNRESET);
			goto out;
		}
	}

	list_for_each_entry(r, &dep->started_list, list) {
		if (r == req) {
			struct dwc3_request *t;

			/* wait until it is processed */
			dwc3_stop_active_transfer(dep, true, true);

			/*
			 * Remove any started request if the transfer is
			 * cancelled.
			 */
			list_for_each_entry_safe(r, t, &dep->started_list, list)
				dwc3_gadget_move_cancelled_request(r,
						DWC3_REQUEST_STATUS_DEQUEUED);

			dep->flags &= ~DWC3_EP_WAIT_TRANSFER_COMPLETE;

			goto out;
		}
	}

	dev_err(dwc->dev, "request %pK was not queued to %s\n",
		request, ep->name);
	ret = -EINVAL;
out:
	spin_unlock_irqrestore(&dwc->lock, flags);

	return ret;
}

int __dwc3_gadget_ep_set_halt(struct dwc3_ep *dep, int value, int protocol)
{
	struct dwc3_gadget_ep_cmd_params	params;
	struct dwc3				*dwc = dep->dwc;
	int					ret;

	if (usb_endpoint_xfer_isoc(dep->endpoint.desc)) {
		dev_err(dwc->dev, "%s is of Isochronous type\n", dep->name);
		return -EINVAL;
	}

	memset(&params, 0x00, sizeof(params));

	if (value) {
		struct dwc3_trb *trb;

		unsigned int transfer_in_flight;
		unsigned int started;

		if (dep->number > 1)
			trb = dwc3_ep_prev_trb(dep, dep->trb_enqueue);
		else
			trb = &dwc->ep0_trb[dep->trb_enqueue];

		transfer_in_flight = trb->ctrl & DWC3_TRB_CTRL_HWO;
		started = !list_empty(&dep->started_list);

		if (!protocol && ((dep->direction && transfer_in_flight) ||
				(!dep->direction && started))) {
			return -EAGAIN;
		}

		ret = dwc3_send_gadget_ep_cmd(dep, DWC3_DEPCMD_SETSTALL,
				&params);
		if (ret)
			dev_err(dwc->dev, "failed to set STALL on %s\n",
					dep->name);
		else
			dep->flags |= DWC3_EP_STALL;
	} else {
		/*
		 * Don't issue CLEAR_STALL command to control endpoints. The
		 * controller automatically clears the STALL when it receives
		 * the SETUP token.
		 */
		if (dep->number <= 1) {
			dep->flags &= ~(DWC3_EP_STALL | DWC3_EP_WEDGE);
			return 0;
		}

		dwc3_stop_active_transfer(dep, true, true);

		if (!list_empty(&dep->started_list))
			dep->flags |= DWC3_EP_DELAY_START;

		if (dep->flags & DWC3_EP_END_TRANSFER_PENDING) {
			dep->flags |= DWC3_EP_PENDING_CLEAR_STALL;
			return 0;
		}

		ret = dwc3_send_clear_stall_ep_cmd(dep);
		if (ret) {
			dev_err(dwc->dev, "failed to clear STALL on %s\n",
					dep->name);
			return ret;
		}

		dep->flags &= ~(DWC3_EP_STALL | DWC3_EP_WEDGE);

		if ((dep->flags & DWC3_EP_DELAY_START) &&
		    !usb_endpoint_xfer_isoc(dep->endpoint.desc))
			__dwc3_gadget_kick_transfer(dep);

		dep->flags &= ~DWC3_EP_DELAY_START;
	}

	return ret;
}

static int dwc3_gadget_ep_set_halt(struct usb_ep *ep, int value)
{
	struct dwc3_ep			*dep = to_dwc3_ep(ep);
	struct dwc3			*dwc = dep->dwc;

	unsigned long			flags;

	int				ret;

	spin_lock_irqsave(&dwc->lock, flags);
	ret = __dwc3_gadget_ep_set_halt(dep, value, false);
	spin_unlock_irqrestore(&dwc->lock, flags);

	return ret;
}

static int dwc3_gadget_ep_set_wedge(struct usb_ep *ep)
{
	struct dwc3_ep			*dep = to_dwc3_ep(ep);
	struct dwc3			*dwc = dep->dwc;
	unsigned long			flags;
	int				ret;

	spin_lock_irqsave(&dwc->lock, flags);
	dep->flags |= DWC3_EP_WEDGE;

	if (dep->number == 0 || dep->number == 1)
		ret = __dwc3_gadget_ep0_set_halt(ep, 1);
	else
		ret = __dwc3_gadget_ep_set_halt(dep, 1, false);
	spin_unlock_irqrestore(&dwc->lock, flags);

	return ret;
}

/* -------------------------------------------------------------------------- */

static struct usb_endpoint_descriptor dwc3_gadget_ep0_desc = {
	.bLength	= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bmAttributes	= USB_ENDPOINT_XFER_CONTROL,
};

static const struct usb_ep_ops dwc3_gadget_ep0_ops = {
	.enable		= dwc3_gadget_ep0_enable,
	.disable	= dwc3_gadget_ep0_disable,
	.alloc_request	= dwc3_gadget_ep_alloc_request,
	.free_request	= dwc3_gadget_ep_free_request,
	.queue		= dwc3_gadget_ep0_queue,
	.dequeue	= dwc3_gadget_ep_dequeue,
	.set_halt	= dwc3_gadget_ep0_set_halt,
	.set_wedge	= dwc3_gadget_ep_set_wedge,
};

static const struct usb_ep_ops dwc3_gadget_ep_ops = {
	.enable		= dwc3_gadget_ep_enable,
	.disable	= dwc3_gadget_ep_disable,
	.alloc_request	= dwc3_gadget_ep_alloc_request,
	.free_request	= dwc3_gadget_ep_free_request,
	.queue		= dwc3_gadget_ep_queue,
	.dequeue	= dwc3_gadget_ep_dequeue,
	.set_halt	= dwc3_gadget_ep_set_halt,
	.set_wedge	= dwc3_gadget_ep_set_wedge,
};

/* -------------------------------------------------------------------------- */

static int dwc3_gadget_get_frame(struct usb_gadget *g)
{
	struct dwc3		*dwc = gadget_to_dwc(g);

	return __dwc3_gadget_get_frame(dwc);
}

static int __dwc3_gadget_wakeup(struct dwc3 *dwc)
{
	int			retries;

	int			ret;
	u32			reg;

	u8			link_state;

	/*
	 * According to the Databook Remote wakeup request should
	 * be issued only when the device is in early suspend state.
	 *
	 * We can check that via USB Link State bits in DSTS register.
	 */
	reg = dwc3_readl(dwc->regs, DWC3_DSTS);

	link_state = DWC3_DSTS_USBLNKST(reg);

	switch (link_state) {
	case DWC3_LINK_STATE_RESET:
	case DWC3_LINK_STATE_RX_DET:	/* in HS, means Early Suspend */
	case DWC3_LINK_STATE_U3:	/* in HS, means SUSPEND */
	case DWC3_LINK_STATE_U2:	/* in HS, means Sleep (L1) */
	case DWC3_LINK_STATE_U1:
	case DWC3_LINK_STATE_RESUME:
		break;
	default:
		return -EINVAL;
	}

	ret = dwc3_gadget_set_link_state(dwc, DWC3_LINK_STATE_RECOV);
	if (ret < 0) {
		dev_err(dwc->dev, "failed to put link in Recovery\n");
		return ret;
	}

	/* Recent versions do this automatically */
	if (DWC3_VER_IS_PRIOR(DWC3, 194A)) {
		/* write zeroes to Link Change Request */
		reg = dwc3_readl(dwc->regs, DWC3_DCTL);
		reg &= ~DWC3_DCTL_ULSTCHNGREQ_MASK;
		dwc3_writel(dwc->regs, DWC3_DCTL, reg);
	}

	/* poll until Link State changes to ON */
	retries = 20000;

	while (retries--) {
		reg = dwc3_readl(dwc->regs, DWC3_DSTS);

		/* in HS, means ON */
		if (DWC3_DSTS_USBLNKST(reg) == DWC3_LINK_STATE_U0)
			break;
	}

	if (DWC3_DSTS_USBLNKST(reg) != DWC3_LINK_STATE_U0) {
		dev_err(dwc->dev, "failed to send remote wakeup\n");
		return -EINVAL;
	}

	return 0;
}

static int dwc3_gadget_wakeup(struct usb_gadget *g)
{
	struct dwc3		*dwc = gadget_to_dwc(g);
	unsigned long		flags;
	int			ret;

	spin_lock_irqsave(&dwc->lock, flags);
	ret = __dwc3_gadget_wakeup(dwc);
	spin_unlock_irqrestore(&dwc->lock, flags);

	return ret;
}

static int dwc3_gadget_set_selfpowered(struct usb_gadget *g,
		int is_selfpowered)
{
	struct dwc3		*dwc = gadget_to_dwc(g);
	unsigned long		flags;

	spin_lock_irqsave(&dwc->lock, flags);
	g->is_selfpowered = !!is_selfpowered;
	spin_unlock_irqrestore(&dwc->lock, flags);

	return 0;
}

static void dwc3_stop_active_transfers(struct dwc3 *dwc)
{
	u32 epnum;

	for (epnum = 2; epnum < dwc->num_eps; epnum++) {
		struct dwc3_ep *dep;

		dep = dwc->eps[epnum];
		if (!dep)
			continue;

		dwc3_remove_requests(dwc, dep);
	}
}

static void __dwc3_gadget_set_ssp_rate(struct dwc3 *dwc)
{
	enum usb_ssp_rate	ssp_rate = dwc->gadget_ssp_rate;
	u32			reg;

	if (ssp_rate == USB_SSP_GEN_UNKNOWN)
		ssp_rate = dwc->max_ssp_rate;

	reg = dwc3_readl(dwc->regs, DWC3_DCFG);
	reg &= ~DWC3_DCFG_SPEED_MASK;
	reg &= ~DWC3_DCFG_NUMLANES(~0);

	if (ssp_rate == USB_SSP_GEN_1x2)
		reg |= DWC3_DCFG_SUPERSPEED;
	else if (dwc->max_ssp_rate != USB_SSP_GEN_1x2)
		reg |= DWC3_DCFG_SUPERSPEED_PLUS;

	if (ssp_rate != USB_SSP_GEN_2x1 &&
	    dwc->max_ssp_rate != USB_SSP_GEN_2x1)
		reg |= DWC3_DCFG_NUMLANES(1);

	dwc3_writel(dwc->regs, DWC3_DCFG, reg);
}

static void __dwc3_gadget_set_speed(struct dwc3 *dwc)
{
	enum usb_device_speed	speed;
	u32			reg;

	speed = dwc->gadget_max_speed;
	if (speed == USB_SPEED_UNKNOWN || speed > dwc->maximum_speed)
		speed = dwc->maximum_speed;

	if (speed == USB_SPEED_SUPER_PLUS &&
	    DWC3_IP_IS(DWC32)) {
		__dwc3_gadget_set_ssp_rate(dwc);
		return;
	}

	reg = dwc3_readl(dwc->regs, DWC3_DCFG);
	reg &= ~(DWC3_DCFG_SPEED_MASK);

	/*
	 * WORKAROUND: DWC3 revision < 2.20a have an issue
	 * which would cause metastability state on Run/Stop
	 * bit if we try to force the IP to USB2-only mode.
	 *
	 * Because of that, we cannot configure the IP to any
	 * speed other than the SuperSpeed
	 *
	 * Refers to:
	 *
	 * STAR#9000525659: Clock Domain Crossing on DCTL in
	 * USB 2.0 Mode
	 */
	if (DWC3_VER_IS_PRIOR(DWC3, 220A) &&
	    !dwc->dis_metastability_quirk) {
		reg |= DWC3_DCFG_SUPERSPEED;
	} else {
		switch (speed) {
		case USB_SPEED_LOW:
			reg |= DWC3_DCFG_LOWSPEED;
			break;
		case USB_SPEED_FULL:
			reg |= DWC3_DCFG_FULLSPEED;
			break;
		case USB_SPEED_HIGH:
			reg |= DWC3_DCFG_HIGHSPEED;
			break;
		case USB_SPEED_SUPER:
			reg |= DWC3_DCFG_SUPERSPEED;
			break;
		case USB_SPEED_SUPER_PLUS:
			if (DWC3_IP_IS(DWC3))
				reg |= DWC3_DCFG_SUPERSPEED;
			else
				reg |= DWC3_DCFG_SUPERSPEED_PLUS;
			break;
		default:
			dev_err(dwc->dev, "invalid speed (%d)\n", speed);

			if (DWC3_IP_IS(DWC3))
				reg |= DWC3_DCFG_SUPERSPEED;
			else
				reg |= DWC3_DCFG_SUPERSPEED_PLUS;
		}
	}

	if (DWC3_IP_IS(DWC32) &&
	    speed > USB_SPEED_UNKNOWN &&
	    speed < USB_SPEED_SUPER_PLUS)
		reg &= ~DWC3_DCFG_NUMLANES(~0);

	dwc3_writel(dwc->regs, DWC3_DCFG, reg);
}

static int dwc3_gadget_run_stop(struct dwc3 *dwc, int is_on, int suspend)
{
	u32			reg;
	u32			timeout = 500;

	if (pm_runtime_suspended(dwc->dev))
		return 0;

	reg = dwc3_readl(dwc->regs, DWC3_DCTL);
	if (is_on) {
		if (DWC3_VER_IS_WITHIN(DWC3, ANY, 187A)) {
			reg &= ~DWC3_DCTL_TRGTULST_MASK;
			reg |= DWC3_DCTL_TRGTULST_RX_DET;
		}

		if (!DWC3_VER_IS_PRIOR(DWC3, 194A))
			reg &= ~DWC3_DCTL_KEEP_CONNECT;
		reg |= DWC3_DCTL_RUN_STOP;

		if (dwc->has_hibernation)
			reg |= DWC3_DCTL_KEEP_CONNECT;

		__dwc3_gadget_set_speed(dwc);
		dwc->pullups_connected = true;
	} else {
		reg &= ~DWC3_DCTL_RUN_STOP;

		if (dwc->has_hibernation && !suspend)
			reg &= ~DWC3_DCTL_KEEP_CONNECT;

		dwc->pullups_connected = false;
	}

	dwc3_gadget_dctl_write_safe(dwc, reg);

	do {
		reg = dwc3_readl(dwc->regs, DWC3_DSTS);
		reg &= DWC3_DSTS_DEVCTRLHLT;
	} while (--timeout && !(!is_on ^ !reg));

	if (!timeout)
		return -ETIMEDOUT;

	return 0;
}

static void dwc3_gadget_disable_irq(struct dwc3 *dwc);
static void __dwc3_gadget_stop(struct dwc3 *dwc);
static int __dwc3_gadget_start(struct dwc3 *dwc);

static int dwc3_gadget_pullup(struct usb_gadget *g, int is_on)
{
	struct dwc3		*dwc = gadget_to_dwc(g);
	struct dwc3_vendor	*vdwc = container_of(dwc, struct dwc3_vendor, dwc);
	unsigned long		flags;
	int			ret;

	is_on = !!is_on;
	vdwc->softconnect = is_on;

	/*
	 * Per databook, when we want to stop the gadget, if a control transfer
	 * is still in process, complete it and get the core into setup phase.
	 */
	if (!is_on && dwc->ep0state != EP0_SETUP_PHASE) {
		reinit_completion(&dwc->ep0_in_setup);

		ret = wait_for_completion_timeout(&dwc->ep0_in_setup,
				msecs_to_jiffies(DWC3_PULL_UP_TIMEOUT));
		if (ret == 0)
			dev_warn(dwc->dev, "timed out waiting for SETUP phase\n");
	}

	/*
	 * Avoid issuing a runtime resume if the device is already in the
	 * suspended state during gadget disconnect.  DWC3 gadget was already
	 * halted/stopped during runtime suspend.
	 */
	if (!is_on) {
		pm_runtime_barrier(dwc->dev);
		if (pm_runtime_suspended(dwc->dev))
			return 0;
	}

	/*
	 * Check the return value for successful resume, or error.  For a
	 * successful resume, the DWC3 runtime PM resume routine will handle
	 * the run stop sequence, so avoid duplicate operations here.
	 */
	ret = pm_runtime_get_sync(dwc->dev);
	if (!ret || ret < 0) {
		pm_runtime_put(dwc->dev);
		return 0;
	}

	/*
	 * Synchronize and disable any further event handling while controller
	 * is being enabled/disabled.
	 */
	disable_irq(dwc->irq_gadget);

	spin_lock_irqsave(&dwc->lock, flags);

	if (!is_on) {
		u32 count;

		dwc->connected = false;
		/*
		 * In the Synopsis DesignWare Cores USB3 Databook Rev. 3.30a
		 * Section 4.1.8 Table 4-7, it states that for a device-initiated
		 * disconnect, the SW needs to ensure that it sends "a DEPENDXFER
		 * command for any active transfers" before clearing the RunStop
		 * bit.
		 */
		dwc3_stop_active_transfers(dwc);
		__dwc3_gadget_stop(dwc);

		/*
		 * In the Synopsis DesignWare Cores USB3 Databook Rev. 3.30a
		 * Section 1.3.4, it mentions that for the DEVCTRLHLT bit, the
		 * "software needs to acknowledge the events that are generated
		 * (by writing to GEVNTCOUNTn) while it is waiting for this bit
		 * to be set to '1'."
		 */
		count = dwc3_readl(dwc->regs, DWC3_GEVNTCOUNT(0));
		count &= DWC3_GEVNTCOUNT_MASK;
		if (count > 0) {
			dwc3_writel(dwc->regs, DWC3_GEVNTCOUNT(0), count);
			dwc->ev_buf->lpos = (dwc->ev_buf->lpos + count) %
						dwc->ev_buf->length;
		}
	} else {
		__dwc3_gadget_start(dwc);
	}

	ret = dwc3_gadget_run_stop(dwc, is_on, false);
	spin_unlock_irqrestore(&dwc->lock, flags);
	enable_irq(dwc->irq_gadget);

	pm_runtime_put(dwc->dev);

	return ret;
}

static void dwc3_gadget_enable_irq(struct dwc3 *dwc)
{
	u32			reg;

	/* Enable all but Start and End of Frame IRQs */
	reg = (DWC3_DEVTEN_EVNTOVERFLOWEN |
			DWC3_DEVTEN_CMDCMPLTEN |
			DWC3_DEVTEN_ERRTICERREN |
			DWC3_DEVTEN_WKUPEVTEN |
			DWC3_DEVTEN_CONNECTDONEEN |
			DWC3_DEVTEN_USBRSTEN |
			DWC3_DEVTEN_DISCONNEVTEN);

	if (DWC3_VER_IS_PRIOR(DWC3, 250A))
		reg |= DWC3_DEVTEN_ULSTCNGEN;

	/* On 2.30a and above this bit enables U3/L2-L1 Suspend Events */
	if (!DWC3_VER_IS_PRIOR(DWC3, 230A))
		reg |= DWC3_DEVTEN_U3L2L1SUSPEN;

	dwc3_writel(dwc->regs, DWC3_DEVTEN, reg);
}

static void dwc3_gadget_disable_irq(struct dwc3 *dwc)
{
	/* mask all interrupts */
	dwc3_writel(dwc->regs, DWC3_DEVTEN, 0x00);
}

static irqreturn_t dwc3_interrupt(int irq, void *_dwc);
static irqreturn_t dwc3_thread_interrupt(int irq, void *_dwc);

/**
 * dwc3_gadget_setup_nump - calculate and initialize NUMP field of %DWC3_DCFG
 * @dwc: pointer to our context structure
 *
 * The following looks like complex but it's actually very simple. In order to
 * calculate the number of packets we can burst at once on OUT transfers, we're
 * gonna use RxFIFO size.
 *
 * To calculate RxFIFO size we need two numbers:
 * MDWIDTH = size, in bits, of the internal memory bus
 * RAM2_DEPTH = depth, in MDWIDTH, of internal RAM2 (where RxFIFO sits)
 *
 * Given these two numbers, the formula is simple:
 *
 * RxFIFO Size = (RAM2_DEPTH * MDWIDTH / 8) - 24 - 16;
 *
 * 24 bytes is for 3x SETUP packets
 * 16 bytes is a clock domain crossing tolerance
 *
 * Given RxFIFO Size, NUMP = RxFIFOSize / 1024;
 */
static void dwc3_gadget_setup_nump(struct dwc3 *dwc)
{
	u32 ram2_depth;
	u32 mdwidth;
	u32 nump;
	u32 reg;

	ram2_depth = DWC3_GHWPARAMS7_RAM2_DEPTH(dwc->hwparams.hwparams7);
	mdwidth = dwc3_mdwidth(dwc);

	nump = ((ram2_depth * mdwidth / 8) - 24 - 16) / 1024;
	nump = min_t(u32, nump, 16);

	/* update NumP */
	reg = dwc3_readl(dwc->regs, DWC3_DCFG);
	reg &= ~DWC3_DCFG_NUMP_MASK;
	reg |= nump << DWC3_DCFG_NUMP_SHIFT;
	dwc3_writel(dwc->regs, DWC3_DCFG, reg);
}

static int __dwc3_gadget_start(struct dwc3 *dwc)
{
	struct dwc3_ep		*dep;
	int			ret = 0;
	u32			reg;

	/*
	 * If the DWC3 is in runtime suspend, the clocks maybe
	 * disabled, so avoid enable the DWC3 endpoints here.
	 * The DWC3 runtime PM resume routine will handle the
	 * gadget start sequence.
	 */
	if (pm_runtime_suspended(dwc->dev))
		return ret;

	/*
	 * Use IMOD if enabled via dwc->imod_interval. Otherwise, if
	 * the core supports IMOD, disable it.
	 */
	if (dwc->imod_interval) {
		dwc3_writel(dwc->regs, DWC3_DEV_IMOD(0), dwc->imod_interval);
		dwc3_writel(dwc->regs, DWC3_GEVNTCOUNT(0), DWC3_GEVNTCOUNT_EHB);
	} else if (dwc3_has_imod(dwc)) {
		dwc3_writel(dwc->regs, DWC3_DEV_IMOD(0), 0);
	}

	/*
	 * We are telling dwc3 that we want to use DCFG.NUMP as ACK TP's NUMP
	 * field instead of letting dwc3 itself calculate that automatically.
	 *
	 * This way, we maximize the chances that we'll be able to get several
	 * bursts of data without going through any sort of endpoint throttling.
	 */
	reg = dwc3_readl(dwc->regs, DWC3_GRXTHRCFG);
	if (DWC3_IP_IS(DWC3))
		reg &= ~DWC3_GRXTHRCFG_PKTCNTSEL;
	else
		reg &= ~DWC31_GRXTHRCFG_PKTCNTSEL;

	dwc3_writel(dwc->regs, DWC3_GRXTHRCFG, reg);

	dwc3_gadget_setup_nump(dwc);

	/*
	 * Currently the controller handles single stream only. So, Ignore
	 * Packet Pending bit for stream selection and don't search for another
	 * stream if the host sends Data Packet with PP=0 (for OUT direction) or
	 * ACK with NumP=0 and PP=0 (for IN direction). This slightly improves
	 * the stream performance.
	 */
	reg = dwc3_readl(dwc->regs, DWC3_DCFG);
	reg |= DWC3_DCFG_IGNSTRMPP;
	dwc3_writel(dwc->regs, DWC3_DCFG, reg);

	/* Start with SuperSpeed Default */
	dwc3_gadget_ep0_desc.wMaxPacketSize = cpu_to_le16(512);

	dep = dwc->eps[0];
	ret = __dwc3_gadget_ep_enable(dep, DWC3_DEPCFG_ACTION_INIT);
	if (ret) {
		dev_err(dwc->dev, "failed to enable %s\n", dep->name);
		goto err0;
	}

	dep = dwc->eps[1];
	ret = __dwc3_gadget_ep_enable(dep, DWC3_DEPCFG_ACTION_INIT);
	if (ret) {
		dev_err(dwc->dev, "failed to enable %s\n", dep->name);
		goto err1;
	}

	/* begin to receive SETUP packets */
	dwc->ep0state = EP0_SETUP_PHASE;
	dwc->link_state = DWC3_LINK_STATE_SS_DIS;
	dwc->delayed_status = false;
	dwc3_ep0_out_start(dwc);

	dwc3_gadget_enable_irq(dwc);

	return 0;

err1:
	__dwc3_gadget_ep_disable(dwc->eps[0]);

err0:
	return ret;
}

static int dwc3_gadget_start(struct usb_gadget *g,
		struct usb_gadget_driver *driver)
