// SPDX-License-Identifier: GPL-2.0
/*
 * xHCI host controller driver
 *
 * Copyright (C) 2008 Intel Corp.
 *
 * Author: Sarah Sharp
 * Some code borrowed from the Linux EHCI driver.
 */

#include <linux/pci.h>
#include <linux/iopoll.h>
#include <linux/irq.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/dmi.h>
#include <linux/dma-mapping.h>

#include "xhci.h"
#include "xhci-trace.h"
#include "xhci-debugfs.h"
#include "xhci-dbgcap.h"

#define DRIVER_AUTHOR "Sarah Sharp"
#define DRIVER_DESC "'eXtensible' Host Controller (xHC) Driver"

#define	PORT_WAKE_BITS	(PORT_WKOC_E | PORT_WKDISC_E | PORT_WKCONN_E)

/* Some 0.95 hardware can't handle the chain bit on a Link TRB being cleared */
static int link_quirk;
module_param(link_quirk, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(link_quirk, "Don't clear the chain bit on a link TRB");

static unsigned long long quirks;
module_param(quirks, ullong, S_IRUGO);
MODULE_PARM_DESC(quirks, "Bit flags for quirks to be enabled as default");

static bool td_on_ring(struct xhci_td *td, struct xhci_ring *ring)
{
	struct xhci_segment *seg = ring->first_seg;

	if (!td || !td->start_seg)
		return false;
	do {
		if (seg == td->start_seg)
			return true;
		seg = seg->next;
	} while (seg && seg != ring->first_seg);

	return false;
}

/*
 * xhci_handshake - spin reading hc until handshake completes or fails
 * @ptr: address of hc register to be read
 * @mask: bits to look at in result of read
 * @done: value of those bits when handshake succeeds
 * @usec: timeout in microseconds
 *
 * Returns negative errno, or zero on success
 *
 * Success happens when the "mask" bits have the specified value (hardware
 * handshake done).  There are two failure modes:  "usec" have passed (major
 * hardware flakeout), or the register reads as all-ones (hardware removed).
 */
int xhci_handshake(void __iomem *ptr, u32 mask, u32 done, int usec)
{
	u32	result;
	int	ret;

	ret = readl_poll_timeout_atomic(ptr, result,
					(result & mask) == done ||
					result == U32_MAX,
					1, usec);
	if (result == U32_MAX)		/* card removed */
		return -ENODEV;

	return ret;
}

/*
 * Disable interrupts and begin the xHCI halting process.
 */
void xhci_quiesce(struct xhci_hcd *xhci)
{
	u32 halted;
	u32 cmd;
	u32 mask;

	mask = ~(XHCI_IRQS);
	halted = readl(&xhci->op_regs->status) & STS_HALT;
	if (!halted)
		mask &= ~CMD_RUN;

	cmd = readl(&xhci->op_regs->command);
	cmd &= mask;
	writel(cmd, &xhci->op_regs->command);
}

/*
 * Force HC into halt state.
 *
 * Disable any IRQs and clear the run/stop bit.
 * HC will complete any current and actively pipelined transactions, and
 * should halt within 16 ms of the run/stop bit being cleared.
 * Read HC Halted bit in the status register to see when the HC is finished.
 */
int xhci_halt(struct xhci_hcd *xhci)
{
	int ret;
	xhci_dbg_trace(xhci, trace_xhci_dbg_init, "// Halt the HC");
	xhci_quiesce(xhci);

	ret = xhci_handshake(&xhci->op_regs->status,
			STS_HALT, STS_HALT, XHCI_MAX_HALT_USEC);
	if (ret) {
		xhci_warn(xhci, "Host halt failed, %d\n", ret);
		return ret;
	}
	xhci->xhc_state |= XHCI_STATE_HALTED;
	xhci->cmd_ring_state = CMD_RING_STATE_STOPPED;
	return ret;
}

/*
 * Set the run bit and wait for the host to be running.
 */
int xhci_start(struct xhci_hcd *xhci)
{
	u32 temp;
	int ret;

	temp = readl(&xhci->op_regs->command);
	temp |= (CMD_RUN);
	xhci_dbg_trace(xhci, trace_xhci_dbg_init, "// Turn on HC, cmd = 0x%x.",
			temp);
	writel(temp, &xhci->op_regs->command);

	/*
	 * Wait for the HCHalted Status bit to be 0 to indicate the host is
	 * running.
	 */
	ret = xhci_handshake(&xhci->op_regs->status,
			STS_HALT, 0, XHCI_MAX_HALT_USEC);
	if (ret == -ETIMEDOUT)
		xhci_err(xhci, "Host took too long to start, "
				"waited %u microseconds.\n",
				XHCI_MAX_HALT_USEC);
	if (!ret)
		/* clear state flags. Including dying, halted or removing */
		xhci->xhc_state = 0;

	return ret;
}

/*
 * Reset a halted HC.
 *
 * This resets pipelines, timers, counters, state machines, etc.
 * Transactions will be terminated immediately, and operational registers
 * will be set to their defaults.
 */
int xhci_reset(struct xhci_hcd *xhci)
{
	u32 command;
	u32 state;
	int ret;

	state = readl(&xhci->op_regs->status);

	if (state == ~(u32)0) {
		xhci_warn(xhci, "Host not accessible, reset failed.\n");
		return -ENODEV;
	}

	if ((state & STS_HALT) == 0) {
		xhci_warn(xhci, "Host controller not halted, aborting reset.\n");
		return 0;
	}

	xhci_dbg_trace(xhci, trace_xhci_dbg_init, "// Reset the HC");
	command = readl(&xhci->op_regs->command);
	command |= CMD_RESET;
	writel(command, &xhci->op_regs->command);

	/* Existing Intel xHCI controllers require a delay of 1 mS,
	 * after setting the CMD_RESET bit, and before accessing any
	 * HC registers. This allows the HC to complete the
	 * reset operation and be ready for HC register access.
	 * Without this delay, the subsequent HC register access,
	 * may result in a system hang very rarely.
	 */
	if (xhci->quirks & XHCI_INTEL_HOST)
		udelay(1000);

	ret = xhci_handshake(&xhci->op_regs->command,
			CMD_RESET, 0, 10 * 1000 * 1000);
	if (ret)
		return ret;

	if (xhci->quirks & XHCI_ASMEDIA_MODIFY_FLOWCONTROL)
		usb_asmedia_modifyflowcontrol(to_pci_dev(xhci_to_hcd(xhci)->self.controller));

	xhci_dbg_trace(xhci, trace_xhci_dbg_init,
			 "Wait for controller to be ready for doorbell rings");
	/*
	 * xHCI cannot write to any doorbells or operational registers other
	 * than status until the "Controller Not Ready" flag is cleared.
	 */
	ret = xhci_handshake(&xhci->op_regs->status,
			STS_CNR, 0, 10 * 1000 * 1000);

	xhci->usb2_rhub.bus_state.port_c_suspend = 0;
	xhci->usb2_rhub.bus_state.suspended_ports = 0;
	xhci->usb2_rhub.bus_state.resuming_ports = 0;
	xhci->usb3_rhub.bus_state.port_c_suspend = 0;
	xhci->usb3_rhub.bus_state.suspended_ports = 0;
	xhci->usb3_rhub.bus_state.resuming_ports = 0;

	return ret;
}

static void xhci_zero_64b_regs(struct xhci_hcd *xhci)
{
	struct device *dev = xhci_to_hcd(xhci)->self.sysdev;
	int err, i;
	u64 val;
	u32 intrs;

	/*
	 * Some Renesas controllers get into a weird state if they are
	 * reset while programmed with 64bit addresses (they will preserve
	 * the top half of the address in internal, non visible
	 * registers). You end up with half the address coming from the
	 * kernel, and the other half coming from the firmware. Also,
	 * changing the programming leads to extra accesses even if the
	 * controller is supposed to be halted. The controller ends up with
	 * a fatal fault, and is then ripe for being properly reset.
	 *
	 * Special care is taken to only apply this if the device is behind
	 * an iommu. Doing anything when there is no iommu is definitely
	 * unsafe...
	 */
	if (!(xhci->quirks & XHCI_ZERO_64B_REGS) || !device_iommu_mapped(dev))
		return;

	xhci_info(xhci, "Zeroing 64bit base registers, expecting fault\n");

	/* Clear HSEIE so that faults do not get signaled */
	val = readl(&xhci->op_regs->command);
	val &= ~CMD_HSEIE;
	writel(val, &xhci->op_regs->command);

	/* Clear HSE (aka FATAL) */
	val = readl(&xhci->op_regs->status);
	val |= STS_FATAL;
	writel(val, &xhci->op_regs->status);

	/* Now zero the registers, and brace for impact */
	val = xhci_read_64(xhci, &xhci->op_regs->dcbaa_ptr);
	if (upper_32_bits(val))
		xhci_write_64(xhci, 0, &xhci->op_regs->dcbaa_ptr);
	val = xhci_read_64(xhci, &xhci->op_regs->cmd_ring);
	if (upper_32_bits(val))
		xhci_write_64(xhci, 0, &xhci->op_regs->cmd_ring);

	intrs = min_t(u32, HCS_MAX_INTRS(xhci->hcs_params1),
		      ARRAY_SIZE(xhci->run_regs->ir_set));

	for (i = 0; i < intrs; i++) {
		struct xhci_intr_reg __iomem *ir;

		ir = &xhci->run_regs->ir_set[i];
		val = xhci_read_64(xhci, &ir->erst_base);
		if (upper_32_bits(val))
			xhci_write_64(xhci, 0, &ir->erst_base);
		val= xhci_read_64(xhci, &ir->erst_dequeue);
		if (upper_32_bits(val))
			xhci_write_64(xhci, 0, &ir->erst_dequeue);
	}

	/* Wait for the fault to appear. It will be cleared on reset */
	err = xhci_handshake(&xhci->op_regs->status,
			     STS_FATAL, STS_FATAL,
			     XHCI_MAX_HALT_USEC);
	if (!err)
		xhci_info(xhci, "Fault detected\n");
}

#ifdef CONFIG_USB_PCI
/*
 * Set up MSI
 */
static int xhci_setup_msi(struct xhci_hcd *xhci)
{
	int ret;
	/*
	 * TODO:Check with MSI Soc for sysdev
	 */
	struct pci_dev  *pdev = to_pci_dev(xhci_to_hcd(xhci)->self.controller);

	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSI);
	if (ret < 0) {
		xhci_dbg_trace(xhci, trace_xhci_dbg_init,
				"failed to allocate MSI entry");
		return ret;
	}

	ret = request_irq(pdev->irq, xhci_msi_irq,
				0, "xhci_hcd", xhci_to_hcd(xhci));
	if (ret) {
		xhci_dbg_trace(xhci, trace_xhci_dbg_init,
				"disable MSI interrupt");
		pci_free_irq_vectors(pdev);
	}

	return ret;
}

/*
 * Set up MSI-X
 */
static int xhci_setup_msix(struct xhci_hcd *xhci)
{
	int i, ret = 0;
	struct usb_hcd *hcd = xhci_to_hcd(xhci);
	struct pci_dev *pdev = to_pci_dev(hcd->self.controller);

	/*
	 * calculate number of msi-x vectors supported.
	 * - HCS_MAX_INTRS: the max number of interrupts the host can handle,
	 *   with max number of interrupters based on the xhci HCSPARAMS1.
	 * - num_online_cpus: maximum msi-x vectors per CPUs core.
	 *   Add additional 1 vector to ensure always available interrupt.
	 */
	xhci->msix_count = min(num_online_cpus() + 1,
				HCS_MAX_INTRS(xhci->hcs_params1));

	ret = pci_alloc_irq_vectors(pdev, xhci->msix_count, xhci->msix_count,
			PCI_IRQ_MSIX);
	if (ret < 0) {
		xhci_dbg_trace(xhci, trace_xhci_dbg_init,
				"Failed to enable MSI-X");
		return ret;
	}

	for (i = 0; i < xhci->msix_count; i++) {
		ret = request_irq(pci_irq_vector(pdev, i), xhci_msi_irq, 0,
				"xhci_hcd", xhci_to_hcd(xhci));
		if (ret)
			goto disable_msix;
	}

	hcd->msix_enabled = 1;
	return ret;

disable_msix:
	xhci_dbg_trace(xhci, trace_xhci_dbg_init, "disable MSI-X interrupt");
	while (--i >= 0)
		free_irq(pci_irq_vector(pdev, i), xhci_to_hcd(xhci));
	pci_free_irq_vectors(pdev);
	return ret;
}

/* Free any IRQs and disable MSI-X */
static void xhci_cleanup_msix(struct xhci_hcd *xhci)
{
	struct usb_hcd *hcd = xhci_to_hcd(xhci);
	struct pci_dev *pdev = to_pci_dev(hcd->self.controller);

	if (xhci->quirks & XHCI_PLAT)
		return;

	/* return if using legacy interrupt */
	if (hcd->irq > 0)
		return;

	if (hcd->msix_enabled) {
		int i;

		for (i = 0; i < xhci->msix_count; i++)
			free_irq(pci_irq_vector(pdev, i), xhci_to_hcd(xhci));
	} else {
		free_irq(pci_irq_vector(pdev, 0), xhci_to_hcd(xhci));
	}

	pci_free_irq_vectors(pdev);
	hcd->msix_enabled = 0;
}

static void __maybe_unused xhci_msix_sync_irqs(struct xhci_hcd *xhci)
{
	struct usb_hcd *hcd = xhci_to_hcd(xhci);

	if (hcd->msix_enabled) {
		struct pci_dev *pdev = to_pci_dev(hcd->self.controller);
		int i;

		for (i = 0; i < xhci->msix_count; i++)
			synchronize_irq(pci_irq_vector(pdev, i));
	}
}

static int xhci_try_enable_msi(struct usb_hcd *hcd)
{
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	struct pci_dev  *pdev;
	int ret;

	/* The xhci platform device has set up IRQs through usb_add_hcd. */
	if (xhci->quirks & XHCI_PLAT)
		return 0;

	pdev = to_pci_dev(xhci_to_hcd(xhci)->self.controller);
	/*
	 * Some Fresco Logic host controllers advertise MSI, but fail to
	 * generate interrupts.  Don't even try to enable MSI.
	 */
	if (xhci->quirks & XHCI_BROKEN_MSI)
		goto legacy_irq;

	/* unregister the legacy interrupt */
	if (hcd->irq)
		free_irq(hcd->irq, hcd);
	hcd->irq = 0;

	ret = xhci_setup_msix(xhci);
	if (ret)
		/* fall back to msi*/
		ret = xhci_setup_msi(xhci);

	if (!ret) {
		hcd->msi_enabled = 1;
		return 0;
	}

	if (!pdev->irq) {
		xhci_err(xhci, "No msi-x/msi found and no IRQ in BIOS\n");
		return -EINVAL;
	}

 legacy_irq:
	if (!strlen(hcd->irq_descr))
		snprintf(hcd->irq_descr, sizeof(hcd->irq_descr), "%s:usb%d",
			 hcd->driver->description, hcd->self.busnum);

	/* fall back to legacy interrupt*/
	ret = request_irq(pdev->irq, &usb_hcd_irq, IRQF_SHARED,
			hcd->irq_descr, hcd);
	if (ret) {
		xhci_err(xhci, "request interrupt %d failed\n",
				pdev->irq);
		return ret;
	}
	hcd->irq = pdev->irq;
	return 0;
}

#else

static inline int xhci_try_enable_msi(struct usb_hcd *hcd)
{
	return 0;
}

static inline void xhci_cleanup_msix(struct xhci_hcd *xhci)
{
}

static inline void xhci_msix_sync_irqs(struct xhci_hcd *xhci)
{
}

#endif

static void compliance_mode_recovery(struct timer_list *t)
{
	struct xhci_hcd *xhci;
	struct usb_hcd *hcd;
	struct xhci_hub *rhub;
	u32 temp;
	int i;

	xhci = from_timer(xhci, t, comp_mode_recovery_timer);
	rhub = &xhci->usb3_rhub;

	for (i = 0; i < rhub->num_ports; i++) {
		temp = readl(rhub->ports[i]->addr);
		if ((temp & PORT_PLS_MASK) == USB_SS_PORT_LS_COMP_MOD) {
			/*
			 * Compliance Mode Detected. Letting USB Core
			 * handle the Warm Reset
			 */
			xhci_dbg_trace(xhci, trace_xhci_dbg_quirks,
					"Compliance mode detected->port %d",
					i + 1);
			xhci_dbg_trace(xhci, trace_xhci_dbg_quirks,
					"Attempting compliance mode recovery");
			hcd = xhci->shared_hcd;

			if (hcd->state == HC_STATE_SUSPENDED)
				usb_hcd_resume_root_hub(hcd);

			usb_hcd_poll_rh_status(hcd);
		}
	}

	if (xhci->port_status_u0 != ((1 << rhub->num_ports) - 1))
		mod_timer(&xhci->comp_mode_recovery_timer,
			jiffies + msecs_to_jiffies(COMP_MODE_RCVRY_MSECS));
}

/*
 * Quirk to work around issue generated by the SN65LVPE502CP USB3.0 re-driver
 * that causes ports behind that hardware to enter compliance mode sometimes.
 * The quirk creates a timer that polls every 2 seconds the link state of
 * each host controller's port and recovers it by issuing a Warm reset
 * if Compliance mode is detected, otherwise the port will become "dead" (no
 * device connections or disconnections will be detected anymore). Becasue no
 * status event is generated when entering compliance mode (per xhci spec),
 * this quirk is needed on systems that have the failing hardware installed.
 */
static void compliance_mode_recovery_timer_init(struct xhci_hcd *xhci)
{
	xhci->port_status_u0 = 0;
	timer_setup(&xhci->comp_mode_recovery_timer, compliance_mode_recovery,
		    0);
	xhci->comp_mode_recovery_timer.expires = jiffies +
			msecs_to_jiffies(COMP_MODE_RCVRY_MSECS);

	add_timer(&xhci->comp_mode_recovery_timer);
	xhci_dbg_trace(xhci, trace_xhci_dbg_quirks,
			"Compliance mode recovery timer initialized");
}

/*
 * This function identifies the systems that have installed the SN65LVPE502CP
 * USB3.0 re-driver and that need the Compliance Mode Quirk.
 * Systems:
 * Vendor: Hewlett-Packard -> System Models: Z420, Z620 and Z820
 */
static bool xhci_compliance_mode_recovery_timer_quirk_check(void)
{
	const char *dmi_product_name, *dmi_sys_vendor;

	dmi_product_name = dmi_get_system_info(DMI_PRODUCT_NAME);
	dmi_sys_vendor = dmi_get_system_info(DMI_SYS_VENDOR);
	if (!dmi_product_name || !dmi_sys_vendor)
		return false;

	if (!(strstr(dmi_sys_vendor, "Hewlett-Packard")))
		return false;

	if (strstr(dmi_product_name, "Z420") ||
			strstr(dmi_product_name, "Z620") ||
			strstr(dmi_product_name, "Z820") ||
			strstr(dmi_product_name, "Z1 Workstation"))
		return true;

	return false;
}

static int xhci_all_ports_seen_u0(struct xhci_hcd *xhci)
{
	return (xhci->port_status_u0 == ((1 << xhci->usb3_rhub.num_ports) - 1));
}


/*
 * Initialize memory for HCD and xHC (one-time init).
 *
 * Program the PAGESIZE register, initialize the device context array, create
 * device contexts (?), set up a command ring segment (or two?), create event
 * ring (one for now).
 */
static int xhci_init(struct usb_hcd *hcd)
{
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	int retval = 0;

	xhci_dbg_trace(xhci, trace_xhci_dbg_init, "xhci_init");
	spin_lock_init(&xhci->lock);
	if (xhci->hci_version == 0x95 && link_quirk) {
		xhci_dbg_trace(xhci, trace_xhci_dbg_quirks,
				"QUIRK: Not clearing Link TRB chain bits.");
		xhci->quirks |= XHCI_LINK_TRB_QUIRK;
	} else {
		xhci_dbg_trace(xhci, trace_xhci_dbg_init,
				"xHCI doesn't need link TRB QUIRK");
	}
	retval = xhci_mem_init(xhci, GFP_KERNEL);
	xhci_dbg_trace(xhci, trace_xhci_dbg_init, "Finished xhci_init");

	/* Initializing Compliance Mode Recovery Data If Needed */
	if (xhci_compliance_mode_recovery_timer_quirk_check()) {
		xhci->quirks |= XHCI_COMP_MODE_QUIRK;
		compliance_mode_recovery_timer_init(xhci);
	}

	return retval;
}

/*-------------------------------------------------------------------------*/


static int xhci_run_finished(struct xhci_hcd *xhci)
{
	if (xhci_start(xhci)) {
		xhci_halt(xhci);
		return -ENODEV;
	}
	xhci->shared_hcd->state = HC_STATE_RUNNING;
	xhci->cmd_ring_state = CMD_RING_STATE_RUNNING;

	if (xhci->quirks & XHCI_NEC_HOST)
		xhci_ring_cmd_db(xhci);

	xhci_dbg_trace(xhci, trace_xhci_dbg_init,
			"Finished xhci_run for USB3 roothub");
	return 0;
}

/*
 * Start the HC after it was halted.
 *
 * This function is called by the USB core when the HC driver is added.
 * Its opposite is xhci_stop().
 *
 * xhci_init() must be called once before this function can be called.
 * Reset the HC, enable device slot contexts, program DCBAAP, and
 * set command ring pointer and event ring pointer.
 *
 * Setup MSI-X vectors and enable interrupts.
 */
int xhci_run(struct usb_hcd *hcd)
{
	u32 temp;
	u64 temp_64;
	int ret;
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);

	/* Start the xHCI host controller running only after the USB 2.0 roothub
	 * is setup.
	 */

	hcd->uses_new_polling = 1;
	if (!usb_hcd_is_primary_hcd(hcd))
		return xhci_run_finished(xhci);

	xhci_dbg_trace(xhci, trace_xhci_dbg_init, "xhci_run");

	ret = xhci_try_enable_msi(hcd);
	if (ret)
		return ret;

	temp_64 = xhci_read_64(xhci, &xhci->ir_set->erst_dequeue);
	temp_64 &= ~ERST_PTR_MASK;
	xhci_dbg_trace(xhci, trace_xhci_dbg_init,
			"ERST deq = 64'h%0lx", (long unsigned int) temp_64);

	xhci_dbg_trace(xhci, trace_xhci_dbg_init,
			"// Set the interrupt modulation register");
	temp = readl(&xhci->ir_set->irq_control);
	temp &= ~ER_IRQ_INTERVAL_MASK;
	temp |= (xhci->imod_interval / 250) & ER_IRQ_INTERVAL_MASK;
	writel(temp, &xhci->ir_set->irq_control);

	/* Set the HCD state before we enable the irqs */
	temp = readl(&xhci->op_regs->command);
	temp |= (CMD_EIE);
	xhci_dbg_trace(xhci, trace_xhci_dbg_init,
			"// Enable interrupts, cmd = 0x%x.", temp);
	writel(temp, &xhci->op_regs->command);

	temp = readl(&xhci->ir_set->irq_pending);
	xhci_dbg_trace(xhci, trace_xhci_dbg_init,
			"// Enabling event ring interrupter %p by writing 0x%x to irq_pending",
			xhci->ir_set, (unsigned int) ER_IRQ_ENABLE(temp));
	writel(ER_IRQ_ENABLE(temp), &xhci->ir_set->irq_pending);

	if (xhci->quirks & XHCI_NEC_HOST) {
		struct xhci_command *command;

		command = xhci_alloc_command(xhci, false, GFP_KERNEL);
		if (!command)
			return -ENOMEM;

		ret = xhci_queue_vendor_command(xhci, command, 0, 0, 0,
				TRB_TYPE(TRB_NEC_GET_FW));
		if (ret)
			xhci_free_command(xhci, command);
	}
	xhci_dbg_trace(xhci, trace_xhci_dbg_init,
			"Finished xhci_run for USB2 roothub");

	xhci_dbc_init(xhci);

	xhci_debugfs_init(xhci);

	return 0;
}
EXPORT_SYMBOL_GPL(xhci_run);

/*
 * Stop xHCI driver.
 *
 * This function is called by the USB core when the HC driver is removed.
 * Its opposite is xhci_run().
 *
 * Disable device contexts, disable IRQs, and quiesce the HC.
 * Reset the HC, finish any completed transactions, and cleanup memory.
 */
static void xhci_stop(struct usb_hcd *hcd)
{
	u32 temp;
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);

	mutex_lock(&xhci->mutex);

	/* Only halt host and free memory after both hcds are removed */
	if (!usb_hcd_is_primary_hcd(hcd)) {
		mutex_unlock(&xhci->mutex);
		return;
	}

	xhci_dbc_exit(xhci);

	spin_lock_irq(&xhci->lock);
	xhci->xhc_state |= XHCI_STATE_HALTED;
	xhci->cmd_ring_state = CMD_RING_STATE_STOPPED;
	xhci_halt(xhci);
	xhci_reset(xhci);
	spin_unlock_irq(&xhci->lock);

	xhci_cleanup_msix(xhci);

	/* Deleting Compliance Mode Recovery Timer */
	if ((xhci->quirks & XHCI_COMP_MODE_QUIRK) &&
			(!(xhci_all_ports_seen_u0(xhci)))) {
		del_timer_sync(&xhci->comp_mode_recovery_timer);
		xhci_dbg_trace(xhci, trace_xhci_dbg_quirks,
				"%s: compliance mode recovery timer deleted",
				__func__);
	}

	if (xhci->quirks & XHCI_AMD_PLL_FIX)
		usb_amd_dev_put();

	xhci_dbg_trace(xhci, trace_xhci_dbg_init,
			"// Disabling event ring interrupts");
	temp = readl(&xhci->op_regs->status);
	writel((temp & ~0x1fff) | STS_EINT, &xhci->op_regs->status);
	temp = readl(&xhci->ir_set->irq_pending);
	writel(ER_IRQ_DISABLE(temp), &xhci->ir_set->irq_pending);

	xhci_dbg_trace(xhci, trace_xhci_dbg_init, "cleaning up memory");
	xhci_mem_cleanup(xhci);
	xhci_debugfs_exit(xhci);
	xhci_dbg_trace(xhci, trace_xhci_dbg_init,
			"xhci_stop completed - status = %x",
			readl(&xhci->op_regs->status));
	mutex_unlock(&xhci->mutex);
}

/*
 * Shutdown HC (not bus-specific)
 *
 * This is called when the machine is rebooting or halting.  We assume that the
 * machine will be powered off, and the HC's internal state will be reset.
 * Don't bother to free memory.
 *
 * This will only ever be called with the main usb_hcd (the USB3 roothub).
 */
void xhci_shutdown(struct usb_hcd *hcd)
{
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);

	if (xhci->quirks & XHCI_SPURIOUS_REBOOT)
		usb_disable_xhci_ports(to_pci_dev(hcd->self.sysdev));

	spin_lock_irq(&xhci->lock);
	xhci_halt(xhci);
	/* Workaround for spurious wakeups at shutdown with HSW */
	if (xhci->quirks & XHCI_SPURIOUS_WAKEUP)
		xhci_reset(xhci);
	spin_unlock_irq(&xhci->lock);

	xhci_cleanup_msix(xhci);

	xhci_dbg_trace(xhci, trace_xhci_dbg_init,
			"xhci_shutdown completed - status = %x",
			readl(&xhci->op_regs->status));
}
EXPORT_SYMBOL_GPL(xhci_shutdown);

#ifdef CONFIG_PM
static void xhci_save_registers(struct xhci_hcd *xhci)
{
	xhci->s3.command = readl(&xhci->op_regs->command);
	xhci->s3.dev_nt = readl(&xhci->op_regs->dev_notification);
	xhci->s3.dcbaa_ptr = xhci_read_64(xhci, &xhci->op_regs->dcbaa_ptr);
	xhci->s3.config_reg = readl(&xhci->op_regs->config_reg);
	xhci->s3.erst_size = readl(&xhci->ir_set->erst_size);
	xhci->s3.erst_base = xhci_read_64(xhci, &xhci->ir_set->erst_base);
	xhci->s3.erst_dequeue = xhci_read_64(xhci, &xhci->ir_set->erst_dequeue);
	xhci->s3.irq_pending = readl(&xhci->ir_set->irq_pending);
	xhci->s3.irq_control = readl(&xhci->ir_set->irq_control);
}

static void xhci_restore_registers(struct xhci_hcd *xhci)
{
	writel(xhci->s3.command, &xhci->op_regs->command);
	writel(xhci->s3.dev_nt, &xhci->op_regs->dev_notification);
	xhci_write_64(xhci, xhci->s3.dcbaa_ptr, &xhci->op_regs->dcbaa_ptr);
	writel(xhci->s3.config_reg, &xhci->op_regs->config_reg);
	writel(xhci->s3.erst_size, &xhci->ir_set->erst_size);
	xhci_write_64(xhci, xhci->s3.erst_base, &xhci->ir_set->erst_base);
	xhci_write_64(xhci, xhci->s3.erst_dequeue, &xhci->ir_set->erst_dequeue);
	writel(xhci->s3.irq_pending, &xhci->ir_set->irq_pending);
	writel(xhci->s3.irq_control, &xhci->ir_set->irq_control);
}

static void xhci_set_cmd_ring_deq(struct xhci_hcd *xhci)
{
	u64	val_64;

	/* step 2: initialize command ring buffer */
	val_64 = xhci_read_64(xhci, &xhci->op_regs->cmd_ring);
	val_64 = (val_64 & (u64) CMD_RING_RSVD_BITS) |
		(xhci_trb_virt_to_dma(xhci->cmd_ring->deq_seg,
				      xhci->cmd_ring->dequeue) &
		 (u64) ~CMD_RING_RSVD_BITS) |
		xhci->cmd_ring->cycle_state;
	xhci_dbg_trace(xhci, trace_xhci_dbg_init,
			"// Setting command ring address to 0x%llx",
			(long unsigned long) val_64);
	xhci_write_64(xhci, val_64, &xhci->op_regs->cmd_ring);
}

/*
 * The whole command ring must be cleared to zero when we suspend the host.
 *
 * The host doesn't save the command ring pointer in the suspend well, so we
 * need to re-program it on resume.  Unfortunately, the pointer must be 64-byte
 * aligned, because of the reserved bits in the command ring dequeue pointer
 * register.  Therefore, we can't just set the dequeue pointer back in the
 * middle of the ring (TRBs are 16-byte aligned).
 */
static void xhci_clear_command_ring(struct xhci_hcd *xhci)
{
	struct xhci_ring *ring;
	struct xhci_segment *seg;

	ring = xhci->cmd_ring;
	seg = ring->deq_seg;
	do {
		memset(seg->trbs, 0,
			sizeof(union xhci_trb) * (TRBS_PER_SEGMENT - 1));
		seg->trbs[TRBS_PER_SEGMENT - 1].link.control &=
			cpu_to_le32(~TRB_CYCLE);
		seg = seg->next;
	} while (seg != ring->deq_seg);

	/* Reset the software enqueue and dequeue pointers */
	ring->deq_seg = ring->first_seg;
	ring->dequeue = ring->first_seg->trbs;
	ring->enq_seg = ring->deq_seg;
	ring->enqueue = ring->dequeue;

	ring->num_trbs_free = ring->num_segs * (TRBS_PER_SEGMENT - 1) - 1;
	/*
	 * Ring is now zeroed, so the HW should look for change of ownership
	 * when the cycle bit is set to 1.
	 */
	ring->cycle_state = 1;

	/*
	 * Reset the hardware dequeue pointer.
	 * Yes, this will need to be re-written after resume, but we're paranoid
	 * and want to make sure the hardware doesn't access bogus memory
	 * because, say, the BIOS or an SMI started the host without changing
	 * the command ring pointers.
	 */
	xhci_set_cmd_ring_deq(xhci);
}

/*
 * Disable port wake bits if do_wakeup is not set.
 *
 * Also clear a possible internal port wake state left hanging for ports that
 * detected termination but never successfully enumerated (trained to 0U).
 * Internal wake causes immediate xHCI wake after suspend. PORT_CSC write done
 * at enumeration clears this wake, force one here as well for unconnected ports
 */

static void xhci_disable_hub_port_wake(struct xhci_hcd *xhci,
				       struct xhci_hub *rhub,
				       bool do_wakeup)
{
	unsigned long flags;
	u32 t1, t2, portsc;
	int i;

	spin_lock_irqsave(&xhci->lock, flags);

	for (i = 0; i < rhub->num_ports; i++) {
		portsc = readl(rhub->ports[i]->addr);
		t1 = xhci_port_state_to_neutral(portsc);
		t2 = t1;

		/* clear wake bits if do_wake is not set */
		if (!do_wakeup)
			t2 &= ~PORT_WAKE_BITS;

		/* Don't touch csc bit if connected or connect change is set */
		if (!(portsc & (PORT_CSC | PORT_CONNECT)))
			t2 |= PORT_CSC;

		if (t1 != t2) {
			writel(t2, rhub->ports[i]->addr);
			xhci_dbg(xhci, "config port %d-%d wake bits, portsc: 0x%x, write: 0x%x\n",
				 rhub->hcd->self.busnum, i + 1, portsc, t2);
		}
	}
	spin_unlock_irqrestore(&xhci->lock, flags);
}

static bool xhci_pending_portevent(struct xhci_hcd *xhci)
{
	struct xhci_port	**ports;
	int			port_index;
	u32			status;
	u32			portsc;

	status = readl(&xhci->op_regs->status);
	if (status & STS_EINT)
		return true;
	/*
	 * Checking STS_EINT is not enough as there is a lag between a change
	 * bit being set and the Port Status Change Event that it generated
	 * being written to the Event Ring. See note in xhci 1.1 section 4.19.2.
	 */

	port_index = xhci->usb2_rhub.num_ports;
	ports = xhci->usb2_rhub.ports;
	while (port_index--) {
		portsc = readl(ports[port_index]->addr);
		if (portsc & PORT_CHANGE_MASK ||
		    (portsc & PORT_PLS_MASK) == XDEV_RESUME)
			return true;
	}
	port_index = xhci->usb3_rhub.num_ports;
	ports = xhci->usb3_rhub.ports;
	while (port_index--) {
		portsc = readl(ports[port_index]->addr);
		if (portsc & PORT_CHANGE_MASK ||
		    (portsc & PORT_PLS_MASK) == XDEV_RESUME)
			return true;
	}
	return false;
}

/*
 * Stop HC (not bus-specific)
 *
 * This is called when the machine transition into S3/S4 mode.
 *
 */
int xhci_suspend(struct xhci_hcd *xhci, bool do_wakeup)
{
	int			rc = 0;
	unsigned int		delay = XHCI_MAX_HALT_USEC * 2;
	struct usb_hcd		*hcd = xhci_to_hcd(xhci);
	u32			command;
	u32			res;

	if (!hcd->state)
		return 0;

	if (hcd->state != HC_STATE_SUSPENDED ||
			xhci->shared_hcd->state != HC_STATE_SUSPENDED)
		return -EINVAL;

	/* Clear root port wake on bits if wakeup not allowed. */
	xhci_disable_hub_port_wake(xhci, &xhci->usb3_rhub, do_wakeup);
	xhci_disable_hub_port_wake(xhci, &xhci->usb2_rhub, do_wakeup);

	if (!HCD_HW_ACCESSIBLE(hcd))
		return 0;

	xhci_dbc_suspend(xhci);

	/* Don't poll the roothubs on bus suspend. */
	xhci_dbg(xhci, "%s: stopping port polling.\n", __func__);
	clear_bit(HCD_FLAG_POLL_RH, &hcd->flags);
	del_timer_sync(&hcd->rh_timer);
	clear_bit(HCD_FLAG_POLL_RH, &xhci->shared_hcd->flags);
	del_timer_sync(&xhci->shared_hcd->rh_timer);

	if (xhci->quirks & XHCI_SUSPEND_DELAY)
		usleep_range(1000, 1500);

	spin_lock_irq(&xhci->lock);
	clear_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags);
	clear_bit(HCD_FLAG_HW_ACCESSIBLE, &xhci->shared_hcd->flags);
	/* step 1: stop endpoint */
	/* skipped assuming that port suspend has done */

	/* step 2: clear Run/Stop bit */
	command = readl(&xhci->op_regs->command);
	command &= ~CMD_RUN;
	writel(command, &xhci->op_regs->command);

	/* Some chips from Fresco Logic need an extraordinary delay */
	delay *= (xhci->quirks & XHCI_SLOW_SUSPEND) ? 10 : 1;

	if (xhci_handshake(&xhci->op_regs->status,
		      STS_HALT, STS_HALT, delay)) {
		xhci_warn(xhci, "WARN: xHC CMD_RUN timeout\n");
		spin_unlock_irq(&xhci->lock);
		return -ETIMEDOUT;
	}
	xhci_clear_command_ring(xhci);

	/* step 3: save registers */
	xhci_save_registers(xhci);

	/* step 4: set CSS flag */
	command = readl(&xhci->op_regs->command);
	command |= CMD_CSS;
	writel(command, &xhci->op_regs->command);
	xhci->broken_suspend = 0;
	if (xhci_handshake(&xhci->op_regs->status,
				STS_SAVE, 0, 20 * 1000)) {
	/*
	 * AMD SNPS xHC 3.0 occasionally does not clear the
	 * SSS bit of USBSTS and when driver tries to poll
	 * to see if the xHC clears BIT(8) which never happens
	 * and driver assumes that controller is not responding
	 * and times out. To workaround this, its good to check
	 * if SRE and HCE bits are not set (as per xhci
	 * Section 5.4.2) and bypass the timeout.
	 */
		res = readl(&xhci->op_regs->status);
		if ((xhci->quirks & XHCI_SNPS_BROKEN_SUSPEND) &&
		    (((res & STS_SRE) == 0) &&
				((res & STS_HCE) == 0))) {
			xhci->broken_suspend = 1;
		} else {
			xhci_warn(xhci, "WARN: xHC save state timeout\n");
			spin_unlock_irq(&xhci->lock);
			return -ETIMEDOUT;
		}
	}
	spin_unlock_irq(&xhci->lock);

	/*
	 * Deleting Compliance Mode Recovery Timer because the xHCI Host
	 * is about to be suspended.
	 */
	if ((xhci->quirks & XHCI_COMP_MODE_QUIRK) &&
			(!(xhci_all_ports_seen_u0(xhci)))) {
		del_timer_sync(&xhci->comp_mode_recovery_timer);
		xhci_dbg_trace(xhci, trace_xhci_dbg_quirks,
				"%s: compliance mode recovery timer deleted",
				__func__);
	}

	/* step 5: remove core well power */
	/* synchronize irq when using MSI-X */
	xhci_msix_sync_irqs(xhci);

	return rc;
}
EXPORT_SYMBOL_GPL(xhci_suspend);

/*
 * start xHC (not bus-specific)
 *
 * This is called when the machine transition from S3/S4 mode.
 *
 */
int xhci_resume(struct xhci_hcd *xhci, bool hibernated)
{
	u32			command, temp = 0;
	struct usb_hcd		*hcd = xhci_to_hcd(xhci);
	struct usb_hcd		*secondary_hcd;
	int			retval = 0;
	bool			comp_timer_running = false;
	bool			pending_portevent = false;

	if (!hcd->state)
		return 0;

	/* Wait a bit if either of the roothubs need to settle from the
	 * transition into bus suspend.
	 */

	if (time_before(jiffies, xhci->usb2_rhub.bus_state.next_statechange) ||
	    time_before(jiffies, xhci->usb3_rhub.bus_state.next_statechange))
		msleep(100);

	set_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags);
	set_bit(HCD_FLAG_HW_ACCESSIBLE, &xhci->shared_hcd->flags);

	spin_lock_irq(&xhci->lock);
	if ((xhci->quirks & XHCI_RESET_ON_RESUME) || xhci->broken_suspend)
		hibernated = true;

	if (!hibernated) {
		/*
		 * Some controllers might lose power during suspend, so wait
		 * for controller not ready bit to clear, just as in xHC init.
		 */
		retval = xhci_handshake(&xhci->op_regs->status,
					STS_CNR, 0, 10 * 1000 * 1000);
		if (retval) {
			xhci_warn(xhci, "Controller not ready at resume %d\n",
				  retval);
			spin_unlock_irq(&xhci->lock);
			return retval;
		}
		/* step 1: restore register */
		xhci_restore_registers(xhci);
		/* step 2: initialize command ring buffer */
		xhci_set_cmd_ring_deq(xhci);
		/* step 3: restore state and start state*/
		/* step 3: set CRS flag */
		command = readl(&xhci->op_regs->command);
		command |= CMD_CRS;
		writel(command, &xhci->op_regs->command);
		/*
		 * Some controllers take up to 55+ ms to complete the controller
		 * restore so setting the timeout to 100ms. Xhci specification
		 * doesn't mention any timeout value.
		 */
		if (xhci_handshake(&xhci->op_regs->status,
			      STS_RESTORE, 0, 100 * 1000)) {
			xhci_warn(xhci, "WARN: xHC restore state timeout\n");
			spin_unlock_irq(&xhci->lock);
			return -ETIMEDOUT;
		}
		temp = readl(&xhci->op_regs->status);
	}

	/* If restore operation fails, re-initialize the HC during resume */
	if ((temp & STS_SRE) || hibernated) {

		if ((xhci->quirks & XHCI_COMP_MODE_QUIRK) &&
				!(xhci_all_ports_seen_u0(xhci))) {
			del_timer_sync(&xhci->comp_mode_recovery_timer);
			xhci_dbg_trace(xhci, trace_xhci_dbg_quirks,
				"Compliance Mode Recovery Timer deleted!");
		}

		/* Let the USB core know _both_ roothubs lost power. */
		usb_root_hub_lost_power(xhci->main_hcd->self.root_hub);
		usb_root_hub_lost_power(xhci->shared_hcd->self.root_hub);

		xhci_dbg(xhci, "Stop HCD\n");
		xhci_halt(xhci);
		xhci_zero_64b_regs(xhci);
		retval = xhci_reset(xhci);
		spin_unlock_irq(&xhci->lock);
		if (retval)
			return retval;
		xhci_cleanup_msix(xhci);

		xhci_dbg(xhci, "// Disabling event ring interrupts\n");
		temp = readl(&xhci->op_regs->status);
		writel((temp & ~0x1fff) | STS_EINT, &xhci->op_regs->status);
		temp = readl(&xhci->ir_set->irq_pending);
		writel(ER_IRQ_DISABLE(temp), &xhci->ir_set->irq_pending);

		xhci_dbg(xhci, "cleaning up memory\n");
		xhci_mem_cleanup(xhci);
		xhci_debugfs_exit(xhci);
		xhci_dbg(xhci, "xhci_stop completed - status = %x\n",
			    readl(&xhci->op_regs->status));

		/* USB core calls the PCI reinit and start functions twice:
		 * first with the primary HCD, and then with the secondary HCD.
		 * If we don't do the same, the host will never be started.
		 */
		if (!usb_hcd_is_primary_hcd(hcd))
			secondary_hcd = hcd;
		else
			secondary_hcd = xhci->shared_hcd;

		xhci_dbg(xhci, "Initialize the xhci_hcd\n");
		retval = xhci_init(hcd->primary_hcd);
		if (retval)
			return retval;
		comp_timer_running = true;

		xhci_dbg(xhci, "Start the primary HCD\n");
		retval = xhci_run(hcd->primary_hcd);
		if (!retval) {
			xhci_dbg(xhci, "Start the secondary HCD\n");
			retval = xhci_run(secondary_hcd);
		}
		hcd->state = HC_STATE_SUSPENDED;
		xhci->shared_hcd->state = HC_STATE_SUSPENDED;
		goto done;
	}

	/* step 4: set Run/Stop bit */
	command = readl(&xhci->op_regs->command);
	command |= CMD_RUN;
	writel(command, &xhci->op_regs->command);
	xhci_handshake(&xhci->op_regs->status, STS_HALT,
		  0, 250 * 1000);

	/* step 5: walk topology and initialize portsc,
	 * portpmsc and portli
	 */
	/* this is done in bus_resume */

	/* step 6: restart each of the previously
	 * Running endpoints by ringing their doorbells
	 */

	spin_unlock_irq(&xhci->lock);

	xhci_dbc_resume(xhci);

 done:
	if (retval == 0) {
		/*
		 * Resume roothubs only if there are pending events.
		 * USB 3 devices resend U3 LFPS wake after a 100ms delay if
		 * the first wake signalling failed, give it that chance.
		 */
		pending_portevent = xhci_pending_portevent(xhci);
		if (!pending_portevent) {
			msleep(120);
			pending_portevent = xhci_pending_portevent(xhci);
		}

		if (pending_portevent) {
			usb_hcd_resume_root_hub(xhci->shared_hcd);
			usb_hcd_resume_root_hub(hcd);
		}
	}
	/*
	 * If system is subject to the Quirk, Compliance Mode Timer needs to
	 * be re-initialized Always after a system resume. Ports are subject
	 * to suffer the Compliance Mode issue again. It doesn't matter if
	 * ports have entered previously to U0 before system's suspension.
	 */
	if ((xhci->quirks & XHCI_COMP_MODE_QUIRK) && !comp_timer_running)
		compliance_mode_recovery_timer_init(xhci);

	if (xhci->quirks & XHCI_ASMEDIA_MODIFY_FLOWCONTROL)
		usb_asmedia_modifyflowcontrol(to_pci_dev(hcd->self.controller));

	/* Re-enable port polling. */
	xhci_dbg(xhci, "%s: starting port polling.\n", __func__);
	set_bit(HCD_FLAG_POLL_RH, &xhci->shared_hcd->flags);
	usb_hcd_poll_rh_status(xhci->shared_hcd);
	set_bit(HCD_FLAG_POLL_RH, &hcd->flags);
	usb_hcd_poll_rh_status(hcd);

	return retval;
}
EXPORT_SYMBOL_GPL(xhci_resume);
#endif	/* CONFIG_PM */

/*-------------------------------------------------------------------------*/

/*
 * Bypass the DMA mapping if URB is suitable for Immediate Transfer (IDT),
 * we'll copy the actual data into the TRB address register. This is limited to
 * transfers up to 8 bytes on output endpoints of any kind with wMaxPacketSize
 * >= 8 bytes. If suitable for IDT only one Transfer TRB per TD is allowed.
 */
static int xhci_map_urb_for_dma(struct usb_hcd *hcd, struct urb *urb,
				gfp_t mem_flags)
{
	if (xhci_urb_suitable_for_idt(urb))
		return 0;

	return usb_hcd_map_urb_for_dma(hcd, urb, mem_flags);
}

/*
 * xhci_get_endpoint_index - Used for passing endpoint bitmasks between the core and
 * HCDs.  Find the index for an endpoint given its descriptor.  Use the return
 * value to right shift 1 for the bitmask.
 *
 * Index  = (epnum * 2) + direction - 1,
 * where direction = 0 for OUT, 1 for IN.
 * For control endpoints, the IN index is used (OUT index is unused), so
 * index = (epnum * 2) + direction - 1 = (epnum * 2) + 1 - 1 = (epnum * 2)
 */
unsigned int xhci_get_endpoint_index(struct usb_endpoint_descriptor *desc)
{
	unsigned int index;
	if (usb_endpoint_xfer_control(desc))
		index = (unsigned int) (usb_endpoint_num(desc)*2);
	else
		index = (unsigned int) (usb_endpoint_num(desc)*2) +
			(usb_endpoint_dir_in(desc) ? 1 : 0) - 1;
	return index;
}
EXPORT_SYMBOL_GPL(xhci_get_endpoint_index);

/* The reverse operation to xhci_get_endpoint_index. Calculate the USB endpoint
 * address from the XHCI endpoint index.
 */
unsigned int xhci_get_endpoint_address(unsigned int ep_index)
{
	unsigned int number = DIV_ROUND_UP(ep_index, 2);
	unsigned int direction = ep_index % 2 ? USB_DIR_OUT : USB_DIR_IN;
	return direction | number;
}
EXPORT_SYMBOL_GPL(xhci_get_endpoint_address);

/* Find the flag for this endpoint (for use in the control context).  Use the
 * endpoint index to create a bitmask.  The slot context is bit 0, endpoint 0 is
 * bit 1, etc.
 */
static unsigned int xhci_get_endpoint_flag(struct usb_endpoint_descriptor *desc)
{
	return 1 << (xhci_get_endpoint_index(desc) + 1);
}

/* Compute the last valid endpoint context index.  Basically, this is the
 * endpoint index plus one.  For slot contexts with more than valid endpoint,
 * we find the most significant bit set in the added contexts flags.
 * e.g. ep 1 IN (with epnum 0x81) => added_ctxs = 0b1000
 * fls(0b1000) = 4, but the endpoint context index is 3, so subtract one.
 */
unsigned int xhci_last_valid_endpoint(u32 added_ctxs)
{
	return fls(added_ctxs) - 1;
}

/* Returns 1 if the arguments are OK;
 * returns 0 this is a root hub; returns -EINVAL for NULL pointers.
 */
static int xhci_check_args(struct usb_hcd *hcd, struct usb_device *udev,
		struct usb_host_endpoint *ep, int check_ep, bool check_virt_dev,
		const char *func) {
	struct xhci_hcd	*xhci;
	struct xhci_virt_device	*virt_dev;

	if (!hcd || (check_ep && !ep) || !udev) {
		pr_debug("xHCI %s called with invalid args\n", func);
		return -EINVAL;
	}
	if (!udev->parent) {
		pr_debug("xHCI %s called for root hub\n", func);
		return 0;
	}

	xhci = hcd_to_xhci(hcd);
	if (check_virt_dev) {
		if (!udev->slot_id || !xhci->devs[udev->slot_id]) {
			xhci_dbg(xhci, "xHCI %s called with unaddressed device\n",
					func);
			return -EINVAL;
		}

		virt_dev = xhci->devs[udev->slot_id];
		if (virt_dev->udev != udev) {
			xhci_dbg(xhci, "xHCI %s called with udev and "
					  "virt_dev does not match\n", func);
			return -EINVAL;
		}
	}

	if (xhci->xhc_state & XHCI_STATE_HALTED)
		return -ENODEV;

	return 1;
}

static int xhci_configure_endpoint(struct xhci_hcd *xhci,
		struct usb_device *udev, struct xhci_command *command,
		bool ctx_change, bool must_succeed);

/*
 * Full speed devices may have a max packet size greater than 8 bytes, but the
 * USB core doesn't know that until it reads the first 8 bytes of the
 * descriptor.  If the usb_device's max packet size changes after that point,
 * we need to issue an evaluate context command and wait on it.
 */
static int xhci_check_maxpacket(struct xhci_hcd *xhci, unsigned int slot_id,
		unsigned int ep_index, struct urb *urb, gfp_t mem_flags)
{
	struct xhci_container_ctx *out_ctx;
	struct xhci_input_control_ctx *ctrl_ctx;
	struct xhci_ep_ctx *ep_ctx;
	struct xhci_command *command;
	int max_packet_size;
	int hw_max_packet_size;
	int ret = 0;

	out_ctx = xhci->devs[slot_id]->out_ctx;
	ep_ctx = xhci_get_ep_ctx(xhci, out_ctx, ep_index);
	hw_max_packet_size = MAX_PACKET_DECODED(le32_to_cpu(ep_ctx->ep_info2));
	max_packet_size = usb_endpoint_maxp(&urb->dev->ep0.desc);
	if (hw_max_packet_size != max_packet_size) {
		xhci_dbg_trace(xhci,  trace_xhci_dbg_context_change,
				"Max Packet Size for ep 0 changed.");
		xhci_dbg_trace(xhci,  trace_xhci_dbg_context_change,
				"Max packet size in usb_device = %d",
				max_packet_size);
		xhci_dbg_trace(xhci,  trace_xhci_dbg_context_change,
				"Max packet size in xHCI HW = %d",
				hw_max_packet_size);
		xhci_dbg_trace(xhci,  trace_xhci_dbg_context_change,
				"Issuing evaluate context command.");

		/* Set up the input context flags for the command */
		/* FIXME: This won't work if a non-default control endpoint
		 * changes max packet sizes.
		 */

		command = xhci_alloc_command(xhci, true, mem_flags);
		if (!command)
			return -ENOMEM;

		command->in_ctx = xhci->devs[slot_id]->in_ctx;
		ctrl_ctx = xhci_get_input_control_ctx(command->in_ctx);
		if (!ctrl_ctx) {
			xhci_warn(xhci, "%s: Could not get input context, bad type.\n",
					__func__);
			ret = -ENOMEM;
			goto command_cleanup;
		}
		/* Set up the modified control endpoint 0 */
		xhci_endpoint_copy(xhci, xhci->devs[slot_id]->in_ctx,
				xhci->devs[slot_id]->out_ctx, ep_index);

		ep_ctx = xhci_get_ep_ctx(xhci, command->in_ctx, ep_index);
		ep_ctx->ep_info &= cpu_to_le32(~EP_STATE_MASK);/* must clear */
		ep_ctx->ep_info2 &= cpu_to_le32(~MAX_PACKET_MASK);
		ep_ctx->ep_info2 |= cpu_to_le32(MAX_PACKET(max_packet_size));

		ctrl_ctx->add_flags = cpu_to_le32(EP0_FLAG);
		ctrl_ctx->drop_flags = 0;

		ret = xhci_configure_endpoint(xhci, urb->dev, command,
				true, false);

		/* Clean up the input context for later use by bandwidth
		 * functions.
		 */
		ctrl_ctx->add_flags = cpu_to_le32(SLOT_FLAG);
command_cleanup:
		kfree(command->completion);
		kfree(command);
	}
	return ret;
}

/*
 * non-error returns are a promise to giveback() the urb later
 * we drop ownership so next owner (or urb unlink) can get it
 */
static int xhci_urb_enqueue(struct usb_hcd *hcd, struct urb *urb, gfp_t mem_flags)
{
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	unsigned long flags;
	int ret = 0;
	unsigned int slot_id, ep_index;
	unsigned int *ep_state;
	struct urb_priv	*urb_priv;
	int num_tds;

	if (!urb || xhci_check_args(hcd, urb->dev, urb->ep,
					true, true, __func__) <= 0)
		return -EINVAL;

	slot_id = urb->dev->slot_id;
	ep_index = xhci_get_endpoint_index(&urb->ep->desc);
	ep_state = &xhci->devs[slot_id]->eps[ep_index].ep_state;

	if (!HCD_HW_ACCESSIBLE(hcd)) {
		if (!in_interrupt())
			xhci_dbg(xhci, "urb submitted during PCI suspend\n");
		return -ESHUTDOWN;
	}
	if (xhci->devs[slot_id]->flags & VDEV_PORT_ERROR) {
		xhci_dbg(xhci, "Can't queue urb, port error, link inactive\n");
		return -ENODEV;
	}

	if (xhci_vendor_usb_offload_skip_urb(xhci, urb)) {
		xhci_dbg(xhci, "skip urb for usb offload\n");
		return -EOPNOTSUPP;
	}

	if (usb_endpoint_xfer_isoc(&urb->ep->desc))
		num_tds = urb->number_of_packets;
	else if (usb_endpoint_is_bulk_out(&urb->ep->desc) &&
	    urb->transfer_buffer_length > 0 &&
	    urb->transfer_flags & URB_ZERO_PACKET &&
	    !(urb->transfer_buffer_length % usb_endpoint_maxp(&urb->ep->desc)))
		num_tds = 2;
	else
		num_tds = 1;

	urb_priv = kzalloc(struct_size(urb_priv, td, num_tds), mem_flags);
	if (!urb_priv)
		return -ENOMEM;

	urb_priv->num_tds = num_tds;
	urb_priv->num_tds_done = 0;
	urb->hcpriv = urb_priv;

	trace_xhci_urb_enqueue(urb);

	if (usb_endpoint_xfer_control(&urb->ep->desc)) {
		/* Check to see if the max packet size for the default control
		 * endpoint changed during FS device enumeration
		 */
		if (urb->dev->speed == USB_SPEED_FULL) {
			ret = xhci_check_maxpacket(xhci, slot_id,
					ep_index, urb, mem_flags);
			if (ret < 0) {
				xhci_urb_free_priv(urb_priv);
				urb->hcpriv = NULL;
				return ret;
			}
		}
	}

	spin_lock_irqsave(&xhci->lock, flags);

	if (xhci->xhc_state & XHCI_STATE_DYING) {
		xhci_dbg(xhci, "Ep 0x%x: URB %p submitted for non-responsive xHCI host.\n",
			 urb->ep->desc.bEndpointAddress, urb);
		ret = -ESHUTDOWN;
		goto free_priv;
	}
	if (*ep_state & (EP_GETTING_STREAMS | EP_GETTING_NO_STREAMS)) {
		xhci_warn(xhci, "WARN: Can't enqueue URB, ep in streams transition state %x\n",
			  *ep_state);
		ret = -EINVAL;
		goto free_priv;
	}
	if (*ep_state & EP_SOFT_CLEAR_TOGGLE) {
		xhci_warn(xhci, "Can't enqueue URB while manually clearing toggle\n");
		ret = -EINVAL;
		goto free_priv;
	}

	switch (usb_endpoint_type(&urb->ep->desc)) {

	case USB_ENDPOINT_XFER_CONTROL:
		ret = xhci_queue_ctrl_tx(xhci, GFP_ATOMIC, urb,
					 slot_id, ep_index);
		break;
	case USB_ENDPOINT_XFER_BULK:
		ret = xhci_queue_bulk_tx(xhci, GFP_ATOMIC, urb,
					 slot_id, ep_index);
		break;
	case USB_ENDPOINT_XFER_INT:
		ret = xhci_queue_intr_tx(xhci, GFP_ATOMIC, urb,
				slot_id, ep_index);
		break;
	case USB_ENDPOINT_XFER_ISOC:
		ret = xhci_queue_isoc_tx_prepare(xhci, GFP_ATOMIC, urb,
				slot_id, ep_index);
	}

	if (ret) {
free_priv:
		xhci_urb_free_priv(urb_priv);
		urb->hcpriv = NULL;
	}
	spin_unlock_irqrestore(&xhci->lock, flags);
	return ret;
}

/*
 * Remove the URB's TD from the endpoint ring.  This may cause the HC to stop
 * USB transfers, potentially stopping in the middle of a TRB buffer.  The HC
 * should pick up where it left off in the TD, unless a Set Transfer Ring
 * Dequeue Pointer is issued.
 *
 * The TRBs that make up the buffers for the canceled URB will be "removed" from
 * the ring.  Since the ring is a contiguous structure, they can't be physically
 * removed.  Instead, there are two options:
 *
 *  1) If the HC is in the middle of processing the URB to be canceled, we
 *     simply move the ring's dequeue pointer past those TRBs using the Set
 *     Transfer Ring Dequeue Pointer command.  This will be the common case,
 *     when drivers timeout on the last submitted URB and attempt to cancel.
 *
 *  2) If the HC is in the middle of a different TD, we turn the TRBs into a
 *     series of 1-TRB transfer no-op TDs.  (No-ops shouldn't be chained.)  The
 *     HC will need to invalidate the any TRBs it has cached after the stop
 *     endpoint command, as noted in the xHCI 0.95 errata.
 *
 *  3) The TD may have completed by the time the Stop Endpoint Command
 *     completes, so software needs to handle that case too.
 *
 * This function should protect against the TD enqueueing code ringing the
 * doorbell while this code is waiting for a Stop Endpoint command to complete.
 * It also needs to account for multiple cancellations on happening at the same
 * time for the same endpoint.
 *
 * Note that this function can be called in any context, or so says
 * usb_hcd_unlink_urb()
 */
static int xhci_urb_dequeue(struct usb_hcd *hcd, struct urb *urb, int status)
{
	unsigned long flags;
	int ret, i;
	u32 temp;
	struct xhci_hcd *xhci;
	struct urb_priv	*urb_priv;
	struct xhci_td *td;
	unsigned int ep_index;
	struct xhci_ring *ep_ring;
	struct xhci_virt_ep *ep;
	struct xhci_command *command;
	struct xhci_virt_device *vdev;

	xhci = hcd_to_xhci(hcd);
	spin_lock_irqsave(&xhci->lock, flags);

	trace_xhci_urb_dequeue(urb);

	/* Make sure the URB hasn't completed or been unlinked already */
	ret = usb_hcd_check_unlink_urb(hcd, urb, status);
	if (ret)
		goto done;

	/* give back URB now if we can't queue it for cancel */
	vdev = xhci->devs[urb->dev->slot_id];
	urb_priv = urb->hcpriv;
	if (!vdev || !urb_priv)
		goto err_giveback;

	ep_index = xhci_get_endpoint_index(&urb->ep->desc);
	ep = &vdev->eps[ep_index];
	ep_ring = xhci_urb_to_transfer_ring(xhci, urb);
	if (!ep || !ep_ring)
		goto err_giveback;

	/* If xHC is dead take it down and return ALL URBs in xhci_hc_died() */
	temp = readl(&xhci->op_regs->status);
	if (temp == ~(u32)0 || xhci->xhc_state & XHCI_STATE_DYING) {
		xhci_hc_died(xhci);
		goto done;
	}

	/*
	 * check ring is not re-allocated since URB was enqueued. If it is, then
	 * make sure none of the ring related pointers in this URB private data
	 * are touched, such as td_list, otherwise we overwrite freed data
	 */
	if (!td_on_ring(&urb_priv->td[0], ep_ring)) {
		xhci_err(xhci, "Canceled URB td not found on endpoint ring");
		for (i = urb_priv->num_tds_done; i < urb_priv->num_tds; i++) {
			td = &urb_priv->td[i];
			if (!list_empty(&td->cancelled_td_list))
				list_del_init(&td->cancelled_td_list);
		}
		goto err_giveback;
	}

	if (xhci->xhc_state & XHCI_STATE_HALTED) {
		xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
				"HC halted, freeing TD manually.");
		for (i = urb_priv->num_tds_done;
		     i < urb_priv->num_tds;
		     i++) {
			td = &urb_priv->td[i];
			if (!list_empty(&td->td_list))
				list_del_init(&td->td_list);
			if (!list_empty(&td->cancelled_td_list))
				list_del_init(&td->cancelled_td_list);
		}
		goto err_giveback;
	}

	i = urb_priv->num_tds_done;
	if (i < urb_priv->num_tds)
		xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
				"Cancel URB %p, dev %s, ep 0x%x, "
				"starting at offset 0x%llx",
				urb, urb->dev->devpath,
				urb->ep->desc.bEndpointAddress,
				(unsigned long long) xhci_trb_virt_to_dma(
					urb_priv->td[i].start_seg,
					urb_priv->td[i].first_trb));

	for (; i < urb_priv->num_tds; i++) {
		td = &urb_priv->td[i];
		/* TD can already be on cancelled list if ep halted on it */
		if (list_empty(&td->cancelled_td_list)) {
			td->cancel_status = TD_DIRTY;
			list_add_tail(&td->cancelled_td_list,
				      &ep->cancelled_td_list);
		}
	}

	/* Queue a stop endpoint command, but only if this is
	 * the first cancellation to be handled.
	 */
	if (!(ep->ep_state & EP_STOP_CMD_PENDING)) {
		command = xhci_alloc_command(xhci, false, GFP_ATOMIC);
		if (!command) {
			ret = -ENOMEM;
			goto done;
		}
		ep->ep_state |= EP_STOP_CMD_PENDING;
		ep->stop_cmd_timer.expires = jiffies +
			XHCI_STOP_EP_CMD_TIMEOUT * HZ;
		add_timer(&ep->stop_cmd_timer);
		xhci_queue_stop_endpoint(xhci, command, urb->dev->slot_id,
					 ep_index, 0);
		xhci_ring_cmd_db(xhci);
	}
done:
	spin_unlock_irqrestore(&xhci->lock, flags);
	return ret;

err_giveback:
	if (urb_priv)
		xhci_urb_free_priv(urb_priv);
	usb_hcd_unlink_urb_from_ep(hcd, urb);
	spin_unlock_irqrestore(&xhci->lock, flags);
	usb_hcd_giveback_urb(hcd, urb, -ESHUTDOWN);
	return ret;
}

/* Drop an endpoint from a new bandwidth configuration for this device.
 * Only one call to this function is allowed per endpoint before
 * check_bandwidth() or reset_bandwidth() must be called.
 * A call to xhci_drop_endpoint() followed by a call to xhci_add_endpoint() will
 * add the endpoint to the schedule with possibly new parameters denoted by a
 * different endpoint descriptor in usb_host_endpoint.
 * A call to xhci_add_endpoint() followed by a call to xhci_drop_endpoint() is
 * not allowed.
 *
 * The USB core will not allow URBs to be queued to an endpoint that is being
 * disabled, so there's no need for mutual exclusion to protect
 * the xhci->devs[slot_id] structure.
 */
int xhci_drop_endpoint(struct usb_hcd *hcd, struct usb_device *udev,
		       struct usb_host_endpoint *ep)
{
	struct xhci_hcd *xhci;
	struct xhci_container_ctx *in_ctx, *out_ctx;
	struct xhci_input_control_ctx *ctrl_ctx;
	unsigned int ep_index;
	struct xhci_ep_ctx *ep_ctx;
	u32 drop_flag;
	u32 new_add_flags, new_drop_flags;
	int ret;

	ret = xhci_check_args(hcd, udev, ep, 1, true, __func__);
	if (ret <= 0)
		return ret;
	xhci = hcd_to_xhci(hcd);
	if (xhci->xhc_state & XHCI_STATE_DYING)
		return -ENODEV;

	xhci_dbg(xhci, "%s called for udev %p\n", __func__, udev);
	drop_flag = xhci_get_endpoint_flag(&ep->desc);
	if (drop_flag == SLOT_FLAG || drop_flag == EP0_FLAG) {
		xhci_dbg(xhci, "xHCI %s - can't drop slot or ep 0 %#x\n",
				__func__, drop_flag);
		return 0;
	}

	in_ctx = xhci->devs[udev->slot_id]->in_ctx;
	out_ctx = xhci->devs[udev->slot_id]->out_ctx;
	ctrl_ctx = xhci_get_input_control_ctx(in_ctx);
	if (!ctrl_ctx) {
		xhci_warn(xhci, "%s: Could not get input context, bad type.\n",
				__func__);
		return 0;
	}

	ep_index = xhci_get_endpoint_index(&ep->desc);
	ep_ctx = xhci_get_ep_ctx(xhci, out_ctx, ep_index);
	/* If the HC already knows the endpoint is disabled,
	 * or the HCD has noted it is disabled, ignore this request
	 */
	if ((GET_EP_CTX_STATE(ep_ctx) == EP_STATE_DISABLED) ||
	    le32_to_cpu(ctrl_ctx->drop_flags) &
	    xhci_get_endpoint_flag(&ep->desc)) {
		/* Do not warn when called after a usb_device_reset */
		if (xhci->devs[udev->slot_id]->eps[ep_index].ring != NULL)
			xhci_warn(xhci, "xHCI %s called with disabled ep %p\n",
				  __func__, ep);
		return 0;
	}

	ctrl_ctx->drop_flags |= cpu_to_le32(drop_flag);
	new_drop_flags = le32_to_cpu(ctrl_ctx->drop_flags);

	ctrl_ctx->add_flags &= cpu_to_le32(~drop_flag);
	new_add_flags = le32_to_cpu(ctrl_ctx->add_flags);

	xhci_debugfs_remove_endpoint(xhci, xhci->devs[udev->slot_id], ep_index);

	xhci_endpoint_zero(xhci, xhci->devs[udev->slot_id], ep);

	xhci_dbg(xhci, "drop ep 0x%x, slot id %d, new drop flags = %#x, new add flags = %#x\n",
			(unsigned int) ep->desc.bEndpointAddress,
			udev->slot_id,
			(unsigned int) new_drop_flags,
			(unsigned int) new_add_flags);
	return 0;
}
EXPORT_SYMBOL_GPL(xhci_drop_endpoint);

/* Add an endpoint to a new possible bandwidth configuration for this device.
 * Only one call to this function is allowed per endpoint before
 * check_bandwidth() or reset_bandwidth() must be called.
 * A call to xhci_drop_endpoint() followed by a call to xhci_add_endpoint() will
 * add the endpoint to the schedule with possibly new parameters denoted by a
 * different endpoint descriptor in usb_host_endpoint.
 * A call to xhci_add_endpoint() followed by a call to xhci_drop_endpoint() is
 * not allowed.
 *
 * The USB core will not allow URBs to be queued to an endpoint until the
 * configuration or alt setting is installed in the device, so there's no need
 * for mutual exclusion to protect the xhci->devs[slot_id] structure.
 */
int xhci_add_endpoint(struct usb_hcd *hcd, struct usb_device *udev,
		      struct usb_host_endpoint *ep)
{
	struct xhci_hcd *xhci;
	struct xhci_container_ctx *in_ctx;
	unsigned int ep_index;
	struct xhci_input_control_ctx *ctrl_ctx;
	struct xhci_ep_ctx *ep_ctx;
	u32 added_ctxs;
	u32 new_add_flags, new_drop_flags;
	struct xhci_virt_device *virt_dev;
	int ret = 0;

	ret = xhci_check_args(hcd, udev, ep, 1, true, __func__);
	if (ret <= 0) {
		/* So we won't queue a reset ep command for a root hub */
		ep->hcpriv = NULL;
		return ret;
	}
	xhci = hcd_to_xhci(hcd);
	if (xhci->xhc_state & XHCI_STATE_DYING)
		return -ENODEV;

	added_ctxs = xhci_get_endpoint_flag(&ep->desc);
	if (added_ctxs == SLOT_FLAG || added_ctxs == EP0_FLAG) {
		/* FIXME when we have to issue an evaluate endpoint command to
		 * deal with ep0 max packet size changing once we get the
		 * descriptors
		 */
		xhci_dbg(xhci, "xHCI %s - can't add slot or ep 0 %#x\n",
				__func__, added_ctxs);
		return 0;
	}

	virt_dev = xhci->devs[udev->slot_id];
	in_ctx = virt_dev->in_ctx;
	ctrl_ctx = xhci_get_input_control_ctx(in_ctx);
	if (!ctrl_ctx) {
		xhci_warn(xhci, "%s: Could not get input context, bad type.\n",
				__func__);
		return 0;
	}

	ep_index = xhci_get_endpoint_index(&ep->desc);
	/* If this endpoint is already in use, and the upper layers are trying
	 * to add it again without dropping it, reject the addition.
	 */
	if (virt_dev->eps[ep_index].ring &&
			!(le32_to_cpu(ctrl_ctx->drop_flags) & added_ctxs)) {
		xhci_warn(xhci, "Trying to add endpoint 0x%x "
				"without dropping it.\n",
				(unsigned int) ep->desc.bEndpointAddress);
		return -EINVAL;
	}

	/* If the HCD has already noted the endpoint is enabled,
	 * ignore this request.
	 */
	if (le32_to_cpu(ctrl_ctx->add_flags) & added_ctxs) {
		xhci_warn(xhci, "xHCI %s called with enabled ep %p\n",
				__func__, ep);
		return 0;
	}

	/*
	 * Configuration and alternate setting changes must be done in
	 * process context, not interrupt context (or so documenation
	 * for usb_set_interface() and usb_set_configuration() claim).
	 */
	if (xhci_endpoint_init(xhci, virt_dev, udev, ep, GFP_NOIO) < 0) {
		dev_dbg(&udev->dev, "%s - could not initialize ep %#x\n",
				__func__, ep->desc.bEndpointAddress);
		return -ENOMEM;
	}

	ctrl_ctx->add_flags |= cpu_to_le32(added_ctxs);
	new_add_flags = le32_to_cpu(ctrl_ctx->add_flags);

	/* If xhci_endpoint_disable() was called for this endpoint, but the
	 * xHC hasn't been notified yet through the check_bandwidth() call,
	 * this re-adds a new state for the endpoint from the new endpoint
	 * descriptors.  We must drop and re-add this endpoint, so we leave the
	 * drop flags alone.
	 */
	new_drop_flags = le32_to_cpu(ctrl_ctx->drop_flags);

	/* Store the usb_device pointer for later use */
	ep->hcpriv = udev;

	ep_ctx = xhci_get_ep_ctx(xhci, virt_dev->in_ctx, ep_index);
	trace_xhci_add_endpoint(ep_ctx);

	xhci_dbg(xhci, "add ep 0x%x, slot id %d, new drop flags = %#x, new add flags = %#x\n",
			(unsigned int) ep->desc.bEndpointAddress,
			udev->slot_id,
			(unsigned int) new_drop_flags,
			(unsigned int) new_add_flags);
	return 0;
}
EXPORT_SYMBOL_GPL(xhci_add_endpoint);

static void xhci_zero_in_ctx(struct xhci_hcd *xhci, struct xhci_virt_device *virt_dev)
{
	struct xhci_input_control_ctx *ctrl_ctx;
	struct xhci_ep_ctx *ep_ctx;
	struct xhci_slot_ctx *slot_ctx;
	int i;

	ctrl_ctx = xhci_get_input_control_ctx(virt_dev->in_ctx);
	if (!ctrl_ctx) {
		xhci_warn(xhci, "%s: Could not get input context, bad type.\n",
				__func__);
		return;
	}

	/* When a device's add flag and drop flag are zero, any subsequent
	 * configure endpoint command will leave that endpoint's state
	 * untouched.  Make sure we don't leave any old state in the input
	 * endpoint contexts.
	 */
	ctrl_ctx->drop_flags = 0;
	ctrl_ctx->add_flags = 0;
	slot_ctx = xhci_get_slot_ctx(xhci, virt_dev->in_ctx);
	slot_ctx->dev_info &= cpu_to_le32(~LAST_CTX_MASK);
	/* Endpoint 0 is always valid */
	slot_ctx->dev_info |= cpu_to_le32(LAST_CTX(1));
	for (i = 1; i < 31; i++) {
		ep_ctx = xhci_get_ep_ctx(xhci, virt_dev->in_ctx, i);
		ep_ctx->ep_info = 0;
		ep_ctx->ep_info2 = 0;
		ep_ctx->deq = 0;
		ep_ctx->tx_info = 0;
	}
}

static int xhci_configure_endpoint_result(struct xhci_hcd *xhci,
		struct usb_device *udev, u32 *cmd_status)
{
	int ret;

	switch (*cmd_status) {
	case COMP_COMMAND_ABORTED:
	case COMP_COMMAND_RING_STOPPED:
		xhci_warn(xhci, "Timeout while waiting for configure endpoint command\n");
		ret = -ETIME;
		break;
	case COMP_RESOURCE_ERROR:
		dev_warn(&udev->dev,
			 "Not enough host controller resources for new device state.\n");
		ret = -ENOMEM;
		/* FIXME: can we allocate more resources for the HC? */
		break;
	case COMP_BANDWIDTH_ERROR:
	case COMP_SECONDARY_BANDWIDTH_ERROR:
		dev_warn(&udev->dev,
