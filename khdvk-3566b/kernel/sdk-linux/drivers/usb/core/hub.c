// SPDX-License-Identifier: GPL-2.0
/*
 * USB hub driver.
 *
 * (C) Copyright 1999 Linus Torvalds
 * (C) Copyright 1999 Johannes Erdfelt
 * (C) Copyright 1999 Gregory P. Smith
 * (C) Copyright 2001 Brad Hards (bhards@bigpond.net.au)
 *
 * Released under the GPLv2 only.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/completion.h>
#include <linux/sched/mm.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kcov.h>
#include <linux/ioctl.h>
#include <linux/usb.h>
#include <linux/usbdevice_fs.h>
#include <linux/usb/hcd.h>
#include <linux/usb/otg.h>
#include <linux/usb/quirks.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/pm_qos.h>
#include <linux/kobject.h>

#include <linux/uaccess.h>
#include <asm/byteorder.h>

#include "hub.h"
#include "otg_productlist.h"

#define USB_VENDOR_GENESYS_LOGIC		0x05e3
#define USB_VENDOR_SMSC				0x0424
#define USB_PRODUCT_USB5534B			0x5534
#define USB_VENDOR_CYPRESS			0x04b4
#define USB_PRODUCT_CY7C65632			0x6570
#define HUB_QUIRK_CHECK_PORT_AUTOSUSPEND	0x01
#define HUB_QUIRK_DISABLE_AUTOSUSPEND		0x02

#define USB_TP_TRANSMISSION_DELAY	40	/* ns */
#define USB_TP_TRANSMISSION_DELAY_MAX	65535	/* ns */
#define USB_PING_RESPONSE_TIME		400	/* ns */

/* Protect struct usb_device->state and ->children members
 * Note: Both are also protected by ->dev.sem, except that ->state can
 * change to USB_STATE_NOTATTACHED even when the semaphore isn't held. */
static DEFINE_SPINLOCK(device_state_lock);

/* workqueue to process hub events */
static struct workqueue_struct *hub_wq;
static void hub_event(struct work_struct *work);

/* synchronize hub-port add/remove and peering operations */
DEFINE_MUTEX(usb_port_peer_mutex);

/* cycle leds on hubs that aren't blinking for attention */
static bool blinkenlights;
module_param(blinkenlights, bool, S_IRUGO);
MODULE_PARM_DESC(blinkenlights, "true to cycle leds on hubs");

/*
 * Device SATA8000 FW1.0 from DATAST0R Technology Corp requires about
 * 10 seconds to send reply for the initial 64-byte descriptor request.
 */
/* define initial 64-byte descriptor request timeout in milliseconds */
static int initial_descriptor_timeout = USB_CTRL_GET_TIMEOUT;
module_param(initial_descriptor_timeout, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(initial_descriptor_timeout,
		"initial 64-byte descriptor request timeout in milliseconds "
		"(default 5000 - 5.0 seconds)");

/*
 * As of 2.6.10 we introduce a new USB device initialization scheme which
 * closely resembles the way Windows works.  Hopefully it will be compatible
 * with a wider range of devices than the old scheme.  However some previously
 * working devices may start giving rise to "device not accepting address"
 * errors; if that happens the user can try the old scheme by adjusting the
 * following module parameters.
 *
 * For maximum flexibility there are two boolean parameters to control the
 * hub driver's behavior.  On the first initialization attempt, if the
 * "old_scheme_first" parameter is set then the old scheme will be used,
 * otherwise the new scheme is used.  If that fails and "use_both_schemes"
 * is set, then the driver will make another attempt, using the other scheme.
 */
static bool old_scheme_first;
module_param(old_scheme_first, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(old_scheme_first,
		 "start with the old device initialization scheme");

static bool use_both_schemes = true;
module_param(use_both_schemes, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(use_both_schemes,
		"try the other device initialization scheme if the "
		"first one fails");

/* Mutual exclusion for EHCI CF initialization.  This interferes with
 * port reset on some companion controllers.
 */
DECLARE_RWSEM(ehci_cf_port_reset_rwsem);
EXPORT_SYMBOL_GPL(ehci_cf_port_reset_rwsem);

#define HUB_DEBOUNCE_TIMEOUT	2000
#define HUB_DEBOUNCE_STEP	  25
#define HUB_DEBOUNCE_STABLE	 100

static void hub_release(struct kref *kref);
static int usb_reset_and_verify_device(struct usb_device *udev);
static int hub_port_disable(struct usb_hub *hub, int port1, int set_state);
static bool hub_port_warm_reset_required(struct usb_hub *hub, int port1,
		u16 portstatus);

static inline char *portspeed(struct usb_hub *hub, int portstatus)
{
	if (hub_is_superspeedplus(hub->hdev))
		return "10.0 Gb/s";
	if (hub_is_superspeed(hub->hdev))
		return "5.0 Gb/s";
	if (portstatus & USB_PORT_STAT_HIGH_SPEED)
		return "480 Mb/s";
	else if (portstatus & USB_PORT_STAT_LOW_SPEED)
		return "1.5 Mb/s";
	else
		return "12 Mb/s";
}

/* Note that hdev or one of its children must be locked! */
struct usb_hub *usb_hub_to_struct_hub(struct usb_device *hdev)
{
	if (!hdev || !hdev->actconfig || !hdev->maxchild)
		return NULL;
	return usb_get_intfdata(hdev->actconfig->interface[0]);
}

int usb_device_supports_lpm(struct usb_device *udev)
{
	/* Some devices have trouble with LPM */
	if (udev->quirks & USB_QUIRK_NO_LPM)
		return 0;

	/* USB 2.1 (and greater) devices indicate LPM support through
	 * their USB 2.0 Extended Capabilities BOS descriptor.
	 */
	if (udev->speed == USB_SPEED_HIGH || udev->speed == USB_SPEED_FULL) {
		if (udev->bos->ext_cap &&
			(USB_LPM_SUPPORT &
			 le32_to_cpu(udev->bos->ext_cap->bmAttributes)))
			return 1;
		return 0;
	}

	/*
	 * According to the USB 3.0 spec, all USB 3.0 devices must support LPM.
	 * However, there are some that don't, and they set the U1/U2 exit
	 * latencies to zero.
	 */
	if (!udev->bos->ss_cap) {
		dev_info(&udev->dev, "No LPM exit latency info found, disabling LPM.\n");
		return 0;
	}

	if (udev->bos->ss_cap->bU1devExitLat == 0 &&
			udev->bos->ss_cap->bU2DevExitLat == 0) {
		if (udev->parent)
			dev_info(&udev->dev, "LPM exit latency is zeroed, disabling LPM.\n");
		else
			dev_info(&udev->dev, "We don't know the algorithms for LPM for this host, disabling LPM.\n");
		return 0;
	}

	if (!udev->parent || udev->parent->lpm_capable)
		return 1;
	return 0;
}

/*
 * Set the Maximum Exit Latency (MEL) for the host to wakup up the path from
 * U1/U2, send a PING to the device and receive a PING_RESPONSE.
 * See USB 3.1 section C.1.5.2
 */
static void usb_set_lpm_mel(struct usb_device *udev,
		struct usb3_lpm_parameters *udev_lpm_params,
		unsigned int udev_exit_latency,
		struct usb_hub *hub,
		struct usb3_lpm_parameters *hub_lpm_params,
		unsigned int hub_exit_latency)
{
	unsigned int total_mel;

	/*
	 * tMEL1. time to transition path from host to device into U0.
	 * MEL for parent already contains the delay up to parent, so only add
	 * the exit latency for the last link (pick the slower exit latency),
	 * and the hub header decode latency. See USB 3.1 section C 2.2.1
	 * Store MEL in nanoseconds
	 */
	total_mel = hub_lpm_params->mel +
		max(udev_exit_latency, hub_exit_latency) * 1000 +
		hub->descriptor->u.ss.bHubHdrDecLat * 100;

	/*
	 * tMEL2. Time to submit PING packet. Sum of tTPTransmissionDelay for
	 * each link + wHubDelay for each hub. Add only for last link.
	 * tMEL4, the time for PING_RESPONSE to traverse upstream is similar.
	 * Multiply by 2 to include it as well.
	 */
	total_mel += (__le16_to_cpu(hub->descriptor->u.ss.wHubDelay) +
		      USB_TP_TRANSMISSION_DELAY) * 2;

	/*
	 * tMEL3, tPingResponse. Time taken by device to generate PING_RESPONSE
	 * after receiving PING. Also add 2100ns as stated in USB 3.1 C 1.5.2.4
	 * to cover the delay if the PING_RESPONSE is queued behind a Max Packet
	 * Size DP.
	 * Note these delays should be added only once for the entire path, so
	 * add them to the MEL of the device connected to the roothub.
	 */
	if (!hub->hdev->parent)
		total_mel += USB_PING_RESPONSE_TIME + 2100;

	udev_lpm_params->mel = total_mel;
}

/*
 * Set the maximum Device to Host Exit Latency (PEL) for the device to initiate
 * a transition from either U1 or U2.
 */
static void usb_set_lpm_pel(struct usb_device *udev,
		struct usb3_lpm_parameters *udev_lpm_params,
		unsigned int udev_exit_latency,
		struct usb_hub *hub,
		struct usb3_lpm_parameters *hub_lpm_params,
		unsigned int hub_exit_latency,
		unsigned int port_to_port_exit_latency)
{
	unsigned int first_link_pel;
	unsigned int hub_pel;

	/*
	 * First, the device sends an LFPS to transition the link between the
	 * device and the parent hub into U0.  The exit latency is the bigger of
	 * the device exit latency or the hub exit latency.
	 */
	if (udev_exit_latency > hub_exit_latency)
		first_link_pel = udev_exit_latency * 1000;
	else
		first_link_pel = hub_exit_latency * 1000;

	/*
	 * When the hub starts to receive the LFPS, there is a slight delay for
	 * it to figure out that one of the ports is sending an LFPS.  Then it
	 * will forward the LFPS to its upstream link.  The exit latency is the
	 * delay, plus the PEL that we calculated for this hub.
	 */
	hub_pel = port_to_port_exit_latency * 1000 + hub_lpm_params->pel;

	/*
	 * According to figure C-7 in the USB 3.0 spec, the PEL for this device
	 * is the greater of the two exit latencies.
	 */
	if (first_link_pel > hub_pel)
		udev_lpm_params->pel = first_link_pel;
	else
		udev_lpm_params->pel = hub_pel;
}

/*
 * Set the System Exit Latency (SEL) to indicate the total worst-case time from
 * when a device initiates a transition to U0, until when it will receive the
 * first packet from the host controller.
 *
 * Section C.1.5.1 describes the four components to this:
 *  - t1: device PEL
 *  - t2: time for the ERDY to make it from the device to the host.
 *  - t3: a host-specific delay to process the ERDY.
 *  - t4: time for the packet to make it from the host to the device.
 *
 * t3 is specific to both the xHCI host and the platform the host is integrated
 * into.  The Intel HW folks have said it's negligible, FIXME if a different
 * vendor says otherwise.
 */
static void usb_set_lpm_sel(struct usb_device *udev,
		struct usb3_lpm_parameters *udev_lpm_params)
{
	struct usb_device *parent;
	unsigned int num_hubs;
	unsigned int total_sel;

	/* t1 = device PEL */
	total_sel = udev_lpm_params->pel;
	/* How many external hubs are in between the device & the root port. */
	for (parent = udev->parent, num_hubs = 0; parent->parent;
			parent = parent->parent)
		num_hubs++;
	/* t2 = 2.1us + 250ns * (num_hubs - 1) */
	if (num_hubs > 0)
		total_sel += 2100 + 250 * (num_hubs - 1);

	/* t4 = 250ns * num_hubs */
	total_sel += 250 * num_hubs;

	udev_lpm_params->sel = total_sel;
}

static void usb_set_lpm_parameters(struct usb_device *udev)
{
	struct usb_hub *hub;
	unsigned int port_to_port_delay;
	unsigned int udev_u1_del;
	unsigned int udev_u2_del;
	unsigned int hub_u1_del;
	unsigned int hub_u2_del;

	if (!udev->lpm_capable || udev->speed < USB_SPEED_SUPER)
		return;

	hub = usb_hub_to_struct_hub(udev->parent);
	/* It doesn't take time to transition the roothub into U0, since it
	 * doesn't have an upstream link.
	 */
	if (!hub)
		return;

	udev_u1_del = udev->bos->ss_cap->bU1devExitLat;
	udev_u2_del = le16_to_cpu(udev->bos->ss_cap->bU2DevExitLat);
	hub_u1_del = udev->parent->bos->ss_cap->bU1devExitLat;
	hub_u2_del = le16_to_cpu(udev->parent->bos->ss_cap->bU2DevExitLat);

	usb_set_lpm_mel(udev, &udev->u1_params, udev_u1_del,
			hub, &udev->parent->u1_params, hub_u1_del);

	usb_set_lpm_mel(udev, &udev->u2_params, udev_u2_del,
			hub, &udev->parent->u2_params, hub_u2_del);

	/*
	 * Appendix C, section C.2.2.2, says that there is a slight delay from
	 * when the parent hub notices the downstream port is trying to
	 * transition to U0 to when the hub initiates a U0 transition on its
	 * upstream port.  The section says the delays are tPort2PortU1EL and
	 * tPort2PortU2EL, but it doesn't define what they are.
	 *
	 * The hub chapter, sections 10.4.2.4 and 10.4.2.5 seem to be talking
	 * about the same delays.  Use the maximum delay calculations from those
	 * sections.  For U1, it's tHubPort2PortExitLat, which is 1us max.  For
	 * U2, it's tHubPort2PortExitLat + U2DevExitLat - U1DevExitLat.  I
	 * assume the device exit latencies they are talking about are the hub
	 * exit latencies.
	 *
	 * What do we do if the U2 exit latency is less than the U1 exit
	 * latency?  It's possible, although not likely...
	 */
	port_to_port_delay = 1;

	usb_set_lpm_pel(udev, &udev->u1_params, udev_u1_del,
			hub, &udev->parent->u1_params, hub_u1_del,
			port_to_port_delay);

	if (hub_u2_del > hub_u1_del)
		port_to_port_delay = 1 + hub_u2_del - hub_u1_del;
	else
		port_to_port_delay = 1 + hub_u1_del;

	usb_set_lpm_pel(udev, &udev->u2_params, udev_u2_del,
			hub, &udev->parent->u2_params, hub_u2_del,
			port_to_port_delay);

	/* Now that we've got PEL, calculate SEL. */
	usb_set_lpm_sel(udev, &udev->u1_params);
	usb_set_lpm_sel(udev, &udev->u2_params);
}

/* USB 2.0 spec Section 11.24.4.5 */
static int get_hub_descriptor(struct usb_device *hdev,
		struct usb_hub_descriptor *desc)
{
	int i, ret, size;
	unsigned dtype;

	if (hub_is_superspeed(hdev)) {
		dtype = USB_DT_SS_HUB;
		size = USB_DT_SS_HUB_SIZE;
	} else {
		dtype = USB_DT_HUB;
		size = sizeof(struct usb_hub_descriptor);
	}

	for (i = 0; i < 3; i++) {
		ret = usb_control_msg(hdev, usb_rcvctrlpipe(hdev, 0),
			USB_REQ_GET_DESCRIPTOR, USB_DIR_IN | USB_RT_HUB,
			dtype << 8, 0, desc, size,
			USB_CTRL_GET_TIMEOUT);
		if (hub_is_superspeed(hdev)) {
			if (ret == size)
				return ret;
		} else if (ret >= USB_DT_HUB_NONVAR_SIZE + 2) {
			/* Make sure we have the DeviceRemovable field. */
			size = USB_DT_HUB_NONVAR_SIZE + desc->bNbrPorts / 8 + 1;
			if (ret < size)
				return -EMSGSIZE;
			return ret;
		}
	}
	return -EINVAL;
}

/*
 * USB 2.0 spec Section 11.24.2.1
 */
static int clear_hub_feature(struct usb_device *hdev, int feature)
{
	return usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
		USB_REQ_CLEAR_FEATURE, USB_RT_HUB, feature, 0, NULL, 0, 1000);
}

/*
 * USB 2.0 spec Section 11.24.2.2
 */
int usb_clear_port_feature(struct usb_device *hdev, int port1, int feature)
{
	return usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
		USB_REQ_CLEAR_FEATURE, USB_RT_PORT, feature, port1,
		NULL, 0, 1000);
}

/*
 * USB 2.0 spec Section 11.24.2.13
 */
static int set_port_feature(struct usb_device *hdev, int port1, int feature)
{
	return usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
		USB_REQ_SET_FEATURE, USB_RT_PORT, feature, port1,
		NULL, 0, 1000);
}

static char *to_led_name(int selector)
{
	switch (selector) {
	case HUB_LED_AMBER:
		return "amber";
	case HUB_LED_GREEN:
		return "green";
	case HUB_LED_OFF:
		return "off";
	case HUB_LED_AUTO:
		return "auto";
	default:
		return "??";
	}
}

/*
 * USB 2.0 spec Section 11.24.2.7.1.10 and table 11-7
 * for info about using port indicators
 */
static void set_port_led(struct usb_hub *hub, int port1, int selector)
{
	struct usb_port *port_dev = hub->ports[port1 - 1];
	int status;

	status = set_port_feature(hub->hdev, (selector << 8) | port1,
			USB_PORT_FEAT_INDICATOR);
	dev_dbg(&port_dev->dev, "indicator %s status %d\n",
		to_led_name(selector), status);
}

#define	LED_CYCLE_PERIOD	((2*HZ)/3)

static void led_work(struct work_struct *work)
{
	struct usb_hub		*hub =
		container_of(work, struct usb_hub, leds.work);
	struct usb_device	*hdev = hub->hdev;
	unsigned		i;
	unsigned		changed = 0;
	int			cursor = -1;

	if (hdev->state != USB_STATE_CONFIGURED || hub->quiescing)
		return;

	for (i = 0; i < hdev->maxchild; i++) {
		unsigned	selector, mode;

		/* 30%-50% duty cycle */

		switch (hub->indicator[i]) {
		/* cycle marker */
		case INDICATOR_CYCLE:
			cursor = i;
			selector = HUB_LED_AUTO;
			mode = INDICATOR_AUTO;
			break;
		/* blinking green = sw attention */
		case INDICATOR_GREEN_BLINK:
			selector = HUB_LED_GREEN;
			mode = INDICATOR_GREEN_BLINK_OFF;
			break;
		case INDICATOR_GREEN_BLINK_OFF:
			selector = HUB_LED_OFF;
			mode = INDICATOR_GREEN_BLINK;
			break;
		/* blinking amber = hw attention */
		case INDICATOR_AMBER_BLINK:
			selector = HUB_LED_AMBER;
			mode = INDICATOR_AMBER_BLINK_OFF;
			break;
		case INDICATOR_AMBER_BLINK_OFF:
			selector = HUB_LED_OFF;
			mode = INDICATOR_AMBER_BLINK;
			break;
		/* blink green/amber = reserved */
		case INDICATOR_ALT_BLINK:
			selector = HUB_LED_GREEN;
			mode = INDICATOR_ALT_BLINK_OFF;
			break;
		case INDICATOR_ALT_BLINK_OFF:
			selector = HUB_LED_AMBER;
			mode = INDICATOR_ALT_BLINK;
			break;
		default:
			continue;
		}
		if (selector != HUB_LED_AUTO)
			changed = 1;
		set_port_led(hub, i + 1, selector);
		hub->indicator[i] = mode;
	}
	if (!changed && blinkenlights) {
		cursor++;
		cursor %= hdev->maxchild;
		set_port_led(hub, cursor + 1, HUB_LED_GREEN);
		hub->indicator[cursor] = INDICATOR_CYCLE;
		changed++;
	}
	if (changed)
		queue_delayed_work(system_power_efficient_wq,
				&hub->leds, LED_CYCLE_PERIOD);
}

/* use a short timeout for hub/port status fetches */
#define	USB_STS_TIMEOUT		1000
#define	USB_STS_RETRIES		5

/*
 * USB 2.0 spec Section 11.24.2.6
 */
static int get_hub_status(struct usb_device *hdev,
		struct usb_hub_status *data)
{
	int i, status = -ETIMEDOUT;

	for (i = 0; i < USB_STS_RETRIES &&
			(status == -ETIMEDOUT || status == -EPIPE); i++) {
		status = usb_control_msg(hdev, usb_rcvctrlpipe(hdev, 0),
			USB_REQ_GET_STATUS, USB_DIR_IN | USB_RT_HUB, 0, 0,
			data, sizeof(*data), USB_STS_TIMEOUT);
	}
	return status;
}

/*
 * USB 2.0 spec Section 11.24.2.7
 * USB 3.1 takes into use the wValue and wLength fields, spec Section 10.16.2.6
 */
static int get_port_status(struct usb_device *hdev, int port1,
			   void *data, u16 value, u16 length)
{
	int i, status = -ETIMEDOUT;

	for (i = 0; i < USB_STS_RETRIES &&
			(status == -ETIMEDOUT || status == -EPIPE); i++) {
		status = usb_control_msg(hdev, usb_rcvctrlpipe(hdev, 0),
			USB_REQ_GET_STATUS, USB_DIR_IN | USB_RT_PORT, value,
			port1, data, length, USB_STS_TIMEOUT);
	}
	return status;
}

static int hub_ext_port_status(struct usb_hub *hub, int port1, int type,
			       u16 *status, u16 *change, u32 *ext_status)
{
	int ret;
	int len = 4;

	if (type != HUB_PORT_STATUS)
		len = 8;

	mutex_lock(&hub->status_mutex);
	ret = get_port_status(hub->hdev, port1, &hub->status->port, type, len);
	if (ret < len) {
		if (ret != -ENODEV)
			dev_err(hub->intfdev,
				"%s failed (err = %d)\n", __func__, ret);
		if (ret >= 0)
			ret = -EIO;
	} else {
		*status = le16_to_cpu(hub->status->port.wPortStatus);
		*change = le16_to_cpu(hub->status->port.wPortChange);
		if (type != HUB_PORT_STATUS && ext_status)
			*ext_status = le32_to_cpu(
				hub->status->port.dwExtPortStatus);
		ret = 0;
	}
	mutex_unlock(&hub->status_mutex);
	return ret;
}

static int hub_port_status(struct usb_hub *hub, int port1,
		u16 *status, u16 *change)
{
	return hub_ext_port_status(hub, port1, HUB_PORT_STATUS,
				   status, change, NULL);
}

static void hub_resubmit_irq_urb(struct usb_hub *hub)
{
	unsigned long flags;
	int status;

	spin_lock_irqsave(&hub->irq_urb_lock, flags);

	if (hub->quiescing) {
		spin_unlock_irqrestore(&hub->irq_urb_lock, flags);
		return;
	}

	status = usb_submit_urb(hub->urb, GFP_ATOMIC);
	if (status && status != -ENODEV && status != -EPERM &&
	    status != -ESHUTDOWN) {
		dev_err(hub->intfdev, "resubmit --> %d\n", status);
		mod_timer(&hub->irq_urb_retry, jiffies + HZ);
	}

	spin_unlock_irqrestore(&hub->irq_urb_lock, flags);
}

static void hub_retry_irq_urb(struct timer_list *t)
{
	struct usb_hub *hub = from_timer(hub, t, irq_urb_retry);

	hub_resubmit_irq_urb(hub);
}


static void kick_hub_wq(struct usb_hub *hub)
{
	struct usb_interface *intf;

	if (hub->disconnected || work_pending(&hub->events))
		return;

	/*
	 * Suppress autosuspend until the event is proceed.
	 *
	 * Be careful and make sure that the symmetric operation is
	 * always called. We are here only when there is no pending
	 * work for this hub. Therefore put the interface either when
	 * the new work is called or when it is canceled.
	 */
	intf = to_usb_interface(hub->intfdev);
	usb_autopm_get_interface_no_resume(intf);
	kref_get(&hub->kref);

	if (queue_work(hub_wq, &hub->events))
		return;

	/* the work has already been scheduled */
	usb_autopm_put_interface_async(intf);
	kref_put(&hub->kref, hub_release);
}

void usb_kick_hub_wq(struct usb_device *hdev)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(hdev);

	if (hub)
		kick_hub_wq(hub);
}

/*
 * Let the USB core know that a USB 3.0 device has sent a Function Wake Device
 * Notification, which indicates it had initiated remote wakeup.
 *
 * USB 3.0 hubs do not report the port link state change from U3 to U0 when the
 * device initiates resume, so the USB core will not receive notice of the
 * resume through the normal hub interrupt URB.
 */
void usb_wakeup_notification(struct usb_device *hdev,
		unsigned int portnum)
{
	struct usb_hub *hub;
	struct usb_port *port_dev;

	if (!hdev)
		return;

	hub = usb_hub_to_struct_hub(hdev);
	if (hub) {
		port_dev = hub->ports[portnum - 1];
		if (port_dev && port_dev->child)
			pm_wakeup_event(&port_dev->child->dev, 0);

		set_bit(portnum, hub->wakeup_bits);
		kick_hub_wq(hub);
	}
}
EXPORT_SYMBOL_GPL(usb_wakeup_notification);

/* completion function, fires on port status changes and various faults */
static void hub_irq(struct urb *urb)
{
	struct usb_hub *hub = urb->context;
	int status = urb->status;
	unsigned i;
	unsigned long bits;

	switch (status) {
	case -ENOENT:		/* synchronous unlink */
	case -ECONNRESET:	/* async unlink */
	case -ESHUTDOWN:	/* hardware going away */
		return;

	default:		/* presumably an error */
		/* Cause a hub reset after 10 consecutive errors */
		dev_dbg(hub->intfdev, "transfer --> %d\n", status);
		if ((++hub->nerrors < 10) || hub->error)
			goto resubmit;
		hub->error = status;
		fallthrough;

	/* let hub_wq handle things */
	case 0:			/* we got data:  port status changed */
		bits = 0;
		for (i = 0; i < urb->actual_length; ++i)
			bits |= ((unsigned long) ((*hub->buffer)[i]))
					<< (i*8);
		hub->event_bits[0] = bits;
		break;
	}

	hub->nerrors = 0;

	/* Something happened, let hub_wq figure it out */
	kick_hub_wq(hub);

resubmit:
	hub_resubmit_irq_urb(hub);
}

/* USB 2.0 spec Section 11.24.2.3 */
static inline int
hub_clear_tt_buffer(struct usb_device *hdev, u16 devinfo, u16 tt)
{
	/* Need to clear both directions for control ep */
	if (((devinfo >> 11) & USB_ENDPOINT_XFERTYPE_MASK) ==
			USB_ENDPOINT_XFER_CONTROL) {
		int status = usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
				HUB_CLEAR_TT_BUFFER, USB_RT_PORT,
				devinfo ^ 0x8000, tt, NULL, 0, 1000);
		if (status)
			return status;
	}
	return usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
			       HUB_CLEAR_TT_BUFFER, USB_RT_PORT, devinfo,
			       tt, NULL, 0, 1000);
}

/*
 * enumeration blocks hub_wq for a long time. we use keventd instead, since
 * long blocking there is the exception, not the rule.  accordingly, HCDs
 * talking to TTs must queue control transfers (not just bulk and iso), so
 * both can talk to the same hub concurrently.
 */
static void hub_tt_work(struct work_struct *work)
{
	struct usb_hub		*hub =
		container_of(work, struct usb_hub, tt.clear_work);
	unsigned long		flags;

	spin_lock_irqsave(&hub->tt.lock, flags);
	while (!list_empty(&hub->tt.clear_list)) {
		struct list_head	*next;
		struct usb_tt_clear	*clear;
		struct usb_device	*hdev = hub->hdev;
		const struct hc_driver	*drv;
		int			status;

		next = hub->tt.clear_list.next;
		clear = list_entry(next, struct usb_tt_clear, clear_list);
		list_del(&clear->clear_list);

		/* drop lock so HCD can concurrently report other TT errors */
		spin_unlock_irqrestore(&hub->tt.lock, flags);
		status = hub_clear_tt_buffer(hdev, clear->devinfo, clear->tt);
		if (status && status != -ENODEV)
			dev_err(&hdev->dev,
				"clear tt %d (%04x) error %d\n",
				clear->tt, clear->devinfo, status);

		/* Tell the HCD, even if the operation failed */
		drv = clear->hcd->driver;
		if (drv->clear_tt_buffer_complete)
			(drv->clear_tt_buffer_complete)(clear->hcd, clear->ep);

		kfree(clear);
		spin_lock_irqsave(&hub->tt.lock, flags);
	}
	spin_unlock_irqrestore(&hub->tt.lock, flags);
}

/**
 * usb_hub_set_port_power - control hub port's power state
 * @hdev: USB device belonging to the usb hub
 * @hub: target hub
 * @port1: port index
 * @set: expected status
 *
 * call this function to control port's power via setting or
 * clearing the port's PORT_POWER feature.
 *
 * Return: 0 if successful. A negative error code otherwise.
 */
int usb_hub_set_port_power(struct usb_device *hdev, struct usb_hub *hub,
			   int port1, bool set)
{
	int ret;

	if (set)
		ret = set_port_feature(hdev, port1, USB_PORT_FEAT_POWER);
	else
		ret = usb_clear_port_feature(hdev, port1, USB_PORT_FEAT_POWER);

	if (ret)
		return ret;

	if (set)
		set_bit(port1, hub->power_bits);
	else
		clear_bit(port1, hub->power_bits);
	return 0;
}

/**
 * usb_hub_clear_tt_buffer - clear control/bulk TT state in high speed hub
 * @urb: an URB associated with the failed or incomplete split transaction
 *
 * High speed HCDs use this to tell the hub driver that some split control or
 * bulk transaction failed in a way that requires clearing internal state of
 * a transaction translator.  This is normally detected (and reported) from
 * interrupt context.
 *
 * It may not be possible for that hub to handle additional full (or low)
 * speed transactions until that state is fully cleared out.
 *
 * Return: 0 if successful. A negative error code otherwise.
 */
int usb_hub_clear_tt_buffer(struct urb *urb)
{
	struct usb_device	*udev = urb->dev;
	int			pipe = urb->pipe;
	struct usb_tt		*tt = udev->tt;
	unsigned long		flags;
	struct usb_tt_clear	*clear;

	/* we've got to cope with an arbitrary number of pending TT clears,
	 * since each TT has "at least two" buffers that can need it (and
	 * there can be many TTs per hub).  even if they're uncommon.
	 */
	clear = kmalloc(sizeof *clear, GFP_ATOMIC);
	if (clear == NULL) {
		dev_err(&udev->dev, "can't save CLEAR_TT_BUFFER state\n");
		/* FIXME recover somehow ... RESET_TT? */
		return -ENOMEM;
	}

	/* info that CLEAR_TT_BUFFER needs */
	clear->tt = tt->multi ? udev->ttport : 1;
	clear->devinfo = usb_pipeendpoint (pipe);
	clear->devinfo |= ((u16)udev->devaddr) << 4;
	clear->devinfo |= usb_pipecontrol(pipe)
			? (USB_ENDPOINT_XFER_CONTROL << 11)
			: (USB_ENDPOINT_XFER_BULK << 11);
	if (usb_pipein(pipe))
		clear->devinfo |= 1 << 15;

	/* info for completion callback */
	clear->hcd = bus_to_hcd(udev->bus);
	clear->ep = urb->ep;

	/* tell keventd to clear state for this TT */
	spin_lock_irqsave(&tt->lock, flags);
	list_add_tail(&clear->clear_list, &tt->clear_list);
	schedule_work(&tt->clear_work);
	spin_unlock_irqrestore(&tt->lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(usb_hub_clear_tt_buffer);

static void hub_power_on(struct usb_hub *hub, bool do_delay)
{
	int port1;

	/* Enable power on each port.  Some hubs have reserved values
	 * of LPSM (> 2) in their descriptors, even though they are
	 * USB 2.0 hubs.  Some hubs do not implement port-power switching
	 * but only emulate it.  In all cases, the ports won't work
	 * unless we send these messages to the hub.
	 */
	if (hub_is_port_power_switchable(hub))
		dev_dbg(hub->intfdev, "enabling power on all ports\n");
	else
		dev_dbg(hub->intfdev, "trying to enable port power on "
				"non-switchable hub\n");
	for (port1 = 1; port1 <= hub->hdev->maxchild; port1++)
		if (test_bit(port1, hub->power_bits))
			set_port_feature(hub->hdev, port1, USB_PORT_FEAT_POWER);
		else
			usb_clear_port_feature(hub->hdev, port1,
						USB_PORT_FEAT_POWER);
	if (do_delay)
		msleep(hub_power_on_good_delay(hub));
}

static int hub_hub_status(struct usb_hub *hub,
		u16 *status, u16 *change)
{
	int ret;

	mutex_lock(&hub->status_mutex);
	ret = get_hub_status(hub->hdev, &hub->status->hub);
	if (ret < 0) {
		if (ret != -ENODEV)
			dev_err(hub->intfdev,
				"%s failed (err = %d)\n", __func__, ret);
	} else {
		*status = le16_to_cpu(hub->status->hub.wHubStatus);
		*change = le16_to_cpu(hub->status->hub.wHubChange);
		ret = 0;
	}
	mutex_unlock(&hub->status_mutex);
	return ret;
}

static int hub_set_port_link_state(struct usb_hub *hub, int port1,
			unsigned int link_status)
{
	return set_port_feature(hub->hdev,
			port1 | (link_status << 3),
			USB_PORT_FEAT_LINK_STATE);
}

/*
 * Disable a port and mark a logical connect-change event, so that some
 * time later hub_wq will disconnect() any existing usb_device on the port
 * and will re-enumerate if there actually is a device attached.
 */
static void hub_port_logical_disconnect(struct usb_hub *hub, int port1)
{
	dev_dbg(&hub->ports[port1 - 1]->dev, "logical disconnect\n");
	hub_port_disable(hub, port1, 1);

	/* FIXME let caller ask to power down the port:
	 *  - some devices won't enumerate without a VBUS power cycle
	 *  - SRP saves power that way
	 *  - ... new call, TBD ...
	 * That's easy if this hub can switch power per-port, and
	 * hub_wq reactivates the port later (timer, SRP, etc).
	 * Powerdown must be optional, because of reset/DFU.
	 */

	set_bit(port1, hub->change_bits);
	kick_hub_wq(hub);
}

/**
 * usb_remove_device - disable a device's port on its parent hub
 * @udev: device to be disabled and removed
 * Context: @udev locked, must be able to sleep.
 *
 * After @udev's port has been disabled, hub_wq is notified and it will
 * see that the device has been disconnected.  When the device is
 * physically unplugged and something is plugged in, the events will
 * be received and processed normally.
 *
 * Return: 0 if successful. A negative error code otherwise.
 */
int usb_remove_device(struct usb_device *udev)
{
	struct usb_hub *hub;
	struct usb_interface *intf;
	int ret;

	if (!udev->parent)	/* Can't remove a root hub */
		return -EINVAL;
	hub = usb_hub_to_struct_hub(udev->parent);
	intf = to_usb_interface(hub->intfdev);

	ret = usb_autopm_get_interface(intf);
	if (ret < 0)
		return ret;

	set_bit(udev->portnum, hub->removed_bits);
	hub_port_logical_disconnect(hub, udev->portnum);
	usb_autopm_put_interface(intf);
	return 0;
}

enum hub_activation_type {
	HUB_INIT, HUB_INIT2, HUB_INIT3,		/* INITs must come first */
	HUB_POST_RESET, HUB_RESUME, HUB_RESET_RESUME,
};

static void hub_init_func2(struct work_struct *ws);
static void hub_init_func3(struct work_struct *ws);

static void hub_activate(struct usb_hub *hub, enum hub_activation_type type)
{
	struct usb_device *hdev = hub->hdev;
	struct usb_hcd *hcd;
	int ret;
	int port1;
	int status;
	bool need_debounce_delay = false;
	unsigned delay;

	/* Continue a partial initialization */
	if (type == HUB_INIT2 || type == HUB_INIT3) {
		device_lock(&hdev->dev);

		/* Was the hub disconnected while we were waiting? */
		if (hub->disconnected)
			goto disconnected;
		if (type == HUB_INIT2)
			goto init2;
		goto init3;
	}
	kref_get(&hub->kref);

	/* The superspeed hub except for root hub has to use Hub Depth
	 * value as an offset into the route string to locate the bits
	 * it uses to determine the downstream port number. So hub driver
	 * should send a set hub depth request to superspeed hub after
	 * the superspeed hub is set configuration in initialization or
	 * reset procedure.
	 *
	 * After a resume, port power should still be on.
	 * For any other type of activation, turn it on.
	 */
	if (type != HUB_RESUME) {
		if (hdev->parent && hub_is_superspeed(hdev)) {
			ret = usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
					HUB_SET_DEPTH, USB_RT_HUB,
					hdev->level - 1, 0, NULL, 0,
					USB_CTRL_SET_TIMEOUT);
			if (ret < 0)
				dev_err(hub->intfdev,
						"set hub depth failed\n");
		}

		/* Speed up system boot by using a delayed_work for the
		 * hub's initial power-up delays.  This is pretty awkward
		 * and the implementation looks like a home-brewed sort of
		 * setjmp/longjmp, but it saves at least 100 ms for each
		 * root hub (assuming usbcore is compiled into the kernel
		 * rather than as a module).  It adds up.
		 *
		 * This can't be done for HUB_RESUME or HUB_RESET_RESUME
		 * because for those activation types the ports have to be
		 * operational when we return.  In theory this could be done
		 * for HUB_POST_RESET, but it's easier not to.
		 */
		if (type == HUB_INIT) {
			delay = hub_power_on_good_delay(hub);

			hub_power_on(hub, false);
			INIT_DELAYED_WORK(&hub->init_work, hub_init_func2);
			queue_delayed_work(system_power_efficient_wq,
					&hub->init_work,
					msecs_to_jiffies(delay));

			/* Suppress autosuspend until init is done */
			usb_autopm_get_interface_no_resume(
					to_usb_interface(hub->intfdev));
			return;		/* Continues at init2: below */
		} else if (type == HUB_RESET_RESUME) {
			/* The internal host controller state for the hub device
			 * may be gone after a host power loss on system resume.
			 * Update the device's info so the HW knows it's a hub.
			 */
			hcd = bus_to_hcd(hdev->bus);
			if (hcd->driver->update_hub_device) {
				ret = hcd->driver->update_hub_device(hcd, hdev,
						&hub->tt, GFP_NOIO);
				if (ret < 0) {
					dev_err(hub->intfdev,
						"Host not accepting hub info update\n");
					dev_err(hub->intfdev,
						"LS/FS devices and hubs may not work under this hub\n");
				}
			}
			hub_power_on(hub, true);
		} else {
			hub_power_on(hub, true);
		}
	}
 init2:

	/*
	 * Check each port and set hub->change_bits to let hub_wq know
	 * which ports need attention.
	 */
	for (port1 = 1; port1 <= hdev->maxchild; ++port1) {
		struct usb_port *port_dev = hub->ports[port1 - 1];
		struct usb_device *udev = port_dev->child;
		u16 portstatus, portchange;

		portstatus = portchange = 0;
		status = hub_port_status(hub, port1, &portstatus, &portchange);
		if (status)
			goto abort;

		if (udev || (portstatus & USB_PORT_STAT_CONNECTION))
			dev_dbg(&port_dev->dev, "status %04x change %04x\n",
					portstatus, portchange);

		/*
		 * After anything other than HUB_RESUME (i.e., initialization
		 * or any sort of reset), every port should be disabled.
		 * Unconnected ports should likewise be disabled (paranoia),
		 * and so should ports for which we have no usb_device.
		 */
		if ((portstatus & USB_PORT_STAT_ENABLE) && (
				type != HUB_RESUME ||
				!(portstatus & USB_PORT_STAT_CONNECTION) ||
				!udev ||
				udev->state == USB_STATE_NOTATTACHED)) {
			/*
			 * USB3 protocol ports will automatically transition
			 * to Enabled state when detect an USB3.0 device attach.
			 * Do not disable USB3 protocol ports, just pretend
			 * power was lost
			 */
			portstatus &= ~USB_PORT_STAT_ENABLE;
			if (!hub_is_superspeed(hdev))
				usb_clear_port_feature(hdev, port1,
						   USB_PORT_FEAT_ENABLE);
		}

		/* Make sure a warm-reset request is handled by port_event */
		if (type == HUB_RESUME &&
		    hub_port_warm_reset_required(hub, port1, portstatus))
			set_bit(port1, hub->event_bits);

		/*
		 * Add debounce if USB3 link is in polling/link training state.
		 * Link will automatically transition to Enabled state after
		 * link training completes.
		 */
		if (hub_is_superspeed(hdev) &&
		    ((portstatus & USB_PORT_STAT_LINK_STATE) ==
						USB_SS_PORT_LS_POLLING))
			need_debounce_delay = true;

		/* Clear status-change flags; we'll debounce later */
		if (portchange & USB_PORT_STAT_C_CONNECTION) {
			need_debounce_delay = true;
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_CONNECTION);
		}
		if (portchange & USB_PORT_STAT_C_ENABLE) {
			need_debounce_delay = true;
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_ENABLE);
		}
		if (portchange & USB_PORT_STAT_C_RESET) {
			need_debounce_delay = true;
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_RESET);
		}
		if ((portchange & USB_PORT_STAT_C_BH_RESET) &&
				hub_is_superspeed(hub->hdev)) {
			need_debounce_delay = true;
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_BH_PORT_RESET);
		}
		/* We can forget about a "removed" device when there's a
		 * physical disconnect or the connect status changes.
		 */
		if (!(portstatus & USB_PORT_STAT_CONNECTION) ||
				(portchange & USB_PORT_STAT_C_CONNECTION))
			clear_bit(port1, hub->removed_bits);

		if (!udev || udev->state == USB_STATE_NOTATTACHED) {
			/* Tell hub_wq to disconnect the device or
			 * check for a new connection or over current condition.
			 * Based on USB2.0 Spec Section 11.12.5,
			 * C_PORT_OVER_CURRENT could be set while
			 * PORT_OVER_CURRENT is not. So check for any of them.
			 */
			if (udev || (portstatus & USB_PORT_STAT_CONNECTION) ||
			    (portchange & USB_PORT_STAT_C_CONNECTION) ||
			    (portstatus & USB_PORT_STAT_OVERCURRENT) ||
			    (portchange & USB_PORT_STAT_C_OVERCURRENT))
				set_bit(port1, hub->change_bits);

		} else if (portstatus & USB_PORT_STAT_ENABLE) {
			bool port_resumed = (portstatus &
					USB_PORT_STAT_LINK_STATE) ==
				USB_SS_PORT_LS_U0;
			/* The power session apparently survived the resume.
			 * If there was an overcurrent or suspend change
			 * (i.e., remote wakeup request), have hub_wq
			 * take care of it.  Look at the port link state
			 * for USB 3.0 hubs, since they don't have a suspend
			 * change bit, and they don't set the port link change
			 * bit on device-initiated resume.
			 */
			if (portchange || (hub_is_superspeed(hub->hdev) &&
						port_resumed))
				set_bit(port1, hub->change_bits);

		} else if (udev->persist_enabled) {
#ifdef CONFIG_PM
			udev->reset_resume = 1;
#endif
			/* Don't set the change_bits when the device
			 * was powered off.
			 */
			if (test_bit(port1, hub->power_bits))
				set_bit(port1, hub->change_bits);

		} else {
			/* The power session is gone; tell hub_wq */
			usb_set_device_state(udev, USB_STATE_NOTATTACHED);
			set_bit(port1, hub->change_bits);
		}
	}

	/* If no port-status-change flags were set, we don't need any
	 * debouncing.  If flags were set we can try to debounce the
	 * ports all at once right now, instead of letting hub_wq do them
	 * one at a time later on.
	 *
	 * If any port-status changes do occur during this delay, hub_wq
	 * will see them later and handle them normally.
	 */
	if (need_debounce_delay) {
		delay = HUB_DEBOUNCE_STABLE;

		/* Don't do a long sleep inside a workqueue routine */
		if (type == HUB_INIT2) {
			INIT_DELAYED_WORK(&hub->init_work, hub_init_func3);
			queue_delayed_work(system_power_efficient_wq,
					&hub->init_work,
					msecs_to_jiffies(delay));
			device_unlock(&hdev->dev);
			return;		/* Continues at init3: below */
		} else {
			msleep(delay);
		}
	}
 init3:
	hub->quiescing = 0;

	status = usb_submit_urb(hub->urb, GFP_NOIO);
	if (status < 0)
		dev_err(hub->intfdev, "activate --> %d\n", status);
	if (hub->has_indicators && blinkenlights)
		queue_delayed_work(system_power_efficient_wq,
				&hub->leds, LED_CYCLE_PERIOD);

	/* Scan all ports that need attention */
	kick_hub_wq(hub);
 abort:
	if (type == HUB_INIT2 || type == HUB_INIT3) {
		/* Allow autosuspend if it was suppressed */
 disconnected:
		usb_autopm_put_interface_async(to_usb_interface(hub->intfdev));
		device_unlock(&hdev->dev);
	}

	kref_put(&hub->kref, hub_release);
}

/* Implement the continuations for the delays above */
static void hub_init_func2(struct work_struct *ws)
{
	struct usb_hub *hub = container_of(ws, struct usb_hub, init_work.work);

	hub_activate(hub, HUB_INIT2);
}

static void hub_init_func3(struct work_struct *ws)
{
	struct usb_hub *hub = container_of(ws, struct usb_hub, init_work.work);

	hub_activate(hub, HUB_INIT3);
}

enum hub_quiescing_type {
	HUB_DISCONNECT, HUB_PRE_RESET, HUB_SUSPEND
};

static void hub_quiesce(struct usb_hub *hub, enum hub_quiescing_type type)
{
	struct usb_device *hdev = hub->hdev;
	unsigned long flags;
	int i;

	/* hub_wq and related activity won't re-trigger */
	spin_lock_irqsave(&hub->irq_urb_lock, flags);
	hub->quiescing = 1;
	spin_unlock_irqrestore(&hub->irq_urb_lock, flags);

	if (type != HUB_SUSPEND) {
		/* Disconnect all the children */
		for (i = 0; i < hdev->maxchild; ++i) {
			if (hub->ports[i]->child)
				usb_disconnect(&hub->ports[i]->child);
		}
	}

	/* Stop hub_wq and related activity */
	del_timer_sync(&hub->irq_urb_retry);
	usb_kill_urb(hub->urb);
	if (hub->has_indicators)
		cancel_delayed_work_sync(&hub->leds);
	if (hub->tt.hub)
		flush_work(&hub->tt.clear_work);
}

static void hub_pm_barrier_for_all_ports(struct usb_hub *hub)
{
	int i;

	for (i = 0; i < hub->hdev->maxchild; ++i)
		pm_runtime_barrier(&hub->ports[i]->dev);
}

/* caller has locked the hub device */
static int hub_pre_reset(struct usb_interface *intf)
{
	struct usb_hub *hub = usb_get_intfdata(intf);

	hub_quiesce(hub, HUB_PRE_RESET);
	hub->in_reset = 1;
	hub_pm_barrier_for_all_ports(hub);
	return 0;
}

/* caller has locked the hub device */
static int hub_post_reset(struct usb_interface *intf)
{
	struct usb_hub *hub = usb_get_intfdata(intf);

	hub->in_reset = 0;
	hub_pm_barrier_for_all_ports(hub);
	hub_activate(hub, HUB_POST_RESET);
	return 0;
}

static int hub_configure(struct usb_hub *hub,
	struct usb_endpoint_descriptor *endpoint)
{
	struct usb_hcd *hcd;
	struct usb_device *hdev = hub->hdev;
	struct device *hub_dev = hub->intfdev;
	u16 hubstatus, hubchange;
	u16 wHubCharacteristics;
	unsigned int pipe;
	int maxp, ret, i;
	char *message = "out of memory";
	unsigned unit_load;
	unsigned full_load;
	unsigned maxchild;

	hub->buffer = kmalloc(sizeof(*hub->buffer), GFP_KERNEL);
	if (!hub->buffer) {
		ret = -ENOMEM;
		goto fail;
	}

	hub->status = kmalloc(sizeof(*hub->status), GFP_KERNEL);
	if (!hub->status) {
		ret = -ENOMEM;
		goto fail;
	}
	mutex_init(&hub->status_mutex);

	hub->descriptor = kzalloc(sizeof(*hub->descriptor), GFP_KERNEL);
	if (!hub->descriptor) {
		ret = -ENOMEM;
		goto fail;
	}

	/* Request the entire hub descriptor.
	 * hub->descriptor can handle USB_MAXCHILDREN ports,
	 * but a (non-SS) hub can/will return fewer bytes here.
	 */
	ret = get_hub_descriptor(hdev, hub->descriptor);
	if (ret < 0) {
		message = "can't read hub descriptor";
		goto fail;
	}

	maxchild = USB_MAXCHILDREN;
	if (hub_is_superspeed(hdev))
		maxchild = min_t(unsigned, maxchild, USB_SS_MAXPORTS);

	if (hub->descriptor->bNbrPorts > maxchild) {
		message = "hub has too many ports!";
		ret = -ENODEV;
		goto fail;
	} else if (hub->descriptor->bNbrPorts == 0) {
		message = "hub doesn't have any ports!";
		ret = -ENODEV;
		goto fail;
	}

	/*
	 * Accumulate wHubDelay + 40ns for every hub in the tree of devices.
	 * The resulting value will be used for SetIsochDelay() request.
	 */
	if (hub_is_superspeed(hdev) || hub_is_superspeedplus(hdev)) {
		u32 delay = __le16_to_cpu(hub->descriptor->u.ss.wHubDelay);

		if (hdev->parent)
			delay += hdev->parent->hub_delay;

		delay += USB_TP_TRANSMISSION_DELAY;
		hdev->hub_delay = min_t(u32, delay, USB_TP_TRANSMISSION_DELAY_MAX);
	}

	maxchild = hub->descriptor->bNbrPorts;
	dev_info(hub_dev, "%d port%s detected\n", maxchild,
			(maxchild == 1) ? "" : "s");

	hub->ports = kcalloc(maxchild, sizeof(struct usb_port *), GFP_KERNEL);
	if (!hub->ports) {
		ret = -ENOMEM;
		goto fail;
	}

	wHubCharacteristics = le16_to_cpu(hub->descriptor->wHubCharacteristics);
	if (hub_is_superspeed(hdev)) {
		unit_load = 150;
		full_load = 900;
	} else {
		unit_load = 100;
		full_load = 500;
	}

	/* FIXME for USB 3.0, skip for now */
	if ((wHubCharacteristics & HUB_CHAR_COMPOUND) &&
			!(hub_is_superspeed(hdev))) {
		char	portstr[USB_MAXCHILDREN + 1];

		for (i = 0; i < maxchild; i++)
			portstr[i] = hub->descriptor->u.hs.DeviceRemovable
				    [((i + 1) / 8)] & (1 << ((i + 1) % 8))
				? 'F' : 'R';
		portstr[maxchild] = 0;
		dev_dbg(hub_dev, "compound device; port removable status: %s\n", portstr);
	} else
		dev_dbg(hub_dev, "standalone hub\n");

	switch (wHubCharacteristics & HUB_CHAR_LPSM) {
	case HUB_CHAR_COMMON_LPSM:
		dev_dbg(hub_dev, "ganged power switching\n");
		break;
	case HUB_CHAR_INDV_PORT_LPSM:
		dev_dbg(hub_dev, "individual port power switching\n");
		break;
	case HUB_CHAR_NO_LPSM:
	case HUB_CHAR_LPSM:
		dev_dbg(hub_dev, "no power switching (usb 1.0)\n");
		break;
	}

	switch (wHubCharacteristics & HUB_CHAR_OCPM) {
	case HUB_CHAR_COMMON_OCPM:
		dev_dbg(hub_dev, "global over-current protection\n");
		break;
	case HUB_CHAR_INDV_PORT_OCPM:
		dev_dbg(hub_dev, "individual port over-current protection\n");
		break;
	case HUB_CHAR_NO_OCPM:
	case HUB_CHAR_OCPM:
		dev_dbg(hub_dev, "no over-current protection\n");
		break;
	}

	spin_lock_init(&hub->tt.lock);
	INIT_LIST_HEAD(&hub->tt.clear_list);
	INIT_WORK(&hub->tt.clear_work, hub_tt_work);
	switch (hdev->descriptor.bDeviceProtocol) {
	case USB_HUB_PR_FS:
		break;
	case USB_HUB_PR_HS_SINGLE_TT:
		dev_dbg(hub_dev, "Single TT\n");
		hub->tt.hub = hdev;
		break;
	case USB_HUB_PR_HS_MULTI_TT:
		ret = usb_set_interface(hdev, 0, 1);
		if (ret == 0) {
			dev_dbg(hub_dev, "TT per port\n");
			hub->tt.multi = 1;
		} else
			dev_err(hub_dev, "Using single TT (err %d)\n",
				ret);
		hub->tt.hub = hdev;
		break;
	case USB_HUB_PR_SS:
		/* USB 3.0 hubs don't have a TT */
		break;
	default:
		dev_dbg(hub_dev, "Unrecognized hub protocol %d\n",
			hdev->descriptor.bDeviceProtocol);
		break;
	}

	/* Note 8 FS bit times == (8 bits / 12000000 bps) ~= 666ns */
	switch (wHubCharacteristics & HUB_CHAR_TTTT) {
	case HUB_TTTT_8_BITS:
		if (hdev->descriptor.bDeviceProtocol != 0) {
			hub->tt.think_time = 666;
			dev_dbg(hub_dev, "TT requires at most %d "
					"FS bit times (%d ns)\n",
				8, hub->tt.think_time);
		}
		break;
	case HUB_TTTT_16_BITS:
		hub->tt.think_time = 666 * 2;
		dev_dbg(hub_dev, "TT requires at most %d "
				"FS bit times (%d ns)\n",
			16, hub->tt.think_time);
		break;
	case HUB_TTTT_24_BITS:
		hub->tt.think_time = 666 * 3;
		dev_dbg(hub_dev, "TT requires at most %d "
				"FS bit times (%d ns)\n",
			24, hub->tt.think_time);
		break;
	case HUB_TTTT_32_BITS:
		hub->tt.think_time = 666 * 4;
		dev_dbg(hub_dev, "TT requires at most %d "
				"FS bit times (%d ns)\n",
			32, hub->tt.think_time);
		break;
	}

	/* probe() zeroes hub->indicator[] */
	if (wHubCharacteristics & HUB_CHAR_PORTIND) {
		hub->has_indicators = 1;
		dev_dbg(hub_dev, "Port indicators are supported\n");
	}

	dev_dbg(hub_dev, "power on to power good time: %dms\n",
		hub->descriptor->bPwrOn2PwrGood * 2);

	/* power budgeting mostly matters with bus-powered hubs,
	 * and battery-powered root hubs (may provide just 8 mA).
	 */
	ret = usb_get_std_status(hdev, USB_RECIP_DEVICE, 0, &hubstatus);
	if (ret) {
		message = "can't get hub status";
		goto fail;
	}
	hcd = bus_to_hcd(hdev->bus);
	if (hdev == hdev->bus->root_hub) {
		if (hcd->power_budget > 0)
			hdev->bus_mA = hcd->power_budget;
		else
			hdev->bus_mA = full_load * maxchild;
		if (hdev->bus_mA >= full_load)
			hub->mA_per_port = full_load;
		else {
			hub->mA_per_port = hdev->bus_mA;
			hub->limited_power = 1;
		}
	} else if ((hubstatus & (1 << USB_DEVICE_SELF_POWERED)) == 0) {
		int remaining = hdev->bus_mA -
			hub->descriptor->bHubContrCurrent;

		dev_dbg(hub_dev, "hub controller current requirement: %dmA\n",
			hub->descriptor->bHubContrCurrent);
		hub->limited_power = 1;

		if (remaining < maxchild * unit_load)
			dev_warn(hub_dev,
					"insufficient power available "
					"to use all downstream ports\n");
		hub->mA_per_port = unit_load;	/* 7.2.1 */

	} else {	/* Self-powered external hub */
		/* FIXME: What about battery-powered external hubs that
		 * provide less current per port? */
		hub->mA_per_port = full_load;
	}
	if (hub->mA_per_port < full_load)
		dev_dbg(hub_dev, "%umA bus power budget for each child\n",
				hub->mA_per_port);

	ret = hub_hub_status(hub, &hubstatus, &hubchange);
	if (ret < 0) {
		message = "can't get hub status";
		goto fail;
	}

	/* local power status reports aren't always correct */
	if (hdev->actconfig->desc.bmAttributes & USB_CONFIG_ATT_SELFPOWER)
		dev_dbg(hub_dev, "local power source is %s\n",
			(hubstatus & HUB_STATUS_LOCAL_POWER)
			? "lost (inactive)" : "good");

	if ((wHubCharacteristics & HUB_CHAR_OCPM) == 0)
		dev_dbg(hub_dev, "%sover-current condition exists\n",
			(hubstatus & HUB_STATUS_OVERCURRENT) ? "" : "no ");

	/* set up the interrupt endpoint
	 * We use the EP's maxpacket size instead of (PORTS+1+7)/8
	 * bytes as USB2.0[11.12.3] says because some hubs are known
	 * to send more data (and thus cause overflow). For root hubs,
	 * maxpktsize is defined in hcd.c's fake endpoint descriptors
	 * to be big enough for at least USB_MAXCHILDREN ports. */
	pipe = usb_rcvintpipe(hdev, endpoint->bEndpointAddress);
	maxp = usb_maxpacket(hdev, pipe, usb_pipeout(pipe));

	if (maxp > sizeof(*hub->buffer))
		maxp = sizeof(*hub->buffer);

	hub->urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!hub->urb) {
		ret = -ENOMEM;
		goto fail;
	}

	usb_fill_int_urb(hub->urb, hdev, pipe, *hub->buffer, maxp, hub_irq,
		hub, endpoint->bInterval);

	/* maybe cycle the hub leds */
	if (hub->has_indicators && blinkenlights)
		hub->indicator[0] = INDICATOR_CYCLE;

	mutex_lock(&usb_port_peer_mutex);
	for (i = 0; i < maxchild; i++) {
		ret = usb_hub_create_port_device(hub, i + 1);
		if (ret < 0) {
			dev_err(hub->intfdev,
				"couldn't create port%d device.\n", i + 1);
			break;
		}
	}
	hdev->maxchild = i;
	for (i = 0; i < hdev->maxchild; i++) {
		struct usb_port *port_dev = hub->ports[i];

		pm_runtime_put(&port_dev->dev);
	}

	mutex_unlock(&usb_port_peer_mutex);
	if (ret < 0)
		goto fail;

	/* Update the HCD's internal representation of this hub before hub_wq
	 * starts getting port status changes for devices under the hub.
	 */
	if (hcd->driver->update_hub_device) {
		ret = hcd->driver->update_hub_device(hcd, hdev,
				&hub->tt, GFP_KERNEL);
		if (ret < 0) {
			message = "can't update HCD hub info";
			goto fail;
		}
	}

	usb_hub_adjust_deviceremovable(hdev, hub->descriptor);

	hub_activate(hub, HUB_INIT);
	return 0;

fail:
	dev_err(hub_dev, "config failed, %s (err %d)\n",
			message, ret);
	/* hub_disconnect() frees urb and descriptor */
	return ret;
}

static void hub_release(struct kref *kref)
{
	struct usb_hub *hub = container_of(kref, struct usb_hub, kref);

	usb_put_dev(hub->hdev);
	usb_put_intf(to_usb_interface(hub->intfdev));
	kfree(hub);
}

static unsigned highspeed_hubs;

static void hub_disconnect(struct usb_interface *intf)
{
	struct usb_hub *hub = usb_get_intfdata(intf);
	struct usb_device *hdev = interface_to_usbdev(intf);
	int port1;

	/*
	 * Stop adding new hub events. We do not want to block here and thus
	 * will not try to remove any pending work item.
	 */
	hub->disconnected = 1;

	/* Disconnect all children and quiesce the hub */
	hub->error = 0;
	hub_quiesce(hub, HUB_DISCONNECT);

	mutex_lock(&usb_port_peer_mutex);

	/* Avoid races with recursively_mark_NOTATTACHED() */
	spin_lock_irq(&device_state_lock);
	port1 = hdev->maxchild;
	hdev->maxchild = 0;
	usb_set_intfdata(intf, NULL);
	spin_unlock_irq(&device_state_lock);

	for (; port1 > 0; --port1)
		usb_hub_remove_port_device(hub, port1);

	mutex_unlock(&usb_port_peer_mutex);

	if (hub->hdev->speed == USB_SPEED_HIGH)
		highspeed_hubs--;

	usb_free_urb(hub->urb);
	kfree(hub->ports);
	kfree(hub->descriptor);
	kfree(hub->status);
	kfree(hub->buffer);

	pm_suspend_ignore_children(&intf->dev, false);

	if (hub->quirk_disable_autosuspend)
		usb_autopm_put_interface(intf);

	kref_put(&hub->kref, hub_release);
}

static bool hub_descriptor_is_sane(struct usb_host_interface *desc)
{
	/* Some hubs have a subclass of 1, which AFAICT according to the */
	/*  specs is not defined, but it works */
	if (desc->desc.bInterfaceSubClass != 0 &&
	    desc->desc.bInterfaceSubClass != 1)
		return false;

	/* Multiple endpoints? What kind of mutant ninja-hub is this? */
	if (desc->desc.bNumEndpoints != 1)
		return false;

	/* If the first endpoint is not interrupt IN, we'd better punt! */
	if (!usb_endpoint_is_int_in(&desc->endpoint[0].desc))
		return false;

        return true;
}

static int hub_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	struct usb_host_interface *desc;
	struct usb_device *hdev;
	struct usb_hub *hub;

	desc = intf->cur_altsetting;
	hdev = interface_to_usbdev(intf);

	/*
	 * Set default autosuspend delay as 0 to speedup bus suspend,
	 * based on the below considerations:
	 *
	 * - Unlike other drivers, the hub driver does not rely on the
	 *   autosuspend delay to provide enough time to handle a wakeup
	 *   event, and the submitted status URB is just to check future
	 *   change on hub downstream ports, so it is safe to do it.
	 *
	 * - The patch might cause one or more auto supend/resume for
	 *   below very rare devices when they are plugged into hub
	 *   first time:
	 *
	 *   	devices having trouble initializing, and disconnect
	 *   	themselves from the bus and then reconnect a second
	 *   	or so later
	 *
	 *   	devices just for downloading firmware, and disconnects
	 *   	themselves after completing it
	 *
	 *   For these quite rare devices, their drivers may change the
	 *   autosuspend delay of their parent hub in the probe() to one
	 *   appropriate value to avoid the subtle problem if someone
	 *   does care it.
	 *
	 * - The patch may cause one or more auto suspend/resume on
	 *   hub during running 'lsusb', but it is probably too
	 *   infrequent to worry about.
	 *
	 * - Change autosuspend delay of hub can avoid unnecessary auto
	 *   suspend timer for hub, also may decrease power consumption
	 *   of USB bus.
	 *
	 * - If user has indicated to prevent autosuspend by passing
	 *   usbcore.autosuspend = -1 then keep autosuspend disabled.
	 */
#ifdef CONFIG_PM
	if (hdev->dev.power.autosuspend_delay >= 0)
		pm_runtime_set_autosuspend_delay(&hdev->dev, 0);
#endif

	/*
	 * Hubs have proper suspend/resume support, except for root hubs
	 * where the controller driver doesn't have bus_suspend and
	 * bus_resume methods.
	 */
	if (hdev->parent) {		/* normal device */
		if (!(hdev->parent->quirks & USB_QUIRK_AUTO_SUSPEND))
			usb_enable_autosuspend(hdev);
	} else {			/* root hub */
		const struct hc_driver *drv = bus_to_hcd(hdev->bus)->driver;

		if (drv->bus_suspend && drv->bus_resume)
			usb_enable_autosuspend(hdev);
	}

	if (hdev->level == MAX_TOPO_LEVEL) {
		dev_err(&intf->dev,
			"Unsupported bus topology: hub nested too deep\n");
		return -E2BIG;
	}

#ifdef	CONFIG_USB_OTG_DISABLE_EXTERNAL_HUB
	if (hdev->parent) {
		dev_warn(&intf->dev, "ignoring external hub\n");
		return -ENODEV;
	}
#endif

	if (!hub_descriptor_is_sane(desc)) {
		dev_err(&intf->dev, "bad descriptor, ignoring hub\n");
		return -EIO;
	}

	/* We found a hub */
	dev_info(&intf->dev, "USB hub found\n");

	hub = kzalloc(sizeof(*hub), GFP_KERNEL);
	if (!hub)
		return -ENOMEM;

	kref_init(&hub->kref);
	hub->intfdev = &intf->dev;
	hub->hdev = hdev;
	INIT_DELAYED_WORK(&hub->leds, led_work);
	INIT_DELAYED_WORK(&hub->init_work, NULL);
	INIT_WORK(&hub->events, hub_event);
	spin_lock_init(&hub->irq_urb_lock);
	timer_setup(&hub->irq_urb_retry, hub_retry_irq_urb, 0);
	usb_get_intf(intf);
	usb_get_dev(hdev);

	usb_set_intfdata(intf, hub);
	intf->needs_remote_wakeup = 1;
	pm_suspend_ignore_children(&intf->dev, true);

	if (hdev->speed == USB_SPEED_HIGH)
		highspeed_hubs++;

	if (id->driver_info & HUB_QUIRK_CHECK_PORT_AUTOSUSPEND)
		hub->quirk_check_port_auto_suspend = 1;

	if (id->driver_info & HUB_QUIRK_DISABLE_AUTOSUSPEND) {
		hub->quirk_disable_autosuspend = 1;
		usb_autopm_get_interface_no_resume(intf);
	}

	if (hub_configure(hub, &desc->endpoint[0].desc) >= 0)
		return 0;

	hub_disconnect(intf);
	return -ENODEV;
}

static int
hub_ioctl(struct usb_interface *intf, unsigned int code, void *user_data)
{
	struct usb_device *hdev = interface_to_usbdev(intf);
	struct usb_hub *hub = usb_hub_to_struct_hub(hdev);

	/* assert ifno == 0 (part of hub spec) */
	switch (code) {
	case USBDEVFS_HUB_PORTINFO: {
		struct usbdevfs_hub_portinfo *info = user_data;
		int i;

		spin_lock_irq(&device_state_lock);
		if (hdev->devnum <= 0)
			info->nports = 0;
		else {
			info->nports = hdev->maxchild;
			for (i = 0; i < info->nports; i++) {
				if (hub->ports[i]->child == NULL)
					info->port[i] = 0;
				else
					info->port[i] =
						hub->ports[i]->child->devnum;
			}
		}
		spin_unlock_irq(&device_state_lock);

		return info->nports + 1;
		}

	default:
		return -ENOSYS;
	}
}

/*
 * Allow user programs to claim ports on a hub.  When a device is attached
 * to one of these "claimed" ports, the program will "own" the device.
 */
static int find_port_owner(struct usb_device *hdev, unsigned port1,
		struct usb_dev_state ***ppowner)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(hdev);

	if (hdev->state == USB_STATE_NOTATTACHED)
		return -ENODEV;
	if (port1 == 0 || port1 > hdev->maxchild)
		return -EINVAL;

	/* Devices not managed by the hub driver
	 * will always have maxchild equal to 0.
	 */
	*ppowner = &(hub->ports[port1 - 1]->port_owner);
	return 0;
}

/* In the following three functions, the caller must hold hdev's lock */
int usb_hub_claim_port(struct usb_device *hdev, unsigned port1,
		       struct usb_dev_state *owner)
{
	int rc;
	struct usb_dev_state **powner;

	rc = find_port_owner(hdev, port1, &powner);
	if (rc)
		return rc;
	if (*powner)
		return -EBUSY;
	*powner = owner;
	return rc;
}
EXPORT_SYMBOL_GPL(usb_hub_claim_port);

int usb_hub_release_port(struct usb_device *hdev, unsigned port1,
			 struct usb_dev_state *owner)
{
	int rc;
	struct usb_dev_state **powner;

	rc = find_port_owner(hdev, port1, &powner);
	if (rc)
		return rc;
	if (*powner != owner)
		return -ENOENT;
	*powner = NULL;
	return rc;
}
EXPORT_SYMBOL_GPL(usb_hub_release_port);

void usb_hub_release_all_ports(struct usb_device *hdev, struct usb_dev_state *owner)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(hdev);
	int n;

	for (n = 0; n < hdev->maxchild; n++) {
		if (hub->ports[n]->port_owner == owner)
			hub->ports[n]->port_owner = NULL;
	}

}

/* The caller must hold udev's lock */
bool usb_device_is_owned(struct usb_device *udev)
{
	struct usb_hub *hub;

	if (udev->state == USB_STATE_NOTATTACHED || !udev->parent)
		return false;
	hub = usb_hub_to_struct_hub(udev->parent);
	return !!hub->ports[udev->portnum - 1]->port_owner;
}

static void recursively_mark_NOTATTACHED(struct usb_device *udev)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(udev);
	int i;

	for (i = 0; i < udev->maxchild; ++i) {
		if (hub->ports[i]->child)
			recursively_mark_NOTATTACHED(hub->ports[i]->child);
	}
	if (udev->state == USB_STATE_SUSPENDED)
		udev->active_duration -= jiffies;
	udev->state = USB_STATE_NOTATTACHED;
}

/**
 * usb_set_device_state - change a device's current state (usbcore, hcds)
 * @udev: pointer to device whose state should be changed
 * @new_state: new state value to be stored
 *
 * udev->state is _not_ fully protected by the device lock.  Although
 * most transitions are made only while holding the lock, the state can
 * can change to USB_STATE_NOTATTACHED at almost any time.  This
 * is so that devices can be marked as disconnected as soon as possible,
 * without having to wait for any semaphores to be released.  As a result,
 * all changes to any device's state must be protected by the
 * device_state_lock spinlock.
 *
 * Once a device has been added to the device tree, all changes to its state
 * should be made using this routine.  The state should _not_ be set directly.
 *
 * If udev->state is already USB_STATE_NOTATTACHED then no change is made.
 * Otherwise udev->state is set to new_state, and if new_state is
 * USB_STATE_NOTATTACHED then all of udev's descendants' states are also set
 * to USB_STATE_NOTATTACHED.
 */
void usb_set_device_state(struct usb_device *udev,
		enum usb_device_state new_state)
{
	unsigned long flags;
	int wakeup = -1;

	spin_lock_irqsave(&device_state_lock, flags);
	if (udev->state == USB_STATE_NOTATTACHED)
		;	/* do nothing */
	else if (new_state != USB_STATE_NOTATTACHED) {

		/* root hub wakeup capabilities are managed out-of-band
		 * and may involve silicon errata ... ignore them here.
		 */
		if (udev->parent) {
			if (udev->state == USB_STATE_SUSPENDED
					|| new_state == USB_STATE_SUSPENDED)
				;	/* No change to wakeup settings */
			else if (new_state == USB_STATE_CONFIGURED)
				wakeup = (udev->quirks &
					USB_QUIRK_IGNORE_REMOTE_WAKEUP) ? 0 :
					udev->actconfig->desc.bmAttributes &
					USB_CONFIG_ATT_WAKEUP;
			else
				wakeup = 0;
		}
		if (udev->state == USB_STATE_SUSPENDED &&
			new_state != USB_STATE_SUSPENDED)
			udev->active_duration -= jiffies;
		else if (new_state == USB_STATE_SUSPENDED &&
				udev->state != USB_STATE_SUSPENDED)
			udev->active_duration += jiffies;
		udev->state = new_state;
	} else
		recursively_mark_NOTATTACHED(udev);
	spin_unlock_irqrestore(&device_state_lock, flags);
	if (wakeup >= 0)
		device_set_wakeup_capable(&udev->dev, wakeup);
}
EXPORT_SYMBOL_GPL(usb_set_device_state);

/*
 * Choose a device number.
 *
 * Device numbers are used as filenames in usbfs.  On USB-1.1 and
 * USB-2.0 buses they are also used as device addresses, however on
 * USB-3.0 buses the address is assigned by the controller hardware
 * and it usually is not the same as the device number.
 *
 * WUSB devices are simple: they have no hubs behind, so the mapping
 * device <-> virtual port number becomes 1:1. Why? to simplify the
 * life of the device connection logic in
 * drivers/usb/wusbcore/devconnect.c. When we do the initial secret
 * handshake we need to assign a temporary address in the unauthorized
 * space. For simplicity we use the first virtual port number found to
 * be free [drivers/usb/wusbcore/devconnect.c:wusbhc_devconnect_ack()]
 * and that becomes it's address [X < 128] or its unauthorized address
 * [X | 0x80].
 *
 * We add 1 as an offset to the one-based USB-stack port number
 * (zero-based wusb virtual port index) for two reasons: (a) dev addr
 * 0 is reserved by USB for default address; (b) Linux's USB stack
 * uses always #1 for the root hub of the controller. So USB stack's
 * port #1, which is wusb virtual-port #0 has address #2.
 *
 * Devices connected under xHCI are not as simple.  The host controller
 * supports virtualization, so the hardware assigns device addresses and
 * the HCD must setup data structures before issuing a set address
 * command to the hardware.
 */
static void choose_devnum(struct usb_device *udev)
{
	int		devnum;
	struct usb_bus	*bus = udev->bus;

	/* be safe when more hub events are proceed in parallel */
	mutex_lock(&bus->devnum_next_mutex);
	if (udev->wusb) {
		devnum = udev->portnum + 1;
		BUG_ON(test_bit(devnum, bus->devmap.devicemap));
	} else {
		/* Try to allocate the next devnum beginning at
		 * bus->devnum_next. */
		devnum = find_next_zero_bit(bus->devmap.devicemap, 128,
					    bus->devnum_next);
		if (devnum >= 128)
			devnum = find_next_zero_bit(bus->devmap.devicemap,
						    128, 1);
		bus->devnum_next = (devnum >= 127 ? 1 : devnum + 1);
	}
	if (devnum < 128) {
		set_bit(devnum, bus->devmap.devicemap);
		udev->devnum = devnum;
	}
	mutex_unlock(&bus->devnum_next_mutex);
}

static void release_devnum(struct usb_device *udev)
{
	if (udev->devnum > 0) {
		clear_bit(udev->devnum, udev->bus->devmap.devicemap);
		udev->devnum = -1;
	}
}

static void update_devnum(struct usb_device *udev, int devnum)
{
	/* The address for a WUSB device is managed by wusbcore. */
	if (!udev->wusb)
		udev->devnum = devnum;
	if (!udev->devaddr)
		udev->devaddr = (u8)devnum;
}

static void hub_free_dev(struct usb_device *udev)
{
	struct usb_hcd *hcd = bus_to_hcd(udev->bus);

	/* Root hubs aren't real devices, so don't free HCD resources */
	if (hcd->driver->free_dev && udev->parent)
		hcd->driver->free_dev(hcd, udev);
}

static void hub_disconnect_children(struct usb_device *udev)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(udev);
	int i;

	/* Free up all the children before we remove this device */
	for (i = 0; i < udev->maxchild; i++) {
		if (hub->ports[i]->child)
			usb_disconnect(&hub->ports[i]->child);
	}
}

/**
 * usb_disconnect - disconnect a device (usbcore-internal)
 * @pdev: pointer to device being disconnected
 * Context: !in_interrupt ()
 *
 * Something got disconnected. Get rid of it and all of its children.
 *
 * If *pdev is a normal device then the parent hub must already be locked.
 * If *pdev is a root hub then the caller must hold the usb_bus_idr_lock,
 * which protects the set of root hubs as well as the list of buses.
 *
 * Only hub drivers (including virtual root hub drivers for host
 * controllers) should ever call this.
 *
 * This call is synchronous, and may not be used in an interrupt context.
 */
void usb_disconnect(struct usb_device **pdev)
{
	struct usb_port *port_dev = NULL;
	struct usb_device *udev = *pdev;
	struct usb_hub *hub = NULL;
	int port1 = 1;

	/* mark the device as inactive, so any further urb submissions for
	 * this device (and any of its children) will fail immediately.
	 * this quiesces everything except pending urbs.
	 */
	usb_set_device_state(udev, USB_STATE_NOTATTACHED);
	dev_info(&udev->dev, "USB disconnect, device number %d\n",
			udev->devnum);

	/*
	 * Ensure that the pm runtime code knows that the USB device
	 * is in the process of being disconnected.
	 */
	pm_runtime_barrier(&udev->dev);

	usb_lock_device(udev);

	hub_disconnect_children(udev);

	/* deallocate hcd/hardware state ... nuking all pending urbs and
	 * cleaning up all state associated with the current configuration
	 * so that the hardware is now fully quiesced.
	 */
	dev_dbg(&udev->dev, "unregistering device\n");
	usb_disable_device(udev, 0);
	usb_hcd_synchronize_unlinks(udev);

	if (udev->parent) {
		port1 = udev->portnum;
		hub = usb_hub_to_struct_hub(udev->parent);
		port_dev = hub->ports[port1 - 1];

		sysfs_remove_link(&udev->dev.kobj, "port");
		sysfs_remove_link(&port_dev->dev.kobj, "device");

		/*
		 * As usb_port_runtime_resume() de-references udev, make
		 * sure no resumes occur during removal
		 */
		if (!test_and_set_bit(port1, hub->child_usage_bits))
			pm_runtime_get_sync(&port_dev->dev);
	}

	usb_remove_ep_devs(&udev->ep0);
	usb_unlock_device(udev);

	/* Unregister the device.  The device driver is responsible
	 * for de-configuring the device and invoking the remove-device
	 * notifier chain (used by usbfs and possibly others).
	 */
	device_del(&udev->dev);

	/* Free the device number and delete the parent's children[]
	 * (or root_hub) pointer.
	 */
	release_devnum(udev);

	/* Avoid races with recursively_mark_NOTATTACHED() */
	spin_lock_irq(&device_state_lock);
	*pdev = NULL;
	spin_unlock_irq(&device_state_lock);

	if (port_dev && test_and_clear_bit(port1, hub->child_usage_bits))
		pm_runtime_put(&port_dev->dev);

	hub_free_dev(udev);

	put_device(&udev->dev);
}

#ifdef CONFIG_USB_ANNOUNCE_NEW_DEVICES
static void show_string(struct usb_device *udev, char *id, char *string)
{
	if (!string)
		return;
	dev_info(&udev->dev, "%s: %s\n", id, string);
}

static void announce_device(struct usb_device *udev)
{
	u16 bcdDevice = le16_to_cpu(udev->descriptor.bcdDevice);

	dev_info(&udev->dev,
		"New USB device found, idVendor=%04x, idProduct=%04x, bcdDevice=%2x.%02x\n",
		le16_to_cpu(udev->descriptor.idVendor),
		le16_to_cpu(udev->descriptor.idProduct),
		bcdDevice >> 8, bcdDevice & 0xff);
	dev_info(&udev->dev,
		"New USB device strings: Mfr=%d, Product=%d, SerialNumber=%d\n",
		udev->descriptor.iManufacturer,
		udev->descriptor.iProduct,
		udev->descriptor.iSerialNumber);
	show_string(udev, "Product", udev->product);
	show_string(udev, "Manufacturer", udev->manufacturer);
	show_string(udev, "SerialNumber", udev->serial);
}
#else
static inline void announce_device(struct usb_device *udev) { }
#endif


/**
 * usb_enumerate_device_otg - FIXME (usbcore-internal)
 * @udev: newly addressed device (in ADDRESS state)
 *
 * Finish enumeration for On-The-Go devices
 *
 * Return: 0 if successful. A negative error code otherwise.
 */
static int usb_enumerate_device_otg(struct usb_device *udev)
{
	int err = 0;

#ifdef	CONFIG_USB_OTG
	/*
	 * OTG-aware devices on OTG-capable root hubs may be able to use SRP,
	 * to wake us after we've powered off VBUS; and HNP, switching roles
	 * "host" to "peripheral".  The OTG descriptor helps figure this out.
	 */
	if (!udev->bus->is_b_host
			&& udev->config
			&& udev->parent == udev->bus->root_hub) {
		struct usb_otg_descriptor	*desc = NULL;
		struct usb_bus			*bus = udev->bus;
		unsigned			port1 = udev->portnum;

		/* descriptor may appear anywhere in config */
		err = __usb_get_extra_descriptor(udev->rawdescriptors[0],
				le16_to_cpu(udev->config[0].desc.wTotalLength),
				USB_DT_OTG, (void **) &desc, sizeof(*desc));
		if (err || !(desc->bmAttributes & USB_OTG_HNP))
			return 0;

		dev_info(&udev->dev, "Dual-Role OTG device on %sHNP port\n",
					(port1 == bus->otg_port) ? "" : "non-");

		/* enable HNP before suspend, it's simpler */
		if (port1 == bus->otg_port) {
			bus->b_hnp_enable = 1;
			err = usb_control_msg(udev,
				usb_sndctrlpipe(udev, 0),
				USB_REQ_SET_FEATURE, 0,
				USB_DEVICE_B_HNP_ENABLE,
				0, NULL, 0,
				USB_CTRL_SET_TIMEOUT);
			if (err < 0) {
				/*
				 * OTG MESSAGE: report errors here,
				 * customize to match your product.
				 */
				dev_err(&udev->dev, "can't set HNP mode: %d\n",
									err);
				bus->b_hnp_enable = 0;
			}
		} else if (desc->bLength == sizeof
				(struct usb_otg_descriptor)) {
			/* Set a_alt_hnp_support for legacy otg device */
			err = usb_control_msg(udev,
				usb_sndctrlpipe(udev, 0),
				USB_REQ_SET_FEATURE, 0,
				USB_DEVICE_A_ALT_HNP_SUPPORT,
				0, NULL, 0,
				USB_CTRL_SET_TIMEOUT);
			if (err < 0)
				dev_err(&udev->dev,
					"set a_alt_hnp_support failed: %d\n",
					err);
		}
	}
#endif
	return err;
}


/**
 * usb_enumerate_device - Read device configs/intfs/otg (usbcore-internal)
 * @udev: newly addressed device (in ADDRESS state)
 *
 * This is only called by usb_new_device() and usb_authorize_device()
 * and FIXME -- all comments that apply to them apply here wrt to
 * environment.
 *
 * If the device is WUSB and not authorized, we don't attempt to read
 * the string descriptors, as they will be errored out by the device
 * until it has been authorized.
 *
 * Return: 0 if successful. A negative error code otherwise.
 */
static int usb_enumerate_device(struct usb_device *udev)
{
	int err;
	struct usb_hcd *hcd = bus_to_hcd(udev->bus);

	if (udev->config == NULL) {
		err = usb_get_configuration(udev);
		if (err < 0) {
			if (err != -ENODEV)
				dev_err(&udev->dev, "can't read configurations, error %d\n",
						err);
			return err;
		}
	}

	/* read the standard strings and cache them if present */
	udev->product = usb_cache_string(udev, udev->descriptor.iProduct);
	udev->manufacturer = usb_cache_string(udev,
					      udev->descriptor.iManufacturer);
	udev->serial = usb_cache_string(udev, udev->descriptor.iSerialNumber);

	err = usb_enumerate_device_otg(udev);
	if (err < 0)
		return err;

	if (IS_ENABLED(CONFIG_USB_OTG_PRODUCTLIST) && hcd->tpl_support &&
		!is_targeted(udev)) {
		/* Maybe it can talk to us, though we can't talk to it.
		 * (Includes HNP test device.)
		 */
		if (IS_ENABLED(CONFIG_USB_OTG) && (udev->bus->b_hnp_enable
			|| udev->bus->is_b_host)) {
			err = usb_port_suspend(udev, PMSG_AUTO_SUSPEND);
			if (err < 0)
				dev_dbg(&udev->dev, "HNP fail, %d\n", err);
		}
		return -ENOTSUPP;
	}

	usb_detect_interface_quirks(udev);

	return 0;
}

static void set_usb_port_removable(struct usb_device *udev)
{
	struct usb_device *hdev = udev->parent;
	struct usb_hub *hub;
	u8 port = udev->portnum;
	u16 wHubCharacteristics;
	bool removable = true;

	if (!hdev)
		return;

	hub = usb_hub_to_struct_hub(udev->parent);

	/*
	 * If the platform firmware has provided information about a port,
	 * use that to determine whether it's removable.
	 */
	switch (hub->ports[udev->portnum - 1]->connect_type) {
	case USB_PORT_CONNECT_TYPE_HOT_PLUG:
		udev->removable = USB_DEVICE_REMOVABLE;
		return;
	case USB_PORT_CONNECT_TYPE_HARD_WIRED:
	case USB_PORT_NOT_USED:
		udev->removable = USB_DEVICE_FIXED;
		return;
	default:
		break;
	}

	/*
	 * Otherwise, check whether the hub knows whether a port is removable
	 * or not
	 */
	wHubCharacteristics = le16_to_cpu(hub->descriptor->wHubCharacteristics);

	if (!(wHubCharacteristics & HUB_CHAR_COMPOUND))
		return;

	if (hub_is_superspeed(hdev)) {
		if (le16_to_cpu(hub->descriptor->u.ss.DeviceRemovable)
				& (1 << port))
			removable = false;
	} else {
		if (hub->descriptor->u.hs.DeviceRemovable[port / 8] & (1 << (port % 8)))
			removable = false;
	}

	if (removable)
		udev->removable = USB_DEVICE_REMOVABLE;
	else
		udev->removable = USB_DEVICE_FIXED;

}

/**
 * usb_new_device - perform initial device setup (usbcore-internal)
 * @udev: newly addressed device (in ADDRESS state)
 *
 * This is called with devices which have been detected but not fully
 * enumerated.  The device descriptor is available, but not descriptors
 * for any device configuration.  The caller must have locked either
 * the parent hub (if udev is a normal device) or else the
 * usb_bus_idr_lock (if udev is a root hub).  The parent's pointer to
 * udev has already been installed, but udev is not yet visible through
 * sysfs or other filesystem code.
 *
 * This call is synchronous, and may not be used in an interrupt context.
 *
 * Only the hub driver or root-hub registrar should ever call this.
 *
 * Return: Whether the device is configured properly or not. Zero if the
 * interface was registered with the driver core; else a negative errno
 * value.
 *
 */
int usb_new_device(struct usb_device *udev)
{
	int err;

	if (udev->parent) {
		/* Initialize non-root-hub device wakeup to disabled;
		 * device (un)configuration controls wakeup capable
		 * sysfs power/wakeup controls wakeup enabled/disabled
		 */
		device_init_wakeup(&udev->dev, 0);
	}

	/* Tell the runtime-PM framework the device is active */
	pm_runtime_set_active(&udev->dev);
	pm_runtime_get_noresume(&udev->dev);
	pm_runtime_use_autosuspend(&udev->dev);
	pm_runtime_enable(&udev->dev);

	/* By default, forbid autosuspend for all devices.  It will be
	 * allowed for hubs during binding.
	 */
	usb_disable_autosuspend(udev);

	err = usb_enumerate_device(udev);	/* Read descriptors */
	if (err < 0)
		goto fail;
	dev_dbg(&udev->dev, "udev %d, busnum %d, minor = %d\n",
			udev->devnum, udev->bus->busnum,
			(((udev->bus->busnum-1) * 128) + (udev->devnum-1)));
	/* export the usbdev device-node for libusb */
	udev->dev.devt = MKDEV(USB_DEVICE_MAJOR,
			(((udev->bus->busnum-1) * 128) + (udev->devnum-1)));

	/* Tell the world! */
	announce_device(udev);

	if (udev->serial)
		add_device_randomness(udev->serial, strlen(udev->serial));
	if (udev->product)
		add_device_randomness(udev->product, strlen(udev->product));
	if (udev->manufacturer)
		add_device_randomness(udev->manufacturer,
				      strlen(udev->manufacturer));

	device_enable_async_suspend(&udev->dev);

	/* check whether the hub or firmware marks this port as non-removable */
	if (udev->parent)
		set_usb_port_removable(udev);

	/* Register the device.  The device driver is responsible
	 * for configuring the device and invoking the add-device
	 * notifier chain (used by usbfs and possibly others).
	 */
	err = device_add(&udev->dev);
	if (err) {
		dev_err(&udev->dev, "can't device_add, error %d\n", err);
		goto fail;
	}

	/* Create link files between child device and usb port device. */
	if (udev->parent) {
		struct usb_hub *hub = usb_hub_to_struct_hub(udev->parent);
		int port1 = udev->portnum;
		struct usb_port	*port_dev = hub->ports[port1 - 1];

		err = sysfs_create_link(&udev->dev.kobj,
				&port_dev->dev.kobj, "port");
		if (err)
			goto fail;

		err = sysfs_create_link(&port_dev->dev.kobj,
				&udev->dev.kobj, "device");
		if (err) {
			sysfs_remove_link(&udev->dev.kobj, "port");
			goto fail;
		}

		if (!test_and_set_bit(port1, hub->child_usage_bits))
			pm_runtime_get_sync(&port_dev->dev);
	}

	(void) usb_create_ep_devs(&udev->dev, &udev->ep0, udev);
	usb_mark_last_busy(udev);
	pm_runtime_put_sync_autosuspend(&udev->dev);
	return err;

fail:
	usb_set_device_state(udev, USB_STATE_NOTATTACHED);
	pm_runtime_disable(&udev->dev);
	pm_runtime_set_suspended(&udev->dev);
	return err;
}


/**
 * usb_deauthorize_device - deauthorize a device (usbcore-internal)
 * @usb_dev: USB device
 *
 * Move the USB device to a very basic state where interfaces are disabled
 * and the device is in fact unconfigured and unusable.
 *
 * We share a lock (that we have) with device_del(), so we need to
 * defer its call.
 *
 * Return: 0.
 */
int usb_deauthorize_device(struct usb_device *usb_dev)
{
	usb_lock_device(usb_dev);
	if (usb_dev->authorized == 0)
		goto out_unauthorized;

	usb_dev->authorized = 0;
	usb_set_configuration(usb_dev, -1);

out_unauthorized:
	usb_unlock_device(usb_dev);
	return 0;
}


int usb_authorize_device(struct usb_device *usb_dev)
{
	int result = 0, c;

	usb_lock_device(usb_dev);
	if (usb_dev->authorized == 1)
		goto out_authorized;

	result = usb_autoresume_device(usb_dev);
	if (result < 0) {
		dev_err(&usb_dev->dev,
			"can't autoresume for authorization: %d\n", result);
		goto error_autoresume;
	}

	if (usb_dev->wusb) {
		result = usb_get_device_descriptor(usb_dev, sizeof(usb_dev->descriptor));
		if (result < 0) {
			dev_err(&usb_dev->dev, "can't re-read device descriptor for "
				"authorization: %d\n", result);
			goto error_device_descriptor;
		}
	}

	usb_dev->authorized = 1;
	/* Choose and set the configuration.  This registers the interfaces
	 * with the driver core and lets interface drivers bind to them.
	 */
	c = usb_choose_configuration(usb_dev);
	if (c >= 0) {
		result = usb_set_configuration(usb_dev, c);
		if (result) {
			dev_err(&usb_dev->dev,
				"can't set config #%d, error %d\n", c, result);
			/* This need not be fatal.  The user can try to
			 * set other configurations. */
		}
	}
	dev_info(&usb_dev->dev, "authorized to connect\n");

error_device_descriptor:
	usb_autosuspend_device(usb_dev);
error_autoresume:
out_authorized:
	usb_unlock_device(usb_dev);	/* complements locktree */
	return result;
}

/*
 * Return 1 if port speed is SuperSpeedPlus, 0 otherwise
 * check it from the link protocol field of the current speed ID attribute.
 * current speed ID is got from ext port status request. Sublink speed attribute
 * table is returned with the hub BOS SSP device capability descriptor
 */
static int port_speed_is_ssp(struct usb_device *hdev, int speed_id)
{
	int ssa_count;
	u32 ss_attr;
	int i;
	struct usb_ssp_cap_descriptor *ssp_cap = hdev->bos->ssp_cap;

	if (!ssp_cap)
		return 0;

	ssa_count = le32_to_cpu(ssp_cap->bmAttributes) &
