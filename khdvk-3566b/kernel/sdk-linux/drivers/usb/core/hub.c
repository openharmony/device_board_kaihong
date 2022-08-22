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
