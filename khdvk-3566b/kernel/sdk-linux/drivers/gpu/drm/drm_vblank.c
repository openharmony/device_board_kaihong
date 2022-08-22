/*
 * drm_irq.c IRQ and vblank support
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 * \author Gareth Hughes <gareth@valinux.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/export.h>
#include <linux/kthread.h>
#include <linux/moduleparam.h>

#include <drm/drm_crtc.h>
#include <drm/drm_drv.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_managed.h>
#include <drm/drm_modeset_helper_vtables.h>
#include <drm/drm_print.h>
#include <drm/drm_vblank.h>

#include "drm_internal.h"
#include "drm_trace.h"

/**
 * DOC: vblank handling
 *
 * From the computer's perspective, every time the monitor displays
 * a new frame the scanout engine has "scanned out" the display image
 * from top to bottom, one row of pixels at a time. The current row
 * of pixels is referred to as the current scanline.
 *
 * In addition to the display's visible area, there's usually a couple of
 * extra scanlines which aren't actually displayed on the screen.
 * These extra scanlines don't contain image data and are occasionally used
 * for features like audio and infoframes. The region made up of these
 * scanlines is referred to as the vertical blanking region, or vblank for
 * short.
 *
 * For historical reference, the vertical blanking period was designed to
 * give the electron gun (on CRTs) enough time to move back to the top of
 * the screen to start scanning out the next frame. Similar for horizontal
 * blanking periods. They were designed to give the electron gun enough
 * time to move back to the other side of the screen to start scanning the
 * next scanline.
 *
 * ::
 *
 *
 *    physical →   ⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽
 *    top of      |                                        |
 *    display     |                                        |
 *                |               New frame                |
 *                |                                        |
 *                |↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓|
 *                |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~| ← Scanline,
 *                |↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓|   updates the
 *                |                                        |   frame as it
 *                |                                        |   travels down
 *                |                                        |   ("sacn out")
 *                |               Old frame                |
 *                |                                        |
 *                |                                        |
 *                |                                        |
 *                |                                        |   physical
 *                |                                        |   bottom of
 *    vertical    |⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽| ← display
 *    blanking    ┆xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx┆
 *    region   →  ┆xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx┆
 *                ┆xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx┆
 *    start of →   ⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽
 *    new frame
 *
 * "Physical top of display" is the reference point for the high-precision/
 * corrected timestamp.
 *
 * On a lot of display hardware, programming needs to take effect during the
 * vertical blanking period so that settings like gamma, the image buffer
 * buffer to be scanned out, etc. can safely be changed without showing
 * any visual artifacts on the screen. In some unforgiving hardware, some of
 * this programming has to both start and end in the same vblank. To help
 * with the timing of the hardware programming, an interrupt is usually
 * available to notify the driver when it can start the updating of registers.
 * The interrupt is in this context named the vblank interrupt.
 *
 * The vblank interrupt may be fired at different points depending on the
 * hardware. Some hardware implementations will fire the interrupt when the
 * new frame start, other implementations will fire the interrupt at different
 * points in time.
 *
 * Vertical blanking plays a major role in graphics rendering. To achieve
 * tear-free display, users must synchronize page flips and/or rendering to
 * vertical blanking. The DRM API offers ioctls to perform page flips
 * synchronized to vertical blanking and wait for vertical blanking.
 *
 * The DRM core handles most of the vertical blanking management logic, which
 * involves filtering out spurious interrupts, keeping race-free blanking
 * counters, coping with counter wrap-around and resets and keeping use counts.
 * It relies on the driver to generate vertical blanking interrupts and
 * optionally provide a hardware vertical blanking counter.
 *
 * Drivers must initialize the vertical blanking handling core with a call to
 * drm_vblank_init(). Minimally, a driver needs to implement
 * &drm_crtc_funcs.enable_vblank and &drm_crtc_funcs.disable_vblank plus call
 * drm_crtc_handle_vblank() in its vblank interrupt handler for working vblank
 * support.
 *
 * Vertical blanking interrupts can be enabled by the DRM core or by drivers
 * themselves (for instance to handle page flipping operations).  The DRM core
 * maintains a vertical blanking use count to ensure that the interrupts are not
 * disabled while a user still needs them. To increment the use count, drivers
 * call drm_crtc_vblank_get() and release the vblank reference again with
 * drm_crtc_vblank_put(). In between these two calls vblank interrupts are
 * guaranteed to be enabled.
 *
 * On many hardware disabling the vblank interrupt cannot be done in a race-free
 * manner, see &drm_driver.vblank_disable_immediate and
 * &drm_driver.max_vblank_count. In that case the vblank core only disables the
 * vblanks after a timer has expired, which can be configured through the
 * ``vblankoffdelay`` module parameter.
 *
 * Drivers for hardware without support for vertical-blanking interrupts
 * must not call drm_vblank_init(). For such drivers, atomic helpers will
 * automatically generate fake vblank events as part of the display update.
 * This functionality also can be controlled by the driver by enabling and
 * disabling struct drm_crtc_state.no_vblank.
 */

/* Retry timestamp calculation up to 3 times to satisfy
 * drm_timestamp_precision before giving up.
 */
#define DRM_TIMESTAMP_MAXRETRIES 3

/* Threshold in nanoseconds for detection of redundant
 * vblank irq in drm_handle_vblank(). 1 msec should be ok.
 */
#define DRM_REDUNDANT_VBLIRQ_THRESH_NS 1000000

static bool
drm_get_last_vbltimestamp(struct drm_device *dev, unsigned int pipe,
			  ktime_t *tvblank, bool in_vblank_irq);

static unsigned int drm_timestamp_precision = 20;  /* Default to 20 usecs. */

static int drm_vblank_offdelay = 5000;    /* Default to 5000 msecs. */

module_param_named(vblankoffdelay, drm_vblank_offdelay, int, 0600);
module_param_named(timestamp_precision_usec, drm_timestamp_precision, int, 0600);
MODULE_PARM_DESC(vblankoffdelay, "Delay until vblank irq auto-disable [msecs] (0: never disable, <0: disable immediately)");
MODULE_PARM_DESC(timestamp_precision_usec, "Max. error on timestamps [usecs]");

static void store_vblank(struct drm_device *dev, unsigned int pipe,
			 u32 vblank_count_inc,
			 ktime_t t_vblank, u32 last)
{
	struct drm_vblank_crtc *vblank = &dev->vblank[pipe];

	assert_spin_locked(&dev->vblank_time_lock);

	vblank->last = last;

	write_seqlock(&vblank->seqlock);
	vblank->time = t_vblank;
	atomic64_add(vblank_count_inc, &vblank->count);
	write_sequnlock(&vblank->seqlock);
}

static u32 drm_max_vblank_count(struct drm_device *dev, unsigned int pipe)
{
	struct drm_vblank_crtc *vblank = &dev->vblank[pipe];

	return vblank->max_vblank_count ?: dev->max_vblank_count;
}

/*
 * "No hw counter" fallback implementation of .get_vblank_counter() hook,
 * if there is no useable hardware frame counter available.
 */
static u32 drm_vblank_no_hw_counter(struct drm_device *dev, unsigned int pipe)
{
	drm_WARN_ON_ONCE(dev, drm_max_vblank_count(dev, pipe) != 0);
	return 0;
}

static u32 __get_vblank_counter(struct drm_device *dev, unsigned int pipe)
{
	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
		struct drm_crtc *crtc = drm_crtc_from_index(dev, pipe);

		if (drm_WARN_ON(dev, !crtc))
			return 0;

		if (crtc->funcs->get_vblank_counter)
			return crtc->funcs->get_vblank_counter(crtc);
	} else if (dev->driver->get_vblank_counter) {
		return dev->driver->get_vblank_counter(dev, pipe);
	}

	return drm_vblank_no_hw_counter(dev, pipe);
}

/*
 * Reset the stored timestamp for the current vblank count to correspond
 * to the last vblank occurred.
 *
 * Only to be called from drm_crtc_vblank_on().
 *
 * Note: caller must hold &drm_device.vbl_lock since this reads & writes
 * device vblank fields.
 */
static void drm_reset_vblank_timestamp(struct drm_device *dev, unsigned int pipe)
{
	u32 cur_vblank;
	bool rc;
	ktime_t t_vblank;
	int count = DRM_TIMESTAMP_MAXRETRIES;

	spin_lock(&dev->vblank_time_lock);

	/*
	 * sample the current counter to avoid random jumps
	 * when drm_vblank_enable() applies the diff
	 */
	do {
		cur_vblank = __get_vblank_counter(dev, pipe);
		rc = drm_get_last_vbltimestamp(dev, pipe, &t_vblank, false);
	} while (cur_vblank != __get_vblank_counter(dev, pipe) && --count > 0);

	/*
	 * Only reinitialize corresponding vblank timestamp if high-precision query
	 * available and didn't fail. Otherwise reinitialize delayed at next vblank
	 * interrupt and assign 0 for now, to mark the vblanktimestamp as invalid.
	 */
	if (!rc)
		t_vblank = 0;

	/*
	 * +1 to make sure user will never see the same
	 * vblank counter value before and after a modeset
	 */
	store_vblank(dev, pipe, 1, t_vblank, cur_vblank);

	spin_unlock(&dev->vblank_time_lock);
}

/*
 * Call back into the driver to update the appropriate vblank counter
 * (specified by @pipe).  Deal with wraparound, if it occurred, and
 * update the last read value so we can deal with wraparound on the next
 * call if necessary.
 *
 * Only necessary when going from off->on, to account for frames we
 * didn't get an interrupt for.
 *
 * Note: caller must hold &drm_device.vbl_lock since this reads & writes
 * device vblank fields.
 */
static void drm_update_vblank_count(struct drm_device *dev, unsigned int pipe,
				    bool in_vblank_irq)
{
	struct drm_vblank_crtc *vblank = &dev->vblank[pipe];
	u32 cur_vblank, diff;
	bool rc;
	ktime_t t_vblank;
	int count = DRM_TIMESTAMP_MAXRETRIES;
	int framedur_ns = vblank->framedur_ns;
	u32 max_vblank_count = drm_max_vblank_count(dev, pipe);

	/*
	 * Interrupts were disabled prior to this call, so deal with counter
	 * wrap if needed.
	 * NOTE!  It's possible we lost a full dev->max_vblank_count + 1 events
	 * here if the register is small or we had vblank interrupts off for
	 * a long time.
	 *
	 * We repeat the hardware vblank counter & timestamp query until
	 * we get consistent results. This to prevent races between gpu
	 * updating its hardware counter while we are retrieving the
	 * corresponding vblank timestamp.
	 */
	do {
		cur_vblank = __get_vblank_counter(dev, pipe);
		rc = drm_get_last_vbltimestamp(dev, pipe, &t_vblank, in_vblank_irq);
	} while (cur_vblank != __get_vblank_counter(dev, pipe) && --count > 0);

	if (max_vblank_count) {
		/* trust the hw counter when it's around */
		diff = (cur_vblank - vblank->last) & max_vblank_count;
	} else if (rc && framedur_ns) {
		u64 diff_ns = ktime_to_ns(ktime_sub(t_vblank, vblank->time));

		/*
		 * Figure out how many vblanks we've missed based
		 * on the difference in the timestamps and the
		 * frame/field duration.
		 */

		drm_dbg_vbl(dev, "crtc %u: Calculating number of vblanks."
			    " diff_ns = %lld, framedur_ns = %d)\n",
			    pipe, (long long)diff_ns, framedur_ns);

		diff = DIV_ROUND_CLOSEST_ULL(diff_ns, framedur_ns);

		if (diff == 0 && in_vblank_irq)
			drm_dbg_vbl(dev, "crtc %u: Redundant vblirq ignored\n",
				    pipe);
	} else {
		/* some kind of default for drivers w/o accurate vbl timestamping */
		diff = in_vblank_irq ? 1 : 0;
	}

	/*
	 * Within a drm_vblank_pre_modeset - drm_vblank_post_modeset
	 * interval? If so then vblank irqs keep running and it will likely
	 * happen that the hardware vblank counter is not trustworthy as it
	 * might reset at some point in that interval and vblank timestamps
	 * are not trustworthy either in that interval. Iow. this can result
	 * in a bogus diff >> 1 which must be avoided as it would cause
	 * random large forward jumps of the software vblank counter.
	 */
	if (diff > 1 && (vblank->inmodeset & 0x2)) {
		drm_dbg_vbl(dev,
			    "clamping vblank bump to 1 on crtc %u: diffr=%u"
			    " due to pre-modeset.\n", pipe, diff);
		diff = 1;
	}

	drm_dbg_vbl(dev, "updating vblank count on crtc %u:"
		    " current=%llu, diff=%u, hw=%u hw_last=%u\n",
		    pipe, (unsigned long long)atomic64_read(&vblank->count),
		    diff, cur_vblank, vblank->last);

	if (diff == 0) {
		drm_WARN_ON_ONCE(dev, cur_vblank != vblank->last);
		return;
	}

	/*
	 * Only reinitialize corresponding vblank timestamp if high-precision query
	 * available and didn't fail, or we were called from the vblank interrupt.
	 * Otherwise reinitialize delayed at next vblank interrupt and assign 0
	 * for now, to mark the vblanktimestamp as invalid.
	 */
	if (!rc && !in_vblank_irq)
		t_vblank = 0;

	store_vblank(dev, pipe, diff, t_vblank, cur_vblank);
}

u64 drm_vblank_count(struct drm_device *dev, unsigned int pipe)
{
	struct drm_vblank_crtc *vblank = &dev->vblank[pipe];
	u64 count;

	if (drm_WARN_ON(dev, pipe >= dev->num_crtcs))
		return 0;

	count = atomic64_read(&vblank->count);

	/*
	 * This read barrier corresponds to the implicit write barrier of the
	 * write seqlock in store_vblank(). Note that this is the only place
	 * where we need an explicit barrier, since all other access goes
	 * through drm_vblank_count_and_time(), which already has the required
	 * read barrier curtesy of the read seqlock.
	 */
	smp_rmb();

	return count;
}

/**
 * drm_crtc_accurate_vblank_count - retrieve the master vblank counter
 * @crtc: which counter to retrieve
 *
 * This function is similar to drm_crtc_vblank_count() but this function
 * interpolates to handle a race with vblank interrupts using the high precision
 * timestamping support.
 *
 * This is mostly useful for hardware that can obtain the scanout position, but
 * doesn't have a hardware frame counter.
 */
u64 drm_crtc_accurate_vblank_count(struct drm_crtc *crtc)
{
	struct drm_device *dev = crtc->dev;
	unsigned int pipe = drm_crtc_index(crtc);
	u64 vblank;
	unsigned long flags;

	drm_WARN_ONCE(dev, drm_debug_enabled(DRM_UT_VBL) &&
		      !crtc->funcs->get_vblank_timestamp,
		      "This function requires support for accurate vblank timestamps.");

	spin_lock_irqsave(&dev->vblank_time_lock, flags);

	drm_update_vblank_count(dev, pipe, false);
	vblank = drm_vblank_count(dev, pipe);

	spin_unlock_irqrestore(&dev->vblank_time_lock, flags);

	return vblank;
}
EXPORT_SYMBOL(drm_crtc_accurate_vblank_count);

static void __disable_vblank(struct drm_device *dev, unsigned int pipe)
{
	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
		struct drm_crtc *crtc = drm_crtc_from_index(dev, pipe);

		if (drm_WARN_ON(dev, !crtc))
			return;

		if (crtc->funcs->disable_vblank)
			crtc->funcs->disable_vblank(crtc);
	} else {
		dev->driver->disable_vblank(dev, pipe);
	}
}

/*
 * Disable vblank irq's on crtc, make sure that last vblank count
 * of hardware and corresponding consistent software vblank counter
 * are preserved, even if there are any spurious vblank irq's after
 * disable.
 */
void drm_vblank_disable_and_save(struct drm_device *dev, unsigned int pipe)
{
	struct drm_vblank_crtc *vblank = &dev->vblank[pipe];
	unsigned long irqflags;

	assert_spin_locked(&dev->vbl_lock);

	/* Prevent vblank irq processing while disabling vblank irqs,
	 * so no updates of timestamps or count can happen after we've
	 * disabled. Needed to prevent races in case of delayed irq's.
	 */
	spin_lock_irqsave(&dev->vblank_time_lock, irqflags);

	/*
	 * Update vblank count and disable vblank interrupts only if the
	 * interrupts were enabled. This avoids calling the ->disable_vblank()
	 * operation in atomic context with the hardware potentially runtime
	 * suspended.
	 */
	if (!vblank->enabled)
		goto out;

	/*
	 * Update the count and timestamp to maintain the
	 * appearance that the counter has been ticking all along until
	 * this time. This makes the count account for the entire time
	 * between drm_crtc_vblank_on() and drm_crtc_vblank_off().
	 */
	drm_update_vblank_count(dev, pipe, false);
	__disable_vblank(dev, pipe);
	vblank->enabled = false;

out:
	spin_unlock_irqrestore(&dev->vblank_time_lock, irqflags);
}

static void vblank_disable_fn(struct timer_list *t)
{
	struct drm_vblank_crtc *vblank = from_timer(vblank, t, disable_timer);
	struct drm_device *dev = vblank->dev;
	unsigned int pipe = vblank->pipe;
	unsigned long irqflags;

	spin_lock_irqsave(&dev->vbl_lock, irqflags);
	if (atomic_read(&vblank->refcount) == 0 && vblank->enabled) {
		drm_dbg_core(dev, "disabling vblank on crtc %u\n", pipe);
		drm_vblank_disable_and_save(dev, pipe);
	}
	spin_unlock_irqrestore(&dev->vbl_lock, irqflags);
}

static void drm_vblank_init_release(struct drm_device *dev, void *ptr)
{
	struct drm_vblank_crtc *vblank = ptr;

	drm_WARN_ON(dev, READ_ONCE(vblank->enabled) &&
		    drm_core_check_feature(dev, DRIVER_MODESET));

	drm_vblank_destroy_worker(vblank);
	del_timer_sync(&vblank->disable_timer);
}

/**
 * drm_vblank_init - initialize vblank support
 * @dev: DRM device
 * @num_crtcs: number of CRTCs supported by @dev
 *
 * This function initializes vblank support for @num_crtcs display pipelines.
 * Cleanup is handled automatically through a cleanup function added with
 * drmm_add_action_or_reset().
 *
 * Returns:
 * Zero on success or a negative error code on failure.
 */
int drm_vblank_init(struct drm_device *dev, unsigned int num_crtcs)
{
	int ret;
	unsigned int i;

	spin_lock_init(&dev->vbl_lock);
	spin_lock_init(&dev->vblank_time_lock);

	dev->vblank = drmm_kcalloc(dev, num_crtcs, sizeof(*dev->vblank), GFP_KERNEL);
	if (!dev->vblank)
		return -ENOMEM;

	dev->num_crtcs = num_crtcs;

	for (i = 0; i < num_crtcs; i++) {
		struct drm_vblank_crtc *vblank = &dev->vblank[i];

		vblank->dev = dev;
		vblank->pipe = i;
		init_waitqueue_head(&vblank->queue);
		timer_setup(&vblank->disable_timer, vblank_disable_fn, 0);
		seqlock_init(&vblank->seqlock);

		ret = drmm_add_action_or_reset(dev, drm_vblank_init_release,
					       vblank);
		if (ret)
			return ret;

		ret = drm_vblank_worker_init(vblank);
		if (ret)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL(drm_vblank_init);

/**
 * drm_dev_has_vblank - test if vblanking has been initialized for
 *                      a device
 * @dev: the device
 *
 * Drivers may call this function to test if vblank support is
 * initialized for a device. For most hardware this means that vblanking
 * can also be enabled.
 *
 * Atomic helpers use this function to initialize
 * &drm_crtc_state.no_vblank. See also drm_atomic_helper_check_modeset().
 *
 * Returns:
 * True if vblanking has been initialized for the given device, false
 * otherwise.
 */
bool drm_dev_has_vblank(const struct drm_device *dev)
{
	return dev->num_crtcs != 0;
}
EXPORT_SYMBOL(drm_dev_has_vblank);

/**
 * drm_crtc_vblank_waitqueue - get vblank waitqueue for the CRTC
 * @crtc: which CRTC's vblank waitqueue to retrieve
 *
 * This function returns a pointer to the vblank waitqueue for the CRTC.
 * Drivers can use this to implement vblank waits using wait_event() and related
 * functions.
 */
wait_queue_head_t *drm_crtc_vblank_waitqueue(struct drm_crtc *crtc)
{
	return &crtc->dev->vblank[drm_crtc_index(crtc)].queue;
}
EXPORT_SYMBOL(drm_crtc_vblank_waitqueue);


/**
 * drm_calc_timestamping_constants - calculate vblank timestamp constants
 * @crtc: drm_crtc whose timestamp constants should be updated.
 * @mode: display mode containing the scanout timings
 *
 * Calculate and store various constants which are later needed by vblank and
 * swap-completion timestamping, e.g, by
 * drm_crtc_vblank_helper_get_vblank_timestamp(). They are derived from
 * CRTC's true scanout timing, so they take things like panel scaling or
 * other adjustments into account.
 */
void drm_calc_timestamping_constants(struct drm_crtc *crtc,
				     const struct drm_display_mode *mode)
{
	struct drm_device *dev = crtc->dev;
	unsigned int pipe = drm_crtc_index(crtc);
	struct drm_vblank_crtc *vblank = &dev->vblank[pipe];
	int linedur_ns = 0, framedur_ns = 0;
	int dotclock = mode->crtc_clock;

	if (!drm_dev_has_vblank(dev))
		return;

	if (drm_WARN_ON(dev, pipe >= dev->num_crtcs))
		return;

	/* Valid dotclock? */
	if (dotclock > 0) {
		int frame_size = mode->crtc_htotal * mode->crtc_vtotal;

		/*
		 * Convert scanline length in pixels and video
		 * dot clock to line duration and frame duration
		 * in nanoseconds:
		 */
		linedur_ns  = div_u64((u64) mode->crtc_htotal * 1000000, dotclock);
		framedur_ns = div_u64((u64) frame_size * 1000000, dotclock);

		/*
		 * Fields of interlaced scanout modes are only half a frame duration.
		 */
		if (mode->flags & DRM_MODE_FLAG_INTERLACE)
			framedur_ns /= 2;
	} else {
		drm_err(dev, "crtc %u: Can't calculate constants, dotclock = 0!\n",
			crtc->base.id);
	}

	vblank->linedur_ns  = linedur_ns;
	vblank->framedur_ns = framedur_ns;
	vblank->hwmode = *mode;

	drm_dbg_core(dev,
		     "crtc %u: hwmode: htotal %d, vtotal %d, vdisplay %d\n",
		     crtc->base.id, mode->crtc_htotal,
		     mode->crtc_vtotal, mode->crtc_vdisplay);
	drm_dbg_core(dev, "crtc %u: clock %d kHz framedur %d linedur %d\n",
		     crtc->base.id, dotclock, framedur_ns, linedur_ns);
}
EXPORT_SYMBOL(drm_calc_timestamping_constants);

/**
 * drm_crtc_vblank_helper_get_vblank_timestamp_internal - precise vblank
 *                                                        timestamp helper
 * @crtc: CRTC whose vblank timestamp to retrieve
 * @max_error: Desired maximum allowable error in timestamps (nanosecs)
 *             On return contains true maximum error of timestamp
 * @vblank_time: Pointer to time which should receive the timestamp
 * @in_vblank_irq:
 *     True when called from drm_crtc_handle_vblank().  Some drivers
 *     need to apply some workarounds for gpu-specific vblank irq quirks
 *     if flag is set.
 * @get_scanout_position:
 *     Callback function to retrieve the scanout position. See
 *     @struct drm_crtc_helper_funcs.get_scanout_position.
 *
 * Implements calculation of exact vblank timestamps from given drm_display_mode
 * timings and current video scanout position of a CRTC.
 *
 * The current implementation only handles standard video modes. For double scan
 * and interlaced modes the driver is supposed to adjust the hardware mode
 * (taken from &drm_crtc_state.adjusted mode for atomic modeset drivers) to
 * match the scanout position reported.
 *
 * Note that atomic drivers must call drm_calc_timestamping_constants() before
 * enabling a CRTC. The atomic helpers already take care of that in
 * drm_atomic_helper_calc_timestamping_constants().
 *
 * Returns:
 *
 * Returns true on success, and false on failure, i.e. when no accurate
 * timestamp could be acquired.
 */
bool
drm_crtc_vblank_helper_get_vblank_timestamp_internal(
	struct drm_crtc *crtc, int *max_error, ktime_t *vblank_time,
	bool in_vblank_irq,
	drm_vblank_get_scanout_position_func get_scanout_position)
{
	struct drm_device *dev = crtc->dev;
	unsigned int pipe = crtc->index;
	struct drm_vblank_crtc *vblank = &dev->vblank[pipe];
	struct timespec64 ts_etime, ts_vblank_time;
	ktime_t stime, etime;
	bool vbl_status;
	const struct drm_display_mode *mode;
	int vpos, hpos, i;
	int delta_ns, duration_ns;

	if (pipe >= dev->num_crtcs) {
		drm_err(dev, "Invalid crtc %u\n", pipe);
		return false;
	}

	/* Scanout position query not supported? Should not happen. */
	if (!get_scanout_position) {
		drm_err(dev, "Called from CRTC w/o get_scanout_position()!?\n");
		return false;
	}

	if (drm_drv_uses_atomic_modeset(dev))
		mode = &vblank->hwmode;
	else
		mode = &crtc->hwmode;

	/* If mode timing undefined, just return as no-op:
	 * Happens during initial modesetting of a crtc.
	 */
	if (mode->crtc_clock == 0) {
		drm_dbg_core(dev, "crtc %u: Noop due to uninitialized mode.\n",
			     pipe);
		drm_WARN_ON_ONCE(dev, drm_drv_uses_atomic_modeset(dev));
		return false;
	}

	/* Get current scanout position with system timestamp.
	 * Repeat query up to DRM_TIMESTAMP_MAXRETRIES times
	 * if single query takes longer than max_error nanoseconds.
	 *
	 * This guarantees a tight bound on maximum error if
	 * code gets preempted or delayed for some reason.
	 */
	for (i = 0; i < DRM_TIMESTAMP_MAXRETRIES; i++) {
		/*
		 * Get vertical and horizontal scanout position vpos, hpos,
		 * and bounding timestamps stime, etime, pre/post query.
		 */
		vbl_status = get_scanout_position(crtc, in_vblank_irq,
						  &vpos, &hpos,
						  &stime, &etime,
						  mode);

		/* Return as no-op if scanout query unsupported or failed. */
		if (!vbl_status) {
			drm_dbg_core(dev,
				     "crtc %u : scanoutpos query failed.\n",
				     pipe);
			return false;
		}

		/* Compute uncertainty in timestamp of scanout position query. */
		duration_ns = ktime_to_ns(etime) - ktime_to_ns(stime);

		/* Accept result with <  max_error nsecs timing uncertainty. */
		if (duration_ns <= *max_error)
			break;
	}

	/* Noisy system timing? */
	if (i == DRM_TIMESTAMP_MAXRETRIES) {
		drm_dbg_core(dev,
			     "crtc %u: Noisy timestamp %d us > %d us [%d reps].\n",
			     pipe, duration_ns / 1000, *max_error / 1000, i);
	}

	/* Return upper bound of timestamp precision error. */
	*max_error = duration_ns;

	/* Convert scanout position into elapsed time at raw_time query
	 * since start of scanout at first display scanline. delta_ns
	 * can be negative if start of scanout hasn't happened yet.
	 */
	delta_ns = div_s64(1000000LL * (vpos * mode->crtc_htotal + hpos),
			   mode->crtc_clock);

	/* Subtract time delta from raw timestamp to get final
	 * vblank_time timestamp for end of vblank.
	 */
	*vblank_time = ktime_sub_ns(etime, delta_ns);

	if (!drm_debug_enabled(DRM_UT_VBL))
		return true;

	ts_etime = ktime_to_timespec64(etime);
	ts_vblank_time = ktime_to_timespec64(*vblank_time);

	drm_dbg_vbl(dev,
		    "crtc %u : v p(%d,%d)@ %lld.%06ld -> %lld.%06ld [e %d us, %d rep]\n",
		    pipe, hpos, vpos,
		    (u64)ts_etime.tv_sec, ts_etime.tv_nsec / 1000,
		    (u64)ts_vblank_time.tv_sec, ts_vblank_time.tv_nsec / 1000,
		    duration_ns / 1000, i);

	return true;
}
EXPORT_SYMBOL(drm_crtc_vblank_helper_get_vblank_timestamp_internal);

/**
 * drm_crtc_vblank_helper_get_vblank_timestamp - precise vblank timestamp
 *                                               helper
 * @crtc: CRTC whose vblank timestamp to retrieve
 * @max_error: Desired maximum allowable error in timestamps (nanosecs)
 *             On return contains true maximum error of timestamp
 * @vblank_time: Pointer to time which should receive the timestamp
 * @in_vblank_irq:
 *     True when called from drm_crtc_handle_vblank().  Some drivers
 *     need to apply some workarounds for gpu-specific vblank irq quirks
 *     if flag is set.
 *
 * Implements calculation of exact vblank timestamps from given drm_display_mode
 * timings and current video scanout position of a CRTC. This can be directly
 * used as the &drm_crtc_funcs.get_vblank_timestamp implementation of a kms
 * driver if &drm_crtc_helper_funcs.get_scanout_position is implemented.
 *
 * The current implementation only handles standard video modes. For double scan
 * and interlaced modes the driver is supposed to adjust the hardware mode
 * (taken from &drm_crtc_state.adjusted mode for atomic modeset drivers) to
 * match the scanout position reported.
 *
 * Note that atomic drivers must call drm_calc_timestamping_constants() before
 * enabling a CRTC. The atomic helpers already take care of that in
 * drm_atomic_helper_calc_timestamping_constants().
 *
 * Returns:
 *
 * Returns true on success, and false on failure, i.e. when no accurate
 * timestamp could be acquired.
 */
bool drm_crtc_vblank_helper_get_vblank_timestamp(struct drm_crtc *crtc,
						 int *max_error,
						 ktime_t *vblank_time,
						 bool in_vblank_irq)
{
	return drm_crtc_vblank_helper_get_vblank_timestamp_internal(
		crtc, max_error, vblank_time, in_vblank_irq,
		crtc->helper_private->get_scanout_position);
}
EXPORT_SYMBOL(drm_crtc_vblank_helper_get_vblank_timestamp);

/**
 * drm_get_last_vbltimestamp - retrieve raw timestamp for the most recent
 *                             vblank interval
 * @dev: DRM device
 * @pipe: index of CRTC whose vblank timestamp to retrieve
 * @tvblank: Pointer to target time which should receive the timestamp
 * @in_vblank_irq:
 *     True when called from drm_crtc_handle_vblank().  Some drivers
 *     need to apply some workarounds for gpu-specific vblank irq quirks
 *     if flag is set.
 *
 * Fetches the system timestamp corresponding to the time of the most recent
 * vblank interval on specified CRTC. May call into kms-driver to
 * compute the timestamp with a high-precision GPU specific method.
 *
 * Returns zero if timestamp originates from uncorrected do_gettimeofday()
 * call, i.e., it isn't very precisely locked to the true vblank.
 *
 * Returns:
 * True if timestamp is considered to be very precise, false otherwise.
 */
static bool
drm_get_last_vbltimestamp(struct drm_device *dev, unsigned int pipe,
			  ktime_t *tvblank, bool in_vblank_irq)
{
	struct drm_crtc *crtc = drm_crtc_from_index(dev, pipe);
	bool ret = false;

	/* Define requested maximum error on timestamps (nanoseconds). */
	int max_error = (int) drm_timestamp_precision * 1000;

	/* Query driver if possible and precision timestamping enabled. */
	if (crtc && crtc->funcs->get_vblank_timestamp && max_error > 0) {
		struct drm_crtc *crtc = drm_crtc_from_index(dev, pipe);

		ret = crtc->funcs->get_vblank_timestamp(crtc, &max_error,
							tvblank, in_vblank_irq);
	}

	/* GPU high precision timestamp query unsupported or failed.
	 * Return current monotonic/gettimeofday timestamp as best estimate.
	 */
	if (!ret)
		*tvblank = ktime_get();

	return ret;
}

/**
 * drm_crtc_vblank_count - retrieve "cooked" vblank counter value
 * @crtc: which counter to retrieve
 *
 * Fetches the "cooked" vblank count value that represents the number of
 * vblank events since the system was booted, including lost events due to
 * modesetting activity. Note that this timer isn't correct against a racing
 * vblank interrupt (since it only reports the software vblank counter), see
 * drm_crtc_accurate_vblank_count() for such use-cases.
 *
 * Note that for a given vblank counter value drm_crtc_handle_vblank()
 * and drm_crtc_vblank_count() or drm_crtc_vblank_count_and_time()
 * provide a barrier: Any writes done before calling
 * drm_crtc_handle_vblank() will be visible to callers of the later
 * functions, iff the vblank count is the same or a later one.
 *
 * See also &drm_vblank_crtc.count.
 *
 * Returns:
 * The software vblank counter.
 */
u64 drm_crtc_vblank_count(struct drm_crtc *crtc)
{
	return drm_vblank_count(crtc->dev, drm_crtc_index(crtc));
}
EXPORT_SYMBOL(drm_crtc_vblank_count);

/**
 * drm_vblank_count_and_time - retrieve "cooked" vblank counter value and the
 *     system timestamp corresponding to that vblank counter value.
 * @dev: DRM device
 * @pipe: index of CRTC whose counter to retrieve
 * @vblanktime: Pointer to ktime_t to receive the vblank timestamp.
 *
 * Fetches the "cooked" vblank count value that represents the number of
 * vblank events since the system was booted, including lost events due to
 * modesetting activity. Returns corresponding system timestamp of the time
 * of the vblank interval that corresponds to the current vblank counter value.
 *
 * This is the legacy version of drm_crtc_vblank_count_and_time().
 */
static u64 drm_vblank_count_and_time(struct drm_device *dev, unsigned int pipe,
				     ktime_t *vblanktime)
{
	struct drm_vblank_crtc *vblank = &dev->vblank[pipe];
	u64 vblank_count;
	unsigned int seq;

	if (drm_WARN_ON(dev, pipe >= dev->num_crtcs)) {
		*vblanktime = 0;
		return 0;
	}

	do {
		seq = read_seqbegin(&vblank->seqlock);
		vblank_count = atomic64_read(&vblank->count);
		*vblanktime = vblank->time;
	} while (read_seqretry(&vblank->seqlock, seq));

	return vblank_count;
}

/**
 * drm_crtc_vblank_count_and_time - retrieve "cooked" vblank counter value
 *     and the system timestamp corresponding to that vblank counter value
 * @crtc: which counter to retrieve
 * @vblanktime: Pointer to time to receive the vblank timestamp.
 *
 * Fetches the "cooked" vblank count value that represents the number of
 * vblank events since the system was booted, including lost events due to
 * modesetting activity. Returns corresponding system timestamp of the time
 * of the vblank interval that corresponds to the current vblank counter value.
 *
 * Note that for a given vblank counter value drm_crtc_handle_vblank()
 * and drm_crtc_vblank_count() or drm_crtc_vblank_count_and_time()
 * provide a barrier: Any writes done before calling
 * drm_crtc_handle_vblank() will be visible to callers of the later
 * functions, iff the vblank count is the same or a later one.
 *
 * See also &drm_vblank_crtc.count.
 */
u64 drm_crtc_vblank_count_and_time(struct drm_crtc *crtc,
				   ktime_t *vblanktime)
{
	return drm_vblank_count_and_time(crtc->dev, drm_crtc_index(crtc),
					 vblanktime);
}
EXPORT_SYMBOL(drm_crtc_vblank_count_and_time);

static void send_vblank_event(struct drm_device *dev,
		struct drm_pending_vblank_event *e,
		u64 seq, ktime_t now)
{
	struct timespec64 tv;

	switch (e->event.base.type) {
	case DRM_EVENT_VBLANK:
	case DRM_EVENT_FLIP_COMPLETE:
		tv = ktime_to_timespec64(now);
		e->event.vbl.sequence = seq;
		/*
		 * e->event is a user space structure, with hardcoded unsigned
		 * 32-bit seconds/microseconds. This is safe as we always use
		 * monotonic timestamps since linux-4.15
		 */
		e->event.vbl.tv_sec = tv.tv_sec;
		e->event.vbl.tv_usec = tv.tv_nsec / 1000;
		break;
	case DRM_EVENT_CRTC_SEQUENCE:
		if (seq)
			e->event.seq.sequence = seq;
		e->event.seq.time_ns = ktime_to_ns(now);
		break;
	}
	trace_drm_vblank_event_delivered(e->base.file_priv, e->pipe, seq);
	/*
	 * Use the same timestamp for any associated fence signal to avoid
	 * mismatch in timestamps for vsync & fence events triggered by the
	 * same HW event. Frameworks like SurfaceFlinger in Android expects the
	 * retire-fence timestamp to match exactly with HW vsync as it uses it
	 * for its software vsync modeling.
	 */
	drm_send_event_timestamp_locked(dev, &e->base, now);
}

/**
 * drm_crtc_arm_vblank_event - arm vblank event after pageflip
 * @crtc: the source CRTC of the vblank event
 * @e: the event to send
 *
 * A lot of drivers need to generate vblank events for the very next vblank
 * interrupt. For example when the page flip interrupt happens when the page
 * flip gets armed, but not when it actually executes within the next vblank
 * period. This helper function implements exactly the required vblank arming
 * behaviour.
 *
 * NOTE: Drivers using this to send out the &drm_crtc_state.event as part of an
 * atomic commit must ensure that the next vblank happens at exactly the same
 * time as the atomic commit is committed to the hardware. This function itself
 * does **not** protect against the next vblank interrupt racing with either this
 * function call or the atomic commit operation. A possible sequence could be:
 *
 * 1. Driver commits new hardware state into vblank-synchronized registers.
 * 2. A vblank happens, committing the hardware state. Also the corresponding
 *    vblank interrupt is fired off and fully processed by the interrupt
 *    handler.
 * 3. The atomic commit operation proceeds to call drm_crtc_arm_vblank_event().
 * 4. The event is only send out for the next vblank, which is wrong.
 *
 * An equivalent race can happen when the driver calls
 * drm_crtc_arm_vblank_event() before writing out the new hardware state.
 *
 * The only way to make this work safely is to prevent the vblank from firing
 * (and the hardware from committing anything else) until the entire atomic
 * commit sequence has run to completion. If the hardware does not have such a
 * feature (e.g. using a "go" bit), then it is unsafe to use this functions.
 * Instead drivers need to manually send out the event from their interrupt
 * handler by calling drm_crtc_send_vblank_event() and make sure that there's no
 * possible race with the hardware committing the atomic update.
 *
 * Caller must hold a vblank reference for the event @e acquired by a
 * drm_crtc_vblank_get(), which will be dropped when the next vblank arrives.
 */
void drm_crtc_arm_vblank_event(struct drm_crtc *crtc,
			       struct drm_pending_vblank_event *e)
{
	struct drm_device *dev = crtc->dev;
	unsigned int pipe = drm_crtc_index(crtc);

	assert_spin_locked(&dev->event_lock);

	e->pipe = pipe;
	e->sequence = drm_crtc_accurate_vblank_count(crtc) + 1;
	list_add_tail(&e->base.link, &dev->vblank_event_list);
}
EXPORT_SYMBOL(drm_crtc_arm_vblank_event);

/**
 * drm_crtc_send_vblank_event - helper to send vblank event after pageflip
 * @crtc: the source CRTC of the vblank event
 * @e: the event to send
 *
 * Updates sequence # and timestamp on event for the most recently processed
 * vblank, and sends it to userspace.  Caller must hold event lock.
 *
 * See drm_crtc_arm_vblank_event() for a helper which can be used in certain
 * situation, especially to send out events for atomic commit operations.
 */
void drm_crtc_send_vblank_event(struct drm_crtc *crtc,
				struct drm_pending_vblank_event *e)
{
	struct drm_device *dev = crtc->dev;
	u64 seq;
	unsigned int pipe = drm_crtc_index(crtc);
	ktime_t now;

	if (drm_dev_has_vblank(dev)) {
		seq = drm_vblank_count_and_time(dev, pipe, &now);
	} else {
		seq = 0;

		now = ktime_get();
	}
	e->pipe = pipe;
	send_vblank_event(dev, e, seq, now);
}
EXPORT_SYMBOL(drm_crtc_send_vblank_event);

static int __enable_vblank(struct drm_device *dev, unsigned int pipe)
{
	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
		struct drm_crtc *crtc = drm_crtc_from_index(dev, pipe);

		if (drm_WARN_ON(dev, !crtc))
			return 0;

		if (crtc->funcs->enable_vblank)
			return crtc->funcs->enable_vblank(crtc);
	} else if (dev->driver->enable_vblank) {
		return dev->driver->enable_vblank(dev, pipe);
	}

	return -EINVAL;
}

static int drm_vblank_enable(struct drm_device *dev, unsigned int pipe)
{
	struct drm_vblank_crtc *vblank = &dev->vblank[pipe];
	int ret = 0;

	assert_spin_locked(&dev->vbl_lock);

	spin_lock(&dev->vblank_time_lock);

	if (!vblank->enabled) {
		/*
		 * Enable vblank irqs under vblank_time_lock protection.
		 * All vblank count & timestamp updates are held off
		 * until we are done reinitializing master counter and
		 * timestamps. Filtercode in drm_handle_vblank() will
		 * prevent double-accounting of same vblank interval.
		 */
		ret = __enable_vblank(dev, pipe);
		drm_dbg_core(dev, "enabling vblank on crtc %u, ret: %d\n",
			     pipe, ret);
		if (ret) {
			atomic_dec(&vblank->refcount);
		} else {
			drm_update_vblank_count(dev, pipe, 0);
			/* drm_update_vblank_count() includes a wmb so we just
			 * need to ensure that the compiler emits the write
			 * to mark the vblank as enabled after the call
			 * to drm_update_vblank_count().
			 */
			WRITE_ONCE(vblank->enabled, true);
		}
	}

	spin_unlock(&dev->vblank_time_lock);

	return ret;
}

int drm_vblank_get(struct drm_device *dev, unsigned int pipe)
{
	struct drm_vblank_crtc *vblank = &dev->vblank[pipe];
	unsigned long irqflags;
	int ret = 0;

	if (!drm_dev_has_vblank(dev))
		return -EINVAL;

	if (drm_WARN_ON(dev, pipe >= dev->num_crtcs))
		return -EINVAL;

	spin_lock_irqsave(&dev->vbl_lock, irqflags);
	/* Going from 0->1 means we have to enable interrupts again */
	if (atomic_add_return(1, &vblank->refcount) == 1) {
		ret = drm_vblank_enable(dev, pipe);
	} else {
		if (!vblank->enabled) {
			atomic_dec(&vblank->refcount);
			ret = -EINVAL;
		}
	}
	spin_unlock_irqrestore(&dev->vbl_lock, irqflags);

	return ret;
}

