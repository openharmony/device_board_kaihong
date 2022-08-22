/*
 * Created: Fri Jan  8 09:01:26 1999 by faith@valinux.com
 *
 * Copyright 1999 Precision Insight, Inc., Cedar Park, Texas.
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * All Rights Reserved.
 *
 * Author Rickard E. (Rik) Faith <faith@valinux.com>
 * Author Gareth Hughes <gareth@valinux.com>
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
#include <linux/nospec.h>
#include <linux/pci.h>
#include <linux/uaccess.h>

#include <drm/drm_agpsupport.h>
#include <drm/drm_auth.h>
#include <drm/drm_crtc.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_print.h>

#include "drm_crtc_internal.h"
#include "drm_internal.h"
#include "drm_legacy.h"

/**
 * DOC: getunique and setversion story
 *
 * BEWARE THE DRAGONS! MIND THE TRAPDOORS!
 *
 * In an attempt to warn anyone else who's trying to figure out what's going
 * on here, I'll try to summarize the story. First things first, let's clear up
 * the names, because the kernel internals, libdrm and the ioctls are all named
 * differently:
 *
 *  - GET_UNIQUE ioctl, implemented by drm_getunique is wrapped up in libdrm
 *    through the drmGetBusid function.
 *  - The libdrm drmSetBusid function is backed by the SET_UNIQUE ioctl. All
 *    that code is nerved in the kernel with drm_invalid_op().
 *  - The internal set_busid kernel functions and driver callbacks are
 *    exclusively use by the SET_VERSION ioctl, because only drm 1.0 (which is
 *    nerved) allowed userspace to set the busid through the above ioctl.
 *  - Other ioctls and functions involved are named consistently.
 *
 * For anyone wondering what's the difference between drm 1.1 and 1.4: Correctly
 * handling pci domains in the busid on ppc. Doing this correctly was only
 * implemented in libdrm in 2010, hence can't be nerved yet. No one knows what's
 * special with drm 1.2 and 1.3.
 *
 * Now the actual horror story of how device lookup in drm works. At large,
 * there's 2 different ways, either by busid, or by device driver name.
 *
 * Opening by busid is fairly simple:
 *
 * 1. First call SET_VERSION to make sure pci domains are handled properly. As a
 *    side-effect this fills out the unique name in the master structure.
 * 2. Call GET_UNIQUE to read out the unique name from the master structure,
 *    which matches the busid thanks to step 1. If it doesn't, proceed to try
 *    the next device node.
 *
 * Opening by name is slightly different:
 *
 * 1. Directly call VERSION to get the version and to match against the driver
 *    name returned by that ioctl. Note that SET_VERSION is not called, which
 *    means the the unique name for the master node just opening is _not_ filled
 *    out. This despite that with current drm device nodes are always bound to
 *    one device, and can't be runtime assigned like with drm 1.0.
 * 2. Match driver name. If it mismatches, proceed to the next device node.
 * 3. Call GET_UNIQUE, and check whether the unique name has length zero (by
 *    checking that the first byte in the string is 0). If that's not the case
 *    libdrm skips and proceeds to the next device node. Probably this is just
 *    copypasta from drm 1.0 times where a set unique name meant that the driver
 *    was in use already, but that's just conjecture.
 *
 * Long story short: To keep the open by name logic working, GET_UNIQUE must
 * _not_ return a unique string when SET_VERSION hasn't been called yet,
 * otherwise libdrm breaks. Even when that unique string can't ever change, and
 * is totally irrelevant for actually opening the device because runtime
 * assignable device instances were only support in drm 1.0, which is long dead.
 * But the libdrm code in drmOpenByName somehow survived, hence this can't be
 * broken.
 */

/*
 * Get the bus id.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument, pointing to a drm_unique structure.
 * \return zero on success or a negative number on failure.
 *
 * Copies the bus id from drm_device::unique into user space.
 */
int drm_getunique(struct drm_device *dev, void *data,
		  struct drm_file *file_priv)
{
	struct drm_unique *u = data;
	struct drm_master *master;

	mutex_lock(&dev->master_mutex);
	master = file_priv->master;
	if (u->unique_len >= master->unique_len) {
		if (copy_to_user(u->unique, master->unique, master->unique_len)) {
			mutex_unlock(&dev->master_mutex);
			return -EFAULT;
		}
	}
	u->unique_len = master->unique_len;
	mutex_unlock(&dev->master_mutex);

	return 0;
}

static void
drm_unset_busid(struct drm_device *dev,
		struct drm_master *master)
{
	kfree(master->unique);
	master->unique = NULL;
	master->unique_len = 0;
}

static int drm_set_busid(struct drm_device *dev, struct drm_file *file_priv)
{
	struct drm_master *master = file_priv->master;
	int ret;

	if (master->unique != NULL)
		drm_unset_busid(dev, master);

	if (dev->dev && dev_is_pci(dev->dev)) {
		ret = drm_pci_set_busid(dev, master);
		if (ret) {
			drm_unset_busid(dev, master);
			return ret;
		}
	} else {
		WARN_ON(!dev->unique);
		master->unique = kstrdup(dev->unique, GFP_KERNEL);
		if (master->unique)
			master->unique_len = strlen(dev->unique);
	}

	return 0;
}

/*
 * Get client information.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument, pointing to a drm_client structure.
 *
 * \return zero on success or a negative number on failure.
 *
 * Searches for the client with the specified index and copies its information
 * into userspace
 */
int drm_getclient(struct drm_device *dev, void *data,
		  struct drm_file *file_priv)
{
	struct drm_client *client = data;

	/*
	 * Hollowed-out getclient ioctl to keep some dead old drm tests/tools
	 * not breaking completely. Userspace tools stop enumerating one they
	 * get -EINVAL, hence this is the return value we need to hand back for
	 * no clients tracked.
	 *
	 * Unfortunately some clients (*cough* libva *cough*) use this in a fun
	 * attempt to figure out whether they're authenticated or not. Since
	 * that's the only thing they care about, give it to the directly
	 * instead of walking one giant list.
	 */
	if (client->idx == 0) {
		client->auth = file_priv->authenticated;
		client->pid = task_pid_vnr(current);
		client->uid = overflowuid;
		client->magic = 0;
		client->iocs = 0;

		return 0;
	} else {
		return -EINVAL;
	}
}

/*
 * Get statistics information.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument, pointing to a drm_stats structure.
 *
 * \return zero on success or a negative number on failure.
 */
static int drm_getstats(struct drm_device *dev, void *data,
		 struct drm_file *file_priv)
{
	struct drm_stats *stats = data;

	/* Clear stats to prevent userspace from eating its stack garbage. */
	memset(stats, 0, sizeof(*stats));

	return 0;
}

/*
 * Get device/driver capabilities
 */
static int drm_getcap(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct drm_get_cap *req = data;
	struct drm_crtc *crtc;

	req->value = 0;

	/* Only some caps make sense with UMS/render-only drivers. */
	switch (req->capability) {
	case DRM_CAP_TIMESTAMP_MONOTONIC:
		req->value = 1;
		return 0;
	case DRM_CAP_PRIME:
		req->value |= dev->driver->prime_fd_to_handle ? DRM_PRIME_CAP_IMPORT : 0;
		req->value |= dev->driver->prime_handle_to_fd ? DRM_PRIME_CAP_EXPORT : 0;
		return 0;
	case DRM_CAP_SYNCOBJ:
		req->value = drm_core_check_feature(dev, DRIVER_SYNCOBJ);
		return 0;
	case DRM_CAP_SYNCOBJ_TIMELINE:
		req->value = drm_core_check_feature(dev, DRIVER_SYNCOBJ_TIMELINE);
		return 0;
	}

	/* Other caps only work with KMS drivers */
	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		return -EOPNOTSUPP;

	switch (req->capability) {
	case DRM_CAP_DUMB_BUFFER:
		if (dev->driver->dumb_create)
			req->value = 1;
		break;
	case DRM_CAP_VBLANK_HIGH_CRTC:
		req->value = 1;
		break;
	case DRM_CAP_DUMB_PREFERRED_DEPTH:
		req->value = dev->mode_config.preferred_depth;
		break;
	case DRM_CAP_DUMB_PREFER_SHADOW:
		req->value = dev->mode_config.prefer_shadow;
		break;
	case DRM_CAP_ASYNC_PAGE_FLIP:
		req->value = dev->mode_config.async_page_flip;
		break;
	case DRM_CAP_PAGE_FLIP_TARGET:
		req->value = 1;
		drm_for_each_crtc(crtc, dev) {
			if (!crtc->funcs->page_flip_target)
				req->value = 0;
		}
		break;
	case DRM_CAP_CURSOR_WIDTH:
		if (dev->mode_config.cursor_width)
			req->value = dev->mode_config.cursor_width;
		else
			req->value = 64;
		break;
	case DRM_CAP_CURSOR_HEIGHT:
		if (dev->mode_config.cursor_height)
			req->value = dev->mode_config.cursor_height;
		else
			req->value = 64;
		break;
	case DRM_CAP_ADDFB2_MODIFIERS:
		req->value = dev->mode_config.allow_fb_modifiers;
		break;
	case DRM_CAP_CRTC_IN_VBLANK_EVENT:
		req->value = 1;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/*
 * Set device/driver capabilities
 */
static int
drm_setclientcap(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct drm_set_client_cap *req = data;

	/* No render-only settable capabilities for now */

	/* Below caps that only works with KMS drivers */
	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		return -EOPNOTSUPP;

	switch (req->capability) {
	case DRM_CLIENT_CAP_STEREO_3D:
		if (req->value > 1)
			return -EINVAL;
		file_priv->stereo_allowed = req->value;
		break;
	case DRM_CLIENT_CAP_UNIVERSAL_PLANES:
		if (req->value > 1)
			return -EINVAL;
		file_priv->universal_planes = req->value;
		break;
	case DRM_CLIENT_CAP_ATOMIC:
		if (!drm_core_check_feature(dev, DRIVER_ATOMIC))
			return -EOPNOTSUPP;
		/* The modesetting DDX has a totally broken idea of atomic. */
		if (current->comm[0] == 'X' && req->value == 1) {
			pr_info("broken atomic modeset userspace detected, disabling atomic\n");
			return -EOPNOTSUPP;
		}
		if (req->value > 2)
			return -EINVAL;
		file_priv->atomic = req->value;
		file_priv->universal_planes = req->value;
		/*
		 * No atomic user-space blows up on aspect ratio mode bits.
		 */
		file_priv->aspect_ratio_allowed = req->value;
		break;
	case DRM_CLIENT_CAP_ASPECT_RATIO:
		if (req->value > 1)
			return -EINVAL;
		file_priv->aspect_ratio_allowed = req->value;
		break;
	case DRM_CLIENT_CAP_WRITEBACK_CONNECTORS:
		if (!file_priv->atomic)
			return -EINVAL;
		if (req->value > 1)
			return -EINVAL;
		file_priv->writeback_connectors = req->value;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/*
 * Setversion ioctl.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument, pointing to a drm_lock structure.
 * \return zero on success or negative number on failure.
 *
 * Sets the requested interface version
 */
static int drm_setversion(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct drm_set_version *sv = data;
	int if_version, retcode = 0;

	mutex_lock(&dev->master_mutex);
	if (sv->drm_di_major != -1) {
		if (sv->drm_di_major != DRM_IF_MAJOR ||
		    sv->drm_di_minor < 0 || sv->drm_di_minor > DRM_IF_MINOR) {
			retcode = -EINVAL;
			goto done;
		}
		if_version = DRM_IF_VERSION(sv->drm_di_major,
					    sv->drm_di_minor);
		dev->if_version = max(if_version, dev->if_version);
		if (sv->drm_di_minor >= 1) {
