/*
 * Copyright © 2012 Red Hat
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
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Authors:
 *      Dave Airlie <airlied@redhat.com>
 *      Rob Clark <rob.clark@linaro.org>
 *
 */

#include <linux/export.h>
#include <linux/dma-buf.h>
#include <linux/rbtree.h>

#include <drm/drm.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_gem.h>
#include <drm/drm_prime.h>

#include "drm_internal.h"

/**
 * DOC: overview and lifetime rules
 *
 * Similar to GEM global names, PRIME file descriptors are also used to share
 * buffer objects across processes. They offer additional security: as file
 * descriptors must be explicitly sent over UNIX domain sockets to be shared
 * between applications, they can't be guessed like the globally unique GEM
 * names.
 *
 * Drivers that support the PRIME API implement the
 * &drm_driver.prime_handle_to_fd and &drm_driver.prime_fd_to_handle operations.
 * GEM based drivers must use drm_gem_prime_handle_to_fd() and
 * drm_gem_prime_fd_to_handle() to implement these. For GEM based drivers the
 * actual driver interfaces is provided through the &drm_gem_object_funcs.export
 * and &drm_driver.gem_prime_import hooks.
 *
 * &dma_buf_ops implementations for GEM drivers are all individually exported
 * for drivers which need to overwrite or reimplement some of them.
 *
 * Reference Counting for GEM Drivers
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * On the export the &dma_buf holds a reference to the exported buffer object,
 * usually a &drm_gem_object. It takes this reference in the PRIME_HANDLE_TO_FD
 * IOCTL, when it first calls &drm_gem_object_funcs.export
 * and stores the exporting GEM object in the &dma_buf.priv field. This
 * reference needs to be released when the final reference to the &dma_buf
 * itself is dropped and its &dma_buf_ops.release function is called.  For
 * GEM-based drivers, the &dma_buf should be exported using
 * drm_gem_dmabuf_export() and then released by drm_gem_dmabuf_release().
 *
 * Thus the chain of references always flows in one direction, avoiding loops:
 * importing GEM object -> dma-buf -> exported GEM bo. A further complication
 * are the lookup caches for import and export. These are required to guarantee
 * that any given object will always have only one uniqe userspace handle. This
 * is required to allow userspace to detect duplicated imports, since some GEM
 * drivers do fail command submissions if a given buffer object is listed more
 * than once. These import and export caches in &drm_prime_file_private only
 * retain a weak reference, which is cleaned up when the corresponding object is
 * released.
 *
 * Self-importing: If userspace is using PRIME as a replacement for flink then
 * it will get a fd->handle request for a GEM object that it created.  Drivers
 * should detect this situation and return back the underlying object from the
 * dma-buf private. For GEM based drivers this is handled in
 * drm_gem_prime_import() already.
 */

struct drm_prime_member {
	struct dma_buf *dma_buf;
	uint32_t handle;

	struct rb_node dmabuf_rb;
	struct rb_node handle_rb;
};

static int drm_prime_add_buf_handle(struct drm_prime_file_private *prime_fpriv,
				    struct dma_buf *dma_buf, uint32_t handle)
{
	struct drm_prime_member *member;
	struct rb_node **p, *rb;

	member = kmalloc(sizeof(*member), GFP_KERNEL);
	if (!member)
		return -ENOMEM;

	get_dma_buf(dma_buf);
	member->dma_buf = dma_buf;
	member->handle = handle;

	rb = NULL;
	p = &prime_fpriv->dmabufs.rb_node;
	while (*p) {
		struct drm_prime_member *pos;

		rb = *p;
		pos = rb_entry(rb, struct drm_prime_member, dmabuf_rb);
		if (dma_buf > pos->dma_buf)
			p = &rb->rb_right;
		else
			p = &rb->rb_left;
	}
	rb_link_node(&member->dmabuf_rb, rb, p);
	rb_insert_color(&member->dmabuf_rb, &prime_fpriv->dmabufs);

	rb = NULL;
	p = &prime_fpriv->handles.rb_node;
	while (*p) {
		struct drm_prime_member *pos;

		rb = *p;
		pos = rb_entry(rb, struct drm_prime_member, handle_rb);
		if (handle > pos->handle)
			p = &rb->rb_right;
		else
			p = &rb->rb_left;
	}
	rb_link_node(&member->handle_rb, rb, p);
	rb_insert_color(&member->handle_rb, &prime_fpriv->handles);

	return 0;
}

static struct dma_buf *drm_prime_lookup_buf_by_handle(struct drm_prime_file_private *prime_fpriv,
						      uint32_t handle)
{
	struct rb_node *rb;

	rb = prime_fpriv->handles.rb_node;
	while (rb) {
		struct drm_prime_member *member;

		member = rb_entry(rb, struct drm_prime_member, handle_rb);
		if (member->handle == handle)
			return member->dma_buf;
		else if (member->handle < handle)
			rb = rb->rb_right;
		else
			rb = rb->rb_left;
	}

	return NULL;
}

static int drm_prime_lookup_buf_handle(struct drm_prime_file_private *prime_fpriv,
				       struct dma_buf *dma_buf,
				       uint32_t *handle)
{
	struct rb_node *rb;

	rb = prime_fpriv->dmabufs.rb_node;
	while (rb) {
		struct drm_prime_member *member;

		member = rb_entry(rb, struct drm_prime_member, dmabuf_rb);
		if (member->dma_buf == dma_buf) {
			*handle = member->handle;
			return 0;
		} else if (member->dma_buf < dma_buf) {
			rb = rb->rb_right;
		} else {
			rb = rb->rb_left;
		}
	}

	return -ENOENT;
}

void drm_prime_remove_buf_handle_locked(struct drm_prime_file_private *prime_fpriv,
					struct dma_buf *dma_buf)
{
	struct rb_node *rb;

	rb = prime_fpriv->dmabufs.rb_node;
	while (rb) {
		struct drm_prime_member *member;

		member = rb_entry(rb, struct drm_prime_member, dmabuf_rb);
		if (member->dma_buf == dma_buf) {
			rb_erase(&member->handle_rb, &prime_fpriv->handles);
			rb_erase(&member->dmabuf_rb, &prime_fpriv->dmabufs);

			dma_buf_put(dma_buf);
			kfree(member);
			return;
		} else if (member->dma_buf < dma_buf) {
			rb = rb->rb_right;
		} else {
			rb = rb->rb_left;
		}
	}
}

void drm_prime_init_file_private(struct drm_prime_file_private *prime_fpriv)
{
	mutex_init(&prime_fpriv->lock);
	prime_fpriv->dmabufs = RB_ROOT;
	prime_fpriv->handles = RB_ROOT;
}

void drm_prime_destroy_file_private(struct drm_prime_file_private *prime_fpriv)
{
	/* by now drm_gem_release should've made sure the list is empty */
	WARN_ON(!RB_EMPTY_ROOT(&prime_fpriv->dmabufs));
}

/**
 * drm_gem_dmabuf_export - &dma_buf export implementation for GEM
 * @dev: parent device for the exported dmabuf
 * @exp_info: the export information used by dma_buf_export()
 *
 * This wraps dma_buf_export() for use by generic GEM drivers that are using
 * drm_gem_dmabuf_release(). In addition to calling dma_buf_export(), we take
 * a reference to the &drm_device and the exported &drm_gem_object (stored in
 * &dma_buf_export_info.priv) which is released by drm_gem_dmabuf_release().
 *
 * Returns the new dmabuf.
 */
struct dma_buf *drm_gem_dmabuf_export(struct drm_device *dev,
				      struct dma_buf_export_info *exp_info)
{
	struct drm_gem_object *obj = exp_info->priv;
	struct dma_buf *dma_buf;

	dma_buf = dma_buf_export(exp_info);
	if (IS_ERR(dma_buf))
		return dma_buf;

	drm_dev_get(dev);
	drm_gem_object_get(obj);
	dma_buf->file->f_mapping = obj->dev->anon_inode->i_mapping;

	return dma_buf;
}
EXPORT_SYMBOL(drm_gem_dmabuf_export);

/**
 * drm_gem_dmabuf_release - &dma_buf release implementation for GEM
 * @dma_buf: buffer to be released
 *
 * Generic release function for dma_bufs exported as PRIME buffers. GEM drivers
 * must use this in their &dma_buf_ops structure as the release callback.
 * drm_gem_dmabuf_release() should be used in conjunction with
 * drm_gem_dmabuf_export().
 */
void drm_gem_dmabuf_release(struct dma_buf *dma_buf)
{
	struct drm_gem_object *obj = dma_buf->priv;
	struct drm_device *dev = obj->dev;

	/* drop the reference on the export fd holds */
	drm_gem_object_put(obj);

	drm_dev_put(dev);
}
EXPORT_SYMBOL(drm_gem_dmabuf_release);

/**
 * drm_gem_prime_fd_to_handle - PRIME import function for GEM drivers
 * @dev: dev to export the buffer from
 * @file_priv: drm file-private structure
 * @prime_fd: fd id of the dma-buf which should be imported
 * @handle: pointer to storage for the handle of the imported buffer object
 *
 * This is the PRIME import function which must be used mandatorily by GEM
 * drivers to ensure correct lifetime management of the underlying GEM object.
 * The actual importing of GEM object from the dma-buf is done through the
 * &drm_driver.gem_prime_import driver callback.
 *
 * Returns 0 on success or a negative error code on failure.
 */
int drm_gem_prime_fd_to_handle(struct drm_device *dev,
			       struct drm_file *file_priv, int prime_fd,
			       uint32_t *handle)
{
	struct dma_buf *dma_buf;
	struct drm_gem_object *obj;
	int ret;
