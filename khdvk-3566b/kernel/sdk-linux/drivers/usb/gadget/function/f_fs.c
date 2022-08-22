// SPDX-License-Identifier: GPL-2.0+
/*
 * f_fs.c -- user mode file system API for USB composite function controllers
 *
 * Copyright (C) 2010 Samsung Electronics
 * Author: Michal Nazarewicz <mina86@mina86.com>
 *
 * Based on inode.c (GadgetFS) which was:
 * Copyright (C) 2003-2004 David Brownell
 * Copyright (C) 2003 Agilent Technologies
 */


/* #define DEBUG */
/* #define VERBOSE_DEBUG */

#include <linux/blkdev.h>
#include <linux/pagemap.h>
#include <linux/export.h>
#include <linux/fs_parser.h>
#include <linux/hid.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/sched/signal.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>
#include <asm/unaligned.h>

#include <linux/usb/ccid.h>
#include <linux/usb/composite.h>
#include <linux/usb/functionfs.h>

#include <linux/aio.h>
#include <linux/kthread.h>
#include <linux/poll.h>
#include <linux/eventfd.h>

#include "u_fs.h"
#include "u_f.h"
#include "u_os_desc.h"
#include "configfs.h"

#define FUNCTIONFS_MAGIC	0xa647361 /* Chosen by a honest dice roll ;) */

/* Reference counter handling */
static void ffs_data_get(struct ffs_data *ffs);
static void ffs_data_put(struct ffs_data *ffs);
/* Creates new ffs_data object. */
static struct ffs_data *__must_check ffs_data_new(const char *dev_name)
	__attribute__((malloc));

/* Opened counter handling. */
static void ffs_data_opened(struct ffs_data *ffs);
static void ffs_data_closed(struct ffs_data *ffs);

/* Called with ffs->mutex held; take over ownership of data. */
static int __must_check
__ffs_data_got_descs(struct ffs_data *ffs, char *data, size_t len);
static int __must_check
__ffs_data_got_strings(struct ffs_data *ffs, char *data, size_t len);


/* The function structure ***************************************************/

struct ffs_ep;

struct ffs_function {
	struct usb_configuration	*conf;
	struct usb_gadget		*gadget;
	struct ffs_data			*ffs;

	struct ffs_ep			*eps;
	u8				eps_revmap[32];
	short				*interfaces_nums;

	struct usb_function		function;
};


static struct ffs_function *ffs_func_from_usb(struct usb_function *f)
{
	return container_of(f, struct ffs_function, function);
}


static inline enum ffs_setup_state
ffs_setup_state_clear_cancelled(struct ffs_data *ffs)
{
	return (enum ffs_setup_state)
		cmpxchg(&ffs->setup_state, FFS_SETUP_CANCELLED, FFS_NO_SETUP);
}


static void ffs_func_eps_disable(struct ffs_function *func);
static int __must_check ffs_func_eps_enable(struct ffs_function *func);

static int ffs_func_bind(struct usb_configuration *,
			 struct usb_function *);
static int ffs_func_set_alt(struct usb_function *, unsigned, unsigned);
static void ffs_func_disable(struct usb_function *);
static int ffs_func_setup(struct usb_function *,
			  const struct usb_ctrlrequest *);
static bool ffs_func_req_match(struct usb_function *,
			       const struct usb_ctrlrequest *,
			       bool config0);
static void ffs_func_suspend(struct usb_function *);
static void ffs_func_resume(struct usb_function *);


static int ffs_func_revmap_ep(struct ffs_function *func, u8 num);
static int ffs_func_revmap_intf(struct ffs_function *func, u8 intf);


/* The endpoints structures *************************************************/

struct ffs_ep {
	struct usb_ep			*ep;	/* P: ffs->eps_lock */
	struct usb_request		*req;	/* P: epfile->mutex */

	/* [0]: full speed, [1]: high speed, [2]: super speed */
	struct usb_endpoint_descriptor	*descs[3];

	u8				num;

	int				status;	/* P: epfile->mutex */
};

struct ffs_epfile {
	/* Protects ep->ep and ep->req. */
	struct mutex			mutex;

	struct ffs_data			*ffs;
	struct ffs_ep			*ep;	/* P: ffs->eps_lock */

	struct dentry			*dentry;

	/*
	 * Buffer for holding data from partial reads which may happen since
	 * we’re rounding user read requests to a multiple of a max packet size.
	 *
	 * The pointer is initialised with NULL value and may be set by
	 * __ffs_epfile_read_data function to point to a temporary buffer.
	 *
	 * In normal operation, calls to __ffs_epfile_read_buffered will consume
	 * data from said buffer and eventually free it.  Importantly, while the
	 * function is using the buffer, it sets the pointer to NULL.  This is
	 * all right since __ffs_epfile_read_data and __ffs_epfile_read_buffered
	 * can never run concurrently (they are synchronised by epfile->mutex)
	 * so the latter will not assign a new value to the pointer.
	 *
	 * Meanwhile ffs_func_eps_disable frees the buffer (if the pointer is
	 * valid) and sets the pointer to READ_BUFFER_DROP value.  This special
	 * value is crux of the synchronisation between ffs_func_eps_disable and
	 * __ffs_epfile_read_data.
	 *
	 * Once __ffs_epfile_read_data is about to finish it will try to set the
	 * pointer back to its old value (as described above), but seeing as the
	 * pointer is not-NULL (namely READ_BUFFER_DROP) it will instead free
	 * the buffer.
	 *
	 * == State transitions ==
	 *
	 * • ptr == NULL:  (initial state)
	 *   ◦ __ffs_epfile_read_buffer_free: go to ptr == DROP
	 *   ◦ __ffs_epfile_read_buffered:    nop
	 *   ◦ __ffs_epfile_read_data allocates temp buffer: go to ptr == buf
	 *   ◦ reading finishes:              n/a, not in ‘and reading’ state
	 * • ptr == DROP:
	 *   ◦ __ffs_epfile_read_buffer_free: nop
	 *   ◦ __ffs_epfile_read_buffered:    go to ptr == NULL
	 *   ◦ __ffs_epfile_read_data allocates temp buffer: free buf, nop
	 *   ◦ reading finishes:              n/a, not in ‘and reading’ state
	 * • ptr == buf:
	 *   ◦ __ffs_epfile_read_buffer_free: free buf, go to ptr == DROP
	 *   ◦ __ffs_epfile_read_buffered:    go to ptr == NULL and reading
	 *   ◦ __ffs_epfile_read_data:        n/a, __ffs_epfile_read_buffered
	 *                                    is always called first
	 *   ◦ reading finishes:              n/a, not in ‘and reading’ state
	 * • ptr == NULL and reading:
	 *   ◦ __ffs_epfile_read_buffer_free: go to ptr == DROP and reading
	 *   ◦ __ffs_epfile_read_buffered:    n/a, mutex is held
	 *   ◦ __ffs_epfile_read_data:        n/a, mutex is held
	 *   ◦ reading finishes and …
	 *     … all data read:               free buf, go to ptr == NULL
	 *     … otherwise:                   go to ptr == buf and reading
	 * • ptr == DROP and reading:
	 *   ◦ __ffs_epfile_read_buffer_free: nop
	 *   ◦ __ffs_epfile_read_buffered:    n/a, mutex is held
	 *   ◦ __ffs_epfile_read_data:        n/a, mutex is held
	 *   ◦ reading finishes:              free buf, go to ptr == DROP
	 */
	struct ffs_buffer		*read_buffer;
#define READ_BUFFER_DROP ((struct ffs_buffer *)ERR_PTR(-ESHUTDOWN))

	char				name[5];

	unsigned char			in;	/* P: ffs->eps_lock */
	unsigned char			isoc;	/* P: ffs->eps_lock */

	unsigned char			_pad;
};

struct ffs_buffer {
	size_t length;
	char *data;
	char storage[];
};

/*  ffs_io_data structure ***************************************************/

struct ffs_io_data {
	bool aio;
	bool read;

	struct kiocb *kiocb;
	struct iov_iter data;
	const void *to_free;
	char *buf;

	struct mm_struct *mm;
	struct work_struct work;

	struct usb_ep *ep;
	struct usb_request *req;
	struct sg_table sgt;
	bool use_sg;

	struct ffs_data *ffs;
};

struct ffs_desc_helper {
	struct ffs_data *ffs;
	unsigned interfaces_count;
	unsigned eps_count;
};

static int  __must_check ffs_epfiles_create(struct ffs_data *ffs);
static void ffs_epfiles_destroy(struct ffs_epfile *epfiles, unsigned count);

static struct dentry *
ffs_sb_create_file(struct super_block *sb, const char *name, void *data,
		   const struct file_operations *fops);

/* Devices management *******************************************************/

DEFINE_MUTEX(ffs_lock);
EXPORT_SYMBOL_GPL(ffs_lock);

static struct ffs_dev *_ffs_find_dev(const char *name);
static struct ffs_dev *_ffs_alloc_dev(void);
static void _ffs_free_dev(struct ffs_dev *dev);
static int ffs_acquire_dev(const char *dev_name, struct ffs_data *ffs_data);
static void ffs_release_dev(struct ffs_dev *ffs_dev);
static int ffs_ready(struct ffs_data *ffs);
static void ffs_closed(struct ffs_data *ffs);

/* Misc helper functions ****************************************************/

static int ffs_mutex_lock(struct mutex *mutex, unsigned nonblock)
	__attribute__((warn_unused_result, nonnull));
static char *ffs_prepare_buffer(const char __user *buf, size_t len)
	__attribute__((warn_unused_result, nonnull));


/* Control file aka ep0 *****************************************************/

static void ffs_ep0_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct ffs_data *ffs = req->context;

	complete(&ffs->ep0req_completion);
}

static int __ffs_ep0_queue_wait(struct ffs_data *ffs, char *data, size_t len)
	__releases(&ffs->ev.waitq.lock)
{
	struct usb_request *req = ffs->ep0req;
	int ret;

	req->zero     = len < le16_to_cpu(ffs->ev.setup.wLength);

	spin_unlock_irq(&ffs->ev.waitq.lock);

	req->buf      = data;
	req->length   = len;

	/*
	 * UDC layer requires to provide a buffer even for ZLP, but should
	 * not use it at all. Let's provide some poisoned pointer to catch
	 * possible bug in the driver.
	 */
	if (req->buf == NULL)
		req->buf = (void *)0xDEADBABE;

	reinit_completion(&ffs->ep0req_completion);

	ret = usb_ep_queue(ffs->gadget->ep0, req, GFP_ATOMIC);
	if (unlikely(ret < 0))
		return ret;

	ret = wait_for_completion_interruptible(&ffs->ep0req_completion);
	if (unlikely(ret)) {
		usb_ep_dequeue(ffs->gadget->ep0, req);
		return -EINTR;
	}

	ffs->setup_state = FFS_NO_SETUP;
	return req->status ? req->status : req->actual;
}

static int __ffs_ep0_stall(struct ffs_data *ffs)
{
	if (ffs->ev.can_stall) {
		pr_vdebug("ep0 stall\n");
		usb_ep_set_halt(ffs->gadget->ep0);
		ffs->setup_state = FFS_NO_SETUP;
		return -EL2HLT;
	} else {
		pr_debug("bogus ep0 stall!\n");
		return -ESRCH;
	}
}

static ssize_t ffs_ep0_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *ptr)
{
	struct ffs_data *ffs = file->private_data;
	ssize_t ret;
	char *data;

	ENTER();

	/* Fast check if setup was canceled */
	if (ffs_setup_state_clear_cancelled(ffs) == FFS_SETUP_CANCELLED)
		return -EIDRM;

	/* Acquire mutex */
	ret = ffs_mutex_lock(&ffs->mutex, file->f_flags & O_NONBLOCK);
	if (unlikely(ret < 0))
		return ret;

	/* Check state */
	switch (ffs->state) {
	case FFS_READ_DESCRIPTORS:
	case FFS_READ_STRINGS:
		/* Copy data */
		if (unlikely(len < 16)) {
			ret = -EINVAL;
			break;
		}

		data = ffs_prepare_buffer(buf, len);
		if (IS_ERR(data)) {
			ret = PTR_ERR(data);
			break;
		}

		/* Handle data */
		if (ffs->state == FFS_READ_DESCRIPTORS) {
			pr_info("read descriptors\n");
			ret = __ffs_data_got_descs(ffs, data, len);
			if (unlikely(ret < 0))
				break;

			ffs->state = FFS_READ_STRINGS;
			ret = len;
		} else {
			pr_info("read strings\n");
			ret = __ffs_data_got_strings(ffs, data, len);
			if (unlikely(ret < 0))
				break;

			ret = ffs_epfiles_create(ffs);
			if (unlikely(ret)) {
				ffs->state = FFS_CLOSING;
				break;
			}

			ffs->state = FFS_ACTIVE;
			mutex_unlock(&ffs->mutex);

			ret = ffs_ready(ffs);
			if (unlikely(ret < 0)) {
				ffs->state = FFS_CLOSING;
				return ret;
			}

			return len;
		}
		break;

	case FFS_ACTIVE:
		data = NULL;
		/*
		 * We're called from user space, we can use _irq
		 * rather then _irqsave
		 */
		spin_lock_irq(&ffs->ev.waitq.lock);
		switch (ffs_setup_state_clear_cancelled(ffs)) {
		case FFS_SETUP_CANCELLED:
			ret = -EIDRM;
			goto done_spin;

		case FFS_NO_SETUP:
			ret = -ESRCH;
			goto done_spin;

		case FFS_SETUP_PENDING:
			break;
		}

		/* FFS_SETUP_PENDING */
		if (!(ffs->ev.setup.bRequestType & USB_DIR_IN)) {
			spin_unlock_irq(&ffs->ev.waitq.lock);
			ret = __ffs_ep0_stall(ffs);
			break;
		}

		/* FFS_SETUP_PENDING and not stall */
		len = min(len, (size_t)le16_to_cpu(ffs->ev.setup.wLength));

		spin_unlock_irq(&ffs->ev.waitq.lock);

		data = ffs_prepare_buffer(buf, len);
		if (IS_ERR(data)) {
			ret = PTR_ERR(data);
			break;
		}

		spin_lock_irq(&ffs->ev.waitq.lock);

		/*
		 * We are guaranteed to be still in FFS_ACTIVE state
		 * but the state of setup could have changed from
		 * FFS_SETUP_PENDING to FFS_SETUP_CANCELLED so we need
		 * to check for that.  If that happened we copied data
		 * from user space in vain but it's unlikely.
		 *
		 * For sure we are not in FFS_NO_SETUP since this is
		 * the only place FFS_SETUP_PENDING -> FFS_NO_SETUP
		 * transition can be performed and it's protected by
		 * mutex.
		 */
		if (ffs_setup_state_clear_cancelled(ffs) ==
		    FFS_SETUP_CANCELLED) {
			ret = -EIDRM;
done_spin:
			spin_unlock_irq(&ffs->ev.waitq.lock);
		} else {
			/* unlocks spinlock */
			ret = __ffs_ep0_queue_wait(ffs, data, len);
		}
		kfree(data);
		break;

	default:
		ret = -EBADFD;
		break;
	}

	mutex_unlock(&ffs->mutex);
	return ret;
}

/* Called with ffs->ev.waitq.lock and ffs->mutex held, both released on exit. */
static ssize_t __ffs_ep0_read_events(struct ffs_data *ffs, char __user *buf,
				     size_t n)
	__releases(&ffs->ev.waitq.lock)
{
	/*
	 * n cannot be bigger than ffs->ev.count, which cannot be bigger than
	 * size of ffs->ev.types array (which is four) so that's how much space
	 * we reserve.
	 */
	struct usb_functionfs_event events[ARRAY_SIZE(ffs->ev.types)];
	const size_t size = n * sizeof *events;
	unsigned i = 0;

	memset(events, 0, size);

	do {
		events[i].type = ffs->ev.types[i];
		if (events[i].type == FUNCTIONFS_SETUP) {
			events[i].u.setup = ffs->ev.setup;
			ffs->setup_state = FFS_SETUP_PENDING;
		}
	} while (++i < n);

	ffs->ev.count -= n;
	if (ffs->ev.count)
		memmove(ffs->ev.types, ffs->ev.types + n,
			ffs->ev.count * sizeof *ffs->ev.types);

	spin_unlock_irq(&ffs->ev.waitq.lock);
	mutex_unlock(&ffs->mutex);

	return unlikely(copy_to_user(buf, events, size)) ? -EFAULT : size;
}

static ssize_t ffs_ep0_read(struct file *file, char __user *buf,
			    size_t len, loff_t *ptr)
{
	struct ffs_data *ffs = file->private_data;
	char *data = NULL;
	size_t n;
	int ret;

	ENTER();

	/* Fast check if setup was canceled */
	if (ffs_setup_state_clear_cancelled(ffs) == FFS_SETUP_CANCELLED)
		return -EIDRM;

	/* Acquire mutex */
	ret = ffs_mutex_lock(&ffs->mutex, file->f_flags & O_NONBLOCK);
	if (unlikely(ret < 0))
		return ret;

	/* Check state */
	if (ffs->state != FFS_ACTIVE) {
		ret = -EBADFD;
		goto done_mutex;
	}

	/*
	 * We're called from user space, we can use _irq rather then
	 * _irqsave
	 */
	spin_lock_irq(&ffs->ev.waitq.lock);

	switch (ffs_setup_state_clear_cancelled(ffs)) {
	case FFS_SETUP_CANCELLED:
		ret = -EIDRM;
		break;

	case FFS_NO_SETUP:
		n = len / sizeof(struct usb_functionfs_event);
		if (unlikely(!n)) {
			ret = -EINVAL;
			break;
		}

		if ((file->f_flags & O_NONBLOCK) && !ffs->ev.count) {
			ret = -EAGAIN;
			break;
		}

		if (wait_event_interruptible_exclusive_locked_irq(ffs->ev.waitq,
							ffs->ev.count)) {
			ret = -EINTR;
			break;
		}

		/* unlocks spinlock */
		return __ffs_ep0_read_events(ffs, buf,
					     min(n, (size_t)ffs->ev.count));

	case FFS_SETUP_PENDING:
		if (ffs->ev.setup.bRequestType & USB_DIR_IN) {
			spin_unlock_irq(&ffs->ev.waitq.lock);
			ret = __ffs_ep0_stall(ffs);
			goto done_mutex;
		}

		len = min(len, (size_t)le16_to_cpu(ffs->ev.setup.wLength));

		spin_unlock_irq(&ffs->ev.waitq.lock);

		if (likely(len)) {
			data = kmalloc(len, GFP_KERNEL);
			if (unlikely(!data)) {
				ret = -ENOMEM;
				goto done_mutex;
			}
		}

		spin_lock_irq(&ffs->ev.waitq.lock);

		/* See ffs_ep0_write() */
		if (ffs_setup_state_clear_cancelled(ffs) ==
		    FFS_SETUP_CANCELLED) {
			ret = -EIDRM;
			break;
		}

		/* unlocks spinlock */
		ret = __ffs_ep0_queue_wait(ffs, data, len);
		if (likely(ret > 0) && unlikely(copy_to_user(buf, data, len)))
			ret = -EFAULT;
		goto done_mutex;

	default:
		ret = -EBADFD;
		break;
	}

	spin_unlock_irq(&ffs->ev.waitq.lock);
done_mutex:
	mutex_unlock(&ffs->mutex);
	kfree(data);
	return ret;
}

static int ffs_ep0_open(struct inode *inode, struct file *file)
{
	struct ffs_data *ffs = inode->i_private;

	ENTER();

	if (unlikely(ffs->state == FFS_CLOSING))
		return -EBUSY;

	file->private_data = ffs;
	ffs_data_opened(ffs);

	return stream_open(inode, file);
}

static int ffs_ep0_release(struct inode *inode, struct file *file)
{
	struct ffs_data *ffs = file->private_data;

	ENTER();

	ffs_data_closed(ffs);

	return 0;
}

static long ffs_ep0_ioctl(struct file *file, unsigned code, unsigned long value)
{
	struct ffs_data *ffs = file->private_data;
	struct usb_gadget *gadget = ffs->gadget;
	long ret;

	ENTER();

	if (code == FUNCTIONFS_INTERFACE_REVMAP) {
		struct ffs_function *func = ffs->func;
		ret = func ? ffs_func_revmap_intf(func, value) : -ENODEV;
	} else if (gadget && gadget->ops->ioctl) {
		ret = gadget->ops->ioctl(gadget, code, value);
	} else {
		ret = -ENOTTY;
	}

	return ret;
}

static __poll_t ffs_ep0_poll(struct file *file, poll_table *wait)
{
	struct ffs_data *ffs = file->private_data;
	__poll_t mask = EPOLLWRNORM;
	int ret;

	poll_wait(file, &ffs->ev.waitq, wait);

	ret = ffs_mutex_lock(&ffs->mutex, file->f_flags & O_NONBLOCK);
	if (unlikely(ret < 0))
		return mask;

	switch (ffs->state) {
	case FFS_READ_DESCRIPTORS:
	case FFS_READ_STRINGS:
		mask |= EPOLLOUT;
		break;

	case FFS_ACTIVE:
		switch (ffs->setup_state) {
		case FFS_NO_SETUP:
			if (ffs->ev.count)
				mask |= EPOLLIN;
			break;

		case FFS_SETUP_PENDING:
		case FFS_SETUP_CANCELLED:
			mask |= (EPOLLIN | EPOLLOUT);
			break;
		}
	case FFS_CLOSING:
		break;
	case FFS_DEACTIVATED:
		break;
	}

	mutex_unlock(&ffs->mutex);

	return mask;
}

static const struct file_operations ffs_ep0_operations = {
	.llseek =	no_llseek,

	.open =		ffs_ep0_open,
	.write =	ffs_ep0_write,
	.read =		ffs_ep0_read,
	.release =	ffs_ep0_release,
	.unlocked_ioctl =	ffs_ep0_ioctl,
	.poll =		ffs_ep0_poll,
};


/* "Normal" endpoints operations ********************************************/

static void ffs_epfile_io_complete(struct usb_ep *_ep, struct usb_request *req)
{
	ENTER();
	if (likely(req->context)) {
		struct ffs_ep *ep = _ep->driver_data;
		ep->status = req->status ? req->status : req->actual;
		complete(req->context);
	}
}

static ssize_t ffs_copy_to_iter(void *data, int data_len, struct iov_iter *iter)
{
	ssize_t ret = copy_to_iter(data, data_len, iter);
	if (likely(ret == data_len))
		return ret;

	if (unlikely(iov_iter_count(iter)))
		return -EFAULT;

	/*
	 * Dear user space developer!
	 *
	 * TL;DR: To stop getting below error message in your kernel log, change
	 * user space code using functionfs to align read buffers to a max
	 * packet size.
	 *
	 * Some UDCs (e.g. dwc3) require request sizes to be a multiple of a max
	 * packet size.  When unaligned buffer is passed to functionfs, it
	 * internally uses a larger, aligned buffer so that such UDCs are happy.
	 *
	 * Unfortunately, this means that host may send more data than was
	 * requested in read(2) system call.  f_fs doesn’t know what to do with
	 * that excess data so it simply drops it.
	 *
	 * Was the buffer aligned in the first place, no such problem would
	 * happen.
	 *
	 * Data may be dropped only in AIO reads.  Synchronous reads are handled
	 * by splitting a request into multiple parts.  This splitting may still
	 * be a problem though so it’s likely best to align the buffer
	 * regardless of it being AIO or not..
	 *
	 * This only affects OUT endpoints, i.e. reading data with a read(2),
	 * aio_read(2) etc. system calls.  Writing data to an IN endpoint is not
	 * affected.
	 */
	pr_err("functionfs read size %d > requested size %zd, dropping excess data. "
	       "Align read buffer size to max packet size to avoid the problem.\n",
	       data_len, ret);

	return ret;
}

/*
 * allocate a virtually contiguous buffer and create a scatterlist describing it
 * @sg_table	- pointer to a place to be filled with sg_table contents
 * @size	- required buffer size
 */
static void *ffs_build_sg_list(struct sg_table *sgt, size_t sz)
{
	struct page **pages;
	void *vaddr, *ptr;
	unsigned int n_pages;
	int i;

	vaddr = vmalloc(sz);
	if (!vaddr)
		return NULL;

	n_pages = PAGE_ALIGN(sz) >> PAGE_SHIFT;
	pages = kvmalloc_array(n_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages) {
		vfree(vaddr);

		return NULL;
	}
	for (i = 0, ptr = vaddr; i < n_pages; ++i, ptr += PAGE_SIZE)
		pages[i] = vmalloc_to_page(ptr);

	if (sg_alloc_table_from_pages(sgt, pages, n_pages, 0, sz, GFP_KERNEL)) {
		kvfree(pages);
		vfree(vaddr);

		return NULL;
	}
	kvfree(pages);

	return vaddr;
}

static inline void *ffs_alloc_buffer(struct ffs_io_data *io_data,
	size_t data_len)
{
	if (io_data->use_sg)
		return ffs_build_sg_list(&io_data->sgt, data_len);

	return kmalloc(data_len, GFP_KERNEL);
}

static inline void ffs_free_buffer(struct ffs_io_data *io_data)
{
	if (!io_data->buf)
		return;

	if (io_data->use_sg) {
		sg_free_table(&io_data->sgt);
		vfree(io_data->buf);
	} else {
		kfree(io_data->buf);
	}
}

static void ffs_user_copy_worker(struct work_struct *work)
{
	struct ffs_io_data *io_data = container_of(work, struct ffs_io_data,
						   work);
	int ret = io_data->req->status ? io_data->req->status :
					 io_data->req->actual;
	bool kiocb_has_eventfd = io_data->kiocb->ki_flags & IOCB_EVENTFD;

	if (io_data->read && ret > 0) {
		kthread_use_mm(io_data->mm);
		ret = ffs_copy_to_iter(io_data->buf, ret, &io_data->data);
		kthread_unuse_mm(io_data->mm);
	}

	io_data->kiocb->ki_complete(io_data->kiocb, ret, ret);

	if (io_data->ffs->ffs_eventfd && !kiocb_has_eventfd)
		eventfd_signal(io_data->ffs->ffs_eventfd, 1);

	usb_ep_free_request(io_data->ep, io_data->req);

	if (io_data->read)
		kfree(io_data->to_free);
	ffs_free_buffer(io_data);
	kfree(io_data);
}

static void ffs_epfile_async_io_complete(struct usb_ep *_ep,
					 struct usb_request *req)
{
	struct ffs_io_data *io_data = req->context;
	struct ffs_data *ffs = io_data->ffs;

	ENTER();

	INIT_WORK(&io_data->work, ffs_user_copy_worker);
	queue_work(ffs->io_completion_wq, &io_data->work);
}

static void __ffs_epfile_read_buffer_free(struct ffs_epfile *epfile)
{
	/*
	 * See comment in struct ffs_epfile for full read_buffer pointer
	 * synchronisation story.
	 */
	struct ffs_buffer *buf = xchg(&epfile->read_buffer, READ_BUFFER_DROP);
	if (buf && buf != READ_BUFFER_DROP)
		kfree(buf);
}

/* Assumes epfile->mutex is held. */
static ssize_t __ffs_epfile_read_buffered(struct ffs_epfile *epfile,
					  struct iov_iter *iter)
{
	/*
	 * Null out epfile->read_buffer so ffs_func_eps_disable does not free
	 * the buffer while we are using it.  See comment in struct ffs_epfile
	 * for full read_buffer pointer synchronisation story.
	 */
	struct ffs_buffer *buf = xchg(&epfile->read_buffer, NULL);
	ssize_t ret;
	if (!buf || buf == READ_BUFFER_DROP)
		return 0;

	ret = copy_to_iter(buf->data, buf->length, iter);
	if (buf->length == ret) {
		kfree(buf);
		return ret;
	}

	if (unlikely(iov_iter_count(iter))) {
		ret = -EFAULT;
	} else {
		buf->length -= ret;
		buf->data += ret;
	}

	if (cmpxchg(&epfile->read_buffer, NULL, buf))
		kfree(buf);

	return ret;
}

/* Assumes epfile->mutex is held. */
static ssize_t __ffs_epfile_read_data(struct ffs_epfile *epfile,
				      void *data, int data_len,
				      struct iov_iter *iter)
{
	struct ffs_buffer *buf;

	ssize_t ret = copy_to_iter(data, data_len, iter);
	if (likely(data_len == ret))
		return ret;

	if (unlikely(iov_iter_count(iter)))
		return -EFAULT;

	/* See ffs_copy_to_iter for more context. */
	pr_warn("functionfs read size %d > requested size %zd, splitting request into multiple reads.",
		data_len, ret);

	data_len -= ret;
	buf = kmalloc(sizeof(*buf) + data_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	buf->length = data_len;
	buf->data = buf->storage;
	memcpy(buf->storage, data + ret, data_len);

	/*
	 * At this point read_buffer is NULL or READ_BUFFER_DROP (if
	 * ffs_func_eps_disable has been called in the meanwhile).  See comment
	 * in struct ffs_epfile for full read_buffer pointer synchronisation
	 * story.
	 */
	if (unlikely(cmpxchg(&epfile->read_buffer, NULL, buf)))
		kfree(buf);

	return ret;
}

static ssize_t ffs_epfile_io(struct file *file, struct ffs_io_data *io_data)
{
	struct ffs_epfile *epfile = file->private_data;
	struct usb_request *req;
	struct ffs_ep *ep;
	char *data = NULL;
	ssize_t ret, data_len = -EINVAL;
	int halt;

	/* Are we still active? */
	if (WARN_ON(epfile->ffs->state != FFS_ACTIVE))
		return -ENODEV;

	/* Wait for endpoint to be enabled */
	ep = epfile->ep;
	if (!ep) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		ret = wait_event_interruptible(
				epfile->ffs->wait, (ep = epfile->ep));
		if (ret)
			return -EINTR;
	}

	/* Do we halt? */
	halt = (!io_data->read == !epfile->in);
	if (halt && epfile->isoc)
		return -EINVAL;

	/* We will be using request and read_buffer */
	ret = ffs_mutex_lock(&epfile->mutex, file->f_flags & O_NONBLOCK);
	if (unlikely(ret))
		goto error;

	/* Allocate & copy */
	if (!halt) {
		struct usb_gadget *gadget;

		/*
		 * Do we have buffered data from previous partial read?  Check
		 * that for synchronous case only because we do not have
		 * facility to ‘wake up’ a pending asynchronous read and push
		 * buffered data to it which we would need to make things behave
		 * consistently.
		 */
		if (!io_data->aio && io_data->read) {
			ret = __ffs_epfile_read_buffered(epfile, &io_data->data);
			if (ret)
				goto error_mutex;
		}

		/*
		 * if we _do_ wait above, the epfile->ffs->gadget might be NULL
		 * before the waiting completes, so do not assign to 'gadget'
		 * earlier
		 */
		gadget = epfile->ffs->gadget;

		spin_lock_irq(&epfile->ffs->eps_lock);
		/* In the meantime, endpoint got disabled or changed. */
		if (epfile->ep != ep) {
			ret = -ESHUTDOWN;
			goto error_lock;
		}
		data_len = iov_iter_count(&io_data->data);
		/*
		 * Controller may require buffer size to be aligned to
		 * maxpacketsize of an out endpoint.
		 */
		if (io_data->read)
			data_len = usb_ep_align_maybe(gadget, ep->ep, data_len);

		io_data->use_sg = gadget->sg_supported && data_len > PAGE_SIZE;
		spin_unlock_irq(&epfile->ffs->eps_lock);

		data = ffs_alloc_buffer(io_data, data_len);
		if (unlikely(!data)) {
			ret = -ENOMEM;
			goto error_mutex;
		}
		if (!io_data->read &&
		    !copy_from_iter_full(data, data_len, &io_data->data)) {
			ret = -EFAULT;
			goto error_mutex;
		}
	}

	spin_lock_irq(&epfile->ffs->eps_lock);

	if (epfile->ep != ep) {
		/* In the meantime, endpoint got disabled or changed. */
		ret = -ESHUTDOWN;
	} else if (halt) {
		ret = usb_ep_set_halt(ep->ep);
		if (!ret)
			ret = -EBADMSG;
	} else if (unlikely(data_len == -EINVAL)) {
		/*
		 * Sanity Check: even though data_len can't be used
		 * uninitialized at the time I write this comment, some
		 * compilers complain about this situation.
		 * In order to keep the code clean from warnings, data_len is
		 * being initialized to -EINVAL during its declaration, which
		 * means we can't rely on compiler anymore to warn no future
		 * changes won't result in data_len being used uninitialized.
		 * For such reason, we're adding this redundant sanity check
		 * here.
		 */
		WARN(1, "%s: data_len == -EINVAL\n", __func__);
		ret = -EINVAL;
	} else if (!io_data->aio) {
		DECLARE_COMPLETION_ONSTACK(done);
		bool interrupted = false;

		req = ep->req;
		if (io_data->use_sg) {
			req->buf = NULL;
			req->sg	= io_data->sgt.sgl;
			req->num_sgs = io_data->sgt.nents;
		} else {
			req->buf = data;
			req->num_sgs = 0;
		}
		req->length = data_len;

		io_data->buf = data;

		req->context  = &done;
		req->complete = ffs_epfile_io_complete;

		ret = usb_ep_queue(ep->ep, req, GFP_ATOMIC);
		if (unlikely(ret < 0))
			goto error_lock;

		spin_unlock_irq(&epfile->ffs->eps_lock);

		if (unlikely(wait_for_completion_interruptible(&done))) {
			/*
			 * To avoid race condition with ffs_epfile_io_complete,
			 * dequeue the request first then check
			 * status. usb_ep_dequeue API should guarantee no race
			 * condition with req->complete callback.
			 */
			usb_ep_dequeue(ep->ep, req);
			wait_for_completion(&done);
			interrupted = ep->status < 0;
		}

		if (interrupted)
			ret = -EINTR;
		else if (io_data->read && ep->status > 0)
			ret = __ffs_epfile_read_data(epfile, data, ep->status,
						     &io_data->data);
		else
			ret = ep->status;
		goto error_mutex;
	} else if (!(req = usb_ep_alloc_request(ep->ep, GFP_ATOMIC))) {
		ret = -ENOMEM;
	} else {
		if (io_data->use_sg) {
			req->buf = NULL;
			req->sg	= io_data->sgt.sgl;
			req->num_sgs = io_data->sgt.nents;
		} else {
			req->buf = data;
			req->num_sgs = 0;
		}
		req->length = data_len;

		io_data->buf = data;
		io_data->ep = ep->ep;
		io_data->req = req;
		io_data->ffs = epfile->ffs;

		req->context  = io_data;
		req->complete = ffs_epfile_async_io_complete;

		ret = usb_ep_queue(ep->ep, req, GFP_ATOMIC);
		if (unlikely(ret)) {
			io_data->req = NULL;
			usb_ep_free_request(ep->ep, req);
			goto error_lock;
		}

		ret = -EIOCBQUEUED;
		/*
		 * Do not kfree the buffer in this function.  It will be freed
		 * by ffs_user_copy_worker.
		 */
		data = NULL;
	}

error_lock:
	spin_unlock_irq(&epfile->ffs->eps_lock);
error_mutex:
	mutex_unlock(&epfile->mutex);
error:
	if (ret != -EIOCBQUEUED) /* don't free if there is iocb queued */
		ffs_free_buffer(io_data);
	return ret;
}

static int
ffs_epfile_open(struct inode *inode, struct file *file)
{
	struct ffs_epfile *epfile = inode->i_private;

	ENTER();

	if (WARN_ON(epfile->ffs->state != FFS_ACTIVE))
		return -ENODEV;

	file->private_data = epfile;
	ffs_data_opened(epfile->ffs);

	return stream_open(inode, file);
}

static int ffs_aio_cancel(struct kiocb *kiocb)
{
	struct ffs_io_data *io_data = kiocb->private;
	struct ffs_epfile *epfile = kiocb->ki_filp->private_data;
	unsigned long flags;
	int value;

	ENTER();

	spin_lock_irqsave(&epfile->ffs->eps_lock, flags);

	if (likely(io_data && io_data->ep && io_data->req))
		value = usb_ep_dequeue(io_data->ep, io_data->req);
	else
		value = -EINVAL;

	spin_unlock_irqrestore(&epfile->ffs->eps_lock, flags);

	return value;
}

static ssize_t ffs_epfile_write_iter(struct kiocb *kiocb, struct iov_iter *from)
{
	struct ffs_io_data io_data, *p = &io_data;
	ssize_t res;

	ENTER();

	if (!is_sync_kiocb(kiocb)) {
		p = kzalloc(sizeof(io_data), GFP_KERNEL);
		if (unlikely(!p))
			return -ENOMEM;
		p->aio = true;
	} else {
		memset(p, 0, sizeof(*p));
		p->aio = false;
	}

	p->read = false;
	p->kiocb = kiocb;
	p->data = *from;
	p->mm = current->mm;

	kiocb->private = p;

	if (p->aio)
		kiocb_set_cancel_fn(kiocb, ffs_aio_cancel);

	res = ffs_epfile_io(kiocb->ki_filp, p);
	if (res == -EIOCBQUEUED)
		return res;
	if (p->aio)
		kfree(p);
	else
		*from = p->data;
	return res;
}

static ssize_t ffs_epfile_read_iter(struct kiocb *kiocb, struct iov_iter *to)
{
	struct ffs_io_data io_data, *p = &io_data;
	ssize_t res;

	ENTER();

	if (!is_sync_kiocb(kiocb)) {
		p = kzalloc(sizeof(io_data), GFP_KERNEL);
		if (unlikely(!p))
			return -ENOMEM;
		p->aio = true;
	} else {
		memset(p, 0, sizeof(*p));
		p->aio = false;
	}

	p->read = true;
	p->kiocb = kiocb;
	if (p->aio) {
		p->to_free = dup_iter(&p->data, to, GFP_KERNEL);
		if (!p->to_free) {
			kfree(p);
			return -ENOMEM;
		}
	} else {
		p->data = *to;
		p->to_free = NULL;
	}
	p->mm = current->mm;

	kiocb->private = p;

	if (p->aio)
		kiocb_set_cancel_fn(kiocb, ffs_aio_cancel);

	res = ffs_epfile_io(kiocb->ki_filp, p);
	if (res == -EIOCBQUEUED)
		return res;

	if (p->aio) {
		kfree(p->to_free);
		kfree(p);
	} else {
		*to = p->data;
	}
	return res;
}

static int
ffs_epfile_release(struct inode *inode, struct file *file)
{
	struct ffs_epfile *epfile = inode->i_private;

	ENTER();

	__ffs_epfile_read_buffer_free(epfile);
	ffs_data_closed(epfile->ffs);

	return 0;
}

static long ffs_epfile_ioctl(struct file *file, unsigned code,
			     unsigned long value)
{
	struct ffs_epfile *epfile = file->private_data;
	struct ffs_ep *ep;
	int ret;

	ENTER();

	if (WARN_ON(epfile->ffs->state != FFS_ACTIVE))
		return -ENODEV;

	/* Wait for endpoint to be enabled */
	ep = epfile->ep;
	if (!ep) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		ret = wait_event_interruptible(
				epfile->ffs->wait, (ep = epfile->ep));
		if (ret)
			return -EINTR;
	}

	spin_lock_irq(&epfile->ffs->eps_lock);

	/* In the meantime, endpoint got disabled or changed. */
	if (epfile->ep != ep) {
		spin_unlock_irq(&epfile->ffs->eps_lock);
		return -ESHUTDOWN;
	}

	switch (code) {
	case FUNCTIONFS_FIFO_STATUS:
		ret = usb_ep_fifo_status(epfile->ep->ep);
		break;
	case FUNCTIONFS_FIFO_FLUSH:
		usb_ep_fifo_flush(epfile->ep->ep);
		ret = 0;
		break;
	case FUNCTIONFS_CLEAR_HALT:
		ret = usb_ep_clear_halt(epfile->ep->ep);
		break;
	case FUNCTIONFS_ENDPOINT_REVMAP:
		ret = epfile->ep->num;
		break;
	case FUNCTIONFS_ENDPOINT_DESC:
	{
		int desc_idx;
		struct usb_endpoint_descriptor desc1, *desc;

		switch (epfile->ffs->gadget->speed) {
		case USB_SPEED_SUPER:
		case USB_SPEED_SUPER_PLUS:
			desc_idx = 2;
			break;
		case USB_SPEED_HIGH:
			desc_idx = 1;
			break;
		default:
			desc_idx = 0;
		}

		desc = epfile->ep->descs[desc_idx];
		memcpy(&desc1, desc, desc->bLength);

		spin_unlock_irq(&epfile->ffs->eps_lock);
		ret = copy_to_user((void __user *)value, &desc1, desc1.bLength);
		if (ret)
			ret = -EFAULT;
		return ret;
	}
	default:
		ret = -ENOTTY;
	}
	spin_unlock_irq(&epfile->ffs->eps_lock);

	return ret;
}

static const struct file_operations ffs_epfile_operations = {
	.llseek =	no_llseek,

	.open =		ffs_epfile_open,
	.write_iter =	ffs_epfile_write_iter,
	.read_iter =	ffs_epfile_read_iter,
	.release =	ffs_epfile_release,
	.unlocked_ioctl =	ffs_epfile_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};


/* File system and super block operations ***********************************/

/*
 * Mounting the file system creates a controller file, used first for
 * function configuration then later for event monitoring.
 */

static struct inode *__must_check
ffs_sb_make_inode(struct super_block *sb, void *data,
		  const struct file_operations *fops,
		  const struct inode_operations *iops,
		  struct ffs_file_perms *perms)
{
	struct inode *inode;

	ENTER();

	inode = new_inode(sb);

	if (likely(inode)) {
		struct timespec64 ts = current_time(inode);

		inode->i_ino	 = get_next_ino();
		inode->i_mode    = perms->mode;
		inode->i_uid     = perms->uid;
		inode->i_gid     = perms->gid;
		inode->i_atime   = ts;
		inode->i_mtime   = ts;
		inode->i_ctime   = ts;
		inode->i_private = data;
		if (fops)
			inode->i_fop = fops;
		if (iops)
			inode->i_op  = iops;
	}

	return inode;
}

/* Create "regular" file */
static struct dentry *ffs_sb_create_file(struct super_block *sb,
					const char *name, void *data,
					const struct file_operations *fops)
{
	struct ffs_data	*ffs = sb->s_fs_info;
	struct dentry	*dentry;
	struct inode	*inode;

	ENTER();

	dentry = d_alloc_name(sb->s_root, name);
	if (unlikely(!dentry))
		return NULL;

	inode = ffs_sb_make_inode(sb, data, fops, NULL, &ffs->file_perms);
	if (unlikely(!inode)) {
		dput(dentry);
		return NULL;
	}

	d_add(dentry, inode);
	return dentry;
}

/* Super block */
static const struct super_operations ffs_sb_operations = {
	.statfs =	simple_statfs,
	.drop_inode =	generic_delete_inode,
};

struct ffs_sb_fill_data {
	struct ffs_file_perms perms;
	umode_t root_mode;
	const char *dev_name;
	bool no_disconnect;
	struct ffs_data *ffs_data;
};

static int ffs_sb_fill(struct super_block *sb, struct fs_context *fc)
{
	struct ffs_sb_fill_data *data = fc->fs_private;
	struct inode	*inode;
	struct ffs_data	*ffs = data->ffs_data;

	ENTER();

	ffs->sb              = sb;
	data->ffs_data       = NULL;
	sb->s_fs_info        = ffs;
	sb->s_blocksize      = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic          = FUNCTIONFS_MAGIC;
	sb->s_op             = &ffs_sb_operations;
	sb->s_time_gran      = 1;

	/* Root inode */
	data->perms.mode = data->root_mode;
	inode = ffs_sb_make_inode(sb, NULL,
				  &simple_dir_operations,
				  &simple_dir_inode_operations,
				  &data->perms);
	sb->s_root = d_make_root(inode);
	if (unlikely(!sb->s_root))
		return -ENOMEM;

