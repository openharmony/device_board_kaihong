// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include <linux/iversion.h>

#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_defer.h"
#include "xfs_inode.h"
#include "xfs_dir2.h"
#include "xfs_attr.h"
#include "xfs_trans_space.h"
#include "xfs_trans.h"
#include "xfs_buf_item.h"
#include "xfs_inode_item.h"
#include "xfs_ialloc.h"
#include "xfs_bmap.h"
#include "xfs_bmap_util.h"
#include "xfs_errortag.h"
#include "xfs_error.h"
#include "xfs_quota.h"
#include "xfs_filestream.h"
#include "xfs_trace.h"
#include "xfs_icache.h"
#include "xfs_symlink.h"
#include "xfs_trans_priv.h"
#include "xfs_log.h"
#include "xfs_bmap_btree.h"
#include "xfs_reflink.h"

kmem_zone_t *xfs_inode_zone;

/*
 * Used in xfs_itruncate_extents().  This is the maximum number of extents
 * freed from a file in a single transaction.
 */
#define	XFS_ITRUNC_MAX_EXTENTS	2

STATIC int xfs_iunlink(struct xfs_trans *, struct xfs_inode *);
STATIC int xfs_iunlink_remove(struct xfs_trans *, struct xfs_inode *);

/*
 * helper function to extract extent size hint from inode
 */
xfs_extlen_t
xfs_get_extsz_hint(
	struct xfs_inode	*ip)
{
	/*
	 * No point in aligning allocations if we need to COW to actually
	 * write to them.
	 */
	if (xfs_is_always_cow_inode(ip))
		return 0;
	if ((ip->i_d.di_flags & XFS_DIFLAG_EXTSIZE) && ip->i_d.di_extsize)
		return ip->i_d.di_extsize;
	if (XFS_IS_REALTIME_INODE(ip))
		return ip->i_mount->m_sb.sb_rextsize;
	return 0;
}

/*
 * Helper function to extract CoW extent size hint from inode.
 * Between the extent size hint and the CoW extent size hint, we
 * return the greater of the two.  If the value is zero (automatic),
 * use the default size.
 */
xfs_extlen_t
xfs_get_cowextsz_hint(
	struct xfs_inode	*ip)
{
	xfs_extlen_t		a, b;

	a = 0;
	if (ip->i_d.di_flags2 & XFS_DIFLAG2_COWEXTSIZE)
		a = ip->i_d.di_cowextsize;
	b = xfs_get_extsz_hint(ip);

	a = max(a, b);
	if (a == 0)
		return XFS_DEFAULT_COWEXTSZ_HINT;
	return a;
}

/*
 * These two are wrapper routines around the xfs_ilock() routine used to
 * centralize some grungy code.  They are used in places that wish to lock the
 * inode solely for reading the extents.  The reason these places can't just
 * call xfs_ilock(ip, XFS_ILOCK_SHARED) is that the inode lock also guards to
 * bringing in of the extents from disk for a file in b-tree format.  If the
 * inode is in b-tree format, then we need to lock the inode exclusively until
 * the extents are read in.  Locking it exclusively all the time would limit
 * our parallelism unnecessarily, though.  What we do instead is check to see
 * if the extents have been read in yet, and only lock the inode exclusively
 * if they have not.
 *
 * The functions return a value which should be given to the corresponding
 * xfs_iunlock() call.
 */
uint
xfs_ilock_data_map_shared(
	struct xfs_inode	*ip)
{
	uint			lock_mode = XFS_ILOCK_SHARED;

	if (ip->i_df.if_format == XFS_DINODE_FMT_BTREE &&
	    (ip->i_df.if_flags & XFS_IFEXTENTS) == 0)
		lock_mode = XFS_ILOCK_EXCL;
	xfs_ilock(ip, lock_mode);
	return lock_mode;
}

uint
xfs_ilock_attr_map_shared(
	struct xfs_inode	*ip)
{
	uint			lock_mode = XFS_ILOCK_SHARED;

	if (ip->i_afp &&
	    ip->i_afp->if_format == XFS_DINODE_FMT_BTREE &&
	    (ip->i_afp->if_flags & XFS_IFEXTENTS) == 0)
		lock_mode = XFS_ILOCK_EXCL;
	xfs_ilock(ip, lock_mode);
	return lock_mode;
}

/*
 * In addition to i_rwsem in the VFS inode, the xfs inode contains 2
 * multi-reader locks: i_mmap_lock and the i_lock.  This routine allows
 * various combinations of the locks to be obtained.
 *
 * The 3 locks should always be ordered so that the IO lock is obtained first,
 * the mmap lock second and the ilock last in order to prevent deadlock.
 *
 * Basic locking order:
 *
 * i_rwsem -> i_mmap_lock -> page_lock -> i_ilock
 *
 * mmap_lock locking order:
 *
 * i_rwsem -> page lock -> mmap_lock
 * mmap_lock -> i_mmap_lock -> page_lock
 *
 * The difference in mmap_lock locking order mean that we cannot hold the
 * i_mmap_lock over syscall based read(2)/write(2) based IO. These IO paths can
 * fault in pages during copy in/out (for buffered IO) or require the mmap_lock
 * in get_user_pages() to map the user pages into the kernel address space for
 * direct IO. Similarly the i_rwsem cannot be taken inside a page fault because
 * page faults already hold the mmap_lock.
 *
 * Hence to serialise fully against both syscall and mmap based IO, we need to
 * take both the i_rwsem and the i_mmap_lock. These locks should *only* be both
 * taken in places where we need to invalidate the page cache in a race
 * free manner (e.g. truncate, hole punch and other extent manipulation
 * functions).
 */
void
xfs_ilock(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	trace_xfs_ilock(ip, lock_flags, _RET_IP_);

	/*
	 * You can't set both SHARED and EXCL for the same lock,
	 * and only XFS_IOLOCK_SHARED, XFS_IOLOCK_EXCL, XFS_ILOCK_SHARED,
	 * and XFS_ILOCK_EXCL are valid values to set in lock_flags.
	 */
	ASSERT((lock_flags & (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL)) !=
	       (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL));
	ASSERT((lock_flags & (XFS_MMAPLOCK_SHARED | XFS_MMAPLOCK_EXCL)) !=
	       (XFS_MMAPLOCK_SHARED | XFS_MMAPLOCK_EXCL));
	ASSERT((lock_flags & (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL)) !=
	       (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL));
	ASSERT((lock_flags & ~(XFS_LOCK_MASK | XFS_LOCK_SUBCLASS_MASK)) == 0);

	if (lock_flags & XFS_IOLOCK_EXCL) {
		down_write_nested(&VFS_I(ip)->i_rwsem,
				  XFS_IOLOCK_DEP(lock_flags));
	} else if (lock_flags & XFS_IOLOCK_SHARED) {
		down_read_nested(&VFS_I(ip)->i_rwsem,
				 XFS_IOLOCK_DEP(lock_flags));
	}

	if (lock_flags & XFS_MMAPLOCK_EXCL)
		mrupdate_nested(&ip->i_mmaplock, XFS_MMAPLOCK_DEP(lock_flags));
	else if (lock_flags & XFS_MMAPLOCK_SHARED)
		mraccess_nested(&ip->i_mmaplock, XFS_MMAPLOCK_DEP(lock_flags));

	if (lock_flags & XFS_ILOCK_EXCL)
		mrupdate_nested(&ip->i_lock, XFS_ILOCK_DEP(lock_flags));
	else if (lock_flags & XFS_ILOCK_SHARED)
		mraccess_nested(&ip->i_lock, XFS_ILOCK_DEP(lock_flags));
}

/*
 * This is just like xfs_ilock(), except that the caller
 * is guaranteed not to sleep.  It returns 1 if it gets
 * the requested locks and 0 otherwise.  If the IO lock is
 * obtained but the inode lock cannot be, then the IO lock
 * is dropped before returning.
 *
 * ip -- the inode being locked
 * lock_flags -- this parameter indicates the inode's locks to be
 *       to be locked.  See the comment for xfs_ilock() for a list
 *	 of valid values.
 */
int
xfs_ilock_nowait(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	trace_xfs_ilock_nowait(ip, lock_flags, _RET_IP_);

	/*
	 * You can't set both SHARED and EXCL for the same lock,
	 * and only XFS_IOLOCK_SHARED, XFS_IOLOCK_EXCL, XFS_ILOCK_SHARED,
	 * and XFS_ILOCK_EXCL are valid values to set in lock_flags.
	 */
	ASSERT((lock_flags & (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL)) !=
	       (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL));
	ASSERT((lock_flags & (XFS_MMAPLOCK_SHARED | XFS_MMAPLOCK_EXCL)) !=
	       (XFS_MMAPLOCK_SHARED | XFS_MMAPLOCK_EXCL));
	ASSERT((lock_flags & (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL)) !=
	       (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL));
	ASSERT((lock_flags & ~(XFS_LOCK_MASK | XFS_LOCK_SUBCLASS_MASK)) == 0);

	if (lock_flags & XFS_IOLOCK_EXCL) {
		if (!down_write_trylock(&VFS_I(ip)->i_rwsem))
			goto out;
	} else if (lock_flags & XFS_IOLOCK_SHARED) {
		if (!down_read_trylock(&VFS_I(ip)->i_rwsem))
			goto out;
	}

	if (lock_flags & XFS_MMAPLOCK_EXCL) {
		if (!mrtryupdate(&ip->i_mmaplock))
			goto out_undo_iolock;
	} else if (lock_flags & XFS_MMAPLOCK_SHARED) {
		if (!mrtryaccess(&ip->i_mmaplock))
			goto out_undo_iolock;
	}

	if (lock_flags & XFS_ILOCK_EXCL) {
		if (!mrtryupdate(&ip->i_lock))
			goto out_undo_mmaplock;
	} else if (lock_flags & XFS_ILOCK_SHARED) {
		if (!mrtryaccess(&ip->i_lock))
			goto out_undo_mmaplock;
	}
	return 1;

out_undo_mmaplock:
	if (lock_flags & XFS_MMAPLOCK_EXCL)
		mrunlock_excl(&ip->i_mmaplock);
	else if (lock_flags & XFS_MMAPLOCK_SHARED)
		mrunlock_shared(&ip->i_mmaplock);
out_undo_iolock:
	if (lock_flags & XFS_IOLOCK_EXCL)
		up_write(&VFS_I(ip)->i_rwsem);
	else if (lock_flags & XFS_IOLOCK_SHARED)
		up_read(&VFS_I(ip)->i_rwsem);
out:
	return 0;
}

/*
 * xfs_iunlock() is used to drop the inode locks acquired with
 * xfs_ilock() and xfs_ilock_nowait().  The caller must pass
 * in the flags given to xfs_ilock() or xfs_ilock_nowait() so
 * that we know which locks to drop.
 *
 * ip -- the inode being unlocked
 * lock_flags -- this parameter indicates the inode's locks to be
 *       to be unlocked.  See the comment for xfs_ilock() for a list
 *	 of valid values for this parameter.
 *
 */
void
xfs_iunlock(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	/*
	 * You can't set both SHARED and EXCL for the same lock,
	 * and only XFS_IOLOCK_SHARED, XFS_IOLOCK_EXCL, XFS_ILOCK_SHARED,
	 * and XFS_ILOCK_EXCL are valid values to set in lock_flags.
	 */
	ASSERT((lock_flags & (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL)) !=
	       (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL));
	ASSERT((lock_flags & (XFS_MMAPLOCK_SHARED | XFS_MMAPLOCK_EXCL)) !=
	       (XFS_MMAPLOCK_SHARED | XFS_MMAPLOCK_EXCL));
	ASSERT((lock_flags & (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL)) !=
	       (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL));
	ASSERT((lock_flags & ~(XFS_LOCK_MASK | XFS_LOCK_SUBCLASS_MASK)) == 0);
	ASSERT(lock_flags != 0);

	if (lock_flags & XFS_IOLOCK_EXCL)
		up_write(&VFS_I(ip)->i_rwsem);
	else if (lock_flags & XFS_IOLOCK_SHARED)
		up_read(&VFS_I(ip)->i_rwsem);
