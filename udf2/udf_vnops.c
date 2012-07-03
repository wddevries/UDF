/*-
 * Copyright (c) 2012 Will DeVries
 * Copyright (c) 2006, 2008 Reinoud Zandijk
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * Generic parts are derived from software contributed to The NetBSD Foundation
 * by Julio M. Merino Vidal, developed as part of Google's Summer of Code
 * 2005 program.
 *
 */

#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/endian.h>
#include <sys/systm.h> /* printf, bzero, etc */
#include <sys/namei.h> /* componentname */
#include <sys/buf.h> /* buf */
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/unistd.h> /* udf_pathconf */
#include <sys/bio.h>

#include "ecma167-udf.h"
#include "udf.h"
#include "udf_subr.h"


static vop_access_t	udf_access;
static vop_bmap_t       udf_bmap;
static vop_cachedlookup_t udf_cachedlookup;
static vop_getattr_t	udf_getattr;
static vop_ioctl_t      udf_ioctl;
static vop_open_t	udf_open;
static vop_pathconf_t   udf_pathconf;
static vop_print_t      udf_print;
static vop_read_t       udf_read;
static vop_readdir_t    udf_readdir;
static vop_readlink_t   udf_readlink;
static vop_reclaim_t    udf_reclaim;
static vop_setattr_t    udf_setattr;
static vop_strategy_t   udf_strategy;
static vop_vptofh_t     udf_vptofh;

static struct vop_vector udf_vnodeops = {
	.vop_default =		&default_vnodeops,
	.vop_access =		udf_access,
	.vop_getattr =		udf_getattr,
	.vop_open =		udf_open,
	.vop_ioctl =		udf_ioctl,
	.vop_pathconf =		udf_pathconf,
	.vop_print =		udf_print,
	.vop_read =		udf_read,
	.vop_readdir =		udf_readdir,
	.vop_readlink =		udf_readlink,
	.vop_setattr =		udf_setattr,
	.vop_strategy =		udf_strategy,
	.vop_bmap =		udf_bmap,
	.vop_cachedlookup =	udf_cachedlookup,
	.vop_reclaim =		udf_reclaim,
	.vop_vptofh =		udf_vptofh,
	.vop_lookup =		vfs_cache_lookup,
};

struct vop_vector udf_fifoops = {
	.vop_access =	udf_access,
	.vop_getattr =	udf_getattr,
	.vop_print =	udf_print,
	.vop_setattr =	udf_setattr,
	.vop_reclaim =	udf_reclaim,
	.vop_vptofh =	udf_vptofh,
	.vop_default =	&fifo_specops,
};

/* implementations of vnode functions; table follows at end */
/* --------------------------------------------------------------------- */

int
udf_getanode(struct mount *mp, struct vnode **vpp)
{
	return (getnewvnode("udf2", mp, &udf_vnodeops, vpp));
}


#if 0 
int
udf_inactive(void *v)
{
	struct vop_inactive_args /* {
		struct vnode *a_vp;
		bool         *a_recycle;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct udf_node *udf_node = VTOI(vp);
	int refcnt;

	DPRINTF(NODE, ("udf_inactive called for udf_node %p\n", VTOI(vp)));

	if (udf_node == NULL) {
		DPRINTF(NODE, ("udf_inactive: inactive NULL UDF node\n"));
		VOP_UNLOCK(vp);
		return (0);
	}

	/*
	 * Optionally flush metadata to disc. If the file has not been
	 * referenced anymore in a directory we ought to free up the resources
	 * on disc if applicable.
	 */
	if (udf_node->fe) {
		refcnt = le16toh(udf_node->fe->link_cnt);
	} else {
		assert(udf_node->efe);
		refcnt = le16toh(udf_node->efe->link_cnt);
	}

	if ((refcnt == 0) && (vp->v_vflag & VV_SYSTEM)) {
		DPRINTF(VOLUMES, ("UDF_INACTIVE deleting VV_SYSTEM\n"));
		/* system nodes are not writen out on inactive, so flush */
		udf_node->i_flags = 0;
	}

	*ap->a_recycle = false;
	if ((refcnt == 0) && ((vp->v_vflag & VV_SYSTEM) == 0)) {
	 	/* remove this file's allocation */
		DPRINTF(NODE, ("udf_inactive deleting unlinked file\n"));
		*ap->a_recycle = true;
		udf_delete_node(udf_node);
		VOP_UNLOCK(vp);
		vrecycle(vp, NULL, curlwp);
		return (0);
	}

	/* write out its node */
	if (udf_node->i_flags & (IN_CHANGE | IN_UPDATE | IN_MODIFIED))
		udf_update(vp, NULL, NULL, NULL, 0);
	VOP_UNLOCK(vp);

	return (0);
}
#endif
/* --------------------------------------------------------------------- */


static int
udf_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct udf_node *udf_node = VTOI(vp);

	vnode_destroy_vobject(vp);

	if (udf_node == NULL)
		return (0);
#if 0
	/* update note for closure */
	udf_update(vp, NULL, NULL, NULL, UPDATE_CLOSE);

	/* async check to see if all node descriptors are written out */
	while ((volatile int) udf_node->outstanding_nodedscr > 0) {
		vprint("udf_reclaim(): waiting for writeout\n", vp);
		tsleep(&udf_node->outstanding_nodedscr, PRIBIO, "recl wait", hz/8);
	}

	/* purge old data from namei */
	cache_purge(vp);
#endif
	/* dispose all node knowledge */
	vfs_hash_remove(vp);
	udf_dispose_node(udf_node);
	vp->v_data = NULL;

	return (0);
}

/* --------------------------------------------------------------------- */
static int
udf_read(struct vop_read_args *ap)
{
	struct vnode *vp     = ap->a_vp;
	struct uio *uio    = ap->a_uio;
	struct buf *bp;
	struct udf_node *udf_node = VTOI(vp);
	uint64_t file_size;
	int on, n, lbn; 
	int error = 0;

	/* can this happen? some filingsystems have this check */
	if (uio->uio_offset < 0)
		return (EINVAL);
	if (uio->uio_resid == 0)
		return (0);

#ifdef INVARIANTS
	/* As in ffs_read() */
	if (vp->v_type != VDIR && vp->v_type != VREG)
		panic("udf_read: type %d",  vp->v_type);
#endif

	/* get file/directory filesize */
	if (udf_node->fe)
		file_size = le64toh(udf_node->fe->inf_len);
	else 
		file_size = le64toh(udf_node->efe->inf_len);

	/* read contents using buffercache */
	while (error == 0 && uio->uio_resid > 0) {
		/* reached end? */
		if (file_size <= uio->uio_offset)
			break;

		n = min(file_size - uio->uio_offset, uio->uio_resid);

 		lbn = uio->uio_offset / udf_node->ump->sector_size;
		on = uio->uio_offset % udf_node->ump->sector_size;
		n = min(udf_node->ump->sector_size - on, uio->uio_resid);
		n = min(n, file_size - uio->uio_offset);
		error = bread(vp, lbn, udf_node->ump->sector_size, NOCRED, &bp);
		n = min(n, udf_node->ump->sector_size - bp->b_resid);
		if (!error) 
			error = uiomove(bp->b_data + on, n, uio);

		brelse(bp);
	}

#if 0
	/* note access time unless not requested */
	if (!(vp->v_mount->mnt_flag & MNT_NOATIME)) {
		udf_node->i_flags |= IN_ACCESS;
		if ((ioflag & IO_SYNC) == IO_SYNC)
			error = udf_update(vp, NULL, NULL, NULL, UPDATE_WAIT);
	}
#endif

	return (error);
}
/* --------------------------------------------------------------------- */
#if 0
int
udf_write(void *v)
{
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct vnode *vp     = ap->a_vp;
	struct uio   *uio    = ap->a_uio;
	int           ioflag = ap->a_ioflag;
	kauth_cred_t  cred   = ap->a_cred;
	int           advice = IO_ADV_DECODE(ap->a_ioflag);
	struct uvm_object    *uobj;
	struct udf_node      *udf_node = VTOI(vp);
	struct file_entry    *fe;
	struct extfile_entry *efe;
	uint64_t file_size, old_size, old_offset;
	vsize_t len;
	int async = vp->v_mount->mnt_flag & MNT_ASYNC;
	int aflag = ioflag & IO_SYNC ? B_SYNC : 0;
	int error;
	int resid, extended;

	/*
	 * XXX writing to extended attributes not yet implemented. FreeBSD has
	 * it in mind to forward the IO_EXT read call to the
	 * VOP_READEXTATTR().
	 */

	DPRINTF(WRITE, ("udf_write called\n"));

	/* can this happen? some filingsystems have this check */
	if (uio->uio_offset < 0)
		return (EINVAL);
	if (uio->uio_resid == 0)
		return (0);

	/* protect against rogue programs writing raw directories or links */
	if ((ioflag & IO_ALTSEMANTICS) == 0) {
		if (vp->v_type == VDIR)
			return (EISDIR);
		/* all but regular files just give EINVAL for now */
		if (vp->v_type != VREG)
			return (EINVAL);
	}

	assert(udf_node);
	assert(udf_node->fe || udf_node->efe);

	/* get file/directory filesize */
	if (udf_node->fe) {
		fe = udf_node->fe;
		file_size = le64toh(fe->inf_len);
	} else {
		assert(udf_node->efe);
		efe = udf_node->efe;
		file_size = le64toh(efe->inf_len);
	}
	old_size = file_size;

	/* if explicitly asked to append, uio_offset can be wrong? */
	if (ioflag & IO_APPEND)
		uio->uio_offset = file_size;

	extended = (uio->uio_offset + uio->uio_resid > file_size);
	if (extended) {
		DPRINTF(WRITE, ("extending file from %"PRIu64" to %"PRIu64"\n",
			file_size, uio->uio_offset + uio->uio_resid));
		error = udf_grow_node(udf_node, uio->uio_offset + uio->uio_resid);
		if (error)
			return (error);
		file_size = uio->uio_offset + uio->uio_resid;
	}

	/* write contents using buffercache */
	uobj = &vp->v_uobj;
	resid = uio->uio_resid;
	error = 0;

	uvm_vnp_setwritesize(vp, file_size);
	old_offset = uio->uio_offset;
	while (uio->uio_resid > 0) {
		/* maximise length to file extremity */
		len = MIN(file_size - uio->uio_offset, uio->uio_resid);
		if (len == 0)
			break;

		genfs_node_wrlock(vp);
		error = GOP_ALLOC(vp, uio->uio_offset, len, aflag, cred);
		genfs_node_unlock(vp);
		if (error)
			break;

		/* ubc, here we come, prepare to trap */
		error = ubc_uiomove(uobj, uio, len, advice,
		    UBC_WRITE | UBC_UNMAP_FLAG(vp));
		if (error)
			break;

		/*
		 * flush what we just wrote if necessary.
		 * XXXUBC simplistic async flushing.
		 *
		 * Directories are excluded since its file data that we want
		 * to purge.
		 */
		if (!async && (vp->v_type != VDIR) &&
		  (old_offset >> 16 != uio->uio_offset >> 16)) {
			mutex_enter(&vp->v_interlock);
			error = VOP_PUTPAGES(vp, (old_offset >> 16) << 16,
			    (uio->uio_offset >> 16) << 16, PGO_CLEANIT);
			old_offset = uio->uio_offset;
		}
	}
	uvm_vnp_setsize(vp, file_size);

	/* mark node changed and request update */
	udf_node->i_flags |= IN_CHANGE | IN_UPDATE;

	/*
	 * XXX TODO FFS has code here to reset setuid & setgid when we're not
	 * the superuser as a precaution against tampering.
	 */

	/* if we wrote a thing, note write action on vnode */
	if (resid > uio->uio_resid)
		VN_KNOTE(vp, NOTE_WRITE | (extended ? NOTE_EXTEND : 0));

	if (error) {
		/* bring back file size to its former size */
		/* take notice of its errors? */
		(void) udf_chsize(vp, (u_quad_t) old_size, cred);

		/* roll back uio */
		uio->uio_offset -= resid - uio->uio_resid;
		uio->uio_resid = resid;
	} else {
		/* if we write and we're synchronous, update node */
		if ((resid > uio->uio_resid) && ((ioflag & IO_SYNC) == IO_SYNC))
			error = udf_update(vp, NULL, NULL, NULL, UPDATE_WAIT);
	}

	return (error);
}
#endif

/* --------------------------------------------------------------------- */
static int
udf_bmap(struct vop_bmap_args /* {
		struct vop_generic_args a_gen;
		struct vnode *a_vp;
		daddr_t a_bn;
		struct bufobj **a_bop;
		daddr_t *a_bnp;
		int *a_runp;
		int *a_runb;
	 } */ *ap)
{
	struct vnode  *vp  = ap->a_vp;	/* our node	*/
	struct udf_node *udf_node = VTOI(vp);
	uint64_t lsector;
	int exttype, error;
	uint32_t maxblks;

	if (ap->a_bop != NULL)
		*ap->a_bop = udf_node->ump->bo;

	if (ap->a_bnp == NULL)
		return (0);

	/* get logical block and run */
	error = udf_bmap_translate(udf_node, ap->a_bn, &exttype, &lsector,
	    &maxblks);
	if (error)
		return (error);

	/* convert to dev blocks */
	if (exttype == UDF_TRAN_INTERN)
		return (EOPNOTSUPP);
	else if (exttype == UDF_TRAN_ZERO)
		*ap->a_bnp = -1; /* zero the buffer */
	else
		*ap->a_bnp = lsector * (udf_node->ump->sector_size/DEV_BSIZE);

	/* set runlength of maximum block size */
	if (ap->a_runp)
		*ap->a_runp = 0;

	if (ap->a_runb) 
		*ap->a_runb = 0;

	/* return success */
	return (0);
}

static int
udf_strategy(struct vop_strategy_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct buf   *bp = ap->a_bp;
	struct udf_node *udf_node = VTOI(vp);
	struct bufobj *bo = udf_node->ump->bo;
	uint64_t lsector;
	int exttype, error;
	uint32_t lb_size, from, sectors;
	uint32_t maxblks;

	if (vp->v_type == VBLK || vp->v_type == VCHR)
		panic("udf_strategy: spec");

	/* get sector size */
	lb_size = udf_node->ump->sector_size;
	from = bp->b_blkno;
	sectors = bp->b_bcount / lb_size;

	/* get logical block and run */
	error = udf_bmap_translate(udf_node, bp->b_lblkno, &exttype, &lsector,
	    &maxblks);
	if (error) {
		bp->b_error  = error;
		bufdone(bp);
		return (error);
	}

	if (bp->b_iocmd & BIO_READ) {
		if (exttype == UDF_TRAN_ZERO) {
			memset(bp->b_data, 0, lb_size);
			if ((bp->b_flags & B_ASYNC) == 0)
				bufwait(bp);
		} else if (exttype == UDF_TRAN_INTERN) {
			error = udf_read_internal(udf_node, (uint8_t *) bp->b_data);
			if (error)
				bp->b_error  = error;
			bufdone(bp);
			if ((bp->b_flags & B_ASYNC) == 0)
				bufwait(bp);
		} else {
			bp->b_blkno = lsector * (udf_node->ump->sector_size/DEV_BSIZE);
			bp->b_iooffset = dbtob(bp->b_blkno);
			BO_STRATEGY(bo, bp);
		}
	} else {
		return (ENOTSUP);
	}

	return (bp->b_error);
}


/* --------------------------------------------------------------------- */
/* TODO: Needs lots of work */
static int
udf_readdir(struct vop_readdir_args /* {
                struct vnode *a_vp;
                struct uio *a_uio;
                struct ucred *a_cred;
                int *a_eofflag;
                int *a_ncookies;
                u_long **a_cookies;
        } */ *ap)
{
	struct uio *uio;
	struct vnode *vp;
	struct file_entry *fe;
	struct extfile_entry *efe;
	struct fileid_desc *fid;
	struct dirent *dirent;
	struct udf_mount *ump;
	struct udf_node *udf_node;
	uint64_t *cookiesp, *cookies, cookie;
	uint64_t file_size, diroffset, transoffset;
	int ncookies, acookies;
	int error;
	uint32_t lb_size;
	uint8_t *fid_name;
	
	uio = ap->a_uio;
	vp = ap->a_vp;
	udf_node = VTOI(vp);
	ump = udf_node->ump;

	/* This operation only makes sense on directory nodes. */
	if (vp->v_type != VDIR)
		return (ENOTDIR);

	/* get directory filesize */
	if (udf_node->fe) {
		fe = udf_node->fe;
		file_size = le64toh(fe->inf_len);
	} else {
		efe = udf_node->efe;
		file_size = le64toh(efe->inf_len);
	}

	dirent = malloc(sizeof(struct dirent), M_UDFTEMP, M_WAITOK | M_ZERO);
	if (ap->a_ncookies != NULL) {
		/* is this the max number possible? */
		ncookies = uio->uio_resid / 8;
		cookies = malloc(sizeof(u_long) * ncookies, M_UDFTEMP, 
		    M_WAITOK | M_ZERO);
		if (cookies == NULL)
			return (ENOMEM);
		cookiesp = cookies;
	} else {
		ncookies = 0;
		cookies = NULL;
		cookiesp = NULL;
	}
	acookies = 0;

	/*
	 * Add `.' pseudo entry if at offset zero since its not in the fid
	 * stream
	 */
	if (uio->uio_offset == 0) {
		memset(dirent, 0, sizeof(struct dirent));
		dirent->d_fileno = udf_get_node_id(&udf_node->loc);
		dirent->d_type = DT_DIR;
		dirent->d_name[0] = '.';
		dirent->d_name[1] = '\0';
		dirent->d_namlen = 1;
		dirent->d_reclen = GENERIC_DIRSIZ(dirent);
		if (cookiesp) {
			acookies++;
			*cookiesp++ = 1;
		}
		error = uiomove(dirent, GENERIC_DIRSIZ(dirent), uio);
		if (error)
			goto bail;

		/* mark with magic value that we have done the dummy */
		uio->uio_offset = UDF_DIRCOOKIE_DOT;
	}

	/* we are called just as long as we keep on pushing data in */
	error = 0;
	if (uio->uio_offset < file_size) {
		/* allocate temporary space for fid */
		lb_size = le32toh(udf_node->ump->logical_vol->lb_size);
		fid = malloc(lb_size, M_UDFTEMP, M_WAITOK);

		if (uio->uio_offset == UDF_DIRCOOKIE_DOT)
			uio->uio_offset = 0;

		diroffset   = uio->uio_offset;
		transoffset = diroffset;
		while (diroffset < file_size) {
			/* transfer a new fid/dirent */
			error = udf_read_fid_stream(vp, &diroffset, fid);
			if (error) {
				printf("Read error in read fid: %d\n", error);
				break;
			}
			
			/*
			 * create resulting dirent structure 
			 */
			memset(dirent, 0, sizeof(struct dirent));
			dirent->d_fileno = udf_get_node_id(&fid->icb);	/* inode hash XXX */

			/* Not worth trying to go for the filetypes now, too expensive */
			dirent->d_type = DT_UNKNOWN;
			if (fid->file_char & UDF_FILE_CHAR_DIR)
				dirent->d_type = DT_DIR;

			/* '..' has no name, so provide one */
			if (fid->file_char & UDF_FILE_CHAR_PAR) {
				dirent->d_name[0] = '.';
				dirent->d_name[1] = '.';
				dirent->d_name[2] = '\0';
				dirent->d_namlen = 2;
				cookie = 2;
			}
			else {
				fid_name = fid->data + le16toh(fid->l_iu);
				udf_to_unix_name(ump, dirent->d_name, MAXNAMLEN,
				    fid_name, fid->l_fi);
				dirent->d_namlen = strlen(dirent->d_name);
				cookie = transoffset;
			}
			dirent->d_reclen = GENERIC_DIRSIZ(dirent);

			/* 
			 * If there isn't enough space in the uio to return a
			 * whole dirent, break off read
			 */
			if (uio->uio_resid < GENERIC_DIRSIZ(dirent))
				break;

			/* remember the last entry we transfered */
			transoffset = diroffset;

			/* skip deleted entries */
			if (fid->file_char & UDF_FILE_CHAR_DEL)
				continue;

			/* skip not visible files */
			if (fid->file_char & UDF_FILE_CHAR_VIS)
				continue;

			/* copy dirent to the caller */
			if (cookiesp) {
				/*
				if (++acookies >= ncookies)
					break; 
				*/
				acookies++;
				*cookiesp++ = cookie;
			}
			error = uiomove(dirent, GENERIC_DIRSIZ(dirent), uio);
			if (error)
				break;
		}

		/* pass on last transfered offset */
		/* We lied for '.', so tell more lies. */
		uio->uio_offset = transoffset; 
		free(fid, M_UDFTEMP);
	}

bail:
	*ap->a_eofflag = (uio->uio_offset >= file_size);

	if (ap->a_ncookies != NULL) {
		if (error) {
			free(cookies, M_UDFTEMP);
		} else {
			*ap->a_ncookies = acookies;
			*ap->a_cookies = cookies;
		}
	}
	free(dirent, M_UDFTEMP);

	return (error);
}

/* --------------------------------------------------------------------- */

static int
udf_cachedlookup(struct vop_cachedlookup_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct vnode *tdp = NULL;
	struct componentname *cnp = ap->a_cnp;
	struct fileid_desc *fid;
	struct udf_node  *dir_node; 
	struct udf_mount *ump;
	uint64_t file_size, offset;
	ino_t id = 0;
	int nameiop, islastcn, mounted_ro, numpasses;
	int unix_len, ltype;
	int error = 0;
	uint8_t *fid_name;
	char *unix_name;

	dir_node = VTOI(dvp);
	ump = dir_node->ump;
	*vpp = NULL;

	/* simplify/clarification flags */
	nameiop     = cnp->cn_nameiop;
	islastcn    = cnp->cn_flags & ISLASTCN;
	mounted_ro  = dvp->v_mount->mnt_flag & MNT_RDONLY;

	/*
	 * If requesting a modify on the last path element on a read-only
	 * filingsystem, reject lookup; XXX why is this repeated in every FS ?
	 */
	if (islastcn && mounted_ro && (nameiop == DELETE || nameiop == RENAME))
		return (EROFS);

	/* get directory filesize */
	if (dir_node->fe)
		file_size = le64toh(dir_node->fe->inf_len);
	else
		file_size = le64toh(dir_node->efe->inf_len);

	/* 
	 * 
	 */
	if (nameiop != LOOKUP || dir_node->diroff == 0 || dir_node->diroff > file_size) {
		offset = 0;
		numpasses = 1;
	}
	else {
		offset = dir_node->diroff;
		numpasses = 2;
		nchstats.ncs_2passes++;
	}

	fid = malloc(ump->sector_size, M_UDFTEMP, M_WAITOK);
	unix_name = malloc(MAXNAMLEN, M_UDFTEMP, M_WAITOK);
lookuploop:
	while (offset < file_size) {
		error = udf_read_fid_stream(dvp, &offset, fid);
		if (error) {
			break;
		}

		/* skip deleted entries */
		if (fid->file_char & UDF_FILE_CHAR_DEL)
			continue;

		/* skip not visible files */
		if (fid->file_char & UDF_FILE_CHAR_VIS)
			continue;
		
		if (fid->file_char & UDF_FILE_CHAR_PAR) {
			if (cnp->cn_flags & ISDOTDOT) {
				id = udf_get_node_id(&fid->icb);
				break;
			}
		}
		else {
			fid_name = fid->data + le16toh(fid->l_iu);
			udf_to_unix_name(ump, unix_name, MAXNAMLEN, fid_name,
			    fid->l_fi);
			unix_len = strlen(unix_name);

			if (unix_len == cnp->cn_namelen) {
				if (!strncmp(unix_name, cnp->cn_nameptr, cnp->cn_namelen)) {
					id = udf_get_node_id(&fid->icb);
					break;
				}
			}
		}
	}

	if (error)
		goto exit; 

	if (id) {
		if ((cnp->cn_flags & ISLASTCN) && cnp->cn_nameiop == LOOKUP)
			dir_node->diroff = offset;
		if (numpasses == 2)
			nchstats.ncs_pass2++;

		if (cnp->cn_flags & ISDOTDOT) {
			vn_vget_ino(dvp, id, cnp->cn_lkflags, &tdp);
		}
		else if (dir_node->hash_id == id) {
			/* through a glass darkly... */
			VREF(dvp);
			ltype = cnp->cn_lkflags & LK_TYPE_MASK;
			if (ltype != VOP_ISLOCKED(dvp)) {
				if (ltype == LK_EXCLUSIVE)
					vn_lock(dvp, LK_UPGRADE | LK_RETRY);
				else
					vn_lock(dvp, LK_DOWNGRADE | LK_RETRY);
			}
			tdp = dvp;
		}
		else {
			error = udf_vget(ump->vfs_mountp, id, cnp->cn_lkflags, &tdp);
		}

		if (!error) {
			*vpp = tdp;
			if (cnp->cn_flags & MAKEENTRY) 
				cache_enter(dvp, *vpp, cnp);
		}
	}
	else {
		if (numpasses-- == 2) {
			offset = 0;
			goto lookuploop;
		}

		if (cnp->cn_flags & MAKEENTRY)
			cache_enter(dvp, *vpp, cnp);

		if ((cnp->cn_flags & ISLASTCN) && 
		    (cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME))
			error = EROFS;
		else 
			error = ENOENT;
	}

exit:
	free(fid, M_UDFTEMP);
	free(unix_name, M_UDFTEMP);

	return (error);
#if 0
	not sure if anything like this would be needed.
	if ((cnp->cn_namelen == 1) && (cnp->cn_nameptr[0] == '.')) {
		DPRINTF(LOOKUP, ("\tlookup '.'\n"));
		/* special case 1 '.' */
		vref(dvp);
		*vpp = dvp;
		/* done */
	}
#endif
}

/* --------------------------------------------------------------------- */
/* This is finished */
static int
udf_getattr(struct vop_getattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct udf_node *udf_node = VTOI(vp);
	struct file_entry    *fe  = udf_node->fe;
	struct extfile_entry *efe = udf_node->efe;
	struct filetimes_extattr_entry *ft_extattr;
	struct device_extattr_entry *devattr;
	struct vattr *vap = ap->a_vap;
	struct timestamp *atime, *mtime, *attrtime, *creatime;
	struct udf_mount *ump = udf_node->ump;
	uint64_t filesize, blkssize;
	gid_t gid;
	int error;
	uid_t uid;
	uint32_t nlink;
	uint32_t offset, a_l;
	uint8_t *filedata;

	/* update times before we returning values */ 
#if 0
	udf_itimes(udf_node, NULL, NULL, NULL);
#endif

	/* get descriptor information */
	if (fe) {
		nlink    = le16toh(fe->link_cnt);
		uid      = (uid_t)le32toh(fe->uid);
		gid      = (gid_t)le32toh(fe->gid);
		filesize = le64toh(fe->inf_len);
		blkssize = le64toh(fe->logblks_rec);
		atime    = &fe->atime;
		mtime    = &fe->mtime;
		attrtime = &fe->attrtime;
		filedata = fe->data;

		/* initial guess */
		creatime = mtime;

		/* check our extended attribute if present */
		error = udf_extattr_search_intern(udf_node,
			UDF_FILETIMES_ATTR_NO, "", &offset, &a_l);
		if (!error) {
			ft_extattr = (struct filetimes_extattr_entry *)
				(filedata + offset);
			if (ft_extattr->existence & UDF_FILETIMES_FILE_CREATION)
				creatime = &ft_extattr->times[0];
		}
	} else {
		nlink    = le16toh(efe->link_cnt);
		uid      = (uid_t)le32toh(efe->uid);
		gid      = (gid_t)le32toh(efe->gid);
		filesize = le64toh(efe->inf_len);	/* XXX or obj_size? */
		blkssize = le64toh(efe->logblks_rec);
		atime    = &efe->atime;
		mtime    = &efe->mtime;
		attrtime = &efe->attrtime;
		creatime = &efe->ctime;
		filedata = efe->data;
	}

	/* do the uid/gid translation game */
	if (uid == (uid_t) -1)
		uid = ump->anon_uid;
	if (gid == (gid_t) -1)
		gid = ump->anon_gid;

	/*
	 * BUG-ALERT: UDF doesn't count '.' as an entry, so we'll have to add
	 * 1 to the link count if its a directory we're requested attributes
	 * of.
	 */
	if (vp->v_type == VDIR) {
		nlink++;

		/* directories should be at least a single block? */
		if (blkssize != 0) 
			filesize = blkssize * ump->sector_size;
		else
			filesize = ump->sector_size;
	}

	/* fill in struct vattr with values from the node */
	vattr_null(vap);
	vap->va_type      = vp->v_type;
	vap->va_mode      = udf_getaccessmode(udf_node);
	vap->va_nlink     = nlink;
	vap->va_uid       = uid;
	vap->va_gid       = gid;
	vap->va_fsid      = dev2udev(ump->dev); /* vp->v_mount->mnt_stat.f_fsidx.__fsid_val[0]; */
	vap->va_fileid    = udf_get_node_id(&udf_node->loc);   /* inode hash XXX */
	vap->va_size      = filesize;
	vap->va_blocksize = ump->sector_size;  /* wise? */

	/* access times */
	udf_timestamp_to_timespec(ump, atime,    &vap->va_atime);
	udf_timestamp_to_timespec(ump, mtime,    &vap->va_mtime);
	udf_timestamp_to_timespec(ump, attrtime, &vap->va_ctime);
	udf_timestamp_to_timespec(ump, creatime, &vap->va_birthtime);

	vap->va_gen       = 1;		/* no multiple generations yes (!?) */
	vap->va_flags     = 0;		/* no flags */
	vap->va_bytes     = blkssize * ump->sector_size;
	vap->va_filerev   = 0;		/* TODO file revision numbers? 
					  This was changed from a 1. */
	vap->va_vaflags   = 0;
	/* TODO get vaflags from the extended attributes? */

	if ((vap->va_type == VBLK) || (vap->va_type == VCHR)) {
		error = udf_extattr_search_intern(udf_node,
				UDF_DEVICESPEC_ATTR_NO, "",
				&offset, &a_l);
		/* if error, deny access */
		if (error || (filedata == NULL)) {
			vap->va_mode = 0;	/* or v_type = VNON?  */
		} else {
			devattr = (struct device_extattr_entry *)
				filedata + offset;
			vap->va_rdev = makedev(
				le32toh(devattr->major),
				le32toh(devattr->minor)
				);
			/* TODO we could check the implementator */
		}
	}

	return (0);
}

/* --------------------------------------------------------------------- */
#if 0
static int
udf_chown(struct vnode *vp, uid_t new_uid, gid_t new_gid,
	  kauth_cred_t cred)
{
	struct udf_node  *udf_node = VTOI(vp);
	uid_t uid;
	gid_t gid;
	int error;

#ifdef notyet
	/* TODO get vaflags from the extended attributes? */
	/* Immutable or append-only files cannot be modified, either. */
	if (udf_node->flags & (IMMUTABLE | APPEND))
		return (EPERM);
#endif

	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	/* retrieve old values */
	udf_getownership(udf_node, &uid, &gid);

	/* only one could be specified */
	if (new_uid == VNOVAL)
		new_uid = uid;
	if (new_gid == VNOVAL)
		new_gid = gid;

	/* check if we can fit it in an 32 bits */
	if ((uid_t) ((uint32_t) new_uid) != new_uid)
		return (EINVAL);
	if ((gid_t) ((uint32_t) new_gid) != new_gid)
		return (EINVAL);

	/* check permissions */
	error = genfs_can_chown(vp, cred, uid, gid, new_uid, new_gid);
	if (error)
		return (error);

	/* change the ownership */
	udf_setownership(udf_node, new_uid, new_gid);

	/* mark node changed */
	udf_node->i_flags |= IN_CHANGE;

	return (0);
}


static int
udf_chmod(struct vnode *vp, mode_t mode, kauth_cred_t cred)
{
	struct udf_node  *udf_node = VTOI(vp);
	uid_t uid;
	gid_t gid;
	int error;

#ifdef notyet
	/* TODO get vaflags from the extended attributes? */
	/* Immutable or append-only files cannot be modified, either. */
	if (udf_node->flags & (IMMUTABLE | APPEND))
		return (EPERM);
#endif

	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	/* retrieve uid/gid values */
	udf_getownership(udf_node, &uid, &gid);

	/* check permissions */
	error = genfs_can_chmod(vp, cred, uid, gid, mode);
	if (error)
		return (error);

	/* change mode */
	udf_setaccessmode(udf_node, mode);

	/* mark node changed */
	udf_node->i_flags |= IN_CHANGE;

	return (0);
}


/* exported */
int
udf_chsize(struct vnode *vp, u_quad_t newsize, kauth_cred_t cred)
{
	struct udf_node  *udf_node = VTOI(vp);
	int error, extended;

	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	/* Decide whether this is a valid operation based on the file type. */
	switch (vp->v_type) {
	case VDIR:
		return (EISDIR);
	case VREG:
		if (vp->v_mount->mnt_flag & MNT_RDONLY)
			return (EROFS);
		break;
	case VBLK:
		/* FALLTHROUGH */
	case VCHR:
		/* FALLTHROUGH */
	case VFIFO:
		/* Allow modifications of special files even if in the file
		 * system is mounted read-only (we are not modifying the
		 * files themselves, but the objects they represent). */
		return (0);
	default:
		/* Anything else is unsupported. */
		return (EOPNOTSUPP);
	}

#if notyet
	/* TODO get vaflags from the extended attributes? */
	/* Immutable or append-only files cannot be modified, either. */
	if (node->flags & (IMMUTABLE | APPEND))
		return (EPERM);
#endif

	/* resize file to the requested size */
	error = udf_resize_node(udf_node, newsize, &extended);

	if (error == 0) {
		/* mark change */
		udf_node->i_flags |= IN_CHANGE | IN_MODIFY;
		VN_KNOTE(vp, NOTE_ATTRIB | (extended ? NOTE_EXTEND : 0));
		udf_update(vp, NULL, NULL, NULL, 0);
	}

	return (error);
}


static int
udf_chflags(struct vnode *vp, mode_t mode, kauth_cred_t cred)
{
	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	/* XXX we can't do this yet, but erroring out is enoying XXX */

	return (0);
}


static int
udf_chtimes(struct vnode *vp,
	struct timespec *atime, struct timespec *mtime,
	struct timespec *birthtime, int setattrflags,
	kauth_cred_t cred)
{
	struct udf_node  *udf_node = VTOI(vp);
	uid_t uid;
	gid_t gid;
	int error;

#ifdef notyet
	/* TODO get vaflags from the extended attributes? */
	/* Immutable or append-only files cannot be modified, either. */
	if (udf_node->flags & (IMMUTABLE | APPEND))
		return (EPERM);
#endif

	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	/* retrieve uid/gid values */
	udf_getownership(udf_node, &uid, &gid);

	/* check permissions */
	error = genfs_can_chtimes(vp, setattrflags, uid, cred);
	if (error)
		return (error);

	/* update node flags depending on what times are passed */
	if (atime->tv_sec != VNOVAL)
		if (!(vp->v_mount->mnt_flag & MNT_NOATIME))
			udf_node->i_flags |= IN_ACCESS;
	if ((mtime->tv_sec != VNOVAL) || (birthtime->tv_sec != VNOVAL))
		udf_node->i_flags |= IN_CHANGE | IN_UPDATE;

	return (udf_update(vp, atime, mtime, birthtime, 0));
}
#endif

static int
udf_setattr(struct vop_setattr_args *ap)
{
/*	struct vnode *vp = ap->a_vp; */
/*	struct udf_node  *udf_node = VTOI(vp); */
/*	struct udf_mount *ump = udf_node->ump; */
/*	kauth_cred_t cred = ap->a_cred; */
	struct vattr *vap = ap->a_vap;
	int error;

	/* Abort if any unsettable attribute is given. */
	error = 0;
	if (vap->va_type != VNON ||
	    vap->va_nlink != VNOVAL ||
	    vap->va_fsid != VNOVAL ||
	    vap->va_fileid != VNOVAL ||
	    vap->va_blocksize != VNOVAL ||
#ifdef notyet
	    /* checks are debated */
	    vap->va_ctime.tv_sec != VNOVAL ||
	    vap->va_ctime.tv_nsec != VNOVAL ||
	    vap->va_birthtime.tv_sec != VNOVAL ||
	    vap->va_birthtime.tv_nsec != VNOVAL ||
#endif
	    vap->va_gen != VNOVAL ||
	    vap->va_rdev != VNOVAL ||
	    vap->va_bytes != VNOVAL)
		error = EINVAL;

	if (error == 0 && (vap->va_flags != VNOVAL)) {
		return (EROFS);
/*		error = udf_chflags(vp, vap->va_flags, cred); */
	}

	if (error == 0 && (vap->va_size != VNOVAL)) {
		if (vap->va_type == VDIR)
			return (EISDIR);
		if (vap->va_type == VLNK || vap->va_type == VREG)
			return (EROFS);
/*		error = udf_chsize(vp, vap->va_size, cred); */
	}

	if (error == 0 && (vap->va_uid != VNOVAL || vap->va_gid != VNOVAL)) {
		return (EROFS);
/*		error = udf_chown(vp, vap->va_uid, vap->va_gid, cred); */
	}

	if (error == 0 && (vap->va_mode != (mode_t)VNOVAL)) {
		return (EROFS);
/*		error = udf_chmod(vp, vap->va_mode, cred); */
	}

	if (error == 0 &&
	    ((vap->va_atime.tv_sec != VNOVAL &&
	      vap->va_atime.tv_nsec != VNOVAL)   ||
	     (vap->va_mtime.tv_sec != VNOVAL &&
	      vap->va_mtime.tv_nsec != VNOVAL))
	    ) {
		return (EROFS);
/*		error = udf_chtimes(vp, &vap->va_atime, &vap->va_mtime, */
/*		    &vap->va_birthtime, vap->va_vaflags, cred); */
	}
/*	VN_KNOTE(vp, NOTE_ATTRIB); */

	return (error);
}

/* --------------------------------------------------------------------- */

/*
 * Return POSIX pathconf information for UDF file systems.
 */
static int
udf_pathconf(struct vop_pathconf_args *ap)
{
	uint32_t bits;

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = (1<<16)-1;	/* 16 bits */
		return (0);
	case _PC_NAME_MAX:
		*ap->a_retval = NAME_MAX;
		return (0);
	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX;
		return (0);
	case _PC_PIPE_BUF:
		*ap->a_retval = PIPE_BUF;
		return (0);
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		return (0);
	case _PC_NO_TRUNC:
		*ap->a_retval = 1;
		return (0);
	case _PC_SYNC_IO:
		*ap->a_retval = 0;     /* synchronised is off for performance */
		return (0);
	case _PC_FILESIZEBITS:
		/* 64 bit file offsets -> 2+floor(2log(2^64-1)) = 2 + 63 = 65 */
		bits = 64; /* XXX ought to deliver 65 */
#if 0
		if (udf_node)
			bits = 64 * vp->v_mount->mnt_dev_bshift;
#endif
		*ap->a_retval = bits;
		return (0);
	}

	return (EINVAL);
}


/* --------------------------------------------------------------------- */

static int
udf_open(struct vop_open_args *ap)
{
	struct udf_node *udf_node;
	off_t file_size;
	/* int flags; */

	udf_node = VTOI(ap->a_vp);

	/*
	 * Files marked append-only must be opened for appending.
	 * TODO: get chflags(2) flags from extened attribute.
	 */
	/* if ((flags & APPEND) && (ap->a_mode & (FWRITE | O_APPEND)) == FWRITE)
		return (EPERM); */

	if (udf_node->fe)
		file_size = le64toh(udf_node->fe->inf_len);
	else
		file_size = le64toh(udf_node->efe->inf_len);

	vnode_create_vobject(ap->a_vp, file_size, ap->a_td);

	return (0);
}


/* --------------------------------------------------------------------- */
#if 0
int
udf_close(void *v)
{
	struct vop_close_args /* {
		struct vnode *a_vp;
		int a_fflag;
		kauth_cred_t a_cred;
		struct proc *a_p;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct udf_node *udf_node = VTOI(vp);
	int async = vp->v_mount->mnt_flag & MNT_ASYNC;
	int error;

	DPRINTF(CALL, ("udf_close called\n"));
	udf_node = udf_node;	/* shut up gcc */

	if (!async && (vp->v_type != VDIR)) {
		mutex_enter(&vp->v_interlock);
		error = VOP_PUTPAGES(vp, 0, 0, PGO_CLEANIT);
		if (error)
			return (error);
	}

	mutex_enter(&vp->v_interlock);
		if (vp->v_usecount > 1)
			udf_itimes(udf_node, NULL, NULL, NULL);
	mutex_exit(&vp->v_interlock);

	return (0);
}
#endif

/* --------------------------------------------------------------------- */
static int
udf_access(struct vop_access_args *ap)
{
	struct vnode *vp;
	struct udf_node *udf_node;
	accmode_t accmode;
	gid_t gid;
	mode_t mode;
	uid_t uid;

	vp = ap->a_vp;
	udf_node = VTOI(vp);
	accmode = ap->a_accmode;

	/* check if we are allowed to write */
	switch (vp->v_type) {
	case VDIR:
	case VLNK:
	case VREG:
		/*
		 * normal nodes: check if we're on a read-only mounted
		 * filingsystem and bomb out if we're trying to write.
		 */
		if ((accmode & VWRITE) && (vp->v_mount->mnt_flag & MNT_RDONLY))
			return (EROFS); /* check that this works */
		break;
	case VBLK:
	case VCHR:
	case VSOCK:
	case VFIFO:
		/*
		 * special nodes: even on read-only mounted filingsystems
		 * these are allowed to be written to if permissions allow.
		 */
		break;
	default:
		/* no idea what this is */
		return (EINVAL);
	}

	/* noone may write immutable files */
	/* TODO: get chflags(2) flags from extened attribute. */
#if 0
	flags = 0;
	if ((mode & VWRITE) && (flags & IMMUTABLE))
		return (EPERM);
#endif

	mode = udf_getaccessmode(udf_node);

	if (udf_node->fe) {
		uid = udf_node->fe->uid;
		gid = udf_node->fe->gid;
	}
	else {
		uid = udf_node->efe->uid;
		gid = udf_node->efe->gid;
	}

	return (vaccess(vp->v_type, mode, uid, gid, accmode, ap->a_cred, NULL));
}

/* --------------------------------------------------------------------- */
#if 0
int
udf_create(void *v)
{
	struct vop_create_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap = v;
	struct vnode  *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct vattr  *vap  = ap->a_vap;
	struct componentname *cnp = ap->a_cnp;
	int error;

	DPRINTF(CALL, ("udf_create called\n"));
	error = udf_create_node(dvp, vpp, vap, cnp);

	if (error || !(cnp->cn_flags & SAVESTART))
		PNBUF_PUT(cnp->cn_pnbuf);
	vput(dvp);
	return (error);
}

/* --------------------------------------------------------------------- */

int
udf_mknod(void *v)
{
	struct vop_mknod_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap = v;
	struct vnode  *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct vattr  *vap  = ap->a_vap;
	struct componentname *cnp = ap->a_cnp;
	int error;

	DPRINTF(CALL, ("udf_mknod called\n"));
	error = udf_create_node(dvp, vpp, vap, cnp);

	if (error || !(cnp->cn_flags & SAVESTART))
		PNBUF_PUT(cnp->cn_pnbuf);
	vput(dvp);
	return (error);
}

/* --------------------------------------------------------------------- */

int
udf_mkdir(void *v)
{
	struct vop_mkdir_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap = v;
	struct vnode  *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct vattr  *vap  = ap->a_vap;
	struct componentname *cnp = ap->a_cnp;
	int error;

	DPRINTF(CALL, ("udf_mkdir called\n"));
	error = udf_create_node(dvp, vpp, vap, cnp);

	if (error || !(cnp->cn_flags & SAVESTART))
		PNBUF_PUT(cnp->cn_pnbuf);
	vput(dvp);
	return (error);
}

/* --------------------------------------------------------------------- */

static int
udf_do_link(struct vnode *dvp, struct vnode *vp, struct componentname *cnp)
{
	struct udf_node *udf_node, *dir_node;
	struct vattr vap;
	int error;

	DPRINTF(CALL, ("udf_link called\n"));
	error = 0;

	/* some quick checks */
	if (vp->v_type == VDIR)
		return (EPERM);		/* can't link a directory */
	if (dvp->v_mount != vp->v_mount)
		return (EXDEV);		/* can't link across devices */
	if (dvp == vp)
		return (EPERM);		/* can't be the same */

	/* lock node */
	error = vn_lock(vp, LK_EXCLUSIVE);
	if (error)
		return (error);

	/* get attributes */
	dir_node = VTOI(dvp);
	udf_node = VTOI(vp);

	error = VOP_GETATTR(vp, &vap, FSCRED);
	if (error) {
		VOP_UNLOCK(vp);
		return (error);
	}

	/* check link count overflow */
	if (vap.va_nlink >= (1<<16)-1) {	/* uint16_t */
		VOP_UNLOCK(vp);
		return (EMLINK);
	}

	error = udf_dir_attach(dir_node->ump, dir_node, udf_node, &vap, cnp);
	if (error)
		VOP_UNLOCK(vp);
	return (error);
}

int
udf_link(void *v)
{
	struct vop_link_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap = v;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp  = ap->a_vp;
	struct componentname *cnp = ap->a_cnp;
	int error;

	error = udf_do_link(dvp, vp, cnp);
	if (error)
		VOP_ABORTOP(dvp, cnp);

	VN_KNOTE(vp, NOTE_LINK);
	VN_KNOTE(dvp, NOTE_WRITE);
	vput(dvp);

	return (error);
}

/* --------------------------------------------------------------------- */

static int
udf_do_symlink(struct udf_node *udf_node, char *target)
{
	struct pathcomp pathcomp;
	uint8_t *pathbuf, *pathpos, *compnamepos;
	char *mntonname;
	int pathlen, len, compnamelen, mntonnamelen;
	int error;

	/* process `target' to an UDF structure */
	pathbuf = malloc(UDF_SYMLINKBUFLEN, M_UDFTEMP, M_WAITOK);
	pathpos = pathbuf;
	pathlen = 0;

	if (*target == '/') {
		/* symlink starts from the root */
		len = UDF_PATH_COMP_SIZE;
		memset(&pathcomp, 0, len);
		pathcomp.type = UDF_PATH_COMP_ROOT;

		/* check if its mount-point relative! */
		mntonname    = udf_node->ump->vfs_mountp->mnt_stat.f_mntonname;
		mntonnamelen = strlen(mntonname);
		if (strlen(target) >= mntonnamelen) {
			if (strncmp(target, mntonname, mntonnamelen) == 0) {
				pathcomp.type = UDF_PATH_COMP_MOUNTROOT;
				target += mntonnamelen;
			}
		} else {
			target++;
		}

		memcpy(pathpos, &pathcomp, len);
		pathpos += len;
		pathlen += len;
	}

	error = 0;
	while (*target) {
		/* ignore multiple '/' */
		while (*target == '/') {
			target++;
		}
		if (!*target)
			break;

		/* extract component name */
		compnamelen = 0;
		compnamepos = target;
		while ((*target) && (*target != '/')) {
			target++;
			compnamelen++;
		}

		/* just trunc if too long ?? (security issue) */
		if (compnamelen >= 127) {
			error = ENAMETOOLONG;
			break;
		}

		/* convert unix name to UDF name */
		len = sizeof(struct pathcomp);
		memset(&pathcomp, 0, len);
		pathcomp.type = UDF_PATH_COMP_NAME;
		len = UDF_PATH_COMP_SIZE;

		if ((compnamelen == 2) && (strncmp(compnamepos, "..", 2) == 0))
			pathcomp.type = UDF_PATH_COMP_PARENTDIR;
		if ((compnamelen == 1) && (*compnamepos == '.'))
			pathcomp.type = UDF_PATH_COMP_CURDIR;

		if (pathcomp.type == UDF_PATH_COMP_NAME) {
			unix_to_udf_name(
				(char *) &pathcomp.ident, &pathcomp.l_ci,
				compnamepos, compnamelen,
				&udf_node->ump->logical_vol->desc_charset);
			len = UDF_PATH_COMP_SIZE + pathcomp.l_ci;
		}

		if (pathlen + len >= UDF_SYMLINKBUFLEN) {
			error = ENAMETOOLONG;
			break;
		}

		memcpy(pathpos, &pathcomp, len);
		pathpos += len;
		pathlen += len;
	}

	if (error) {
		/* aparently too big */
		free(pathbuf, M_UDFTEMP);
		return (error);
	}

	error = udf_grow_node(udf_node, pathlen);
	if (error) {
		/* failed to pregrow node */
		free(pathbuf, M_UDFTEMP);
		return (error);
	}

	/* write out structure on the new file */
	error = vn_rdwr(UIO_WRITE, udf_node->vnode,
		pathbuf, pathlen, 0,
		UIO_SYSSPACE, IO_NODELOCKED | IO_ALTSEMANTICS,
		FSCRED, NULL, NULL);

	/* return status of symlink contents writeout */
	free(pathbuf, M_UDFTEMP);
	return (error);
}


int
udf_symlink(void *v)
{
	struct vop_symlink_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
		char *a_target;
	} */ *ap = v;
	struct vnode  *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct vattr  *vap  = ap->a_vap;
	struct componentname *cnp = ap->a_cnp;
	struct udf_node *dir_node;
	struct udf_node *udf_node;
	int error;

	error = udf_create_node(dvp, vpp, vap, cnp);
	KASSERT(((error == 0) && (*vpp != NULL)) || ((error && (*vpp == NULL))));
	if (!error) {
		dir_node = VTOI(dvp);
		udf_node = VTOI(*vpp);
		KASSERT(udf_node);
		error = udf_do_symlink(udf_node, ap->a_target);
		if (error) {
			/* remove node */
			udf_shrink_node(udf_node, 0);
			udf_dir_detach(udf_node->ump, dir_node, udf_node, cnp);
		}
	}
	if (error || !(cnp->cn_flags & SAVESTART))
		PNBUF_PUT(cnp->cn_pnbuf);
	vput(dvp);
	return (error);
}
#endif
/* --------------------------------------------------------------------- */

int
udf_readlink(struct vop_readlink_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct pathcomp pathcomp;
	struct udf_node *udf_node;
	int pathlen, targetlen, namelen, mntonnamelen, len, l_ci, filelen;
	int first, error;
	char *mntonname;
	uint8_t *pathbuf, *targetbuf, *tmpname;
	uint8_t *pathpos, *targetpos;

	udf_node = VTOI(vp);

	if (udf_node->efe)
		filelen = le64toh(udf_node->efe->inf_len);
	else
		filelen = le64toh(udf_node->fe->inf_len);

	/* claim temporary buffers for translation */
	pathbuf   = malloc(UDF_SYMLINKBUFLEN, M_UDFTEMP, M_WAITOK);
	targetbuf = malloc(PATH_MAX+1, M_UDFTEMP, M_WAITOK);
	tmpname   = malloc(PATH_MAX+1, M_UDFTEMP, M_WAITOK);
	memset(pathbuf, 0, UDF_SYMLINKBUFLEN);
	memset(targetbuf, 0, PATH_MAX);


	/* read contents of file in our temporary buffer */
	error = vn_rdwr(UIO_READ, vp,
		pathbuf, filelen, 0,
		UIO_SYSSPACE, IO_NODELOCKED,
		FSCRED, NULL, NULL, curthread);
	if (error) {
		/* failed to read in symlink contents */
		free(pathbuf, M_UDFTEMP);
		free(targetbuf, M_UDFTEMP);
		free(tmpname, M_UDFTEMP);
		return (error);
	}

	/* convert to a unix path */
	pathpos   = pathbuf;
	pathlen   = 0;
	targetpos = targetbuf;
	targetlen = PATH_MAX;
	mntonname    = udf_node->ump->vfs_mountp->mnt_stat.f_mntonname;
	mntonnamelen = strlen(mntonname);

	error = 0;
	first = 1;
	while (filelen - pathlen >= UDF_PATH_COMP_SIZE) {
		len = UDF_PATH_COMP_SIZE;
		memcpy(&pathcomp, pathpos, len);
		l_ci = pathcomp.l_ci;
		switch (pathcomp.type) {
		case UDF_PATH_COMP_ROOT :
			/* XXX should check for l_ci; bugcompatible now */
			if ((targetlen < 1) || !first) {
				error = EINVAL;
				break;
			}
			*targetpos++ = '/'; targetlen--;
			break;
		case UDF_PATH_COMP_MOUNTROOT :
			/* XXX what should it be if l_ci > 0 ? [4/48.16.1.2] */
			if (l_ci || (targetlen < mntonnamelen+1) || !first) {
				error = EINVAL;
				break;
			}
			memcpy(targetpos, mntonname, mntonnamelen);
			targetpos += mntonnamelen; targetlen -= mntonnamelen;
			if (filelen-pathlen > UDF_PATH_COMP_SIZE+l_ci) {
				/* more follows, so must be directory */
				*targetpos++ = '/'; targetlen--;
			}
			break;
		case UDF_PATH_COMP_PARENTDIR :
			/* XXX should check for l_ci; bugcompatible now */
			if (targetlen < 3) {
				error = EINVAL;
				break;
			}
			*targetpos++ = '.'; targetlen--;
			*targetpos++ = '.'; targetlen--;
			*targetpos++ = '/'; targetlen--;
			break;
		case UDF_PATH_COMP_CURDIR :
			/* XXX should check for l_ci; bugcompatible now */
			if (targetlen < 2) {
				error = EINVAL;
				break;
			}
			*targetpos++ = '.'; targetlen--;
			*targetpos++ = '/'; targetlen--;
			break;
		case UDF_PATH_COMP_NAME :
			if (l_ci == 0) {
				error = EINVAL;
				break;
			}
			memset(tmpname, 0, PATH_MAX);
			memcpy(&pathcomp, pathpos, len + l_ci);
			udf_to_unix_name(udf_node->ump, tmpname, MAXPATHLEN,
				pathcomp.ident, l_ci);
			namelen = strlen(tmpname);
			if (targetlen < namelen + 1) {
				error = EINVAL;
				break;
			}
			memcpy(targetpos, tmpname, namelen);
			targetpos += namelen; targetlen -= namelen;
			if (filelen-pathlen > UDF_PATH_COMP_SIZE+l_ci) {
				/* more follows, so must be directory */
				*targetpos++ = '/'; targetlen--;
			}
			break;
		default :
			error = EINVAL;
			break;
		}
		first = 0;
		if (error)
			break;
		pathpos += UDF_PATH_COMP_SIZE + l_ci;
		pathlen += UDF_PATH_COMP_SIZE + l_ci;

	}
	/* all processed? */
	if (filelen - pathlen > 0)
		error = EINVAL;

	/* uiomove() to destination */
	if (!error)
		uiomove(targetbuf, PATH_MAX - targetlen, uio);

	free(pathbuf, M_UDFTEMP);
	free(targetbuf, M_UDFTEMP);
	free(tmpname, M_UDFTEMP);

	return (error);
}

/* --------------------------------------------------------------------- */

/*
 * Check if source directory is in the path of the target directory.  Target
 * is supplied locked, source is unlocked. The target is always vput before
 * returning. Modeled after UFS.
 *
 * If source is on the path from target to the root, return error.
 */
#if 0
static int
udf_on_rootpath(struct udf_node *source, struct udf_node *target)
{
	struct udf_mount *ump = target->ump;
	struct udf_node *res_node;
	struct long_ad icb_loc, *root_icb;
	const char *name;
	int namelen;
	int error, found;

	name     = "..";
	namelen  = 2;
	error    = 0;
	res_node = target;

	root_icb   = &ump->fileset_desc->rootdir_icb;

	/* if nodes are equal, it is no use looking */
	if (udf_compare_icb(&source->loc, &target->loc) == 0) {
		error = EEXIST;
		goto out;
	}

	/* nothing can exist before the root */
	if (udf_compare_icb(root_icb, &target->loc) == 0) {
		error = 0;
		goto out;
	}

	for (;;) {
		DPRINTF(NODE, ("udf_on_rootpath : "
			"source vp %p, looking at vp %p\n",
			source->vnode, res_node->vnode));

		/* sanity check */
		if (res_node->vnode->v_type != VDIR) {
			error = ENOTDIR;
			goto out;
		}

		/* go down one level */
		error = udf_lookup_name_in_dir(res_node->vnode, name, namelen,
			&icb_loc, &found);
		DPRINTF(NODE, ("\tlookup of '..' resulted in error %d, "
			"found %d\n", error, found));

		if (!found)
			error = ENOENT;
		if (error)
			goto out;

		/* did we encounter source node? */
		if (udf_compare_icb(&icb_loc, &source->loc) == 0) {
			error = EINVAL;
			goto out;
		}

		/* did we encounter the root node? */
		if (udf_compare_icb(&icb_loc, root_icb) == 0) {
			error = 0;
			goto out;
		}

		/* push our intermediate node, we're done with it */
		/* DPRINTF(NODE, ("\tvput %p\n", target->vnode)); */
		vput(res_node->vnode);

		DPRINTF(NODE, ("\tgetting the .. node\n"));
		error = udf_get_node(ump, &icb_loc, &res_node);

		if (error) {	/* argh, bail out */
			KASSERT(res_node == NULL);
			// res_node = NULL;
			goto out;
		}
	}
out:
	DPRINTF(NODE, ("\tresult: %svalid, error = %d\n", error?"in":"", error));

	/* put our last node */
	if (res_node)
		vput(res_node->vnode);

	return (error);
}

/* note: i tried to follow the logics of the tmpfs rename code */
int
udf_rename(void *v)
{
	struct vop_rename_args /* {
		struct vnode *a_fdvp;
		struct vnode *a_fvp;
		struct componentname *a_fcnp;
		struct vnode *a_tdvp;
		struct vnode *a_tvp;
		struct componentname *a_tcnp;
	} */ *ap = v;
	struct vnode *tvp = ap->a_tvp;
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *fvp = ap->a_fvp;
	struct vnode *fdvp = ap->a_fdvp;
	struct componentname *tcnp = ap->a_tcnp;
	struct componentname *fcnp = ap->a_fcnp;
	struct udf_node *fnode, *fdnode, *tnode, *tdnode;
	struct vattr fvap, tvap;
	int error;

	DPRINTF(CALL, ("udf_rename called\n"));

	/* disallow cross-device renames */
	if (fvp->v_mount != tdvp->v_mount ||
	    (tvp != NULL && fvp->v_mount != tvp->v_mount)) {
		error = EXDEV;
		goto out_unlocked;
	}

	fnode  = VTOI(fvp);
	fdnode = VTOI(fdvp);
	tnode  = (tvp == NULL) ? NULL : VTOI(tvp);
	tdnode = VTOI(tdvp);

	/* lock our source dir */
	if (fdnode != tdnode) {
		error = vn_lock(fdvp, LK_EXCLUSIVE | LK_RETRY);
		if (error != 0)
			goto out_unlocked;
	}

	/* get info about the node to be moved */
	error = VOP_GETATTR(fvp, &fvap, FSCRED);
	KASSERT(error == 0);

	/* check when to delete the old already existing entry */
	if (tvp) {
		/* get info about the node to be moved to */
		error = VOP_GETATTR(fvp, &tvap, FSCRED);
		KASSERT(error == 0);

		/* if both dirs, make sure the destination is empty */
		if (fvp->v_type == VDIR && tvp->v_type == VDIR) {
			if (tvap.va_nlink > 2) {
				error = ENOTEMPTY;
				goto out;
			}
		}
		/* if moving dir, make sure destination is dir too */
		if (fvp->v_type == VDIR && tvp->v_type != VDIR) {
			error = ENOTDIR;
			goto out;
		}
		/* if we're moving a non-directory, make sure dest is no dir */
		if (fvp->v_type != VDIR && tvp->v_type == VDIR) {
			error = EISDIR;
			goto out;
		}
	}

	/* check if moving a directory to a new parent is allowed */
	if ((fdnode != tdnode) && (fvp->v_type == VDIR)) {
		/* release tvp since we might encounter it and lock up */
		if (tvp)
			vput(tvp);

		/* vref tdvp since we lose its ref in udf_on_rootpath */
		vref(tdvp);

		/* search if fnode is a component of tdnode's path to root */
		error = udf_on_rootpath(fnode, tdnode);

		DPRINTF(NODE, ("Dir rename allowed ? %s\n", error ? "NO":"YES"));

		if (error) {
			/* compensate for our vref earlier */
			vrele(tdvp);
			goto out;
		}

		/* relock tdvp; its still here due to the vref earlier */
		vn_lock(tdvp, LK_EXCLUSIVE | LK_RETRY);

		/*
		 * re-lookup tvp since the parent has been unlocked, so could
		 * have changed/removed in the meantime.
		 */
		tcnp->cn_flags &= ~SAVESTART;
		error = relookup(tdvp, &tvp, tcnp);
		if (error) {
			vput(tdvp);
			goto out;
		}
		tnode  = (tvp == NULL) ? NULL : VTOI(tvp);
	}

	/* remove existing entry if present */
	if (tvp) 
		udf_dir_detach(tdnode->ump, tdnode, tnode, tcnp);

	/* create new directory entry for the node */
	error = udf_dir_attach(tdnode->ump, tdnode, fnode, &fvap, tcnp);
	if (error)
		goto out;

	/* unlink old directory entry for the node, if failing, unattach new */
	error = udf_dir_detach(tdnode->ump, fdnode, fnode, fcnp);
	if (error)
		udf_dir_detach(tdnode->ump, tdnode, fnode, tcnp);
	if (error)
		goto out;

	/* update tnode's '..' if moving directory to new parent */
	if ((fdnode != tdnode) && (fvp->v_type == VDIR)) {
		/* update fnode's '..' entry */
		error = udf_dir_update_rootentry(fnode->ump, fnode, tdnode);
		if (error) {
			/* 'try' to recover from this situation */
			udf_dir_attach(tdnode->ump, fdnode, fnode, &fvap, fcnp);
			udf_dir_detach(tdnode->ump, tdnode, fnode, tcnp);
		}
	}

out:
        if (fdnode != tdnode)
                VOP_UNLOCK(fdvp);

out_unlocked:
	VOP_ABORTOP(tdvp, tcnp);
	if (tdvp == tvp)
		vrele(tdvp);
	else
		vput(tdvp);
	if (tvp)
		vput(tvp);
	VOP_ABORTOP(fdvp, fcnp);

	/* release source nodes. */
	vrele(fdvp);
	vrele(fvp);

	return (error);
}

/* --------------------------------------------------------------------- */

int
udf_remove(void *v)
{
	struct vop_remove_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap = v;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp  = ap->a_vp;
	struct componentname *cnp = ap->a_cnp;
	struct udf_node *dir_node = VTOI(dvp);
	struct udf_node *udf_node = VTOI(vp);
	struct udf_mount *ump = dir_node->ump;
	int error;

	DPRINTF(CALL, ("udf_remove called\n"));
	if (vp->v_type != VDIR) {
		error = udf_dir_detach(ump, dir_node, udf_node, cnp);
		DPRINTFIF(NODE, error, ("\tgot error removing file\n"));
	} else {
		DPRINTF(NODE, ("\tis a directory: perm. denied\n"));
		error = EPERM;
	}

	if (error == 0) {
		VN_KNOTE(vp, NOTE_DELETE);
		VN_KNOTE(dvp, NOTE_WRITE);
	}

	if (dvp == vp)
		vrele(vp);
	else
		vput(vp);
	vput(dvp);

	return (error);
}

/* --------------------------------------------------------------------- */

int
udf_rmdir(void *v)
{
	struct vop_rmdir_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vnode *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	struct udf_node *dir_node = VTOI(dvp);
	struct udf_node *udf_node = VTOI(vp);
	struct udf_mount *ump = dir_node->ump;
	int refcnt, error;

	DPRINTF(NOTIMPL, ("udf_rmdir called\n"));

	/* don't allow '.' to be deleted */
	if (dir_node == udf_node) {
		vrele(dvp);
		vput(vp);
		return (EINVAL);
	}

	/* check to see if the directory is empty */
	error = 0;
	if (dir_node->fe) {
		refcnt = le16toh(udf_node->fe->link_cnt);
	} else {
		refcnt = le16toh(udf_node->efe->link_cnt);
	}
	if (refcnt > 1) {
		/* NOT empty */
		vput(dvp);
		vput(vp);
		return (ENOTEMPTY);
	}

	/* detach the node from the directory */
	error = udf_dir_detach(ump, dir_node, udf_node, cnp);
	if (error == 0) {
		cache_purge(vp);
//		cache_purge(dvp);	/* XXX from msdosfs, why? */
		VN_KNOTE(vp, NOTE_DELETE);
	}
	DPRINTFIF(NODE, error, ("\tgot error removing file\n"));

	/* unput the nodes and exit */
	vput(dvp);
	vput(vp);

	return (error);
}

/* --------------------------------------------------------------------- */

int
udf_fsync(void *v)
{
	struct vop_fsync_args /* {
		struct vnode *a_vp;
		kauth_cred_t a_cred;
		int a_flags;
		off_t offlo;
		off_t offhi;
		struct proc *a_p;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct udf_node *udf_node = VTOI(vp);
	int error, flags, wait;

	DPRINTF(SYNC, ("udf_fsync called on %p : %s, %s\n",
		udf_node,
		(ap->a_flags & FSYNC_WAIT)     ? "wait":"no wait",
		(ap->a_flags & FSYNC_DATAONLY) ? "data_only":"complete"));

	/* flush data and wait for it when requested */
	wait = (ap->a_flags & FSYNC_WAIT) ? UPDATE_WAIT : 0;
	vflushbuf(vp, wait);

	if (udf_node == NULL) {
		printf("udf_fsync() called on NULL udf_node!\n");
		return (0);
	}
	if (vp->v_tag != VT_UDF) {
		printf("udf_fsync() called on node not tagged as UDF node!\n");
		return (0);
	}

	/* set our times */
	udf_itimes(udf_node, NULL, NULL, NULL);

	/* if called when mounted readonly, never write back */
	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (0);

	/* if only data is requested, return */
	if (ap->a_flags & FSYNC_DATAONLY)
		return (0);

	/* check if the node is dirty 'enough'*/
	flags = udf_node->i_flags & (IN_MODIFIED | IN_ACCESSED);
	if (flags == 0)
		return (0);

	/* if we don't have to wait, check for IO pending */
	if (!wait) {
		if (vp->v_numoutput > 0) {
			DPRINTF(SYNC, ("udf_fsync %p, rejecting on v_numoutput\n", udf_node));
			return (0);
		}
		if (udf_node->outstanding_bufs > 0) {
			DPRINTF(SYNC, ("udf_fsync %p, rejecting on outstanding_bufs\n", udf_node));
			return (0);
		}
		if (udf_node->outstanding_nodedscr > 0) {
			DPRINTF(SYNC, ("udf_fsync %p, rejecting on outstanding_nodedscr\n", udf_node));
			return (0);
		}
	}

	/* wait until vp->v_numoutput reaches zero i.e. is finished */
	if (wait) {
		DPRINTF(SYNC, ("udf_fsync %p, waiting\n", udf_node));
		mutex_enter(&vp->v_interlock);
		while (vp->v_numoutput) {
			DPRINTF(SYNC, ("udf_fsync %p, v_numoutput %d\n", udf_node, vp->v_numoutput));
			cv_timedwait(&vp->v_cv, &vp->v_interlock, hz/8);
		}
		mutex_exit(&vp->v_interlock);
		DPRINTF(SYNC, ("udf_fsync %p, fin wait\n", udf_node));
	}

	/* write out node and wait for it if requested */
	DPRINTF(SYNC, ("udf_fsync %p, writeout node\n", udf_node));
	error = udf_writeout_node(udf_node, wait);
	if (error)
		return (error);

	/* TODO/XXX if ap->a_flags & FSYNC_CACHE, we ought to do a disc sync */

	return (0);
}

/* --------------------------------------------------------------------- */

int
udf_advlock(void *v)
{
	struct vop_advlock_args /* {
		struct vnode *a_vp;
		void *a_id;
		int a_op;
		struct flock *a_fl;
		int a_flags;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct udf_node *udf_node = VTOI(vp);
	struct file_entry    *fe;
	struct extfile_entry *efe;
	uint64_t file_size;

	DPRINTF(LOCKING, ("udf_advlock called\n"));

	/* get directory filesize */
	if (udf_node->fe) {
		fe = udf_node->fe;
		file_size = le64toh(fe->inf_len);
	} else {
		assert(udf_node->efe);
		efe = udf_node->efe;
		file_size = le64toh(efe->inf_len);
	}

	return (lf_advlock(ap, &udf_node->lockf, file_size));
}
#endif

static int
udf_ioctl(struct vop_ioctl_args *ap)
{
	return (ENOTTY);
}

static int
udf_print(struct vop_print_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct udf_node *udf_node = VTOI(vp);

	printf("    ino %u, on dev %s", (uint32_t)udf_node->hash_id,
	    devtoname(udf_node->ump->dev));
	if (vp->v_type == VFIFO)
		fifo_printinfo(vp);
	printf("\n");
	return (0);
}

static int
udf_vptofh(struct vop_vptofh_args *ap)
{
	struct udf_node *udf_node = VTOI(ap->a_vp);
	struct udf_fid *ufid = (struct udf_fid *)ap->a_fhp;

	ufid->len = sizeof(struct udf_fid);
	ufid->ino = udf_node->hash_id;

	return (0);
}

