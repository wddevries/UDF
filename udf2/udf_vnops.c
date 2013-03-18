/*-
 * Copyright (c) 2013 Will DeVries
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
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/buf.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/unistd.h>
#include <sys/bio.h>
#include <sys/stat.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>

#if __FreeBSD__ < 10
#include <fs/fifofs/fifo.h>
#endif

#include "ecma167-udf.h"
#include "udf.h"
#include "udf_subr.h"

static int udf_pbuf_freecnt = -1;

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
static vop_getpages_t	udf_getpages;

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
	.vop_getpages =		udf_getpages
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


int
udf_getanode(struct mount *mp, struct vnode **vpp)
{
	return (getnewvnode("udf2", mp, &udf_vnodeops, vpp));
}

static int
udf_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct udf_node *udf_node = VTOI(vp);

	vnode_destroy_vobject(vp);

	if (udf_node == NULL)
		return (0);

	/* dispose all node knowledge */
	vfs_hash_remove(vp);
	udf_dispose_node(udf_node);
	vp->v_data = NULL;

	return (0);
}

static int
udf_read(struct vop_read_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct buf *bp;
	struct udf_node *udf_node = VTOI(vp);
	uint64_t fsize;
	int seqcount, lbn, n, on, sector_size; 
	int error = 0;
	uint8_t *zerobuf;

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
	if (udf_node->fe != NULL)
		fsize = le64toh(udf_node->fe->inf_len);
	else 
		fsize = le64toh(udf_node->efe->inf_len);

	sector_size = udf_node->ump->sector_size;

	seqcount = ap->a_ioflag >> IO_SEQSHIFT;

	while (error == 0 && uio->uio_resid > 0 && fsize > uio->uio_offset) {
 		lbn = uio->uio_offset / sector_size;
		on = uio->uio_offset % sector_size;

		n = min(sector_size - on, uio->uio_resid);
		n = min(n, fsize - uio->uio_offset);

		if ((vp->v_mount->mnt_flag & MNT_NOCLUSTERR) == 0 &&
		    sector_size * (lbn + 1) < fsize) {
			error = cluster_read(vp, fsize, lbn, sector_size, 
			    NOCRED, uio->uio_resid, seqcount, &bp);
		} else {
			error = bread(vp, lbn, sector_size, NOCRED, &bp);
		}

		n = min(n, sector_size - bp->b_resid);

		if (error == 0) 
			error = uiomove(bp->b_data + on, n, uio);

		brelse(bp);
	}

	if (vp->v_type == VDIR && fsize <= uio->uio_offset &&
	    uio->uio_resid > 0) {
		zerobuf = malloc(2048, M_UDFTEMP, M_WAITOK | M_ZERO);
		while (error == 0 && uio->uio_resid > 0) {
			n = min(2048, uio->uio_resid);
			error = uiomove(zerobuf, n, uio);
		}
		free(zerobuf, M_UDFTEMP);
	}

	return (error);
}

static int
udf_bmap(struct vop_bmap_args /* {
		struct vnode *a_vp;
		daddr_t  a_bn;
		struct bufobj **a_bop;
		daddr_t *a_bnp;
		int *a_runp;
		int *a_runb;
	} */ *ap)
{
	struct vnode *vp = ap->a_vp;
	struct udf_node *udf_node = VTOI(vp);
	uint64_t lsector;
	int error, exttype;
	uint32_t maxblks;

	if (ap->a_bop != NULL)
		*ap->a_bop = &ap->a_vp->v_bufobj;

	if (ap->a_bnp == NULL)
		return (0);

	/* get logical block and run */
	error = udf_bmap_translate(udf_node, ap->a_bn, &exttype, &lsector,
	    &maxblks);
	if (error != 0)
		return (error);

	/* convert to dev blocks */
	if (exttype == UDF_TRAN_INTERN)
		*ap->a_bnp = INT64_MAX - 2;
	else if (exttype == UDF_TRAN_ZERO)
		*ap->a_bnp = INT64_MAX - 1; /* zero the buffer */
	else
		*ap->a_bnp = lsector * (udf_node->ump->sector_size/DEV_BSIZE);

	/* set runlength of maximum block size */
	if (ap->a_runp != NULL)
		*ap->a_runp = maxblks - 1;

	if (ap->a_runb != NULL) 
		*ap->a_runb = 0;

	/* return success */
	return (0);
}

static int
udf_strategy(struct vop_strategy_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct buf *bp = ap->a_bp;
	struct udf_node *udf_node = VTOI(vp);
	struct bufobj *bo = &udf_node->ump->devvp->v_bufobj;
	uint64_t lsector;
	int error, exttype;
	uint32_t sector_size, maxblks;

	if (vp->v_type == VBLK || vp->v_type == VCHR)
		panic("udf_strategy: spec");

	/* get sector size */
	sector_size = udf_node->ump->sector_size;


	/* get logical block and run */
	if (bp->b_blkno == bp->b_lblkno) {
		error = udf_bmap_translate(udf_node, bp->b_lblkno, &exttype,
		    &lsector, &maxblks);

		if (error != 0) {
			bp->b_error = error;
			bp->b_ioflags |= BIO_ERROR;
			bufdone(bp);
			return (error);
		}

		if (exttype == UDF_TRAN_ZERO) {
			bp->b_blkno = INT64_MAX - 1;
			vfs_bio_clrbuf(bp);
		}
		else if (exttype == UDF_TRAN_INTERN)
			bp->b_blkno = INT64_MAX - 2;
		else
			bp->b_blkno = lsector * (sector_size / DEV_BSIZE);
	}

	if ((bp->b_iocmd & BIO_READ) == 0)
		return (ENOTSUP);

	if (bp->b_blkno == INT64_MAX - 1) {
		bufdone(bp);
//printf("UDF: Hole in file found. (This is a debuging statement, not an error.\n");
	} else if (bp->b_blkno == INT64_MAX - 2) {
		error = udf_read_internal(udf_node, (uint8_t *)bp->b_data);
		if (error != 0) {
			bp->b_error = error;
			bp->b_ioflags |= BIO_ERROR;
		}
		bufdone(bp);
	} else {
		bp->b_iooffset = dbtob(bp->b_blkno);
		BO_STRATEGY(bo, bp);
	}

	return (bp->b_error);
}

static int
udf_readdir(struct vop_readdir_args *ap)
{
	struct uio *uio;
	struct vnode *vp;
	struct file_entry *fe;
	struct extfile_entry *efe;
	struct fileid_desc *fid;
	struct dirent *dirent;
	struct udf_mount *ump;
	struct udf_node *udf_node;
	uint64_t *cookies, *cookiesp, diroffset, file_size, transoffset;
	int acookies, error, ncookies;
	uint32_t lb_size;
	uint8_t *fid_name;
	
	error = 0;
	uio = ap->a_uio;
	vp = ap->a_vp;
	udf_node = VTOI(vp);
	ump = udf_node->ump;
	transoffset = uio->uio_offset;

	/* This operation only makes sense on directory nodes. */
	if (vp->v_type != VDIR)
		return (ENOTDIR);

	/* get directory filesize */
	if (udf_node->fe != NULL) {
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
		cookies = malloc(sizeof(u_long) * ncookies, M_TEMP, 
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

	/* The directory '.' is not in the fid stream. */
	if (transoffset == 0) {
		memset(dirent, 0, sizeof(struct dirent));
		dirent->d_fileno = udf_node->hash_id;
		dirent->d_type = DT_DIR;
		dirent->d_name[0] = '.';
		dirent->d_name[1] = '\0';
		dirent->d_namlen = 1;
		dirent->d_reclen = GENERIC_DIRSIZ(dirent);
		if (cookiesp != NULL) {
			acookies++;
			*cookiesp++ = 1; // next one
		}
		error = uiomove(dirent, GENERIC_DIRSIZ(dirent), uio);
		if (error != 0)
			goto bail;

		/* in case the directory size is 0 or 1? */
		transoffset = 1;
	}

	/* we are called just as long as we keep on pushing data in */
	if (transoffset < file_size) {
		/* allocate temporary space for fid */
		lb_size = le32toh(udf_node->ump->logical_vol->lb_size);
		fid = malloc(lb_size, M_UDFTEMP, M_WAITOK);

		if (transoffset == 1)
			diroffset = 0;
		else
			diroffset = transoffset;

		while (diroffset < file_size) {
			/* transfer a new fid/dirent */
			error = udf_read_fid_stream(vp, &diroffset, fid);
			if (error != 0) {
				printf("UDF: Read error in read fid: %d\n", error);
				break;
			}
			
			/* create resulting dirent structure */
			memset(dirent, 0, sizeof(struct dirent));
			error = udf_get_node_id(fid->icb, &dirent->d_fileno); /* inode hash XXX */
			if (error != 0)
				break;

			/* Going for the filetypes now is too expensive. */
			dirent->d_type = DT_UNKNOWN;
			if (fid->file_char & UDF_FILE_CHAR_DIR)
				dirent->d_type = DT_DIR;

			/* '..' has no name, so provide one */
			if (fid->file_char & UDF_FILE_CHAR_PAR) {
				dirent->d_name[0] = '.';
				dirent->d_name[1] = '.';
				dirent->d_name[2] = '\0';
				dirent->d_namlen = 2;
			} else {
				fid_name = fid->data + le16toh(fid->l_iu);
				udf_to_unix_name(ump, dirent->d_name, MAXNAMLEN,
				    fid_name, fid->l_fi);
				dirent->d_namlen = strlen(dirent->d_name);
			}
			dirent->d_reclen = GENERIC_DIRSIZ(dirent);

			/* 
			 * If there isn't enough space in the uio to return a
			 * whole dirent, break off read
			 */
			if (uio->uio_resid < GENERIC_DIRSIZ(dirent))
				break;

			/* skip deleted and not visible files */
			if (fid->file_char & UDF_FILE_CHAR_DEL ||
			    fid->file_char & UDF_FILE_CHAR_VIS) {
				transoffset = diroffset;
				if (cookiesp != NULL && acookies > 0)
					*(cookiesp - 1) = transoffset;
				continue;
			}

			/* copy dirent to the caller */
			if (cookiesp != NULL) {
				if (acookies + 1 > ncookies)
					break; 
				acookies++;
				*cookiesp++ = diroffset;
			}

			/* remember the last entry we transfered */
			transoffset = diroffset;

			error = uiomove(dirent, GENERIC_DIRSIZ(dirent), uio);
			if (error != 0)
				break;
		}

		/* pass on last transfered offset */
		/* We lied for '.', so tell more lies. */
		free(fid, M_UDFTEMP);
	}

	uio->uio_offset = transoffset; 

bail:
	if (ap->a_eofflag != NULL)
		*ap->a_eofflag = uio->uio_offset >= file_size;

	if (ap->a_ncookies != NULL) {
		if (error != 0)
			free(cookies, M_UDFTEMP);
		else {
			*ap->a_ncookies = acookies;
			*ap->a_cookies = cookies;
		}
	}
	free(dirent, M_UDFTEMP);

	return (error);
}

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
	int error, islastcn, ltype, mounted_ro, nameiop, numpasses, unix_len;
	uint8_t *fid_name;
	char *unix_name;

	dir_node = VTOI(dvp);
	ump = dir_node->ump;
	*vpp = NULL;
	error = 0;

	/* simplify/clarification flags */
	nameiop = cnp->cn_nameiop;
	islastcn = cnp->cn_flags & ISLASTCN;
	mounted_ro = dvp->v_mount->mnt_flag & MNT_RDONLY;

	/*
	 * If requesting a modify on the last path element on a read-only
	 * filingsystem, reject lookup; XXX why is this repeated in every FS ?
	 */
	if (islastcn && mounted_ro && (nameiop == DELETE || nameiop == RENAME))
		return (EROFS);

	/* get directory filesize */
	if (dir_node->fe != NULL)
		file_size = le64toh(dir_node->fe->inf_len);
	else
		file_size = le64toh(dir_node->efe->inf_len);

	/* 
	 * 
	 */
	if (nameiop != LOOKUP || dir_node->diroff == 0 || 
	    dir_node->diroff > file_size) {
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
		if (error != 0) {
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
				error = udf_get_node_id(fid->icb, &id);
				break;
			}
		}
		else {
			fid_name = fid->data + le16toh(fid->l_iu);
			udf_to_unix_name(ump, unix_name, MAXNAMLEN, fid_name,
			    fid->l_fi);
			unix_len = strlen(unix_name);

			if (unix_len == cnp->cn_namelen) {
				if (!strncmp(unix_name, cnp->cn_nameptr, 
				    cnp->cn_namelen)) {
					error = udf_get_node_id(fid->icb, &id);
					break;
				}
			}
		}
	}

	if (error != 0)
		goto exit; 

	if (id != 0) {
		if ((cnp->cn_flags & ISLASTCN) && cnp->cn_nameiop == LOOKUP)
			dir_node->diroff = offset;
		if (numpasses == 2)
			nchstats.ncs_pass2++;

		if (cnp->cn_flags & ISDOTDOT)
			vn_vget_ino(dvp, id, cnp->cn_lkflags, &tdp);
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
		} else
			error = udf_vget(ump->vfs_mountp, id, cnp->cn_lkflags,
			    &tdp);

		if (error == 0) {
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
}

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
	struct timestamp *atime, *attrtime, *creatime, *mtime;
	struct udf_mount *ump = udf_node->ump;
	uint64_t blkssize, filesize;
	gid_t gid;
	int error;
	uid_t uid;
	uint32_t a_l, nlink, offset;
	uint8_t *filedata;

	/* get descriptor information */
	if (fe != NULL) {
		nlink = le16toh(fe->link_cnt);
		uid = (uid_t)le32toh(fe->uid);
		gid = (gid_t)le32toh(fe->gid);
		filesize = le64toh(fe->inf_len);
		blkssize = le64toh(fe->logblks_rec);
		atime = &fe->atime;
		mtime = &fe->mtime;
		attrtime = &fe->attrtime;
		filedata = fe->data;

		/* initial guess */
		creatime = mtime;

		/* check our extended attribute if present */
		error = udf_extattr_search_intern(udf_node,
		    UDF_FILETIMES_ATTR_NO, "", &offset, &a_l);
		if (error == 0) {
			ft_extattr = (struct filetimes_extattr_entry *)
				(filedata + offset);
			if (ft_extattr->existence & UDF_FILETIMES_FILE_CREATION)
				creatime = &ft_extattr->times[0];
		}
	} else {
		nlink = le16toh(efe->link_cnt);
		uid = (uid_t)le32toh(efe->uid);
		gid = (gid_t)le32toh(efe->gid);
		filesize = le64toh(efe->inf_len);	/* XXX or obj_size? */
		blkssize = le64toh(efe->logblks_rec);
		atime = &efe->atime;
		mtime = &efe->mtime;
		attrtime = &efe->attrtime;
		creatime = &efe->ctime;
		filedata = efe->data;
	}

	/* do the uid/gid translation game */
	if (uid == (uid_t)-1 || ump->flags & UDFMNT_OVERRIDE_UID)
		uid = ump->anon_uid;
	if (gid == (gid_t)-1 || ump->flags & UDFMNT_OVERRIDE_GID)
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
	vap->va_type = vp->v_type;
	vap->va_mode = udf_getaccessmode(udf_node);
	if (vap->va_type == VDIR && ump->flags & UDFMNT_USE_DIRMASK) {
		vap->va_mode = (vap->va_mode & ~ALLPERMS) | ump->dirmode;
	} else if (ump->flags & UDFMNT_USE_MASK) {
		vap->va_mode = (vap->va_mode & ~ALLPERMS) | ump->mode;
	}
	vap->va_nlink = nlink;
	vap->va_uid = uid;
	vap->va_gid = gid;
	vap->va_fsid = dev2udev(ump->devvp->v_rdev);
	vap->va_fileid = udf_node->hash_id;
	vap->va_size = filesize;
	vap->va_blocksize = ump->sector_size; /* wise? */

	/* access times */
	udf_timestamp_to_timespec(ump, atime, &vap->va_atime);
	udf_timestamp_to_timespec(ump, mtime, &vap->va_mtime);
	udf_timestamp_to_timespec(ump, attrtime, &vap->va_ctime);
	udf_timestamp_to_timespec(ump, creatime, &vap->va_birthtime);

	vap->va_gen = 1; /* no multiple generations yes (!?) */
	vap->va_flags = 0;
	vap->va_bytes = blkssize * ump->sector_size;
	vap->va_filerev = 0; /* TODO file revision numbers? */
	vap->va_vaflags = 0;
	/* TODO get vaflags from the extended attributes? */

	if (vap->va_type == VBLK || vap->va_type == VCHR) {
		error = udf_extattr_search_intern(udf_node,
		    UDF_DEVICESPEC_ATTR_NO, "",	&offset, &a_l);
		/* if error, deny access */
		if (error != 0 || filedata == NULL)
			vap->va_mode = 0;	/* or v_type = VNON?  */
		else {
			devattr = (struct device_extattr_entry *)filedata +
			    offset;
			vap->va_rdev = makedev(le32toh(devattr->major),
			    le32toh(devattr->minor));
			/* TODO we could check the implementator */
		}
	}

	return (0);
}

static int
udf_setattr(struct vop_setattr_args *ap)
{
	struct vattr *vap = ap->a_vap;

	/* Abort if any unsettable attribute is given. */
	if (vap->va_type != VNON ||
	    vap->va_nlink != VNOVAL ||
	    vap->va_fsid != VNOVAL ||
	    vap->va_fileid != VNOVAL ||
	    vap->va_blocksize != VNOVAL ||
	    vap->va_gen != VNOVAL ||
	    vap->va_rdev != VNOVAL ||
	    vap->va_bytes != VNOVAL)
		return (EINVAL);

	if (vap->va_flags != VNOVAL ||
	    vap->va_mode != (mode_t)VNOVAL || 
	    vap->va_atime.tv_sec != VNOVAL ||
	    vap->va_mtime.tv_sec != VNOVAL ||
	    vap->va_uid != VNOVAL || 
	    vap->va_gid != VNOVAL) {
		return (EROFS);
	}

	if (vap->va_size != VNOVAL) {
		if (vap->va_type == VDIR)
			return (EISDIR);
		if (vap->va_type == VLNK || vap->va_type == VREG)
			return (EROFS);
	}

	return (0);
}

/*
 * Return POSIX pathconf information for UDF file systems.
 */
static int
udf_pathconf(struct vop_pathconf_args *ap)
{
	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = (1 << 16) - 1; /* 16 bits */
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
		*ap->a_retval = 64; /* XXX ought to deliver 65 */
		return (0);
	}

	return (EINVAL);
}

static int
udf_open(struct vop_open_args *ap)
{
	struct udf_node *udf_node;
	off_t file_size;

	udf_node = VTOI(ap->a_vp);

	if (udf_node->fe != NULL)
		file_size = le64toh(udf_node->fe->inf_len);
	else
		file_size = le64toh(udf_node->efe->inf_len);

	vnode_create_vobject(ap->a_vp, file_size, ap->a_td);

	return (0);
}

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
		if (accmode & VWRITE)
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

	mode = udf_getaccessmode(udf_node);
	if (vp->v_type == VDIR && udf_node->ump->flags & UDFMNT_USE_DIRMASK) {
		mode = (mode & ~ALLPERMS) | udf_node->ump->dirmode;
	} else if (udf_node->ump->flags & UDFMNT_USE_MASK) {
		mode = (mode & ~ALLPERMS) | udf_node->ump->mode;
	}

	if (udf_node->fe != NULL) {
		uid = udf_node->fe->uid;
		gid = udf_node->fe->gid;
	}
	else {
		uid = udf_node->efe->uid;
		gid = udf_node->efe->gid;
	}

	return (vaccess(vp->v_type, mode, uid, gid, accmode, ap->a_cred, NULL));
}

int
udf_readlink(struct vop_readlink_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct pathcomp pathcomp;
	struct udf_node *udf_node;
	int error, filelen, first, len, l_ci, mntonnamelen, namelen, pathlen;
	int targetlen;
	char *mntonname;
	uint8_t *pathbuf, *pathpos, *targetbuf, *targetpos, *tmpname;

	udf_node = VTOI(vp);

	if (udf_node->efe != NULL)
		filelen = le64toh(udf_node->efe->inf_len);
	else
		filelen = le64toh(udf_node->fe->inf_len);

	/* claim temporary buffers for translation */
	pathbuf = malloc(UDF_SYMLINKBUFLEN, M_UDFTEMP, M_WAITOK);
	targetbuf = malloc(PATH_MAX + 1, M_UDFTEMP, M_WAITOK);
	tmpname = malloc(PATH_MAX + 1, M_UDFTEMP, M_WAITOK);
	memset(pathbuf, 0, UDF_SYMLINKBUFLEN);
	memset(targetbuf, 0, PATH_MAX);

	/* read contents of file in our temporary buffer */
	error = vn_rdwr(UIO_READ, vp, pathbuf, filelen, 0, UIO_SYSSPACE,
	    IO_NODELOCKED, FSCRED, NULL, NULL, curthread);
	if (error != 0) {
		/* failed to read in symlink contents */
		free(pathbuf, M_UDFTEMP);
		free(targetbuf, M_UDFTEMP);
		free(tmpname, M_UDFTEMP);
		return (error);
	}

	/* convert to a unix path */
	pathpos = pathbuf;
	pathlen = 0;
	targetpos = targetbuf;
	targetlen = PATH_MAX;
	mntonname = udf_node->ump->vfs_mountp->mnt_stat.f_mntonname;
	mntonnamelen = strlen(mntonname);

	error = 0;
	first = 1;
	while (filelen - pathlen >= UDF_PATH_COMP_SIZE) {
		len = UDF_PATH_COMP_SIZE;
		memcpy(&pathcomp, pathpos, len);
		l_ci = pathcomp.l_ci;
		switch (pathcomp.type) {
		case UDF_PATH_COMP_ROOT:
			/* XXX should check for l_ci; bugcompatible now */
			if (targetlen < 1 || first == 0) {
				error = EINVAL;
				break;
			}
			*targetpos++ = '/';
			targetlen--;
			break;
		case UDF_PATH_COMP_MOUNTROOT:
			/* XXX what should it be if l_ci > 0 ? [4/48.16.1.2] */
			if (l_ci || targetlen < mntonnamelen + 1 || !first) {
				error = EINVAL;
				break;
			}
			memcpy(targetpos, mntonname, mntonnamelen);
			targetpos += mntonnamelen;
			targetlen -= mntonnamelen;
			if (filelen - pathlen > UDF_PATH_COMP_SIZE + l_ci) {
				/* more follows, so must be directory */
				*targetpos++ = '/';
				targetlen--;
			}
			break;
		case UDF_PATH_COMP_PARENTDIR:
			/* XXX should check for l_ci; bugcompatible now */
			if (targetlen < 3) {
				error = EINVAL;
				break;
			}
			*targetpos++ = '.';
			targetlen--;
			*targetpos++ = '.';
			targetlen--;
			*targetpos++ = '/';
			targetlen--;
			break;
		case UDF_PATH_COMP_CURDIR:
			/* XXX should check for l_ci; bugcompatible now */
			if (targetlen < 2) {
				error = EINVAL;
				break;
			}
			*targetpos++ = '.';
			targetlen--;
			*targetpos++ = '/';
			targetlen--;
			break;
		case UDF_PATH_COMP_NAME:
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
			targetpos += namelen;
			targetlen -= namelen;
			if (filelen-pathlen > UDF_PATH_COMP_SIZE + l_ci) {
				/* more follows, so must be directory */
				*targetpos++ = '/';
				targetlen--;
			}
			break;
		default:
			error = EINVAL;
			break;
		}
		first = 0;
		if (error != 0)
			break;
		pathpos += UDF_PATH_COMP_SIZE + l_ci;
		pathlen += UDF_PATH_COMP_SIZE + l_ci;

	}
	/* all processed? */
	if (filelen - pathlen > 0)
		error = EINVAL;

	/* uiomove() to destination */
	if (error == 0)
		uiomove(targetbuf, PATH_MAX - targetlen, uio);

	free(pathbuf, M_UDFTEMP);
	free(targetbuf, M_UDFTEMP);
	free(tmpname, M_UDFTEMP);

	return (error);
}

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
	    devtoname(udf_node->ump->devvp->v_rdev));
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

static int
udf_getpages(struct vop_getpages_args /* {
		struct vnode *a_vp;
		vm_page_t *a_m;
		int a_count;
		int a_reqpage;
		vm_ooffset_t a_offset;
	} */ *ap)
{
	struct buf *bp;
	struct bufobj *bo;
	struct vnode *vp = ap->a_vp;
	vm_page_t *pages;
	daddr_t startreq, lastreq, firstblk, vblock, address;
	off_t filesize, foff, tfoff;
	vm_offset_t kva, curdata;
	int blksperpage, bsize, error, i, numblks, pagecnt, size;
	int curpage, fpage, npage;

	bsize = vp->v_mount->mnt_stat.f_iosize;
	filesize = vp->v_object->un_pager.vnp.vnp_size;
	pages = ap->a_m;
	pagecnt = btoc(ap->a_count);
	blksperpage = PAGE_SIZE / bsize;

	/* 
	 * Free other pages, if requested page is partially valid.  UDF does not
	 * partially fill pages.
	 */
	VM_OBJECT_LOCK(vp->v_object);
	if (pages[ap->a_reqpage]->valid != 0) {
		for (i = 0; i < pagecnt; i++)
			if (i != ap->a_reqpage) {
				vm_page_lock(pages[i]);
				vm_page_free(pages[i]);
				vm_page_unlock(pages[i]);
			}
		VM_OBJECT_UNLOCK(vp->v_object);
		return VM_PAGER_OK;
	}
	VM_OBJECT_UNLOCK(vp->v_object);

	/* Map all memory pages, and then use a single buf object for all 
	bstrategy calls. */
	bp = getpbuf(&udf_pbuf_freecnt);
	bp->b_iocmd = BIO_READ;
	bp->b_iodone = bdone;
	bp->b_rcred = crhold(curthread->td_ucred);
	bp->b_wcred = crhold(curthread->td_ucred);

	curdata = kva = (vm_offset_t)bp->b_data;
	pmap_qenter(kva, pages, pagecnt);

	firstblk = pages[0]->pindex * blksperpage;
	startreq = pages[ap->a_reqpage]->pindex * blksperpage;
	lastreq = startreq + blksperpage - 1;
	if ((lastreq + 1) * bsize > filesize)
		lastreq = (filesize - 1) / bsize;
	fpage = -1;

	for (curpage = 0, vblock = firstblk; vblock <= lastreq; ) {
		error = VOP_BMAP(vp, vblock, &bo, &address, &numblks, NULL);
		if (error)
			goto error;

		numblks++;
		if (vblock + numblks <= startreq) {
			vblock += numblks - 1; /* last block of run */
			npage = (vblock - firstblk) / blksperpage + 1;
			vblock = pages[npage]->pindex * blksperpage; 
			curdata = kva + IDX_TO_OFF(pages[npage]->pindex);
			continue;
		} 

		curpage = ((vblock - firstblk) * bsize) / PAGE_SIZE;

		/* find number of blocks to readahead */
		numblks = MIN(numblks, 
		    blksperpage * pagecnt - (vblock - firstblk));
		if (vblock + numblks - 1 > lastreq)
			numblks -= (vblock - firstblk + numblks) % blksperpage;
		size = bsize * numblks;

		/* from initpbuf() */
		bp->b_qindex = 0;
		bp->b_xflags = 0;
		bp->b_flags = 0;
		bp->b_ioflags = 0;
		bp->b_iodone = NULL;
		bp->b_error = 0;

		/* setup the buffer for this run */
		if (fpage == -1) {
			pbgetbo(bo, bp);
			bp->b_vp = vp;
			fpage = curpage;
		}

		bp->b_data = (caddr_t)curdata;
		bp->b_blkno = address;
		bp->b_lblkno = vblock;
		bp->b_bcount = size; /* this is the current read size. */
		bp->b_bufsize = size;
		bp->b_runningbufspace = bp->b_bufsize;
		atomic_add_long(&runningbufspace, bp->b_runningbufspace);

		bp->b_iooffset = dbtob(bp->b_blkno);
		bstrategy(bp);

		bwait(bp, PVM, "udfvnread");

		if ((bp->b_ioflags & BIO_ERROR) != 0) {
			error = EIO;
			goto error;
		}

		vblock = vblock + numblks;
		curdata += size;
	}

	/* it should error out before here if vblock == firstblk */
	npage = (vblock - 1 - firstblk) / blksperpage + 1;

	if ((vblock - firstblk) % blksperpage != 0) {
		bzero((caddr_t) curdata, 
		    ((vblock - firstblk) % blksperpage) * bsize);
	}

error:
	pmap_qremove(kva, pagecnt);

	bp->b_vp = NULL;
	pbrelbo(bp);
	relpbuf(bp, &vnode_pbuf_freecnt);

	if (error != 0) {
		VM_OBJECT_LOCK(vp->v_object);
		for (i = 0; i < pagecnt; i++)
			if (i != ap->a_reqpage) {
				vm_page_lock(pages[i]);
				vm_page_free(pages[i]);
				vm_page_unlock(pages[i]);
			}
		VM_OBJECT_UNLOCK(vp->v_object);
		return (VM_PAGER_ERROR);
	}

	VM_OBJECT_LOCK(vp->v_object);
	/* remove all pages before first loaded page. */
	for (i = 0; i < fpage; i++) {
		vm_page_lock(pages[i]);
		vm_page_free(pages[i]);
		vm_page_unlock(pages[i]);
	}

	/* mark filled pages. */
	foff = IDX_TO_OFF(pages[fpage]->pindex);
	for (i = fpage, tfoff = foff; i < npage; i++, tfoff += PAGE_SIZE) {
		/* We only read complete pages above. */
		if (tfoff + PAGE_SIZE <= filesize)
			pages[i]->valid = VM_PAGE_BITS_ALL;
		else {
#if __FreeBSD__ < 10
			vm_page_set_valid(pages[i], 0, filesize - tfoff);
#else
			vm_page_set_valid_range(pages[i], 0, filesize - tfoff);
#endif
		}

		if (i != ap->a_reqpage)
			vm_page_readahead_finish(pages[i]);
	}

	/* remove all pages after last loaded page. */
	for (i = npage; i < pagecnt; i++) {
		vm_page_lock(pages[i]);
		vm_page_free(pages[i]);
		vm_page_unlock(pages[i]);
	}
	VM_OBJECT_UNLOCK(vp->v_object);

	return (VM_PAGER_OK);
}

