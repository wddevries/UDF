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
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/cdefs.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/conf.h>
#include <sys/module.h>
#include <sys/priv.h>
#include <sys/iconv.h>
#include <geom/geom.h>
#include <geom/geom_vfs.h>

#include "ecma167-udf.h"
#include "udf.h"
#include "udf_subr.h"
#include "udf_mount.h"

MALLOC_DEFINE(M_UDFTEMP, "UDF temp", "UDF allocation space");
uma_zone_t udf_zone_node = NULL;

struct iconv_functions *udf2_iconv = NULL;

static int	udf_mountfs(struct vnode *, struct mount *); 


/* predefine vnode-op list descriptor */

static vfs_fhtovp_t	udf_fhtovp;
static vfs_init_t	udf_init;
static vfs_mount_t	udf_mount;
static vfs_root_t	udf_root;
static vfs_statfs_t	udf_statfs;
static vfs_uninit_t	udf_uninit;
static vfs_unmount_t	udf_unmount;

static struct vfsops udf_vfsops = {
	.vfs_init =		udf_init,
	.vfs_uninit =		udf_uninit,
	.vfs_mount =		udf_mount,
	.vfs_root =		udf_root,
	.vfs_statfs =		udf_statfs,
	.vfs_unmount =		udf_unmount,
	.vfs_fhtovp =		udf_fhtovp,
	.vfs_vget =		udf_vget
};
VFS_SET(udf_vfsops, udf2, VFCF_READONLY);

MODULE_VERSION(udf2, 1);


static int
udf_init(struct vfsconf *notused)
{
	/* init node pools */
	udf_zone_node = uma_zcreate("UDF Node Pool Zone", 
	    sizeof(struct udf_node), NULL, NULL, NULL, NULL, 0, 0);

	if (udf_zone_node == NULL) {
		printf("Cannot create node pool zone.");
		return (ENOMEM);
	}

	return (0);
}

static int
udf_uninit(struct vfsconf *notused)
{
	/* remove pools */
	if (udf_zone_node != NULL) {
		uma_zdestroy(udf_zone_node);
		udf_zone_node = NULL;
	}

	return (0);
}

#define MPFREE(a, lst) \
	if ((a)) free((a), lst);
static void
free_udf_mountinfo(struct mount *mp)
{
	struct udf_mount *ump;
	int i;

	if (mp == NULL)
		return;

	ump = VFSTOUDF(mp);
	if (ump != NULL) {
		/* VAT partition support */
		if (ump->vat_node != NULL)
			udf_dispose_node(ump->vat_node);

		/* Metadata partition support */
		if (ump->metadata_node != NULL)
			udf_dispose_node(ump->metadata_node);
		if (ump->metadatamirror_node != NULL)
			udf_dispose_node(ump->metadatamirror_node);
		if (ump->metadatabitmap_node != NULL)
			udf_dispose_node(ump->metadatabitmap_node);

		/* clear our data */
		for (i = 0; i < UDF_ANCHORS; i++)
			MPFREE(ump->anchors[i], M_UDFTEMP);
		MPFREE(ump->primary_vol, M_UDFTEMP);
		MPFREE(ump->logical_vol, M_UDFTEMP);
		MPFREE(ump->unallocated, M_UDFTEMP);
		MPFREE(ump->implementation, M_UDFTEMP);
		MPFREE(ump->logvol_integrity, M_UDFTEMP);
		for (i = 0; i < UDF_PARTITIONS; i++) {
			MPFREE(ump->partitions[i], M_UDFTEMP);
			MPFREE(ump->part_unalloc_dscr[i], M_UDFTEMP);
			MPFREE(ump->part_freed_dscr[i], M_UDFTEMP);
		}
		MPFREE(ump->metadata_unalloc_dscr, M_UDFTEMP);
		MPFREE(ump->fileset_desc, M_UDFTEMP);
		MPFREE(ump->sparing_table, M_UDFTEMP);
		MPFREE(ump->vat_table, M_UDFTEMP);

		free(ump, M_UDFTEMP);
	}
}
#undef MPFREE

static int
udf_mount(struct mount *mp)
{
	struct thread *td;	
	struct vnode *devvp;
	struct nameidata nd;
	int error, len;
	char *fspec;
	
	td = curthread;

	MNT_ILOCK(mp);
	mp->mnt_flag |= MNT_RDONLY;
	MNT_IUNLOCK(mp);

	if (mp->mnt_flag & MNT_ROOTFS)
		return (ENOTSUP);

	/* handle request for updating mount parameters */
	/* TODO can't update my mountpoint yet */
	if (mp->mnt_flag & MNT_UPDATE)
		return (0);
	
	fspec = NULL;
	error = vfs_getopt(mp->mnt_optnew, "from", (void **)&fspec, &len);
	if (!error && fspec[len - 1] != '\0')
		return (EINVAL);
	if (fspec == NULL)
		return (EINVAL);

	/* lookup name to get its vnode */
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, fspec, td);
	if ((error = namei(&nd)))
		return (error);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	devvp = nd.ni_vp;
	if (vn_isdisk(devvp, &error) == 0) {
		vput(devvp);
		return (error);
	}

	error = VOP_ACCESS(devvp, VREAD, td->td_ucred, td);
	if (error != 0)
		error = priv_check(td, PRIV_VFS_MOUNT_PERM);
	if (error != 0) {
		vput(devvp);
		return (error);
	}
	

	/*
	 * Open device and try to mount it!
	 */
	error = udf_mountfs(devvp, mp);
	if (error != 0) {
		vrele(devvp);
		return (error);
	}

	vfs_mountedfrom(mp, fspec);
	return (0);
}


int
udf_unmount(struct mount *mp, int mntflags)
{
	struct udf_mount *ump;
	int error, flags;

	ump = VFSTOUDF(mp);
	if (ump == NULL)
		panic("UDF unmount: empty ump\n");

	flags = (mntflags & MNT_FORCE) ? FORCECLOSE : 0;

	/*
	 * By specifying SKIPSYSTEM we can skip vnodes marked with VV_SYSTEM.
	 * This hardly documented feature allows us to exempt certain files
	 * from being flushed.
	 */
	error = vflush(mp, 0, flags, curthread);
	if (error != 0)
		return (error);

	if (ump->iconv_d2l != NULL)
		udf2_iconv->close(ump->iconv_d2l);

	DROP_GIANT();
	g_topology_lock();
	g_vfs_close(ump->geomcp);
	g_topology_unlock();
	PICKUP_GIANT();
	vrele(ump->devvp);
	dev_rel(ump->dev);

	/* free our ump */
	free_udf_mountinfo(mp);

	/* free ump struct references */
	mp->mnt_data = NULL;
	MNT_ILOCK(mp);
	mp->mnt_flag &= ~MNT_LOCAL;
	MNT_IUNLOCK(mp);

	return (0);
}

/*
 * Helper function of udf_mount() that actually mounts the disc.
 */
static int
udf_mountfs(struct vnode *devvp, struct mount *mp)
{
	struct g_consumer *cp;
	struct cdev *dev;
	struct udf_mount *ump = NULL;
	int error, len, num_anchors, *udf_flags;
	uint32_t bshift, logvol_integrity, numsecs; /*lb_size,*/
	char *cs_disk, *cs_local;
	void *optdata;

	/* Open a consumer. */
	dev = devvp->v_rdev;
	dev_ref(dev);
	DROP_GIANT();
	g_topology_lock();
	error = g_vfs_open(devvp, &cp, "udf2", 0);
	g_topology_unlock();
	PICKUP_GIANT();
	VOP_UNLOCK(devvp, 0);
	if (error != 0)
		goto fail;

	/* setup basic mount information */
	mp->mnt_stat.f_fsid.val[0] = dev2udev(devvp->v_rdev);
	mp->mnt_stat.f_fsid.val[1] = mp->mnt_vfc->vfc_typenum;
	mp->mnt_stat.f_namemax = UDF_MAX_NAMELEN;
	if (devvp->v_rdev->si_iosize_max != 0)
		mp->mnt_iosize_max = devvp->v_rdev->si_iosize_max;
	if (mp->mnt_iosize_max > MAXPHYS)
		mp->mnt_iosize_max = MAXPHYS;
	MNT_ILOCK(mp);
	mp->mnt_flag |= MNT_LOCAL;
	mp->mnt_kern_flag |= MNTK_MPSAFE | MNTK_LOOKUP_SHARED |
		MNTK_EXTENDED_SHARED;
	MNT_IUNLOCK(mp);

	ump = malloc(sizeof(struct udf_mount), M_UDFTEMP, M_WAITOK | M_ZERO);

#if 0
	/* init locks */
	mutex_init(&ump->logvol_mutex, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&ump->ihash_lock, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&ump->get_node_lock, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&ump->allocate_mutex, MUTEX_DEFAULT, IPL_NONE);
	cv_init(&ump->dirtynodes_cv, "udfsync2");
#endif

	/* set up linkage */
	mp->mnt_data = ump;
	ump->vfs_mountp = mp;
	ump->devvp = devvp;
	ump->dev = dev;
	ump->geomcp = cp;
	ump->bo = &devvp->v_bufobj;

	/* Load flags for later.  Not sure what to use them for... */
	udf_flags = NULL;
	error = vfs_getopt(mp->mnt_optnew, "flags", (void **)&udf_flags, &len);
	if (error != 0 || len != sizeof(int))
		return (EINVAL);
	ump->flags = *udf_flags;
	
	/* read in disk info from options */
	ump->anon_uid = 0;
	ump->anon_gid = 0;
	ump->nobody_uid = -1;
	ump->nobody_gid = -1;

	optdata = NULL;
	error = vfs_getopt(mp->mnt_optnew, "first_trackblank", &optdata, &len);
	if (error != 0 || len != sizeof(uint8_t)) {
		error = EINVAL;
		goto fail;
	}
	ump->first_trackblank = *(uint8_t *)optdata;
	
	optdata = NULL;
	error = vfs_getopt(mp->mnt_optnew, "session_start_addr", &optdata,
	    &len);
	if (error != 0 || len != sizeof(uint32_t)) {
		error = EINVAL;
		goto fail;
	}
	ump->session_start = *(uint32_t *)optdata;

	optdata = NULL;
	error = vfs_getopt(mp->mnt_optnew, "session_end_addr", &optdata, &len);
	if (error != 0 || len != sizeof(uint32_t)) {
		error = EINVAL;
		goto fail;
	}
	ump->session_end = *(uint32_t *)optdata;

	optdata = NULL;
	error = vfs_getopt(mp->mnt_optnew, "session_last_written", &optdata, &len);
	if (error != 0 || len != sizeof(uint32_t)) {
		error = EINVAL;
		goto fail;
	}
	ump->session_last_written = *(uint32_t *)optdata;

	/* We do not want the session_end value to be zero. */
	numsecs = cp->provider->mediasize / cp->provider->sectorsize;
	if (ump->session_end == 0)
		ump->session_end = numsecs;

	/* We should only need to search one, so this is also a hack. */
	if (ump->session_end - ump->session_start > 25)
		ump->first_possible_vat_location = ump->session_last_written -
		    25; 
	else
		ump->first_possible_vat_location = ump->session_start;
	ump->last_possible_vat_location = ump->session_last_written;

	if (ump->flags & UDFMNT_KICONV && udf2_iconv != NULL) {
		cs_disk = "UTF-16BE";

		cs_local = NULL;
		error = vfs_getopt(mp->mnt_optnew, "cs_local", 
		    (void **)&cs_local, &len);
		if (error != 0 || cs_local[len-1] != '\0') {
			error = EINVAL;
			goto fail;
		}

		udf2_iconv->open(cs_local, cs_disk, &ump->iconv_d2l);
	}

	/* inspect sector size */
	ump->sector_size = cp->provider->sectorsize;

	bshift = 1;
	while ((1 << bshift) < ump->sector_size)
		bshift++;
	if ((1 << bshift) != ump->sector_size) {
		printf("UDF mount: "
		       "hit implementation fence on sector size\n");
		return (EIO);
	}

	/* temporary check to overcome sectorsize >= 8192 bytes panic */
	if (ump->sector_size >= 8192) {
		printf("UDF mount: "
			"hit implementation limit, sectorsize to big\n");
		return (EIO);
	}


	/* read all anchors to get volume descriptor sequence */
	num_anchors = udf_read_anchors(ump);
	if (num_anchors == 0) {
		printf("UDF mount: error reading anchors\n");
		error = EINVAL;
		goto fail;
	}

	/* read in volume descriptor sequence */
	error = udf_read_vds_space(ump);
	if (error != 0) {
		printf("UDF mount: error reading volume space\n");
		goto fail;
	}

	/* check consistency and completeness */
	error = udf_process_vds(ump);
	if (error != 0) {
		printf( "UDF mount: disc not properly formatted(bad VDS)\n");
		goto fail;
	}

	/* note that the mp info needs to be initialised for reading! */
	/* read vds support tables like VAT, sparable etc. */
	error = udf_read_vds_tables(ump);
	if (error != 0) {
		printf("UDF mount: error in format or damaged disc "
		    "(VDS tables failing)\n");
		goto fail;
	}

	/* check if volume integrity is closed otherwise its dirty */
	logvol_integrity = le32toh(ump->logvol_integrity->integrity_type);
	if (logvol_integrity != UDF_INTEGRITY_CLOSED) {
		printf("UDF mount: file system is not clean; ");
		printf("please fsck(8)\n");
		error = EPERM;
		goto fail;
	}

	/* read root directory */
	error = udf_read_rootdirs(ump);
	if (error != 0) {
		printf("UDF mount: disc not properly formatted or damaged disc "
		    "(rootdirs failing)\n");
		goto fail;
	}

	/* success! */
	return (0);

fail:
	if (cp != NULL) {
		DROP_GIANT();
		g_topology_lock();
		g_vfs_close(cp);
		g_topology_unlock();
		PICKUP_GIANT();
	}
	dev_rel(dev);
	if (ump != NULL)
		free_udf_mountinfo(mp);

	return (error);
}

int
udf_root(struct mount *mp, int flags, struct vnode **vpp)
{
	struct udf_mount *ump = VFSTOUDF(mp);
	ino_t ino;
	int error;

	error = udf_get_node_id(ump->fileset_desc->rootdir_icb, &ino);
	if (error == 0)
		error = udf_vget(mp, ino, flags, vpp);
	if (error != 0 && ((*vpp)->v_vflag & VV_ROOT) == 0) {
		printf("NOT A ROOT NODE?");
		return (EDOOFUS);
	}

	return (error);
}

int
udf_statfs(struct mount *mp, struct statfs *sbp)
{
	struct udf_mount *ump = VFSTOUDF(mp);
	struct logvol_int_desc *lvid;
	struct udf_logvol_info *impl;
	uint64_t files, freeblks, sizeblks; 
	int num_part;
	
/*	mutex_enter(&ump->allocate_mutex); */
	udf_calc_freespace(ump, &sizeblks, &freeblks);
	files = 0;

	lvid = ump->logvol_integrity;
	num_part = le32toh(lvid->num_part);
	impl = (struct udf_logvol_info *)(lvid->tables + 2*num_part);
	if (impl != NULL) {
		files = le32toh(impl->num_files);
		files += le32toh(impl->num_directories);
	}
/*	mutex_exit(&ump->allocate_mutex); */
	
	sbp->f_version = STATFS_VERSION; 	/* structure version number */
	/*uint32_t f_type;*/			/* type of filesystem */
	sbp->f_flags = mp->mnt_flag; 		/* copy of mount exported flags */
	sbp->f_bsize = ump->sector_size; 	/* filesystem fragment size */
	sbp->f_iosize = ump->sector_size; 	/* optimal transfer block size */
	sbp->f_blocks = sizeblks;		/* total data blocks in filesystem */
	sbp->f_bfree  = freeblks;		/* free blocks in filesystem */
	sbp->f_bavail = 0;			/* free blocks avail to non-superuser */
	sbp->f_files = files;			/* total file nodes in filesystem */
	sbp->f_ffree  = 0;			/* free nodes avail to non-superuser */
	/*uint64_t f_syncwrites;*/		/* count of sync writes since mount */
	/*uint64_t f_asyncwrites;*/		/* count of async writes since mount */
	/*uint64_t f_syncreads;*/		/* count of sync reads since mount */
	/*uint64_t f_asyncreads;*/		/* count of async reads since mount */
	/*uint64_t f_spare[10];*/		/* unused spare */
	/*uint32_t f_namemax;*/			/* maximum filename length */
	/*uid_t	  f_owner;*/			/* user that mounted the filesystem */
	/*fsid_t  f_fsid;*/			/* filesystem id */
	/*char	  f_charspare[80];*/	    	/* spare string space */
	/*char	  f_fstypename[MFSNAMELEN];*/ 	/* filesystem type name */
	/*char	  f_mntfromname[MNAMELEN];*/  	/* mounted filesystem */
	/*char	  f_mntonname[MNAMELEN];*/    	/* directory on which mounted */
	
	return (0);
}

struct udf_node *
udf_alloc_node()
{
	return (uma_zalloc(udf_zone_node, M_WAITOK | M_ZERO));
}

void 
udf_free_node(struct udf_node *unode)
{
	uma_zfree(udf_zone_node, unode);
}

/*
 * Get vnode for the file system type specific file id ino for the fs. Its
 * used for reference to files by unique ID and for NFSv3.
 * (optional) TODO lookup why some sources state NFSv3
 */
int
udf_vget(struct mount *mp, ino_t ino, int flags, struct vnode **vpp)
{
	struct vnode *nvp;
	struct udf_node *unode;
	struct udf_mount *ump;
	struct long_ad icb;
	int error, udf_file_type;

	error = vfs_hash_get(mp, ino, flags, curthread, vpp, NULL, NULL);
	if (error != 0 || *vpp != NULL)
		return (error);

	if ((flags & LK_TYPE_MASK) == LK_SHARED) {
		flags &= ~LK_TYPE_MASK;
		flags |= LK_EXCLUSIVE;
	}

	ump = VFSTOUDF(mp);
	error = udf_getanode(mp, &nvp);
	if (error != 0)
		return (error);
	
	lockmgr(nvp->v_vnlock, LK_EXCLUSIVE, NULL);
	error = insmntque(nvp, mp);
	if (error != 0)
		return (error);

	/* TODO: Does this leak unode or vnodes? */
	error = vfs_hash_insert(nvp, ino, flags, curthread, vpp, NULL, NULL);
	if (error != 0 || *vpp != NULL)
		return (error);

	/* 
	 * Load read and set up the unode structure.
	 */
	udf_get_node_longad(ino, &icb);
	error = udf_get_node(ump, icb, &unode);
	if (error != 0) {
		vgone(nvp);
		vput(nvp);
		return (error);
	}
	nvp->v_data = unode;
	unode->vnode = nvp;
	unode->hash_id = ino;

	/* mark the root node as such */
	if (ump->fileset_desc && 
	    icb.loc.lb_num == ump->fileset_desc->rootdir_icb.loc.lb_num && 
	    icb.loc.part_num == ump->fileset_desc->rootdir_icb.loc.part_num)
		nvp->v_vflag |= VV_ROOT;

	/*
	 * Translate UDF filetypes into vnode types.
	 *
	 * Systemfiles like the meta main and mirror files are not treated as
	 * normal files, so we type them as having no type. UDF dictates that
	 * they are not allowed to be visible.
	 */
	if (unode->fe != NULL)
		udf_file_type = unode->fe->icbtag.file_type;
	else
		udf_file_type = unode->efe->icbtag.file_type;
		
	switch (udf_file_type) {
	case UDF_ICB_FILETYPE_DIRECTORY:
	case UDF_ICB_FILETYPE_STREAMDIR:
		nvp->v_type = VDIR;
		break;
	case UDF_ICB_FILETYPE_BLOCKDEVICE:
		nvp->v_type = VBLK;
		break;
	case UDF_ICB_FILETYPE_CHARDEVICE:
		nvp->v_type = VCHR;
		break;
	case UDF_ICB_FILETYPE_SOCKET:
		nvp->v_type = VSOCK;
		break;
	case UDF_ICB_FILETYPE_FIFO:
		nvp->v_type = VFIFO;
		break;
	case UDF_ICB_FILETYPE_SYMLINK:
		nvp->v_type = VLNK;
		break;
	case UDF_ICB_FILETYPE_VAT:
	case UDF_ICB_FILETYPE_META_MAIN:
	case UDF_ICB_FILETYPE_META_MIRROR:
		nvp->v_type = VNON;
		break;
	case UDF_ICB_FILETYPE_RANDOMACCESS:
	case UDF_ICB_FILETYPE_REALTIME:
		nvp->v_type = VREG;
		break;
	default:
		/* YIKES, something else */
		nvp->v_type = VNON;
	}

	if (nvp->v_type != VFIFO)
		VN_LOCK_ASHARE(nvp);

	*vpp = nvp;

	return (0);
}

/*
 * Lookup vnode for file handle specified
 */
int
udf_fhtovp(struct mount *mp, struct fid *fhp, int flags,
    struct vnode **vpp)
{
	struct vnode *vp;
	struct udf_fid *ufid = (struct udf_fid*)fhp;
	struct udf_node *udf_node;
	uint64_t filelen;
	int error;
	
	error = VFS_VGET(mp, ufid->ino, LK_EXCLUSIVE, &vp);
	if (error != 0) {
		*vpp = NULLVP;
		return (error);
	}

	udf_node = VTOI(vp);
	if (udf_node->efe != NULL)
		filelen = le64toh(udf_node->efe->inf_len);
	else
		filelen = le64toh(udf_node->fe->inf_len);

	vnode_create_vobject(vp, filelen, curthread);
	*vpp = vp;

	return (0);
}

