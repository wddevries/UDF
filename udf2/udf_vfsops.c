/*-
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
#include <sys/kernel.h> /* needed by malloc.h */
#include <sys/malloc.h>
#include <sys/systm.h> /* printf */
#include <sys/fcntl.h> /* needed by namei.h */
#include <sys/namei.h>
#include <sys/proc.h> /* thread */
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/conf.h> /* dev_ref */
#include <sys/module.h> /* MODULE_VERSION */
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

static int udf_mountfs(struct vnode *, struct mount *); 

/* --------------------------------------------------------------------- */

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

/* --------------------------------------------------------------------- */

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

/* --------------------------------------------------------------------- */

#define MPFREE(a, lst) \
	if ((a)) free((a), lst);
static void
free_udf_mountinfo(struct mount *mp)
{
	struct udf_mount *ump;
	int i;

	if (!mp)
		return;

	ump = VFSTOUDF(mp);
	if (ump) {
		/* clear our data */
		for (i = 0; i < UDF_ANCHORS; i++)
			MPFREE(ump->anchors[i], M_UDFTEMP);
		MPFREE(ump->primary_vol,      M_UDFTEMP);
		MPFREE(ump->logical_vol,      M_UDFTEMP);
		MPFREE(ump->unallocated,      M_UDFTEMP);
		MPFREE(ump->implementation,   M_UDFTEMP);
		MPFREE(ump->logvol_integrity, M_UDFTEMP);
		for (i = 0; i < UDF_PARTITIONS; i++) {
			MPFREE(ump->partitions[i],        M_UDFTEMP);
			MPFREE(ump->part_unalloc_dscr[i], M_UDFTEMP);
			MPFREE(ump->part_freed_dscr[i],   M_UDFTEMP);
		}
		MPFREE(ump->metadata_unalloc_dscr, M_UDFTEMP);

		MPFREE(ump->fileset_desc,   M_UDFTEMP);
		MPFREE(ump->sparing_table,  M_UDFTEMP);

#if 0
		MPFREE(ump->la_node_ad_cpy, M_UDFTEMP);
		MPFREE(ump->la_pmapping,    M_UDFTEMP);
		MPFREE(ump->la_lmapping,    M_UDFTEMP);

		mutex_destroy(&ump->ihash_lock);
		mutex_destroy(&ump->get_node_lock);
		mutex_destroy(&ump->logvol_mutex);
		mutex_destroy(&ump->allocate_mutex);
		cv_destroy(&ump->dirtynodes_cv);
#endif

		MPFREE(ump->vat_table, M_UDFTEMP);

		free(ump, M_UDFTEMP);
	}
}
#undef MPFREE

/* --------------------------------------------------------------------- */

/* if the system nodes exist, release them */
static void
udf_release_system_nodes(struct mount *mp)
{
	struct udf_mount *ump = VFSTOUDF(mp);

	/* if we haven't even got an ump, dont bother */
	if (!ump)
		return;

	/* VAT partition support */
	if (ump->vat_node)
		udf_dispose_node(ump->vat_node);

	/* Metadata partition support */
	if (ump->metadata_node)
		udf_dispose_node(ump->metadata_node);
	if (ump->metadatamirror_node)
		udf_dispose_node(ump->metadatamirror_node);
	if (ump->metadatabitmap_node)
		udf_dispose_node(ump->metadatabitmap_node);

#if 0
	/* This flush should NOT write anything nor allow any node to remain */
	if (vflush(ump->vfs_mountp, NULLVP, 0) != 0)
		panic("Failure to flush UDF system vnodes\n");
#endif
}


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
	if (error)
		error = priv_check(td, PRIV_VFS_MOUNT_PERM);
	if (error) {
		vput(devvp);
		return (error);
	}
	

	/*
	 * Open device and try to mount it!
	 */
	if ((error = udf_mountfs(devvp, mp))) {
		vrele(devvp);
		return (error);
	}

	/* successfully mounted */

#if 0 
	/* If we're not opened read-only, open its logical volume */
	if ((mp->mnt_flag & MNT_RDONLY) == 0) {
		if ((error = udf_open_logvol(VFSTOUDF(mp))) != 0) {
			printf( "mount_udf: can't open logical volume for "
				"writing, downgrading access to read-only\n");
			mp->mnt_flag |= MNT_RDONLY;
			/* FIXME we can't return error now on open failure */
			return 0;
		}
	}
#endif
	
	/* TODO: Add some iconv code here. */

	vfs_mountedfrom(mp, fspec);
	return 0;
}

/* --------------------------------------------------------------------- */
#if 0
#ifdef DEBUG
static void
udf_unmount_sanity_check(struct mount *mp)
{
	struct vnode *vp;

	printf("On unmount, i found the following nodes:\n");
	TAILQ_FOREACH(vp, &mp->mnt_vnodelist, v_mntvnodes) {
		vprint("", vp);
		if (VOP_ISLOCKED(vp) == LK_EXCLUSIVE) {
			printf("  is locked\n");
		}
		if (vp->v_usecount > 1)
			printf("  more than one usecount %d\n", vp->v_usecount);
	}
}
#endif
#endif

int
udf_unmount(struct mount *mp, int mntflags)
{
	struct udf_mount *ump;
	int error, flags;

	ump = VFSTOUDF(mp);
	if (!ump)
		panic("UDF unmount: empty ump\n");

	flags = (mntflags & MNT_FORCE) ? FORCECLOSE : 0;

	/* TODO remove these paranoid functions */
#if 0	
#ifdef DEBUG
	if (udf_verbose & UDF_DEBUG_LOCKING)
		udf_unmount_sanity_check(mp);
#endif
#endif
	/*
	 * By specifying SKIPSYSTEM we can skip vnodes marked with VV_SYSTEM.
	 * This hardly documented feature allows us to exempt certain files
	 * from being flushed.
	 */
	if ((error = vflush(mp, 0, flags, curthread)) != 0)
		return error;

	/* update nodes and wait for completion of writeout of system nodes */
#if  0
	udf_sync(mp, FSYNC_WAIT, NOCRED);

#ifdef DEBUG
	if (udf_verbose & UDF_DEBUG_LOCKING)
		udf_unmount_sanity_check(mp);
#endif

	/* flush again, to check if we are still busy for something else */
	if ((error = vflush(ump->vfs_mountp, NULLVP, flags | SKIPSYSTEM)) != 0)
		return error;

	/* close logical volume and close session if requested */
	if ((error = udf_close_logvol(ump, mntflags)) != 0)
		return error;
#ifdef DEBUG
	DPRINTF(VOLUMES, ("FINAL sanity check\n"));
	if (udf_verbose & UDF_DEBUG_LOCKING)
		udf_unmount_sanity_check(mp);
#endif
#endif

	/* NOTE release system nodes should NOT write anything */
	udf_release_system_nodes(mp);

#if 0
	/* finalise disc strategy */
	udf_discstrat_finish(ump);

	/* synchronise device caches */
	(void) udf_synchronise_caches(ump);
#endif

/* TODO: clean up iconv here */
	if (ump->iconv_d2l)
		udf2_iconv->close(ump->iconv_d2l);
#if 0
	if (ump->iconv_d2l)
		udf2_iconv->close(ump->iconv_d2l);
#endif

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

	return 0;
}

/* --------------------------------------------------------------------- */

/*
 * Helper function of udf_mount() that actually mounts the disc.
 */

static int
udf_mountfs(struct vnode *devvp, struct mount *mp)
{
	struct g_consumer *cp;
	struct cdev *dev;
	struct udf_mount     *ump = NULL;
	int    num_anchors, error, len, *udf_flags;
	uint32_t sector_size, bshift, logvol_integrity; /*lb_size,*/
	char *cs_disk, *cs_local;
	void *optdata;

	/* flush out any old buffers remaining from a previous use. */
	/*if ((error = vinvalbuf(devvp, V_SAVE, l->l_cred, l, 0, 0)))
		return error; */

	/* Open a consumer.  This seems to setup the bufobj used later. */
	dev = devvp->v_rdev;
	dev_ref(dev);
	DROP_GIANT();
	g_topology_lock();
	error = g_vfs_open(devvp, &cp, "udf2", 0);
	g_topology_unlock();
	PICKUP_GIANT();
	VOP_UNLOCK(devvp, 0);
	if (error)
		goto fail;

	/* allocate udf part of mount structure; malloc always succeeds */
	ump = malloc(sizeof(struct udf_mount), M_UDFTEMP, M_WAITOK | M_ZERO);
	if (ump == NULL) {
		printf("Memory allocation error for udf_mount struct.");
		error = ENOMEM;
		goto fail;
	}

	/* setup basic mount information */
	mp->mnt_data = ump;
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

	/* init locks */
#if 0
	mutex_init(&ump->logvol_mutex, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&ump->ihash_lock, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&ump->get_node_lock, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&ump->allocate_mutex, MUTEX_DEFAULT, IPL_NONE);
	cv_init(&ump->dirtynodes_cv, "udfsync2");
#endif

	/* set up linkage */
	mp->mnt_data    = ump;
	ump->vfs_mountp = mp;
	ump->devvp = devvp;
	ump->dev = dev;
	ump->geomcp = cp;
	ump->bo = &devvp->v_bufobj;

	/* Load flags for later.  Not sure what to use them for... */
	udf_flags = NULL;
	error = vfs_getopt(mp->mnt_optnew, "flags", (void **)&udf_flags, &len);
	if (error || len != sizeof(int))
		return (EINVAL);
	ump->flags = *udf_flags;
	
	/* read in disk info from options */
	ump->anon_uid = 0;
	ump->anon_gid = 0;
	ump->nobody_uid = -1;
	ump->nobody_gid = -1;

	optdata = NULL;
	error = vfs_getopt(mp->mnt_optnew, "first_trackblank", &optdata, &len);
	if (error || len != sizeof(uint32_t)) {
		error = EINVAL;
		goto fail;
	}
	ump->first_trackblank = *(uint32_t *)optdata;
	
	optdata = NULL;
	error = vfs_getopt(mp->mnt_optnew, "session_start_addr", &optdata, &len);
	if (error || len != sizeof(uint32_t)) {
		error = EINVAL;
		goto fail;
	}
	ump->session_start = *(uint32_t *)optdata;

	optdata = NULL;
	error = vfs_getopt(mp->mnt_optnew, "session_end_addr", &optdata, &len);
	if (error || len != sizeof(uint32_t)) {
		error = EINVAL;
		goto fail;
	}
	ump->session_end = *(uint32_t *)optdata;

	ump->last_possible_vat_location = ump->session_end;

	if (ump->flags & UDFMNT_KICONV && udf2_iconv) {
#if 0
		cs_disk = NULL;
		error = vfs_getopt(mp->mnt_optnew, "cs_disk", (void **)&cs_disk, &len);
		if (error != 0 || cs_disk[len-1] != '\0') {
			error = EINVAL;
			goto fail;
		}
#endif
		cs_disk = "UTF-16BE";

		cs_local = NULL;
		error = vfs_getopt(mp->mnt_optnew, "cs_local", (void **)&cs_local, &len);
		if (error != 0 || cs_local[len-1] != '\0') {
			error = EINVAL;
			goto fail;
		}

		udf2_iconv->open(cs_local, cs_disk, &ump->iconv_d2l);
#if 0
		udf2_iconv->open(cs_disk, cs_local, &ump->iconv_l2d);
#endif
	}
/*	if ((error = udf_update_discinfo(ump))) {
		printf("UDF mount: error inspecting fs node\n");
		return error;
	}*/

	/* inspect sector size */
	sector_size = cp->provider->sectorsize;
	ump->sector_size = sector_size;

	bshift = 1;
	while ((1 << bshift) < sector_size)
		bshift++;
	if ((1 << bshift) != sector_size) {
		printf("UDF mount: "
		       "hit implementation fence on sector size\n");
		return EIO;
	}

	/* temporary check to overcome sectorsize >= 8192 bytes panic */
	if (sector_size >= 8192) {
		printf("UDF mount: "
			"hit implementation limit, sectorsize to big\n");
		return EIO;
	}

#if 0
	/*
	 * Inspect if we're asked to mount read-write on a non recordable or
	 * closed sequential disc.
	 */
	if ((mp->mnt_flag & MNT_RDONLY) == 0) {
		if ((ump->discinfo.mmc_cur & MMC_CAP_RECORDABLE) == 0) {
			printf("UDF mount: disc is not recordable\n");
			return EROFS;
		}
		if (ump->discinfo.mmc_cur & MMC_CAP_SEQUENTIAL) {
			if (ump->discinfo.disc_state == MMC_STATE_FULL) {
				printf("UDF mount: disc is not appendable\n");
				return EROFS;
			}

			/*
			 * TODO if the last session is closed check if there
			 * is enough space to open/close new session
			 */
		}
		/* double check if we're not mounting a pervious session RW */
		if (args->sessionnr != 0) {
			printf("UDF mount: updating a previous session "
				"not yet allowed\n");
			return EROFS;
		}
	}
#endif

#if 0
	/* initialise bootstrap disc strategy */
	ump->strategy = &udf_strat_bootstrap;
	udf_discstrat_init(ump);
#endif

	/* read all anchors to get volume descriptor sequence */
	num_anchors = udf_read_anchors(ump);
	if (num_anchors == 0) {
		printf("UDF mount: error reading anchors\n");
		error = EINVAL;
		goto fail;
	}

	/* read in volume descriptor sequence */
	if ((error = udf_read_vds_space(ump))) {
		printf("UDF mount: error reading volume space\n");
		goto fail;
	}

#if 0
	/* close down bootstrap disc strategy */
	udf_discstrat_finish(ump);
#endif

	/* check consistency and completeness */
	if ((error = udf_process_vds(ump))) {
		printf( "UDF mount: disc not properly formatted(bad VDS)\n");
		goto fail;
	}

#if 0
	/* switch to new disc strategy */
	KASSERT(ump->strategy != &udf_strat_bootstrap,
		("ump->strategy != &udf_strat_bootstrap"));
	udf_discstrat_init(ump);

	/* initialise late allocation administration space */
	ump->la_lmapping = malloc(sizeof(uint64_t) * UDF_MAX_MAPPINGS,
			M_UDFTEMP, M_WAITOK);
	ump->la_pmapping = malloc(sizeof(uint64_t) * UDF_MAX_MAPPINGS,
			M_UDFTEMP, M_WAITOK);

	/* setup node cleanup extents copy space */
	lb_size = le32toh(ump->logical_vol->lb_size);
	ump->la_node_ad_cpy = malloc(lb_size * UDF_MAX_ALLOC_EXTENTS,
		M_UDFTEMP, M_WAITOK);
	memset(ump->la_node_ad_cpy, 0, lb_size * UDF_MAX_ALLOC_EXTENTS);
#endif

	/* setup rest of mount information */

	/* note that the mp info needs to be initialised for reading! */
	/* read vds support tables like VAT, sparable etc. */
	if ((error = udf_read_vds_tables(ump))) {
		printf( "UDF mount: error in format or damaged disc "
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
	if ((error = udf_read_rootdirs(ump))) {
		printf( "UDF mount: "
			"disc not properly formatted or damaged disc "
			"(rootdirs failing)\n");
		goto fail;
	}

	/* do we have to set this? */
	/* devvp->v_specmountpoint = mp; */

	/* success! */
	return 0;

fail:
	if (cp != NULL) {
		DROP_GIANT();
		g_topology_lock();
		g_vfs_close(cp);
		g_topology_unlock();
		PICKUP_GIANT();
	}
	dev_rel(dev);
	if (ump != NULL) {
		udf_release_system_nodes(mp);
		/*udf_discstrat_finish(VFSTOUDF(mp)); */
		free_udf_mountinfo(mp);
	}
	return error;
}

/* --------------------------------------------------------------------- */

int
udf_root(struct mount *mp, int flags, struct vnode **vpp)
{
	struct long_ad *dir_loc;
	struct udf_mount *ump = VFSTOUDF(mp);
	ino_t ino;
	int error;

	dir_loc = &ump->fileset_desc->rootdir_icb;
	ino = udf_get_node_id(dir_loc);
	error = udf_vget(mp, ino, flags, vpp);
	if (!((*vpp)->v_vflag & VV_ROOT)) {
		printf("NOT A ROOT NODE?");
		return EDOOFUS;
	}
	return error;
}

/* --------------------------------------------------------------------- */

int
udf_statfs(struct mount *mp, struct statfs *sbp)
{
	struct udf_mount *ump = VFSTOUDF(mp);
	struct logvol_int_desc *lvid;
	struct udf_logvol_info *impl;
	uint64_t sizeblks, freeblks, files; 
	int num_part;
	
/*	mutex_enter(&ump->allocate_mutex); */
	udf_calc_freespace(ump, &sizeblks, &freeblks);
	//sizeblks = 0; // added to make if just compile.
	//freeblks = 0;
	files = 0;

	lvid = ump->logvol_integrity;
	num_part = le32toh(lvid->num_part);
	impl = (struct udf_logvol_info *) (lvid->tables + 2*num_part);
	if (impl) {
		files  = le32toh(impl->num_files);
		files += le32toh(impl->num_directories);
	}
/*	mutex_exit(&ump->allocate_mutex); */
	
	sbp->f_version = STATFS_VERSION; 	/* structure version number */
	/*uint32_t f_type;*/			/* type of filesystem */
	sbp->f_flags   = mp->mnt_flag; 		/* copy of mount exported flags */
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
	/*fsid_t	  f_fsid;*/		/* filesystem id */
	/*char	  f_charspare[80];*/	    	/* spare string space */
	/*char	  f_fstypename[MFSNAMELEN];*/ 	/* filesystem type name */
	/*char	  f_mntfromname[MNAMELEN];*/  	/* mounted filesystem */
	/*char	  f_mntonname[MNAMELEN];*/    	/* directory on which mounted */
	
	return 0;
}

/* --------------------------------------------------------------------- */

/*
 * TODO what about writing out free space maps, lvid etc? only on `waitfor'
 * i.e. explicit syncing by the user?
 */
#if 0
static int
udf_sync_writeout_system_files(struct udf_mount *ump, int clearflags)
{
	int error;

	/* XXX lock for VAT en bitmaps? */
	/* metadata nodes are written synchronous */
	DPRINTF(CALL, ("udf_sync: syncing metadata\n"));
	if (ump->lvclose & UDF_WRITE_VAT)
		udf_writeout_vat(ump);

	error = 0;
	if (ump->lvclose & UDF_WRITE_PART_BITMAPS) {
		/* writeout metadata spacetable if existing */
		error = udf_write_metadata_partition_spacetable(ump, MNT_WAIT);
		if (error)
			printf( "udf_writeout_system_files : "
				" writeout of metadata space bitmap failed\n");

		/* writeout partition spacetables */
		error = udf_write_physical_partition_spacetables(ump, MNT_WAIT);
		if (error)
			printf( "udf_writeout_system_files : "
				"writeout of space tables failed\n");
		if (!error && clearflags)
			ump->lvclose &= ~UDF_WRITE_PART_BITMAPS;
	}

	return error;
}


int
udf_sync(struct mount *mp, int waitfor, kauth_cred_t cred)
{
	struct udf_mount *ump = VFSTOUDF(mp);

	DPRINTF(CALL, ("udf_sync called\n"));
	/* if called when mounted readonly, just ignore */
	if (mp->mnt_flag & MNT_RDONLY)
		return 0;

	if (ump->syncing && !waitfor) {
		printf("UDF: skipping autosync\n");
		return 0;
	}

	/* get sync lock */
	ump->syncing = 1;

	/* pre-sync */
	udf_do_sync(ump, cred, waitfor);

	if (waitfor == MNT_WAIT)
		udf_sync_writeout_system_files(ump, true);

	DPRINTF(CALL, ("end of udf_sync()\n"));
	ump->syncing = 0;

	return 0;
}
#endif

/* This added only for temp use */
struct udf_node *
udf_alloc_node()
{
	return uma_zalloc(udf_zone_node, M_WAITOK | M_ZERO);
}

void 
udf_free_node(struct udf_node *unode)
{
	uma_zfree(udf_zone_node, unode);
}
/* --------------------------------------------------------------------- */

/*
 * Get vnode for the file system type specific file id ino for the fs. Its
 * used for reference to files by unique ID and for NFSv3.
 * (optional) TODO lookup why some sources state NFSv3


 This done as in the current udf implementation.  I really have no idea
 if it is correct.
 */
int
udf_vget(struct mount *mp, ino_t ino, int flags, struct vnode **vpp)
{
	struct vnode *nvp;
	struct udf_node *unode;
	struct udf_mount *ump;
	int error, udf_file_type;

	error = vfs_hash_get(mp, ino, flags, curthread, vpp, NULL, NULL);
	if (error || *vpp != NULL)
		return error;

	if ((flags & LK_TYPE_MASK) == LK_SHARED) {
		flags &= ~LK_TYPE_MASK;
		flags |= LK_EXCLUSIVE;
	}

	ump = VFSTOUDF(mp);
	error = udf_getanode(mp, &nvp);
	if (error)
		return error;
	
	lockmgr(nvp->v_vnlock, LK_EXCLUSIVE, NULL);
	if ((error = insmntque(nvp, mp)) != 0)
		return error;

	/* TODO: Does this leak unode or vnodes? */
	error = vfs_hash_insert(nvp, ino, flags, curthread, vpp, NULL, NULL);
	if (error || *vpp != NULL)
		return error;


	/* 
	 * Load read and set up the unode structure.
	 */
	error = udf_get_node(ump, ino, &unode);
	if (error) {
		vgone(nvp);
		vput(nvp);
	}
	nvp->v_data = unode;
	unode->vnode = nvp;

	/* mark the root node as such */
	if (ump->fileset_desc && 
	    ino == udf_get_node_id(&ump->fileset_desc->rootdir_icb)) 
		nvp->v_vflag |= VV_ROOT;

	/*
	 * Translate UDF filetypes into vnode types.
	 *
	 * Systemfiles like the meta main and mirror files are not treated as
	 * normal files, so we type them as having no type. UDF dictates that
	 * they are not allowed to be visible.
	 */
	if (unode->fe)
		udf_file_type = unode->fe->icbtag.file_type;
	else
		udf_file_type = unode->efe->icbtag.file_type;
		
	switch (udf_file_type) {
	case UDF_ICB_FILETYPE_DIRECTORY :
	case UDF_ICB_FILETYPE_STREAMDIR :
		nvp->v_type = VDIR;
		break;
	case UDF_ICB_FILETYPE_BLOCKDEVICE :
		nvp->v_type = VBLK;
		break;
	case UDF_ICB_FILETYPE_CHARDEVICE :
		nvp->v_type = VCHR;
		break;
	case UDF_ICB_FILETYPE_SOCKET :
		nvp->v_type = VSOCK;
		break;
	case UDF_ICB_FILETYPE_FIFO :
		nvp->v_type = VFIFO;
		break;
	case UDF_ICB_FILETYPE_SYMLINK :
		nvp->v_type = VLNK;
		break;
	case UDF_ICB_FILETYPE_VAT :
	case UDF_ICB_FILETYPE_META_MAIN :
	case UDF_ICB_FILETYPE_META_MIRROR :
		nvp->v_type = VNON;
		break;
	case UDF_ICB_FILETYPE_RANDOMACCESS :
	case UDF_ICB_FILETYPE_REALTIME :
		nvp->v_type = VREG;
		break;
	default:
		/* YIKES, something else */
		nvp->v_type = VNON;
	}

	/* TODO specfs, fifofs etc etc. vnops setting */

	/* don't forget to set vnode's v_size */
/*	uvm_vnp_setsize(nvp, file_size); */

	if (nvp->v_type != VFIFO)
		VN_LOCK_ASHARE(nvp);

	*vpp = nvp;

	return 0;
}

/* --------------------------------------------------------------------- */

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
		return error;
	}

	udf_node = VTOI(vp);
	if (udf_node->efe)
		filelen = le64toh(udf_node->efe->inf_len);
	else
		filelen = le64toh(udf_node->fe->inf_len);

	vnode_create_vobject(vp, filelen, curthread);
	*vpp = vp;

	return 0;
}

