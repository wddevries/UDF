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

#ifndef _FS_UDF_UDF_H_
#define _FS_UDF_UDF_H_

#include "udf_osta.h"

/* constants to identify what kind of identifier we are dealing with */
#define UDF_REGID_DOMAIN		 1
#define UDF_REGID_UDF			 2
#define UDF_REGID_IMPLEMENTATION	 3
#define UDF_REGID_APPLICATION		 4
#define UDF_REGID_NAME			99

/* Configuration values */
#define UDF_VAT_ALLOC_LIMIT	104857600		/* picked at random */
#define UDF_VAT_CHUNKSIZE	(64*1024)		/* picked */
#define UDF_SYMLINKBUFLEN	(64*1024)		/* picked */

#define UDF_DISC_SLACK		(128)			/* picked, at least 64 kb or 128 */

/* structure space */
#define UDF_ANCHORS		4	/* 256, 512, N-256, N */
#define UDF_PARTITIONS		4	/* overkill */
#define UDF_PMAPS		5	/* overkill */
#define UDF_MAX_ALLOC_EXTENTS	50	/* overkill */

/* constants */
#define UDF_MAX_NAMELEN		255	/* as per SPEC */
#define UDF_TRAN_EXTERNAL	0
#define UDF_TRAN_INTERN		1
#define UDF_TRAN_ZERO		2

/* RW content hint for allocation and other purposes */
#define UDF_C_DSCR		 2	/* update sectornr and CRC */

/* virtual to physical mapping types */
#define UDF_VTOP_RAWPART UDF_PMAPS	/* [0..UDF_PMAPS> are normal     */

#define UDF_VTOP_TYPE_RAW            0
#define UDF_VTOP_TYPE_UNKNOWN        0
#define UDF_VTOP_TYPE_PHYS           1
#define UDF_VTOP_TYPE_VIRT           2
#define UDF_VTOP_TYPE_SPARABLE       3
#define UDF_VTOP_TYPE_META           4

/* logical volume error handling actions */
#define UDF_UPDATE_TRACKINFO	  0x01	/* update trackinfo and re-shedule   */
#define UDF_REMAP_BLOCK		  0x02	/* remap the failing block length    */

/* mounting options */
#define UDFMNT_KICONV 		0x1
#define UDFMNT_OVERRIDE_UID	0x2
#define UDFMNT_OVERRIDE_GID	0x4
#define UDFMNT_USE_MASK		0x8
#define UDFMNT_USE_DIRMASK	0x16

/* malloc pools */
MALLOC_DECLARE(M_UDFTEMP);

struct udf_node;

struct udf_lvintq {
	uint32_t		start;
	uint32_t		end;
	uint32_t		pos;
	uint32_t		wpos;
};

struct udf_mount {
	struct mount		*vfs_mountp;
	struct vnode		*devvp;	
	struct g_consumer	*geomcp;
	uint32_t		 sector_size;
	uint64_t		 flags;
	uid_t			 anon_uid;
	gid_t			 anon_gid;
	void			*iconv_d2l;		/* disk to local */
	mode_t			 mode;
	mode_t			 dirmode;

	/* Used in mounting */
	uint32_t		 first_trackblank;
	uint32_t 		 session_start;
	uint32_t		 session_end;
	uint32_t		 session_last_written;

	/* format descriptors */
	struct anchor_vdp	*anchors[UDF_ANCHORS];	/* anchors to VDS    */
	struct pri_vol_desc	*primary_vol;		/* identification    */
	struct logvol_desc	*logical_vol;		/* main mapping v->p */
	struct unalloc_sp_desc	*unallocated;		/* free UDF space    */
	struct impvol_desc	*implementation;	/* likely reduntant  */
	struct logvol_int_desc	*logvol_integrity;	/* current integrity */
	struct part_desc	*partitions[UDF_PARTITIONS]; /* partitions   */
	/* logvol_info is derived; points *into* other structures */
	struct udf_logvol_info	*logvol_info;		/* integrity descr.  */

	/* fileset and root directories */
	struct fileset_desc	*fileset_desc;		/* normally one      */

	/* logical to physical translations */
	int 			 vtop[UDF_PMAPS+1];	/* vpartnr trans     */
	int			 vtop_tp[UDF_PMAPS+1];	/* type of trans     */

	/* VAT */
	uint32_t		 first_possible_vat_location;
	uint32_t		 last_possible_vat_location;
	uint32_t		 vat_entries;
	uint32_t		 vat_offset;		/* offset in table   */
	uint32_t		 vat_table_alloc_len;
	uint8_t			*vat_table;

	/* sparable */
	uint32_t		 sparable_packet_size;
	struct udf_sparing_table *sparing_table;

	/* meta */
	struct udf_node 	*metadata_node;		/* system node       */
};

/*
 * UDF node describing a file/directory.
 *
 * BUGALERT claim node_mutex before reading/writing to prevent inconsistencies !
 */
struct udf_node {
	struct vnode		*vnode;			/* vnode associated  */
	struct udf_mount	*ump;

	ino_t			 hash_id;		/* should contain inode */
	int			 diroff;		/* used in lookup */

	/* one of `fe' or `efe' can be set, not both (UDF file entry dscr.)  */
	struct file_entry	*fe;
	struct extfile_entry	*efe;
	struct alloc_ext_entry	*ext[UDF_MAX_ALLOC_EXTENTS];
	int			 num_extensions;

	/* location found, recording location & hints */
	struct long_ad		 loc;			/* FID/hash loc.     */
};

struct udf_fid {
	u_short		len;		/* length of data in bytes */
	u_short		padding;		/* force longword alignment */
	ino_t		ino;
};

#endif /* !_FS_UDF_UDF_H_ */
