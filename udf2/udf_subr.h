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

#ifndef _FS_UDF_UDF_SUBR_H_
#define _FS_UDF_UDF_SUBR_H_

/* handies */
#define	VFSTOUDF(mp)	((struct udf_mount *)mp->mnt_data)
#define VTOI(vnode) ((struct udf_node *) (vnode)->v_data)

struct buf;
struct long_ad;

/* tags operations */
int	udf_fidsize(struct fileid_desc *fid);
int	udf_check_tag(void *blob);
int	udf_check_tag_payload(void *blob, uint32_t max_length);
void	udf_validate_tag_sum(void *blob);
void	udf_validate_tag_and_crc_sums(void *blob);
int	udf_tagsize(union dscrptr *dscr, uint32_t udf_sector_size);

/* read/write descriptors */
int	udf_read_phys_dscr(struct udf_mount *ump, uint32_t sector,
	    struct malloc_type *mtype, union dscrptr **dstp);

/* volume descriptors readers and checkers */
int	udf_read_anchors(struct udf_mount *ump);
int	udf_read_vds_space(struct udf_mount *ump);
int	udf_process_vds(struct udf_mount *ump);
int	udf_read_vds_tables(struct udf_mount *ump);
int	udf_read_rootdirs(struct udf_mount *ump);

/* open/close and sync volumes */
int	udf_open_logvol(struct udf_mount *ump);
int	udf_close_logvol(struct udf_mount *ump, int mntflags);

/* translation services */
int	udf_translate_vtop(struct udf_mount *ump, struct long_ad *icb_loc,
	    uint32_t *lb_numres, uint32_t *extres);
int	udf_bmap_translate(struct udf_node *udf_node, uint32_t block, 
	    int *exttype, uint64_t *lsector, uint32_t *maxblks);
void	udf_get_adslot(struct udf_node *udf_node, int slot, struct long_ad *icb,
	    int *eof);
int	udf_append_adslot(struct udf_node *udf_node, int *slot,
	    struct long_ad *icb);

int	udf_vat_read(struct udf_mount *ump, uint8_t *blob, int size,
	    uint32_t offset);

/* disc allocation */
int	udf_get_c_type(struct udf_node *udf_node);
int	udf_get_record_vpart(struct udf_mount *ump, int udf_c_type);
void	udf_calc_freespace(struct udf_mount *ump, uint64_t *sizeblks,
	    uint64_t *freeblks);

/* node readers and writers */
#define UDF_LOCK_NODE(udf_node, flag) udf_lock_node(udf_node, (flag), __FILE__, __LINE__)
#define UDF_UNLOCK_NODE(udf_node, flag) udf_unlock_node(udf_node, (flag))
void	udf_lock_node(struct udf_node *udf_node, int flag, char const *fname,
	    const int lineno);
void	udf_unlock_node(struct udf_node *udf_node, int flag);

int	udf_get_node(struct udf_mount *ump, struct long_ad icb_loc,
	    struct udf_node **ppunode);
int	udf_dispose_node(struct udf_node *node);

/* node ops */
int	udf_extattr_search_intern(struct udf_node *node, uint32_t sattr,
	    char const *sattrname, uint32_t *offsetp, uint32_t *lengthp);

/* node data buffer read/write */
void	udf_read_filebuf(struct udf_node *node, struct buf *buf);

/* directory operations and helpers */
void	udf_osta_charset(struct charspec *charspec);
int	udf_read_fid_stream(struct vnode *vp, uint64_t *offset,
	    struct fileid_desc *fid);
int	udf_lookup_name_in_dir(struct vnode *vp, const char *name, int namelen,
	    struct long_ad *icb_loc, int *found);

/* helpers and converters */
int	udf_get_node_id(const struct long_ad icbptr, ino_t *ino);
void	udf_get_node_longad(const ino_t ino, struct long_ad *icbptr);
uint32_t udf_getaccessmode(struct udf_node *node);
void	udf_to_unix_name(struct udf_mount *ump, char *result, int result_len,
	    uint8_t *id, int len);
void	udf_timestamp_to_timespec(struct udf_mount *ump,
	    struct timestamp *timestamp, struct timespec *timespec);

/* vnode operations */
int	udf_getanode(struct mount *mp, struct vnode **vpp);
int	udf_read_internal(struct udf_node *node, uint8_t *blob);

/* Created by for testing */
struct	udf_node * udf_alloc_node(void);
void	udf_free_node(struct udf_node *unode);
int	udf_vget(struct mount *mp, ino_t ino, int flags, struct vnode **vpp);
int	udf_read_node(struct udf_node *unode, uint8_t *blob, off_t start,
	    int length);
#endif	/* !_FS_UDF_UDF_SUBR_H_ */
