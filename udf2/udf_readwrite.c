/*-
 * Copyright (c) 2007, 2008 Reinoud Zandijk
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

#include <sys/cdefs.h>
#include <sys/endian.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/buf.h>
#include <sys/malloc.h>

#include "ecma167-udf.h"
#include "udf.h"
#include "udf_subr.h"


static int udf_read_phys_sectors(struct udf_mount *ump, int what, void *blob,
	uint32_t start, uint32_t sectors);
/* --------------------------------------------------------------------- */

#if 0
void
udf_fixup_fid_block(uint8_t *blob, int lb_size,
	int rfix_pos, int max_rfix_pos, uint32_t lb_num)
{
	struct fileid_desc *fid;
	uint8_t *fid_pos;
	int fid_len, found;

	/* needs to be word aligned */
	KASSERT(rfix_pos % 4 == 0);

	/* first resync with the FID stream !!! */
	found = 0;
	while (rfix_pos + sizeof(struct desc_tag) <= max_rfix_pos) {
		fid_pos = blob + rfix_pos;
		fid = (struct fileid_desc *) fid_pos;
		if (udf_rw16(fid->tag.id) == TAGID_FID) {
			if (udf_check_tag((union dscrptr *) fid) == 0)
				found = 1;
		}
		if (found)
			break;
		/* try next location; can only be 4 bytes aligned */
		rfix_pos += 4;
	}

	/* walk over the fids */
	fid_pos = blob + rfix_pos;
	while (rfix_pos + sizeof(struct desc_tag) <= max_rfix_pos) {
		fid = (struct fileid_desc *) fid_pos;
		if (udf_rw16(fid->tag.id) != TAGID_FID) {
			/* end of FID stream; end of directory or currupted */
			break;
		}

		/* update sector number and recalculate checkum */
		fid->tag.tag_loc = udf_rw32(lb_num);
		udf_validate_tag_sum((union dscrptr *) fid);

		/* if the FID crosses the memory, we're done! */
		if (rfix_pos + UDF_FID_SIZE >= max_rfix_pos)
			break;

		fid_len = udf_fidsize(fid);
		fid_pos  += fid_len;
		rfix_pos += fid_len;
	}
}


void
udf_fixup_internal_extattr(uint8_t *blob, uint32_t lb_num)
{
	struct desc_tag        *tag;
	struct file_entry      *fe;
	struct extfile_entry   *efe;
	struct extattrhdr_desc *eahdr;
	int l_ea;

	/* get information from fe/efe */
	tag = (struct desc_tag *) blob;
	switch (udf_rw16(tag->id)) {
	case TAGID_FENTRY :
		fe = (struct file_entry *) blob;
		l_ea  = udf_rw32(fe->l_ea);
		eahdr = (struct extattrhdr_desc *) fe->data;
		break;
	case TAGID_EXTFENTRY :
		efe = (struct extfile_entry *) blob;
		l_ea  = udf_rw32(efe->l_ea);
		eahdr = (struct extattrhdr_desc *) efe->data;
		break;
	case TAGID_INDIRECTENTRY :
	case TAGID_ALLOCEXTENT :
	case TAGID_EXTATTR_HDR :
		return;
	default:
		panic("%s: passed bad tag\n", __func__);
	}

	/* something recorded here? (why am i called?) */
	if (l_ea == 0)
		return;

#if 0
	/* check extended attribute tag */
	/* TODO XXX what to do when we encounter an error here? */
	error = udf_check_tag(eahdr);
	if (error)
		return;	/* for now */
	if (udf_rw16(eahdr->tag.id) != TAGID_EXTATTR_HDR)
		return;	/* for now */
	error = udf_check_tag_payload(eahdr, sizeof(struct extattrhdr_desc));
	if (error)
		return; /* for now */
#endif

	DPRINTF(EXTATTR, ("node fixup: found %d bytes of extended attributes\n",
		l_ea));

	/* fixup eahdr tag */
	eahdr->tag.tag_loc = udf_rw32(lb_num);
	udf_validate_tag_and_crc_sums((union dscrptr *) eahdr);
}


void
udf_fixup_node_internals(struct udf_mount *ump, uint8_t *blob, int udf_c_type)
{
	struct desc_tag *tag, *sbm_tag;
	struct file_entry *fe;
	struct extfile_entry *efe;
	struct alloc_ext_entry *ext;
	uint32_t lb_size, lb_num;
	uint32_t intern_pos, max_intern_pos;
	int icbflags, addr_type, file_type, intern, has_fids, has_sbm, l_ea;

	lb_size = udf_rw32(ump->logical_vol->lb_size);
	/* if its not a node we're done */
	if (udf_c_type != UDF_C_NODE)
		return;

	/* NOTE this could also be done in write_internal */
	/* start of a descriptor */
	l_ea      = 0;
	has_fids  = 0;
	has_sbm   = 0;
	intern    = 0;
	file_type = 0;
	max_intern_pos = intern_pos = lb_num = 0;	/* shut up gcc! */

	tag = (struct desc_tag *) blob;
	switch (udf_rw16(tag->id)) {
	case TAGID_FENTRY :
		fe = (struct file_entry *) tag;
		l_ea = udf_rw32(fe->l_ea);
		icbflags  = udf_rw16(fe->icbtag.flags);
		addr_type = (icbflags & UDF_ICB_TAG_FLAGS_ALLOC_MASK);
		file_type = fe->icbtag.file_type;
		intern = (addr_type == UDF_ICB_INTERN_ALLOC);
		intern_pos  = UDF_FENTRY_SIZE + l_ea;
		max_intern_pos = intern_pos + udf_rw64(fe->inf_len);
		lb_num = udf_rw32(fe->tag.tag_loc);
		break;
	case TAGID_EXTFENTRY :
		efe = (struct extfile_entry *) tag;
		l_ea = udf_rw32(efe->l_ea);
		icbflags  = udf_rw16(efe->icbtag.flags);
		addr_type = (icbflags & UDF_ICB_TAG_FLAGS_ALLOC_MASK);
		file_type = efe->icbtag.file_type;
		intern = (addr_type == UDF_ICB_INTERN_ALLOC);
		intern_pos  = UDF_EXTFENTRY_SIZE + l_ea;
		max_intern_pos = intern_pos + udf_rw64(efe->inf_len);
		lb_num = udf_rw32(efe->tag.tag_loc);
		break;
	case TAGID_INDIRECTENTRY :
	case TAGID_EXTATTR_HDR :
		break;
	case TAGID_ALLOCEXTENT :
		/* force crclen to 8 for UDF version < 2.01 */
		ext = (struct alloc_ext_entry *) tag;
		if (udf_rw16(ump->logvol_info->min_udf_readver) <= 0x200)
			ext->tag.desc_crc_len = udf_rw16(8);
		break;
	default:
		panic("%s: passed bad tag\n", __func__);
		break;
	}

	/* determine what to fix if its internally recorded */
	if (intern) {
		has_fids = (file_type == UDF_ICB_FILETYPE_DIRECTORY) ||
			   (file_type == UDF_ICB_FILETYPE_STREAMDIR);
		has_sbm  = (file_type == UDF_ICB_FILETYPE_META_BITMAP);
	}

	/* fixup internal extended attributes if present */
	if (l_ea)
		udf_fixup_internal_extattr(blob, lb_num);

	/* fixup fids lb numbers */
	if (has_fids)
		udf_fixup_fid_block(blob, lb_size, intern_pos,
			max_intern_pos, lb_num);

	/* fixup space bitmap descriptor */
	if (has_sbm) {
		sbm_tag = (struct desc_tag *) (blob + intern_pos);
		sbm_tag->tag_loc = tag->tag_loc;
		udf_validate_tag_and_crc_sums((uint8_t *) sbm_tag);
	}

	udf_validate_tag_and_crc_sums(blob);
}
#endif

/* --------------------------------------------------------------------- */

/*
 * Set of generic descriptor readers and writers and their helper functions.
 * Descriptors inside `logical space' i.e. inside logically mapped partitions
 * can never be longer than one logical sector.
 *
 * NOTE that these functions *can* be used by the sheduler backends to read
 * node descriptors too.
 *
 * For reading, the size of allocated piece is returned in multiple of sector
 * size due to udf_calc_udf_malloc_size().
 */
int
udf_read_node(struct udf_node *unode, uint8_t *blob, off_t start, int length)
{
	struct vnode *devvp = unode->ump->devvp;
	struct buf *bp; /* *buf, *nestbuf, ; */
	uint64_t file_size, lsect;
	int icbflags, addr_type, exttype, error = 0;
	uint32_t sector_size, blkinsect, fileblk, fileblkoff, numlsect, numb;
	uint8_t  *pos;

	sector_size = unode->ump->sector_size;
	blkinsect = sector_size / DEV_BSIZE;

	if (unode->fe) {
		pos      = &unode->fe->data[0] + le32toh(unode->fe->l_ea);
		icbflags = le16toh(unode->fe->icbtag.flags);
		file_size = le64toh(unode->fe->inf_len);
	} else {
		pos      = &unode->efe->data[0] + le32toh(unode->efe->l_ea);
		icbflags = le16toh(unode->efe->icbtag.flags);
		file_size = le64toh(unode->efe->inf_len);
	}

	length = min(file_size - start, length);
	fileblk = start / sector_size;
	fileblkoff = start % sector_size;

	addr_type = icbflags & UDF_ICB_TAG_FLAGS_ALLOC_MASK;
	if (addr_type == UDF_ICB_INTERN_ALLOC) {
		numb = min(length, file_size - fileblkoff);
		memcpy(blob, pos + fileblkoff, numb);
		return error;
	}

	while (length) {
		error = udf_bmap_translate(unode, fileblk, &exttype, &lsect,
		    &numlsect);
		if (error)
			return error;

		if (exttype == UDF_TRAN_ZERO) {
			numb = min(length, sector_size * numlsect - fileblkoff);
			memset(blob, 0, numb);
			length -= numb;
			blob += numb;
			fileblkoff = 0;
		} else if (exttype == UDF_TRAN_INTERN) {
			return EDOOFUS;
		} else {
			while (numlsect > 0) {
				if ((error = bread(devvp, lsect*blkinsect, sector_size, NOCRED,
				   		&bp)) != 0) {
					if (buf != NULL)
						brelse(bp);
					return error;
				}
		
				numb = min(length, sector_size - fileblkoff);
				bcopy(bp->b_data + fileblkoff, blob, numb);
				brelse(bp);
				bp = NULL;
		
				blob += numb;
				length -= numb;
				lsect++;
				numlsect--;
				fileblkoff = 0;
			}
		}
		
		fileblk += numlsect;
	}
	return (0);
}

/* SYNC reading of n blocks from specified sector */
static int
udf_read_phys_sectors(struct udf_mount *ump, int what, void *blob,
	uint32_t start, uint32_t sectors)
{
	struct buf *bp; /* *buf, *nestbuf, ; */
	int error = 0; /* piece; */
	/* off_t lblkno, rblkno; */
	uint32_t sector_size, blks; /* buf_offset; */
	struct vnode *devvp = ump->devvp;

	sector_size = ump->sector_size;
	blks = sector_size / DEV_BSIZE;

	while (sectors > 0 && error == 0) {
		if ((error = bread(devvp, start*blks, sector_size, NOCRED,
				   &bp)) != 0) {
			if (buf != NULL)
				brelse(bp);
			return error;
		}

		bcopy(bp->b_data, blob, sector_size);
		brelse(bp);
		bp = NULL;

		blob = (void *) ((uint8_t *)blob + sector_size);
		start++;
		sectors--;
	}

	return (0);
#if 0
	DPRINTF(READ, ("udf_intbreadn() : sectors = %d, sector_size = %d\n",
		sectors, sector_size));
	buf = getiobuf(ump->devvp, true);
	buf->b_flags    = B_READ;
	buf->b_cflags   = BC_BUSY;	/* needed? */
	buf->b_iodone   = NULL;
	buf->b_data     = blob;
	buf->b_bcount   = sectors * sector_size;
	buf->b_resid    = buf->b_bcount;
	buf->b_bufsize  = buf->b_bcount;
	buf->b_private  = NULL;	/* not needed yet */
	BIO_SETPRIO(buf, BPRIO_DEFAULT);
	buf->b_lblkno   = buf->b_blkno = buf->b_rawblkno = start * blks;
	buf->b_proc     = NULL;

	error = 0;
	buf_offset = 0;
	rblkno = start;
	lblkno = 0;
	while ((sectors > 0) && (error == 0)) {
		piece = MIN(MAXPHYS/sector_size, sectors);
		DPRINTF(READ, ("read in %d + %d\n", (uint32_t) rblkno, piece));

		nestbuf = getiobuf(NULL, true);
		nestiobuf_setup(buf, nestbuf, buf_offset, piece * sector_size);
		/* nestbuf is B_ASYNC */

		/* identify this nestbuf */
		nestbuf->b_lblkno   = lblkno;

		/* CD shedules on raw blkno */
		nestbuf->b_blkno      = rblkno * blks;
		nestbuf->b_proc       = NULL;
		nestbuf->b_rawblkno   = rblkno * blks;
		nestbuf->b_udf_c_type = what;

		udf_discstrat_queuebuf(ump, nestbuf);

		lblkno     += piece;
		rblkno     += piece;
		buf_offset += piece * sector_size;
		sectors    -= piece;
	}
	error = biowait(buf);
	putiobuf(buf);

	return error;
#endif
}


/* synchronous generic descriptor read */
int
udf_read_phys_dscr(struct udf_mount *ump, uint32_t sector,
		    struct malloc_type *mtype, union dscrptr **dstp)
{
	union dscrptr *dst, *new_dst;
	int sectors, dscrlen, i, error, sector_size;
	uint8_t *pos;

	sector_size = ump->sector_size;

	*dstp = dst = NULL;
	dscrlen = sector_size;

	/* read initial piece */
	dst = malloc(sector_size, mtype, M_WAITOK);
	error = udf_read_phys_sectors(ump, UDF_C_DSCR, dst, sector, 1);

	if (!error) {
		/* check if its a valid tag */
		error = udf_check_tag(dst);
		if (error) {
			/* check if its an empty block */
			pos = (uint8_t *) dst;
			for (i = 0; i < sector_size; i++, pos++) {
				if (*pos) break;
			}
			if (i == sector_size) {
				/* return no error but with no dscrptr */
				/* dispose first block */
				free(dst, mtype);
				return 0;
			}
		}
		/* calculate descriptor size */
		dscrlen = udf_tagsize(dst, sector_size);
	}

	if (!error && (dscrlen > sector_size)) {
		/*
		 * Read the rest of descriptor. Since it is only used at mount
		 * time its overdone to define and use a specific udf_intbreadn
		 * for this alone.
		 */

		new_dst = realloc(dst, dscrlen, mtype, M_WAITOK);
		if (new_dst == NULL) {
			free(dst, mtype);
			return ENOMEM;
		}
		dst = new_dst;

		sectors = (dscrlen + sector_size -1) / sector_size;
	
		pos = (uint8_t *) dst + sector_size;
		error = udf_read_phys_sectors(ump, UDF_C_DSCR, pos,
				sector + 1, sectors-1);
	}
	if (!error)
		error = udf_check_tag_payload(dst, dscrlen);
	if (error && dst) {
		free(dst, mtype);
		dst = NULL;
	}
	*dstp = dst;

	return error;
}


#if 0
static void
udf_write_phys_buf(struct udf_mount *ump, int what, struct buf *buf)
{
	struct buf *nestbuf;
	uint32_t buf_offset;
	off_t lblkno, rblkno;
	int sector_size = ump->discinfo.sector_size;
	int blks = sector_size / DEV_BSIZE;
	uint32_t sectors;
	int piece;
	int error;

	sectors = buf->b_bcount / sector_size;
	DPRINTF(WRITE, ("udf_intbwriten() : sectors = %d, sector_size = %d\n",
		sectors, sector_size));

	/* don't forget to increase pending count for the bwrite itself */
/* panic("NO WRITING\n"); */
	if (buf->b_vp) {
		mutex_enter(&buf->b_vp->v_interlock);
		buf->b_vp->v_numoutput++;
		mutex_exit(&buf->b_vp->v_interlock);
	}

	error = 0;
	buf_offset = 0;
	rblkno = buf->b_blkno / blks;
	lblkno = 0;
	while ((sectors > 0) && (error == 0)) {
		piece = MIN(MAXPHYS/sector_size, sectors);
		DPRINTF(WRITE, ("write out %d + %d\n",
		    (uint32_t) rblkno, piece));

		nestbuf = getiobuf(NULL, true);
		nestiobuf_setup(buf, nestbuf, buf_offset, piece * sector_size);
		/* nestbuf is B_ASYNC */

		/* identify this nestbuf */
		nestbuf->b_lblkno   = lblkno;

		/* CD shedules on raw blkno */
		nestbuf->b_blkno      = rblkno * blks;
		nestbuf->b_proc       = NULL;
		nestbuf->b_rawblkno   = rblkno * blks;
		nestbuf->b_udf_c_type = what;

		udf_discstrat_queuebuf(ump, nestbuf);

		lblkno     += piece;
		rblkno     += piece;
		buf_offset += piece * sector_size;
		sectors    -= piece;
	}
}


/* SYNC writing of n blocks from specified sector */
int
udf_write_phys_sectors(struct udf_mount *ump, int what, void *blob,
	uint32_t start, uint32_t sectors)
{
	struct vnode *vp;
	struct buf *buf;
	int sector_size = ump->discinfo.sector_size;
	int blks = sector_size / DEV_BSIZE;
	int error;

	/* get transfer buffer */
	vp = ump->devvp;
	buf = getiobuf(vp, true);
	buf->b_flags    = B_WRITE;
	buf->b_cflags   = BC_BUSY;	/* needed? */
	buf->b_iodone   = NULL;
	buf->b_data     = blob;
	buf->b_bcount   = sectors * sector_size;
	buf->b_resid    = buf->b_bcount;
	buf->b_bufsize  = buf->b_bcount;
	buf->b_private  = NULL;	/* not needed yet */
	BIO_SETPRIO(buf, BPRIO_DEFAULT);
	buf->b_lblkno   = buf->b_blkno = buf->b_rawblkno = start * blks;
	buf->b_proc     = NULL;

	/* do the write, wait and return error */
	udf_write_phys_buf(ump, what, buf);
	error = biowait(buf);
	putiobuf(buf);

	return error;
}


/* synchronous generic descriptor write */
int
udf_write_phys_dscr_sync(struct udf_mount *ump, struct udf_node *udf_node, int what,
		     union dscrptr *dscr, uint32_t sector, uint32_t logsector)
{
	struct vnode *vp;
	struct buf *buf;
	int sector_size = ump->discinfo.sector_size;
	int blks = sector_size / DEV_BSIZE;
	int dscrlen;
	int error;

	/* set sector number in the descriptor and validate */
	dscr->tag.tag_loc = udf_rw32(logsector);
	udf_validate_tag_and_crc_sums(dscr);

	/* calculate descriptor size */
	dscrlen = udf_tagsize(dscr, sector_size);

	/* get transfer buffer */
	vp = udf_node ? udf_node->vnode : ump->devvp;
	buf = getiobuf(vp, true);
	buf->b_flags    = B_WRITE;
	buf->b_cflags   = BC_BUSY;	/* needed? */
	buf->b_iodone   = NULL;
	buf->b_data     = (void *) dscr;
	buf->b_bcount   = dscrlen;
	buf->b_resid    = buf->b_bcount;
	buf->b_bufsize  = buf->b_bcount;
	buf->b_private  = NULL;	/* not needed yet */
	BIO_SETPRIO(buf, BPRIO_DEFAULT);
	buf->b_lblkno   = buf->b_blkno = buf->b_rawblkno = sector * blks;
	buf->b_proc     = NULL;

	/* do the write, wait and return error */
	udf_write_phys_buf(ump, what, buf);
	error = biowait(buf);
	putiobuf(buf);

	return error;
}


/* asynchronous generic descriptor write */
int
udf_write_phys_dscr_async(struct udf_mount *ump, struct udf_node *udf_node,
		      int what, union dscrptr *dscr,
		      uint32_t sector, uint32_t logsector,
		      void (*dscrwr_callback)(struct buf *))
{
	struct vnode *vp;
	struct buf *buf;
	int dscrlen;
	int sector_size = ump->discinfo.sector_size;
	int blks = sector_size / DEV_BSIZE;

	KASSERT(dscrwr_callback);
	DPRINTF(NODE, ("udf_write_phys_dscr_async() called\n"));

	/* set sector number in the descriptor and validate */
	dscr->tag.tag_loc = udf_rw32(logsector);
	udf_validate_tag_and_crc_sums(dscr);

	/* calculate descriptor size */
	dscrlen = udf_tagsize(dscr, sector_size);

	/* get transfer buffer */
	vp = udf_node ? udf_node->vnode : ump->devvp;
	buf = getiobuf(vp, true);
	buf->b_flags    = B_WRITE | B_ASYNC;
	buf->b_cflags   = BC_BUSY;
	buf->b_iodone	= dscrwr_callback;
	buf->b_data     = dscr;
	buf->b_bcount   = dscrlen;
	buf->b_resid    = buf->b_bcount;
	buf->b_bufsize  = buf->b_bcount;
	buf->b_private  = NULL;	/* not needed yet */
	BIO_SETPRIO(buf, BPRIO_DEFAULT);
	buf->b_lblkno   = buf->b_blkno = buf->b_rawblkno = sector * blks;
	buf->b_proc     = NULL;

	/* do the write and return no error */
	udf_write_phys_buf(ump, what, buf);
	return 0;
}

/* --------------------------------------------------------------------- */

/* disc strategy dispatchers */

int
udf_create_logvol_dscr(struct udf_mount *ump, struct udf_node *udf_node, struct long_ad *icb,
	union dscrptr **dscrptr)
{
	struct udf_strategy *strategy = ump->strategy;
	struct udf_strat_args args;
	int error;

	KASSERT(strategy);
	args.ump  = ump;
	args.udf_node = udf_node;
	args.icb  = icb;
	args.dscr = NULL;

	error = (strategy->create_logvol_dscr)(&args);
	*dscrptr = args.dscr;

	return error;
}


void
udf_free_logvol_dscr(struct udf_mount *ump, struct long_ad *icb,
	void *dscr)
{
	struct udf_strategy *strategy = ump->strategy;
	struct udf_strat_args args;

	KASSERT(strategy,("Strategy not specified."));
	args.ump  = ump;
	args.icb  = icb;
	args.dscr = dscr;

	(strategy->free_logvol_dscr)(&args);
}


int
udf_read_logvol_dscr(struct udf_mount *ump, struct long_ad *icb,
	union dscrptr **dscrptr)
{
	struct udf_strategy *strategy = ump->strategy;
	struct udf_strat_args args;
	int error;

	KASSERT(strategy);
	args.ump  = ump;
	args.icb  = icb;
	args.dscr = NULL;

	error = (strategy->read_logvol_dscr)(&args);
	*dscrptr = args.dscr;

	return error;
}


int
udf_write_logvol_dscr(struct udf_node *udf_node, union dscrptr *dscr,
	struct long_ad *icb, int waitfor)
{
	struct udf_strategy *strategy = udf_node->ump->strategy;
	struct udf_strat_args args;
	int error;

	KASSERT(strategy);
	args.ump      = udf_node->ump;
	args.udf_node = udf_node;
	args.icb      = icb;
	args.dscr     = dscr;
	args.waitfor  = waitfor;

	error = (strategy->write_logvol_dscr)(&args);
	return error;
}


void
udf_discstrat_queuebuf(struct udf_mount *ump, struct buf *nestbuf)
{
	struct udf_strategy *strategy = ump->strategy;
	struct udf_strat_args args;

	KASSERT(strategy);
	args.ump = ump;
	args.nestbuf = nestbuf;

	(strategy->queuebuf)(&args);
}


void
udf_discstrat_init(struct udf_mount *ump)
{
	struct udf_strategy *strategy = ump->strategy;
	struct udf_strat_args args;

	KASSERT(strategy);
	args.ump = ump;
	(strategy->discstrat_init)(&args);
}


void udf_discstrat_finish(struct udf_mount *ump)
{
	struct udf_strategy *strategy = ump->strategy;
	struct udf_strat_args args;

	/* strategy might not have been set, so ignore if not set */
	if (strategy) {
		args.ump = ump;
		(strategy->discstrat_finish)(&args);
	}
}
#endif
/* --------------------------------------------------------------------- */

