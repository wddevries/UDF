/*-
 * Copyright (c) 2012 Will DeVries
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


static int	udf_read_phys_sectors(struct udf_mount *ump, int what, 
		    void *blob, uint32_t start, uint32_t sectors);

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
	struct buf *bp;
	uint64_t file_size, lsect;
	int addr_type, exttype, error, icbflags;
	uint32_t blkinsect, fileblk, fileblkoff, numb, numlsect, sector_size;
	uint8_t  *pos;

	error = 0;
	sector_size = unode->ump->sector_size;
	blkinsect = sector_size / DEV_BSIZE;

	if (unode->fe != NULL) {
		pos = &unode->fe->data[0] + le32toh(unode->fe->l_ea);
		icbflags = le16toh(unode->fe->icbtag.flags);
		file_size = le64toh(unode->fe->inf_len);
	} else {
		pos = &unode->efe->data[0] + le32toh(unode->efe->l_ea);
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
		return (error);
	}

	while (length) {
		error = udf_bmap_translate(unode, fileblk, &exttype, &lsect,
		    &numlsect);
		if (error != 0)
			return (error);

		if (exttype == UDF_TRAN_ZERO) {
			numb = min(length, sector_size * numlsect - fileblkoff);
			memset(blob, 0, numb);
			length -= numb;
			blob += numb;
			fileblkoff = 0;
		} else if (exttype == UDF_TRAN_INTERN)
			return (EDOOFUS);
		else {
			while (numlsect > 0) {
				error = bread(devvp, lsect * blkinsect,
				    sector_size, NOCRED, &bp);
				if (error != 0) {
					if (buf != NULL)
						brelse(bp);
					return (error);
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
	struct vnode *devvp = ump->devvp;
	struct buf *bp;
	int error = 0;
	uint32_t blks, sector_size;

	sector_size = ump->sector_size;
	blks = sector_size / DEV_BSIZE;

	while (sectors > 0 && error == 0) {
		error = bread(devvp, start * blks, sector_size, NOCRED, &bp);
		if (error != 0) {
			if (buf != NULL)
				brelse(bp);
			return (error);
		}

		bcopy(bp->b_data, blob, sector_size);
		brelse(bp);
		bp = NULL;

		blob = (void *)((uint8_t *)blob + sector_size);
		start++;
		sectors--;
	}

	return (0);
}

/* synchronous generic descriptor read */
int
udf_read_phys_dscr(struct udf_mount *ump, uint32_t sector,
    struct malloc_type *mtype, union dscrptr **dstp)
{
	union dscrptr *dst, *new_dst;
	int dscrlen, error, i, sectors, sector_size;
	uint8_t *pos;

	sector_size = ump->sector_size;

	*dstp = dst = NULL;
	dscrlen = sector_size;

	/* read initial piece */
	dst = malloc(sector_size, mtype, M_WAITOK);
	error = udf_read_phys_sectors(ump, UDF_C_DSCR, dst, sector, 1);

	if (error == 0) {
		/* check if its a valid tag */
		error = udf_check_tag(dst);
		if (error != 0) {
			/* check if its an empty block */
			pos = (uint8_t *)dst;
			for (i = 0; i < sector_size; i++, pos++)
				if (*pos)
					break;

			if (i == sector_size) {
				/* return no error but with no dscrptr */
				/* dispose first block */
				free(dst, mtype);
				return (0);
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
			return (ENOMEM);
		}
		dst = new_dst;

		sectors = (dscrlen + sector_size - 1) / sector_size;
	
		pos = (uint8_t *)dst + sector_size;
		error = udf_read_phys_sectors(ump, UDF_C_DSCR, pos, sector + 1,
		    sectors - 1);
	}
	if (error == 0)
		error = udf_check_tag_payload(dst, dscrlen);
	if (error && dst) {
		free(dst, mtype);
		dst = NULL;
	}
	*dstp = dst;

	return (error);
}
