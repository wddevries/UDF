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

#include <sys/cdefs.h>
#include <sys/endian.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/limits.h>
#include <sys/malloc.h>

#include "ecma167-udf.h"
#include "udf.h"
#include "udf_subr.h"


void
udf_calc_freespace(struct udf_mount *ump, uint64_t *sizeblks, 
    uint64_t *freeblks)
{
	struct logvol_int_desc *lvid;
	int num_vpart, vpart;
	uint32_t *pos1, *pos2;

	lvid = ump->logvol_integrity;
	*freeblks = *sizeblks = 0;

	/*
	 * Sequentials media report free space directly (CD/DVD/BD-R), for the
	 * other media we need the logical volume integrity.
	 *
	 * We sum all free space up here regardless of type.
	 */

	num_vpart = le32toh(lvid->num_part);

#if 0
	if (ump->discinfo.mmc_cur & MMC_CAP_SEQUENTIAL) {
		/* use track info directly summing if there are 2 open */
		/* XXX assumption at most two tracks open */
		*freeblks = ump->data_track.free_blocks;
		if (ump->data_track.tracknr != ump->metadata_track.tracknr)
			*freeblks += ump->metadata_track.free_blocks;
		*sizeblks = ump->discinfo.last_possible_lba;
	} else {
#endif
		/* free and used space for mountpoint based on logvol integrity */
		for (vpart = 0; vpart < num_vpart; vpart++) {
			pos1 = &lvid->tables[0] + vpart;
			pos2 = &lvid->tables[0] + num_vpart + vpart;
			if (le32toh(*pos1) != (uint32_t) -1) {
				*freeblks += le32toh(*pos1);
				*sizeblks += le32toh(*pos2);
			}
		}
#if 0
	}
#endif

	if (*freeblks > UDF_DISC_SLACK)
		*freeblks -= UDF_DISC_SLACK;
	else
		*freeblks = 0;
}

int
udf_translate_vtop(struct udf_mount *ump, struct long_ad *icb_loc,
		   uint32_t *lb_numres, uint32_t *extres)
{
	struct part_desc *pdesc;
	struct spare_map_entry *sme;
	struct long_ad s_icb_loc;
	uint64_t end_foffset, foffset;
	int eof, error, flags, part, rel, slot;
	uint32_t lb_num, lb_packet, lb_rel, lb_size, len;
	uint32_t ext_offset, udf_rw32_lbmap;
	uint16_t vpart;

	KASSERT(ump && icb_loc && lb_numres,("ump && icb_loc && lb_numres"));

	vpart = le16toh(icb_loc->loc.part_num);
	lb_num = le32toh(icb_loc->loc.lb_num);
	if (vpart > UDF_VTOP_RAWPART)
		return (EINVAL);

translate_again:
	part = ump->vtop[vpart];
	pdesc = ump->partitions[part];

	switch (ump->vtop_tp[vpart]) {
	case UDF_VTOP_TYPE_RAW:
		/* 1:1 to the end of the device */
		*lb_numres = lb_num;
		*extres = INT_MAX;
		return (0);
	case UDF_VTOP_TYPE_PHYS:
		/* transform into its disc logical block */
		if (lb_num > le32toh(pdesc->part_len))
			return (EINVAL);
		*lb_numres = lb_num + le32toh(pdesc->start_loc);

		/* extent from here to the end of the partition */
		*extres = le32toh(pdesc->part_len) - lb_num;
		return (0);
	case UDF_VTOP_TYPE_VIRT:
		/* only maps one logical block, lookup in VAT */
		if (lb_num >= ump->vat_entries)		/* XXX > or >= ? */
			return (EINVAL);

		/* lookup in virtual allocation table file */
		error = udf_vat_read(ump, (uint8_t *)&udf_rw32_lbmap, 4, 
		    ump->vat_offset + lb_num * 4);
		if (error != 0)
			return (error);

		lb_num = le32toh(udf_rw32_lbmap);

		/* transform into its disc logical block */
		if (lb_num > le32toh(pdesc->part_len))
			return (EINVAL);
		*lb_numres = lb_num + le32toh(pdesc->start_loc);

		/* just one logical block */
		*extres = 1;
		return (0);
	case UDF_VTOP_TYPE_SPARABLE:
		/* check if the packet containing the lb_num is remapped */
		lb_packet = lb_num / ump->sparable_packet_size;
		lb_rel = lb_num % ump->sparable_packet_size;

		for (rel = 0; rel < le16toh(ump->sparing_table->rt_l); rel++) {
			sme = &ump->sparing_table->entries[rel];
			if (lb_packet == le32toh(sme->org)) {
				/* NOTE maps to absolute disc logical block! */
				*lb_numres = le32toh(sme->map) + lb_rel;
				*extres = ump->sparable_packet_size - lb_rel;
				return (0);
			}
		}

		/* transform into its disc logical block */
		if (lb_num > le32toh(pdesc->part_len))
			return (EINVAL);
		*lb_numres = lb_num + le32toh(pdesc->start_loc);

		/* rest of block */
		*extres = ump->sparable_packet_size - lb_rel;
		return (0);
	case UDF_VTOP_TYPE_META:
printf("Metadata Partition Translated\n");
		/* we have to look into the file's allocation descriptors */

		/* use metadatafile allocation mutex */
		lb_size = le32toh(ump->logical_vol->lb_size);

		UDF_LOCK_NODE(ump->metadata_node, 0);

		/* get first overlapping extent */
		foffset = 0;
		slot = 0;
		for (;;) {
			udf_get_adslot(ump->metadata_node, slot, &s_icb_loc,
			    &eof);
			if (eof) {
				UDF_UNLOCK_NODE(ump->metadata_node, 0);
				return (EINVAL);
			}
			len = le32toh(s_icb_loc.len);
			flags = UDF_EXT_FLAGS(len);
			len = UDF_EXT_LEN(len);

			if (flags == UDF_EXT_REDIRECT) {
				slot++;
				continue;
			}

			end_foffset = foffset + len;

			if (end_foffset > lb_num * lb_size)
				break;	/* found */
			foffset = end_foffset;
			slot++;
		}
		/* found overlapping slot */
		ext_offset = lb_num * lb_size - foffset;

		/* process extent offset */
		lb_num = le32toh(s_icb_loc.loc.lb_num);
		vpart = le16toh(s_icb_loc.loc.part_num);
		lb_num  += (ext_offset + lb_size -1) / lb_size;
		ext_offset = 0;

		UDF_UNLOCK_NODE(ump->metadata_node, 0);
		if (flags != UDF_EXT_ALLOCATED)
			return (EINVAL);

		/*
		 * vpart and lb_num are updated, translate again since we
		 * might be mapped on sparable media
		 */
		goto translate_again;
	default:
		printf("UDF vtop translation scheme %d unimplemented yet\n",
		    ump->vtop_tp[vpart]);
	}

	return (EINVAL);
}

/* 
 * This is a simplified version of the udf_translate_file_extent function. 
 */
int
udf_bmap_translate(struct udf_node *udf_node, uint32_t block, 
		   int *exttype, uint64_t *lsector, uint32_t *maxblks)
{
	struct udf_mount *ump;
	struct icb_tag *icbtag;
	struct long_ad s_ad, t_ad;
	uint64_t foffset, new_foffset;
	int addr_type, eof, error, flags, icbflags, slot;
	uint32_t ext_offset, ext_remain, lb_num, lb_size, len, transsec32;
	uint32_t translen;
	uint16_t vpart_num;


	if (udf_node == NULL)
		return (ENOENT);

	KASSERT(num_lb > 0,("num_lb > 0"));

	UDF_LOCK_NODE(udf_node, 0);

	/* initialise derivative vars */
	ump = udf_node->ump;
	lb_size = le32toh(ump->logical_vol->lb_size);

	if (udf_node->fe != NULL)
		icbtag = &udf_node->fe->icbtag;
	else
		icbtag = &udf_node->efe->icbtag;

	icbflags = le16toh(icbtag->flags);
	addr_type = icbflags & UDF_ICB_TAG_FLAGS_ALLOC_MASK;

	/* do the work */
	if (addr_type == UDF_ICB_INTERN_ALLOC) {
		*exttype = UDF_TRAN_INTERN;
		*maxblks = 1;
		UDF_UNLOCK_NODE(udf_node, 0);
		return (0);
	}

	/* find first overlapping extent */
	foffset = 0;
	slot = 0;
	for (;;) {
		udf_get_adslot(udf_node, slot, &s_ad, &eof);
		if (eof) {
			UDF_UNLOCK_NODE(udf_node, 0);
			return (EINVAL);
		}
		len = le32toh(s_ad.len);
		flags = UDF_EXT_FLAGS(len);
		len = UDF_EXT_LEN(len);

		if (flags == UDF_EXT_REDIRECT) {
			slot++;
			continue;
		}

		new_foffset = foffset + len;

		if (new_foffset > block * lb_size)
			break;	/* found */
		foffset = new_foffset;
		slot++;
	}
	/* found overlapping slot */

	lb_num = le32toh(s_ad.loc.lb_num);
	vpart_num = le16toh(s_ad.loc.part_num);
	
	ext_offset = block * lb_size - foffset;
	lb_num += (ext_offset + lb_size - 1) / lb_size;
	ext_remain = (len - ext_offset + lb_size - 1) / lb_size;

	/*
	 * note that the while(){} is nessisary for the extent that
	 * the udf_translate_vtop() returns doens't have to span the
	 * whole extent.
	 */
	switch (flags) {
	case UDF_EXT_FREE:
	case UDF_EXT_ALLOCATED_BUT_NOT_USED:
		*exttype = UDF_TRAN_ZERO;
		*maxblks = ext_remain;
		break;
	case UDF_EXT_ALLOCATED:
		*exttype = UDF_TRAN_EXTERNAL;
		t_ad.loc.lb_num = htole32(lb_num);
		t_ad.loc.part_num = htole16(vpart_num);
		error = udf_translate_vtop(ump, &t_ad, &transsec32, &translen);
		if (error != 0) {
			UDF_UNLOCK_NODE(udf_node, 0);
			return (error);
		}
		*lsector = transsec32;
		*maxblks = MIN(ext_remain, translen);
		break;
	default:
		UDF_UNLOCK_NODE(udf_node, 0);
		return (EINVAL);
	}

	UDF_UNLOCK_NODE(udf_node, 0);

	return (0);
}

void
udf_get_adslot(struct udf_node *udf_node, int slot, struct long_ad *icb,
	int *eof) {
	struct file_entry *fe;
	struct extfile_entry *efe;
	struct alloc_ext_entry *ext;
	struct icb_tag *icbtag;
	struct short_ad *short_ad;
	struct long_ad *long_ad, l_icb;
	int addr_type, adlen, extnr, icbflags;
	uint32_t dscr_size, flags, lb_size, l_ad, l_ea, offset;
	uint8_t *data_pos;

	/* determine what descriptor we are in */
	lb_size = le32toh(udf_node->ump->logical_vol->lb_size);

	fe = udf_node->fe;
	efe = udf_node->efe;
	if (fe != NULL) {
		icbtag = &fe->icbtag;
		dscr_size = sizeof(struct file_entry) -1;
		l_ea = le32toh(fe->l_ea);
		l_ad = le32toh(fe->l_ad);
		data_pos = (uint8_t *)fe + dscr_size + l_ea;
	} else {
		icbtag = &efe->icbtag;
		dscr_size = sizeof(struct extfile_entry) -1;
		l_ea = le32toh(efe->l_ea);
		l_ad = le32toh(efe->l_ad);
		data_pos = (uint8_t *)efe + dscr_size + l_ea;
	}

	icbflags = le16toh(icbtag->flags);
	addr_type = icbflags & UDF_ICB_TAG_FLAGS_ALLOC_MASK;

	/* just in case we're called on an intern, its EOF */
	if (addr_type == UDF_ICB_INTERN_ALLOC) {
		memset(icb, 0, sizeof(struct long_ad));
		*eof = 1;
		return;
	}

	adlen = 0;
	if (addr_type == UDF_ICB_SHORT_ALLOC)
		adlen = sizeof(struct short_ad);
	else if (addr_type == UDF_ICB_LONG_ALLOC)
		adlen = sizeof(struct long_ad);

	/* if offset too big, we go to the allocation extensions */
	offset = slot * adlen;
	extnr = -1;
	while (offset >= l_ad) {
		/* check if our last entry is a redirect */
		if (addr_type == UDF_ICB_SHORT_ALLOC) {
			short_ad = (struct short_ad *)(data_pos + l_ad-adlen);
			l_icb.len = short_ad->len;
			l_icb.loc.part_num = udf_node->loc.loc.part_num;
			l_icb.loc.lb_num = short_ad->lb_num;
		} else {
			KASSERT(addr_type == UDF_ICB_LONG_ALLOC,
			    ("addr_type == UDF_ICB_LONG_ALLOC"));
			long_ad = (struct long_ad *)(data_pos + l_ad-adlen);
			l_icb = *long_ad;
		}
		flags = UDF_EXT_FLAGS(le32toh(l_icb.len));
		if (flags != UDF_EXT_REDIRECT) {
			l_ad = 0;	/* force EOF */
			break;
		}

		/* advance to next extent */
		extnr++;
		if (extnr >= udf_node->num_extensions) {
			l_ad = 0;	/* force EOF */
			break;
		}
		offset = offset - l_ad;
		ext = udf_node->ext[extnr];
		dscr_size = sizeof(struct alloc_ext_entry) - 1;
		l_ad = le32toh(ext->l_ad);
		data_pos = (uint8_t *)ext + dscr_size;
	}

	/* XXX l_ad == 0 should be enough to check */
	*eof = (offset >= l_ad) || (l_ad == 0);
	if (*eof) {
		memset(icb, 0, sizeof(struct long_ad));
		return;
	}

	/* get the element */
	if (addr_type == UDF_ICB_SHORT_ALLOC) {
		short_ad = (struct short_ad *)(data_pos + offset);
		icb->len = short_ad->len;
		icb->loc.part_num = udf_node->loc.loc.part_num;
		icb->loc.lb_num = short_ad->lb_num;
	} else if (addr_type == UDF_ICB_LONG_ALLOC) {
		long_ad = (struct long_ad *)(data_pos + offset);
		*icb = *long_ad;
	}
}
