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
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/iconv.h>

#include "ecma167-udf.h"
#include "udf.h"
#include "udf_subr.h"

#define VTOI(vnode) ((struct udf_node *) (vnode)->v_data)

static int	udf_leapyear(int year);

/*
 * Check if the blob starts with a good UDF tag. Tags are protected by a
 * checksum over the reader except one byte at position 4 that is the checksum
 * itself.
 */
int
udf_check_tag(void *blob)
{
	struct desc_tag *tag = blob;
	uint8_t cnt, *pos, sum;

	/* check TAG header checksum */
	pos = (uint8_t *)tag;
	sum = 0;

	for (cnt = 0; cnt < 16; cnt++) {
		if (cnt != 4)
			sum += *pos;
		pos++;
	}
	if (sum != tag->cksum) {
		/* bad tag header checksum; this is not a valid tag */
		return (EINVAL);
	}

	return (0);
}

/*
 * check tag payload will check descriptor CRC as specified.
 * If the descriptor is too long, it will return EIO otherwise EINVAL.
 */
int
udf_check_tag_payload(void *blob, uint32_t max_length)
{
	struct desc_tag *tag = blob;
	uint16_t crc, crc_len;

	crc_len = le16toh(tag->desc_crc_len);

	/* check payload CRC if applicable */
	if (crc_len == 0)
		return (0);

	if (crc_len > max_length)
		return (EIO);

	crc = udf_cksum(((uint8_t *)tag) + UDF_DESC_TAG_LENGTH, crc_len);
	if (crc != le16toh(tag->desc_crc)) {
		/* bad payload CRC; this is a broken tag */
		return (EINVAL);
	}

	return (0);
}

void
udf_validate_tag_sum(void *blob)
{
	struct desc_tag *tag = blob;
	uint8_t cnt, *pos, sum;

	/* calculate TAG header checksum */
	pos = (uint8_t *)tag;
	sum = 0;

	for (cnt = 0; cnt < 16; cnt++) {
		if (cnt != 4) sum += *pos;
		pos++;
	}
	tag->cksum = sum;	/* 8 bit */
}

/* assumes sector number of descriptor to be saved already present */
void
udf_validate_tag_and_crc_sums(void *blob)
{
	struct desc_tag *tag = blob;
	uint16_t crc, crc_len;
	uint8_t *btag = (uint8_t *)tag;

	crc_len = le16toh(tag->desc_crc_len);

	/* check payload CRC if applicable */
	if (crc_len > 0) {
		crc = udf_cksum(btag + UDF_DESC_TAG_LENGTH, crc_len);
		tag->desc_crc = htole16(crc);
	}

	/* calculate TAG header checksum */
	udf_validate_tag_sum(blob);
}

/*
 * XXX note the different semantics from udfclient: for FIDs it still rounds
 * up to sectors. Use udf_fidsize() for a correct length.
 */
int
udf_tagsize(union dscrptr *dscr, uint32_t lb_size)
{
	uint32_t elmsz, num_lb, size, tag_id;

	tag_id = le16toh(dscr->tag.id);

	switch (tag_id) {
	case TAGID_LOGVOL:
		size = sizeof(struct logvol_desc) - 1;
		size += le32toh(dscr->lvd.mt_l);
		break;
	case TAGID_UNALLOC_SPACE:
		elmsz = sizeof(struct extent_ad);
		size = sizeof(struct unalloc_sp_desc) - elmsz;
		size += le32toh(dscr->usd.alloc_desc_num) * elmsz;
		break;
	case TAGID_FID:
		size = UDF_FID_SIZE + dscr->fid.l_fi + le16toh(dscr->fid.l_iu);
		size = (size + 3) & ~3;
		break;
	case TAGID_LOGVOL_INTEGRITY:
		size = sizeof(struct logvol_int_desc) - sizeof(uint32_t);
		size += le32toh(dscr->lvid.l_iu);
		size += (2 * le32toh(dscr->lvid.num_part) * sizeof(uint32_t));
		break;
	case TAGID_SPACE_BITMAP:
		size = sizeof(struct space_bitmap_desc) - 1;
		size += le32toh(dscr->sbd.num_bytes);
		break;
	case TAGID_SPARING_TABLE:
		elmsz = sizeof(struct spare_map_entry);
		size = sizeof(struct udf_sparing_table) - elmsz;
		size += le16toh(dscr->spt.rt_l) * elmsz;
		break;
	case TAGID_FENTRY:
		size = sizeof(struct file_entry);
		size += le32toh(dscr->fe.l_ea) + le32toh(dscr->fe.l_ad)-1;
		break;
	case TAGID_EXTFENTRY:
		size = sizeof(struct extfile_entry);
		size += le32toh(dscr->efe.l_ea) + le32toh(dscr->efe.l_ad)-1;
		break;
	case TAGID_FSD:
		size = sizeof(struct fileset_desc);
		break;
	default:
		size = sizeof(union dscrptr);
		break;
	}

	if ((size == 0) || (lb_size == 0))
		return (0);

	if (lb_size == 1)
		return (size);

	/* round up in sectors */
	num_lb = (size + lb_size -1) / lb_size;

	return (num_lb * lb_size);
}

int
udf_fidsize(struct fileid_desc *fid)
{
	uint32_t size;

	if (le16toh(fid->tag.id) != TAGID_FID)
		panic("got udf_fidsize on non FID\n");

	size = UDF_FID_SIZE + fid->l_fi + le16toh(fid->l_iu);
	size = (size + 3) & ~3;

	/* We know this value will fit in an int. */
	return (size);
}

void
udf_lock_node(struct udf_node *udf_node, int flag, char const *fname, 
    const int lineno)
{
#if 0
	int ret;

	mutex_enter(&udf_node->node_mutex);
	/* wait until free */
	while (udf_node->i_flags & IN_LOCKED) {
		ret = cv_timedwait(&udf_node->node_lock, &udf_node->node_mutex, hz/8);
		/* TODO check if we should return error; abort */
		if (ret == EWOULDBLOCK) {
			DPRINTF(LOCKING, ( "udf_lock_node: udf_node %p would block "
				"wanted at %s:%d, previously locked at %s:%d\n",
				udf_node, fname, lineno, 
				udf_node->lock_fname, udf_node->lock_lineno));
		}
	}
	/* grab */
	udf_node->i_flags |= IN_LOCKED | flag;
	/* debug */
	udf_node->lock_fname  = fname;
	udf_node->lock_lineno = lineno;

	mutex_exit(&udf_node->node_mutex);
#endif
}

void
udf_unlock_node(struct udf_node *udf_node, int flag)
{
#if 0
	mutex_enter(&udf_node->node_mutex);
	udf_node->i_flags &= ~(IN_LOCKED | flag);
	cv_broadcast(&udf_node->node_lock);
	mutex_exit(&udf_node->node_mutex);
#endif
}

static int
udf_read_anchor(struct udf_mount *ump, uint32_t sector, struct anchor_vdp **dst)
{
	int error;

	error = udf_read_phys_dscr(ump, sector, M_UDFTEMP,
	    (union dscrptr **)dst);
	if (error == 0) {
		/* blank terminator blocks are not allowed here */
		if (*dst == NULL)
			return (ENOENT);
		if (le16toh((*dst)->tag.id) != TAGID_ANCHOR) {
			error = ENOENT;
			free(*dst, M_UDFTEMP);
			*dst = NULL;
		}
	}

	return (error);
}

int
udf_read_anchors(struct udf_mount *ump)
{
	struct anchor_vdp **anchorsp;
	int first_anchor, anch, error, ok;
	uint32_t positions[4], session_end, session_start;

	session_start = ump->session_start;
	session_end = ump->session_end;

	/* read anchors start+256, start+512, end-256, end */
	positions[0] = session_start + 256;
	positions[1] = session_end - 256;
	positions[2] = session_end;
	/* XXX shouldn't +512 be prefered above +256 for compat with Roxio CD */
	positions[3] = session_start + 512; /* [UDF 2.60/6.11.2] */

	ok = 0;
	anchorsp = ump->anchors;
	first_anchor = 0;
	if (ump->first_trackblank)
		first_anchor = 1;
	for (anch = first_anchor; anch < 4; anch++) {
		if (positions[anch] <= session_end) {
			error = udf_read_anchor(ump, positions[anch], anchorsp);
			if (error == 0) {
				anchorsp++;
				ok++;
			}
		}
	}

	return (ok);
}

/* we dont try to be smart; we just record the parts */
#define UDF_UPDATE_DSCR(name, dscr) \
	if (name) \
		free(name, M_UDFTEMP); \
	name = dscr;

static int
udf_process_vds_descriptor(struct udf_mount *ump, union dscrptr *dscr)
{
	struct part_desc *part;
	uint16_t phys_part, raw_phys_part;

	switch (le16toh(dscr->tag.id)) {
	case TAGID_PRI_VOL:		/* primary partition */
		UDF_UPDATE_DSCR(ump->primary_vol, &dscr->pvd);
		break;
	case TAGID_LOGVOL:		/* logical volume */
		UDF_UPDATE_DSCR(ump->logical_vol, &dscr->lvd);
		break;
	case TAGID_UNALLOC_SPACE:	/* unallocated space */
		UDF_UPDATE_DSCR(ump->unallocated, &dscr->usd);
		break;
	case TAGID_IMP_VOL:		/* implementation */
		/* XXX do we care about multiple impl. descr ? */
		UDF_UPDATE_DSCR(ump->implementation, &dscr->ivd);
		break;
	case TAGID_PARTITION:		/* physical partition */
		/* not much use if its not allocated */
		if ((le16toh(dscr->pd.flags) & UDF_PART_FLAG_ALLOCATED) == 0) {
			free(dscr, M_UDFTEMP);
			break;
		}

		/*
		 * BUGALERT: some rogue implementations use random physical
		 * partition numbers to break other implementations so lookup
		 * the number.
		 */
		raw_phys_part = le16toh(dscr->pd.part_num);
		for (phys_part = 0; phys_part < UDF_PARTITIONS; phys_part++) {
			part = ump->partitions[phys_part];
			if (part == NULL)
				break;
			if (le16toh(part->part_num) == raw_phys_part)
				break;
		}
		if (phys_part == UDF_PARTITIONS) {
			free(dscr, M_UDFTEMP);
			return (EINVAL);
		}

		UDF_UPDATE_DSCR(ump->partitions[phys_part], &dscr->pd);
		break;
	case TAGID_VOL:		/* volume space extender; rare	*/
		free(dscr, M_UDFTEMP);
		break;
	default:
		free(dscr, M_UDFTEMP);
	}

	return (0);
}
#undef UDF_UPDATE_DSCR

static int
udf_read_vds_extent(struct udf_mount *ump, uint32_t loc, uint32_t len)
{
	union dscrptr *dscr;
	int error;
	uint32_t dscr_size, sector_size;

	sector_size = ump->sector_size;

	/* loc is sectornr, len is in bytes */
	error = EIO;
	while (len) {
		error = udf_read_phys_dscr(ump, loc, M_UDFTEMP, &dscr);
		if (error != 0) {
			if (!dscr)
				free(dscr, M_UDFTEMP);
			return (error);
		}

		/* blank block is a terminator */
		if (dscr == NULL)
			return (0);

		/* TERM descriptor is a terminator */
		if (le16toh(dscr->tag.id) == TAGID_TERM) {
			free(dscr, M_UDFTEMP);
			return (0);
		}

		/* process all others */
		dscr_size = udf_tagsize(dscr, sector_size);

		/* dscr is assigned into ump */
		error = udf_process_vds_descriptor(ump, dscr);
		if (error != 0) 
			break;

		len -= dscr_size;
		loc += dscr_size / sector_size;
	}

	return (error);
}

int
udf_read_vds_space(struct udf_mount *ump)
{
	/* struct udf_args *args = &ump->mount_args; */
	struct anchor_vdp *anchor, *anchor2;
	size_t size;
	int error;
	uint32_t main_len, main_loc, reserve_len, reserve_loc;

	/*
	 * read in VDS space provided by the anchors; if one descriptor read
	 * fails, try the mirror sector.
	 *
	 * check if 2nd anchor is different from 1st; if so, go for 2nd. This
	 * avoids the `compatibility features' of DirectCD that may confuse
	 * stuff completely.
	 */

	anchor = ump->anchors[0];
	anchor2 = ump->anchors[1];

	if (anchor2) {
		size = sizeof(struct extent_ad);
		if (memcmp(&anchor->main_vds_ex, &anchor2->main_vds_ex, size))
			anchor = anchor2;
		/* reserve is specified to be a literal copy of main */
	}

	main_loc = le32toh(anchor->main_vds_ex.loc);
	main_len = le32toh(anchor->main_vds_ex.len);

	reserve_loc = le32toh(anchor->reserve_vds_ex.loc);
	reserve_len = le32toh(anchor->reserve_vds_ex.len);

	error = udf_read_vds_extent(ump, main_loc, main_len);
	if (error != 0) {
		printf("UDF mount: reading in reserve VDS extent\n");
		error = udf_read_vds_extent(ump, reserve_loc, reserve_len);
	}

	return (error);
}

/*
 * Read in the logical volume integrity sequence pointed to by our logical
 * volume descriptor. Its a sequence that can be extended using fields in the
 * integrity descriptor itself. On sequential media only one is found, on
 * rewritable media a sequence of descriptors can be found as a form of
 * history keeping and on non sequential write-once media the chain is vital
 * to allow more and more descriptors to be written. The last descriptor
 * written in an extent needs to claim space for a new extent.
 */

static int
udf_retrieve_lvint(struct udf_mount *ump)
{
	union dscrptr *dscr;
	struct logvol_int_desc *lvint;
	int dscr_type, error;
	uint32_t lbnum, lb_size, len;

	lb_size = le32toh(ump->logical_vol->lb_size);
	len = le32toh(ump->logical_vol->integrity_seq_loc.len);
	lbnum = le32toh(ump->logical_vol->integrity_seq_loc.loc);

	lvint = NULL;
	dscr = NULL;
	error = 0;
	while (len) {
		/* read in our integrity descriptor */
		error = udf_read_phys_dscr(ump, lbnum, M_UDFTEMP, &dscr);
		if (error == 0) {
			if (dscr == NULL)
				break;		/* empty terminates */
			dscr_type = le16toh(dscr->tag.id);
			if (dscr_type == TAGID_TERM)
				break;		/* clean terminator */
			if (dscr_type != TAGID_LOGVOL_INTEGRITY) {
				printf("UDF mount: Invalid logical volume "
				    "integrity sequence entry found.\n");
#if 0
				/* fatal... corrupt disc */
				error = ENOENT;
#endif
				break;
			}
			if (lvint)
				free(lvint, M_UDFTEMP);
			lvint = &dscr->lvid;
			dscr = NULL;
		} /* else hope for the best... maybe the next is ok */

		/* proceed sequential */
		lbnum += 1;
		len -= lb_size;

		/* are we linking to a new piece? */
		if (dscr && lvint->next_extent.len) {
			len = le32toh(lvint->next_extent.len);
			lbnum = le32toh(lvint->next_extent.loc);
		}
	}

	/* clean up the mess, esp. when there is an error */
	if (dscr)
		free(dscr, M_UDFTEMP);

	if (error != 0 && lvint != NULL) {
		free(lvint, M_UDFTEMP);
		lvint = NULL;
	} else if (lvint == NULL) {
		printf("UDF mount: No logical volume integrity sequence entries"
		    " found.\n");
		error = ENOENT;
	}

	ump->logvol_integrity = lvint;

	return (error);
}

/*
 * Checks if ump's vds information is correct and complete
 */
int
udf_process_vds(struct udf_mount *ump) {
	/* struct udf_args *args = &ump->mount_args; */
	union udf_pmap *mapping;
	struct logvol_int_desc *lvint;
	struct part_desc *part;
	struct udf_logvol_info *lvinfo;
	int error, log_part, phys_part, pmap_size, pmap_stype, pmap_type;
	int len, n_meta, n_phys, n_spar, n_virt, raw_phys_part;
	uint32_t mt_l, n_pm;
	char *domain_name, *map_name; /* bits[128]; */
	const char *check_name;
	uint8_t *pmap_pos;

	/* we need at least one primary and one logical volume descriptor */
	if ((ump->primary_vol == NULL) || (ump->logical_vol) == NULL)
		return (EINVAL);

	/* we need at least one partition descriptor */
	if (ump->partitions[0] == NULL)
		return (EINVAL);

	/* check logical volume sector size verses device sector size */
	if (le32toh(ump->logical_vol->lb_size) != ump->sector_size) {
		printf("UDF mount: format violation, lb_size != sector size\n");
		return (EINVAL);
	}

	/* check domain name */
	domain_name = ump->logical_vol->domain_id.id;
	if (strncmp(domain_name, "*OSTA UDF Compliant", 20)) {
		printf("UDF mount: disc not OSTA UDF Compliant, aborting\n");
		return (EINVAL);
	}

	/*
	 * We need at least one logvol integrity descriptor recorded.  Note
	 * that its OK to have an open logical volume integrity here. The VAT
	 * will close/update the integrity.
	 */
	error = udf_retrieve_lvint(ump);
	if (error != 0)
		return (EINVAL); // previously it always returned this on error.

	/* process derived structures */
	n_pm = le32toh(ump->logical_vol->n_pm);   /* num partmaps         */
	lvint = ump->logvol_integrity;
	lvinfo = (struct udf_logvol_info *)(&lvint->tables[2 * n_pm]);
	ump->logvol_info = lvinfo;

	/* TODO check udf versions? */

	/*
	 * check logvol mappings: effective virt->log partmap translation
	 * check and recording of the mapping results. Saves expensive
	 * strncmp() in tight places.
	 */
	n_pm = le32toh(ump->logical_vol->n_pm);   /* num partmaps         */
	mt_l = le32toh(ump->logical_vol->mt_l);   /* partmaps data length */
	pmap_pos = ump->logical_vol->maps;

	if (n_pm > UDF_PMAPS) {
		printf("UDF mount: too many mappings\n");
		return (EINVAL);
	}

	/* count types and set partition numbers */
	n_phys = n_virt = n_spar = n_meta = 0;
	for (log_part = 0; log_part < n_pm; log_part++) {
		mapping = (union udf_pmap *)pmap_pos;
		pmap_stype = pmap_pos[0];
		pmap_size = pmap_pos[1];

		switch (pmap_stype) {
		case 1:	/* physical mapping */
			/* volseq = le16toh(mapping->pm1.vol_seq_num); */
			raw_phys_part = le16toh(mapping->pm1.part_num);
			pmap_type = UDF_VTOP_TYPE_PHYS;
			n_phys++;
			break;
		case 2: /* virtual/sparable/meta mapping */
			map_name = mapping->pm2.part_id.id;
			/* volseq = le16toh(mapping->pm2.vol_seq_num); */
			raw_phys_part = le16toh(mapping->pm2.part_num);
			pmap_type = UDF_VTOP_TYPE_UNKNOWN;
			len = UDF_REGID_ID_SIZE;

			check_name = "*UDF Virtual Partition";
			if (strncmp(map_name, check_name, len) == 0) {
				pmap_type = UDF_VTOP_TYPE_VIRT;
				n_virt++;
				break;
			}
			check_name = "*UDF Sparable Partition";
			if (strncmp(map_name, check_name, len) == 0) {
				pmap_type = UDF_VTOP_TYPE_SPARABLE;
				n_spar++;
				break;
			}
			check_name = "*UDF Metadata Partition";
			if (strncmp(map_name, check_name, len) == 0) {
				pmap_type = UDF_VTOP_TYPE_META;
				n_meta++;
				break;
			}
			break;
		default:
			return (EINVAL);
		}

		/*
		 * BUGALERT: some rogue implementations use random physical
		 * partition numbers to break other implementations so lookup
		 * the number.
		 */
		for (phys_part = 0; phys_part < UDF_PARTITIONS; phys_part++) {
			part = ump->partitions[phys_part];
			if (part == NULL)
				continue;
			if (le16toh(part->part_num) == raw_phys_part)
				break;
		}

		if (phys_part == UDF_PARTITIONS)
			return (EINVAL);
		if (pmap_type == UDF_VTOP_TYPE_UNKNOWN)
			return (EINVAL);

		ump->vtop[log_part] = phys_part;
		ump->vtop_tp[log_part] = pmap_type;

		pmap_pos += pmap_size;
	}
	/* not winning the beauty contest */
	ump->vtop_tp[UDF_VTOP_RAWPART] = UDF_VTOP_TYPE_RAW;

	/* test some basic UDF assertions/requirements */
	if ((n_virt > 1) || (n_spar > 1) || (n_meta > 1))
		return (EINVAL);

	if (n_virt) {
		if ((n_phys == 0) || n_spar || n_meta)
			return (EINVAL);
	}
	if (n_spar + n_phys == 0)
		return (EINVAL);

	/* signal its OK for now */
	return (0);
}

/*
 * Update logical volume name in all structures that keep a record of it. We
 * use memmove since each of them might be specified as a source.
 *
 * Note that it doesn't update the VAT structure!
 */
static void
udf_update_logvolname(struct udf_mount *ump, char *logvol_id)
{
	struct logvol_desc *lvd = NULL;
	struct fileset_desc *fsd = NULL;
	struct udf_lv_info *lvi = NULL;

	lvd = ump->logical_vol;
	fsd = ump->fileset_desc;
	if (ump->implementation)
		lvi = &ump->implementation->_impl_use.lv_info;

	/* logvol's id might be specified as origional so use memmove here */
	memmove(lvd->logvol_id, logvol_id, 128);
	if (fsd)
		memmove(fsd->logvol_id, logvol_id, 128);
	if (lvi)
		memmove(lvi->logvol_id, logvol_id, 128);
}

/*
 * Extended attribute support. UDF knows of 3 places for extended attributes:
 *
 * (a) inside the file's (e)fe in the length of the extended attribute area
 * before the allocation descriptors/filedata
 *
 * (b) in a file referenced by (e)fe->ext_attr_icb and 
 *
 * (c) in the e(fe)'s associated stream directory that can hold various
 * sub-files. In the stream directory a few fixed named subfiles are reserved
 * for NT/Unix ACL's and OS/2 attributes.
 * 
 * NOTE: Extended attributes are read randomly but allways written
 * *atomicaly*. For ACL's this interface is propably different but not known
 * to me yet.
 *
 * Order of extended attributes in a space :
 *   ECMA 167 EAs
 *   Non block aligned Implementation Use EAs
 *   Block aligned Implementation Use EAs
 *   Application Use EAs
 */

static int
udf_impl_extattr_check(struct impl_extattr_entry *implext)
{
	uint16_t *spos;

	if (strncmp(implext->imp_id.id, "*UDF", 4) == 0) {
		/* checksum valid? */
		spos = (uint16_t *)implext->data;
		if (le16toh(*spos) != udf_ea_cksum((uint8_t *)implext))
			return (EINVAL);
	}

	return (0);
}

static void
udf_calc_impl_extattr_checksum(struct impl_extattr_entry *implext)
{
	uint16_t *spos;

	if (strncmp(implext->imp_id.id, "*UDF", 4) == 0) {
		/* set checksum */
		spos = (uint16_t *)implext->data;
		*spos = le16toh(udf_ea_cksum((uint8_t *)implext));
	}
}

int
udf_extattr_search_intern(struct udf_node *node, uint32_t sattr,
    char const *sattrname, uint32_t *offsetp, uint32_t *lengthp)
{
	struct extattrhdr_desc *eahdr;
	struct extattr_entry *attrhdr;
	struct impl_extattr_entry *implext;
	int error;
	int32_t l_ea;
	uint32_t a_l, offset, sector_size;
	uint8_t *pos;

	/* get mountpoint */
	sector_size = node->ump->sector_size;

	/* get information from fe/efe */
	if (node->fe != NULL) {
		l_ea = le32toh(node->fe->l_ea);
		eahdr = (struct extattrhdr_desc *) node->fe->data;
	} else {
		l_ea = le32toh(node->efe->l_ea);
		eahdr = (struct extattrhdr_desc *) node->efe->data;
	}

	/* something recorded here? */
	if (l_ea == 0)
		return (ENOENT);

	/* check extended attribute tag; what to do if it fails? */
	error = udf_check_tag(eahdr);
	if (error != 0)
		return (EINVAL);
	if (le16toh(eahdr->tag.id) != TAGID_EXTATTR_HDR)
		return (EINVAL);
	error = udf_check_tag_payload(eahdr, sizeof(struct extattrhdr_desc));
	if (error != 0)
		return (EINVAL);

	/* looking for Ecma-167 attributes? */
	offset = sizeof(struct extattrhdr_desc);

	/* looking for either implemenation use or application use */
	if (sattr == 2048) {				/* [4/48.10.8] */
		offset = le32toh(eahdr->impl_attr_loc);
		if (offset == UDF_IMPL_ATTR_LOC_NOT_PRESENT)
			return (ENOENT);
	}
	if (sattr == 65536) {				/* [4/48.10.9] */
		offset = le32toh(eahdr->appl_attr_loc);
		if (offset == UDF_APPL_ATTR_LOC_NOT_PRESENT)
			return (ENOENT);
	}

	/* paranoia check offset and l_ea */
	if (l_ea + offset >= sector_size - sizeof(struct extattr_entry))
		return (EINVAL);

	/* find our extended attribute  */
	l_ea -= offset;
	pos = (uint8_t *)eahdr + offset;

	while (l_ea >= sizeof(struct extattr_entry)) {
		attrhdr = (struct extattr_entry *)pos;
		implext = (struct impl_extattr_entry *)pos;

		/* get complete attribute length and check for roque values */
		a_l = le32toh(attrhdr->a_l);
		if ((a_l == 0) || (a_l > l_ea))
			return (EINVAL);

		if (attrhdr->type != sattr)
			goto next_attribute;

		/* we might have found it! */
		if (attrhdr->type < 2048) {	/* Ecma-167 attribute */
			*offsetp = offset;
			*lengthp = a_l;
			return (0);		/* success */
		}

		/*
		 * Implementation use and application use extended attributes
		 * have a name to identify. They share the same structure only
		 * UDF implementation use extended attributes have a checksum
		 * we need to check
		 */

		if (strcmp(implext->imp_id.id, sattrname) == 0) {
			/* we have found our appl/implementation attribute */
			*offsetp = offset;
			*lengthp = a_l;
			return (0);		/* success */
		}

next_attribute:
		/* next attribute */
		pos += a_l;
		l_ea -= a_l;
		offset += a_l;
	}
	/* not found */
	return (ENOENT);
}

static int 
udf_update_lvid_from_vat_extattr(struct udf_node *vat_node)
{
	struct impl_extattr_entry *implext;
	struct vatlvext_extattr_entry lvext;
	struct udf_mount *ump;
	struct udf_logvol_info *lvinfo;
	uint64_t vat_uniqueid;
	int error;
	uint32_t a_l, offset;
	const char *extstr = "*UDF VAT LVExtension";
	uint8_t *ea_start, *lvextpos;

	/* get mountpoint and lvinfo */
	ump = vat_node->ump;
	lvinfo = ump->logvol_info;

	/* get information from fe/efe */
	if (vat_node->fe != NULL) {
		vat_uniqueid = le64toh(vat_node->fe->unique_id);
		ea_start = vat_node->fe->data;
	} else {
		vat_uniqueid = le64toh(vat_node->efe->unique_id);
		ea_start = vat_node->efe->data;
	}

	error = udf_extattr_search_intern(vat_node, 2048, extstr, &offset, 
	    &a_l);
	if (error !=0)
		return (error);

	implext = (struct impl_extattr_entry *)(ea_start + offset);
	error = udf_impl_extattr_check(implext);
	if (error != 0)
		return (error);

	/* paranoia */
	if (a_l != sizeof(*implext) - 1 + le32toh(implext->iu_l) +
	    sizeof(lvext))
		return (EINVAL);

	/*
	 * we have found our "VAT LVExtension attribute. BUT due to a
	 * bug in the specification it might not be word aligned so
	 * copy first to avoid panics on some machines (!!)
	 */
	lvextpos = implext->data + le32toh(implext->iu_l);
	memcpy(&lvext, lvextpos, sizeof(lvext));

	/* check if it was updated the last time */
	if (le64toh(lvext.unique_id_chk) == vat_uniqueid) {
		lvinfo->num_files = lvext.num_files;
		lvinfo->num_directories = lvext.num_directories;
		udf_update_logvolname(ump, lvext.logvol_id);
	} else {
		/* replace VAT LVExt by free space EA */
		memset(implext->imp_id.id, 0, UDF_REGID_ID_SIZE);
		strcpy(implext->imp_id.id, "*UDF FreeEASpace");
		udf_calc_impl_extattr_checksum(implext);
	}

	return (0);
}

int
udf_vat_read(struct udf_mount *ump, uint8_t *blob, int size, 
    uint32_t offset)
{
/*	mutex_enter(&ump->allocate_mutex); */
	if (offset + size > ump->vat_offset + ump->vat_entries * 4)
		return (EINVAL);
	memcpy(blob, ump->vat_table + offset, size);
/*	mutex_exit(&ump->allocate_mutex); */

	return (0);
}

/*
 * Read in relevant pieces of VAT file and check if its indeed a VAT file
 * descriptor. If OK, read in complete VAT file.
 */

static int
udf_check_for_vat(struct udf_node *vat_node)
{
	struct udf_mount *ump;
	struct icb_tag   *icbtag;
	struct timestamp *mtime;
	struct udf_vat   *vat;
	struct udf_oldvat_tail *oldvat_tl;
	struct udf_logvol_info *lvinfo;
	uint64_t  unique_id;
	int error, filetype;
	uint32_t vat_entries, vat_length, vat_offset, vat_table_alloc_len;
	uint32_t *raw_vat, sector_size;
	char *regid_name;
	uint8_t *vat_table;

	/* vat_length is really 64 bits though impossible */

	if (vat_node == NULL)
		return (ENOENT);

	/* get mount info */
	ump = vat_node->ump;
	sector_size = le32toh(ump->logical_vol->lb_size);

	/* get information from fe/efe */
	if (vat_node->fe != NULL) {
		vat_length = le64toh(vat_node->fe->inf_len);
		icbtag = &vat_node->fe->icbtag;
		mtime = &vat_node->fe->mtime;
		unique_id = le64toh(vat_node->fe->unique_id);
	} else {
		vat_length = le64toh(vat_node->efe->inf_len);
		icbtag = &vat_node->efe->icbtag;
		mtime = &vat_node->efe->mtime;
		unique_id = le64toh(vat_node->efe->unique_id);
	}

	/* Check icb filetype! it has to be 0 or UDF_ICB_FILETYPE_VAT */
	filetype = icbtag->file_type;
	if ((filetype != 0) && (filetype != UDF_ICB_FILETYPE_VAT))
		return (ENOENT);

	vat_table_alloc_len =
		((vat_length + UDF_VAT_CHUNKSIZE - 1) / UDF_VAT_CHUNKSIZE)
			* UDF_VAT_CHUNKSIZE;

	if (vat_table_alloc_len > UDF_VAT_ALLOC_LIMIT) {
		printf("UDF mount: VAT table length of %d bytes exceeds "
		    "implementation limit.\n", vat_table_alloc_len);
		return (ENOMEM);
	}
	vat_table = malloc(vat_table_alloc_len, M_UDFTEMP, M_WAITOK); 

	/* allocate piece to read in head or tail of VAT file */
	raw_vat = malloc(sector_size, M_UDFTEMP, M_WAITOK);

	/*
	 * check contents of the file if its the old 1.50 VAT table format.
	 * Its notoriously broken and allthough some implementations support an
	 * extention as defined in the UDF 1.50 errata document, its doubtfull
	 * to be useable since a lot of implementations don't maintain it.
	 */
	lvinfo = ump->logvol_info;

	if (filetype == 0) {
		/* definition */
		vat_offset = 0;
		vat_entries = (vat_length - 36) / 4;

		/* read in tail of virtual allocation table file */
		error = udf_read_node(vat_node, (uint8_t *)raw_vat, 
		    vat_entries * 4, sizeof(struct udf_oldvat_tail));
		if (error != 0)
			goto out;

		/* check 1.50 VAT */
		oldvat_tl = (struct udf_oldvat_tail *)raw_vat;
		regid_name = (char *)oldvat_tl->id.id;
		error = strncmp(regid_name, "*UDF Virtual Alloc Tbl", 22);
		if (error != 0) {
			error = ENOENT;
			goto out;
		}

		/*
		 * update LVID from "*UDF VAT LVExtension" extended attribute
		 * if present.
		 */
		udf_update_lvid_from_vat_extattr(vat_node);
	} else {
		/* read in head of virtual allocation table file */
		error = udf_read_node(vat_node, (uint8_t *)raw_vat, 0, 
		    sizeof(struct udf_vat));
		if (error != 0)
			goto out;

		/* definition */
		vat = (struct udf_vat *)raw_vat;
		vat_offset = vat->header_len;
		vat_entries = (vat_length - vat_offset) / 4;

		lvinfo->num_files = vat->num_files;
		lvinfo->num_directories = vat->num_directories;
		lvinfo->min_udf_readver = vat->min_udf_readver;
		lvinfo->min_udf_writever = vat->min_udf_writever;
		lvinfo->max_udf_writever = vat->max_udf_writever;
	
		udf_update_logvolname(ump, vat->logvol_id);
	}

	/* read in complete VAT file */
	error = udf_read_node(vat_node, vat_table, 0, vat_length);
	if (error != 0)
		printf("UDF mount: Error reading in of complete VAT file."
		    " (error %d)\n", error);
	if (error != 0)
		goto out;

	ump->logvol_integrity->lvint_next_unique_id = htole64(unique_id);
	ump->logvol_integrity->integrity_type = htole32(UDF_INTEGRITY_CLOSED);
	ump->logvol_integrity->time = *mtime;

	ump->vat_table_alloc_len = vat_table_alloc_len;
	ump->vat_table = vat_table;
	ump->vat_offset = vat_offset;
	ump->vat_entries = vat_entries;

out:
	if (error != 0) {
		if (vat_table != NULL)
			free(vat_table, M_UDFTEMP);
	}
	free(raw_vat, M_UDFTEMP);

	return (error);
}

static int
udf_search_vat(struct udf_mount *ump)
{
	union dscrptr *dscr;
	struct long_ad icb_loc;
	struct udf_node *vat_node;
	int error;
	uint32_t early_vat_loc, vat_loc;
	uint16_t tagid;
	uint8_t file_type;

	vat_node = NULL;

	early_vat_loc = ump->first_possible_vat_location;
	vat_loc = ump->last_possible_vat_location;

	/* start looking from the end of the range */
	do {
		error = udf_read_phys_dscr(ump, vat_loc, M_UDFTEMP, &dscr);
		if (!error && dscr) { /* dscr will be null if zeros were read */
			tagid = le16toh(dscr->tag.id);
			file_type = 0;
			if (tagid == TAGID_FENTRY)
			    file_type = dscr->fe.icbtag.file_type;
			else if (tagid == TAGID_EXTFENTRY)
			    file_type = dscr->efe.icbtag.file_type; 
			free(dscr, M_UDFTEMP);

			if (file_type == 248)
			{
				icb_loc.loc.part_num = 
				    htole16(UDF_VTOP_RAWPART);
				icb_loc.loc.lb_num = htole32(vat_loc);
				error = udf_get_node(ump, icb_loc, &vat_node);
				if (error == 0)
					error = udf_check_for_vat(vat_node);
				if (error == 0) {
					udf_dispose_node(vat_node);
					break;
				}
			}
		}

		if (vat_node != NULL) {
			udf_dispose_node(vat_node);
			vat_node = NULL;
		}

		if (vat_loc == ump->last_possible_vat_location)
			printf("UDF mount: VAT not found at last written "
			    "location\n");

		vat_loc--;
	} while (vat_loc >= early_vat_loc);

	return (error);
}

static int
udf_read_sparables(struct udf_mount *ump, union udf_pmap *mapping)
{
	union dscrptr *dscr;
	struct part_map_spare *pms = &mapping->pms;
	int error, spar;
	uint32_t lb_num;

	/*
	 * The partition mapping passed on to us specifies the information we
	 * need to locate and initialise the sparable partition mapping
	 * information we need.
	 */

	ump->sparable_packet_size = le16toh(pms->packet_len);

	for (spar = 0; spar < pms->n_st; spar++) {
		lb_num = pms->st_loc[spar];
		error = udf_read_phys_dscr(ump, lb_num, M_UDFTEMP, &dscr);
		if (!error && dscr) {
			if (le16toh(dscr->tag.id) == TAGID_SPARING_TABLE) {
				if (ump->sparing_table)
					free(ump->sparing_table, M_UDFTEMP);
				ump->sparing_table = &dscr->spt;
				dscr = NULL;
				break;	/* we're done */
			}
		}
		if (dscr)
			free(dscr, M_UDFTEMP);
	}

	if (ump->sparing_table)
		return (0);

	return (ENOENT);
}

static int
udf_read_metadata_nodes(struct udf_mount *ump, union udf_pmap *mapping)
{
	struct part_map_meta *pmm = &mapping->pmm;
	struct long_ad icb_loc;
	int error = 0;
	char *windows_id = "*Microsoft Windows";

	/* 
	 * The mappings come from the logical volume descripor, and Windows does
	 * not write a usable partion number into the metadata map descriptor. 
	 */
	if (strncmp(windows_id, ump->logical_vol->imp_id.id, 23) == 0)
		icb_loc.loc.part_num = 0;
	else
		icb_loc.loc.part_num = pmm->part_num;

	icb_loc.loc.lb_num = pmm->meta_file_lbn;
	udf_get_node(ump, icb_loc, &ump->metadata_node);

	if (ump->metadata_node == NULL) {
		icb_loc.loc.lb_num = pmm->meta_mirror_file_lbn;
		if (icb_loc.loc.lb_num != -1)
			udf_get_node(ump, icb_loc, &ump->metadata_node);
		
		if (ump->metadata_node != NULL)
			printf("UDF mount: Metadata file not readable, "
			    "substituting Metadata copy file\n");
	}

	/* if we're mounting read-only we relax the requirements */
	if (ump->metadata_node == NULL)
		error = EFAULT;
	
	return (error);
}

int
udf_read_vds_tables(struct udf_mount *ump)
{
	union udf_pmap *mapping;
	int pmap_size, error;
	uint32_t log_part, mt_l, n_pm;
	uint8_t *pmap_pos;

	error = 0;

	/* Iterate (again) over the part mappings for locations   */
	n_pm = le32toh(ump->logical_vol->n_pm);   /* num partmaps         */
	mt_l = le32toh(ump->logical_vol->mt_l);   /* partmaps data length */
	pmap_pos = ump->logical_vol->maps;

	for (log_part = 0; log_part < n_pm; log_part++) {
		mapping = (union udf_pmap *) pmap_pos;
		switch (ump->vtop_tp[log_part]) {
		case UDF_VTOP_TYPE_PHYS:
			/* nothing */
			break;
		case UDF_VTOP_TYPE_VIRT:
			/* search and load VAT */
			error = udf_search_vat(ump);
			if (error != 0)
				return (ENOENT);
			break;
		case UDF_VTOP_TYPE_SPARABLE:
			/* load one of the sparable tables */
			error = udf_read_sparables(ump, mapping);
			if (error != 0)
				return (ENOENT);
			break;
		case UDF_VTOP_TYPE_META:
			/* load the associated file descriptors */
			error = udf_read_metadata_nodes(ump, mapping);
			if (error != 0)
				return (ENOENT);
			break;
		default:
			break;
		}
		pmap_size = pmap_pos[1];
		pmap_pos += pmap_size;
	}

	return (0);
}

int
udf_read_rootdirs(struct udf_mount *ump)
{
	union dscrptr *dscr;
	struct mount *mp;
	struct vnode *rootdir_node, *streamdir_node;
	struct long_ad *dir_loc, fsd_loc;
	ino_t ino;
	int dscr_type, error;
	uint32_t dummy, fsd_len, lb_num;

	mp = ump->vfs_mountp;

	/* TODO implement FSD reading in separate function like integrity? */
	/* get fileset descriptor sequence */
	fsd_loc = ump->logical_vol->lv_fsd_loc;
	fsd_len = le32toh(fsd_loc.len);

	dscr = NULL;
	error = 0;
	while (fsd_len > 0 || error != 0) {
		/* translate fsd_loc to lb_num */
		error = udf_translate_vtop(ump, &fsd_loc, &lb_num, &dummy);
		if (error != 0)
			break;
		error = udf_read_phys_dscr(ump, lb_num, M_UDFTEMP, &dscr);
		/* end markers */
		if (error != 0 || dscr == NULL)
			break;

		/* analyse */
		dscr_type = le16toh(dscr->tag.id);
		if (dscr_type == TAGID_TERM)
			break;
		if (dscr_type != TAGID_FSD) {
			free(dscr, M_UDFTEMP);
			return (ENOENT);
		}

		/*
		 * TODO check for multiple fileset descriptors; its only
		 * picking the last now. Also check for FSD
		 * correctness/interpretability
		 */

		/* update */
		if (ump->fileset_desc != NULL) {
			free(ump->fileset_desc, M_UDFTEMP);
		}
		ump->fileset_desc = &dscr->fsd;
		dscr = NULL;

		/* continue to the next fsd */
		fsd_len -= ump->sector_size;
		fsd_loc.loc.lb_num = htole32(le32toh(fsd_loc.loc.lb_num) + 1);

		/* follow up to fsd->next_ex (long_ad) if its not null */
		if (le32toh(ump->fileset_desc->next_ex.len)) {
			fsd_loc = ump->fileset_desc->next_ex;
			fsd_len = le32toh(ump->fileset_desc->next_ex.len);
		}
	}
	if (dscr != NULL)
		free(dscr, M_UDFTEMP);

	/* there has to be one */
	if (ump->fileset_desc == NULL)
		return (ENOENT);

	udf_update_logvolname(ump, ump->logical_vol->logvol_id);

	/*
	 * Now the FSD is known, read in the rootdirectory and if one exists,
	 * the system stream dir. Some files in the system streamdir are not
	 * wanted in this implementation since they are not maintained. If
	 * writing is enabled we'll delete these files if they exist.
	 */

	rootdir_node = streamdir_node = NULL;
	dir_loc = NULL;

	/* try to read in the rootdir */
	dir_loc = &ump->fileset_desc->rootdir_icb;
	error = udf_get_node_id(*dir_loc, &ino);
	if (error == 0)
		error = udf_vget(mp, ino, LK_EXCLUSIVE, &rootdir_node);
	if (error != 0)
		return (ENOENT);

	/*
	 * Try the system stream directory; not very likely in the ones we
	 * test, but for completeness.
	 */
	dir_loc = &ump->fileset_desc->streamdir_icb;
	if (le32toh(dir_loc->len)) {
		error = udf_get_node_id(*dir_loc, &ino);
		if (error == 0)
			error = udf_vget(mp, ino, LK_EXCLUSIVE, 
			    &streamdir_node);
		if (error != 0)
			printf("UDF mount: streamdir defined but error in "
			    "streamdir reading\n");
#if 0
		else {
			printf("UDF mount: streamdir defined but ignored\n");
			/*
			 * TODO process streamdir `baddies' i.e. files we dont
			 * want if R/W
			 */
		}
#endif
	}

	/* release the vnodes again; they'll be auto-recycled later */
	if (streamdir_node != NULL) {
		/* This is not used later. */
		vgone(streamdir_node);
		vput(streamdir_node);
	}
	if (rootdir_node != NULL) {
		/* Vnodes are not initialized correctly until mounting is
		complete. */
		vgone(rootdir_node);
		vput(rootdir_node);
	}

	return (0);
}

/* 
 * To make absolutely sure we are NOT returning zero, add one.  This can fail,
 * but in final version should probably never fail.
 */
int
udf_get_node_id(const struct long_ad icbptr, ino_t *ino)
{
	uint32_t blkn;
	uint16_t part;

	/* Just for now, this should be done in another way. */
	blkn = le32toh(icbptr.loc.lb_num);
	part = le16toh(icbptr.loc.part_num);

	if ((blkn + 1) & 0xE0000000) {
		printf("UDF: Block number too large to convert to inode "
		    "number.\n");
		return EDOOFUS;
	}
	if (part & 0xFFF8) {
		printf("UDF: Partition number too large to convert to inode "
		    "number.\n");
		return EDOOFUS;
	}

	*ino = (blkn + 1) | (part << 29);

	return (0);
}

void
udf_get_node_longad(const ino_t ino, struct long_ad *icbptr)
{
	uint32_t blkn, ino2;
	uint16_t part;

	/* Just for now, this should be done in another way. */
	ino2 = ino;
	blkn = (ino2 & 0x1FFFFFFF) - 1;
	part = (ino2 & 0xE0000000) >> 29;

	icbptr->loc.lb_num = htole32(blkn);
	icbptr->loc.part_num = htole16(part);
}

/* UDF<->unix converters */

static mode_t
udf_perm_to_unix_mode(uint32_t perm)
{
	mode_t mode;

	mode = ((perm & UDF_FENTRY_PERM_USER_MASK));
	mode |= ((perm & UDF_FENTRY_PERM_GRP_MASK) >> 2);
	mode |= ((perm & UDF_FENTRY_PERM_OWNER_MASK) >> 4);

	return (mode);
}

static uint32_t
udf_icb_to_unix_filetype(uint32_t icbftype)
{
	switch (icbftype) {
	case UDF_ICB_FILETYPE_DIRECTORY:
	case UDF_ICB_FILETYPE_STREAMDIR:
		return (S_IFDIR);
	case UDF_ICB_FILETYPE_FIFO:
		return (S_IFIFO);
	case UDF_ICB_FILETYPE_CHARDEVICE:
		return (S_IFCHR);
	case UDF_ICB_FILETYPE_BLOCKDEVICE:
		return (S_IFBLK);
	case UDF_ICB_FILETYPE_RANDOMACCESS:
	case UDF_ICB_FILETYPE_REALTIME:
		return (S_IFREG);
	case UDF_ICB_FILETYPE_SYMLINK:
		return (S_IFLNK);
	case UDF_ICB_FILETYPE_SOCKET:
		return (S_IFSOCK);
	}
	/* no idea what this is */
	return (0);
}

/* These timestamp_to_timespec functions are done. */

static int 
udf_leapyear(int year)
{
	int i;

	i = (year % 400 == 0) ? 1 : 0;
	i |= (year % 100 == 0) ? 0 : 1; 
	i &= (year % 4 == 0) ? 1 : 0;

	return (i);
}

void
udf_timestamp_to_timespec(struct udf_mount *ump,
			  struct timestamp *timestamp,
			  struct timespec  *timespec)
{
	time_t secs;
	const int days_to_mon[12] = {0, 31, 59, 90, 120, 151, 181, 212, 243,
	    273, 304, 334};
	uint32_t nsecs, usecs;
	uint16_t tz, year;

	year = le16toh(timestamp->year);
	if (year < 1970 || timestamp->month < 1 || timestamp->month > 12) {
		timespec->tv_sec = 0;
		timespec->tv_nsec = 0;
		return;
	}

	secs = timestamp->second;
	secs += timestamp->minute * 60;
	secs += timestamp->hour * 3600;
	secs += (timestamp->day - 1) * 3600 * 24;
	secs += days_to_mon[timestamp->month - 1] * 3600 * 24;

	secs += (year - 1970) * 365 * 3600 * 24;
	secs += ((year - 1 - 1968) / 4) * 3600 * 24;

	if (year > 2100) {
		secs -= (((year - 1 - 2100) / 100) + 1) * 3600 * 24;
	}
	if (year > 2400) {
		secs += (((year - 1 - 2400) / 400) + 1) * 3600 * 24;
	}
	if (timestamp->month > 2) {
		secs += (time_t)udf_leapyear(year) * 3600 * 24;
	}

	usecs = timestamp->usec + 100 * timestamp->hund_usec + 
	    10000 * timestamp->centisec;
	nsecs = usecs * 1000;

	/*
	 * Calculate the time zone.  The timezone is 12 bit signed 2's
	 * compliment, so we gotta do some extra magic to handle it right.
	 */
	tz  = le16toh(timestamp->type_tz);
	tz &= 0x0fff;		/* only lower 12 bits are significant */
	if (tz & 0x0800)	/* sign extention */
		tz |= 0xf000;

	/*
	 * TODO check timezone conversion 
	 * check if we are specified a timezone to convert 
	 */
	if (le16toh(timestamp->type_tz) & 0x1000) {
		if ((int16_t)tz != -2047)
			secs -= (int16_t)tz * 60;
	} /* else {
		secs -= ump->mount_args.gmtoff;
	} */

	timespec->tv_sec = secs;
	timespec->tv_nsec = nsecs;
}

/*
 * Attribute and filetypes converters with get/set pairs
 */

uint32_t
udf_getaccessmode(struct udf_node *udf_node)
{
	struct file_entry *fe = udf_node->fe;
	struct extfile_entry *efe = udf_node->efe;
	uint32_t ftype, icbftype, mode, udf_perm;
	uint16_t icbflags;

	UDF_LOCK_NODE(udf_node, 0);

	if (fe != NULL) {
		udf_perm = le32toh(fe->perm);
		icbftype = fe->icbtag.file_type;
		icbflags = le16toh(fe->icbtag.flags);
	} else {
		/*assert(udf_node->efe != NULL); */
		udf_perm = le32toh(efe->perm);
		icbftype = efe->icbtag.file_type;
		icbflags = le16toh(efe->icbtag.flags);
	}

	mode = udf_perm_to_unix_mode(udf_perm);
	ftype = udf_icb_to_unix_filetype(icbftype);

	/* set suid, sgid, sticky from flags in fe/efe */
	if (icbflags & UDF_ICB_TAG_FLAGS_SETUID)
		mode |= S_ISUID;
	if (icbflags & UDF_ICB_TAG_FLAGS_SETGID)
		mode |= S_ISGID;
	if (icbflags & UDF_ICB_TAG_FLAGS_STICKY)
		mode |= S_ISVTX;

	UDF_UNLOCK_NODE(udf_node, 0);

	return (mode | ftype);
}

/*
 * Each node can have an attached streamdir node though not recursively. These
 * are otherwise known as named substreams/named extended attributes that have
 * no size limitations.
 *
 * `Normal' extended attributes are indicated with a number and are recorded
 * in either the fe/efe descriptor itself for small descriptors or recorded in
 * the attached extended attribute file. Since these spaces can get
 * fragmented, care ought to be taken.
 *
 * Since the size of the space reserved for allocation descriptors is limited,
 * there is a mechanim provided for extending this space; this is done by a
 * special extent to allow schrinking of the allocations without breaking the
 * linkage to the allocation extent descriptor.
 */

int
udf_get_node(struct udf_mount *ump, struct long_ad icb_loc,
    struct udf_node **ppunode)
{
	union dscrptr *dscr;
	struct long_ad last_fe_icb_loc;
	struct udf_node *udf_node;
	uint64_t file_size;
	int dscr_type, eof, error, slot, strat, strat4096;
	uint32_t dummy, lb_size, sector;
	uint8_t  *file_data;

	/* garbage check: translate udf_node_icb_loc to sectornr */
	error = udf_translate_vtop(ump, &icb_loc, &sector, &dummy);
	if (error != 0)
		return (EINVAL);

	/* initialise crosslinks, note location of fe/efe for hashing */
	udf_node = udf_alloc_node();
	udf_node->ump = ump;
	udf_node->loc = icb_loc;
/*	mutex_init(&udf_node->node_mutex, MUTEX_DEFAULT, IPL_NONE); */
/*	cv_init(&udf_node->node_lock, "udf_nlk"); */

	/* safe to unlock, the entry is in the hash table, vnode is locked */
/*	mutex_exit(&ump->get_node_lock); */

	strat4096 = 0;
	file_size = 0;
	file_data = NULL;
	lb_size = le32toh(ump->logical_vol->lb_size);

	do {
		/* try to read in fe/efe */
		error = udf_translate_vtop(ump, &icb_loc, &sector, &dummy);
		if (error == 0)
			error = udf_read_phys_dscr(ump, sector, M_UDFTEMP, 
			    &dscr);

		/* blank sector marks end of sequence, check this */
		if (dscr == NULL && strat4096 == 0)
			error = ENOENT;

		/* break if read error or blank sector */
		if (error != 0 || dscr == NULL)
			break;

		/* process descriptor based on the descriptor type */
		dscr_type = le16toh(dscr->tag.id);

		/* if dealing with an indirect entry, follow the link */
		if (dscr_type == TAGID_INDIRECTENTRY) {
			free(dscr, M_UDFTEMP);
			icb_loc = dscr->inde.indirect_icb;
			continue;
		}

		/* only file entries and extended file entries allowed here */
		if ((dscr_type != TAGID_FENTRY) &&
		    (dscr_type != TAGID_EXTFENTRY)) {
			free(dscr, M_UDFTEMP);
			error = ENOENT;
			break;
		}

		/* choose this one */
		last_fe_icb_loc = icb_loc;
		
		/* record and process/update (ext)fentry */
		file_data = NULL;
		if (dscr_type == TAGID_FENTRY) {
			if (udf_node->fe != NULL)
				free(udf_node->fe, M_UDFTEMP);
			udf_node->fe = &dscr->fe;
			strat = le16toh(udf_node->fe->icbtag.strat_type);
			file_size = le64toh(udf_node->fe->inf_len);
			file_data = udf_node->fe->data;
		} else {
			if (udf_node->efe != NULL)
				free(udf_node->efe, M_UDFTEMP);
			udf_node->efe = &dscr->efe;
			strat = le16toh(udf_node->efe->icbtag.strat_type);
			file_size = le64toh(udf_node->efe->inf_len);
			file_data = udf_node->efe->data;
		}

		/* check recording strategy (structure) */

		/*
		 * Strategy 4096 is a daisy linked chain terminating with an
		 * unrecorded sector or a TERM descriptor. The next
		 * descriptor is to be found in the sector that follows the
		 * current sector.
		 */
		if (strat == 4096) {
			strat4096 = 1;
			icb_loc.loc.lb_num = le32toh(icb_loc.loc.lb_num) + 1;
		}

		/*
		 * Strategy 4 is the normal strategy and terminates, but if
		 * we're in strategy 4096, we can't have strategy 4 mixed in
		 */

		if (strat == 4) {
			if (strat4096 != 0) {
				error = EINVAL;
				break;
			}
			break;		/* done */
		}
	} while (!error);

	/* first round of cleanup code */
	if (error != 0) {
		udf_dispose_node(udf_node);
		return (EINVAL);
	}

	/*
	 * Go trough all allocations extents of this descriptor and when
	 * encountering a redirect read in the allocation extension. These are
	 * daisy-chained.
	 */
	UDF_LOCK_NODE(udf_node, 0);
	udf_node->num_extensions = 0;

	error = 0;
	slot = 0;
	for (;;) {
		udf_get_adslot(udf_node, slot, &icb_loc, &eof);
		if (eof != 0)
			break;
		slot++;

		if (UDF_EXT_FLAGS(le32toh(icb_loc.len)) != UDF_EXT_REDIRECT)
			continue;

		if (udf_node->num_extensions >= UDF_MAX_ALLOC_EXTENTS) {
			error = EINVAL;
			break;
		}

		/* length can only be *one* lb : UDF 2.50/2.3.7.1 */
		if (UDF_EXT_LEN(le32toh(icb_loc.len)) != lb_size) {
			error = EINVAL;
			break;
		}

		/* load in allocation extent */
		error = udf_translate_vtop(ump, &icb_loc, &sector, &dummy);
		if (error == 0)
			error = udf_read_phys_dscr(ump, sector, M_UDFTEMP, 
			    &dscr);
		if (error != 0 || dscr == NULL)
			break;

		/* process read-in descriptor */
		dscr_type = le16toh(dscr->tag.id);

		if (dscr_type != TAGID_ALLOCEXTENT) {
			free(dscr, M_UDFTEMP);
			error = ENOENT;
			break;
		}

		udf_node->ext[udf_node->num_extensions] = &dscr->aee;

		udf_node->num_extensions++;

	} /* while */
	UDF_UNLOCK_NODE(udf_node, 0);

	/* second round of cleanup code */
	if (error != 0) {
		/* recycle udf_node */
		udf_dispose_node(udf_node);
		return (EINVAL);		/* error code ok? */
	}

	/* TODO ext attr and streamdir udf_nodes */

	*ppunode = udf_node;

	return (0);
}

int
udf_dispose_node(struct udf_node *udf_node)
{
	int extnr;

	if (udf_node == NULL)
		return (0);

	/* TODO extended attributes and streamdir */

	/* free associated memory and the node itself */
	for (extnr = 0; extnr < udf_node->num_extensions; extnr++) {
		free(udf_node->ext[extnr], M_UDFTEMP);
		udf_node->ext[extnr] = (void *)0xdeadcccc;
	}

	if (udf_node->fe != NULL)
		free(udf_node->fe, M_UDFTEMP);

	if (udf_node->efe != NULL)
		free(udf_node->efe, M_UDFTEMP);

	udf_node->fe = (void *)0xdeadaaaa;
	udf_node->efe = (void *)0xdeadbbbb;
	udf_node->ump = (void *)0xdeadbeef;
	udf_free_node(udf_node);

	return (0);
}

/*
 * Read one fid and process it into a dirent and advance to the next (*fid)
 * has to be allocated a logical block in size, (*dirent) struct dirent length
 */

int
udf_validate_fid(struct fileid_desc *fid, int *realsize)
{
	int error, fid_size;

	/* check if our FID header is OK */
	if ((error = udf_check_tag(fid)) != 0)
		goto brokendir;

	if (le16toh(fid->tag.id) != TAGID_FID) {
		error = EIO;
		goto brokendir;
	}

	/* check for length */
	fid_size = udf_fidsize(fid);
	if (*realsize < fid_size) {
		error = EIO;
		goto brokendir;
	}

	/* check FID contents */
	error = udf_check_tag_payload((union dscrptr *)fid, *realsize);

	*realsize = fid_size;
brokendir:
	if (error != 0)
		return (EIO);

	return (error);
}

/*
 * Read and write file extent in/from the buffer.
 *
 * The splitup of the extent into seperate request-buffers is to minimise
 * copying around as much as possible.
 *
 * block based file reading and writing
 */

int
udf_read_internal(struct udf_node *node, uint8_t *blob)
{
	struct file_entry *fe = node->fe;
	struct extfile_entry *efe = node->efe;
	struct udf_mount *ump;
	uint64_t inflen;
	int addr_type, icbflags;
	uint32_t sector_size;
	uint8_t *pos;

	/* get extent and do some paranoia checks */
	ump = node->ump;
	sector_size = ump->sector_size;

	if (fe != NULL) {
		inflen = le64toh(fe->inf_len);
		pos = &fe->data[0] + le32toh(fe->l_ea);
		icbflags = le16toh(fe->icbtag.flags);
	} else {
		inflen = le64toh(efe->inf_len);
		pos = &efe->data[0] + le32toh(efe->l_ea);
		icbflags = le16toh(efe->icbtag.flags);
	}
	addr_type = icbflags & UDF_ICB_TAG_FLAGS_ALLOC_MASK;

	/* copy out info */
	memset(blob, 0, sector_size);
	memcpy(blob, pos, inflen);

	return (0);
}
