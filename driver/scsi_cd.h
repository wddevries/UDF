/*-
 * Copyright (c) 2000, 2002 Kenneth D. Merry
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
/*
 * Written by Julian Elischer (julian@tfs.com)
 * for TRW Financial Systems.
 *
 * TRW Financial Systems, in accordance with their agreement with Carnegie
 * Mellon University, makes this software available to CMU to distribute
 * or use in any manner that they see fit as long as this message is kept with
 * the software. For this reason TFS also grants any other persons or
 * organisations permission to use or modify this software.
 *
 * TFS supplies this software to be publicly redistributed
 * on the understanding that TFS is not responsible for the correct
 * functioning of this software in any circumstances.
 *
 * Ported to run under 386BSD by Julian Elischer (julian@tfs.com) Sept 1992
 *
 *	from: scsi_cd.h,v 1.10 1997/02/22 09:44:28 peter Exp $
 * $FreeBSD: src/sys/cam/scsi/scsi_cd.h,v 1.7 2003/02/21 06:19:38 ken Exp $
 */
#ifndef	_SCSI_SCSI_CD_H
#define _SCSI_SCSI_CD_H 1

/*
 *	Define two bits always in the same place in byte 2 (flag byte)
 */
#define	CD_RELADDR	0x01
#define	CD_MSF		0x02

/*
 * SCSI command format
 */

/* Used in UDF */

#define GET_CONFIGURATION 0x46	/* cdrom read TOC */
struct scsi_get_conf 
{
	uint8_t op_code;
	uint8_t byte2;
#define GC_RT_ALLFEATURES	0x00 /* Return header and all features active or not. */
#define GC_RT_CURFEATURES	0x01 /* Return header and all active features. */
#define GC_RT_ZEROFEATURES	0x02 /* Return header and zero or one feature. */
	uint8_t start_feature[2];
	uint8_t reserved[3];
	uint8_t alloc_len[2];
	uint8_t control;
};

struct scsi_get_conf_header
{
	uint8_t data_len[4];
	uint8_t reserved[2];
	uint8_t cur_profile[2];
};

struct scsi_get_conf_feature_generic
{
	uint8_t	feature_code[2];
#define GC_FC_PROFILE_LIST		0x0000
#define GC_FC_CORE			0x0001
#define GC_FC_MORPHING			0x0002 
#define GC_FC_REMOVABLE_MEDIUM		0x0003
#define GC_FC_WRITE_PROTECT		0x0004
#define GC_FC_RANDOM_READABLE		0x0010
#define GC_FC_MULTIREAD			0x001D
#define GC_FC_CD_READ			0x001E
#define GC_FC_DVD_READ			0x001F
#define GC_FC_RANDOM_WRITABLE		0x0020
#define GC_FC_INCR_STREAMING_WRITABLE	0x0021
#define GC_FC_SECTOR_ERASABLE		0x0022
#define GC_FC_FORMATTABLE		0x0023
#define GC_FC_DEFECT_MANAGEMENT 	0x0024
#define GC_FC_WRITE_ONCE		0x0025
#define GC_FC_RESTRICTED_OVERWRITE	0x0026
#define GC_FC_CD_RW_CAV_WRITE		0x0027
#define GC_FC_MRW_SUPPORT		0x0028 /* feature name guessed */
#define GC_FC_DVD_READ_OPT_WRITE	0x002B /* feature name guessed */
#define GC_FC_RIGID_RESTRICTED_OVERWRITE 0x002C
#define GC_FC_CD_TRACK_AT_ONCE		0x002D
#define GC_FC_CD_MASTERING		0x002E
#define GC_FC_DVD_R_RW_WRITE		0x002F
#define GC_FC_POWER_MANAGEMENT		0x0100
#define GC_FC_SMART			0x0101
#define GC_FC_EMBEDDED_CHANGER		0x0102
#define GC_FC_CD_AUDIO_ANALOG_PLAY	0x0103
#define GC_FC_MICROCODE_UPGRADE 	0x0104
#define GC_FC_TIME_OUT 			0x0105
#define GC_FC_DVD_CSS			0x0106
#define GC_FC_REAL_TIME_STREAMING	0x0107
#define GC_FC_LOGICAL_UNIT_SERIAL_NUMBER 0x0108
#define GC_FC_DISC_CONTROL_BLOCKS	0x010A
#define GC_FC_DVD_CPRM			0x010B
	uint8_t	byte3;
#define GC_CURRENT			0x1
#define GC_PERSISTENT			0x2
	uint8_t	additional_len;
	uint8_t data[];
};


#define READ_DISC_INFO 0x51
struct scsi_read_disc_info
{
	uint8_t op_code;
	uint8_t byte2;
	uint8_t reserved[5];
	uint8_t alloc_len[2];
	uint8_t control;
};

struct scsi_read_disc_info_data
{
	uint8_t disc_info_len[2];
	uint8_t byte2;
	uint8_t num_first_track;
	uint8_t num_sessions_lsb;
	uint8_t first_track_last_session_lsb;
	uint8_t last_track_last_session_lsb;
	uint8_t byte8;
	uint8_t disc_type;
	uint8_t num_sessions_msb;
	uint8_t first_track_last_session_msb;
	uint8_t last_track_last_session_msb;
	uint8_t disc_id[4];
	uint8_t leadin_start_last_session[4];
	uint8_t last_start_time_leadout[4];
	uint8_t disc_bar_code[8];
	uint8_t reserved;
	uint8_t num_opc_entries;
	uint8_t opc_entries[];
};


#define READ_TRACK_INFO 0x52
struct scsi_read_track_info
{
	uint8_t op_code;
	uint8_t byte2;
#define READ_TRACK_INFO_AT_LBA		0x00
#define READ_TRACK_INFO_AT_TRACK	0x01
#define READ_TRACK_INFO_AT_BORDER	0x02
	uint8_t address[4];
	uint8_t reserved;
	uint8_t alloc_len[2];
	uint8_t control;
};

struct scsi_read_track_info_data
{
	uint8_t track_info_len[2];
	uint8_t track_num_lsb;
	uint8_t session_num_lsb;
	uint8_t reserved1;
	uint8_t track_info1;
	uint8_t track_info2;
	uint8_t valid_data;
#define READ_TRACK_INFO_LRA_V		0x2
#define READ_TRACK_INFO_NWA_V		0x1
	uint8_t track_start_addr[4];
	uint8_t next_writable_addr[4];
	uint8_t free_blocks[4];
	uint8_t packet_size[4];
	uint8_t track_size[4];
	uint8_t last_recorded_addr[4];
	uint8_t track_num_msb;
	uint8_t session_num_msb;
	uint8_t reserved2[2];
};
/* End of UDF */

struct scsi_pause
{
	u_int8_t op_code;
	u_int8_t byte2;
	u_int8_t unused[6];
	u_int8_t resume;
	u_int8_t control;
};
#define	PA_PAUSE	1
#define PA_RESUME	0

struct scsi_play_msf
{
	u_int8_t op_code;
	u_int8_t byte2;
	u_int8_t unused;
	u_int8_t start_m;
	u_int8_t start_s;
	u_int8_t start_f;
	u_int8_t end_m;
	u_int8_t end_s;
	u_int8_t end_f;
	u_int8_t control;
};

struct scsi_play_track
{
	u_int8_t op_code;
	u_int8_t byte2;
	u_int8_t unused[2];
	u_int8_t start_track;
	u_int8_t start_index;
	u_int8_t unused1;
	u_int8_t end_track;
	u_int8_t end_index;
	u_int8_t control;
};

struct scsi_play_10
{
	u_int8_t op_code;
	u_int8_t byte2;
	u_int8_t blk_addr[4];
	u_int8_t unused;
	u_int8_t xfer_len[2];
	u_int8_t control;
};

struct scsi_play_12
{
	u_int8_t op_code;
	u_int8_t byte2;	/* same as above */
	u_int8_t blk_addr[4];
	u_int8_t xfer_len[4];
	u_int8_t unused;
	u_int8_t control;
};

struct scsi_play_rel_12
{
	u_int8_t op_code;
	u_int8_t byte2;	/* same as above */
	u_int8_t blk_addr[4];
	u_int8_t xfer_len[4];
	u_int8_t track;
	u_int8_t control;
};

struct scsi_read_header
{
	u_int8_t op_code;
	u_int8_t byte2;
	u_int8_t blk_addr[4];
	u_int8_t unused;
	u_int8_t data_len[2];
	u_int8_t control;
};

struct scsi_read_subchannel
{
	u_int8_t op_code;
	u_int8_t byte1;
	u_int8_t byte2;
#define	SRS_SUBQ	0x40
	u_int8_t subchan_format;
	u_int8_t unused[2];
	u_int8_t track;
	u_int8_t data_len[2];
	u_int8_t control;
};

struct scsi_read_toc
{
	u_int8_t op_code;
	u_int8_t byte2;
	u_int8_t unused[4];
	u_int8_t from_track;
	u_int8_t data_len[2];
	u_int8_t control;
};

struct scsi_read_cd_capacity
{
	u_int8_t op_code;
	u_int8_t byte2;
	u_int8_t addr_3;	/* Most Significant */
	u_int8_t addr_2;
	u_int8_t addr_1;
	u_int8_t addr_0;	/* Least Significant */
	u_int8_t unused[3];
	u_int8_t control;
};

struct scsi_set_speed
{
	u_int8_t opcode;
	u_int8_t byte2;
	u_int8_t readspeed[2];
	u_int8_t writespeed[2];
	u_int8_t reserved[5];
	u_int8_t control;
};

struct scsi_report_key 
{
	u_int8_t opcode;
	u_int8_t reserved0;
	u_int8_t lba[4];
	u_int8_t reserved1[2];
	u_int8_t alloc_len[2];
	u_int8_t agid_keyformat;
#define RK_KF_AGID_MASK		0xc0
#define RK_KF_AGID_SHIFT	6
#define RK_KF_KEYFORMAT_MASK	0x3f
#define RK_KF_AGID		0x00
#define RK_KF_CHALLENGE		0x01
#define RF_KF_KEY1		0x02
#define RK_KF_KEY2		0x03
#define RF_KF_TITLE		0x04
#define RF_KF_ASF		0x05
#define RK_KF_RPC_SET		0x06
#define RF_KF_RPC_REPORT	0x08
#define RF_KF_INV_AGID		0x3f
	u_int8_t control;
};

/*
 * See the report key structure for key format and AGID definitions.
 */
struct scsi_send_key
{
	u_int8_t opcode;
	u_int8_t reserved[7];
	u_int8_t param_len[2];
	u_int8_t agid_keyformat;
	u_int8_t control;
};

struct scsi_read_dvd_structure
{
	u_int8_t opcode;
	u_int8_t reserved;
	u_int8_t address[4];
	u_int8_t layer_number;
	u_int8_t format;
#define RDS_FORMAT_PHYSICAL		0x00
#define RDS_FORMAT_COPYRIGHT		0x01
#define RDS_FORMAT_DISC_KEY		0x02
#define RDS_FORMAT_BCA			0x03
#define RDS_FORMAT_MANUFACTURER		0x04
#define RDS_FORMAT_CMGS_CPM		0x05
#define RDS_FORMAT_PROT_DISCID		0x06
#define RDS_FORMAT_DISC_KEY_BLOCK	0x07
#define RDS_FORMAT_DDS			0x08
#define RDS_FORMAT_DVDRAM_MEDIA_STAT	0x09
#define RDS_FORMAT_SPARE_AREA		0x0a
#define RDS_FORMAT_RMD_BORDEROUT	0x0c
#define RDS_FORMAT_RMD			0x0d
#define RDS_FORMAT_LEADIN		0x0e
#define RDS_FORMAT_DISC_ID		0x0f
#define RDS_FORMAT_DCB			0x30
#define RDS_FORMAT_WRITE_PROT		0xc0
#define RDS_FORMAT_STRUCTURE_LIST	0xff
	u_int8_t alloc_len[2];
	u_int8_t agid;
	u_int8_t control;
};

/*
 * Opcodes
 */
#define READ_CD_CAPACITY	0x25	/* slightly different from disk */
#define READ_SUBCHANNEL		0x42	/* cdrom read Subchannel */
#define READ_TOC		0x43	/* cdrom read TOC */
#define READ_HEADER		0x44	/* cdrom read header */
#define PLAY_10			0x45	/* cdrom play  'play audio' mode */
#define PLAY_MSF		0x47	/* cdrom play Min,Sec,Frames mode */
#define PLAY_TRACK		0x48	/* cdrom play track/index mode */
#define PLAY_TRACK_REL		0x49	/* cdrom play track/index mode */
#define PAUSE			0x4b	/* cdrom pause in 'play audio' mode */
#define SEND_KEY		0xa3	/* dvd send key command */
#define REPORT_KEY		0xa4	/* dvd report key command */
#define PLAY_12			0xa5	/* cdrom pause in 'play audio' mode */
#define PLAY_TRACK_REL_BIG	0xa9	/* cdrom play track/index mode */
#define READ_DVD_STRUCTURE	0xad	/* read dvd structure */
#define SET_CD_SPEED		0xbb	/* set c/dvd speed */

struct scsi_report_key_data_header
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
};

struct scsi_report_key_data_agid
{
	u_int8_t data_len[2];
	u_int8_t reserved[5];
	u_int8_t agid;
#define RKD_AGID_MASK	0xc0
#define RKD_AGID_SHIFT	6
};

struct scsi_report_key_data_challenge
{
	u_int8_t data_len[2];
	u_int8_t reserved0[2];
	u_int8_t challenge_key[10];
	u_int8_t reserved1[2];
};

struct scsi_report_key_data_key1_key2
{
	u_int8_t data_len[2];
	u_int8_t reserved0[2];
	u_int8_t key1[5];
	u_int8_t reserved1[3];
};

struct scsi_report_key_data_title
{
	u_int8_t data_len[2];
	u_int8_t reserved0[2];
	u_int8_t byte0;
#define RKD_TITLE_CPM		0x80
#define RKD_TITLE_CPM_SHIFT	7
#define RKD_TITLE_CP_SEC	0x40
#define RKD_TITLE_CP_SEC_SHIFT	6
#define RKD_TITLE_CMGS_MASK	0x30
#define RKD_TITLE_CMGS_SHIFT	4
#define RKD_TITLE_CMGS_NO_RST	0x00
#define RKD_TITLE_CMGS_RSVD	0x10
#define RKD_TITLE_CMGS_1_GEN	0x20
#define RKD_TITLE_CMGS_NO_COPY	0x30
	u_int8_t title_key[5];
	u_int8_t reserved1[2];
};

struct scsi_report_key_data_asf
{
	u_int8_t data_len[2];
	u_int8_t reserved[5];
	u_int8_t success;
#define RKD_ASF_SUCCESS	0x01
};

struct scsi_report_key_data_rpc
{
	u_int8_t data_len[2];
	u_int8_t rpc_scheme0;
#define RKD_RPC_SCHEME_UNKNOWN		0x00
#define RKD_RPC_SCHEME_PHASE_II		0x01
	u_int8_t reserved0;
	u_int8_t byte4;
#define RKD_RPC_TYPE_MASK		0xC0
#define RKD_RPC_TYPE_SHIFT		6
#define RKD_RPC_TYPE_NONE		0x00
#define RKD_RPC_TYPE_SET		0x40
#define RKD_RPC_TYPE_LAST_CHANCE	0x80
#define RKD_RPC_TYPE_PERM		0xC0
#define RKD_RPC_VENDOR_RESET_MASK	0x38
#define RKD_RPC_VENDOR_RESET_SHIFT	3
#define RKD_RPC_USER_RESET_MASK		0x07
#define RKD_RPC_USER_RESET_SHIFT	0
	u_int8_t region_mask;
	u_int8_t rpc_scheme1;
	u_int8_t reserved1;
};

struct scsi_send_key_data_rpc
{
	u_int8_t data_len[2];
	u_int8_t reserved0[2];
	u_int8_t region_code;
	u_int8_t reserved1[3];
};

/*
 * Common header for the return data from the READ DVD STRUCTURE command.
 */
struct scsi_read_dvd_struct_data_header
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
};

struct scsi_read_dvd_struct_data_layer_desc
{
	u_int8_t book_type_version;
#define RDSD_BOOK_TYPE_DVD_ROM	0x00
#define RDSD_BOOK_TYPE_DVD_RAM	0x10
#define RDSD_BOOK_TYPE_DVD_R	0x20
#define RDSD_BOOK_TYPE_DVD_RW	0x30
#define RDSD_BOOK_TYPE_DVD_PRW	0x90
#define RDSD_BOOK_TYPE_MASK	0xf0
#define RDSD_BOOK_TYPE_SHIFT	4
#define RDSD_BOOK_VERSION_MASK	0x0f
	/*
	 * The lower 4 bits of this field is referred to as the "minimum
	 * rate" field in MMC2, and the "maximum rate" field in MMC3.  Ugh.
	 */
	u_int8_t disc_size_max_rate;
#define RDSD_DISC_SIZE_120MM	0x00
#define RDSD_DISC_SIZE_80MM	0x10
#define RDSD_DISC_SIZE_MASK	0xf0
#define RDSD_DISC_SIZE_SHIFT	4
#define RDSD_MAX_RATE_0252	0x00
#define RDSD_MAX_RATE_0504	0x01
#define RDSD_MAX_RATE_1008	0x02
#define RDSD_MAX_RATE_NOT_SPEC	0x0f
#define RDSD_MAX_RATE_MASK	0x0f
	u_int8_t layer_info;
#define RDSD_NUM_LAYERS_MASK	0x60
#define RDSD_NUM_LAYERS_SHIFT	5
#define RDSD_NL_ONE_LAYER	0x00
#define RDSD_NL_TWO_LAYERS	0x20
#define RDSD_TRACK_PATH_MASK	0x10
#define RDSD_TRACK_PATH_SHIFT	4
#define RDSD_TP_PTP		0x00
#define RDSD_TP_OTP		0x10
#define RDSD_LAYER_TYPE_RO	0x01
#define RDSD_LAYER_TYPE_RECORD	0x02
#define RDSD_LAYER_TYPE_RW	0x04
#define RDSD_LAYER_TYPE_MASK	0x0f
	u_int8_t density;
#define RDSD_LIN_DENSITY_0267		0x00
#define RDSD_LIN_DENSITY_0293		0x10
#define RDSD_LIN_DENSITY_0409_0435	0x20
#define RDSD_LIN_DENSITY_0280_0291	0x40
/* XXX MMC2 uses 0.176um/bit instead of 0.353 as in MMC3 */
#define RDSD_LIN_DENSITY_0353		0x80
#define RDSD_LIN_DENSITY_MASK		0xf0
#define RDSD_LIN_DENSITY_SHIFT		4
#define RDSD_TRACK_DENSITY_074		0x00
#define RDSD_TRACK_DENSITY_080		0x01
#define RDSD_TRACK_DENSITY_0615		0x02
#define RDSD_TRACK_DENSITY_MASK		0x0f
	u_int8_t zeros0;
	u_int8_t main_data_start[3];
#define RDSD_MAIN_DATA_START_DVD_RO	0x30000
#define RDSD_MAIN_DATA_START_DVD_RW	0x31000
	u_int8_t zeros1;
	u_int8_t main_data_end[3];
	u_int8_t zeros2;
	u_int8_t end_sector_layer0[3];
	u_int8_t bca;
#define RDSD_BCA	0x80
#define RDSD_BCA_MASK	0x80
#define RDSD_BCA_SHIFT	7
	u_int8_t media_specific[2031];
};

struct scsi_read_dvd_struct_data_physical
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
	struct scsi_read_dvd_struct_data_layer_desc layer_desc;
};

struct scsi_read_dvd_struct_data_copyright
{
	u_int8_t data_len[2];
	u_int8_t reserved0[2];
	u_int8_t cps_type;
#define RDSD_CPS_NOT_PRESENT	0x00
#define RDSD_CPS_DATA_EXISTS	0x01
	u_int8_t region_info;
	u_int8_t reserved1[2];
};

struct scsi_read_dvd_struct_data_disc_key
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
	u_int8_t disc_key[2048];
};

struct scsi_read_dvd_struct_data_bca
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
	u_int8_t bca_info[188]; /* XXX 12-188 bytes */
};

struct scsi_read_dvd_struct_data_manufacturer
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
	u_int8_t manuf_info[2048];
};

struct scsi_read_dvd_struct_data_copy_manage
{
	u_int8_t data_len[2];
	u_int8_t reserved0[2];
	u_int8_t byte4;
#define RDSD_CPM_NO_COPYRIGHT	0x00
#define RDSD_CPM_HAS_COPYRIGHT	0x80
#define RDSD_CPM_MASK		0x80
#define RDSD_CMGS_COPY_ALLOWED	0x00
#define RDSD_CMGS_ONE_COPY	0x20
#define RDSD_CMGS_NO_COPIES	0x30
#define RDSD_CMGS_MASK		0x30
	u_int8_t reserved1[3];
};

struct scsi_read_dvd_struct_data_prot_discid
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
	u_int8_t prot_discid_data[16];
};

struct scsi_read_dvd_struct_data_disc_key_blk
{
	/*
	 * Length is 0x6ffe == 28670 for CPRM, 0x3002 == 12990 for CSS2.
	 */
	u_int8_t data_len[2];
	u_int8_t reserved;
	u_int8_t total_packs;
	u_int8_t disc_key_pack_data[28668];
};
struct scsi_read_dvd_struct_data_dds
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
	u_int8_t dds_info[2048];
};

struct scsi_read_dvd_struct_data_medium_status
{
	u_int8_t data_len[2];
	u_int8_t reserved0[2];
	u_int8_t byte4;
#define RDSD_MS_CARTRIDGE	0x80
#define RDSD_MS_OUT		0x40
#define RDSD_MS_MSWI		0x08
#define RDSD_MS_CWP		0x04
#define RDSD_MS_PWP		0x02
	u_int8_t disc_type_id;
#define RDSD_DT_NEED_CARTRIDGE	0x00
#define RDSD_DT_NO_CART_NEEDED	0x01
	u_int8_t reserved1;
	u_int8_t ram_swi_info;
#define RDSD_SWI_NO_BARE	0x01
#define RDSD_SWI_UNSPEC		0xff
};

struct scsi_read_dvd_struct_data_spare_area
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
	u_int8_t unused_primary[4];
	u_int8_t unused_supl[4];
	u_int8_t allocated_supl[4];
};

struct scsi_read_dvd_struct_data_rmd_borderout
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
	u_int8_t rmd[30720]; 	/* maximum is 30720 bytes */
};

struct scsi_read_dvd_struct_data_rmd
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
	u_int8_t last_sector_num[4];
	u_int8_t rmd_bytes[32768];  /* This is the maximum */
};

/*
 * XXX KDM this is the MMC2 version of the structure.
 * The variable positions have changed (in a semi-conflicting way) in the
 * MMC3 spec, although the overall length of the structure is the same.
 */
struct scsi_read_dvd_struct_data_leadin
{
	u_int8_t data_len[2];
	u_int8_t reserved0[2];
	u_int8_t field_id_1;
	u_int8_t app_code;
	u_int8_t disc_physical_data;
	u_int8_t last_addr[3];
	u_int8_t reserved1[2];
	u_int8_t field_id_2;
	u_int8_t rwp;
	u_int8_t rwp_wavelength;
	u_int8_t optimum_write_strategy;
	u_int8_t reserved2[4];
	u_int8_t field_id_3;
	u_int8_t manuf_id_17_12[6];
	u_int8_t reserved3;
	u_int8_t field_id_4;
	u_int8_t manuf_id_11_6[6];
	u_int8_t reserved4;
	u_int8_t field_id_5;
	u_int8_t manuf_id_5_0[6];
	u_int8_t reserved5[25];
};

struct scsi_read_dvd_struct_data_disc_id
{
	u_int8_t data_len[2];
	u_int8_t reserved[4];
	u_int8_t random_num[2];
	u_int8_t year[4];
	u_int8_t month[2];
	u_int8_t day[2];
	u_int8_t hour[2];
	u_int8_t minute[2];
	u_int8_t second[2];
};

struct scsi_read_dvd_struct_data_generic_dcb
{
	u_int8_t content_desc[4];
#define SCSI_RCB
	u_int8_t unknown_desc_actions[4];
#define RDSD_ACTION_RECORDING	0x0001
#define RDSD_ACTION_READING	0x0002
#define RDSD_ACTION_FORMAT	0x0004
#define RDSD_ACTION_MODIFY_DCB	0x0008
	u_int8_t vendor_id[32];
	u_int8_t dcb_data[32728];
};

struct scsi_read_dvd_struct_data_dcb
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
	struct scsi_read_dvd_struct_data_generic_dcb dcb;
};

struct read_dvd_struct_write_prot
{
	u_int8_t data_len[2];
	u_int8_t reserved0[2];
	u_int8_t write_prot_status;
#define RDSD_WPS_MSWI		0x08
#define RDSD_WPS_CWP		0x04
#define RDSD_WPS_PWP		0x02
#define RDSD_WPS_SWPP		0x01
	u_int8_t reserved[3];
};

struct read_dvd_struct_list_entry
{
	u_int8_t format_code;
	u_int8_t sds_rds;
#define RDSD_SDS_NOT_WRITEABLE	0x00
#define RDSD_SDS_WRITEABLE	0x80
#define RDSD_SDS_MASK		0x80
#define RDSD_RDS_NOT_READABLE	0x00
#define RDSD_RDS_READABLE	0x40
#define RDSD_RDS_MASK		0x40
	u_int8_t struct_len[2];
};

struct read_dvd_struct_data_list
{
	u_int8_t data_len[2];
	u_int8_t reserved[2];
	struct read_dvd_struct_list_entry entries[0];
};

struct scsi_read_cd_cap_data
{
	u_int8_t addr_3;	/* Most significant */
	u_int8_t addr_2;
	u_int8_t addr_1;
	u_int8_t addr_0;	/* Least significant */
	u_int8_t length_3;	/* Most significant */
	u_int8_t length_2;
	u_int8_t length_1;
	u_int8_t length_0;	/* Least significant */
};

struct cd_audio_page
{
	u_int8_t page_code;
#define	CD_PAGE_CODE		0x3F
#define	AUDIO_PAGE		0x0e
#define	CD_PAGE_PS		0x80
	u_int8_t param_len;
	u_int8_t flags;
#define	CD_PA_SOTC		0x02
#define	CD_PA_IMMED		0x04
	u_int8_t unused[2];
	u_int8_t format_lba;
#define	CD_PA_FORMAT_LBA	0x0F
#define	CD_PA_APR_VALID		0x80
	u_int8_t lb_per_sec[2];
	struct	port_control
	{
		u_int8_t channels;
#define	CHANNEL			0x0F
#define	CHANNEL_0		1
#define	CHANNEL_1		2
#define	CHANNEL_2		4
#define	CHANNEL_3		8
#define	LEFT_CHANNEL		CHANNEL_0
#define	RIGHT_CHANNEL		CHANNEL_1
		u_int8_t volume;
	} port[4];
#define	LEFT_PORT		0
#define	RIGHT_PORT		1
};

union cd_pages
{
	struct cd_audio_page audio;
};

struct cd_mode_data_10
{
	struct scsi_mode_header_10 header;
	struct scsi_mode_blk_desc  blk_desc;
	union cd_pages page;
};

struct cd_mode_data
{
	struct scsi_mode_header_6 header;
	struct scsi_mode_blk_desc blk_desc;
	union cd_pages page;
};

union cd_mode_data_6_10
{
	struct cd_mode_data mode_data_6;
	struct cd_mode_data_10 mode_data_10;
};

struct cd_mode_params
{
	STAILQ_ENTRY(cd_mode_params)	links;
	int				cdb_size;
	int				alloc_len;
	u_int8_t			*mode_buf;
};

__BEGIN_DECLS
void scsi_report_key(struct ccb_scsiio *csio, u_int32_t retries,
		     void (*cbfcnp)(struct cam_periph *, union ccb *),
		     u_int8_t tag_action, u_int32_t lba, u_int8_t agid,
		     u_int8_t key_format, u_int8_t *data_ptr,
		     u_int32_t dxfer_len, u_int8_t sense_len,
		     u_int32_t timeout);

void scsi_send_key(struct ccb_scsiio *csio, u_int32_t retries,
		   void (*cbfcnp)(struct cam_periph *, union ccb *),
		   u_int8_t tag_action, u_int8_t agid, u_int8_t key_format,
		   u_int8_t *data_ptr, u_int32_t dxfer_len, u_int8_t sense_len,
		   u_int32_t timeout);

void scsi_read_dvd_structure(struct ccb_scsiio *csio, u_int32_t retries,
			     void (*cbfcnp)(struct cam_periph *, union ccb *),
			     u_int8_t tag_action, u_int32_t address,
			     u_int8_t layer_number, u_int8_t format,
			     u_int8_t agid, u_int8_t *data_ptr,
			     u_int32_t dxfer_len, u_int8_t sense_len,
			     u_int32_t timeout);

__END_DECLS

#endif /*_SCSI_SCSI_CD_H*/

