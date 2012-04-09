

/* Shared between kernel & process */

#ifndef	_SYS_UDFIO_H_
#define	_SYS_UDFIO_H_

#ifndef _KERNEL
#include <sys/types.h>
#endif
#include <sys/ioccom.h>

/*
struct ioc_play_blocks {
	int	blk;
	int	len;
};
#define	CDIOCPLAYBLOCKS	_IOW('c',2,struct ioc_play_blocks)

#define	UDFIOTEST	_IO('c',300)
*/

struct udf_session_info {
	uint32_t session_num;

	uint16_t sector_size;
	uint16_t num_sessions;
	uint32_t session_start_addr;
	uint32_t session_end_addr;

	uint16_t num_tracks;
	uint8_t  first_track;
	uint16_t session_first_track;
	uint16_t session_last_track;
};
#define	UDFIOTEST	_IO('c',300)

#endif /* !_SYS_UDFIO_H_ */
