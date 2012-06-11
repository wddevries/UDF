/*
 * Prototypes for the OSTA functions
 */


#ifndef _FS_UDF_OSTA_H_
#define _FS_UDF_OSTA_H_

#include <sys/types.h>

unsigned short udf_cksum(unsigned char *, int);
#if 0
unsigned short udf_unicode_cksum(unsigned short *, int);
#endif
uint16_t udf_ea_cksum(uint8_t *data);

#endif /* _FS_UDF_OSTA_H_ */
