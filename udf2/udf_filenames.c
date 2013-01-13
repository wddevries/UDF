/*-
 * Copyright (c) 2012 Will DeVries
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
#include <sys/malloc.h>
#include <sys/iconv.h>
#include <sys/systm.h>

#include "ecma167-udf.h"
#include "udf.h"
#include "udf_subr.h"

extern struct iconv_functions *udf2_iconv;

static int
udf_to_utf8(char **result, size_t *rrem, uint32_t ch) 
{
	int n = 0;
	char *rp = *result;

	if ((ch & 0xFFFFFF80) == 0) {
		if (*rrem < 1)
			return (0);

		n = 1;
		rp[0] = ch & 0x7F;
	} else if ((ch & 0xFFFFF800) == 0) {
		if (*rrem < 2)
			return (0);

		n = 2;
		rp[0] = 0xC0 | (ch >> 6);
		rp[1] = 0x80 | (0x3F & ch);
	} else if ((ch & 0xFFFF0000) == 0) {
		if (*rrem < 3)
			return (0);

		n = 3;
		rp[0] = 0xE0 | (ch >> 12);
		rp[1] = 0x80 | (0x3F & (ch >> 6));
		rp[2] = 0x80 | (0x3F & ch);
	} else if ((ch & 0xFFE00000) == 0) {
		if (*rrem < 4)
			return (0);

		n = 4;
		rp[0] = 0xF0 | (ch >> 18);
		rp[1] = 0x80 | (0x3F & (ch >> 12));
		rp[2] = 0x80 | (0x3F & (ch >> 6));
		rp[3] = 0x80 | (0x3F & ch);
	} else {
		/* do not convert points above 21 bits. */
		return (0);
	}

	*rrem -= n;
	*result += n;
	return (n);
}

static void 
udf_convert_str(struct udf_mount *ump, char *result, int *result_len,
    uint8_t *id, int id_len, uint16_t *index, int *needsCRC, int *extloc, 
    int eightbit) 
{
	size_t chrem, rrem;
	int endi, i, invalid;
	uint32_t uch;
	char ch[2], *rp;
	const char *chp;

	if (eightbit)
		endi = id_len;
	else
		endi = (id_len - 1 > 0) ? id_len - 1 : 0;

	*extloc = 0;
	*needsCRC = 0;
	invalid = 0;
	rp = result;
	rrem = *result_len - 1; /* for the null */
	for (i = 0; i < endi;) { 
		if (eightbit) {
			uch = id[i];
			if (index)
				index[i] = *result_len - 1 - rrem; 
		} else {
			uch = id[i] << 8 | id[i+1];
			if (index)
				index[i/2] = *result_len - 1 - rrem; 
		}

		//id[i] starts at this place in result

		if (rrem == 0) {
			/* no more space, we need to truncate it. */
			*needsCRC = 1;	
		} else if (uch == 0 || uch == 0x2F) {
			/* do not allow nulls or slashes */
			invalid++;
		} else if (ump->flags & UDFMNT_KICONV && udf2_iconv) {
			/* it might be a valid character */
			chrem = 2;
			chp = ch;
			ch[0] = uch >> 8;
			ch[1] = uch & 0x00FF;
			udf2_iconv->convchr(ump->iconv_d2l, &chp, &chrem, &rp,
			    &rrem);
			if (chrem > 0) {
				/* not printable or doesn't fit */
				invalid++;
				*needsCRC = 1;
			} else
				invalid = 0;
		} else {
			/* utf8 output */
			/* it is a valid character */
			if (udf_to_utf8(&rp, &rrem, uch) == 0) {
				/* doesn't fit or too large */
				invalid++;
				*needsCRC = 1;
			} else
				invalid = 0;
		}

		if (uch == 0x002E && i != 1) {
			/* record locations of periods where they occur within
			5 char of the end, but not at the end or start */
			if (eightbit && id_len - 6 < i && i + 1 != endi)
				*extloc = i;
			else if (!eightbit && id_len - 12 < i && i + 2 != endi)
				*extloc = i;
		}

		if (rrem > 0 && invalid == 1) {
			uch = 0x5F; // underscore

			/* if the result doesn't have space this may not fit */
			if (ump->flags & UDFMNT_KICONV && udf2_iconv) {
				chrem = 2;
				chp = ch;
				ch[0] = uch >> 8;
				ch[1] = uch & 0x00FF;
				udf2_iconv->convchr(ump->iconv_d2l, &chp,
				    &chrem, &rp, &rrem); 
			} else
				udf_to_utf8(&rp, &rrem, uch);

			invalid++;
		}

		if (eightbit)
			i++;
		else
			i += 2;
	}

	// this is the null placement
	if (index) {
		if (eightbit)
			index[i] = *result_len - 1 - rrem; 
		else
			index[i/2] = *result_len - 1 - rrem; 
	}

	*rp = '\0';
	*result_len -= rrem;
}

/*
 * The result_len is assumed to include the zero.
 * id_len - 1 is character, not \0.
 */
void
udf_to_unix_name(struct udf_mount *ump, char *result, int result_len, 
    uint8_t *id, int id_len)
{
	int crclen, eightbit, extlen, extloc, i, junkloc, mainlen, maxmainlen;
	int maxnpart, needsCRC;
	uint16_t crcsum, *index;
	char *crc, crcbuf[6], *ext;

	if (id[0] != 8 && id[0] != 16) {
		/* this is either invalid or an empty string */
		result_len = 0;
		return;
	} 

	if (id[0] == 8)
		eightbit = 1;
	else 
		eightbit = 0;
	
	/* remove marker byte from start of string */
	id++;
	id_len--;

	index = malloc((id_len + 1) * sizeof(uint16_t), M_UDFTEMP, M_WAITOK);

	mainlen = result_len;
	udf_convert_str(ump, result, &mainlen, id, id_len, index, &needsCRC,
	    &extloc, eightbit);

	if (needsCRC) {
		if (extloc) {
			//build ext
			ext = malloc(result_len, M_UDFTEMP, M_WAITOK | M_ZERO);
			extlen = result_len;
			udf_convert_str(ump, ext, &extlen, id + extloc, 
			    id_len - extloc, NULL, &needsCRC, &junkloc,
			    eightbit);
		} else {
			ext = NULL;
			extlen = 1;
		}
		
		crcsum = udf_cksum(id, id_len);
		crcbuf[0] = '#';
		crcbuf[1] = "0123456789ABCDEF"[(crcsum >> 12) & 0x000F];
		crcbuf[2] = "0123456789ABCDEF"[(crcsum >> 8) & 0x000F];
		crcbuf[3] = "0123456789ABCDEF"[(crcsum >> 4) & 0x000F];
		crcbuf[4] = "0123456789ABCDEF"[crcsum & 0x000F];
		crcbuf[5] = '\0';

		crc = malloc(result_len, M_UDFTEMP, M_WAITOK | M_ZERO);
		crclen = result_len;
		udf_convert_str(ump, crc, &crclen, crcbuf, 5, NULL, &needsCRC,
		    &junkloc, 1);

		// find index of last character to be written into filename.
		maxnpart = result_len - crclen - extlen - 3;
		if (extloc)
			maxmainlen = (eightbit) ? extloc : extloc / 2;
		else 
			maxmainlen = (eightbit) ? id_len : id_len / 2;

		for (i = 0; i < maxmainlen; i++)
			if (index[i + 1] - 1 > maxnpart)
				break;
		i--;

		memcpy(result + index[i + 1], crc, crclen - 1);
		if (ext)
			memcpy(result + index[i + 1] + crclen - 1, ext, extlen);
		result[index[i + 1] + crclen + extlen - 2] = '\0';

		if (ext)
			free(ext, M_UDFTEMP);
		free(crc, M_UDFTEMP);
	}

	free(index, M_UDFTEMP);
}
