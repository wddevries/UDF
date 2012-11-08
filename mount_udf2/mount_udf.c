/*-
 * Copyright (c) 1992, 1993, 1994
 *      The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2002 Scott Long
 * Copyright (c) 2012 Will DeVries
 *
 * This code is derived from software contributed to Berkeley
 * by Pace Willisson (pace@blitz.com).  The Rock Ridge Extension
 * Support code is derived from software contributed to Berkeley
 * by Atsushi Murai (amurai@spec.co.jp).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sbin/mount_udf/mount_udf.c,v 1.13 2005/06/10 09:51:43 delphij Exp $
 */

/*
 * This is just a rip-off of mount_iso9660.c.  It's been vastly simplified
 * because UDF doesn't take any options at this time.
 */

#include <sys/cdio.h>
#include <sys/file.h>
#include <sys/iconv.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/endian.h>
#include <sys/ioctl.h>
#include <sys/udfio.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>

#include "mntopts.h"
#include "../udf2/udf_mount.h"


struct mntopt mopts[] = {
	MOPT_STDOPTS,
	MOPT_UPDATE,
	MOPT_END
};

static void	get_session_info(char *dev, struct udf_session_info *usi, 
   		    int session_num);
static void	print_session_info(char *dev, int session_num);
static int	set_charset(char **, char **, const char *);
static void	usage(void);

int
main(int argc, char **argv)
{
	struct udf_session_info usi;
	struct iovec iov[24];
	struct passwd *nobody;
	long session_num;
	gid_t gid;
	int ch, i, mntflags, opts, sessioninfo, udf_flags, verbose;
	int nobody_gid, nobody_uid;
	int32_t first_trackblank;
	uid_t uid;
	char *cs_disk, *cs_local, *dev, *dir, *endp, mntpath[MAXPATHLEN];

	session_num = 0;
	sessioninfo = 0;
	gid = 0;
	uid = 0;
	nobody_uid = 1;
	nobody_gid = 1;

	i = mntflags = opts = udf_flags = verbose = 0;
	cs_disk = cs_local = NULL;
	while ((ch = getopt(argc, argv, "C:G:o:ps:U:v")) != -1)
		switch (ch) {
		case 'C':
			if (set_charset(&cs_disk, &cs_local, optarg) == -1)
				err(EX_OSERR, "udf2_iconv");
			udf_flags |= UDFMNT_KICONV;
			break;
		case 'G':
			gid = strtol(optarg, &endp, 10);
			if (optarg == endp || *endp != '\0')
				usage();	
			nobody_gid = 1;
			break;
		case 'o':
			getmntopts(optarg, mopts, &mntflags, &opts);
			break;
		case 'p':
			sessioninfo = 1;	
			break;
		case 's':
			session_num = strtol(optarg, &endp, 10);
			if (optarg == endp || *endp != '\0')
				usage();	
			break;
		case 'U':
			uid = strtol(optarg, &endp, 10);
			if (optarg == endp || *endp != '\0')
				usage();	
			nobody_uid = 1;
			break;
		case 'v':
			verbose++;
			break;
		case '?':
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	if (sessioninfo == 1) {
		if (argc != 1)
			usage();
		print_session_info(argv[0], session_num);
	}

	if (argc != 2)
		usage();

	dev = argv[0];
	dir = argv[1];


	/*
	 * Resolve the mountpoint with realpath(3) and remove unnecessary
	 * slashes from the devicename if there are any.
	 */
	(void)checkpath(dir, mntpath);
	(void)rmslashes(dev, dev);

	/*
	 * Get session info from device
	 */
	get_session_info(dev, &usi, session_num);


	/*
	 * Use nobody for uid and gid if not given above. 
	 */
	if (nobody_gid == 1 || nobody_uid == 1) {
		nobody = getpwnam("nobody");
		if (nobody == NULL)
			errx(EX_USAGE, "There is no entry for 'nobody'. Please "
			    "use the G and U options to specify defaults for "
			    "uid and gid.");
	}
	if (nobody_gid == 1)
		gid = nobody->pw_gid;
	if (nobody_uid == 1)
		uid = nobody->pw_uid;

	/*
	 * UDF file systems are not writeable.
	 */
	mntflags |= MNT_RDONLY;

	iov[i].iov_base = "fstype";
	iov[i++].iov_len = sizeof("fstype");
	iov[i].iov_base = "udf2";
	iov[i].iov_len = strlen(iov[i].iov_base) + 1;
	i++;
	
	iov[i].iov_base = "fspath";
	iov[i++].iov_len = sizeof("fspath");
	iov[i].iov_base = mntpath;
	iov[i++].iov_len = strlen(mntpath) + 1;

	iov[i].iov_base = "from";
	iov[i++].iov_len = sizeof("from");
	iov[i].iov_base = dev;
	iov[i++].iov_len = strlen(dev) + 1;

	iov[i].iov_base = "flags";
	iov[i++].iov_len = sizeof("flags");
	iov[i].iov_base = &udf_flags;
	iov[i++].iov_len = sizeof(udf_flags);

	iov[i].iov_base = "anon_uid";
	iov[i++].iov_len = sizeof("anon_uid");
	iov[i].iov_base = &uid;
	iov[i++].iov_len = sizeof(uid);

	iov[i].iov_base = "anon_gid";
	iov[i++].iov_len = sizeof("anon_gid");
	iov[i].iov_base = &gid;
	iov[i++].iov_len = sizeof(gid);

	iov[i].iov_base = "first_trackblank";
	iov[i++].iov_len = sizeof("first_trackblank");
	iov[i].iov_base = &usi.session_first_track_blank;
	iov[i++].iov_len = sizeof(uint8_t);

	iov[i].iov_base = "session_start_addr";
	iov[i++].iov_len = sizeof("session_start_addr");
	iov[i].iov_base = &usi.session_start_addr;
	iov[i++].iov_len = sizeof(uint32_t);

	iov[i].iov_base = "session_end_addr";
	iov[i++].iov_len = sizeof("session_end_addr");
	iov[i].iov_base = &usi.session_end_addr;
	iov[i++].iov_len = sizeof(uint32_t);

	iov[i].iov_base = "session_last_written";
	iov[i++].iov_len = sizeof("session_last_written");
	iov[i].iov_base = &usi.session_last_written;
	iov[i++].iov_len = sizeof(uint32_t);

	if (udf_flags & UDFMNT_KICONV) {
		iov[i].iov_base = "cs_disk";
		iov[i++].iov_len = sizeof("cs_disk");
		iov[i].iov_base = cs_disk;
		iov[i++].iov_len = strlen(cs_disk) + 1;
		iov[i].iov_base = "cs_local";
		iov[i++].iov_len = sizeof("cs_local");
		iov[i].iov_base = cs_local;
		iov[i++].iov_len = strlen(cs_local) + 1;
	}

	if (nmount(iov, i, mntflags) < 0)
		err(1, "%s", dev);

	exit(0);
}

static int
set_charset(char **cs_disk, char **cs_local, const char *localcs)
{
	int error;

	if (modfind("udf2_iconv") < 0)
		if (kldload("udf2_iconv") < 0 || modfind("udf2_iconv") < 0) {
			warnx("cannot find or load \"udf2_iconv\" kernel"
			    " module");
			return (-1);
		}

	if ((*cs_disk = malloc(ICONV_CSNMAXLEN)) == NULL)
		return (-1);
	if ((*cs_local = malloc(ICONV_CSNMAXLEN)) == NULL)
		return (-1);
	strncpy(*cs_disk, ENCODING_UNICODE, ICONV_CSNMAXLEN);
	strncpy(*cs_local, localcs, ICONV_CSNMAXLEN);
	error = kiconv_add_xlat16_cspairs(*cs_disk, *cs_local);
	if (error != 0)
		return (-1);

	return (0);
}

static void
get_session_info(char *dev, struct udf_session_info *usi, int session_num)
{
	int fd, error;
	unsigned int out;

	fd = open(dev, O_RDONLY, 0);
	if (fd < 0)
		err(1, "open");

	bzero(usi, sizeof(struct udf_session_info));
	usi->session_num = session_num;
	error = ioctl(fd, UDFIOREADSESSIONINFO, usi);
	if (error != 0) {
		if (session_num != 0)
			errx(EX_USAGE, "Cannot mount selected session.  This "
			    "device does not properly support multi-sessions "
			    "disc.");
		
		warnx("Warning, this device does not properly support "
		    "multi-sessions disc.");

		/* We populate the end address inside the kernel. */
		usi->session_start_addr = 0;
		usi->session_end_addr = 0;
	}

	close(fd);
}

static void
print_session_info(char *dev, int session_num) 
{
	struct udf_session_info usi;

	rmslashes(dev, dev);
	get_session_info(dev, &usi, session_num);

	printf("Number of Sessions: %u\n", usi.num_sessions);
	printf("Number of Tracks: %u\n", usi.num_tracks);
	printf("First Track Number: %u\n", usi.first_track);
	printf("Sector Size: %u\n", usi.sector_size);
	
	printf("Session Number: %u\n", usi.session_num);
	printf("Session Start Address: %u\n", usi.session_start_addr);
	printf("Session End Address: %u\n", usi.session_end_addr);
	printf("Last Written Address in Session: %u\n", usi.session_last_written);
	printf("First Track Number of Session: %u\n", usi.session_first_track);
	printf("Last Track of Session: %u\n", usi.session_last_track);

	exit(0);
}

static void
usage(void)
{

	(void)fprintf(stderr, "usage: mount_udf [-v] [-C charset] [-G gid] "
	    "[-o options] [-s session] [-U uid] special node\n");
	(void)fprintf(stderr, "usage: mount_udf [-p] [-s session] special\n");
	exit(EX_USAGE);
}
