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
#include <grp.h>

#include "mntopts.h"

struct mntopt mopts[] = {
	MOPT_STDOPTS,
	MOPT_UPDATE,
	MOPT_END
};

static void	get_session_info(char *dev, struct udf_session_info *usi, 
   		    int session_num);
static void	print_session_info(char *dev, int session_num);
static int	set_charset(char *, const char *);
static void	usage(void);
static int	get_uid(char *u, uid_t *uid);
static int	get_gid(char *g, gid_t *gid);
static int	get_mode(char *m, mode_t *mode);

int
main(int argc, char **argv)
{
	struct udf_session_info usi;
	struct iovec *iov;
	struct passwd *nobody;
	long session_num;
	gid_t anon_gid, override_gid;
	int iovlen, ch, mntflags, opts, sessioninfo;
	uid_t anon_uid, override_uid;
	mode_t mode, dirmode;
	char cs_local[ICONV_CSNMAXLEN];
	char *dev, *dir, *endp, mntpath[MAXPATHLEN];
	uint8_t use_nobody_gid, use_nobody_uid;
	uint8_t use_override_gid, use_override_uid;
	uint8_t use_mode, use_dirmode;

	cs_local[0] = '\0';
	session_num = 0;
	sessioninfo = 0;
	use_nobody_uid = use_nobody_gid = 1;
	use_override_uid = use_override_gid = 0;
	use_mode = use_dirmode = 0;
	iov = NULL;
	iovlen = 0;
	mntflags = opts = 0;

	while ((ch = getopt(argc, argv, "C:G:g:M:m:o:ps:U:u:")) != -1)
		switch (ch) {
		case 'C':
			set_charset(cs_local, optarg);
			break;
		case 'G':
			if (get_gid(optarg, &anon_gid) == -1)
				errx(EX_USAGE, "invalid gid in option G: %s", 
				    optarg);
			use_nobody_gid = 0;
			break;
		case 'g':
			if (get_gid(optarg, &override_gid) == -1)
				errx(EX_USAGE, "invalid gid in option g: %s", 
				    optarg);
			use_override_gid = 1;
			break;
		case 'M':
			if (get_mode(optarg, &dirmode) == -1)
				errx(EX_USAGE, "invalid mode in option M: %s", 
				    optarg);
			use_dirmode = 1;
			break;
		case 'm':
			if (get_mode(optarg, &mode) == -1)
				errx(EX_USAGE, "invalid mode in option m: %s", 
				    optarg);
			use_mode = 1;
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
				errx(EX_USAGE, "invalid number in option s: %s", 
				    optarg);
			break;
		case 'U':
			if (get_uid(optarg, &anon_uid) == -1)
				errx(EX_USAGE, "invalid uid in option U: %s", 
				    optarg);
			use_nobody_uid = 0;
			break;
		case 'u':
			if (get_uid(optarg, &override_uid) == -1)
				errx(EX_USAGE, "invalid uid in option u: %s", 
				    optarg);
			use_override_uid = 1;
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
	if (use_nobody_gid == 1 && use_override_gid == 0) {
		if (get_gid("nobody", &anon_gid) == -1)
			errx(EX_USAGE, "There is no group 'nobody'; use the G "
			    "option to specify a default gid.");
	} else if (use_override_gid == 1)
		anon_gid = override_gid;

	if (use_nobody_uid == 1 && use_override_uid == 0) {
		if (get_uid("nobody", &anon_uid) == -1)
			errx(EX_USAGE, "There is no user 'nobody'; use the U "
			    "option to specify a default uid.");
	} else if (use_override_uid == 1)
		anon_uid = override_uid;

	/* UDF file systems are not writeable. */
	mntflags |= MNT_RDONLY;

	build_iovec(&iov, &iovlen, "fstype", "udf2", (size_t) - 1);
	build_iovec(&iov, &iovlen, "fspath", mntpath, (size_t) - 1);
	build_iovec(&iov, &iovlen, "from", dev, (size_t) - 1);
	build_iovec(&iov, &iovlen, "uid", &anon_uid, sizeof(anon_uid));
	if (use_override_uid == 1)
		build_iovec(&iov, &iovlen, "override_uid", NULL, 0);
	build_iovec(&iov, &iovlen, "gid", &anon_gid, sizeof(anon_gid));
	if (use_override_gid == 1)
		build_iovec(&iov, &iovlen, "override_gid", NULL, 0);
	if (use_mode)
		build_iovec(&iov, &iovlen, "mode", &mode, sizeof(mode_t));
	if (use_dirmode)
		build_iovec(&iov, &iovlen, "dirmode", &dirmode, sizeof(mode_t));

	build_iovec(&iov, &iovlen, "first_trackblank", 
	    &usi.session_first_track_blank, sizeof(uint8_t));
	build_iovec(&iov, &iovlen, "session_start_addr",
	    &usi.session_start_addr, sizeof(uint32_t));
	build_iovec(&iov, &iovlen, "session_end_addr", &usi.session_end_addr, 
	    sizeof(uint32_t));
	build_iovec(&iov, &iovlen, "session_last_written",
	    &usi.session_last_written, sizeof(uint32_t));

	if (cs_local[0] != '\0') {
		build_iovec(&iov, &iovlen, "cs_local", cs_local, (size_t) - 1);
	}

	if (nmount(iov, iovlen, mntflags) < 0)
		err(1, "%s", dev);

	free(iov);
	exit(0);
}

static int
get_uid(char *u, uid_t *uid)
{
	struct passwd *usr;
	char *endp;

	usr = getpwnam(u);
	if (usr != NULL)
		*uid = usr->pw_gid;
	else {
		*uid = strtoul(u, &endp, 10);

		if (u == endp || *endp != '\0')
			return (-1);	
	}

	return (0);
}

static int
get_gid(char *g, gid_t *gid)
{
	struct group *grp;
	char *endp;

	grp = getgrnam(g);
	if (grp != NULL)
		*gid = grp->gr_gid;
	else {
		*gid = strtoul(g, &endp, 10);

		if (g == endp || *endp != '\0')
			return (-1);	
	}

	return (0);
}

static int
get_mode(char *m, mode_t *mode) 
{
	char *endp;

	*mode = strtoul(m, &endp, 8);	
	if (m == endp || *endp != '\0')
		return (-1);	
	return (0);
}

static int
set_charset(char *cs_local, const char *localcs)
{
	int error;

	if (modfind("udf2_iconv") < 0)
		if (kldload("udf2_iconv") < 0 || modfind("udf2_iconv") < 0) {
			errx(EX_OSERR, "cannot find or load \"udf2_iconv\" "
			    "kernel module");
		}

	strncpy(cs_local, localcs, ICONV_CSNMAXLEN);
	error = kiconv_add_xlat16_cspairs(ENCODING_UNICODE, cs_local);
	if (error != 0)
		err(EX_OSERR, "udf2_iconv");

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

		/* Other fatal errors besides EIO and ENXIO may exist, but 
		trying to mount an invalid device shouldn't result in anything 
		to bad. */ 
		if (errno == EIO)
			errx(EX_IOERR, "Device not ready.");
		else if (errno == ENXIO)
			errx(EX_IOERR, "No media present.");
		else
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
