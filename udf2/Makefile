# $FreeBSD: src/sys/modules/udf/Makefile,v 1.5 2004/01/13 11:28:50 ru Exp $

.PATH: ${.CURDIR}

KMOD=	udf2

SRCS=	udf_readwrite.c udf_subr.c udf_allocation.c \
	udf_osta.c udf_vfsops.c udf_vnops.c udf_filenames.c
#	udf_strat_bootstrap.c udf_strat_direct.c udf_strat_rmw.c udf_strat_sequential.c
SRCS+=	vnode_if.h
EXPORT_SYMS=	udf_iconv

.include <bsd.kmod.mk>
