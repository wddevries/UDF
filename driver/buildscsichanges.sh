#!/bin/sh

cp -r /shared/freebsd/sys/cam/scsi/scsi_cd.c /usr/src/sys/cam/scsi/
cp -r /shared/freebsd/sys/cam/scsi/scsi_cd.h /usr/src/sys/cam/scsi/
cp -r /shared/UDF/driver/udfio.h /usr/src/sys/sys/
cp -r /shared/UDF/driver/udfio.h /usr/include/sys/
