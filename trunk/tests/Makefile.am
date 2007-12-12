## Process this file with automake to produce Makefile.in
# Copyright © 2002  Networks Associates Technology, Inc.
# All rights reserved.
# $Id: Makefile.am,v 1.11 2003/10/27 19:47:40 dougk Exp $

CFLAGS = -W -Wall -O2 -g
CPPFLAGS = -I../src

noinst_PROGRAMS = myecho myecho2 mycat mycat2 myexec myrerun mypopen 	\
		  microb myecho6					\
		@CHECK_USER@

EXTRA_PROGRAMS = check_user

myecho_SOURCES = myecho.c

myecho2_SOURCES = myecho2.c

myecho6_SOURCES = myecho6.c

mycat_SOURCES = mycat.c

check_user_SOURCES = check_user.c

myexec_SOURCES = myexec.c

myrerun_SOURCES = myrerun.c

mypopen_SOURCES = mypopen.c

microb_SOURCES = microb.c

LDADD = ../src/libprivman.la
#LDADD = -lprivman
#LDFLAGS = -L../src

MAINTAINERCLEANFILES = Makefile.in
