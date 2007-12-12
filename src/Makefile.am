## Process this file with automake to produce Makefile.in
# Copyright © 2002  Networks Associates Technology, Inc.
# All rights reserved.
# $Id: Makefile.am,v 1.15 2005/07/01 08:05:52 kilpatds Exp $:

# create a token-defs file.
YFLAGS = -d

# Turn on warnings
CFLAGS =-W -Wshadow -Wall -O0 -g -DCONFIG_PATH="\"@sysconfdir@/@PACKAGE@.d/\""
CXXFLAGS =-W -Wshadow -Wall -O0 -g -DCONFIG_PATH="\"@sysconfdir@/@PACKAGE@.d/\""

lib_LTLIBRARIES = libprivman.la
libprivman_la_SOURCES = config_lex.ll config_parse.yy			\
			privman.cc priv_client.cc msghdr.c
libprivman_la_LDFLAGS = -export-symbols-regex 'priv_' -version-info 2:3:1
#							a-c = major
#							c = minor.
#							b = extra-minor
BUILT_SOURCES = config_lex.cc config_parse.cc config_parse.h
noinst_HEADERS = types.h config_parse.h priv_impl.h
include_HEADERS = msghdr.h privman.h
libprivman_la_LIBADD = @LIBS@ -lstdc++

# Need to create this depenency to force the definitions file to be built
config_lex.ll: config_parse.cc

CLEANFILES = config_parse.cc config_parse.h config_lex.cc
MAINTAINERCLEANFILES = Makefile.in 
