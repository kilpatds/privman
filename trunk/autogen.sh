#! /bin/sh
# Needed for the AM_ macros in config.h
aclocal
autoheader
libtoolize --automake
autoconf
automake --foreign --add-missing
#echo ./configure
