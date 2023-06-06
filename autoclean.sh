#!/bin/sh

if [ -f Makefile ] ; then
  make distclean
fi

rm -f aclocal.m4
rm -f build-aux/compile
rm -f build-aux/config.guess
rm -f build-aux/config.sub
rm -f build-aux/depcomp
rm -f build-aux/install-sh
rm -f build-aux/ltmain.sh
rm -f build-aux/missing
rm -f build-aux/test-driver
rm -f config.h.in
rm -f configure
rm -f m4/libtool.m4
rm -f m4/ltoptions.m4
rm -f m4/ltsugar.m4
rm -f m4/ltversion.m4
rm -f m4/lt~obsolete.m4
rm -f config.h
rm -f config.status
rm -f libtool
rm -f stamp-h1
