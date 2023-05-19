#!/bin/sh

if [ -f Makefile ] ; then
	make distclean
fi

rm -rf autom4te.cache
rm -f Makefile.in
rm -f Makefile
rm -f aclocal.m4
rm -f config.log
rm -f configure
rm -f configure~
rm -f configure.ac~
rm -f compile
rm -f depcomp
rm -f ar-lib
rm -f install-sh
rm -f missing

