#!/bin/sh

aclocal -I m4
autoheader
libtoolize --install
automake --add-missing --copy
autoconf

