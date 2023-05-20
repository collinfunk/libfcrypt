
AM_CFLAGS = -I$(top_srcdir)/

noinst_LIBRARIES = libfcrypt.a
libfcrypt_a_SOURCES = arc4.c md5.c sha1.c sha256.c sha512.c tiger.c
include_HEADERS = arc4.h bswap.h circularshift.h md5.h sha1.h sha256.h \
		  sha512.h tiger.h

dist_doc_DATA = README LICENSE

# ./configure --build-tests
if BUILD_TESTS
LDADD = libfcrypt.a

noinst_PROGRAMS = test-arc4 test-md5 test-sha1 test-sha256 test-sha512 \
		  test-tiger

test_arc4_SOURCES = test-arc4.c
test_md5_SOURCES = test-md5.c
test_sha1_SOURCES = test-sha1.c
test_sha256_SOURCES = test-sha256.c
test_sha512_SOURCES = test-sha512.c
test_tiger_SOURCES = test-tiger.c

endif

