
AM_CFLAGS = -I$(top_srcdir)/

noinst_LIBRARIES = libfcrypt.a
libfcrypt_a_SOURCES = arc4.c sha1.c sha256.c sha512.c

dist_doc_DATA = README.txt

# Should build these conditionally...
bin_PROGRAMS = test-arc4 test-sha1 test-sha256 test-sha512

LDADD = libfcrypt.a

test_arc4_SOURCES = test-arc4.c
test_sha1_SOURCES = test-sha1.c
test_sha256_SOURCES = test-sha256.c
test_sha512_SOURCES = test-sha512.c

