
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I$(top_srcdir)
AM_CPPFLAGS = -I$(top_srcdir)

EXTRA_DIST = ALGORITHMS LICENSE README

lib_LTLIBRARIES = libfcrypt.la
libfcrypt_la_SOURCES = aes.c \
		       arc4.c \
		       blake2b.c \
		       blake2s.c \
		       blowfish.c \
		       bswap.h \
		       chacha.c \
		       circularshift.h \
		       crc32.c \
		       fcrypt_memzero.c \
		       has160.c \
		       md2.c \
		       md4.c \
		       md5.c \
		       rmd128.c \
		       rmd160.c \
		       sha1.c \
		       sha256.c \
		       sha512.c \
		       siphash.c \
		       tiger.c

include_HEADERS = aes.h \
		  arc4.h \
		  blake2b.h \
		  blake2s.h \
		  blowfish.h \
		  camellia.h \
		  chacha.h \
		  crc32.h \
		  fcrypt_memzero.h \
		  has160.h \
		  md2.h \
		  md4.h \
		  md5.h \
		  rmd128.h \
		  rmd160.h \
		  sha1.h \
		  sha256.h \
		  sha512.h \
		  siphash.h \
		  tiger.h 

LDADD = libfcrypt.la

TESTS = test-aes \
	test-arc4 \
	test-blake2b \
	test-blake2s \
	test-blowfish \
	test-chacha \
	test-crc32 \
	test-has160 \
	test-md2 \
	test-md4 \
	test-md5 \
	test-rmd128 \
	test-rmd160 \
	test-sha1 \
	test-sha256 \
	test-sha512 \
	test-siphash \
	test-tiger

check_PROGRAMS = $(TESTS)

test_aes_SOURCES = test-aes.c
test_arc4_SOURCES = test-arc4.c
test_blake2b_SOURCES = test-blake2b.c
test_blake2s_SOURCES = test-blake2s.c
test_blowfish_SOURCES = test-blowfish.c
test_chacha_SOURCES = test-chacha.c
test_crc32_SOURCES = test-crc32.c
test_has160_SOURCES = test-has160.c
test_md2_SOURCES = test-md2.c
test_md4_SOURCES = test-md4.c
test_md5_SOURCES = test-md5.c
test_rmd128_SOURCES = test-rmd128.c
test_rmd160_SOURCES = test-rmd160.c
test_sha1_SOURCES = test-sha1.c
test_sha256_SOURCES = test-sha256.c
test_sha512_SOURCES = test-sha512.c
test_siphash_SOURCES = test-siphash.c
test_tiger_SOURCES = test-tiger.c

