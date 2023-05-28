
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(libfcrypt VERSION 0.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)

include(CheckSymbolExists)
include(CheckFunctionExists)

# Safe memzero functions
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
check_function_exists(explicit_memset HAVE_EXPLICIT_MEMSET)
check_function_exists(memset_explicit HAVE_MEMSET_EXPLICIT)

# Configuration file.
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

option(FCRYPT_BUILD_TESTS OFF "Build test executables")

add_library(fcrypt STATIC
	arc4.c
	blake2b.c
	blake2s.c
	blowfish.c
	camellia.c
	chacha.c
	crc32.c
	fcrypt_memzero.c
	md2.c
	md4.c
	md5.c
	rmd128.c
	rmd160.c
	sha1.c
	sha256.c
	sha512.c
	siphash.c
	tiger.c
)

target_include_directories(fcrypt PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/
	${CMAKE_CURRENT_BINARY_DIR}/
)

if (FCRYPT_BUILD_TESTS)
	add_executable(test-arc4 test-arc4.c)
	add_executable(test-blake2b test-blake2b.c)
	add_executable(test-blake2s test-blake2s.c)
	add_executable(test-blowfish test-blowfish.c)
	add_executable(test-chacha test-chacha.c)
	add_executable(test-crc32 test-crc32.c)
	add_executable(test-md2 test-md2.c)
	add_executable(test-md4 test-md4.c)
	add_executable(test-md5 test-md5.c)
	add_executable(test-rmd128 test-rmd128.c)
	add_executable(test-rmd160 test-rmd160.c)
	add_executable(test-sha1 test-sha1.c)
	add_executable(test-sha256 test-sha256.c)
	add_executable(test-sha512 test-sha512.c)
	add_executable(test-siphash test-siphash.c)
	add_executable(test-tiger test-tiger.c)

	target_link_libraries(test-arc4 PRIVATE fcrypt)
	target_link_libraries(test-blake2b PRIVATE fcrypt)
	target_link_libraries(test-blake2s PRIVATE fcrypt)
	target_link_libraries(test-blowfish PRIVATE fcrypt)
	target_link_libraries(test-chacha PRIVATE fcrypt)
	target_link_libraries(test-crc32 PRIVATE fcrypt)
	target_link_libraries(test-md2 PRIVATE fcrypt)
	target_link_libraries(test-md4 PRIVATE fcrypt)
	target_link_libraries(test-md5 PRIVATE fcrypt)
	target_link_libraries(test-rmd128 PRIVATE fcrypt)
	target_link_libraries(test-rmd160 PRIVATE fcrypt)
	target_link_libraries(test-sha1 PRIVATE fcrypt)
	target_link_libraries(test-sha256 PRIVATE fcrypt)
	target_link_libraries(test-sha512 PRIVATE fcrypt)
	target_link_libraries(test-siphash PRIVATE fcrypt)
	target_link_libraries(test-tiger PRIVATE fcrypt)
endif ()

