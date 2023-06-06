
AC_INIT([libfcrypt], [0.0], [https://github.com/collinfunk/libfcrypt])
AC_PREREQ([2.69])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign])
LT_INIT

# Disable automake spam by default if possible
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC

AC_C_INLINE
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

