
AC_INIT([libfcrypt],[0.0],[github.com/collinfunk/libfcrypt])
AC_PREREQ([2.71])


AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# cc, ranlib, ar
AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR

# inline functions
AC_C_INLINE

# Don't build test executables by default.
AC_ARG_ENABLE([build-tests],
	      [ --enable-build-tests Build test executables],
	      [ case "${enableval}" in
	       yes) build_tests=true ;;
	       no) build_tests=false ;;
	       *) AC_MSG_ERROR([bad value ${enableval}
				for --enable-build-tests]) ;;
				esac], [build_tests=false])
AM_CONDITIONAL([BUILD_TESTS], [test x$build_tests = xtrue])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

