#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([firmador], [0.1.0], [https://github.com/fdelapena/firmador/issues],[firmador],[https://fran.cr/firmador])

AM_INIT_AUTOMAKE([1.11.4 foreign subdir-objects -Wall -Werror])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([src/firmador.cpp])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
PKG_PROG_PKG_CONFIG

# Checks for libraries.
PKG_CHECK_MODULES([GNUTLS],[gnutls])
PKG_CHECK_MODULES([MICROHTTPD],[libmicrohttpd])

AM_OPTIONS_WXCONFIG
reqwx=2.8.12
AM_PATH_WXCONFIG($reqwx, wxWin=1)
AS_IF([test "$wxWin" != 1], [
	AC_MSG_ERROR([
		wxWidgets must be installed on your system.
 
		Please check that wx-config is in path, the directory
		where wxWidgets libraries are installed (returned by
		'wx-config --libs' or 'wx-config --static --libs' command)
		is in LD_LIBRARY_PATH or equivalent variable and
		wxWidgets version is $reqwx or above.
		])
])


# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([getpass])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
