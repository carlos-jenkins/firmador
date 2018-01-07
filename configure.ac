#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([firmador], [0.1.0], [https://github.com/fdelapena/firmador/issues],
	[firmador], [https://fran.cr/firmador])

AM_INIT_AUTOMAKE([1.11.4 foreign subdir-objects -Wall -Werror])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([src/firmador.cpp])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
m4_ifdef([PKG_PROG_PKG_CONFIG], [PKG_PROG_PKG_CONFIG],
	[AC_MSG_ERROR([pkg-config not found.])])

# Checks for libraries.
PKG_CHECK_MODULES([GNUTLS], [gnutls])
PKG_CHECK_MODULES([MICROHTTPD], [libmicrohttpd])
m4_ifdef([AM_OPTIONS_WXCONFIG], [AM_OPTIONS_WXCONFIG],
	[AC_MSG_ERROR([wxWidgets not found.])])
AM_PATH_WXCONFIG([2.8.12], [wxWin=1])
AS_IF([test "$wxWin" != 1], [AC_MSG_ERROR([wx-config not found.])])
AS_CASE([$host], [*-mingw*], [AC_SUBST([MINGW_LIBS], ["-lws2_32"])])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
