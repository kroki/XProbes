dnl Process this file with autoconf to produce a configure script.
dnl
dnl To bootstrap run './bootstrap.sh'.
dnl

m4_define([xprobes_copyright],
          [patsubst([
Copyright (C) 2010 Tomash Brechko.  All rights reserved.

libxprobes and corresponding header files are released under LGPLv3+.
xprobes control utility is released under GPLv3+ (it uses libreadline).
Essentially this means that all the functionality is available for
non-(L)GPLd code too.  See <http://www.gnu.org/licenses/> for further
details.

XProbes is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
], [
], [\\n])])

AC_PREREQ(2.63)
m4_include([version.m4])
AC_INIT([Explicit probes], [VERSION_STRING], [tomash.brechko@gmail.com],
        [xprobes])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.9.2 -Wall no-define subdir-objects
                  dist-bzip2 no-dist-gzip color-tests])

AC_PREFIX_DEFAULT([/usr/local])

AC_CONFIG_SRCDIR([src/Makefile.am])

AS_IF([test "`cd $srcdir; pwd`" = "`pwd`"],
      [AC_MSG_ERROR([Building in the source directory is not supported.
                  Create an empty directory, and run configure from there.])])

AC_USE_SYSTEM_EXTENSIONS

LT_INIT([disable-static])
AS_IF([test "x$enable_static" = "xyes"],
      AC_MSG_ERROR([libxprobes can't be build static]))

AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_CC_C99
CC="$CC -pthread"
AC_PROG_CXX

AC_ARG_ENABLE([dlerror],
  [AS_HELP_STRING([--enable-dlerror],
                  [assume dlerror() is thread-safe @<:@default=if found@:>@])],
  [], [enable_dlerror=check])

AC_ARG_ENABLE([dladdr],
  [AS_HELP_STRING([--enable-dladdr],
                  [assume dladdr() may be called from object constructor
                   (i.e. from dlopen()) @<:@default=if found@:>@])],
  [], [enable_dladdr=check])

AC_ARG_ENABLE([control],
  [AS_HELP_STRING([--disable-control],
                  [do not build xprobes control utility
                   @<:@default=build@:>@])],
  [], [enable_control=yes])
AM_CONDITIONAL([ENABLE_CONTROL], [test x"$enable_control" != x"no"])

save_LIBS=$LIBS

LIBADD_DLOPEN=
AC_SEARCH_LIBS([dlopen], [dl], [LIBADD_DLOPEN=$ac_cv_search_dlopen],
               [AC_MSG_ERROR([libxprobes requires dlopen()])])
AC_SUBST([LIBADD_DLOPEN])

LT_FUNC_DLSYM_USCORE

AS_IF([test x"$enable_dlerror" != x"no"],
      [AC_CHECK_FUNCS([dlerror],
        [AC_DEFINE([ENABLE_DLERROR], 1, [dlerror() is thread-safe])],
        [AS_IF([test x"$enable_dlerror" = x"yes"],
               [AC_MSG_ERROR([dlerrro() not found])])])])

AS_IF([test x"$enable_dladdr" != x"no"],
      [AC_CHECK_FUNCS([dladdr],
        [AC_DEFINE([ENABLE_DLADDR], 1,
                   [dladdr() may be called from dlopen()])],
        [AS_IF([test x"$enable_dladdr" = x"yes"],
               [AC_MSG_ERROR([dladdr() not found])])])])

LIBS=$save_LIBS

AM_COND_IF([ENABLE_CONTROL],
  [LIBREADLINE=
   AC_SEARCH_LIBS([readline], [readline], [LIBREADLINE=$ac_cv_search_readline],
                  [AC_MSG_ERROR([xprobes requires libreadline])])
   AC_SUBST([LIBREADLINE])])

LIBS=$save_LIBS

AC_DEFINE([PACKAGE_COPYRIGHT], ["xprobes_copyright"], [Copyright string.])
AC_DEFINE([DEFAULT_SIGNAL], [SIGRTMAX], [Default signal.])
AC_DEFINE([DEFAULT_UNLOAD_DELAY], [60], [Default unload delay (secs).])
AC_DEFINE([ISALIVE_CHAR], ['\b'], [Is-alive char.])

AC_CACHE_SAVE

AC_CONFIG_FILES([
Makefile
src/Makefile
test/Makefile
])
AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])

AC_OUTPUT
