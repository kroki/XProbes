## Process this file with automake to produce Makefile.in.
##

include $(top_srcdir)/Makefile.common


noinst_HEADERS =				\
	restart.h				\
	uitoa.h					\
	list.h


noinst_LTLIBRARIES =				\
	libsocket.la


libsocket_la_SOURCES =				\
	socket.c				\
	socket.h


if ENABLE_CONTROL


sbin_PROGRAMS =					\
	xprobes


xprobes_SOURCES =				\
	xprobes.c


xprobes_LDADD =					\
	libsocket.la				\
	$(LIBREADLINE)


endif # ENABLE_CONTROL


nobase_include_HEADERS =			\
	xprobes/site.h				\
	xprobes/probe.h                         \
	xprobes/bits/object.h			\
	xprobes/bits/module.h			\
	xprobes/bits/list_node.h


lib_LTLIBRARIES =				\
	libxprobes.la


libxprobes_la_SOURCES =				\
	libxprobes.c


libxprobes_la_LIBADD =				\
	libsocket.la				\
	$(LIBADD_DLOPEN)


## Here's an excerpt from 'info libtool versioning updating' on when
## and how to update shared library version:
##
##   1. Start with version information of `0:0:0' for each libtool library.
##
##   2. Update the version information only immediately before a public
##      release of your software.  More frequent updates are unnecessary,
##      and only guarantee that the current interface number gets larger
##      faster.
##
##   3. If the library source code has changed at all since the last
##      update, then increment REVISION (`C:R:A' becomes `C:R+1:A').
##
##   4. If any interfaces have been added, removed, or changed since the
##      last update, increment CURRENT, and set REVISION to 0.
##
##   5. If any interfaces have been added since the last public release,
##      then increment AGE.
##
##   6. If any interfaces have been removed since the last public release,
##      then set AGE to 0.

libxprobes_la_LDFLAGS = -version-info 0:0:0
