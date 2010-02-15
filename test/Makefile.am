## Process this file with automake to produce Makefile.in.
##

include $(top_srcdir)/Makefile.common


TESTS =						\
	main.sh


EXTRA_DIST =					\
	main.sh


check_PROGRAMS =				\
	main


check_LTLIBRARIES =				\
	libshared.la				\
	module.la				\
	module2.la				\
	probe1.la				\
	probe2.la				\
	probe3.la


AM_DEFAULT_SOURCE_EXT = .c


main_SOURCES =					\
	main.cpp				\
	file.c


main_LDADD =					\
	libshared.la				\
	../src/libxprobes.la			\
	$(LIBADD_DLOPEN)


libshared_la_SOURCES =				\
	libshared.c				\
	libshared2.c


libshared_la_LIBADD =				\
	../src/libxprobes.la


libshared_la_LDFLAGS =				\
	-shared -rpath $(PWD)


module_la_LIBADD =				\
	../src/libxprobes.la


module_la_LDFLAGS =				\
	-module -shared -rpath $(PWD)


module2_la_LDFLAGS =				\
	-module -shared -rpath $(PWD)


probe1_la_LDFLAGS =				\
	-module -shared -rpath $(PWD)


probe2_la_SOURCES =				\
	probe2.cpp				\
	probe.c


probe2_la_LDFLAGS =				\
	-module -shared -rpath $(PWD)


probe3_la_LDFLAGS =				\
	-module -shared -rpath $(PWD)
