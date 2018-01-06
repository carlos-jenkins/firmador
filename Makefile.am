EXTRA_DIST = README.md firmador.exe.manifest

bin_PROGRAMS = firmador

firmador_SOURCES = \
	src/firmador.cpp \
	src/firmador.h

firmador_CXXFLAGS = \
	-Wall -Wextra -pedantic -Wno-unused-local-typedefs \
	-I$(srcdir)/src \
	$(GNUTLS_CFLAGS) \
	$(MICROHTTPD_CFLAGS) \
	$(WX_CFLAGS)

firmador_LDADD = \
	$(GNUTLS_LIBS) \
	$(MICROHTTPD_LIBS) \
	$(WX_LIBS)
