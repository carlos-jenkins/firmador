EXTRA_DIST = README.md firmador.exe.manifest

bin_PROGRAMS = firmador

firmador_SOURCES = \
	src/base64.cpp \
	src/base64.h \
	src/firmador.cpp \
	src/firmador.h \
	src/pin.cpp \
	src/pin.h

firmador_CXXFLAGS = \
	-Wall -Wextra -pedantic -Wno-unused-local-typedefs \
	-I$(srcdir)/src \
	$(GNUTLS_CFLAGS) \
	$(MICROHTTPD_CFLAGS) \
	$(WX_CFLAGS)

firmador_LDADD = \
	$(GNUTLS_LIBS) \
	$(MICROHTTPD_LIBS) \
	$(WX_LIBS) \
	$(MINGW_LIBS)
