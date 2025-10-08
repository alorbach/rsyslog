pkglib_LTLIBRARIES = omotlp.la

omotlp_la_SOURCES = omotlp.c
omotlp_la_CPPFLAGS = $(RSRT_CFLAGS) $(PTHREADS_CFLAGS) $(CURL_CFLAGS) $(JSON_CFLAGS)
omotlp_la_LDFLAGS = -module -avoid-version
omotlp_la_LIBADD = $(CURL_LIBS) $(JSON_LIBS) $(ZLIB_LIBS)

EXTRA_DIST =