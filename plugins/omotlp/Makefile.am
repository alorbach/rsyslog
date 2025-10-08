pkglib_LTLIBRARIES = omotlp.la

omotlp_la_SOURCES = omotlp.c omotlp.h otlp_json.c omotlp_http.c
omotlp_la_CPPFLAGS = $(RSRT_CFLAGS) $(PTHREADS_CFLAGS) $(CURL_CFLAGS) $(LIBFASTJSON_CFLAGS)
omotlp_la_LDFLAGS = -module -avoid-version
omotlp_la_LIBADD = $(CURL_LIBS) $(LIBFASTJSON_LIBS) $(LIBM)

EXTRA_DIST = MODULE_METADATA.yaml

