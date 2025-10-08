pkglib_LTLIBRARIES = omotlp.la

omotlp_la_SOURCES = \
       omotlp.c \
       otlp_json.c

noinst_HEADERS = \
       otlp_json.h

omotlp_la_CPPFLAGS = \
       -I$(srcdir) \
       -I$(top_srcdir) \
       -I$(top_srcdir)/runtime \
       -I$(top_srcdir)/grammar \
       $(RSRT_CFLAGS) \
        $(OMOTLP_HTTP_CFLAGS)

omotlp_la_LDFLAGS = -module -avoid-version $(OMOTLP_HTTP_LIBS)

EXTRA_DIST = \
        AGENTS.md \
        MODULE_METADATA.yaml
