pkglib_LTLIBRARIES = omotlp.la

omotlp_la_SOURCES = omotlp.c

# Optional gRPC bridge support
if ENABLE_OMOTLP_GRPC
omotlp_la_SOURCES += grpc_bridge.cc
omotlp_la_CPPFLAGS = $(RSRT_CFLAGS) $(PTHREADS_CFLAGS) $(CURL_CFLAGS) $(JSON_CFLAGS) -DENABLE_OMOTLP_GRPC -fvisibility=hidden -std=c++17
omotlp_la_LDFLAGS = -module -avoid-version
omotlp_la_LIBADD = $(CURL_LIBS) $(JSON_LIBS) $(ZLIB_LIBS) -lopentelemetry_logs -lopentelemetry_exporter_otlp_grpc_logs -lgrpc++ -lprotobuf -labsl_base -labsl_strings
else
omotlp_la_CPPFLAGS = $(RSRT_CFLAGS) $(PTHREADS_CFLAGS) $(CURL_CFLAGS) $(JSON_CFLAGS)
omotlp_la_LDFLAGS = -module -avoid-version
omotlp_la_LIBADD = $(CURL_LIBS) $(JSON_LIBS) $(ZLIB_LIBS)
endif

EXTRA_DIST = grpc_bridge.h