AC_DEFUN([RS_ENABLE_OMOTLP], [
    omotlp_have_deps=no

    if test "x$enable_omotlp" != "xno"; then
        PKG_CHECK_MODULES([OMOTLP_HTTP], [libcurl libfastjson], [omotlp_have_deps=yes], [omotlp_have_deps=no])

        if test "x$omotlp_have_deps" = "xyes"; then
            if test "x$enable_omotlp" = "xauto"; then
                enable_omotlp=yes
            fi
        else
            if test "x$enable_omotlp" = "xyes"; then
                AC_MSG_ERROR([--enable-omotlp was given, but libcurl and libfastjson were not found])
            fi
            enable_omotlp=no
        fi
    fi

    AS_IF([test "x$omotlp_have_deps" != "xyes"], [
        OMOTLP_HTTP_CFLAGS=""
        OMOTLP_HTTP_LIBS=""
    ], [
        OMOTLP_HTTP_LIBS="$OMOTLP_HTTP_LIBS $ZLIB_LIBS"
    ])

    AC_SUBST([OMOTLP_HTTP_CFLAGS])
    AC_SUBST([OMOTLP_HTTP_LIBS])
])
