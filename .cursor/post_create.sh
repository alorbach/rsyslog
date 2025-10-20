#!/bin/bash
# .cursor/post_create.sh

if [ ! -f /tmp/rsyslog_base_env.flag ]; then
  sudo apt-get update -qq
  sudo apt-get install -y autoconf autoconf-archive automake autotools-dev \
    bison flex gcc libcurl4-gnutls-dev libdbi-dev libgcrypt20-dev libglib2.0-dev \
    libgnutls28-dev libtool libtool-bin libzstd-dev make libestr-dev \
    python3-docutils python3-venv libfastjson-dev liblognorm-dev libcurl4-gnutls-dev \
    libaprutil1-dev libcivetweb-dev valgrind clang-format
  touch /tmp/rsyslog_base_env.flag
fi
