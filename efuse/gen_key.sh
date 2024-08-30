#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <key_filename>"
  exit 1
fi

. ~/esp/esp-idf/export.sh

openssl rand -out $1 32