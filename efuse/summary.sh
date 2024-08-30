#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <port_suffix>"
  exit 1
fi

. ~/esp/esp-idf/export.sh

PORT="/dev/tty$1"
espefuse.py --chip esp32c6 summary --port $PORT
