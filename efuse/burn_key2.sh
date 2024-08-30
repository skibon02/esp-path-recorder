#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <port_suffix> <device_number>"
  exit 1
fi

. ~/esp/esp-idf/export.sh

PORT="/dev/tty$1"
KEY_FILENAME="dev$2_key2_soft_hmac.bin"
echo "Burning key $KEY_FILENAME for device $2 on port $PORT"
espefuse.py burn_key --chip esp32c6 --port $PORT BLOCK_KEY2 $KEY_FILENAME HMAC_UP
