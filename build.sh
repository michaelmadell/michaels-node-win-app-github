#!/bin/bash

set -e

RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[0;33m'
NC='\e[0m'
msg=""

print_error() {
  echo -e "${RED}[ERROR]\e[0m \e[1;31m${msg}\e[0m"
}

print_success() {
  echo -e "${GREEN}[SUCCESS]\e[0m \e[1;32m${msg}\e[0m"
}

print_info() {
  echo -e "${YELLOW}[INFO]\e[0m \e[1;33m${msg}\e[0m"
}

if [ ! -f "Makefile" ]; then
  msg="Makefile not found in current directory!"
  print_error
  exit 1
fi

msg="Found Makefile"
print_info

msg="Running 'make clean'..."
print_info

echo -e -n '\e[2m'

if make clean; then
  msg="make clean completed successfully"
  print_success
else
  msg="make clean failed with exit code $?"
  print_error
  exit 1
fi

msg="Running 'make'..."
print_info

echo -e -n '\e[2m'

if make; then
msg="make completed successfully"
print_success
msg="Build Process Completed"
print_success
else
  "make failed with exit code $?"
print_error
  exit 1
fi

exit 0
