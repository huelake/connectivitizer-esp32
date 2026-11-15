#!/bin/sh
# Builds the library for this PC (Linux, macOS): host/build/cz_host
set -e
cd "$(dirname "$0")"
mkdir -p build
CC=${CC:-cc}
FLAGS="-std=c11 -O2 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE"
for source in ../src/vendor/monocypher.c ../src/vendor/uECC.c ../src/vendor/ikcp.c; do
  # The vendored sources are compiled as their authors publish them; their warnings are not ours to fix.
  $CC $FLAGS -w -c "$source" -o "build/$(basename "$source" .c).o"
done
$CC $FLAGS -Wall -Wextra -Wno-unused-parameter -o build/cz_host cz_host.c ../src/cz_*.c ../src/port/*.c build/monocypher.o build/uECC.o build/ikcp.o -lpthread
echo "built host/build/cz_host"
