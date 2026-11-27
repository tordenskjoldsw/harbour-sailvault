#!/usr/bin/env bash
# Builds tools/strength-benchmark.c with the target's compiler and runs it
# on the configured sfdk device.
#
# Usage: tools/run-strength-benchmark.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
sfdk=${SFDK:-"$HOME/SailfishOS/bin/sfdk"}
build_dir="$root/build-benchmark"
binary="$build_dir/strength-benchmark"
remote=/tmp/sailvault-strength-benchmark

cd "$root"
mkdir -p "$build_dir"
log="$build_dir/strength-benchmark-build.log"
# build-shell hangs when stdin is open, so stdin is closed and the compiler
# output goes to a log file.
if ! "$sfdk" build-shell sh -c "gcc -O2 -Ithird_party/zxcvbn -o '$binary' \
    tools/strength-benchmark.c third_party/zxcvbn/zxcvbn.c -lm > '$log' 2>&1" \
    < /dev/null > /dev/null 2>&1; then
    tail -20 "$log" >&2
    exit 1
fi

# sfdk device exec has no file transfer, so the binary is streamed over stdin.
"$sfdk" device exec -- sh -c "cat > $remote && chmod 700 $remote" < "$binary"
"$sfdk" device exec -- sh -c "$remote; status=\$?; rm -f $remote; exit \$status"
