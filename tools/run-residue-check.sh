#!/usr/bin/env bash
# Builds tools/residue-check.c with the target's compiler and runs it on the
# configured sfdk device. Fails when rating passwords the way the password
# report does leaves fragments of them in memory.
#
# Usage: tools/run-residue-check.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
sfdk=${SFDK:-"$HOME/SailfishOS/bin/sfdk"}
build_dir="$root/build-benchmark"
binary="$build_dir/residue-check"
remote=/tmp/sailvault-residue-check

cd "$root"
mkdir -p "$build_dir"
log="$build_dir/residue-check-build.log"
# build-shell hangs when stdin is open, so stdin is closed and the compiler
# output goes to a log file.
if ! "$sfdk" build-shell sh -c "gcc -O2 -Isrc -Ithird_party/zxcvbn -o '$binary' \
    tools/residue-check.c src/estimator.c src/wipedstack.c -lm -lpthread > '$log' 2>&1" \
    < /dev/null > /dev/null 2>&1; then
    tail -20 "$log" >&2
    exit 1
fi

# sfdk device exec has no file transfer, so the binary is streamed over stdin.
"$sfdk" device exec -- sh -c "cat > $remote && chmod 700 $remote" < "$binary"
"$sfdk" device exec -- "$remote"
