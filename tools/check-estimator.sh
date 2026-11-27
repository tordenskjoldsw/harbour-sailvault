#!/bin/sh
# Checks the vendored strength estimator for memory errors. Run it whenever
# third_party/zxcvbn or src/estimator.c changes (security review 2026-11,
# condition C5).
#
# 1. Walks the generated dictionary and checks every index the estimator
#    can form against its table.
# 2. Fuzzes the estimator, built as the app builds it, under
#    AddressSanitizer and UndefinedBehaviorSanitizer. Needs clang.
#
# Usage: tools/check-estimator.sh [seconds]   # fuzzing time, default 120
set -eu

seconds=${1:-120}
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cc -O2 -I"$root/third_party/zxcvbn" -o "$work/tables" "$root/tools/check-zxcvbn-tables.c"
"$work/tables"

clang -O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
    -I"$root/src" -I"$root/third_party/zxcvbn" -o "$work/fuzz" \
    "$root/tools/fuzz-estimator.c" "$root/src/estimator.c" -lm

mkdir "$work/corpus"
index=0
for seed in 'password' 'correct horse battery staple' 'Tr0ub4dor&3' '1986-04-26 qwertyuiop' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' 'P@ssw0rd!zxcvbnm,./1234567890' '121212121212121212'; do
    index=$((index + 1))
    printf '%s' "$seed" > "$work/corpus/$index"
done
# A slow input is no memory error: the estimator needs up to seconds for
# number-pad neighbours, so the fuzzer's own time limit stays high.
(cd "$work" && ./fuzz -max_total_time="$seconds" -max_len=1024 -timeout=120 \
    -print_final_stats=1 corpus > fuzz.log 2>&1) || {
    tail -40 "$work/fuzz.log"
    cp "$work"/crash-* "$work"/leak-* "$work"/oom-* "$root/" 2>/dev/null || true
    echo "The fuzzer found a problem; its input is in $root." >&2
    exit 1
}
grep -E 'Done [0-9]+ runs|stat::number_of_executed_units' "$work/fuzz.log" | head -1
echo "No memory error found."
