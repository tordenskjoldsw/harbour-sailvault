#!/usr/bin/env bash
# Builds core/examples/kdf_benchmark.rs with the target's Rust toolchain and
# runs it on the configured sfdk device.
#
# Usage: tools/run-kdf-benchmark.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
sfdk=${SFDK:-"$HOME/SailfishOS/bin/sfdk"}
triple=aarch64-unknown-linux-gnu
target_dir="$root/rust-target"
binary="$target_dir/$triple/release/examples/kdf_benchmark"
remote=/tmp/sailvault-kdf-benchmark

cd "$root"
log="$target_dir/kdf-benchmark-build.log"
# build-shell hangs when stdin is open or when cargo writes through it, so
# stdin is closed and the cargo output goes to a log file.
if ! "$sfdk" build-shell sh -c "CARGO_HOME='$root/cargo-home' cargo build --release --offline \
    --manifest-path core/Cargo.toml --target $triple --target-dir '$target_dir' \
    --example kdf_benchmark > '$log' 2>&1" < /dev/null > /dev/null 2>&1; then
    tail -20 "$log" >&2
    exit 1
fi
tail -1 "$log"

# sfdk device exec has no file transfer, so the binary is streamed over stdin.
"$sfdk" device exec -- sh -c "cat > $remote && chmod 700 $remote" < "$binary"
"$sfdk" device exec -- sh -c "$remote; status=\$?; rm -f $remote; exit \$status"
