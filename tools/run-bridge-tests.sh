#!/bin/sh
# Builds and runs the tests of the C++ bridge on the host (tests/bridge):
# the real Vault with the host build of the Rust core and the real strength
# estimator, without a device. Needs cargo and Qt 5 with qmake.
#
# Usage: tools/run-bridge-tests.sh [QtTest arguments]
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
build=$root/build-bridge-tests
qmake=${QMAKE:-$(command -v qmake-qt5 || command -v qmake)}

(cd "$root" && cargo build --release --offline --locked --manifest-path core/Cargo.toml \
    --target-dir "$build/core")
mkdir -p "$build/qt"
cd "$build/qt"
"$qmake" "$root/tests/bridge/bridge-tests.pro" "CORE_LIB=$build/core/release/libsailvault_core.a" \
    > qmake.log 2>&1 || { cat qmake.log >&2; exit 1; }
make -j"$(nproc)" > make.log 2>&1 || { grep -E 'error|Error' -A3 make.log >&2; exit 1; }
./bridge-tests "$@"
