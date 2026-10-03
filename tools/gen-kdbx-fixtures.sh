#!/usr/bin/env bash
# Creates the KeePassXC-made test databases in core/tests/fixtures from
# tools/kdbx-fixtures/content.xml.
#
# keepassxc-cli import writes AES-KDF with AES-256. KeePassXC picks the format
# from the content: CustomData forces KDBX 4.0, without it the file stays
# KDBX 3.1. The other KDBX 4 variants are made in the KeePassXC GUI as
# described in core/tests/fixtures/README.md.
#
# Usage: tools/gen-kdbx-fixtures.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
content="$root/tools/kdbx-fixtures/content.xml"
fixtures="$root/core/tests/fixtures"
password="sailvault-fixture"
key_file="$fixtures/fixture.keyx"
# The lowest decryption time keepassxc-cli accepts keeps the test suite fast;
# production KDF costs are measured on the device.
decryption_time_ms=100

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python3 - "$content" "$work/content-kdbx31.xml" <<'EOF'
import re
import sys

content = open(sys.argv[1], encoding="utf-8").read()
open(sys.argv[2], "w", encoding="utf-8").write(
    re.sub(r"\s*<CustomData>.*?</CustomData>", "", content, flags=re.S))
EOF

import_database() {
    local xml=$1 target=$2
    shift 2
    rm -f "$fixtures/$target"
    printf '%s\n%s\n' "$password" "$password" |
        keepassxc-cli import -q -p -t "$decryption_time_ms" "$@" \
            "$xml" "$fixtures/$target"
}

assert_version() {
    local target=$1 expected=$2 actual
    actual=$(od -An -tx4 -j8 -N4 "$fixtures/$target" | tr -d ' ')
    if [[ $actual != "$expected" ]]; then
        echo "$target: expected version $expected, got $actual" >&2
        exit 1
    fi
}

mkdir -p "$fixtures"
rm -f "$key_file"

import_database "$work/content-kdbx31.xml" kdbx31-aeskdf.kdbx
import_database "$work/content-kdbx31.xml" kdbx31-aeskdf-keyfile.kdbx --set-key-file "$key_file"
import_database "$content" kdbx4-aes-aeskdf.kdbx
import_database "$content" kdbx4-aes-aeskdf-keyfile.kdbx -k "$key_file"
chmod 644 "$key_file"

assert_version kdbx31-aeskdf.kdbx 00030001
assert_version kdbx31-aeskdf-keyfile.kdbx 00030001
assert_version kdbx4-aes-aeskdf.kdbx 00040000
assert_version kdbx4-aes-aeskdf-keyfile.kdbx 00040000

keepassxc-cli --version
