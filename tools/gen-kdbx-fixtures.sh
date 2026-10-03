#!/usr/bin/env bash
# Creates the KeePassXC-made test databases in core/tests/fixtures from
# tools/kdbx-fixtures/content.xml. keepassxc-cli always writes KDBX 3.1 with
# AES-KDF; the KDBX 4 variants are derived from these files in the KeePassXC
# GUI as described in core/tests/fixtures/README.md.
#
# Usage: tools/gen-kdbx-fixtures.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
content="$root/tools/kdbx-fixtures/content.xml"
fixtures="$root/core/tests/fixtures"
password="sailvault-fixture"
# The lowest decryption time keepassxc-cli accepts keeps the test suite fast;
# production KDF costs are measured on the device.
decryption_time_ms=100

mkdir -p "$fixtures"
rm -f "$fixtures/kdbx31-aeskdf.kdbx" "$fixtures/kdbx31-aeskdf-keyfile.kdbx" "$fixtures/fixture.keyx"

printf '%s\n%s\n' "$password" "$password" |
    keepassxc-cli import -q -p -t "$decryption_time_ms" \
        "$content" "$fixtures/kdbx31-aeskdf.kdbx"

printf '%s\n%s\n' "$password" "$password" |
    keepassxc-cli import -q -p -t "$decryption_time_ms" \
        --set-key-file "$fixtures/fixture.keyx" \
        "$content" "$fixtures/kdbx31-aeskdf-keyfile.kdbx"
chmod 644 "$fixtures/fixture.keyx"

keepassxc-cli --version
