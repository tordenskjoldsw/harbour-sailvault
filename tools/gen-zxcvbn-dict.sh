#!/bin/sh
# Fetches zxcvbn-c at the pinned release and regenerates the vendored copy in
# third_party/zxcvbn: the two source files, the license and dict-src.h, the
# dictionary that upstream's dictgen builds from its word lists.
#
# Usage: tools/gen-zxcvbn-dict.sh          # rewrite the vendored files
#        tools/gen-zxcvbn-dict.sh --check  # fail if they differ
set -eu

REPOSITORY=https://github.com/tsyrogit/zxcvbn-c.git
RELEASE=v2.7
COMMIT=4011582de2ee7885c8f29560f86716829cfdfd44
WORDS="words-eng_wiki.txt words-female.txt words-male.txt words-passwd.txt words-surname.txt words-tv_film.txt"

root=$(cd "$(dirname "$0")/.." && pwd)
vendored=$root/third_party/zxcvbn
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$RELEASE" "$REPOSITORY" "$work/source"
actual=$(git -C "$work/source" rev-parse HEAD)
if [ "$actual" != "$COMMIT" ]; then
    echo "$RELEASE is $actual, expected $COMMIT" >&2
    exit 1
fi

mkdir "$work/out"
c++ -std=c++11 -O2 -o "$work/dictgen" "$work/source/dict-generate.cpp"
# dictgen reads the word lists from the current directory.
(cd "$work/source" && "$work/dictgen" -o "$work/out/dict-src.h" $WORDS)
cp "$work/source/zxcvbn.c" "$work/source/zxcvbn.h" "$work/source/LICENSE.txt" "$work/out/"

if [ "${1:-}" = "--check" ]; then
    for file in dict-src.h zxcvbn.c zxcvbn.h LICENSE.txt; do
        cmp "$work/out/$file" "$vendored/$file"
    done
    exit 0
fi
mkdir -p "$vendored"
cp "$work/out/"* "$vendored/"
