#!/bin/sh
# Compares the vendored estimator with KeePassXC: both must report the same
# entropy for every sample password. Needs cc and keepassxc-cli.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat > "$work/estimate.c" <<'SOURCE'
#include <stdio.h>
#include <zxcvbn.h>

int main(int argc, char *argv[])
{
    if (argc != 2)
        return 2;
    printf("%.3f\n", ZxcvbnMatch(argv[1], NULL, NULL));
    return 0;
}
SOURCE
cc -O2 -I"$root/third_party/zxcvbn" -o "$work/estimate" \
    "$work/estimate.c" "$root/third_party/zxcvbn/zxcvbn.c" -lm

failed=0
while IFS= read -r password; do
    ours=$("$work/estimate" "$password")
    theirs=$(printf '%s' "$password" | keepassxc-cli estimate | sed -n 's/.*Entropy \([0-9.]*\).*/\1/p')
    if [ "$ours" = "$theirs" ]; then
        printf 'ok    %8s  %s\n' "$ours" "$password"
    else
        printf 'FAIL  %8s  %8s  %s\n' "$ours" "$theirs" "$password"
        failed=1
    fi
done <<'SAMPLES'
password
passwordpassword
aaaaaaaaaaaaaaa
qwertzuiop1234
Tr0ub4dor&3
sailvault-fixture
correct horse battery staple
Xk9#mQ2$vL7!pR4z
1986-04-26 Tschernobyl
Der Hund läuft über die Straße
zxcvbnm,./zxcvbnm,./
7f3a9c1e5b2d8046af19c37e
SAMPLES
exit $failed
