# zxcvbn-c

The password strength estimator KeePassXC uses, so SailVault and KeePassXC
rate a password the same.

- Source: https://github.com/tsyrogit/zxcvbn-c, release v2.7 (commit
  `4011582de2ee7885c8f29560f86716829cfdfd44`), MIT license (`LICENSE.txt`).
- `zxcvbn.c` and `zxcvbn.h` are unchanged copies.
- `dict-src.h` is generated: the dictionary that upstream's `dictgen`
  builds from its word lists. The word lists come from the original zxcvbn
  by Dan Wheeler and Dropbox, MIT license (`LICENSE-wordlists.txt`).

Do not edit these files. `tools/gen-zxcvbn-dict.sh` fetches the pinned
release and rewrites them; with `--check` it fails when they differ.
`tools/check-password-strength.sh` compares the estimates with
`keepassxc-cli estimate`.
