# KDBX test databases

Made-up content from `tools/kdbx-fixtures/content.xml`, written by KeePassXC
as the reference implementation. No real secrets.

- Password for all files: `sailvault-fixture`
- Key file for `*-keyfile.kdbx`: `fixture.keyx` (KeePassXC XML key file v2.0)

## Generated with keepassxc-cli

`tools/gen-kdbx-fixtures.sh` creates these. `keepassxc-cli` always writes
KDBX 3.1 with AES-KDF and AES-256.

| File | Format | KDF | Cipher | Key file |
|------|--------|-----|--------|----------|
| `kdbx31-aeskdf.kdbx` | KDBX 3.1 | AES-KDF | AES-256 | no |
| `kdbx31-aeskdf-keyfile.kdbx` | KDBX 3.1 | AES-KDF | AES-256 | yes |

## Made in the KeePassXC GUI

KeePassXC 2.7.12. For each row: open the source file, then **Database >
Database Settings > Security > Encryption Settings**, switch to **Advanced
Settings**, set the values, click **OK**, then **Database > Save Database
As** with the file name from the table. Argon2: 2 iterations, 8 MiB memory,
2 threads. AES-KDF: 10000 transform rounds.

| File | Source | Format | KDF | Cipher |
|------|--------|--------|-----|--------|
| `kdbx4-aes-argon2d.kdbx` | `kdbx31-aeskdf.kdbx` | KDBX 4.0 | Argon2d | AES 256-bit |
| `kdbx4-chacha20-argon2id.kdbx` | `kdbx31-aeskdf.kdbx` | KDBX 4.0 | Argon2id | ChaCha20 256-bit |
| `kdbx4-twofish-aeskdf.kdbx` | `kdbx31-aeskdf.kdbx` | KDBX 4.0 | AES-KDF | Twofish 256-bit |
| `kdbx4-aes-argon2d-keyfile.kdbx` | `kdbx31-aeskdf-keyfile.kdbx` | KDBX 4.0 | Argon2d | AES 256-bit |
