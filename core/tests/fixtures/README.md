# KDBX test databases

Made-up content from `tools/kdbx-fixtures/content.xml`, written by KeePassXC
as the reference implementation. No real secrets.

- Password for all files: `sailvault-fixture`
- Key file for `*-keyfile.kdbx`: `fixture.keyx` (KeePassXC XML key file v2.0)

## Generated with keepassxc-cli

`tools/gen-kdbx-fixtures.sh` creates these and checks their format version.
`keepassxc-cli import` writes AES-KDF with AES-256; CustomData in the content
forces KDBX 4.0, so the 3.1 files are imported without CustomData.

| File | Format | KDF | Cipher | Key file | Content |
|------|--------|-----|--------|----------|---------|
| `kdbx31-aeskdf.kdbx` | KDBX 3.1 | AES-KDF | AES 256-bit | no | without CustomData |
| `kdbx31-aeskdf-keyfile.kdbx` | KDBX 3.1 | AES-KDF | AES 256-bit | yes | without CustomData |
| `kdbx4-aes-aeskdf.kdbx` | KDBX 4.0 | AES-KDF | AES 256-bit | no | full |
| `kdbx4-aes-aeskdf-keyfile.kdbx` | KDBX 4.0 | AES-KDF | AES 256-bit | yes | full |

## Made in the KeePassXC GUI

KeePassXC 2.7.12 saves after every settings change when "Automatically save
after every change" is on, so each file is edited in place, never with
"Save As":

1. Copy `kdbx4-aes-aeskdf.kdbx` to the target name.
2. Open the copy, then **Database > Database Settings > Security >
   Encryption Settings > Advanced Settings**.
3. Set the values from the table, click **OK**, then **Database > Save
   Database** (Ctrl+S).

Argon2: 2 iterations, 8 MiB memory, 2 threads. AES-KDF: 10000 rounds.

| File | Format | KDF | Cipher |
|------|--------|-----|--------|
| `kdbx4-aes-argon2d.kdbx` | KDBX 4.0 | Argon2d | AES 256-bit |
| `kdbx4-chacha20-argon2id.kdbx` | KDBX 4.0 | Argon2id | ChaCha20 256-bit |
| `kdbx4-twofish-aeskdf.kdbx` | KDBX 4.0 | AES-KDF | Twofish 256-bit |
