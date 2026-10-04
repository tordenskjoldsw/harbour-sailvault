# SailVault

A password manager for Sailfish OS that keeps your passwords in a standard
KeePass (KDBX 4) file. No account, no server, no lock-in: the same file
opens in KeePassXC on your computer.

I built SailVault because no sandboxed Sailfish app could write KDBX 4
files, and I wanted my passwords on my phone in a format I control. It is
written for Sailfish OS 5.2 and tested on the Jolla Phone (aarch64).

**Status:** version 0.5.3. Reading, editing, importing, merging and sync
through Nextcloud are done and tested on the device. Next, I will submit it
to the Jolla Store (Harbour).

## Features

- Open KDBX 4.0 and 4.1 databases with a master password, a key file or
  both. Supports AES-256, ChaCha20 and Twofish, and AES-KDF, Argon2d and
  Argon2id.
- Add older KDBX 3.1 databases: SailVault stores them as KDBX 4 with the
  stronger Argon2id key derivation, and KeePassXC opens them as before.
  The original file stays unchanged.
- Create, edit, move and delete entries and groups. Edits keep the previous
  version in the entry history, and deleted items go to the recycle bin,
  both as in KeePassXC.
- View earlier versions of an entry; restore items from the recycle bin.
- Search across titles, user names, URLs, notes and tags.
- Copy a field to the clipboard; SailVault clears it after 30 seconds and
  when the database locks.
- Lock after five minutes without use and after one minute in the
  background.
- Password generator.
- Create a new database with Argon2id at one of three strengths, all
  measured on the Jolla Phone (about 1, 2.5 and 5 seconds to unlock).
- Keep databases and key files in SailVault's private storage, out of
  reach of other apps. Save a copy to Documents or Downloads to open it
  on your computer.
- Import Bitwarden and Vaultwarden JSON exports, unencrypted or
  password-protected. Running the import again with a newer export merges
  the changes instead of creating duplicates.
- Sync with your own Nextcloud: log in through the browser, and SailVault
  keeps the file on the server and on the phone in step, merging changes
  made on both sides the way KeePassXC does. Without a network, it works
  on and syncs later.
- Merge a copy of the database from a file, for example one from your
  computer, without Nextcloud.

SailVault writes back everything it reads, including data it does not
use itself (attachments, custom data, plugin data), so KeePassXC sees the
same database after SailVault has saved it.

## What SailVault does not do

- **No TOTP codes.** Keeping one-time codes next to the passwords turns two
  factors into one. SailVault keeps `otp` fields from KeePassXC intact and
  shows them as hidden fields, but does not generate codes.
- **No fingerprint unlock.** Harbour apps cannot use the fingerprint
  reader, and I won't store anything that unlocks the database without
  your master password.
- **No autofill.** Sailfish OS has no API for it.
- **No Bitwarden sync.** The import reads an export file; SailVault never
  talks to a Bitwarden server.

## Security

SailVault connects to nothing but your own Nextcloud, and only once you set
up sync. It never writes decrypted data to disk and asks for the full master
password every time.

- Decryption, key handling and parsing run in a Rust core that does no
  file or network I/O. Keys and decrypted values are wiped from memory
  when the database locks.
- The UI only gets what it displays: list titles and the one field you
  open.
- Every save goes to a temporary file, is decrypted again to verify it and
  only then replaces the database. The last three versions are kept as
  backups in the app's private directory.
- Databases and key files live in SailVault's private directory, which
  other sandboxed apps cannot read. The sandbox gives SailVault access to
  Documents, Downloads and the internet, and nothing else; it uses them to
  add files, save copies, read imports and sync.
- Sync uses https only. A self-signed server certificate is accepted only
  after you confirmed its fingerprint, and then only that certificate. The
  Nextcloud app password is stored in the database itself, as the entry
  "Nextcloud sync (SailVault)", so the master password protects it; you
  can revoke it in Nextcloud at any time. Nextcloud only ever receives the
  encrypted file.

The [threat model](docs/threat-model.md) explains what SailVault protects
against, what it does not, and the known limits (for example, Qt strings
in the UI cannot be wiped).

Found a vulnerability? Please report it privately, as described in
[SECURITY.md](SECURITY.md), and not as a public issue.

## Install

SailVault is not in the Jolla Store yet. Until it is, build the RPM
yourself (see below) and install it with `sfdk deploy` or `pkcon
install-local`.

## Using a database from KeePassXC

1. Copy the `.kdbx` file, and your key file if you use one, to Documents
   or Downloads on the phone.
2. In SailVault, choose **Add existing database** from the pulley menu,
   pick the file and unlock it. SailVault keeps its own copy and offers to
   delete the originals.
3. To take the database back to your computer, open the list of databases,
   long-press it and choose **Save copy**.

To keep both in step, set up sync with Nextcloud from the pulley menu of
the entry list and open the same file in KeePassXC through the Nextcloud
client on your computer. Without Nextcloud, **Merge with file** brings the
changes of a newer copy from your computer into the phone's database.

## Moving from Bitwarden or Vaultwarden

1. In the Bitwarden web vault, export your vault as **.json** or as
   **.json (Encrypted)** with the **Password protected** option. Exports
   tied to your account cannot be read outside Bitwarden.
2. Copy the file to Documents or Downloads on the phone.
3. Open your database in SailVault and choose **Import** from the pulley
   menu.

The entries land in the group "Bitwarden import", with fields mapped the
same way KeePassXC maps them. An unencrypted export holds all your passwords in
plain text, so SailVault offers to delete it after the import. Details:
[docs/bitwarden-export.md](docs/bitwarden-export.md).

## Building

You need the [Sailfish SDK](https://docs.sailfishos.org/Tools/Sailfish_SDK/)
(tested with 3.13) and its aarch64 build target. The Rust dependencies are
vendored in `core/vendor`, so the build works offline.

```sh
sfdk config --global --push target SailfishOS-5.1.0.11-aarch64
sfdk build
```

The RPM lands in `RPMS/`. To run the Harbour validator on it:

```sh
sfdk -c no-fix-version build
sfdk check RPMS/harbour-sailvault-*.rpm
```

The core tests run on the host and need Rust 1.75 or newer. The writer
tests open the saved files with `keepassxc-cli`, so install KeePassXC first:

```sh
cargo test --manifest-path core/Cargo.toml
```

## How it is built

```
core/   Rust: KDBX 4 codec, crypto, merge, import, search. C API, no I/O.
src/    C++ (Qt 5.6): file access, list models, clipboard, auto-lock.
qml/    Silica user interface.
docs/   Threat model, security review, Bitwarden export format.
tools/  Fixture generators, measurement scripts, license notice generator.
```

Test databases in `core/tests/fixtures` hold fake data only and are made
with `keepassxc-cli` or the KeePassXC GUI. Their password is
`sailvault-fixture`.

## Contributing

Bug reports and ideas are welcome as
[issues](https://github.com/tordenskjoldsw/harbour-sailvault/issues). If you
plan a pull request, open an issue first so we can agree on the approach.
Please never attach a real database or a real export, not even an encrypted
one.

## License

[MIT](LICENSE). The licenses of the bundled Rust crates are listed on the
About page in the app.

SailVault is an independent project and not affiliated with KeePass,
KeePassXC, Bitwarden or Jolla.
