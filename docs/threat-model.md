# SailVault threat model

Status: 2026-10-04, Phase 5 (the app creates, edits, moves and deletes
entries, imports Bitwarden exports, merges copies of the database and
syncs with Nextcloud), after the security review fixes
(`docs/security-review-2026-10.md`), with databases and key files kept in
the app's private storage. Covers the code in this repository at that
state.
Points marked **unverified** have not been checked on Sailfish OS or the
device yet.

## Assets

| Asset | Where it lives |
|-------|----------------|
| Database content (entries, passwords, notes, attachments) | Encrypted in the KDBX file; decrypted only in RAM while unlocked |
| Master password | Typed into the unlock page; never stored |
| Database file | `~/.local/share/de.tordenskjold/sailvault/databases/<name>.kdbx`, owner-only permissions |
| Key file | `~/.local/share/de.tordenskjold/sailvault/keyfiles/<name>.key`, unencrypted, owner-only permissions; read into RAM during unlock |
| Clipboard content | The system clipboard, for up to 30 seconds after a copy |
| Backups | `~/.local/share/de.tordenskjold/sailvault/backups/`: the three newest versions the app replaced, encrypted like the database |
| Name of the last database, ETag and file digest of the last sync | `~/.config/de.tordenskjold/sailvault/settings.ini` (no secrets) |
| Nextcloud app password, server, login name, path, pinned certificate | The entry "Nextcloud sync (SailVault)" of the database, encrypted like every entry; in RAM while a sync runs, also in Qt buffers that cannot be wiped |
| Copy of the database on Nextcloud | The user's Nextcloud, encrypted like the database |
| Copies the user saves, originals not yet deleted | Documents or Downloads, encrypted like the database; key files unencrypted |

## Architecture and trust boundaries

```
QML / JavaScript engine   titles, user names, the one field being shown
        |
C++ bridge (Qt 5.6)       file reading and writing, backups, clipboard, lock state, timers
        |  C API (core/include/sailvault_core.h)
Rust core                 KDBX4 parsing and writing, KDF, encryption, search
```

- The Rust core holds the decrypted database. It parses untrusted input with
  bounds on header size, KDF parameters (AES-KDF up to 1e9 rounds; Argon2 up
  to 1 GiB, 1000 iterations and 64 GiB of memory times iterations), payload
  (256 MiB), decompressed XML (512 MiB), XML depth (128), attributes per
  element (64) and attachment count. The header hash is checked before the
  KDF runs. Decrypted buffers, text nodes, cipher states (AES, ChaCha20,
  Twofish) and the Argon2 working memory are zeroized when dropped; the
  keystream for protected values is dropped right after parsing; errors
  carry no content.
- The core writes the same tree it parsed. Each save draws a fresh master
  seed, encryption IV, KDF seed and inner stream key from `getrandom(2)`,
  the core's only system call, so the KDF runs again and the composite key
  stays in the core while the database is unlocked. The serialized file is
  decrypted and compared with the model before it leaves the core.
- The C API returns lists with ids, titles, user names and group names. A
  field value crosses the boundary only when the user shows or copies it.
  New entries cross it once, on the way in. Every string from the core is
  zeroized by `sv_string_free`.
- QML never holds the database. It receives what is on screen.
- The app runs in the Sailjail sandbox with the permissions `Documents`,
  `Downloads` and `Internet`. Only the sync uses the network.

## Attackers and protections

### 1. Lost or stolen phone, app locked or not running

Protected:

- The KDBX file is encrypted with the master password (and key file, if
  used) through the KDF stored in the file. Nothing that unlocks it is
  stored on the device.
- No decrypted data is written to disk. Settings contain only the name of
  the last database.
  A save writes the encrypted file to a new temporary file next to the
  database (created exclusively, never through a symlink, and read back
  through the same descriptor) and renames it over the original; the
  previous file goes to the backups, encrypted as it was. A version another
  program had written is kept as a separate backup outside the rotation.
- `/home` is LUKS-encrypted on the Jolla Phone (checked on 5.2.0.18), which
  protects the files while the phone is off.

Limits:

- The protection is only as strong as the master password and the KDF
  parameters. Databases created in the app use Argon2id with at least 256 MiB
  and 3 iterations and a master password of at least 15 characters; for files
  from KeePassXC the user chose the settings there, and the app opens weak
  settings without warning.
- A key file kept on the phone next to the database adds no protection
  against someone who has the phone's files. It protects a copy of the
  database that leaves the phone without it.
- Backups are protected by the credentials in effect when they were
  written. A later credential change does not re-protect them; deleting
  them on a credential change is planned (`PLAN.md`, section 7).

### 2. Unlocked phone in someone else's hands

Protected:

- Auto-lock after 5 minutes without input and after 1 minute in the
  background (another app or display off); manual lock from the pulley menu
  and the cover. Locking drops and zeroizes the decrypted database.
- The deadlines count time the phone spends asleep (`CLOCK_BOOTTIME`). They
  are checked before every database access, when the app becomes active,
  and every 5 seconds while a deadline is pending, so after the phone wakes
  up the lock happens within 5 seconds. Qt timers alone stop during
  suspend; the Jolla Phone was asleep 48 of 75 hours since boot when this
  was measured.
- Protected fields stay masked until the user chooses "Show". One-time
  password secrets (`otp`, `TOTP Seed`, `TimeOtp-Secret*`,
  `HmacOtp-Secret*`) are masked even when a file stores them unprotected.
- Swiping back to the unlock page locks the database, and open dialogs and
  lists empty on lock.

Limits:

- Within the lock window, everything in the database is accessible.
- Locking on device lock is not implemented: it would need a system D-Bus
  service that the sandbox does not allow. The background rule locks 1
  minute after the display turns off, or within 5 seconds of waking up if
  the phone slept longer.
- Fingerprint unlock is not available to Harbour apps (Phase 1 result), so
  there is no quick re-authentication; the auto-lock timeouts are a
  trade-off between exposure and typing the master password.

### 3. Other apps on the same phone

Protected:

- Sailjail isolates the app's memory and private directories from other
  sandboxed apps. The database and key file live there, so apps with the
  `Documents` or `Downloads` permission can neither read nor replace nor
  delete them. A database from outside the app is added by unlocking it
  once; only then are the database and the key file that opened it copied
  in, and the app offers to delete the originals.
- The clipboard is cleared 30 seconds after a copy (counting sleep time),
  on lock and on exit, but only if it still holds the copied value, so the
  app never clears what another app put there. To compare, the app asks the
  core for the value again and keeps no copy or hash of it. Only before an
  edit, which could change that value, does it keep a copy while the
  clipboard holds the same value, until the clipboard is cleared.

Limits:

- During the 30 seconds, any app that can read the clipboard can read the
  copied value. Clearing works from the background and on exit (tested on
  the Jolla Phone, 5.2.0.18). Whether Sailfish OS keeps a clipboard history
  (for example in the keyboard) is **unverified**.
- Apps with the `Documents` or `Downloads` permission can read a file there:
  an original the user keeps after adding it, or a copy the user saves to
  move it to a computer. A database copy is encrypted; a key file copy is
  not. Deleting a file on flash storage does not erase its blocks.
- Unsandboxed apps (OpenRepos, Chum, `Sandboxing=Disabled`) and the user with
  `devel-su` are not restricted by Sailjail.

### 4. Crafted database or key file

Protected:

- The header SHA-256 and HMAC and the per-block HMAC are checked before any
  decrypted data is used, so a modified file is rejected unless the attacker
  knows the credentials.
- Parsing is done in Rust with the bounds listed above; malformed input
  produces an error, not undefined behavior. `unsafe` code is limited to the
  C API.
- KDBX 3.0 and 3.1 files are read with the same bounds and converted to
  KDBX 4 when they are added; the stored copy has the KDBX 4 protection
  (header and block HMACs, Argon2id). Other versions and unknown formats
  are rejected.

Limits:

- A file the attacker created with their own credentials opens normally if
  the user knows those credentials; the app cannot tell whose database it is.
- KDBX 3 authenticates less while it is read: the header only through the
  SHA-256 in the XML (required for 3.1, checked after decryption), the
  payload only through unkeyed SHA-256 block hashes inside the encryption.
  A modified 3.x file is still rejected or fails to decrypt, but later than
  a KDBX 4 file would be, so more parsing code sees it first.
- Resource limits stop a hostile file from exhausting the phone, but a file
  inside the limits can still make an unlock slow (about a minute at the
  Argon2 work cap). Argon2 memory is reserved fallibly, so a failed
  allocation is an error, not a crash.

### 5. Bitwarden exports

Protected:

- A password-protected export is decrypted in the core with the KDF its
  file names, within bounded parameters; the password is wiped after use
  and a wrong password is reported without decrypting anything.
- The export is read with bounds (32 MiB, nesting limited by the fixed
  structure, at most 32 folder levels) and treated as untrusted input.
  Values are kept in zeroized memory and the import is added in one step.
- After importing an unencrypted export the app offers to delete it once
  the imported entries are saved; it can delete only that file. The import
  checks that the file is still the kind of export the user confirmed, so
  a plain export swapped in for a protected one is refused.
- A later import merges only into entries an import created (UUID and a
  CustomData record), so a crafted export cannot change other entries;
  dates in the future count as the import time.
- Database content and file names are shown as plain text, so markup in an
  imported title cannot change what the app displays.

Limits:

- An unencrypted export is a plaintext file with every password in it.
  Anything that can read Documents or Downloads can read it until it is
  deleted, and deleting it on flash storage does not erase the blocks; the
  LUKS encryption of `/home` protects them while the phone is off.
- Account-restricted exports cannot be imported; the app asks for a
  password-protected export instead.

### 6. Network attacker and the Nextcloud server

Protected:

- Requests go over https only, through Qt and OpenSSL with the certificates
  the system trusts. A self-signed certificate is accepted only after the
  user confirmed its SHA-256 fingerprint, and then only exactly that
  certificate, for the errors a self-signed certificate raises; a changed
  pinned certificate stops the sync with a warning. Certificate errors are
  never ignored otherwise.
- Redirects are not followed, since Qt 5.6 would send the credentials to
  any redirect target; cookies are not kept.
- The app password is sent as Basic auth on each request and never logged.
  The Login Flow v2 poll token, which yields the app password, goes only to
  the server the user entered, and the flow is refused if the server
  points its poll or login address elsewhere.
- Nextcloud only receives the encrypted KDBX file. A downloaded file is
  untrusted input with the reader's bounds, and it is merged only if it
  opens with the credentials of the open database. An older file served
  again merges without removing newer changes.

Limits:

- A Nextcloud app password opens all files of the account, not only the
  database. Anyone who can open the database sees it in the sync entry,
  also in copies on the computer and on the server; it can be revoked in
  Nextcloud.
- The server, its admin or anyone who breaks into it gets the encrypted
  file and can guess master passwords offline; the KDF parameters decide
  the cost. File size and sync times are visible to the server.
- A user who confirms a wrong fingerprint lets an attacker in the middle
  read the app password and the encrypted file.
- The app password exists in Qt buffers during a sync and cannot be wiped
  there, like other Qt strings.
- Deletions from the other copy are applied when the item did not change
  afterwards; a server that serves a file with forged deletion records
  could only do so with the credentials of the database.

## Known limits of the implementation

- **QML and Qt strings cannot be wiped.** The master password typed into the
  password field, revealed field values and on-screen titles, user names,
  URLs and notes exist as `QString` in Qt and the JavaScript engine and are
  freed without zeroing. The input method (keyboard) also sees the typed
  password; Silica's `PasswordField` disables prediction and automatic
  capitalization (`Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase`).
- **C++ buffers are wiped on a best-effort basis.** Key files and exports
  are read with POSIX calls into one exact allocation, without Qt's read
  buffer, and the password bytes have a single owner, the task that uses
  them; both are overwritten with `explicit_bzero` after use. Qt's
  implicit sharing elsewhere can leave copies that are freed without
  zeroing.
- **HMAC and SHA-2 states are not wiped.** The `hmac` and `sha2` crates
  offer no zeroize support; their internal states, derived from key
  material, are freed without zeroing.
- **Compression buffers are not wiped.** `flate2` keeps part of the
  plaintext in internal buffers (its window on unlock, staged output on
  save) that are freed without zeroing. The buffers the core owns are
  zeroized, also when they grow: a growing buffer moves into a larger
  allocation and the old one is wiped.
- **Copies by the compiler.** Keys are derived straight into zeroized
  buffers, but the compiler may still leave copies in registers or stack
  slots that are not wiped.
- **JSON parser buffers are not wiped.** When reading a Bitwarden export,
  `serde_json` copies strings with escape sequences through an internal
  buffer that is freed without zeroing; every value the core keeps is
  zeroized.
- **Memory paging.** The phone swaps to zram (compressed RAM, checked on
  5.2.0.18), not to flash, so swapped pages stay in RAM. The app does not
  lock its memory.
- **Crash dumps.** `kernel.core_pattern` is `|/bin/false` on the Jolla Phone
  (checked on 5.2.0.18), so core dumps are discarded.
- **Screen content.** Revealed values are visible on screen and in
  screenshots the user takes. Whether the app switcher keeps a snapshot of
  the page is **unverified**; the cover itself shows only the lock state.
- **Dependencies.** The core uses established, widely used crates (mostly
  RustCrypto), vendored and pinned; not every crate has a formal audit. The
  `aes` crate is built with `aes_armv8` for hardware AES on aarch64.
- **No TOTP codes.** By design: generating codes from the same database
  would turn two factors into one. `otp` attributes are kept and shown as
  hidden fields.
- **Old values stay in the file.** As in KeePassXC, an edit keeps the
  previous state as a history item (up to `Meta/HistoryMaxItems`, default
  10), and a deleted entry sits in the recycle bin until it is deleted
  there. A changed password therefore remains in the database, encrypted,
  until the history is trimmed or the entry is removed for good. An
  attachment leaves the file once no entry or history item refers to it.
  Backups keep earlier versions until they rotate out.

## Out of scope

- An attacker with root on the phone, a compromised OS or keyboard, or
  hardware attacks on RAM.
- The security of KeePassXC and of other devices that open the same file.
- Phishing: the app does no autofill and does not check where a password is
  pasted.

## Changes in later phases

- None planned at the moment; a quick unlock (Phase 7, opt-in, RAM only)
  would add a section here.

## Reporting

See [SECURITY.md](../SECURITY.md): a private report on GitHub, or email
to sailvault-security@mailbox.org.
