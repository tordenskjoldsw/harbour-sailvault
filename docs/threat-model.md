# SailVault threat model

Status: 2026-10-03, Phase 3 (read-only app). Covers the code in this
repository at that state. Phases 4 (write, Bitwarden import) and 5 (Nextcloud
sync) change the model; see "Changes in later phases". Points marked
**unverified** have not been checked on Sailfish OS or the device yet.

## Assets

| Asset | Where it lives |
|-------|----------------|
| Database content (entries, passwords, notes, attachments) | Encrypted in the KDBX file; decrypted only in RAM while unlocked |
| Master password | Typed into the unlock page; never stored |
| Key file | A file the user picks; read into RAM during unlock |
| Clipboard content | The system clipboard, for up to 30 seconds after a copy |
| Last database and key file path | `~/.config/de.tordenskjold/sailvault/settings.ini` (paths only, no secrets) |

## Architecture and trust boundaries

```
QML / JavaScript engine   titles, user names, the one field being shown
        |
C++ bridge (Qt 5.6)       file reading, clipboard, lock state, timers
        |  C API (core/include/sailvault_core.h)
Rust core                 KDBX4 parsing, KDF, decryption, search
```

- The Rust core holds the decrypted database. It parses untrusted input with
  bounds on header size, KDF parameters (AES-KDF up to 1e9 rounds, Argon2 up
  to 2 GiB), payload (256 MiB), decompressed XML (512 MiB), XML depth (128)
  and attachment count. Decrypted buffers and text nodes are zeroized when
  dropped; errors carry no content.
- The C API returns lists with ids, titles, user names and group names. A
  field value crosses the boundary only when the user shows or copies it.
  Every string from the core is zeroized by `sv_string_free`.
- QML never holds the database. It receives what is on screen.
- The app runs in the Sailjail sandbox with the permissions `Documents` and
  `Downloads` and no network permission.

## Attackers and protections

### 1. Lost or stolen phone, app locked or not running

Protected:

- The KDBX file is encrypted with the master password (and key file, if
  used) through the KDF stored in the file. Nothing that unlocks it is
  stored on the device.
- No decrypted data is written to disk. Settings contain only file paths.
- `/home` is LUKS-encrypted on the Jolla Phone (checked on 5.2.0.18), which
  protects the files while the phone is off.

Limits:

- The protection is only as strong as the master password and the KDF
  parameters, which the user chooses in KeePassXC. The app opens weak
  settings without warning.
- A key file stored next to the database in Documents adds no protection
  against someone who has the phone's files.

### 2. Unlocked phone in someone else's hands

Protected:

- Auto-lock after 5 minutes without input and after 1 minute in the
  background (another app or display off); manual lock from the pulley menu
  and the cover. Locking drops and zeroizes the decrypted database.
- Protected fields stay masked until the user chooses "Show".

Limits:

- Within the lock window, everything in the database is accessible.
- Locking on device lock is not implemented: it would need a system D-Bus
  service that the sandbox does not allow. The background rule locks after
  at most 1 minute with the display off.
- Fingerprint unlock is not available to Harbour apps (Phase 1 result), so
  there is no quick re-authentication; the auto-lock timeouts are a
  trade-off between exposure and typing the master password.

### 3. Other apps on the same phone

Protected:

- Sailjail isolates the app's memory and private directories from other
  sandboxed apps.
- The clipboard is cleared 30 seconds after a copy, on lock and on exit,
  but only if it still holds the copied value (compared by SHA-256), so the
  app never clears what another app put there.

Limits:

- During the 30 seconds, any app that can read the clipboard can read the
  copied value. Whether Sailfish OS keeps a clipboard history (for example
  in the keyboard) is **unverified**.
- Apps with the `Documents` or `Downloads` permission can read the KDBX file
  and a key file stored there. The KDBX file is encrypted; the key file is
  not.
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
- KDBX 3.x and unknown formats are rejected with a distinct error.

Limits:

- A file the attacker created with their own credentials opens normally if
  the user knows those credentials; the app cannot tell whose database it is.
- Resource limits stop a hostile file from exhausting the phone, but a file
  inside the limits can still make an unlock slow (for example Argon2 at
  2 GiB).

### 5. Network attacker

Not applicable in Phase 3: the app has no network permission and makes no
network requests.

## Known limits of the implementation

- **QML and Qt strings cannot be wiped.** The master password typed into the
  password field, revealed field values and on-screen titles, user names,
  URLs and notes exist as `QString` in Qt and the JavaScript engine and are
  freed without zeroing. The input method (keyboard) also sees the typed
  password; Silica's `PasswordField` disables prediction and automatic
  capitalization (`Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase`).
- **C++ buffers are wiped on a best-effort basis.** Password and key file
  bytes are overwritten with `explicit_bzero` after use, but Qt's implicit
  sharing can leave copies that are freed without zeroing.
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

## Out of scope

- An attacker with root on the phone, a compromised OS or keyboard, or
  hardware attacks on RAM.
- The security of KeePassXC and of other devices that open the same file.
- Phishing: the app does no autofill and does not check where a password is
  pasted.

## Changes in later phases

- **Phase 4 (write, import):** the app writes the KDBX file (atomic save,
  verification, backups) and needs a random source for seeds, IVs and keys.
  Unencrypted Bitwarden exports are plaintext files on the device until the
  user deletes them.
- **Phase 5 (Nextcloud sync):** adds the `Internet` permission, a network
  attacker (TLS through Qt and the system CA store) and the Nextcloud app
  password, stored in Sailfish Secrets with device-lock protection only
  (Phase 1 result). Nextcloud sees the encrypted file, never its content.

## Reporting

Security issues: open a private report on the repository host. A dedicated
contact is added before the repository goes public.
