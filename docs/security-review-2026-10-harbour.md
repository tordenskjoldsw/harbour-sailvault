# Security review before Harbour submission, October 2026

Reviewed state: commit `677c091` (release 0.2.0 plus the About page),
2026-10-03. Scope: the whole app, not only the changes since the
[first review](security-review-2026-10.md): `core/` (KDBX4 reader and
writer, merge, Bitwarden import, C API), `src/` (C++ bridge), `qml/`,
packaging.

Method: two independent security reviews (Rust core; C++ bridge, QML and
packaging) and two code-quality reviews of the same parts. Each read the
sources against the first review's findings, the threat model, the Silica
QML and Qt 5.6 sources of the SDK target and the KeePassXC sources. Every
finding below was re-checked against the code; F1 was reproduced with the
public core API before the fix and is covered by tests now.

Result: no critical or high findings, and no way to read the database
without its credentials. The medium findings are a save that could fail
for a whole session (data loss) and a clipboard value that was never
cleared. All findings are fixed.

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 3 |
| Low | 11 |

## Findings and fixes

| Finding | Fix | Commit |
|---------|-----|--------|
| **M1** Text with a carriage return or a character XML 1.0 forbids (Windows line endings in imported notes) failed the save verification; every save of the session failed, and the import page already offered to delete the export | Carriage returns written as character references; forbidden characters dropped from unprotected text when it enters the model; the export can be deleted only after a successful save | `e75245e`, `1053690` |
| **M2** The clipboard was never cleared once the copied field changed (edit, permanent delete, import) | The guard keeps the copied value before an edit while the clipboard still holds it | `6c03415` |
| **M3** Growing buffers left unwiped copies of the decrypted payload (inner stream key, attachments, XML) | `SecretBuffer` and pre-sized allocations; keys derived in place | `fab4f7e` |
| L1 Deleted attachments stayed in every later save and backup | The pool drops unreferenced attachments, as KeePassXC does on save | `d944463` |
| L2 Groups nested deeper than the reader accepts made every save fail | Nesting limited to 100 levels for new, moved, restored and imported groups | `324ebea` |
| L3 Backup rotation matched other databases' backups and could delete the backup just written | Rotation matches exactly `<name>-<timestamp>.kdbx` | `51ebac6` |
| L4 A file changed by another program survived only in the rotating backups | Its backup is kept outside the rotation | `51ebac6` |
| L5 The unlock page was reachable while unlocked, and the database path could change while unlocked | Returning to the unlock page locks; paths change only while locked | `64a2472` |
| L6 A plain export swapped in for a protected one after inspection was imported without warning | The import checks the export kind of the bytes it reads | `a3264ba` |
| L7 Key files and small exports left a copy in QFile's read buffer; a FIFO under a picked name blocked the reader | POSIX reads into the wiped allocation, regular files only | `7dbbcee` |
| L8 OTP secrets stored unprotected by another client were shown in clear text | Hidden by attribute name | `fd47581` |
| L9 The save completion let a pending import start a second save with the old digest | Result applied before the next save can start | `7f44e21` |
| L10 Password bytes were shared between the caller and the task; one copy could be freed unwiped | The task takes the only copy | `3a663b2`, `a3264ba` |
| L11 The entry dialog and history kept their content after a lock when the page stack could not pop | Both empty on lock | `9d54a92` |

Smaller fixes from the same reviews: a save error stayed on the unlock
page, and a lock that discarded unsaved changes did not say so
(`7f44e21`); the import group name went through translation (`2c74659`);
a failed directory sync after a completed rename reported a failed save,
and a new database's failed temporary file was left behind (`c08e074`);
repeated field names in an export took cubic time (`25c559a`); C API
string outputs are emptied on errors (`b57195c`); dialogs no longer drop
input while a save runs (`7a50957`).

Verified on the device (Jolla Phone, 2026-10-03, build `7e97b25`): an
export with Windows line endings, a control character and unprotected OTP
fields imports and saves, its notes keep their line breaks and the OTP
fields stay hidden; the export is deleted only through the remorse timer;
a password copied before editing it is cleared after 30 seconds; swiping
back to the unlock page and a minute in the background lock the database;
opening, searching, history, moving and the new-database name check work.

## Checked and found correct

- Every first-review fix is in place.
- Each save draws a fresh master seed, IV, KDF seed and inner stream key;
  no ChaCha20 key and nonce pair is reused.
- Header and block HMACs are verified in constant time before any data is
  used; padding cannot be probed before the MAC passes.
- KDF parameters, sizes, decompression, XML depth and element counts, and
  Bitwarden KDF parameters are bounded.
- Bitwarden: only EncString type 2, MAC checked before decryption, keys
  and values zeroized; a merge touches only entries an import created.
- The password generator uses rejection sampling, without modulo bias.
- C API: null and length checks everywhere, no key material crosses it,
  every handle is freed once; `unsafe` only in `ffi.rs`.
- Saves: temporary file with `O_EXCL | O_NOFOLLOW`, read back through the
  same descriptor, renamed; new databases are 0600 and linked, never
  replacing a file.
- Every label shows database content as plain text; entry URLs are never
  opened; the cover shows only the lock state; nothing is logged.
- Sailjail permissions: `Documents` and `Downloads` only.
