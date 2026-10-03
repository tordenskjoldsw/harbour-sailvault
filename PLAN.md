# SailVault - Project Plan

Status: 2026-10-03 - direction changed from a Bitwarden client to a KeePass
(KDBX4) password manager with Bitwarden import. Phase 1 (device spike) is
complete and carries over.
Next step: Phase 2 (KDBX4 read core).

## 1. Goal

A native, open-source password manager for Sailfish OS, published in the
Jolla Harbour store. The phone holds the primary database as a standard
KeePass KDBX4 file, which KeePassXC on a PC opens through Nextcloud sync.
Users of Bitwarden or Vaultwarden switch by importing an export.

- Package name: `harbour-sailvault`
- Primary target: Jolla Phone (2026), aarch64, Sailfish OS 5.2
- Secondary targets: armv7hl and i486 (emulator), once the primary target works

## 2. Success criteria

| # | Criterion | Measured by |
|---|-----------|-------------|
| 1 | In Harbour | RPM passes the Harbour validator in CI and Jolla QA accepts it |
| 2 | Secure unlock | Database unlocks with master password and optional key file; KDF runs in the Rust core off the UI thread; key material only in RAM and zeroized on lock; auto-lock on timeout and device lock |
| 3 | Lossless KeePassXC round trip | A file written by KeePassXC, opened, edited and saved by SailVault, and reopened by KeePassXC loses nothing: entries, history, attachments, custom data, unknown XML, KDBX minor version |
| 4 | No data loss on sync | Concurrent edits on phone and PC merge like KeePassXC; the phone never overwrites a changed remote file without merging |
| 5 | Fast cold start | Unlock page visible < 1 s after tap; entry list visible < 0.5 s after key derivation with 1000 entries; KDF time measured separately |
| 6 | Native UI | Silica components only; passes the Sailfish UI "Definition of Done" checklist |

Baseline (Phase 1): the empty app reaches its first frame about 400 ms after
a direct launch on the Jolla Phone, leaving about 600 ms for the unlock page.
Measure with `tools/measure-startup.sh`.

## 3. Positioning (as of 2026-10)

Guiding principle: security is never traded for features. A convenience
feature that weakens the security model is not built, or only as an explicit,
documented opt-in.

KeePass on Sailfish (research 2026-10-03, not tested first-hand):

| App | State | Gap |
|-----|-------|-----|
| ownKeepass 1.2.6 (Harbour) | Released 2019, upstream archived, armv7hl/i486 only | No aarch64 build, unmaintained |
| ownKeepass 2.x (Chum) | Active fork, KDBX4, TOTP since 2026-09 | `Sandboxing=Disabled`, shared libsodium/libargon2: not Harbour-compliant; no built-in sync |
| KeePassRX (OpenRepos) | First release 2026-08, KDBX 1-4, key files, TOTP | Read-only; AGPL; Harbour status unknown |

No sandboxed app in Harbour can write KDBX4 today. Bitwarden clients
(BitSailor, SailWarden) need a server and, in their Harbour builds, have no
fingerprint unlock either.

SailVault competes on:

- **Harbour-native KeePass**: sandboxed, aarch64, writes KDBX4 losslessly
- **Easy switch**: import from Bitwarden/Vaultwarden exports
- **Sync without a server product**: KDBX file on the user's Nextcloud, merged like KeePassXC
- **Trust**: open source, documented threat model, no network except the user's own Nextcloud
- **Sailfish-native UX**: Silica conventions, not ported from another platform

Lessons from the Bitwarden clients (desk research 2026-10-03), still valid:

| Gap seen elsewhere | SailVault answer |
|--------------------|------------------|
| Whole decrypted vault passed to QML/JS (BitSailor) | Plaintext stays in the Rust core; QML gets list titles and only the field being shown |
| PIN as UI check only, no idle lock (BitSailor) | Real KDF on every unlock; idle and device-lock auto-lock; keys zeroized |
| Clipboard cleared for some fields, timer dies with the app (BitSailor) | Every copied field clears; timer in C++; cleared on lock and exit |
| Slow with large vaults (SailWarden) | Search in Rust, C++ list model, measured with 1000+ entries |
| Android-style tab bars, custom toasts (both) | Pulley menus, page stack, system notices |
| Log files on disk (BitSailor) | No log files |

## 4. Non-goals

- Autofill into other apps or the browser (no Sailfish API, no daemons allowed in Harbour)
- Background or scheduled sync (Harbour allows no background services)
- Bitwarden/Vaultwarden server sync (import only)
- KDBX 3.x writing; KeePass 1.x (KDB) files
- YubiKey challenge-response unlock (no practical path on the phone)
- Passkey provider; Android AppSupport integration

## 5. Architecture

```
+--------------------------------------------------+
| QML / Silica UI                                  |
+--------------------------------------------------+
| C++ bridge (Qt 5.6)                              |
|  - QObject models exposed to QML                 |
|  - file I/O: atomic save, backups                |
|  - WebDAV to Nextcloud via QNetworkAccessManager |
|  - Nextcloud app password via Sailfish Secrets   |
+--------------------------------------------------+
| Rust core (static lib, C FFI, no I/O)            |
|  - KDBX4 codec: KDFs, ciphers, HMAC blocks, XML  |
|  - lossless entry model, history, merge          |
|  - Bitwarden export import, TOTP, search         |
+--------------------------------------------------+
```

| Decision | Rationale |
|----------|-----------|
| Rust core as static library | Memory safety for parsing and crypto, `zeroize`, links into the binary so the validator only sees allowed system libs |
| Core does no I/O | Unit-testable on the host; the C++ layer owns files and network |
| Own KDBX4 codec on audited primitives | `keepass` crate: only 0.7.17 builds with Rust 1.75 and it drops attachments on save; newer releases need Rust 1.85+ and still drop unknown XML, force KDBX 4.1 and have an unstable merge |
| Lossless XML model | Unknown elements and attributes are kept and written back; required for criterion 3 |
| KDBX file as the only storage | Standard format, readable by KeePassXC, the file is the backup |

## 6. Unlock design

1. The master password (and optional key file) form the KDBX composite key.
2. The KDF from the file header (AES-KDF, Argon2d, Argon2id) runs in the Rust
   core on a worker thread, with progress in the UI.
3. On lock, all key material and decrypted data are zeroized.

Fingerprint: not reachable from a Harbour app. The Phase 1 spike showed that
Sailfish Secrets only offers a Confirm dialog for DeviceLock collections on
the Jolla Phone; direct access to the fingerprint daemon or polkit is not
allowed in Harbour. Details: `docs/spike-results.md`. A convenience unlock
may be reconsidered after the MVP (section 12).

## 7. Data safety design

The phone holds the primary copy, so a writer bug can destroy real data.

- Save atomically: write a temporary file, verify it, then rename
- Verify every save by decrypting the written file and comparing the model
- Keep rotating backups of previous versions in the app data directory
- Every edit pushes the previous state into entry history and updates
  `LastModificationTime`; deletes go to the recycle bin by default
- Hard deletes write `DeletedObjects`; moves set `LocationChanged`
- Write back the KDBX minor version that was read (4.0 or 4.1)

## 8. Sync design

- The app syncs the KDBX file with Nextcloud over WebDAV itself, only while
  it runs: on open, after save, and on pull-down
- Conditional requests: download with ETag, upload with `If-Match`
- If the remote file changed, download it, merge (UUID, then
  `LastModificationTime`, history union, `LocationChanged`, apply
  `DeletedObjects`), save locally, then upload
- The Nextcloud app password (scoped, revocable) is stored in Sailfish Secrets
- Known limit: KeePassXC's default merge ignores deletions, so a phone-side
  hard delete can return if the PC merges an older in-memory copy; the
  recycle bin default avoids this

## 9. Import design

- Bitwarden/Vaultwarden JSON, unencrypted and password-protected (PBKDF2 or
  Argon2id, HKDF, EncString type 2; reuses the existing crypto core)
- Account-restricted encrypted exports cannot be decrypted offline and are
  rejected with a clear message
- Field mapping follows KeePassXC's Bitwarden importer, so imported files
  look the same as files imported in KeePassXC
- Unencrypted import files: warn, and offer to delete the file after import

## 10. Harbour constraints

- Name prefix `harbour-`, everything except binary, desktop file and icons under `/usr/share/harbour-sailvault`
- Only libraries and QML imports from the Harbour allowlist; anything else is statically linked
- Sailjail permissions, minimal, each added with a reason: expected Internet
  (Nextcloud), Secrets (Nextcloud app password), Downloads or Documents
  (import and export files)
- No daemons, no systemd units, no D-Bus services outside the app's own namespace
- Validator runs on every build
- No "KeePass" or "Bitwarden" in the app name or icon; marked as an independent app

## 11. Phases

### Phase 1 - Device spike (complete)

Results in `docs/spike-results.md`: SDK and target set up, Rust 1.75 static
library linked and running on the Jolla Phone (5.2.0.18), Harbour validator
passes, fingerprint not available to Harbour apps, cold start baseline about
400 ms.

### Phase 2 - KDBX4 read core

- Outer header, VariantDictionary, KDFs (AES-KDF, Argon2d, Argon2id),
  ciphers (AES-256-CBC, ChaCha20, Twofish), HMAC block stream, gzip
- Composite key: password and key files (XML v1/v2, 32-byte, hex, hashed)
- Inner header, protected values, attachments
- Lossless XML model; entries, groups, history, meta, deleted objects
- Tests against databases generated with `keepassxc-cli` and with
  independently generated vectors

Exit: the core opens every test database created with KeePassXC and exposes
all entries; nothing unknown is dropped from the model.

### Phase 3 - Read-only MVP

- Open a local KDBX file, unlock, auto-lock
- List, search, entry detail, copy with clipboard timeout, TOTP
- Groups and tags as navigation and filters
- Cover with lock state

Exit: usable as a daily read-only KeePass app on the Jolla Phone; criteria 2,
5 and 6 measured and met.

### Phase 4 - Write and import

- KDBX4 writer, round trip against KeePassXC (criterion 3)
- Create, edit, delete (recycle bin, remorse), history, password generator
- Data safety design (section 7)
- Bitwarden/Vaultwarden import into a new or existing database

### Phase 5 - Nextcloud sync

- WebDAV client, ETag handling, KeePassXC-equivalent merge (criterion 4)

### Phase 6 - Harbour submission

- Submit; fix QA findings before growing the feature set (criterion 1)

### Phase 7 - Differentiation

- Attachments UI, key file management, multiple databases
- Published threat model, reproducible CI builds, signed releases
- Translations

## 12. Security principles

- Key material and decrypted data live only in RAM, in the Rust core, and are zeroized on lock
- No plaintext secret is ever written to disk or to logs
- Crypto only through audited crates, never hand-rolled primitives
- Untrusted input (KDBX files, imports, server responses) has strict bounds:
  KDF parameters, sizes, nesting depth
- Auto-lock on timeout and on device lock; clipboard is cleared after a timeout
- Threat model is written down (`docs/threat-model.md`) before Phase 3 ships

## 13. Risks

| Risk | Mitigation |
|------|------------|
| Writer bug destroys the user's database | Data safety design (section 7); round-trip tests against KeePassXC before write ships |
| Merge loses edits | Mirror KeePassXC's Merger; tests with conflicting edits; recycle bin default |
| KDBX format details misread | Verify against KeePassXC source; test files generated with `keepassxc-cli` |
| Argon2 with high memory too slow on the device | Measure on the Jolla Phone in Phase 2; worker thread with progress |
| Rust 1.75 in the target too old for a needed crate | Pin compatible versions; fallback: build the static library on the host with a current Rust |
| Project goes stale after release | Keep scope small enough to maintain alone |

## 14. Open decisions

- License (must be compatible with any reference code that gets reused)
- Convenience unlock after the MVP: none, PIN, or the Secrets Confirm dialog
- Exact import and export file location (Downloads, Documents, or file picker)

Decided:

- Direction (2026-10-03): KDBX4 password manager with Bitwarden import
  instead of a Bitwarden client. Reasons: no sandboxed KDBX4 writer exists in
  Harbour, no server product needed, standard format with KeePassXC on the
  PC. The Bitwarden server protocol work is shelved (`docs/protocol.md`
  keeps the notes).
- KDBX codec (2026-10-03): own implementation in the core on audited
  primitives instead of the `keepass` crate; see section 5.
- FFI (2026-10-03): hand-written C API with opaque handles; key material
  never crosses the boundary.
- Cold start targets (2026-10-03): unlock page < 1 s, list < 0.5 s after key
  derivation with 1000 entries, KDF time measured separately.
- Build system: qmake (2026-10-02); the Rust core is built by cargo from a
  qmake extra target and linked statically.
- Unlock (2026-10-03): no fingerprint; not reachable from a Harbour app.

## 15. References

- Harbour allowed APIs: https://docs.sailfishos.org/Develop/Apps/Harbour/Allowed_APIs/
- UI Definition of Done: https://docs.sailfishos.org/Develop/Apps/UI/Definition_of_Done/
- KDBX 4: https://keepass.info/help/kb/kdbx_4.html, https://keepass.info/help/kb/kdbx_4.1.html
- KeePassXC source (format, merge, Bitwarden import): https://github.com/keepassxreboot/keepassxc
- Bitwarden export formats: https://github.com/bitwarden/clients (`libs/tools/export`)
- ownKeepass (Chum): https://github.com/sailfishos-chum/ownkeepass
