# SailVault - Project Plan

Status: 2026-10-03 - Phase 3 (read-only MVP) complete; next: Harbour
submission or Phase 4, see "Proposed in review" in section 14.
Earlier on 2026-10-03: direction changed from a Bitwarden client to a KeePass
(KDBX4) password manager with Bitwarden import. Phase 1 (device spike) is
complete and carries over. The cleanup of the Bitwarden server client is
done and Phase 2 (KDBX4 read core) has started.
Phase 2 is complete (2026-10-03): the KDBX4 reader opens every
KeePassXC-made fixture, and the KDFs are measured on the Jolla Phone.
Next step: Phase 3 (read-only MVP). The KDBX 3.1 decision (section 14) is still open; 3.1 files are
detected and reported until then.

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
- TOTP code generation: password and second factor in one app turn 2FA into
  a single factor for anyone who gets the database and the master password.
  `otp` attributes from KeePassXC are kept losslessly and shown as hidden
  fields, but no codes are generated. A separate authenticator app may be a
  later, independent project.

Reading KDBX 3.1 is an open decision, see section 14.

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
|  - Bitwarden export import, search               |
+--------------------------------------------------+
```

| Decision | Rationale |
|----------|-----------|
| Rust core as static library | Memory safety for parsing and crypto, `zeroize`, links into the binary so the validator only sees allowed system libs |
| Core does no I/O | Unit-testable on the host; the C++ layer owns files and network |
| Own KDBX4 codec on audited primitives | `keepass` crate: only 0.7.17 builds with Rust 1.75 and it drops attachments on save; newer releases need Rust 1.85+ and still drop unknown XML, force KDBX 4.1 and have an unstable merge |
| Building blocks for the codec | `chacha20`, `twofish`, `flate2` (pure Rust) and `quick-xml` build with Rust 1.75 and have permissive licenses (checked 2026-10-03) |
| Lossless XML model | Unknown elements and attributes are kept and written back; required for criterion 3 |
| KDBX file as the only storage | Standard format, readable by KeePassXC, the file is the backup |

State of the core (2026-10-03, Phase 4 Part A): 47 crates including dev
dependencies. The only Bitwarden code left decrypts password-protected
exports. `getrandom` (0.2 line) is the only system call the core makes; it
serves the seeds, IVs and inner stream key of every save, UUIDs and the
password generator.

## 6. Unlock design

1. The master password (and optional key file) form the KDBX composite key.
2. The KDF from the file header (AES-KDF, Argon2d, Argon2id) runs in the Rust
   core on a worker thread, with progress in the UI.
3. On lock, all key material and decrypted data are zeroized.

Fingerprint: not reachable from a Harbour app. The Phase 1 spike showed that
Sailfish Secrets only offers a Confirm dialog for DeviceLock collections on
the Jolla Phone; direct access to the fingerprint daemon or polkit is not
allowed in Harbour. Details: `docs/spike-results.md`. A convenience unlock
may be reconsidered after the MVP (section 14).

## 7. Data safety design

The phone holds the primary copy, so a writer bug can destroy real data.

- Save atomically: write a temporary file, verify it, then rename
- Verify every save by decrypting the written file and comparing the model
- Keep the last 3 versions as backups in the app's private data directory
  (`~/.local/share/de.tordenskjold/sailvault/backups/`), never next to the
  database; delete them when the master password or key file changes
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
  Argon2id, HKDF, EncString type 2)
- The key of a password-protected export is derived from the export password
  and the salt stored in the export, not from the account email
- Account-restricted encrypted exports cannot be decrypted offline and are
  rejected with a clear message
- Field mapping follows KeePassXC's Bitwarden importer, so imported files
  look the same as files imported in KeePassXC
- Unencrypted import files: warn, and offer to delete the file after import
- Export format and field mapping are documented in `docs/bitwarden-export.md`
- Test vectors are real password-protected exports (PBKDF2 and Argon2id),
  generated independently of the core with OpenSSL

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

### Cleanup after the direction change (complete, 2026-10-03)

- Removed everything that only existed for the Bitwarden server client
- Bitwarden code in the core reduced to the decryption of password-protected
  exports, now with the export's salt instead of the email
- Random-number interface and `getrandom` crate removed
- Server protocol notes turned into `docs/bitwarden-export.md`
- Test vectors replaced by real password-protected exports
- Verified after the cleanup: all tests pass, the target build with Rust 1.75
  works, the Harbour validator passes

### Phase 2 - KDBX4 read core (complete)

Scope:

- Outer header, VariantDictionary, KDFs (AES-KDF, Argon2d, Argon2id),
  ciphers (AES-256-CBC, ChaCha20, Twofish), HMAC block stream, gzip
- Composite key: password and key files (XML v1/v2, 32-byte, hex, hashed)
- Inner header, protected values, attachments
- Lossless XML model; entries, groups, history, meta, deleted objects
- Tests against the fixtures below and against independently generated vectors

Preparation (done):

- Crates checked, see section 5
- `tools/kdbx-fixtures/content.xml`: fake data with history, attachment,
  TOTP, custom fields, tags, nested groups, recycle bin and deleted objects;
  KeePassXC imports all of it
- `tools/gen-kdbx-fixtures.sh`: creates four test databases with
  `keepassxc-cli` and checks their format version: KDBX 3.1 and KDBX 4.0
  (AES-KDF, AES-256), each with and without a key file

Finding: `keepassxc-cli import` writes AES-KDF with AES-256 and picks the
format from the content: entry CustomData forces KDBX 4.0 (Meta CustomData
alone does not), without it the file stays 3.1. Other KDFs and ciphers need the KeePassXC GUI. KeePassXC may save
after every settings change, so GUI fixtures are edited in place on a copy.

Manual step (done 2026-10-03, verified from the file headers) - three KDBX4
fixtures, each a copy of `kdbx4-aes-aeskdf.kdbx` edited in the KeePassXC
GUI. Exact steps are in `core/tests/fixtures/README.md`:

1. Open the file in KeePassXC, password `sailvault-fixture`.
2. Database > Database Settings > Security > Encryption Settings > Advanced
   Settings.
3. Set the values from the table, confirm, then save (Ctrl+S).

| File | Format | KDF | Cipher |
|------|--------|-----|--------|
| `kdbx4-aes-argon2d.kdbx` | KDBX 4.0 | Argon2d | AES 256-bit |
| `kdbx4-chacha20-argon2id.kdbx` | KDBX 4.0 | Argon2id | ChaCha20 256-bit |
| `kdbx4-twofish-aeskdf.kdbx` | KDBX 4.0 | AES-KDF | Twofish 256-bit |

- Argon2 settings: 2 iterations, 8 MiB, 2 threads
- AES-KDF: 10000 rounds

Exit: the core opens every test database created with KeePassXC and exposes
all entries; nothing unknown is dropped from the model.

Result (2026-10-03, host only):

- `kdbx::Database::open` reads all five KDBX4 fixtures (AES-256, ChaCha20,
  Twofish; AES-KDF, Argon2d, Argon2id; with and without key file) and the
  tests assert their full content: fields, protected values, history,
  attachment bytes, tags, groups, recycle bin, deleted objects, custom data
- Wrong password, missing key file and tampered header or payload are
  rejected; KDBX 3.1 is reported as `Kdbx3Unsupported`
- The XML is a lossless element tree; not kept are XML comments, processing
  instructions and indentation between elements, none of which carry data
- KeePassXC adds its own `_LAST_MODIFIED` custom data item on import; the
  reader keeps it like any other item
- Builds with the target's Rust 1.75
- On the Jolla Phone: Argon2id with 64 MiB takes about 140 ms for 2
  iterations and 600 ms for 10; AES-KDF reaches 62 million rounds/s with
  the ARMv8 AES instructions (`aes_armv8` in `.cargo/config.toml`), 1
  million without; opening without the KDF takes 2 ms. Details in
  `docs/spike-results.md`

### Phase 3 - Read-only MVP (complete)

- Open a local KDBX file (picked from Documents or Downloads), unlock,
  auto-lock
- List, search, entry detail, copy with clipboard timeout
- Groups and tags as navigation and filters
- Cover with lock state and a lock action
- No TOTP codes (section 4)

Work order:

1. Search in the core
2. C FFI with opaque handles: open, entry list, single field on demand,
   search, lock
3. C++ bridge: unlock on a worker thread, list model, clipboard with timeout
   (cleared on lock and exit), auto-lock
4. Silica pages: unlock, entry list with search, entry detail, cover
5. Device test and measurements (criteria 2, 5, 6)
6. `docs/threat-model.md`

Status (2026-10-03): steps 1 to 4 are done. First device test on the Jolla
Phone (Sailfish OS 5.2.0.18) with the fixture `kdbx4-aes-argon2d.kdbx` copied
to Documents worked: picking the file, unlocking, group navigation, search,
entry page, copy and lock. Two bugs found on the
device and fixed before that: the unlock result was dropped (quintptr is no
Qt 5.6 metatype) and the entry list bound its model to itself in QML.
Verified on the device later the same day: clipboard
cleared after 30 seconds; a wrong password is shown at the password field;
the 1000-entry fixture unlocks, lists and searches without noticeable delay.
Measured: cold start to the unlock page 557 ms (median, target < 1 s); with
1000 entries the core opens the database in 33 ms after the KDF and searches
in about 2 ms (target: list < 0.5 s after key derivation). Details in
`docs/spike-results.md`. Threat model written (`docs/threat-model.md`).
Also verified on the device: auto-lock after 1 minute in the background with
"Locked automatically" on the unlock page, lock from the pulley menu and
the cover action, landscape. The 5-minute idle lock in the foreground uses
the same mechanism and was not tested separately.

Phase 3 is complete (2026-10-03).

Auto-lock defaults: 5 minutes idle in the foreground, 1 minute in the
background (another app or display off), manual lock from the pulley menu
and the cover. Locking on device lock would need a system D-Bus service,
which the sandbox does not allow; the background rule covers it.

Exit: usable as a daily read-only KeePass app on the Jolla Phone; criteria 2,
5 and 6 measured and met.

### Phase 4 - Write and import

Order (decided 2026-10-03): creating entries first, then editing and
deleting, then the Bitwarden import. A security review of the Phase 3 state
comes before any Phase 4 code.

Part A - create entries:

1. Random source in the core: the `getrandom` crate (Linux `getrandom`
   syscall), the only exception to the no-I/O rule; used for master seed,
   IVs, inner stream key, UUIDs and the password generator
2. KDBX4 writer: serializes the lossless XML tree, re-encrypts protected
   values with a new inner stream, inner header with attachments, gzip,
   HMAC block stream, outer header; writes back the KDBX minor version that
   was read. Which header values KeePassXC regenerates on every save (master
   seed, IV, inner stream key, KDF seed) is checked in `Kdbx4Writer.cpp`
   before implementing
3. Round-trip tests: read, write, read again yields an identical tree for
   every fixture; `keepassxc-cli` opens every written file and its export
   matches the original
4. New entry in the core: new UUID, KDBX4 timestamps, `Protected` flags
   from the database's MemoryProtection settings
5. Safe save in C++ (section 7): backup, temporary file, verify by
   decrypting it again, atomic rename; save right after the user accepts
6. UI: "New entry" in the pulley menu, an entry dialog (title, user name,
   password, URL, notes) and a password generator
7. Device test: create entries on the phone, open the file in KeePassXC

Status (2026-10-03): all steps are done. `Kdbx4Writer.cpp` confirmed that KeePassXC draws a new master seed,
encryption IV, inner stream key and KDF seed on every save
(`Database::setKey` with `updateTransformSalt`); SailVault does the same, so
the KDF runs once per save and the core keeps the composite key while
unlocked. Every fixture, including the 1000-entry one, reopens with an
identical tree and binary pool after a save, and the `keepassxc-cli` export
of the saved file equals the export of the original (apart from KeePassXC's
export-time `_LAST_MODIFIED` stamps). `keepassxc-cli show` reads an entry
that SailVault added to a subgroup. The core verifies each save by
decrypting the serialized file before handing it out. Saving in C++ follows
section 7; the backups live in `~/.local/share/de.tordenskjold/sailvault/
backups/`. The RPM builds without warnings and passes the validator.

Device test on the Jolla Phone (Sailfish OS 5.2.0.18), 2026-10-03: an entry
with a generated password was created in the fixture `kdbx4-aes-argon2d.kdbx`
on the phone. The saved file and the backup were fetched from the phone and
checked on the host: the backup is byte-identical to the previous file,
`keepassxc-cli` 2.7.12 opens the saved file and lists the new entry, and the
exports of backup and saved file differ only by that entry, whose timestamps
match the save time. Criterion 3 holds for a file changed on the phone.

Part B - edit and delete: history, recycle bin with remorse, hard delete
writes `DeletedObjects`.

Status (2026-10-03): done and device-tested. Editing follows
KeePassXC's `Entry::endUpdate`: the previous state becomes a history item,
modification and access times are set, and the history is trimmed to
`Meta/HistoryMaxItems` and `HistoryMaxSize` (KeePassXC sizes an item by its
attributes, auto-type, attachments, custom data and tags; SailVault counts
every text node and the attachments, about a hundred bytes more). Deleting
moves an entry to the recycle bin, which is created like KeePassXC's
`Database::createRecycleBin` when missing; an entry already in the bin, or
any entry while the bin is disabled, is removed and recorded under
`DeletedObjects`. Deleting a group moves it with everything in it to the
bin; a group inside the bin, the bin itself, a group holding the bin, or any
group while the bin is disabled is removed for good, recording its entries,
subgroups and itself like KeePassXC's `Group::~Group`; the root group is
refused. The entry dialog edits existing entries; the entry page and the
list offer "Edit" and "Delete" (groups: "Delete") with a remorse timer whose
text says whether the item is recycled or removed for good. `keepassxc-cli`
reads saved files with all these edits. Not in Part B: creating or renaming
groups, restoring from or emptying the recycle bin, a history viewer, and
deleting backups on a credential change (there is no credential change yet).

Device test on the Jolla Phone (Sailfish OS 5.2.0.18), 2026-10-03: entries
were edited and deleted, and a group was deleted from the list with the
remorse popup.

Part C - Bitwarden/Vaultwarden import:

1. Creating groups and moving entries between them (KeePassXC's
   `KdbxXmlWriter::writeGroup` layout and `Entry::setGroup`), so imported
   entries can be sorted on the phone; moving out of the recycle bin
   restores an entry. As in KeePassXC, nothing new is added inside the
   recycle bin
2. JSON parsing in the core with bounds on size, item count and depth
3. Mapping to KDBX as in KeePassXC's `BitwardenReader.cpp` (section 9);
   item types KeePassXC does not map (SSH key, bank account, driver's
   license, passport) keep every field as a custom attribute, secret values
   protected
4. Import into the open database, in the group "Bitwarden import";
   folders become subgroups; a later import merges
5. UI: file picker, export password, warning for unencrypted exports with
   an offer to delete the file afterwards
6. Device test

Status (2026-10-03): step 1 is done. Device test on the Jolla Phone: an
entry was moved to another group with one tap. Steps 2 to 5 are
done: the core reads unencrypted and
password-protected exports (`serde_json`, 32 MiB cap) and maps them as
listed in `docs/bitwarden-export.md`; the import is added in one step, so
a failure leaves the database unchanged. `keepassxc-cli` reads an imported
and saved database, finds every entry in its folder and computes TOTP
codes from the stored `otp` values. The KDF of a protected export runs on
a pool thread; a lock discards the import.
Device test on the Jolla Phone, 2026-10-03: an unencrypted and a
password-protected export were imported; a wrong export password shows
its error text. Merging: an export with one item, then an export with that
item and a second one, left exactly two entries in the import group.
Part C is complete.

Not in Part C: creating a new database for the import, the zip export with
attachments.

Follow-ups (2026-10-03), done: renaming and
moving groups (`Group::setName`, `Group::setParent`; never into the group
itself), restoring entries and groups from the recycle bin to their previous
group or the root group (KeePassXC restores only entries with a known
previous group), emptying the recycle bin (`Database::emptyRecycleBin`),
and a read-only history view. `keepassxc-cli` reads a saved file with all of
these changes.
Device test on the Jolla Phone: groups were renamed and moved, and items
were restored from and deleted by emptying the recycle bin.

Security review fixes (2026-10-03): the temporary file of a save is created
exclusively and never through a symlink; database content is shown as plain
text; an import merges only into entries an import created. Device test on
the Jolla Phone: saving after an edit still works, and importing the
two-item export and then the one-item export ends with "Nothing new to
import".

Exit: criterion 3 (lossless KeePassXC round trip) met for every fixture and
for files changed on the phone.

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
| KDBX format details misread | Verify against KeePassXC source; fixtures created with KeePassXC (`keepassxc-cli` and the GUI) |
| KDBX4 fixtures are made by hand and can drift from the documented settings | Steps and parameters fixed in `core/tests/fixtures/README.md`; tests assert format, KDF and cipher of each fixture |
| Argon2 with high memory too slow on the device | Measured in Phase 2: about 60 ms per iteration per 64 MiB; worker thread with progress |
| Rust 1.75 in the target too old for a needed crate | Pin compatible versions; fallback: build the static library on the host with a current Rust |
| Project goes stale after release | Keep scope small enough to maintain alone |

## 14. Open decisions

- **KDBX 3.1 support** (needed before the reader is written):
  - (a) KDBX4 only. 3.1 files get a clear message: "Please convert to KDBX 4
    in KeePassXC".
  - (b) Read 3.1 too and save as KDBX 4.0, which KeePassXC opens without
    trouble.
  - Who has 3.1 files: anyone whose database uses AES-KDF and no KDBX4-only
    features (for example created with `keepassxc-cli db-create`) or comes
    from an older KeePass version; KeePassXC keeps the old format then. The KeePassXC GUI defaults to
    KDBX4, so most KeePassXC users have KDBX4 files.
  - Cost of (b): 3.1 differs internally (block format, stream encryption of
    protected fields, attachment storage). Extra work, easier switch.
  - Recommendation: (a) now, (b) later as its own step. The 3.1 fixtures
    already exist for that.
- Convenience unlock after the MVP: none, PIN, or the Secrets Confirm dialog

Proposed in review (2026-10-03), not decided:

- Decide the convenience unlock before Phase 3 instead of after the MVP. It
  affects how key material is held in RAM, and typing the full master
  password on every unlock pushes users toward weaker passwords.
- KDF parameter bounds: warn with a time estimate instead of rejecting, so
  that high memory settings chosen in KeePassXC do not lock users out of
  their own database.
- Replace "audited" in sections 5 and 12 with a per-crate check or with
  "established, widely used". Not every crate in use has a formal audit.
- Add a known limit to section 8: if KeePassXC saves on the PC while the
  Nextcloud client holds a newer version, Nextcloud creates conflict files
  outside the app's control.

Decided:

- License (2026-10-03): MIT. No code from GPL projects such as KeePassXC is
  reused, only documented behavior; every vendored crate has a permissive
  license (MIT, Apache-2.0, BSD-3-Clause, Zlib, Unicode-3.0, Unlicense).
- Harbour submission (2026-10-03): not right after Phase 3; the maintainer
  submits later.
- Phase 4 order (2026-10-03): create entries, then edit and delete, then
  the Bitwarden import.
- Import target (2026-10-03): the open database, in the group "Bitwarden
  import"; a later import merges into it like KeePassXC's merge (item ID as
  entry UUID, newer side wins, the other goes to history, deleted entries
  stay deleted, nothing is removed).
  Creating a database is a separate feature (KDF settings, credentials,
  file location). Groups can be created and entries moved between them to
  sort the import.
- Import scope (2026-10-03): JSON exports, unencrypted and
  password-protected; the zip export with attachments comes later. Item
  types without a KeePassXC mapping keep all fields as custom attributes.
- Random source (2026-10-03): `getrandom` in the core, documented exception
  to the no-I/O rule. The 0.2 line, because the 0.3 line's wasm
  dependencies have manifests that the SDK's cargo 1.75 cannot parse,
  although they are never built for the target.
- Changed file on save (2026-10-03): until Phase 5 brings merging, a file
  that another program changed while the database was unlocked is replaced;
  the backup keeps that version and the UI says so. Refusing would leave
  the new entry only in RAM.
- Saving (2026-10-03): immediately after the user accepts a change, like
  KeePassXC's autosave; no separate save button.
- Backups (2026-10-03): last 3 versions in the private data directory;
  deleted on credential changes. Fewer copies limit exposure to old
  passwords, three are enough to roll back a faulty save.
- TOTP (2026-10-03): SailVault generates no TOTP codes; see section 4.
- File location for Phase 3 (2026-10-03): the user picks the KDBX file with
  the Sailfish file picker from Documents or Downloads; Sailjail permissions
  `Documents` and `Downloads`, not the broader `UserDirs`.
- Auto-lock (2026-10-03): 5 minutes idle, 1 minute in the background,
  manual lock from pulley menu and cover.
- Direction (2026-10-03): KDBX4 password manager with Bitwarden import
  instead of a Bitwarden client. Reasons: no sandboxed KDBX4 writer exists in
  Harbour, no server product needed, standard format with KeePassXC on the
  PC. The Bitwarden server protocol work is shelved (notes in git history;
  import details in `docs/bitwarden-export.md`).
- Cleanup (2026-10-03): code and notes that only served the Bitwarden server
  client are removed; the core keeps only the decryption of
  password-protected exports.
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
