# Security review, October 2026

Reviewed state: commit `9a2bebe` (end of Phase 3, read-only app), 2026-10-03.
Scope: `core/` (KDBX4 reader, Bitwarden export decryption, C API), `src/`
(C++ bridge), `qml/`, build and packaging configuration, dependency set.

Method: three independent code reviews (Rust core; FFI, C++ and QML; build,
sandbox and dependencies), each against the sources, the Qt 5.6 headers of
the SDK target, the KeePassXC sources and the vendored crate sources. Every
finding below was then re-checked against the code or the built binary.
Dependency advisories were matched against the RustSec advisory database
(clone of 2026-10-03). Device facts were checked on the Jolla Phone
(Sailfish OS 5.2.0.18). Points that could not be checked are marked
**unverified**.

Result: no critical or high findings. Two medium findings, both in secret
handling after the fact (timers during suspend, unwiped key material), and a
set of low findings that are cheap to fix. The cryptographic pipeline is
correct and authenticates every byte before using it.

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 13 |
| Info | 7 |

## Fix status (2026-10-03)

| Finding | Status | Commit |
|---------|--------|--------|
| M1 timers during suspend | fixed: deadlines on CLOCK_BOOTTIME, checked on access, on activation and by a 5 s watchdog | `a5f8585` |
| M2 unwiped key material | fixed: zeroize features for aes, cbc, chacha20, twofish; core-owned zeroized Argon2 memory; inner stream dropped after parsing. HMAC and SHA-2 states cannot be wiped (no crate support), documented in the threat model | `fcc1f38` |
| L1 late unlock in background | fixed | `a5f8585` |
| L2 RUSTSEC-2026-0194 | mitigated: duplicate check off, 64 attributes per element; upgrade needs Rust 1.79 | `fcc1f38` |
| L3 partial RELRO | fixed: BIND_NOW, checked with readelf | `0afd2d5` |
| L4 symbol table | fixed: binary stripped; dynamic exports stay for the booster | `0afd2d5` |
| L5 `--locked` | fixed | `0afd2d5` |
| L6 overflow checks | fixed for sailvault-core | `0afd2d5` |
| L7 exit race | fixed: cancel, wait for the pool, deliver posted result | `a5f8585` |
| L8 file read | fixed: one bounded allocation | `a5f8585` |
| L9 entry page on lock | fixed | `98a82c6` |
| L10 clipboard hash | fixed: no hash, compares against the core's value | `a5f8585` |
| L11 small unwiped copies | fixed | `fcc1f38` |
| L12 pre-authentication bounds | fixed: header hash before KDF, fallible Argon2 memory, tighter Argon2 caps | `fcc1f38` |
| L13 compatibility | fixed: UUID names pinned by a test, KeePassXC boolean rules, Comment field, VariantDictionary Bool and trailing bytes; Salsa20 inner stream stays unsupported (fails closed) | `fcc1f38` |
| I1 clipboard on exit | fixed: `QGuiApplication::sync()` after clearing; verified on the device | `a5f8585` |
| I2 keyboard input | fixed | `a5f8585` |
| I3 empty password | open: needs a separate "no password" control in the UI | - |
| I4 Send assertion | fixed | `fcc1f38` |
| I5 key file during unlock | fixed | `98a82c6` |
| I6 unused dependencies | fixed for argon2 alloc (password-hash, rand_core removed); libQt5Network stays (sailfishapp) | `0afd2d5` |
| I7 duplicate keys, `&amp;` in key file | open, behavior documented | - |

Device tests on the Jolla Phone (Sailfish OS 5.2.0.18), 2026-10-03, after
installing the fixed build:

- Copy a password, lock the phone for more than 2 minutes, wake it: the app
  is locked and the clipboard is empty (M1).
- Copy a password, switch to another app, paste after 35 seconds: empty, so
  a sandboxed app in the background can clear the selection (M1, L10).
- Copy a password, close the app, paste in another app: empty (I1).

## Medium

### M1. Lock and clipboard timers stand still while the phone sleeps

`src/vault.cpp:17-18,146-151,326-334`, `src/clipboardguard.cpp:9,26`

Qt timers count `CLOCK_MONOTONIC` time, which does not advance while Linux is
suspended. The Jolla Phone suspends aggressively: a probe on the device
showed 174042 s of suspend within 268862 s since boot (48 of 75 hours). The
1-minute background lock and the 30-second clipboard clear therefore count
awake time only. Qt's use of the monotonic clock is standard Qt behavior and
was not re-verified in the Sailfish Qt build.

Scenario: the user unlocks, the display turns off, the phone sleeps for an
hour. Whoever wakes it finds the database unlocked for the rest of the
timer budget, and a copied password still on the clipboard. This contradicts
`docs/threat-model.md` ("locks after at most 1 minute with the display
off").

Fix: record a `CLOCK_BOOTTIME` stamp when the background timer and the
clipboard timer start (the clock is already used in `src/main.cpp`). On
`ApplicationActive`, on every timer timeout and before `fieldValue`,
`copyField` and list access, compare the elapsed boot time and lock or clear
if the deadline has passed. Correct the threat model wording.

### M2. Key material in cipher, MAC and KDF state is freed without wiping

`core/Cargo.toml`; `core/src/kdbx/payload.rs:59,132,137,143`,
`core/src/kdbx/kdf.rs:163`, `core/src/kdbx/inner_header.rs:96`,
`core/src/kdbx/database.rs:18`, `core/src/bitwarden/kdf.rs:96`,
`core/src/bitwarden/enc_string.rs:50,58`

- The `aes`, `chacha20` and `cbc` crates offer a `zeroize` feature; none is
  enabled, so expanded AES round keys, ChaCha20 state (payload key and inner
  stream key) and HMAC states are dropped without wiping.
- `argon2::hash_password_into` allocates the whole Argon2 working memory
  (64 MiB with KeePassXC defaults) internally and frees it unwiped. The last
  block holds the derived key before truncation.
- The inner `ProtectedStream` stays inside `Database` for the whole
  unlocked session although it is only needed during XML parsing.

Scenario: memory disclosure after lock (zram page, heap reuse by another
allocation, crash) recovers the payload key or the transformed master key.
This contradicts the project rule that key material is zeroized on lock.

Fix: enable `features = ["zeroize"]` on `aes`, `chacha20` and `cbc`; call
`hash_password_into_with_memory` with a `Zeroizing<Vec<Block>>` allocated
by the core (also allows `try_reserve` instead of an allocation abort, see
L12); drop the `ProtectedStream` after `xml::parse` by taking it out of the
inner header. The same applies to the Bitwarden import path.

## Low

### L1. Unlock finishing in the background skips the 1-minute lock

`src/vault.cpp:218-235,326-334`. `onApplicationStateChanged` returns early
unless the state is `Unlocked`. If the app goes to the background during the
KDF, the unlock completes without a background timer; only the 5-minute idle
timer runs. Fix: after `setState(Unlocked)`, call
`onApplicationStateChanged(QGuiApplication::applicationState())`.

### L2. quick-xml 0.39.4 is affected by RUSTSEC-2026-0194

`core/src/kdbx/xml.rs:174`. `BytesStart::attributes()` checks for duplicate
attribute names with a quadratic scan; a start tag with hundreds of thousands
of attributes stalls the unlock thread for minutes. Reachable only after the
header and block HMACs passed, so the attacker needs credentials the user
will type. The fixed release 0.41 needs Rust 1.79, which the SDK target
(Rust 1.75) does not have. RUSTSEC-2026-0195 (`NsReader`) does not apply;
the core uses the plain `Reader`. Fix: `start.attributes().with_checks(false)`
and a cap on attributes per element.

### L3. Partial RELRO only

`harbour-sailvault.pro`. The binary is PIE with stack protector,
`_FORTIFY_SOURCE=2` and a non-executable stack, but the GOT stays writable
(no `BIND_NOW`; checked with `readelf -d`). Fix:
`QMAKE_LFLAGS += -Wl,-z,relro,-z,now`.

### L4. Shipped binary keeps its symbol table

The RPM binary has no debug info but `.symtab` with the core's symbol names
(`file` reports "not stripped"). Eases reverse engineering only. Fix: strip
at link time or check why `brp-strip` does not strip.

### L5. `cargo build` without `--locked`

`harbour-sailvault.pro`. A manifest and lock file divergence would be
re-resolved silently within the vendored set instead of failing the build.
Fix: add `--locked`.

### L6. Overflow checks are off in the core's release build

`core/Cargo.toml`. The parsers use `checked_add` and `try_from` and the
review found no reachable wraparound, but a missed one would wrap silently.
Fix: `[profile.release.package.sailvault-core] overflow-checks = true`; the
crypto crates are not covered by the package override, so they keep their
speed.

### L7. Exit race between the unlock task and `~Vault`

`src/vault.cpp:61-74,158-161`, `src/main.cpp`. Quitting during a KDF
destroys `Vault` on the main thread while the pool thread still runs
`sv_database_open`; the worker's `QPointer` check-then-use races with the
destruction. If the result is posted but the event loop is gone, the
database handle leaks until process exit. Fix: a shared cancellation flag
the worker checks before posting, or `QThreadPool::globalInstance()->
waitForDone()` in `~Vault` after invalidating the attempt.

### L8. File size check is racy and `readAll()` leaves unwiped key file copies

`src/vault.cpp:30-39`. `file.size()` is checked, then `readAll()` reads
whatever the file is at that moment; another app with the same permission
can swap the file in between (memory exhaustion only). `readAll()` grows its
buffer in steps, so partial copies of the key file are freed without wiping.
Fix: `QByteArray out(size, Qt::Uninitialized); file.read(out.data(), size)`
with a bounded `size`, error on short read.

### L9. Entry page keeps revealed values until the page is destroyed

`qml/pages/EntryPage.qml:65-69,101-103`. `plainValue` and `revealedValue` do
not depend on `vault.state`. The core copy is freed before `stateChanged`
pops the page, and the pop is immediate, but if the page stack is busy
(**unverified** whether Silica delays the pop) a revealed password stays on
screen in a locked app. Fix: reset `revealed` and `revealedValue` and make
`plainValue` read `vault.state` so both become empty on lock.

### L10. Clipboard digest is an unsalted SHA-256 of the copied value

`src/clipboardguard.cpp:25,37,40-43`. Anyone reading process memory during
the clipboard window can brute-force low-entropy values (PINs, user names)
from the hash, and `m_digest.clear()` frees it unwiped. Fix: salt the digest
with per-copy random bytes (from the core once it has `getrandom`) and wipe
it with `secureWipe`.

### L11. Small secret copies without wiping in the core

`core/src/kdbx/search.rs:69,73`: `to_lowercase()` creates plain `String`
copies of title, user name, URL, notes and tags per searchable entry on every
search. `core/src/kdbx/key.rs:60`: the decoded 32-byte key in the hex key
file path is a plain `Vec`. Fix: wrap both in `Zeroizing`.

### L12. Pre-authentication resource bounds are generous for a phone

`core/src/kdbx/kdf.rs:21-24`, `core/src/kdbx/database.rs:26-29`. Argon2 is
allowed up to 2 GiB and 4096 passes before the HMAC check; the 2 GiB
allocation inside the argon2 crate aborts the process on failure, and the
header SHA-256 is checked only after the KDF ran, so a corrupted file fails
after a full KDF instead of immediately. Only a crafted file reaches this
(threat model attacker 4). Fix: check the header hash before the KDF (as
KeePassXC does), allocate the Argon2 memory with `try_reserve_exact` and
return an error, and cap memory times passes.

### L13. Stricter than KeePassXC on files other clients open (fails closed)

- `core/src/kdbx/kdf.rs:14-15`: the AES-KDF UUID constants are named the
  wrong way round (`KDF_AES_KDBX3` holds the KDBX4 UUID and vice versa).
  Reading is unaffected, but a Phase 4 writer that copies KeePassXC's
  "write the KDBX3 UUID" rule would emit the wrong one. Fix before the
  writer, with a test pinning the bytes.
- `core/src/kdbx/header.rs:115`: unknown outer header fields are rejected,
  including `Comment` (ID 1), which KeePassXC ignores.
- `core/src/kdbx/inner_header.rs:77`: the Salsa20 inner stream is rejected;
  KeePassXC accepts it in KDBX4.
- `core/src/kdbx/variant_dictionary.rs:84-88`: Bool accepts only 0 and 1
  (KeePassXC: non-zero), trailing bytes after End are an error.
- `core/src/kdbx/xml.rs:67`, `core/src/kdbx/database.rs:76`: `Protected`
  and `RecycleBinEnabled` are compared case-sensitively, `EnableSearching`
  case-insensitively. KeePassXC reads booleans case-insensitively and
  accepts `1`. A non-canonical `Protected="true"` would desynchronize the
  keystream and then fail closed on UTF-8. Pick one policy.

## Info

- I1. Clipboard clear on exit: `aboutToQuit` runs after the event loop
  stopped, so the Wayland request may not be flushed. Normally the client
  disconnect drops the selection, but whether lipstick retains it or keeps
  a clipboard history is **unverified**. Test: copy, close the app, paste.
  Mitigation: `QGuiApplication::sync()` after clearing.
- I2. The idle filter ignores `QEvent::InputMethod`, so typing on the
  virtual keyboard does not reset the idle timer (fails safe).
- I3. An empty password is treated as "no password"; KDBX distinguishes
  them. Databases with an empty password plus key file will not open.
- I4. `SvDatabase` is created on a pool thread and used on the main thread;
  it is `Send` today. Add a compile-time `assert_send` to keep it so.
- I5. The key file can be removed from the pulley menu while unlocking;
  `saveSettings()` then stores a path that did not open the database.
- I6. Dependencies: `argon2` `alloc` pulls in `password-hash`, `rand_core`
  and `base64ct`, none used; `libQt5Network` is linked by the sailfishapp
  config but unused; stale `moc_systemkeystore.cpp` and `systemkeystore.o`
  in the tree; `License: TBD` blocks a release but is not a security issue.
- I7. Duplicate `String` keys in an entry: first wins (KeePassXC errors,
  KeePass 2 last wins). `&amp;` inside a key file `<Data>` is not resolved.

## Checked and found correct

- Format and crypto: signatures and version layout; cipher and KDF UUIDs;
  composite key `SHA-256(SHA-256(password) || key file key)`; all key file
  formats in KeePassXC's order; AES-KDF (two ECB halves, rounds, SHA-256);
  Argon2d/id with version, memory unit and parallelism as KeePassXC; final
  key and HMAC key derivation; header HMAC with index `u64::MAX`; per-block
  HMAC over index, length and data with the empty terminator; IV lengths
  (16 for CBC, 12 for ChaCha20); PKCS7 only for the block ciphers; gzip
  bounded with CRC check; inner header and `SHA-512` stream key split;
  protected values decrypted in document order including history.
- Authenticate before use: no decrypted byte is used before its MAC passed;
  blocks are borrowed slices, so nothing is allocated before verification;
  padding errors are unreachable from the outside (no padding oracle); all
  MAC checks are constant-time; the header SHA-256 compare is over public
  data.
- Untrusted input: iterative XML parser with depth and element caps; no
  entity expansion (billion laughs impossible); bounds-proved indexing;
  `checked_add` in the byte reader; no `unwrap` or `expect` reachable from
  file content; errors carry static strings only; `Debug` output redacts
  content.
- Bitwarden export decryption matches the Bitwarden client sources: PBKDF2
  with the UTF-8 salt string, Argon2id with `SHA-256(salt)`, HKDF-Expand
  `enc`/`mac`, EncString type 2 with constant-time MAC before decrypt.
- C API: every entry point checks handles and output pointers, writes null
  first and assigns only on success; `SvString` freed exactly once and
  zeroized; `Box<[u8]>` round trip correct; `panic = "abort"` in both
  profiles; no panic reachable from C++ input.
- C++ bridge: attempt counter drops stale unlock results; `lock()` during
  `Unlocking` frees the late result; `secureWipe` semantics match Qt 5.6's
  `detach()`; the password buffer is wiped in the task; `fields()` exposes
  names and flags only; settings hold paths only, written to the
  Sailjail-private config directory.
- QML: no logging; notices and error texts carry no values or paths; the
  password field is cleared after the bytes were copied; the cover shows
  only the lock state.
- Build and supply chain: vendored crates match `Cargo.lock` checksums;
  offline source replacement; `serde_derive` is dev-only; all nine
  `build.rs` scripts are compiler probes without network or file access
  outside `OUT_DIR`; `aes_armv8` applies (35 ARMv8 AES symbols in the
  library); PIE, stack protector, FORTIFY and NX stack confirmed in the
  binary; Sailjail names match `QCoreApplication`; the RPM contains only
  binary, QML, desktop file and icons; no real secrets in the repository.

## Suggested order

1. M1, L1: lock and clipboard deadlines on `CLOCK_BOOTTIME`, background
   timer after a late unlock (C++ only, small).
2. M2, L11: `zeroize` features, Argon2 memory owned by the core, drop the
   inner stream after parsing, wrap the remaining copies.
3. L2, L12: `with_checks(false)` with an attribute cap, header hash before
   the KDF, Argon2 memory via `try_reserve_exact` with tighter bounds.
4. L3, L4, L5, L6: build flags (`-z now`, strip, `--locked`,
   `overflow-checks`).
5. L7, L8, L9, L10: exit race, bounded file read, entry page reset,
   salted clipboard digest.
6. L13 before the Phase 4 writer; I1 as a manual device test.
