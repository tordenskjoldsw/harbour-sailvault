# Phase 1 - Spike results

Status: complete (2026-10-03). Sections "On the device", "Sailfish Secrets"
(device results) and "Cold start baseline" were tested on the Jolla Phone;
everything else was verified on the development host.

## SDK and build target

Verified on the development host (CachyOS, x86_64) on 2026-10-02:

| Item | Value | How verified |
|------|-------|--------------|
| Sailfish SDK | 3.13.5 (Stable) | `sfdk --version` |
| Build engine | Docker 29.8.2, socket-activated, buildx installed | `docker info`, `sfdk engine status` |
| Newest SDK-provided target | `SailfishOS-5.1.0.11` (aarch64, armv7hl, i486) | `sfdk tools list` |

No 5.2 target is provided by the SDK. The app is built against
`SailfishOS-5.1.0.11-aarch64` and is expected to run on 5.2, since binaries
built against an older target normally run on newer releases. Unverified
until the RPM runs on the Jolla Phone with 5.2.

## Rust toolchain in the target

| Package | Version | State in target |
|---------|---------|-----------------|
| `rust` | 1.75.0+git1-1.11.1.jolla | available, not installed |
| `cargo` | 1.75.0+git1-1.11.1.jolla | available, not installed |
| `rust-std-static-aarch64-unknown-linux-gnu` | 1.0+git3-1.3.9.jolla | available, not installed |
| `rust-cbindgen` | 0.26.0+git1-1.15.1.jolla | source package only |

Source: `zypper se -s` inside the target via `sfdk tools exec`.

Consequences:

- Every crate in `core/` must build with Rust 1.75 (MSRV 1.75), edition
  2021. Edition 2024 needs 1.85 and is not available.
- Pin crate versions. Use `rust-version = "1.75"` in `core/Cargo.toml` so
  the MSRV-aware resolver of a newer host cargo picks compatible versions.
- Check the MSRV of each planned crate (RustCrypto, `zeroize`, `rsa`,
  `argon2`, `serde`) before adding it.

## Rust core in the RPM

Verified on the host on 2026-10-02 (not on the device):

- `sfdk build` builds `core/` with the target's cargo and links
  `libsailvault_core.a` statically into `harbour-sailvault`.
- Without `--target`, cargo in the build engine produces i386 objects and
  the aarch64 link fails. The `.pro` file derives the triple from `QT_ARCH`.
- `file` reports the binary as `ELF 64-bit LSB pie executable, ARM aarch64`.
- The RPM requires only system libraries (Qt5, libsailfishapp, libc,
  libgcc_s, libstdc++); nothing from Rust.

## Harbour validator

`sfdk check` on `harbour-sailvault-0.1.0-1.aarch64.rpm`: validation
succeeded (Requires, Sandboxing, RPATH, Architecture passed).

rpmlint findings to fix before submission:

- `E: no-changelogname-tag` - add `rpm/harbour-sailvault.changes`
- `W: invalid-license TBD` - pending the license decision
- `W: unstripped-binary-or-object` - from `QMAKE_STRIP=:` in `%qmake5`;
  check whether Harbour cares

## On the device

Verified on the Jolla Phone with Sailfish OS 5.2.0.18 on 2026-10-02:

- `harbour-sailvault-0.1.0-1.aarch64.rpm` copied to the phone and installed
  as untrusted software.
- The app starts from the app grid. The page shows the header "SailVault"
  and "Core version 0.1.0", so the string comes from the Rust core through
  the C FFI, Qt and QML.

## Sailfish Secrets

Source analysis of sailfish-secrets 0.2.44 (the target's version,
https://github.com/sailfishos/sailfish-secrets, tag `0.2.44`):

- Only `DeviceLock` collections trigger the system authentication flow
  (`beginAuthentication` of `plugin.authentication.default`, see
  `daemon/SecretsImpl/secretsrequestprocessor.cpp`, read path around line
  2610). `CustomLock` collections ask for a collection passphrase instead.
- After an access to an originally locked collection, the daemon relocks it
  unless the semantic is `DeviceLockKeepUnlocked`
  (`daemon/SecretsImpl/pluginfunctionwrappers.cpp` around line 1098).
- The system authentication plugin is not part of the public source. Whether
  it accepts fingerprint can only be checked on the device.

Harbour (https://docs.sailfishos.org/Develop/Apps/Harbour/Allowed_APIs/):
`libsailfishsecrets.so.0`, `sailfishsecretsdaemon` and
`sailfishsecretsdaemon-secretsplugins-default` are allowed; the Sailjail
permission is `Secrets`. pkg-config module: `sailfishsecrets`.

BitSailor (MIT) does not use Secrets for fingerprint unlock. It calls polkit
directly, which is not allowed in Harbour, and disables the feature in its
store build. No working Harbour reference for our approach is known.

Spike configuration (`src/systemkeystore.cpp`), one collection per variant:

| Setting | Value |
|---------|-------|
| Lock type | `CreateCollectionRequest::DeviceLock` |
| Unlock semantic | `DeviceLockVerifyLock` or `DeviceLockRelock` (selectable) |
| Access control | `OwnerOnlyMode` |
| User interaction | `SystemInteraction` |
| Storage and encryption plugin | `DefaultEncryptedStoragePluginName` |
| Authentication plugin | `DefaultAuthenticationPluginName` |
| Secret | 32 random bytes from the Rust core (`getrandom`), collection secret |

Known limitation: the Secrets client library passes secret data in
implicitly shared `QByteArray`s and over D-Bus, so the app cannot zeroize
every copy. To be addressed when the real key flow is designed (Phase 3).

Device test results (Jolla Phone, Sailfish OS 5.2.0.18, 2026-10-02):

- Store, read and delete of the 32-byte test key succeed.
- Each operation shows a system confirmation dialog.
- Both `DeviceLockVerifyLock` and `DeviceLockRelock` show the same dialog:
  "Authorize - /usr/bin/harbour-sailvault wants to store a new secret named
  testkey into collection sailvaultspikerelock in plugin SQLCipher" with
  Cancel and Confirm. It asks for neither fingerprint nor security code.
- Consequence: on an unlocked device the dialog is a confirmation, not an
  authentication. Anyone holding the unlocked phone can confirm it. The
  stored key is only bound to the device lock state, not to a fresh
  fingerprint check. Hard gate (criterion 2) not met with this
  configuration.

## Cold start baseline

Measured on the Jolla Phone (Sailfish OS 5.2.0.18) on 2026-10-03 with
`tools/measure-startup.sh`: launch of `/usr/bin/harbour-sailvault
--startup-trace` over SSH until the first frame is swapped (`frameSwapped`),
both timestamps on `CLOCK_BOOTTIME`, 10 ms resolution (`/proc/uptime`).

| App state | First run | Runs 2-11 median | Min | Max |
|-----------|-----------|------------------|-----|-----|
| Empty app (core version page) | 397 ms | 405 ms | 365 ms | 430 ms |

A second series of 6 runs gave a median of 399 ms.

Limits of this measurement:

- Direct launch: no Silica booster and no Sailjail sandbox. From SSH,
  `invoker` exits with code 1 and `sailjail` starts nothing, so the homescreen
  path could not be scripted. The booster normally makes launches faster; the
  sandbox adds some setup. Homescreen launch time is not measured.
- Files are in the page cache after the first run; dropping caches needs
  root. The first run is not a true cold start either, since the package was
  just installed.

## Open

- [x] Rust "hello" static library linked into a Silica app via `sfdk build`
- [x] Harbour validator (`sfdk check`) passes
- [x] Rust "hello" app starts on the Jolla Phone and shows the core version
- [x] Record the exact Sailfish OS version of the Jolla Phone (5.2.0.18)
- [x] 5.1.0.11 build runs on the Jolla Phone with Sailfish OS 5.2.0.18
- [x] Secret stored in Sailfish Secrets and read back behind system authentication (Confirm dialog only)
- [x] Fingerprint accepted by the system dialog on the Jolla Phone: no, gate failed; fingerprint dropped (PLAN.md section 6)
- [x] Cold start baseline of the empty app (about 400 ms, direct launch)

## KDF and unlock timings (Phase 2)

Measured on the Jolla Phone (Sailfish OS 5.2.0.18) on 2026-10-03 with
`tools/run-kdf-benchmark.sh` (`core/examples/kdf_benchmark.rs`, release
build with the target's Rust 1.75, median of 3 runs). Host: development PC
for comparison.

| KDF | Phone | Host |
|-----|-------|------|
| Argon2id, 2 iterations, 64 MiB | 141 ms | 41 ms |
| Argon2id, 10 iterations, 64 MiB | 616 ms | 187 ms |
| Argon2id, 2 iterations, 256 MiB | 586 ms | 189 ms |
| AES-KDF without `aes_armv8` | 1.0 million rounds/s | - |
| AES-KDF with `aes_armv8` | 62 million rounds/s | 67 million rounds/s |
| Opening a fixture without the KDF | 2 ms | < 1 ms |

- Argon2 cost grows linearly with iterations times memory, about 60 ms per
  iteration per 64 MiB on the phone. The `argon2` crate runs lanes
  sequentially, so parallelism does not speed it up.
- The `aes` crate uses the ARMv8 AES instructions only with
  `--cfg aes_armv8`, set for aarch64 in `.cargo/config.toml`. It detects
  them at runtime and falls back to software. Without the flag, an AES-KDF
  database set to one second in KeePassXC would take about a minute.
- Argon2d timings of the second run varied between 130 and 1600 ms in the
  first rows, likely from other load on the phone; Argon2id matched the
  first run within a few percent.
- The SDK build environment sets no `RUSTFLAGS`, so the app build picks up
  the flag from `.cargo/config.toml`.
