# Phase 1 - Spike results

Status: in progress. Only the section "On the device" was tested on the
Jolla Phone; everything else was verified on the development host.

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

Verified on the Jolla Phone on 2026-10-02 (exact OS build to be recorded):

- `harbour-sailvault-0.1.0-1.aarch64.rpm` copied to the phone and installed
  as untrusted software.
- The app starts from the app grid. The page shows the header "SailVault"
  and "Core version 0.1.0", so the string comes from the Rust core through
  the C FFI, Qt and QML.

## Open

- [x] Rust "hello" static library linked into a Silica app via `sfdk build`
- [x] Harbour validator (`sfdk check`) passes
- [x] Rust "hello" app starts on the Jolla Phone and shows the core version
- [ ] Record the exact Sailfish OS version of the Jolla Phone
- [ ] Secret stored in Sailfish Secrets and read back behind system authentication
- [ ] Fingerprint accepted by the system dialog on the Jolla Phone (hard gate)
- [ ] Cold start baseline of the empty app
