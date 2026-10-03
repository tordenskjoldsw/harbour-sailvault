# SailVault - Project Plan

Status: 2026-10-03 - Phase 1 (device spike) in progress. Fingerprint unlock
dropped (see section 6); the vault unlocks with the master password.
Next step: finish Phase 1 (OS version, cold start baseline).

## 1. Goal

A native, open-source Bitwarden/Vaultwarden client for Sailfish OS that is
published in the Jolla Harbour store.

- Package name: `harbour-sailvault`
- Primary target: Jolla Phone (2026), aarch64, Sailfish OS 5.2
- Secondary targets: armv7hl and i486 (emulator), once the primary target works

## 2. Success criteria

| # | Criterion | Measured by |
|---|-----------|-------------|
| 1 | In Harbour | RPM passes the Harbour validator in CI and Jolla QA accepts it |
| 2 | Secure master password unlock | Vault unlocks with the master password; the KDF runs in the Rust core off the UI thread; key material only in RAM and zeroized on lock; auto-lock on timeout and device lock |
| 3 | Fast cold start | Unlock page visible < 1 s after tap; item list visible < 0.5 s after the master key is derived; KDF duration measured and reported separately; measured with 1000 items, offline |
| 4 | Native UI | Silica components only; passes the Sailfish UI "Definition of Done" checklist |

The cold start numbers are proposed targets, not measured values. Re-baseline
them with real numbers after Phase 1.

## 3. Positioning (as of 2026-10)

| Client | State | Weak spot |
|--------|-------|-----------|
| BitSailor | Open source, rewritten on a native Go core (v1.0.0, July 2026), listed in Harbour news (Sept 2026), fingerprint via polkit, only in the OpenRepos build (not allowed in Harbour), very frequent releases | Unknown from first-hand testing - to be found by daily use |
| SailWarden | Broad feature set (organizations, Send, SSO, device login, biometrics) | Closed source, OpenRepos only, Android-like UI, low community trust |

SailVault does not compete on feature breadth in the first year. It competes on:

- **Trust**: open source from day one, documented threat model, reproducible CI builds
- **Security architecture**: Rust core, keys only in RAM and zeroized, no key material at rest outside the server's encrypted data
- **Offline and speed**: vault fully readable without network, fast cold start with large vaults
- **Sailfish-native UX**: built to Silica conventions, not ported from another platform

Action item: use BitSailor and SailWarden daily for one week and log every
annoyance. That list becomes the differentiation backlog (Phase 6).

## 4. Non-goals

- Autofill into other apps or the browser (no Sailfish API, no daemons allowed in Harbour)
- Passkey provider
- Android AppSupport integration
- Chasing feature parity before the MVP is in Harbour

## 5. Architecture (proposed, to be validated in Phase 1)

```
+--------------------------------------------------+
| QML / Silica UI                                  |
+--------------------------------------------------+
| C++ bridge (Qt 5.6)                              |
|  - QObject models exposed to QML                 |
|  - HTTP via QNetworkAccessManager                |
|  - live sync via QtWebSockets                    |
+--------------------------------------------------+
| Rust core (static lib, C FFI, no I/O)            |
|  - KDF, EncString, RSA, data model, search       |
+--------------------------------------------------+
```

| Decision | Rationale |
|----------|-----------|
| Rust core as static library | Memory safety for crypto code, `zeroize` for key material, links into the binary so the validator only sees allowed system libs |
| Core does no I/O | No TLS stack to bundle, core is unit-testable on the host, all network goes through Qt |
| No Python / PyOtherSide | Allowed in Harbour, but native crypto modules (for example Argon2) would have to be bundled; slower start |
| Offline cache = raw encrypted sync response | Server data is already encrypted with the user key, so no own at-rest crypto is needed |
| Own protocol implementation, RustCrypto crates | No dependency on Bitwarden's internal SDK; no hand-rolled primitives |

## 6. Unlock design

Decision (2026-10-03): the vault unlocks with the master password only.

1. The master password and the account's KDF settings (PBKDF2-SHA256 or
   Argon2id) derive the master key in the Rust core, off the UI thread.
2. The master key decrypts the user key, which decrypts the local cache.
3. On lock, all key material is zeroized. Nothing is stored that would
   allow unlocking without the master password.
4. Session tokens: the access token lives only in RAM. The refresh token is
   stored in the app data directory, encrypted by the Rust core with the
   user key (the same EncString scheme the server uses). Without the master
   password it is unusable, so syncing and refreshing require an unlocked
   vault. No Sailfish Secrets dependency.

Why no fingerprint: the Phase 1 spike showed that Sailfish Secrets, the only
Harbour-allowed route, shows a plain Confirm dialog for DeviceLock
collections on the Jolla Phone, without fingerprint or security code. Direct
access to the fingerprint daemon or polkit is not allowed in Harbour.
Details: `docs/spike-results.md`.

A convenience unlock (PIN or the Secrets Confirm dialog) may be reconsidered
after the MVP; see section 12.

## 7. Cold start design

- UI first, network later: always start from the local encrypted cache, sync in the background
- First screen is the unlock page only; every other page loads lazily (Qt 5.6 has no QML disk cache)
- Use the Silica booster (allowed in Harbour)
- Decrypt lazily: names for the list first, full item on open; parallel in the Rust core
- KDF runs in the Rust core on a worker thread; the UI shows progress
- Measure on every release: tap to unlock page, authentication to list

## 8. Harbour constraints

- Name prefix `harbour-`, everything except binary, desktop file and icons under `/usr/share/harbour-sailvault`
- Only libraries and QML imports from the Harbour allowlist; anything else is statically linked or bundled privately
- Sailjail profile with minimal permissions (expected: Internet only)
- No daemons, no systemd units, no D-Bus services outside the app's own namespace
- Validator runs in CI on every build
- No "Bitwarden" in app name or icon; clearly marked as unofficial

## 9. Phases

### Phase 1 - Device spike (hard gate)

- Minimal Silica app that stores a random 32-byte secret in Sailfish Secrets and reads it back behind system authentication (done: works, but only a Confirm dialog)
- Confirm on the Jolla Phone that the dialog accepts fingerprint; document the exact API configuration (done: no fingerprint; gate failed, fingerprint dropped)
- Rust static library ("hello") linked into the app via sfdk for aarch64
- Record the Rust toolchain version of the build target; check it against the minimum versions of the planned crates
- Run the Harbour validator on the RPM
- Measure cold start of the empty app as baseline

Exit: all of the above works on the device; results written to `docs/spike-results.md`.

### Phase 2 - Core

- Prelogin, KDF (PBKDF2-SHA256 and Argon2id), key stretching, EncString decryption, RSA for organization keys
- Login with master password, API key, and TOTP as second factor; token refresh
- Sync and data model
- Test vectors against Vaultwarden and the official Bitwarden cloud

Exit: host-side test suite decrypts a real synced test vault. Verify every
protocol detail against the Bitwarden Security Whitepaper and the Vaultwarden
source, not against this summary.

### Phase 3 - Read-only MVP

- Login, unlock with master password, auto-lock
- List, search, item detail, copy with clipboard timeout, TOTP codes
- Offline cache, background sync
- Cover with lock state

Exit: usable as the daily read-only client on the Jolla Phone; criteria 2, 3 and 4 measured and met.

### Phase 4 - Early Harbour submission

- Submit the MVP; fix QA findings before growing the feature set

Exit: criterion 1 met.

### Phase 5 - Write support and parity

- Create, edit, delete (with remorse), folders, favorites, trash
- Organizations and collections, attachments, Send, generator
- Further second factors (email, Duo, YubiKey OTP)

### Phase 6 - Differentiation

- Multiple accounts, live sync via WebSocket
- Performance work for large vaults
- Published threat model, reproducible CI builds, signed releases
- Translations
- Items from the differentiation backlog (section 3)

## 10. Security principles

- Key material lives only in RAM, in the Rust core, and is zeroized on lock
- No plaintext secret is ever written to disk or to logs
- Crypto only through audited crates, never hand-rolled primitives
- Auto-lock on timeout and on device lock; clipboard is cleared after a timeout
- Threat model is written down (`docs/threat-model.md`) before Phase 3 ships

## 11. Risks

| Risk | Mitigation |
|------|------------|
| Argon2id with high memory settings too slow or too memory-hungry on the device | Measure on the Jolla Phone in Phase 2; run off the UI thread with progress |
| Rust toolchain in the SDK target too old for planned crates | Check in Phase 1; pin crate versions |
| Bitwarden API and encryption formats change continuously | Treat maintenance as permanent work; test against new Vaultwarden releases |
| Official Bitwarden cloud may treat unknown clients differently | Test early in Phase 2; API-key login as fallback |
| BitSailor moves faster than a one-person side project | Compete on the four fields in section 3, not on feature count |
| Project goes stale after release | Keep scope small enough to maintain alone |

## 12. Open decisions

- License (must be compatible with any reference code that gets reused)
- FFI style: hand-written C API or a binding generator
- Convenience unlock after the MVP: none, PIN, or the Secrets Confirm dialog
- Final cold start targets after Phase 1 measurements

Decided:

- Session tokens (2026-10-03): refresh token stored encrypted with the user
  key, access token in RAM only; see section 6.
- Build system: qmake (2026-10-02). Sailfish default, matches the SDK
  templates; the Rust core is built by cargo from a qmake extra target and
  linked statically.
- Unlock: master password only, no fingerprint (2026-10-03). Fingerprint
  is not reachable from a Harbour app; see section 6.

## 13. References

- Harbour allowed APIs: https://docs.sailfishos.org/Develop/Apps/Harbour/Allowed_APIs/
- UI Definition of Done: https://docs.sailfishos.org/Develop/Apps/UI/Definition_of_Done/
- Fingerprint in apps (forum): https://forum.sailfishos.org/t/fingerprint-for-auth-in-apps/31428
- Fingerprint framework discussion (forum): https://forum.sailfishos.org/t/fingerprint-framework-for-developers/31678
- BitSailor support thread: https://forum.sailfishos.org/t/bitsailor-support-thread/15074
- SailWarden thread: https://forum.sailfishos.org/t/sailwarden-bitwarden-client-for-sailfish-os/30466
