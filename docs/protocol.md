# Bitwarden protocol notes

Verified on 2026-10-03 against source code, not against documentation:

- Vaultwarden tag `1.37.3` (`vw/`), the server version of the test instance
- bitwarden/sdk-internal main `7227e92` (`sdk/`), reference crypto implementation
- bitwarden/clients main `245879a` (`cl/`)
- bitwarden/server main `3ff73a5` (`srv/`)

The Security Whitepaper was not compared yet. Paths are relative to each
repository. Re-verify when the target server version changes.

## Prelogin

- `POST /identity/accounts/prelogin` (also `/api/accounts/prelogin`), body
  `{"email": "..."}` (`vw/src/api/identity.rs:1058`,
  `vw/src/api/core/accounts.rs:1336-1369`).
- Response (camelCase): `kdf`, `kdfIterations`, `kdfMemory`,
  `kdfParallelism`. Unknown emails get the defaults (PBKDF2, 600000), so the
  response does not reveal whether an account exists.
- KDF type: 0 = PBKDF2-SHA256, 1 = Argon2id (`vw/src/db/models/user.rs:89`).
- Vaultwarden limits: PBKDF2 >= 100000 iterations; Argon2 iterations >= 1,
  memory 15-1024 MiB, parallelism 1-16 (`accounts.rs:665-694`). The SDK is
  stricter (Argon2 iterations >= 2, memory >= 16 MiB,
  `sdk/crates/bitwarden-crypto/src/keys/kdf.rs:14-18`).

## Key derivation (`sdk/crates/bitwarden-crypto/src/keys/`)

- Salt: UTF-8 of `email.trim().to_lowercase()` (`kdf.rs:93-98`).
- PBKDF2: HMAC-SHA256, 32-byte master key.
- Argon2id: version 0x13, 32-byte output, salt = SHA-256(normalized email),
  memory sent in MiB, converted to KiB (`kdf.rs:51-74`).
- Login hash: `PBKDF2-SHA256(password = master key, salt = master password,
  iterations = 1)`, base64 (`master_key.rs:81-85`).
- Stretched master key: `HKDF-Expand-SHA256(master key, "enc", 32) ||
  HKDF-Expand-SHA256(master key, "mac", 32)`, no Extract step
  (`keys/utils.rs:12-19`).

## EncString

Symmetric (`enc_string/symmetric.rs`):

| Type | Layout | Algorithm | Status |
|------|--------|-----------|--------|
| 0 | `0.iv\|ct` | AES-256-CBC, no MAC | legacy, decrypt only |
| 2 | `2.iv\|ct\|mac` | AES-256-CBC + HMAC-SHA256 | current |
| 7 | `7.<base64 CBOR>` | COSE Encrypt0 | V2 accounts, not sent by Vaultwarden 1.37.3 |

- No prefix: 3 parts means type 1 (no longer parsed), otherwise type 0.
- Type 2: key = enc(32) || mac(32); MAC = HMAC-SHA256(mac, iv || ct), checked
  in constant time before decrypting; PKCS7 padding.
- Base64: standard alphabet, padding optional.

Asymmetric (`enc_string/asymmetric.rs`): 3 = RSA-2048 OAEP SHA-256,
4 = RSA-2048 OAEP SHA-1 (the only one produced today), 5 and 6 = deprecated
variants with HMAC.

Key chain:

1. `Key` (user key) is a type 2 EncString under the stretched master key
   (type 0 under the raw master key for legacy accounts). Plaintext: 64 bytes.
2. `PrivateKey` is a type 2 EncString under the user key; plaintext is a
   PKCS#8 DER RSA-2048 key.
3. `profile.organizations[].key` is an asymmetric EncString (normally type 4)
   decrypted with the private key; plaintext: 64-byte organization key.
4. A cipher with a `key` field: that field is decrypted with the user or
   organization key, and all fields of the cipher use the resulting key.

## Login (`POST /identity/connect/token`, form-urlencoded)

- Password grant: `grant_type=password`, `username`, `password` (login hash),
  `scope=api offline_access`, `client_id`, `deviceType`, `deviceIdentifier`,
  `deviceName`; optional `twoFactorToken`, `twoFactorProvider`,
  `twoFactorRemember` (`vw/src/api/identity.rs:76-86`).
- API key: `grant_type=client_credentials`, `client_id=user.<uuid>`,
  `client_secret`, `scope=api`, device fields. No refresh token is returned.
- Refresh: `grant_type=refresh_token`, `refresh_token`, `client_id`; invalid
  token returns 400 `invalid_grant`.
- Headers: `Bitwarden-Client-Name`, `Bitwarden-Client-Version` (semver),
  `Device-Type`.
- `deviceIdentifier`: any non-empty string; clients use a UUID generated once
  and persisted.
- Cloud `client_id` must be one of `web`, `browser`, `desktop`, `mobile`,
  `cli`, `connector`.
- `deviceType` has no Linux mobile value; 8 = LinuxDesktop.

## Two-factor

- Required: HTTP 400 with `TwoFactorProviders2` map
  (`vw/src/api/identity.rs:945-1055`).
- Providers: 0 Authenticator, 1 Email, 2 Duo, 3 YubiKey, 4 U2F, 5 Remember,
  6 OrganizationDuo, 7 WebAuthn, 8 RecoveryCode.
- Retry the token request with `twoFactorToken`, `twoFactorProvider`,
  `twoFactorRemember`. With remember, the response has `TwoFactorToken`,
  later sent as provider 5.
- Email code: `POST /api/two-factor/send-email-login` with `email`,
  `masterPasswordHash`, `deviceIdentifier`. Clients >= 2025.5.0 must call it
  explicitly.
- Cloud only: new device verification (`newDeviceOtp`).

## Tokens (`vw/src/api/identity.rs:510-605`, `vw/src/auth.rs`)

- Response: `access_token`, `expires_in`, `refresh_token`, `Key`,
  `PrivateKey`, `Kdf*`, `UserDecryptionOptions` (PascalCase), optional
  `TwoFactorToken`.
- Vaultwarden: access token 2 h; refresh token 30 days (90 days for device
  types 0 and 1), renewed on each refresh (sliding).
- Cloud: access token 1 h; refresh token sliding 30 days (desktop) or 60 days
  (mobile).

## Sync (`GET /api/sync?excludeDomains=true`)

- Top level: `profile`, `folders`, `collections`, `policies`, `ciphers`,
  `sends`, `userDecryption` (`vw/src/api/core/ciphers.rs:121-205`).
- Without `Bitwarden-Client-Version` >= 2024.12.0, Vaultwarden omits SSH key
  ciphers (`ciphers.rs:128-134`).
- Cipher types: 1 login, 2 secure note, 3 card, 4 identity, 5 SSH key,
  6 bank account, 7 driver's license, 8 passport.
- EncString fields: `name`, `notes`, `login.{username,password,totp,uris[].uri}`,
  `fields[].{name,value}`, all `card.*` and `identity.*` strings,
  `sshKey.{privateKey,publicKey,keyFingerprint}`, `passwordHistory[].password`.
- `login.totp`: raw secret or `otpauth://` URI.
- Custom field types: 0 text, 1 hidden, 2 boolean, 3 linked.
- Cipher state: `favorite`, `folderId`, `collectionIds`, `organizationId`,
  `deletedDate`, `reprompt`.
