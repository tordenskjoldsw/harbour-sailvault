# Bitwarden export format

Reference for importing Bitwarden/Vaultwarden exports. Verified on
2026-10-03 against source code:

- bitwarden/clients main `245879a` (`cl/`), export services and models
- bitwarden/sdk-internal main `7227e92` (`sdk/`), reference crypto
- KeePassXC `9e0f57a` (`kpxc/`), `src/format/BitwardenReader.cpp`

The Bitwarden server protocol notes from the shelved client direction are in
git history (`docs/protocol.md` before 2026-10-03).

## Export kinds

| Kind | Marker | Import |
|------|--------|--------|
| Unencrypted JSON | `"encrypted": false` | Supported; warn that the file is plaintext |
| Password-protected JSON | `"encrypted": true, "passwordProtected": true` | Supported |
| Account-restricted JSON | `"encrypted": true` without `passwordProtected` | Rejected: fields are encrypted with the user key, which only the server can unwrap |
| CSV | header row | Optional later; logins and notes only, custom fields lossy |

## Password-protected JSON

Top level (`cl/libs/tools/export/.../base-vault-export.service.ts:21-50`):
`encrypted`, `passwordProtected`, `salt`, `kdfType`, `kdfIterations`,
`kdfMemory`, `kdfParallelism`, `encKeyValidation_DO_NOT_EDIT`, `data`.

Key derivation (`sdk/crates/bitwarden-exporters/src/encrypted_json.rs:47-49`,
`sdk/crates/bitwarden-crypto/src/keys/kdf.rs:33-76`, `keys/utils.rs:12-19`):

1. `salt` is 16 random bytes, base64-encoded. The KDF salt is the UTF-8 bytes
   of that base64 string; it is not decoded.
2. `kdfType` 0: PBKDF2-HMAC-SHA256 over the password, 32 bytes.
   `kdfType` 1: Argon2id v0x13, salt = SHA-256(salt string), memory in MiB
   (times 1024 for KiB), 32 bytes.
3. Stretch with HKDF-Expand-SHA256 (no Extract): `enc` = info "enc",
   `mac` = info "mac", 32 bytes each.
4. `encKeyValidation_DO_NOT_EDIT` (a random UUID) and `data` (the
   unencrypted JSON export) are EncString type 2 under that key. A MAC
   failure on the validation value means a wrong password.

KDF parameters follow the account's settings. Accepted ranges in the core:
PBKDF2 5000 to 5000000 iterations; Argon2id 1 to 10 iterations, 15 to 1024
MiB, parallelism 1 to 16 (lower bounds from Bitwarden/Vaultwarden account
limits, upper bounds against crafted files).

## EncString type 2

`2.<iv>|<data>|<mac>` with standard base64, padding optional
(`sdk/crates/bitwarden-crypto/src/enc_string/symmetric.rs`). AES-256-CBC
with PKCS7 padding; MAC = HMAC-SHA256(mac key, iv || data), checked in
constant time before decrypting. Other types do not appear in exports.

## Unencrypted JSON

Top level (`cl/libs/tools/export-vault-core/src/types/bitwarden-json-export-types.ts`):
`encrypted: false`, `folders[{id, name}]` (personal) or
`collections[{id, organizationId, name, externalId}]` (organization),
`items[]`.

Item (`cl/libs/common/src/models/export/cipher.export.ts:184-206`): `id`,
`organizationId`, `folderId`, `collectionIds`, `type`, `name`, `notes`,
`favorite`, `fields[{name, value, type, linkedId}]`, `reprompt`,
`passwordHistory[{password, lastUsedDate}]`, `revisionDate`,
`creationDate`, `deletedDate`, `archivedDate`, `key`.

- `type`: 1 login, 2 secure note, 3 card, 4 identity, 5 SSH key, 6 bank
  account, 7 driver's license, 8 passport
- Field `type`: 0 text, 1 hidden, 2 boolean, 3 linked
- `login`: `uris[{uri, match}]`, `username`, `password`, `totp`,
  `fido2Credentials[...]`
- `card`: `cardholderName`, `brand`, `number`, `expMonth`, `expYear`, `code`
- `identity`: 18 fields (`identity.export.ts:77-94`)
- `sshKey`: `privateKey`, `publicKey`, `keyFingerprint`
- The zip export adds an `attachments/` folder (personal vault only)

## Mapping to KDBX

Follow KeePassXC's `BitwardenReader.cpp:44-262`, so imported databases match
what KeePassXC itself produces:

- Title, UserName, Password, Notes map directly; first URI to URL, further
  URIs to `KP2A_URL_n`
- `totp` becomes an `otpauth://` URI in the protected `otp` attribute
- `fido2Credentials` become `KPEX_PASSKEY_*` attributes
- `favorite` becomes the tag `Favorite`
- Card and identity fields become `card_*` and `identity_*` attributes,
  sensitive ones protected
- Hidden custom fields become protected attributes
- `passwordHistory` becomes entry history
- `revisionDate` and `creationDate` become entry times
- Folder path `a/b` becomes nested groups; collections are used when there
  are no folders

Unverified in KeePassXC's reader: SSH keys and types 6 to 8. Decide their
mapping when implementing the import.
