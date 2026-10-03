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
- `bankAccount`: `bankName`, `nameOnAccount`, `accountType`,
  `accountNumber`, `routingNumber`, `branchNumber`, `pin`, `swiftCode`,
  `iban`, `bankContactPhone` (`bank-account.export.ts`)
- `driversLicense`: `firstName`, `middleName`, `lastName`, `dateOfBirth`,
  `licenseNumber`, `issuingCountry`, `issuingState`, `issueDate`,
  `expirationDate`, `issuingAuthority`, `licenseClass`
  (`drivers-license.export.ts`)
- `passport`: `surname`, `givenName`, `dateOfBirth`, `sex`, `birthPlace`,
  `nationality`, `issuingCountry`, `passportNumber`, `passportType`,
  `nationalIdentificationNumber`, `issuingAuthority`, `issueDate`,
  `expirationDate` (`passport.export.ts`)
- Items in the trash are not exported: the export services keep only
  ciphers with `deletedDate == null`
  (`cl/libs/tools/export-vault-core/src/services/individual-vault-export.service.ts`,
  `org-vault-export.service.ts`)
- The zip export adds an `attachments/` folder (personal vault only)

## Mapping to KDBX

SailVault follows KeePassXC's `BitwardenReader.cpp` (`kpxc/src/format/
BitwardenReader.cpp`, `readItem` and `createGroup`), so imported entries
match what KeePassXC produces. The import goes into the group "Bitwarden
import" of the open database instead of a new database.

Importing again merges, following KeePassXC's `Merger.cpp`
(`resolveEntryConflict_MergeHistories`, `mergeHistory`):

- The item `id` (a UUID) becomes the entry UUID, and the entry's CustomData
  records `SailVault/ImportedFrom = Bitwarden`. A later import matches only
  entries with that UUID and that record, wherever they are now; entries
  moved out of the import group stay where they are. An item whose ID
  equals the UUID of any other entry is added as a new entry with a random
  UUID, so a crafted export cannot change entries it did not create.
  KeePassXC's importer draws random UUIDs, so its imports cannot be merged
  this way
- Creation and modification times in the future count as the import time;
  otherwise a crafted date would win every later merge
- The newer side by modification time wins; the other becomes a history
  item. History items are combined by modification time. The same file
  imported twice changes nothing
- Unlike KeePassXC, fields and attachments that only the database has are
  kept when the import wins; they also stay in the history item
- Entries in the recycle bin or under `DeletedObjects` stay deleted, and
  entries missing from the export are never removed
- Folders are matched by name below the import group

- `name`, `notes`, `login.username` and `login.password` become Title,
  Notes, UserName and Password; the first URI becomes URL, further URIs
  `KP2A_URL_1`, `KP2A_URL_2` and so on
- `favorite` becomes the tag `Favorite`; a passkey adds the tag `Passkey`
- A passkey becomes `KPEX_PASSKEY_CREDENTIAL_ID` (unpadded base64url),
  `KPEX_PASSKEY_PRIVATE_KEY_PEM` (single-line PEM), `KPEX_PASSKEY_USERNAME`,
  `KPEX_PASSKEY_RELYING_PARTY` and `KPEX_PASSKEY_USER_HANDLE`; ID, key and
  user handle are protected. With several passkeys the last one wins, as in
  KeePassXC
- `identity`: `identity_name` (title, first, middle and last name),
  `identity_address` (address lines, then "city, state postal code", then
  country), `identity_company`, `_email`, `_phone`, `_ssn`,
  `_passportNumber`, `_licenseNumber` (the last three protected); its
  `username` becomes UserName, or `identity_username` when UserName is set
- `card`: `card_` plus the field name; `code` is protected
- Custom fields keep their name; hidden fields (type 1) are protected
- `passwordHistory` items with a password and a valid `lastUsedDate`
  become history items with the entry's other standard fields
- `creationDate` becomes the creation time, `revisionDate` the
  modification and access time
- Folder (or, without one, first collection) `a/b` becomes nested groups;
  an existing path is reused; items without a known folder stay in the
  import group

Where SailVault differs, and why:

- TOTP: an `otpauth://` value is kept as it is (KeePassXC rewrites it and
  drops the issuer); a bare secret becomes the URL KeePassXC's
  `Totp::writeSettings` writes; `steam://` secrets become KeePassXC's Steam
  form (`digits=5`, `encoder=steam`), which KeePassXC's importer breaks.
  SailVault stores the value and generates no codes (`PLAN.md` section 4)
- `card_number` is protected as well as `card_code`
- `identity_name` and `identity_address` are only written when they have
  content; KeePassXC writes them empty
- A taken custom field name gets `_2`, `_3` and so on instead of five random
  characters; an empty name becomes `field`
- Passkey IDs in Bitwarden's `b64.` form (`credential-id-utils.ts`) are
  converted; KeePassXC reads them as hex and loses them
- `sshKey`, `bankAccount`, `driversLicense` and `passport`, which KeePassXC
  ignores, keep every field as `sshKey_`, `bankAccount_`, `driversLicense_`
  or `passport_` plus the field name. Protected: `privateKey`;
  `accountNumber`, `pin`, `iban`; `licenseNumber`; `passportNumber`,
  `nationalIdentificationNumber`
- Times without a UTC offset count as UTC (Qt reads them as local time);
  Bitwarden always writes `Z`
- Folder paths deeper than 32 levels are refused: the KDBX reader bounds
  XML nesting, so a deeper tree could not be read back
