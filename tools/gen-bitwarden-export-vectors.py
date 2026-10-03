#!/usr/bin/env python3
"""Generates password-protected Bitwarden export test vectors with OpenSSL.

OpenSSL is an implementation independent of the RustCrypto crates the core
uses, so matching results cross-check the core. Python only glues the steps
together; every cryptographic operation runs in OpenSSL. The exports follow
the format in docs/bitwarden-export.md and contain only made-up data.

Usage: tools/gen-bitwarden-export-vectors.py > core/tests/vectors/bitwarden_export.json
"""

import base64
import hashlib
import json
import subprocess
import uuid

PASSWORD = "correct horse battery staple"
PBKDF2_ITERATIONS = 600_000
ARGON2_ITERATIONS = 3
ARGON2_MEMORY_MIB = 64
ARGON2_PARALLELISM = 4

VAULT = {
    "encrypted": False,
    "folders": [{"id": "6c1a4f52-3b7e-4d2a-9f0e-1a2b3c4d5e6f", "name": "Example folder"}],
    "items": [
        {
            "id": "0f8c2d1e-7a6b-4c5d-8e9f-0a1b2c3d4e5f",
            "folderId": "6c1a4f52-3b7e-4d2a-9f0e-1a2b3c4d5e6f",
            "type": 1,
            "name": "Example login äöü \U0001f510",
            "favorite": True,
            "login": {
                "username": "alice@example.org",
                "password": "example-password",
                "totp": "JBSWY3DPEHPK3PXP",
                "uris": [{"uri": "https://example.org", "match": None}],
            },
        }
    ],
}


def openssl(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(
        ["openssl", *args], input=data, capture_output=True, check=True
    ).stdout


def kdf(name: str, *options: str) -> bytes:
    args = ["kdf", "-binary", "-keylen", "32"]
    for option in options:
        args += ["-kdfopt", option]
    return openssl(*args, name)


def hkdf_expand(prk: bytes, info: str) -> bytes:
    return kdf("HKDF", "digest:SHA256", "mode:EXPAND_ONLY",
               f"hexkey:{prk.hex()}", f"info:{info}")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def enc_type2(key64: bytes, plaintext: bytes) -> str:
    iv = openssl("rand", "16")
    ciphertext = openssl("enc", "-aes-256-cbc", "-K", key64[:32].hex(),
                         "-iv", iv.hex(), data=plaintext)
    mac = openssl("mac", "-binary", "-digest", "SHA256", "-macopt",
                  f"hexkey:{key64[32:].hex()}", "HMAC", data=iv + ciphertext)
    return f"2.{b64(iv)}|{b64(ciphertext)}|{b64(mac)}"


def tamper_mac(enc_string: str) -> str:
    prefix, mac = enc_string.rsplit("|", 1)
    raw = bytearray(base64.b64decode(mac))
    raw[0] ^= 0x01
    return f"{prefix}|{b64(bytes(raw))}"


def export(derived: bytes, salt: str, kdf_fields: dict, plaintext: bytes) -> dict:
    key = hkdf_expand(derived, "enc") + hkdf_expand(derived, "mac")
    return {
        "encrypted": True,
        "passwordProtected": True,
        "salt": salt,
        **kdf_fields,
        "encKeyValidation_DO_NOT_EDIT": enc_type2(key, str(uuid.uuid4()).encode()),
        "data": enc_type2(key, plaintext),
    }


def main() -> None:
    password = PASSWORD.encode().hex()
    plaintext = json.dumps(VAULT, ensure_ascii=False).encode()

    pbkdf2_salt = b64(openssl("rand", "16"))
    pbkdf2_key = kdf("PBKDF2", "digest:SHA256", f"hexpass:{password}",
                     f"hexsalt:{pbkdf2_salt.encode().hex()}",
                     f"iter:{PBKDF2_ITERATIONS}")
    pbkdf2_export = export(pbkdf2_key, pbkdf2_salt, {
        "kdfType": 0,
        "kdfIterations": PBKDF2_ITERATIONS,
        "kdfMemory": None,
        "kdfParallelism": None,
    }, plaintext)

    argon2_salt = b64(openssl("rand", "16"))
    argon2_key = kdf("ARGON2ID", f"hexpass:{password}",
                     f"hexsalt:{hashlib.sha256(argon2_salt.encode()).hexdigest()}",
                     f"iter:{ARGON2_ITERATIONS}",
                     f"memcost:{ARGON2_MEMORY_MIB * 1024}",
                     f"lanes:{ARGON2_PARALLELISM}")
    argon2_export = export(argon2_key, argon2_salt, {
        "kdfType": 1,
        "kdfIterations": ARGON2_ITERATIONS,
        "kdfMemory": ARGON2_MEMORY_MIB,
        "kdfParallelism": ARGON2_PARALLELISM,
    }, plaintext)

    vectors = {
        "generator": "tools/gen-bitwarden-export-vectors.py with "
                     + openssl("version").decode().strip(),
        "password": PASSWORD,
        "plaintext": plaintext.decode(),
        "pbkdf2_export": pbkdf2_export,
        "argon2id_export": argon2_export,
        "data_tampered_mac": tamper_mac(pbkdf2_export["data"]),
    }
    print(json.dumps(vectors, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
