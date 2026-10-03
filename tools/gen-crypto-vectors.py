#!/usr/bin/env python3
"""Generates crypto test vectors for core/ with the OpenSSL CLI.

OpenSSL is an implementation independent of the RustCrypto crates the core
uses, so matching results cross-check the core. Python only glues the steps
together; every cryptographic operation runs in OpenSSL. Keys are random
test material and protect nothing.

Usage: tools/gen-crypto-vectors.py > core/tests/vectors/crypto.json
"""

import base64
import hashlib
import json
import subprocess

EMAIL_INPUT = "  SailVault.Test@Example.COM "
EMAIL = EMAIL_INPUT.strip().lower()
PASSWORD = "correct horse battery staple"
PBKDF2_ITERATIONS = 600_000
ARGON2_ITERATIONS = 3
ARGON2_MEMORY_MIB = 64
ARGON2_PARALLELISM = 4
PLAINTEXT = "SailVault test plaintext äöü \U0001f510"


def openssl(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(
        ["openssl", *args], input=data, capture_output=True, check=True
    ).stdout


def kdf(name: str, *options: str, length: int = 32) -> bytes:
    args = ["kdf", "-binary", "-keylen", str(length)]
    for option in options:
        args += ["-kdfopt", option]
    return openssl(*args, name)


def pbkdf2(password_hex: str, salt_hex: str, iterations: int) -> bytes:
    return kdf("PBKDF2", "digest:SHA256", f"hexpass:{password_hex}",
               f"hexsalt:{salt_hex}", f"iter:{iterations}")


def hkdf_expand(prk: bytes, info: str) -> bytes:
    return kdf("HKDF", "digest:SHA256", "mode:EXPAND_ONLY",
               f"hexkey:{prk.hex()}", f"info:{info}")


def argon2id(password: bytes, salt: bytes) -> bytes:
    return kdf("ARGON2ID", f"hexpass:{password.hex()}", f"hexsalt:{salt.hex()}",
               f"iter:{ARGON2_ITERATIONS}", f"memcost:{ARGON2_MEMORY_MIB * 1024}",
               f"lanes:{ARGON2_PARALLELISM}")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def aes_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return openssl("enc", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex(),
                   data=plaintext)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return openssl("mac", "-binary", "-digest", "SHA256", "-macopt",
                   f"hexkey:{key.hex()}", "HMAC", data=data)


def enc_type2(key64: bytes, plaintext: bytes) -> str:
    iv = openssl("rand", "16")
    ciphertext = aes_cbc(key64[:32], iv, plaintext)
    mac = hmac_sha256(key64[32:], iv + ciphertext)
    return f"2.{b64(iv)}|{b64(ciphertext)}|{b64(mac)}"


def enc_type0(key32: bytes, plaintext: bytes) -> str:
    iv = openssl("rand", "16")
    return f"0.{b64(iv)}|{b64(aes_cbc(key32, iv, plaintext))}"


def tamper_mac(enc_string: str) -> str:
    prefix, mac = enc_string.rsplit("|", 1)
    raw = bytearray(base64.b64decode(mac))
    raw[0] ^= 0x01
    return f"{prefix}|{b64(bytes(raw))}"



def main() -> None:
    email_salt = EMAIL.encode().hex()
    password = PASSWORD.encode()

    pbkdf2_master_key = pbkdf2(password.hex(), email_salt, PBKDF2_ITERATIONS)
    argon2_master_key = argon2id(password, hashlib.sha256(EMAIL.encode()).digest())
    stretched = hkdf_expand(pbkdf2_master_key, "enc") + hkdf_expand(pbkdf2_master_key, "mac")

    user_key = openssl("rand", "64")

    enc_plaintext = enc_type2(user_key, PLAINTEXT.encode())

    vectors = {
        "generator": "tools/gen-crypto-vectors.py with "
                     + openssl("version").decode().strip(),
        "email_input": EMAIL_INPUT,
        "password": PASSWORD,
        "pbkdf2": {
            "iterations": PBKDF2_ITERATIONS,
            "master_key": pbkdf2_master_key.hex(),
            "login_hash": b64(pbkdf2(pbkdf2_master_key.hex(), password.hex(), 1)),
            "stretched_key": stretched.hex(),
        },
        "argon2id": {
            "iterations": ARGON2_ITERATIONS,
            "memory_mib": ARGON2_MEMORY_MIB,
            "parallelism": ARGON2_PARALLELISM,
            "master_key": argon2_master_key.hex(),
            "login_hash": b64(pbkdf2(argon2_master_key.hex(), password.hex(), 1)),
        },
        "user_key": user_key.hex(),
        "protected_user_key": enc_type2(stretched, user_key),
        "legacy_protected_user_key": enc_type0(pbkdf2_master_key, user_key),
        "plaintext": PLAINTEXT,
        "enc_string": enc_plaintext,
        "enc_string_tampered_mac": tamper_mac(enc_plaintext),
    }
    print(json.dumps(vectors, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
