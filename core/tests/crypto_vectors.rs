//! Cross-checks the core against vectors generated independently with the
//! OpenSSL CLI (`tools/gen-crypto-vectors.py`).

use sailvault_core::crypto::{
    AsymmetricEncString, CryptoError, EncString, Kdf, MasterKey, PrivateKey, SymmetricKey,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    email_input: String,
    password: String,
    pbkdf2: Pbkdf2Vectors,
    argon2id: Argon2Vectors,
    protected_user_key: String,
    legacy_protected_user_key: String,
    plaintext: String,
    enc_string: String,
    enc_string_tampered_mac: String,
    private_key_pkcs8: String,
    protected_private_key: String,
    org_key: String,
    org_key_rsa_oaep_sha1: String,
    org_key_rsa_oaep_sha256: String,
}

#[derive(Deserialize)]
struct Pbkdf2Vectors {
    iterations: u32,
    login_hash: String,
}

#[derive(Deserialize)]
struct Argon2Vectors {
    iterations: u32,
    memory_mib: u32,
    parallelism: u32,
    login_hash: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("vectors/crypto.json")).unwrap()
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

fn pbkdf2_master_key(v: &Vectors) -> MasterKey {
    Kdf::from_server(0, v.pbkdf2.iterations, None, None)
        .unwrap()
        .derive_master_key(v.password.as_bytes(), &v.email_input)
        .unwrap()
}

fn user_key(v: &Vectors) -> SymmetricKey {
    let protected: EncString = v.protected_user_key.parse().unwrap();
    pbkdf2_master_key(v).decrypt_user_key(&protected).unwrap()
}

#[test]
fn pbkdf2_login_hash_matches_openssl() {
    let v = vectors();
    let login_hash = pbkdf2_master_key(&v).login_hash(v.password.as_bytes());
    assert_eq!(*login_hash, v.pbkdf2.login_hash);
}

#[test]
fn argon2id_login_hash_matches_openssl() {
    let v = vectors();
    let kdf = Kdf::from_server(
        1,
        v.argon2id.iterations,
        Some(v.argon2id.memory_mib),
        Some(v.argon2id.parallelism),
    )
    .unwrap();
    let master_key = kdf
        .derive_master_key(v.password.as_bytes(), &v.email_input)
        .unwrap();
    assert_eq!(
        *master_key.login_hash(v.password.as_bytes()),
        v.argon2id.login_hash
    );
}

#[test]
fn stretched_master_key_decrypts_user_key() {
    let v = vectors();
    let plaintext = v
        .enc_string
        .parse::<EncString>()
        .unwrap()
        .decrypt_to_string(&user_key(&v))
        .unwrap();
    assert_eq!(*plaintext, v.plaintext);
}

#[test]
fn raw_master_key_decrypts_legacy_user_key() {
    let v = vectors();
    let protected: EncString = v.legacy_protected_user_key.parse().unwrap();
    let legacy_user_key = pbkdf2_master_key(&v).decrypt_user_key(&protected).unwrap();
    let plaintext = v
        .enc_string
        .parse::<EncString>()
        .unwrap()
        .decrypt_to_string(&legacy_user_key)
        .unwrap();
    assert_eq!(*plaintext, v.plaintext);
}

#[test]
fn tampered_mac_is_rejected() {
    let v = vectors();
    let tampered: EncString = v.enc_string_tampered_mac.parse().unwrap();
    assert_eq!(
        tampered.decrypt(&user_key(&v)).map(|_| ()),
        Err(CryptoError::MacMismatch)
    );
}

#[test]
fn mac_cannot_be_stripped_by_downgrading_to_type_0() {
    let v = vectors();
    let (iv_and_data, _mac) = v.enc_string[2..].rsplit_once('|').unwrap();
    let downgraded: EncString = format!("0.{iv_and_data}").parse().unwrap();
    assert_eq!(
        downgraded.decrypt(&user_key(&v)).map(|_| ()),
        Err(CryptoError::WrongKeyType)
    );
}

#[test]
fn private_key_decrypts_organization_keys() {
    let v = vectors();
    let der = v
        .protected_private_key
        .parse::<EncString>()
        .unwrap()
        .decrypt(&user_key(&v))
        .unwrap();
    assert_eq!(*der, hex(&v.private_key_pkcs8));
    let private_key = PrivateKey::from_pkcs8_der(&der).unwrap();

    for org_key in [&v.org_key_rsa_oaep_sha1, &v.org_key_rsa_oaep_sha256] {
        let enc_string: AsymmetricEncString = org_key.parse().unwrap();
        let decrypted = private_key.decrypt(&enc_string).unwrap();
        assert_eq!(*decrypted, hex(&v.org_key));
        assert!(SymmetricKey::from_aes_cbc_hmac_bytes(&decrypted).is_ok());
    }
}

#[test]
fn weak_or_excessive_kdf_parameters_are_rejected() {
    let invalid = [
        Kdf::from_server(0, 5_000, None, None),
        Kdf::from_server(0, 10_000_000, None, None),
        Kdf::from_server(1, 1, Some(64), Some(4)),
        Kdf::from_server(1, 3, Some(15), Some(4)),
        Kdf::from_server(1, 3, Some(2048), Some(4)),
        Kdf::from_server(1, 3, Some(64), Some(0)),
        Kdf::from_server(1, 3, None, Some(4)),
        Kdf::from_server(2, 600_000, None, None),
    ];
    for result in invalid {
        assert_eq!(result, Err(CryptoError::InvalidKdfParameters));
    }
}

#[test]
fn oversized_user_key_is_reported_as_unsupported_format() {
    assert_eq!(
        SymmetricKey::from_aes_cbc_hmac_bytes(&[0u8; 96]).map(|_| ()),
        Err(CryptoError::UnsupportedKeyFormat)
    );
    assert_eq!(
        SymmetricKey::from_aes_cbc_hmac_bytes(&[0u8; 32]).map(|_| ()),
        Err(CryptoError::InvalidKey)
    );
}
