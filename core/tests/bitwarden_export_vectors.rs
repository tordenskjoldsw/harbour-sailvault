//! Cross-checks export decryption against password-protected exports
//! generated independently with the OpenSSL CLI
//! (`tools/gen-bitwarden-export-vectors.py`).

use sailvault_core::bitwarden::{
    export_kind, read_export, EncString, ExportKind, ImportError, Kdf, SymmetricKey,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    password: String,
    plaintext: String,
    pbkdf2_export: Export,
    argon2id_export: Export,
    data_tampered_mac: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Export {
    salt: String,
    kdf_type: u32,
    kdf_iterations: u32,
    kdf_memory: Option<u32>,
    kdf_parallelism: Option<u32>,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT")]
    enc_key_validation: String,
    data: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("vectors/bitwarden_export.json")).unwrap()
}

fn export_key(export: &Export, password: &str) -> SymmetricKey {
    Kdf::from_export(
        export.kdf_type,
        export.kdf_iterations,
        export.kdf_memory,
        export.kdf_parallelism,
    )
    .unwrap()
    .derive_export_key(password.as_bytes(), &export.salt)
    .unwrap()
}

fn assert_decrypts(export: &Export, v: &Vectors) {
    let key = export_key(export, &v.password);
    let validation: EncString = export.enc_key_validation.parse().unwrap();
    assert!(validation.decrypt(&key).is_ok());
    let data = export
        .data
        .parse::<EncString>()
        .unwrap()
        .decrypt_to_string(&key)
        .unwrap();
    assert_eq!(*data, v.plaintext);
}

#[test]
fn pbkdf2_export_decrypts() {
    let v = vectors();
    assert_decrypts(&v.pbkdf2_export, &v);
}

#[test]
fn argon2id_export_decrypts() {
    let v = vectors();
    assert_decrypts(&v.argon2id_export, &v);
}

#[test]
fn wrong_password_fails_validation() {
    let v = vectors();
    let key = export_key(&v.pbkdf2_export, "wrong password");
    let validation: EncString = v.pbkdf2_export.enc_key_validation.parse().unwrap();
    assert_eq!(
        validation.decrypt(&key).map(|_| ()),
        Err(ImportError::MacMismatch)
    );
}

#[test]
fn tampered_mac_is_rejected() {
    let v = vectors();
    let key = export_key(&v.pbkdf2_export, &v.password);
    let tampered: EncString = v.data_tampered_mac.parse().unwrap();
    assert_eq!(
        tampered.decrypt(&key).map(|_| ()),
        Err(ImportError::MacMismatch)
    );
}

#[test]
fn out_of_range_kdf_parameters_are_rejected() {
    for result in [
        Kdf::from_export(0, 4_999, None, None),
        Kdf::from_export(0, 10_000_000, None, None),
        Kdf::from_export(1, 0, Some(64), Some(4)),
        Kdf::from_export(1, 3, Some(14), Some(4)),
        Kdf::from_export(1, 3, Some(2048), Some(4)),
        Kdf::from_export(1, 3, Some(64), Some(0)),
        Kdf::from_export(1, 3, None, Some(4)),
        Kdf::from_export(2, 600_000, None, None),
    ] {
        assert_eq!(result, Err(ImportError::InvalidKdfParameters));
    }
}

fn export_file(name: &str) -> Vec<u8> {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("vectors/bitwarden_export.json")).unwrap();
    serde_json::to_vec(&vectors[name]).unwrap()
}

#[test]
fn password_protected_exports_read_as_their_plaintext_vault() {
    let v = vectors();
    for name in ["pbkdf2_export", "argon2id_export"] {
        let file = export_file(name);
        assert_eq!(export_kind(&file), Ok(ExportKind::PasswordProtected));
        let vault = read_export(&file, Some(v.password.as_bytes())).unwrap();
        assert_eq!(vault.folders.len(), 1);
        assert_eq!(vault.folders[0].name.as_str(), "Example folder");
        let item = &vault.items[0];
        assert_eq!(item.name.as_str(), "Example login äöü 🔐");
        assert_eq!(item.folder(), vault.folders[0].id.as_str());
        assert!(item.favorite);
        let login = item.login.as_ref().unwrap();
        assert_eq!(login.username.as_str(), "alice@example.org");
        assert_eq!(login.password.as_str(), "example-password");
        assert_eq!(login.totp.as_str(), "JBSWY3DPEHPK3PXP");
        assert_eq!(login.uris[0].uri.as_str(), "https://example.org");
    }
    let plain = read_export(v.plaintext.as_bytes(), None).unwrap();
    assert_eq!(plain.items.len(), 1);
}

#[test]
fn wrong_password_and_tampered_data_are_told_apart() {
    let file = export_file("pbkdf2_export");
    assert_eq!(
        read_export(&file, Some(b"wrong password")).map(|_| ()),
        Err(ImportError::WrongPassword)
    );
    let mut export: serde_json::Value = serde_json::from_slice(&file).unwrap();
    export["data"] = serde_json::Value::String(vectors().data_tampered_mac);
    let tampered = serde_json::to_vec(&export).unwrap();
    assert_eq!(
        read_export(&tampered, Some(vectors().password.as_bytes())).map(|_| ()),
        Err(ImportError::MacMismatch)
    );
}
