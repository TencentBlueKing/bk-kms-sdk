// TencentBlueKing is pleased to support the open source community by making
// 蓝鲸智云 - 凭证管理服务(BlueKing - Key Management Service) available.
// Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
// Licensed under the MIT License (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
// http://opensource.org/licenses/MIT
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
// language governing permissions and limitations under the License.We undertake not
// to change the open source license (MIT license) applicable to the current version
// of the project delivered to anyone in the future.

//! Interoperability and error-handling tests.
//!
//! The stored vectors were produced by the Go SDK's encryption helpers and cover all
//! eight `RSA`/`SM2` x `AES`/`SM4` x `CBC`/`CTR` combinations. Decrypting them here
//! proves that this crate accepts the same wire format as the other SDKs.

use base64::Engine as _;
use bk_kms::{decrypt, Error};
use serde_json::Value;

/// The stored fixture document, embedded at compile time.
const FIXTURES: &str = include_str!("fixtures/interop_vectors.json");

/// Encodes bytes as standard padded Base64, which is what the SDK expects.
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decodes standard padded Base64.
fn unb64(value: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .expect("fixture values must be valid Base64")
}

/// Returns the fixture document together with its expected plaintext.
fn fixtures() -> (Value, String) {
    let document: Value = serde_json::from_str(FIXTURES).expect("fixtures must be valid JSON");
    let plaintext = document["plaintext"]
        .as_str()
        .expect("fixtures must carry the expected plaintext")
        .to_owned();

    (document, plaintext)
}

/// Reads the envelope and private key of a named fixture vector.
fn vector<'a>(document: &'a Value, name: &str) -> (&'a str, &'a str) {
    let entry = &document["vectors"][name];
    (
        entry["envelope"]
            .as_str()
            .expect("envelope must be a string"),
        entry["private_key"]
            .as_str()
            .expect("private_key must be a string"),
    )
}

#[test]
fn all_eight_stored_vectors_decrypt() {
    let (document, expected) = fixtures();
    let vectors = document["vectors"]
        .as_object()
        .expect("vectors must be an object");

    assert_eq!(
        vectors.len(),
        8,
        "fixtures must cover all eight combinations"
    );

    for name in vectors.keys() {
        let (envelope, private_key) = vector(&document, name);

        let plaintext = decrypt(envelope, private_key)
            .unwrap_or_else(|err| panic!("`{name}` must decrypt, got: {err}"));

        assert_eq!(
            plaintext, expected,
            "`{name}` must return the original plaintext"
        );
    }
}

#[test]
fn rsa_pkcs8_key_decrypts_the_same_envelope() {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::RsaPrivateKey;

    let (document, expected) = fixtures();
    let (envelope, private_key) = vector(&document, "rsa_aes_cbc");

    // The stored RSA key is PKCS#1; re-encode it as PKCS#8 to cover that path too.
    let pem = String::from_utf8(unb64(private_key)).expect("the key must be UTF-8 PEM");
    let key = RsaPrivateKey::from_pkcs1_pem(&pem).expect("the fixture must be a PKCS#1 RSA key");
    let pkcs8_pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("re-encoding as PKCS#8 must succeed");

    let plaintext = decrypt(envelope, &b64(pkcs8_pem.as_bytes()))
        .expect("a PKCS#8 form of the same key must decrypt the envelope");

    assert_eq!(plaintext, expected);
}

#[test]
fn empty_inputs_are_rejected() {
    assert!(matches!(decrypt("", "key"), Err(Error::EmptyEnvelope)));
    assert!(matches!(
        decrypt("envelope", ""),
        Err(Error::EmptyPrivateKey)
    ));
}

#[test]
fn malformed_envelope_is_rejected() {
    // Not Base64 at all.
    assert!(matches!(
        decrypt("not base64!!", "key"),
        Err(Error::EnvelopeBase64(_))
    ));

    // Base64 of a payload that is not JSON.
    assert!(matches!(
        decrypt(&b64(b"not json"), "key"),
        Err(Error::EnvelopeJson(_))
    ));

    // Base64 of a JSON array instead of an object.
    assert!(matches!(
        decrypt(&b64(b"[1,2,3]"), "key"),
        Err(Error::EnvelopeJson(_))
    ));

    // A JSON object without any of the required fields.
    assert!(matches!(
        decrypt(&b64(b"{}"), "key"),
        Err(Error::EnvelopeField { .. })
    ));
}

#[test]
fn empty_field_is_rejected() {
    let envelope = b64(br#"{
            "asymmetric_type": "RSA",
            "symmetric_type": "AES",
            "symmetric_mode": "CBC",
            "encrypted_key": "",
            "ciphertext": "AAAA"
        }"#);

    match decrypt(&envelope, "key") {
        Err(Error::EnvelopeField { field }) => assert_eq!(field, "encrypted_key"),
        other => panic!("expected a missing-field error, got: {other:?}"),
    }
}

#[test]
fn unsupported_algorithm_is_rejected() {
    let envelope = b64(br#"{
            "asymmetric_type": "ECC",
            "symmetric_type": "AES",
            "symmetric_mode": "CBC",
            "encrypted_key": "AAAA",
            "ciphertext": "AAAA"
        }"#);

    match decrypt(&envelope, "key") {
        Err(Error::UnsupportedAlgorithm { field, value }) => {
            assert_eq!(field, "asymmetric_type");
            assert_eq!(value, "ECC");
        }
        other => panic!("expected an unsupported-algorithm error, got: {other:?}"),
    }
}

#[test]
fn unsupported_mode_is_rejected() {
    let envelope = b64(br#"{
            "asymmetric_type": "RSA",
            "symmetric_type": "AES",
            "symmetric_mode": "GCM",
            "encrypted_key": "AAAA",
            "ciphertext": "AAAA"
        }"#);

    match decrypt(&envelope, "key") {
        Err(Error::UnsupportedAlgorithm { field, value }) => {
            assert_eq!(field, "symmetric_mode");
            assert_eq!(value, "GCM");
        }
        other => panic!("expected an unsupported-algorithm error, got: {other:?}"),
    }
}

#[test]
fn mismatched_private_key_is_rejected() {
    let (document, _) = fixtures();
    let (envelope, _) = vector(&document, "rsa_aes_cbc");
    let (_, sm2_key) = vector(&document, "sm2_sm4_cbc");

    // An SM2 key cannot decode an RSA envelope.
    assert!(matches!(
        decrypt(envelope, sm2_key),
        Err(Error::PrivateKey { .. })
    ));
}

#[test]
fn corrupted_ciphertext_is_rejected() {
    let (document, _) = fixtures();
    let (envelope, private_key) = vector(&document, "rsa_aes_cbc");

    // Keep the envelope well formed but truncate the payload.
    let mut payload: Value =
        serde_json::from_slice(&unb64(envelope)).expect("the envelope must be JSON");
    payload["ciphertext"] = Value::String(b64(b"short"));

    let tampered = b64(&serde_json::to_vec(&payload).expect("the envelope must re-encode"));
    assert!(matches!(
        decrypt(&tampered, private_key),
        Err(Error::Ciphertext { .. })
    ));
}

#[test]
fn errors_do_not_leak_secrets() {
    let (document, _) = fixtures();
    let (envelope, _) = vector(&document, "rsa_aes_cbc");
    let (_, sm2_key) = vector(&document, "sm2_sm4_cbc");

    let err = decrypt(envelope, sm2_key).expect_err("the keys must not match");
    let rendered = err.to_string();

    assert!(
        !rendered.contains(sm2_key),
        "the error must not embed the private key"
    );
    assert!(
        !rendered.contains(envelope),
        "the error must not embed the envelope"
    );
}

#[test]
fn error_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
}

#[test]
fn non_utf8_plaintext_is_rejected() {
    use aes::Aes128;
    use cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr128BE;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::rand_core::{OsRng, RngCore};
    use rsa::{Oaep, RsaPrivateKey};
    use sha2::Sha256;

    let (document, _) = fixtures();
    let (_, private_key) = vector(&document, "rsa_aes_cbc");

    // Load the stored key and use its public half to build a fresh envelope.
    let pem = String::from_utf8(unb64(private_key)).expect("the key must be UTF-8 PEM");
    let key = RsaPrivateKey::from_pkcs1_pem(&pem).expect("the fixture must be a PKCS#1 RSA key");

    // A payload that is deliberately not valid UTF-8.
    let payload: &[u8] = &[0xff, 0xfe, 0xfd];
    let mut data_key = [0u8; 16];
    OsRng.fill_bytes(&mut data_key);

    // AES-128-CTR over `IV || ciphertext`, exactly as the wire format specifies.
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let mut buffer = payload.to_vec();
    Ctr128BE::<Aes128>::new_from_slices(&data_key, &iv)
        .expect("the data key and IV are 16 bytes")
        .apply_keystream(&mut buffer);

    let mut framed = iv.to_vec();
    framed.extend_from_slice(&buffer);

    let mut rng = OsRng;
    let encrypted_key = key
        .to_public_key()
        .encrypt(&mut rng, Oaep::new::<Sha256>(), &data_key)
        .expect("the data key must encrypt");

    let envelope = b64(serde_json::to_vec(&serde_json::json!({
        "asymmetric_type": "RSA",
        "symmetric_type": "AES",
        "symmetric_mode": "CTR",
        "encrypted_key": b64(&encrypted_key),
        "ciphertext": b64(&framed),
    }))
    .expect("the envelope must serialize")
    .as_slice());

    assert!(matches!(
        decrypt(&envelope, private_key),
        Err(Error::PlaintextUtf8(_))
    ));
}
