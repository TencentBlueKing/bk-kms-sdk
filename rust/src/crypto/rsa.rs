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

//! RSA-OAEP (SHA-256) decryption of the wrapped data key.
//!
//! Matches the Go, Python, and C++ SDKs: OAEP with SHA-256 for both the digest and
//! MGF1, no label, and no segmented encryption. Private keys are Base64-encoded PEM
//! and may be PKCS#8 (`BEGIN PRIVATE KEY`) or PKCS#1 (`BEGIN RSA PRIVATE KEY`).

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, RsaPrivateKey};
use sha2::Sha256;

use super::decode_base64;
use crate::error::Error;

/// Algorithm name used in error messages.
pub(crate) const NAME: &str = "RSA";

/// Decrypts the Base64 `encrypted_key` with a Base64 PEM private key.
pub(crate) fn decrypt(encrypted_key: &str, private_key: &str) -> Result<Vec<u8>, Error> {
    let ciphertext = decode_base64(encrypted_key).map_err(|source| Error::Ciphertext {
        algorithm: NAME,
        source: Box::new(source),
    })?;

    let pem = decode_private_key(private_key)?;
    let key = parse_private_key(&pem)?;

    key.decrypt(Oaep::new::<Sha256>(), &ciphertext)
        .map_err(|source| Error::Ciphertext {
            algorithm: NAME,
            source: Box::new(source),
        })
}

/// Decodes the Base64 wrapper to obtain the PEM text.
fn decode_private_key(private_key: &str) -> Result<String, Error> {
    let raw = decode_base64(private_key).map_err(|source| Error::PrivateKey {
        algorithm: NAME,
        source: Box::new(source),
    })?;

    String::from_utf8(raw).map_err(|source| Error::PrivateKey {
        algorithm: NAME,
        source: Box::new(source),
    })
}

/// Accepts either PKCS#8 or PKCS#1 PEM, mirroring the other SDKs.
fn parse_private_key(pem: &str) -> Result<RsaPrivateKey, Error> {
    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(pem) {
        return Ok(key);
    }

    RsaPrivateKey::from_pkcs1_pem(pem).map_err(|source| Error::PrivateKey {
        algorithm: NAME,
        source: Box::new(source),
    })
}
