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

//! SM2 decryption of the wrapped data key.
//!
//! Ciphertext is ASN.1 DER (`SEQUENCE { x INTEGER, y INTEGER, c3 OCTET STRING,
//! c2 OCTET STRING }`), matching Go's `sm2.EncryptASN1`. Private keys are
//! Base64-encoded PKCS#8 PEM. The implementation is pure Rust, so no platform-specific
//! GM backend is needed.

use sm2::elliptic_curve::pkcs8::DecodePrivateKey;
use sm2::pke::DecryptingKey;
use sm2::SecretKey;

use super::decode_base64;
use crate::error::Error;

/// Algorithm name used in error messages.
pub(crate) const NAME: &str = "SM2";

/// Decrypts the Base64 `encrypted_key` with a Base64 PEM PKCS#8 private key.
pub(crate) fn decrypt(encrypted_key: &str, private_key: &str) -> Result<Vec<u8>, Error> {
    let ciphertext = decode_base64(encrypted_key).map_err(|source| Error::Ciphertext {
        algorithm: NAME,
        source: Box::new(source),
    })?;

    let pem = decode_private_key(private_key)?;
    let secret_key = SecretKey::from_pkcs8_pem(&pem).map_err(|source| Error::PrivateKey {
        algorithm: NAME,
        source: Box::new(source),
    })?;

    DecryptingKey::new(secret_key)
        .decrypt_der(&ciphertext)
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
