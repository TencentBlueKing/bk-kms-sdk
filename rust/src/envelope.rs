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

//! Envelope decoding and the hybrid decryption pipeline.
//!
//! Pipeline, in order:
//!
//! 1. Reject empty inputs.
//! 2. Base64-decode the envelope and parse it as a JSON object.
//! 3. Read and validate the five required fields.
//! 4. Unwrap the 16-byte data key with the private key.
//! 5. Decrypt the payload with the data key.
//! 6. Return the payload as UTF-8 text, unmodified.

use serde_json::{Map, Value};

use crate::crypto::{self, AsymmetricAlgorithm, SymmetricAlgorithm, SymmetricMode, BLOCK_SIZE};
use crate::error::Error;

/// The five required envelope fields, borrowed from the decoded JSON.
struct Fields<'a> {
    asymmetric_type: &'a str,
    symmetric_type: &'a str,
    symmetric_mode: &'a str,
    encrypted_key: &'a str,
    ciphertext: &'a str,
}

/// Decrypts a Base64 envelope with a Base64 PEM private key.
pub(crate) fn decrypt(envelope: &str, private_key: &str) -> Result<String, Error> {
    if envelope.is_empty() {
        return Err(Error::EmptyEnvelope);
    }
    if private_key.is_empty() {
        return Err(Error::EmptyPrivateKey);
    }

    // Decode and parse the envelope. `object` must outlive the borrowed fields.
    let raw = crypto::decode_base64(envelope).map_err(Error::EnvelopeBase64)?;
    let object: Map<String, Value> = serde_json::from_slice(&raw).map_err(Error::EnvelopeJson)?;

    let fields = Fields {
        asymmetric_type: required_field(&object, AsymmetricAlgorithm::FIELD)?,
        symmetric_type: required_field(&object, SymmetricAlgorithm::FIELD)?,
        symmetric_mode: required_field(&object, SymmetricMode::FIELD)?,
        encrypted_key: required_field(&object, "encrypted_key")?,
        ciphertext: required_field(&object, "ciphertext")?,
    };

    let asymmetric = parse_asymmetric(fields.asymmetric_type)?;
    let symmetric = parse_symmetric(fields.symmetric_type)?;
    let mode = parse_mode(fields.symmetric_mode)?;

    // Unwrap the data key with the asymmetric private key.
    let data_key = crypto::decrypt_asymmetric(fields.encrypted_key, asymmetric, private_key)?;
    if data_key.len() != BLOCK_SIZE {
        return Err(Error::Ciphertext {
            algorithm: asymmetric.name(),
            source: format!("unwrapped data key must be exactly {BLOCK_SIZE} bytes").into(),
        });
    }

    // Decrypt the payload with the data key.
    let plaintext = crypto::decrypt_symmetric(fields.ciphertext, symmetric, mode, &data_key)?;

    // Return the original text without normalizing it.
    String::from_utf8(plaintext).map_err(Error::PlaintextUtf8)
}

/// Reads a field that must be a non-empty string.
fn required_field<'a>(
    object: &'a Map<String, Value>,
    name: &'static str,
) -> Result<&'a str, Error> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(Error::EnvelopeField { field: name })
}

/// Parses `asymmetric_type`.
fn parse_asymmetric(value: &str) -> Result<AsymmetricAlgorithm, Error> {
    AsymmetricAlgorithm::parse(value).ok_or_else(|| Error::UnsupportedAlgorithm {
        field: AsymmetricAlgorithm::FIELD,
        value: value.to_owned(),
    })
}

/// Parses `symmetric_type`.
fn parse_symmetric(value: &str) -> Result<SymmetricAlgorithm, Error> {
    SymmetricAlgorithm::parse(value).ok_or_else(|| Error::UnsupportedAlgorithm {
        field: SymmetricAlgorithm::FIELD,
        value: value.to_owned(),
    })
}

/// Parses `symmetric_mode`.
fn parse_mode(value: &str) -> Result<SymmetricMode, Error> {
    SymmetricMode::parse(value).ok_or_else(|| Error::UnsupportedAlgorithm {
        field: SymmetricMode::FIELD,
        value: value.to_owned(),
    })
}
