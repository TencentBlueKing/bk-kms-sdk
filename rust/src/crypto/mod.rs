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

//! Algorithm dispatch for the hybrid envelope.
//!
//! The envelope names an asymmetric algorithm, a symmetric algorithm, and a
//! symmetric mode. This module parses those identifiers and routes the work to the
//! matching implementation. Identifiers are matched case-sensitively against the
//! values agreed with the KMS service.

pub(crate) mod aes;
pub(crate) mod rsa;
pub(crate) mod sm2;
pub(crate) mod sm4;

use crate::error::Error;

/// Asymmetric algorithm used to wrap the symmetric data key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AsymmetricAlgorithm {
    /// RSA-OAEP with SHA-256.
    Rsa,
    /// SM2 public key encryption with ASN.1 ciphertext.
    Sm2,
}

impl AsymmetricAlgorithm {
    /// Envelope field name carrying this identifier.
    pub(crate) const FIELD: &'static str = "asymmetric_type";

    /// Parses the envelope identifier, returning `None` when unsupported.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "RSA" => Some(Self::Rsa),
            "SM2" => Some(Self::Sm2),
            _ => None,
        }
    }

    /// Canonical name used in error messages.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Rsa => "RSA",
            Self::Sm2 => "SM2",
        }
    }
}

/// Symmetric algorithm used to encrypt the credential payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SymmetricAlgorithm {
    /// AES with a 16-byte key.
    Aes,
    /// SM4 with a 16-byte key.
    Sm4,
}

impl SymmetricAlgorithm {
    /// Envelope field name carrying this identifier.
    pub(crate) const FIELD: &'static str = "symmetric_type";

    /// Parses the envelope identifier, returning `None` when unsupported.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "AES" => Some(Self::Aes),
            "SM4" => Some(Self::Sm4),
            _ => None,
        }
    }
}

/// Block cipher mode of operation for the symmetric payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SymmetricMode {
    /// CBC with PKCS#7 padding.
    Cbc,
    /// CTR with no padding.
    Ctr,
}

impl SymmetricMode {
    /// Envelope field name carrying this identifier.
    pub(crate) const FIELD: &'static str = "symmetric_mode";

    /// Parses the envelope identifier, returning `None` when unsupported.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "CBC" => Some(Self::Cbc),
            "CTR" => Some(Self::Ctr),
            _ => None,
        }
    }
}

/// Length in bytes of a symmetric data key and of the IV/nonce.
pub(crate) const BLOCK_SIZE: usize = 16;

/// Unwraps the symmetric data key with the selected asymmetric algorithm.
pub(crate) fn decrypt_asymmetric(
    encrypted_key: &str,
    algorithm: AsymmetricAlgorithm,
    private_key: &str,
) -> Result<Vec<u8>, Error> {
    match algorithm {
        AsymmetricAlgorithm::Rsa => rsa::decrypt(encrypted_key, private_key),
        AsymmetricAlgorithm::Sm2 => sm2::decrypt(encrypted_key, private_key),
    }
}

/// Decrypts the payload with the selected symmetric algorithm and mode.
pub(crate) fn decrypt_symmetric(
    ciphertext: &str,
    algorithm: SymmetricAlgorithm,
    mode: SymmetricMode,
    key: &[u8],
) -> Result<Vec<u8>, Error> {
    match algorithm {
        SymmetricAlgorithm::Aes => aes::decrypt(ciphertext, key, mode),
        SymmetricAlgorithm::Sm4 => sm4::decrypt(ciphertext, key, mode),
    }
}

/// Decodes standard padded Base64, mapping failures to the caller's error variant.
pub(crate) fn decode_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(value)
}
