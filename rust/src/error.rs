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

//! Error types returned by the SDK.
//!
//! Every failure mode of [`crate::decrypt`] is represented by a distinct variant of
//! [`Error`], so callers can react programmatically instead of matching on message
//! strings. Errors never embed the private key, the envelope, the data key, or the
//! decrypted plaintext.

use std::string::FromUtf8Error;

use thiserror::Error;

/// The error type returned by [`crate::decrypt`].
///
/// # Handling errors
///
/// Match on the variant to distinguish configuration problems from data problems:
///
/// ```
/// use bk_kms::Error;
///
/// fn describe(err: &Error) -> &'static str {
///     match err {
///         // The application passed an empty value; this is a programming/configuration bug.
///         Error::EmptyEnvelope | Error::EmptyPrivateKey => "missing configuration",
///         // The envelope is malformed or uses an unsupported algorithm.
///         Error::EnvelopeBase64(_)
///         | Error::EnvelopeJson(_)
///         | Error::EnvelopeField { .. }
///         | Error::UnsupportedAlgorithm { .. } => "bad envelope",
///         // The key does not match the envelope, or the data is corrupted.
///         Error::PrivateKey { .. } | Error::Ciphertext { .. } => "decryption failed",
///         // The plaintext is not text; the SDK only returns UTF-8 strings.
///         Error::PlaintextUtf8(_) => "plaintext is not UTF-8",
///         _ => "unknown",
///     }
/// }
/// ```
///
/// # Security
///
/// Error messages never contain the private key, the envelope, the data key, or the
/// plaintext. The `source` chain may contain library-level diagnostics only.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The envelope argument was an empty string.
    #[error("envelope must be a non-empty string")]
    EmptyEnvelope,

    /// The private key argument was an empty string.
    #[error("private key must be a non-empty string")]
    EmptyPrivateKey,

    /// The envelope is not valid standard Base64 (padded, strict alphabet).
    #[error("credential envelope is not valid Base64")]
    EnvelopeBase64(#[source] base64::DecodeError),

    /// The decoded envelope is not a JSON object.
    #[error("credential envelope is not a valid JSON object")]
    EnvelopeJson(#[source] serde_json::Error),

    /// An envelope field is missing, is not a string, or is an empty string.
    #[error("credential envelope field `{field}` must be a non-empty string")]
    EnvelopeField {
        /// Name of the offending field.
        field: &'static str,
    },

    /// An envelope algorithm identifier is not supported by this SDK.
    #[error("credential envelope field `{field}` has an unsupported value `{value}`")]
    UnsupportedAlgorithm {
        /// Name of the offending field.
        field: &'static str,
        /// The unsupported value found in the envelope.
        value: String,
    },

    /// The private key is not Base64 PEM, or not a usable key of the expected type.
    #[error("failed to decode the {algorithm} private key")]
    PrivateKey {
        /// Algorithm the key was expected to belong to, for example `RSA`.
        algorithm: &'static str,
        /// Underlying decoding failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// The ciphertext could not be decrypted: wrong key, corrupted data, or bad padding.
    #[error("failed to decrypt the {algorithm} ciphertext")]
    Ciphertext {
        /// Algorithm that failed, for example `AES`.
        algorithm: &'static str,
        /// Underlying cryptographic failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// The decrypted bytes are not valid UTF-8, so no `String` can be returned.
    #[error("decrypted plaintext is not valid UTF-8")]
    PlaintextUtf8(#[source] FromUtf8Error),
}

/// A specialized [`Result`](std::result::Result) for SDK operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;
