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

//! # BK-KMS SDK for Rust
//!
//! Local envelope decryption for BlueKing Key Management Service (BK-KMS).
//!
//! The SDK unwraps a hybrid envelope at runtime and returns the original credential
//! plaintext. Acquiring the envelope and its matching private key, parsing the
//! plaintext, and configuring the host application all remain the caller's
//! responsibility.
//!
//! This crate is functionally equivalent to the Go, Python, and C++ SDKs of the same
//! repository: the wire format, the supported algorithms, and the failure taxonomy
//! are kept in sync.
//!
//! ## Supported algorithms
//!
//! | Role | Algorithms |
//! | --- | --- |
//! | Asymmetric, wraps the data key | `RSA` (OAEP SHA-256), `SM2` (ASN.1 ciphertext) |
//! | Symmetric, encrypts the payload | `AES`, `SM4` |
//! | Symmetric mode | `CBC` (PKCS#7 padded), `CTR` (unpadded) |
//!
//! Every algorithm is implemented in pure Rust, so the crate builds on any platform
//! with no native dependency and no separate GM backend to install.
//!
//! ## Wire format
//!
//! The envelope is standard padded Base64 of a JSON object:
//!
//! ```json
//! {
//!   "asymmetric_type": "RSA",
//!   "symmetric_type": "AES",
//!   "symmetric_mode": "CBC",
//!   "encrypted_key": "<Base64 of the wrapped 16-byte data key>",
//!   "ciphertext": "<Base64 of IV || ciphertext>"
//! }
//! ```
//!
//! Algorithm identifiers are case-sensitive. The private key is standard padded
//! Base64 of a PEM document, not the path to a key file.
//!
//! ## Quick start
//!
//! ```no_run
//! use bk_kms::{decrypt, Error};
//!
//! fn load_credential(envelope: &str, private_key_pem: &str) -> Result<String, Error> {
//!     // The private key is Base64 of the PEM text, not the PEM text itself.
//!     let private_key = base64_encode(private_key_pem.as_bytes());
//!
//!     // No client, no configuration, no network: just decrypt.
//!     let plaintext = decrypt(envelope, &private_key)?;
//!
//!     Ok(plaintext)
//! }
//!
//! # fn base64_encode(bytes: &[u8]) -> String {
//! #     use base64::Engine as _;
//! #     base64::engine::general_purpose::STANDARD.encode(bytes)
//! # }
//! ```
//!
//! ## Error handling
//!
//! [`decrypt`] returns [`Error`], which distinguishes configuration mistakes from
//! data problems. See [`Error`] for a full matching example.
//!
//! ```no_run
//! use bk_kms::{decrypt, Error};
//!
//! # fn example(envelope: &str, private_key: &str) {
//! match decrypt(envelope, private_key) {
//!     Ok(plaintext) => {
//!         // Use the plaintext immediately; do not log it.
//!         let _ = plaintext;
//!     }
//!     Err(Error::EmptyEnvelope | Error::EmptyPrivateKey) => {
//!         eprintln!("configuration error: the envelope or key is missing");
//!     }
//!     Err(err @ (Error::EnvelopeBase64(_)
//!     | Error::EnvelopeJson(_)
//!     | Error::EnvelopeField { .. }
//!     | Error::UnsupportedAlgorithm { .. })) => {
//!         eprintln!("the envelope cannot be used: {err}");
//!     }
//!     Err(Error::PrivateKey { .. } | Error::Ciphertext { .. }) => {
//!         eprintln!("decryption failed: the key does not match the envelope");
//!     }
//!     Err(Error::PlaintextUtf8(_)) => {
//!         eprintln!("the plaintext is not UTF-8 text");
//!     }
//!     Err(other) => {
//!         eprintln!("unexpected failure: {other}");
//!     }
//! }
//! # }
//! ```
//!
//! ## Security notes
//!
//! - Do not log the private key, the envelope, or the decrypted plaintext. Error
//!   values produced by this crate never embed them.
//! - The decrypted `String` cannot be reliably zeroized; keep its lifetime short and
//!   avoid copying it into long-lived structures.
//! - The SDK performs no caching: every call re-parses the private key. Cache the
//!   plaintext yourself when the same credential is needed repeatedly.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod crypto;
mod envelope;
mod error;

pub use crate::error::{Error, Result};

/// Decrypts a credential envelope with its matching private key.
///
/// `envelope` is standard padded Base64 of the JSON envelope; `private_key` is
/// standard padded Base64 of a PEM private key. On success the original UTF-8
/// plaintext is returned unchanged: the SDK never parses or normalizes its contents.
///
/// There is no initialization step and no client object. The function performs no
/// I/O and holds no state, so it is safe to call from multiple threads.
///
/// # Errors
///
/// Returns [`Error`] when:
///
/// - either argument is empty ([`Error::EmptyEnvelope`], [`Error::EmptyPrivateKey`]);
/// - the envelope is not Base64 ([`Error::EnvelopeBase64`]) or not a JSON object
///   ([`Error::EnvelopeJson`]);
/// - a required field is missing, empty, or not a string ([`Error::EnvelopeField`]);
/// - an algorithm identifier is not supported ([`Error::UnsupportedAlgorithm`]);
/// - the private key cannot be decoded ([`Error::PrivateKey`]);
/// - the ciphertext cannot be decrypted, for example because the key does not match
///   the envelope or the data is corrupted ([`Error::Ciphertext`]);
/// - the decrypted bytes are not valid UTF-8 ([`Error::PlaintextUtf8`]).
///
/// # Examples
///
/// ```no_run
/// use bk_kms::decrypt;
///
/// fn read_password(
///     envelope: &str,
///     private_key: &str,
/// ) -> Result<String, Box<dyn std::error::Error>> {
///     let plaintext = decrypt(envelope, private_key)?;
///
///     // The plaintext is application-defined; here it is a JSON document.
///     let credential: serde_json::Value = serde_json::from_str(&plaintext)?;
///
///     Ok(credential["password"].as_str().unwrap_or_default().to_owned())
/// }
/// ```
pub fn decrypt(envelope: &str, private_key: &str) -> Result<String> {
    envelope::decrypt(envelope, private_key)
}
