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

//! AES-128 decryption of the credential payload.
//!
//! The wire format is Base64 of `IV[16] || ciphertext`. CBC uses PKCS#7 padding and
//! requires block alignment; CTR uses the standard big-endian counter and carries no
//! padding. Both match the Go, C++, Java, and Python SDKs.

use aes::Aes128;
use cbc::Decryptor;
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, KeyIvInit, StreamCipher};
use ctr::Ctr128BE;

use super::{decode_base64, SymmetricMode, BLOCK_SIZE};
use crate::error::Error;

/// Algorithm name used in error messages.
pub(crate) const NAME: &str = "AES";

/// Decrypts the Base64 payload with a 16-byte key and the given mode.
pub(crate) fn decrypt(ciphertext: &str, key: &[u8], mode: SymmetricMode) -> Result<Vec<u8>, Error> {
    if key.len() != BLOCK_SIZE {
        return Err(fail(format!(
            "symmetric key must be exactly {BLOCK_SIZE} bytes"
        )));
    }

    let raw = decode_base64(ciphertext).map_err(|source| Error::Ciphertext {
        algorithm: NAME,
        source: Box::new(source),
    })?;

    // `IV[16] || ciphertext`, with at least one payload byte as in the other SDKs.
    if raw.len() < BLOCK_SIZE + 1 {
        return Err(fail("ciphertext is too short"));
    }
    let (iv, data) = raw.split_at(BLOCK_SIZE);

    match mode {
        SymmetricMode::Cbc => {
            if data.len() % BLOCK_SIZE != 0 {
                return Err(fail("CBC ciphertext is not block aligned"));
            }

            let mut buffer = data.to_vec();
            let plaintext = Decryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(fail)?
                .decrypt_padded_mut::<Pkcs7>(&mut buffer)
                .map_err(|_| fail("invalid PKCS#7 padding"))?;

            Ok(plaintext.to_vec())
        }
        SymmetricMode::Ctr => {
            let mut buffer = data.to_vec();
            Ctr128BE::<Aes128>::new_from_slices(key, iv)
                .map_err(fail)?
                .apply_keystream(&mut buffer);

            Ok(buffer)
        }
    }
}

/// Builds a ciphertext error from any displayable reason.
fn fail(reason: impl std::fmt::Display) -> Error {
    Error::Ciphertext {
        algorithm: NAME,
        source: reason.to_string().into(),
    }
}
