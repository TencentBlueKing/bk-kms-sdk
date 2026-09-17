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

use std::env;
use std::fs;

use base64::Engine as _;
use bk_kms::decrypt;

/// Stored vector used when no real configuration is supplied.
const FIXTURES: &str = include_str!("../tests/fixtures/interop_vectors.json");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The envelope is issued by the KMS service; the private key is Base64 of PEM text.
    let (envelope, private_key) = match env::var("BK_KMS_ENVELOPE") {
        Ok(envelope) => {
            let pem = fs::read(env::var("BK_KMS_PRIVATE_KEY_PATH")?)?;
            (
                envelope,
                base64::engine::general_purpose::STANDARD.encode(pem),
            )
        }
        Err(_) => stored_vector(),
    };

    // No client, no configuration, no I/O: just decrypt.
    let plaintext = decrypt(envelope.trim(), &private_key)?;

    // Use the plaintext immediately; never log it in production.
    println!("decrypted {} bytes of UTF-8 text", plaintext.len());
    Ok(())
}

/// Reads the RSA + AES-CBC vector from the stored fixtures.
fn stored_vector() -> (String, String) {
    let document: serde_json::Value = serde_json::from_str(FIXTURES).unwrap_or_default();
    let vector = &document["vectors"]["rsa_aes_cbc"];

    (
        vector["envelope"].as_str().unwrap_or_default().to_owned(),
        vector["private_key"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    )
}
