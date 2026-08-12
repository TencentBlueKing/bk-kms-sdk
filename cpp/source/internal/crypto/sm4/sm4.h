/*
 * TencentBlueKing is pleased to support the open source community by making
 * 蓝鲸智云 - 凭证管理服务(BlueKing - Key Management Service) available.
 * Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
 * Licensed under the MIT License (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * http://opensource.org/licenses/MIT
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.We undertake not
 * to change the open source license (MIT license) applicable to the current version
 * of the project delivered to anyone in the future.
 */

#ifndef _BK_KMS_CRYPTO_SM4_H_
#define _BK_KMS_CRYPTO_SM4_H_

#include <string>

namespace bkkms {

// SM4 encryption in CBC mode. key must be 16 bytes. Output is
// base64(iv[16] || pkcs7(ciphertext)).
bool SM4EncryptCBC(const std::string& plaintext, const std::string& key,
                   std::string& encodedText) noexcept;

// SM4 decryption in CBC mode. Input format matches SM4EncryptCBC.
bool SM4DecryptCBC(const std::string& encodedText, const std::string& key,
                   std::string& plaintext) noexcept;

// SM4 encryption in CTR mode. key must be 16 bytes. Output is
// base64(nonce[16] || ciphertext).
bool SM4EncryptCTR(const std::string& plaintext, const std::string& key,
                   std::string& encodedText) noexcept;

// SM4 decryption in CTR mode. Input format matches SM4EncryptCTR.
bool SM4DecryptCTR(const std::string& encodedText, const std::string& key,
                   std::string& plaintext) noexcept;

} // namespace bkkms

#endif // _BK_KMS_CRYPTO_SM4_H_
