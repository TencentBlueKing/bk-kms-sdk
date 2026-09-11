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

#ifndef _BK_KMS_CRYPTO_SM2_H_
#define _BK_KMS_CRYPTO_SM2_H_

#include <string>

namespace bkkms {

// SM2Encrypt performs SM2 encryption. publicKeyB64 is base64(PEM) of a
// SubjectPublicKeyInfo carrying an EC/SM2 curve. Ciphertext is ASN.1-encoded
// (Tongsuo default); the returned string is base64 of that ciphertext.
bool SM2Encrypt(const std::string& plaintext, const std::string& publicKeyB64,
                std::string& ciphertextB64, std::string& err) noexcept;

// SM2Decrypt performs SM2 decryption on an ASN.1-encoded ciphertext.
bool SM2Decrypt(const std::string& ciphertextB64, const std::string& privateKeyB64,
                std::string& plaintext, std::string& err) noexcept;

} // namespace bkkms

#endif // _BK_KMS_CRYPTO_SM2_H_
