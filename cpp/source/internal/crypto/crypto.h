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

#ifndef _BK_KMS_CRYPTO_CRYPTO_H_
#define _BK_KMS_CRYPTO_CRYPTO_H_

#include <string>

namespace bkkms {

// SymmetricDecrypt dispatches to AES/SM4 + CBC/CTR based on (cryptoType, cryptoMode).
bool SymmetricDecrypt(const std::string& encodedText,
                      const std::string& cryptoType, const std::string& cryptoMode,
                      const std::string& cryptoKey, std::string& plaintext, std::string& err) noexcept;

// AsymmetricDecrypt dispatches to RSADecrypt / SM2Decrypt based on cryptoType.
bool AsymmetricDecrypt(const std::string& ciphertextB64, const std::string& cryptoType,
                       const std::string& privateKeyB64, std::string& plaintext, std::string& err) noexcept;

// HybridDecrypt performs hybrid-envelope decryption:
//   1) base64-decode envelopeB64, giving the Envelope JSON.
//   2) AsymmetricDecrypt Envelope.encrypted_key with privateKeyB64 to recover
//      the 16-byte symmetric key.
//   3) SymmetricDecrypt Envelope.ciphertext with the symmetric key.
bool HybridDecrypt(const std::string& envelopeB64, const std::string& privateKeyB64,
                   std::string& plaintext, std::string& err) noexcept;

} // namespace bkkms

#endif // _BK_KMS_CRYPTO_CRYPTO_H_
