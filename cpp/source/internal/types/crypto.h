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

#ifndef _BK_KMS_INTERNAL_TYPES_CRYPTO_H_
#define _BK_KMS_INTERNAL_TYPES_CRYPTO_H_

namespace bkkms {

// clang-format off

// Algorithm identifiers carried inside the envelope.
constexpr const char* const CryptoTypeRSA = "RSA";
constexpr const char* const CryptoTypeSM2 = "SM2";
constexpr const char* const CryptoTypeAES = "AES";
constexpr const char* const CryptoTypeSM4 = "SM4";
constexpr const char* const CryptoModeCBC = "CBC";
constexpr const char* const CryptoModeCTR = "CTR";

// Symmetric data-key length in bytes.
constexpr int CryptoKeyLength = 16;

// clang-format on

} // namespace bkkms

#endif // _BK_KMS_INTERNAL_TYPES_CRYPTO_H_
