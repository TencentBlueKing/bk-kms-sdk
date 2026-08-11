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

#ifndef _BK_KMS_CRYPTO_H_
#define _BK_KMS_CRYPTO_H_

#include <string>

namespace bkkms {

// clang-format off

// Crypto algorithm / mode constants.
constexpr const char* const CryptoTypeRSA = "RSA";
constexpr const char* const CryptoTypeSM2 = "SM2";
constexpr const char* const CryptoTypeAES = "AES";
constexpr const char* const CryptoTypeSM4 = "SM4";
constexpr const char* const CryptoModeCBC = "CBC";
constexpr const char* const CryptoModeCTR = "CTR";

// Symmetric key length in bytes.
constexpr int CryptoKeyLength = 16;

// clang-format on

// CryptoInfo describes the hybrid encryption suite used by this request.
struct CryptoInfo
{
    std::string asymmetricType;
    std::string symmetricType;
    std::string symmetricMode;

    CryptoInfo()
        : asymmetricType(CryptoTypeRSA),
          symmetricType(CryptoTypeAES),
          symmetricMode(CryptoModeCBC) {}
};

// ValidateHybridCrypto returns true when the CryptoInfo triple names a
// supported hybrid combination (asymmetric in {RSA, SM2}, symmetric in
// {AES, SM4}, mode in {CBC, CTR}). Callers may use this to validate their
// options before issuing a request.
inline bool ValidateHybridCrypto(const CryptoInfo& c, std::string& err) noexcept
{
    if (c.asymmetricType != CryptoTypeRSA && c.asymmetricType != CryptoTypeSM2)
    {
        err = "invalid asymmetric type: " + c.asymmetricType;
        return false;
    }

    if (c.symmetricType != CryptoTypeAES && c.symmetricType != CryptoTypeSM4)
    {
        err = "invalid symmetric type: " + c.symmetricType;
        return false;
    }

    if (c.symmetricMode != CryptoModeCBC && c.symmetricMode != CryptoModeCTR)
    {
        err = "invalid symmetric mode: " + c.symmetricMode;
        return false;
    }

    return true;
}

} // namespace bkkms

#endif // _BK_KMS_CRYPTO_H_
