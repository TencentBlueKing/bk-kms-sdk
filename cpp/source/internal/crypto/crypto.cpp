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

#include "internal/crypto/crypto.h"

#include "internal/types/crypto.h"
#include "internal/common/base64.h"
#include "internal/common/rapidjson_macro.h"
#include "internal/crypto/aes/aes.h"
#include "internal/crypto/rsa/rsa.h"
#include "internal/crypto/sm2/sm2.h"
#include "internal/crypto/sm4/sm4.h"

namespace bkkms {

struct Envelope
{
    std::string m_asymmetricType;
    std::string m_symmetricType;
    std::string m_symmetricMode;
    std::string m_encryptedKey;
    std::string m_ciphertext;
};

static bool UnmarshalEnvelope(const std::string& in, Envelope& out) noexcept
{
    rapidjson::Document doc;
    if (doc.Parse(in.data(), in.size()).HasParseError() || !doc.IsObject())
    {
        return false;
    }

    if (!RAPIDJSON_CHECK_IS_STRING(doc, "asymmetric_type") ||
        !RAPIDJSON_CHECK_IS_STRING(doc, "symmetric_type") ||
        !RAPIDJSON_CHECK_IS_STRING(doc, "symmetric_mode") ||
        !RAPIDJSON_CHECK_IS_STRING(doc, "encrypted_key") ||
        !RAPIDJSON_CHECK_IS_STRING(doc, "ciphertext"))
    {
        return false;
    }

    out.m_asymmetricType = RAPIDJSON_GET_STRING(doc, "asymmetric_type", "");
    out.m_symmetricType = RAPIDJSON_GET_STRING(doc, "symmetric_type", "");
    out.m_symmetricMode = RAPIDJSON_GET_STRING(doc, "symmetric_mode", "");
    out.m_encryptedKey = RAPIDJSON_GET_STRING(doc, "encrypted_key", "");
    out.m_ciphertext = RAPIDJSON_GET_STRING(doc, "ciphertext", "");

    return true;
}

bool SymmetricDecrypt(const std::string& encodedText,
                      const std::string& cryptoType, const std::string& cryptoMode,
                      const std::string& cryptoKey, std::string& plaintext, std::string& err) noexcept
{
    bool ok = false;

    if (cryptoType == CryptoTypeAES && cryptoMode == CryptoModeCBC)
    {
        ok = AESDecryptCBC(encodedText, cryptoKey, plaintext);
    }
    else if (cryptoType == CryptoTypeAES && cryptoMode == CryptoModeCTR)
    {
        ok = AESDecryptCTR(encodedText, cryptoKey, plaintext);
    }
    else if (cryptoType == CryptoTypeSM4 && cryptoMode == CryptoModeCBC)
    {
        ok = SM4DecryptCBC(encodedText, cryptoKey, plaintext);
    }
    else if (cryptoType == CryptoTypeSM4 && cryptoMode == CryptoModeCTR)
    {
        ok = SM4DecryptCTR(encodedText, cryptoKey, plaintext);
    }
    else
    {
        err = "unsupported symmetric combination: " + cryptoType + "/" + cryptoMode;
        return false;
    }

    if (!ok)
    {
        err = "symmetric decrypt failed: " + cryptoType + "/" + cryptoMode;
    }

    return ok;
}

bool AsymmetricDecrypt(const std::string& ciphertextB64, const std::string& cryptoType,
                       const std::string& privateKeyB64, std::string& plaintext, std::string& err) noexcept
{
    if (cryptoType == CryptoTypeRSA)
    {
        return RSADecrypt(ciphertextB64, privateKeyB64, plaintext, err);
    }

    if (cryptoType == CryptoTypeSM2)
    {
        return SM2Decrypt(ciphertextB64, privateKeyB64, plaintext, err);
    }

    err = "unsupported asymmetric type: " + cryptoType;

    return false;
}

bool HybridDecrypt(const std::string& envelopeB64, const std::string& privateKeyB64,
                   std::string& plaintext, std::string& err) noexcept
{
    if (envelopeB64.empty())
    {
        plaintext.clear();
        return true;
    }

    const std::string envelopeJson = Base64Decode(envelopeB64);
    if (envelopeJson.empty())
    {
        err = "base64 decode envelope failed";
        return false;
    }

    Envelope env;
    if (!UnmarshalEnvelope(envelopeJson, env))
    {
        err = "invalid envelope fields";
        return false;
    }

    std::string symmetricKey;
    if (!AsymmetricDecrypt(env.m_encryptedKey, env.m_asymmetricType, privateKeyB64, symmetricKey, err))
    {
        return false;
    }

    if (symmetricKey.size() != static_cast<size_t>(CryptoKeyLength))
    {
        err = "invalid symmetric key length";
        return false;
    }

    return SymmetricDecrypt(env.m_ciphertext, env.m_symmetricType, env.m_symmetricMode,
                            symmetricKey, plaintext, err);
}

} // namespace bkkms
