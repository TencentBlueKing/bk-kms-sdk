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

#include "internal/crypto/sm4/sm4.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "bk-kms/crypto.h"
#include "internal/common/base64.h"

namespace bkkms {

static constexpr int SM4BlockSize = 16;

static std::string PKCS7Pad(const std::string& data) noexcept
{
    const int pad = SM4BlockSize - static_cast<int>(data.size() % SM4BlockSize);

    std::string out;
    out.reserve(data.size() + pad);
    out.append(data);
    out.append(static_cast<size_t>(pad), static_cast<char>(pad));

    return out;
}

static bool PKCS7Unpad(std::string& buf) noexcept
{
    if (buf.empty())
    {
        return false;
    }

    const unsigned char pad = static_cast<unsigned char>(buf.back());
    if (pad == 0 || pad > SM4BlockSize || pad > buf.size())
    {
        return false;
    }

    for (size_t i = buf.size() - pad; i < buf.size(); ++i)
    {
        if (static_cast<unsigned char>(buf[i]) != pad)
        {
            return false;
        }
    }

    buf.resize(buf.size() - pad);

    return true;
}

static bool EVPEncrypt(const EVP_CIPHER* cipher, const unsigned char* key, const unsigned char* iv,
                       const unsigned char* in, int inLen, std::string& out) noexcept
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
    {
        return false;
    }

    bool ok = false;

    out.clear();
    out.resize(static_cast<size_t>(inLen) + SM4BlockSize);
    int outLen1 = 0;
    int outLen2 = 0;

    do
    {
        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv) != 1)
        {
            break;
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0);

        if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&out[0]), &outLen1, in, inLen) != 1)
        {
            break;
        }

        if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&out[outLen1]), &outLen2) != 1)
        {
            break;
        }

        ok = true;

    } while (false);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok)
    {
        out.clear();
        return false;
    }

    out.resize(static_cast<size_t>(outLen1 + outLen2));

    return true;
}

static bool EVPDecrypt(const EVP_CIPHER* cipher, const unsigned char* key, const unsigned char* iv,
                       const unsigned char* in, int inLen, std::string& out) noexcept
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
    {
        return false;
    }

    bool ok = false;

    out.clear();
    out.resize(static_cast<size_t>(inLen) + SM4BlockSize);
    int outLen1 = 0;
    int outLen2 = 0;

    do
    {
        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv) != 1)
        {
            break;
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0);

        if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&out[0]), &outLen1, in, inLen) != 1)
        {
            break;
        }

        if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&out[outLen1]), &outLen2) != 1)
        {
            break;
        }

        ok = true;

    } while (false);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok)
    {
        out.clear();
        return false;
    }

    out.resize(static_cast<size_t>(outLen1 + outLen2));

    return true;
}

bool SM4EncryptCBC(const std::string& plaintext, const std::string& key,
                   std::string& encodedText) noexcept
{
    if (key.size() != static_cast<size_t>(CryptoKeyLength))
    {
        return false;
    }

    unsigned char iv[SM4BlockSize] = {0};
    if (RAND_bytes(iv, sizeof(iv)) != 1)
    {
        return false;
    }

    const std::string padded = PKCS7Pad(plaintext);
    std::string ciphertext;
    if (!EVPEncrypt(EVP_sm4_cbc(),
                    reinterpret_cast<const unsigned char*>(key.data()), iv,
                    reinterpret_cast<const unsigned char*>(padded.data()),
                    static_cast<int>(padded.size()), ciphertext))
    {
        return false;
    }

    std::string raw;
    raw.reserve(SM4BlockSize + ciphertext.size());
    raw.append(reinterpret_cast<const char*>(iv), SM4BlockSize);
    raw.append(ciphertext);

    encodedText = Base64Encode(raw);

    return true;
}

bool SM4DecryptCBC(const std::string& encodedText, const std::string& key,
                   std::string& plaintext) noexcept
{
    if (key.size() != static_cast<size_t>(CryptoKeyLength))
    {
        return false;
    }

    const std::string raw = Base64Decode(encodedText);
    if (raw.size() < static_cast<size_t>(SM4BlockSize))
    {
        return false;
    }

    const std::string iv(raw.data(), SM4BlockSize);
    const std::string cipherBytes(raw.data() + SM4BlockSize, raw.size() - SM4BlockSize);
    if (cipherBytes.empty() || (cipherBytes.size() % SM4BlockSize) != 0)
    {
        return false;
    }

    if (!EVPDecrypt(EVP_sm4_cbc(),
                    reinterpret_cast<const unsigned char*>(key.data()),
                    reinterpret_cast<const unsigned char*>(iv.data()),
                    reinterpret_cast<const unsigned char*>(cipherBytes.data()),
                    static_cast<int>(cipherBytes.size()), plaintext))
    {
        return false;
    }

    return PKCS7Unpad(plaintext);
}

bool SM4EncryptCTR(const std::string& plaintext, const std::string& key,
                   std::string& encodedText) noexcept
{
    if (key.size() != static_cast<size_t>(CryptoKeyLength))
    {
        return false;
    }

    unsigned char nonce[SM4BlockSize] = {0};
    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
    {
        return false;
    }

    std::string ciphertext;
    if (!EVPEncrypt(EVP_sm4_ctr(),
                    reinterpret_cast<const unsigned char*>(key.data()), nonce,
                    reinterpret_cast<const unsigned char*>(plaintext.data()),
                    static_cast<int>(plaintext.size()), ciphertext))
    {
        return false;
    }

    std::string raw;
    raw.reserve(SM4BlockSize + ciphertext.size());
    raw.append(reinterpret_cast<const char*>(nonce), SM4BlockSize);
    raw.append(ciphertext);

    encodedText = Base64Encode(raw);

    return true;
}

bool SM4DecryptCTR(const std::string& encodedText, const std::string& key,
                   std::string& plaintext) noexcept
{
    if (key.size() != static_cast<size_t>(CryptoKeyLength))
    {
        return false;
    }

    const std::string raw = Base64Decode(encodedText);
    if (raw.size() < static_cast<size_t>(SM4BlockSize))
    {
        return false;
    }

    const std::string iv(raw.data(), SM4BlockSize);
    const std::string cipherBytes(raw.data() + SM4BlockSize, raw.size() - SM4BlockSize);

    return EVPDecrypt(EVP_sm4_ctr(),
                      reinterpret_cast<const unsigned char*>(key.data()),
                      reinterpret_cast<const unsigned char*>(iv.data()),
                      reinterpret_cast<const unsigned char*>(cipherBytes.data()),
                      static_cast<int>(cipherBytes.size()), plaintext);
}

} // namespace bkkms
