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

#include "internal/crypto/sm2/sm2.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "internal/common/base64.h"

namespace bkkms {

// LoadSM2KeyFromB64PEM parses a base64(PEM) SM2 key. Works for both public
// (via PEM_read_bio_PUBKEY) and private (via PEM_read_bio_PrivateKey).
// The alias is switched to EVP_PKEY_SM2 so subsequent EVP_PKEY_encrypt /
// EVP_PKEY_decrypt use the SM2 code path rather than generic EC.
static EVP_PKEY* LoadSM2PublicKeyFromB64PEM(const std::string& publicKeyB64, std::string& err) noexcept
{
    const std::string pem = Base64Decode(publicKeyB64);
    if (pem.empty())
    {
        err = "base64 decode public key failed";
        return nullptr;
    }

    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio == nullptr)
    {
        err = "alloc bio failed";
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (pkey == nullptr)
    {
        err = "parse public key failed";
        return nullptr;
    }

    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

    return pkey;
}

static EVP_PKEY* LoadSM2PrivateKeyFromB64PEM(const std::string& privateKeyB64, std::string& err) noexcept
{
    const std::string pem = Base64Decode(privateKeyB64);
    if (pem.empty())
    {
        err = "base64 decode private key failed";
        return nullptr;
    }

    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio == nullptr)
    {
        err = "alloc bio failed";
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (pkey == nullptr)
    {
        err = "parse private key failed";
        return nullptr;
    }

    // The PEM block may declare "EC PRIVATE KEY", so the parsed key type is
    // EVP_PKEY_EC. Tongsuo needs an explicit alias to route through the SM2
    // decrypt path.
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

    return pkey;
}

bool SM2Encrypt(const std::string& plaintext, const std::string& publicKeyB64,
                std::string& ciphertextB64, std::string& err) noexcept
{
    EVP_PKEY* pkey = LoadSM2PublicKeyFromB64PEM(publicKeyB64, err);
    if (pkey == nullptr)
    {
        return false;
    }

    bool ok = false;
    std::string ciphertext;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);

    do
    {
        if (ctx == nullptr)
        {
            err = "create sm2 encrypt ctx failed";
            break;
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0)
        {
            err = "sm2 encrypt init failed";
            break;
        }

        size_t outLen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outLen,
                             reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0)
        {
            err = "sm2 encrypt size probe failed";
            break;
        }
        ciphertext.resize(outLen);

        if (EVP_PKEY_encrypt(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &outLen,
                             reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0)
        {
            err = "sm2 encrypt failed";
            break;
        }
        ciphertext.resize(outLen);

        ok = true;

    } while (false);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (!ok)
    {
        return false;
    }

    ciphertextB64 = Base64Encode(ciphertext);

    return true;
}

bool SM2Decrypt(const std::string& ciphertextB64, const std::string& privateKeyB64,
                std::string& plaintext, std::string& err) noexcept
{
    const std::string cipherBytes = Base64Decode(ciphertextB64);
    if (cipherBytes.empty())
    {
        err = "base64 decode sm2 ciphertext failed";
        return false;
    }

    EVP_PKEY* pkey = LoadSM2PrivateKeyFromB64PEM(privateKeyB64, err);
    if (pkey == nullptr)
    {
        return false;
    }

    bool ok = false;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);

    do
    {
        if (ctx == nullptr)
        {
            err = "create sm2 decrypt ctx failed";
            break;
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0)
        {
            err = "sm2 decrypt init failed";
            break;
        }

        size_t outLen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outLen,
                             reinterpret_cast<const unsigned char*>(cipherBytes.data()), cipherBytes.size()) <= 0)
        {
            err = "sm2 decrypt size probe failed";
            break;
        }
        plaintext.resize(outLen);

        if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &outLen,
                             reinterpret_cast<const unsigned char*>(cipherBytes.data()), cipherBytes.size()) <= 0)
        {
            err = "sm2 decrypt failed";
            break;
        }
        plaintext.resize(outLen);

        ok = true;

    } while (false);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ok;
}

} // namespace bkkms
