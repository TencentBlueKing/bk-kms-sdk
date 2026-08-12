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

#include "internal/crypto/rsa/rsa.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "internal/common/base64.h"

namespace bkkms {

static constexpr int RSAKeyBits = 2048;

static std::string BIOToString(BIO* bio) noexcept
{
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);

    if (len <= 0 || data == nullptr)
    {
        return {};
    }

    return std::string(data, static_cast<size_t>(len));
}

// LoadRSAPublicKeyFromB64PEM parses a base64(PEM) public key. It first tries
// PEM_read_bio_PUBKEY (covers PKIX / SubjectPublicKeyInfo), then falls back
// to legacy PKCS1 "RSA PUBLIC KEY" blocks.
static EVP_PKEY* LoadRSAPublicKeyFromB64PEM(const std::string& publicKeyB64, std::string& err) noexcept
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
    if (pkey == nullptr)
    {
        BIO_reset(bio);
        RSA* rsa = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
        if (rsa != nullptr)
        {
            pkey = EVP_PKEY_new();
            if (pkey != nullptr)
            {
                EVP_PKEY_assign_RSA(pkey, rsa);
            }
            else
            {
                RSA_free(rsa);
            }
        }
    }

    BIO_free(bio);

    if (pkey == nullptr)
    {
        err = "parse public key failed";
    }

    return pkey;
}

// LoadRSAPrivateKeyFromB64PEM parses a base64(PEM) private key. It first tries
// PEM_read_bio_PrivateKey (covers PKCS8 "PRIVATE KEY"), then falls back to
// legacy PKCS1 "RSA PRIVATE KEY" blocks.
static EVP_PKEY* LoadRSAPrivateKeyFromB64PEM(const std::string& privateKeyB64, std::string& err) noexcept
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
    if (pkey == nullptr)
    {
        BIO_reset(bio);
        RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
        if (rsa != nullptr)
        {
            pkey = EVP_PKEY_new();
            if (pkey != nullptr)
            {
                EVP_PKEY_assign_RSA(pkey, rsa);
            }
            else
            {
                RSA_free(rsa);
            }
        }
    }

    BIO_free(bio);

    if (pkey == nullptr)
    {
        err = "parse private key failed";
    }

    return pkey;
}

// SetupRSAOAEPSha256 wires OAEP padding and SHA-256 as both OAEP hash and MGF1
// digest. Callers must have already run EVP_PKEY_encrypt_init / decrypt_init.
static bool SetupRSAOAEPSha256(EVP_PKEY_CTX* ctx, std::string& err) noexcept
{
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        err = "rsa set oaep padding failed";
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
    {
        err = "rsa set oaep md failed";
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
    {
        err = "rsa set mgf1 md failed";
        return false;
    }

    return true;
}

bool GenerateRSAKeyPair(std::string& publicKeyB64, std::string& privateKeyB64,
                        std::string& err) noexcept
{
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (ctx == nullptr)
    {
        err = "create rsa keygen ctx failed";
        return false;
    }

    bool ok = false;

    do
    {
        if (EVP_PKEY_keygen_init(ctx) <= 0)
        {
            err = "rsa keygen init failed";
            break;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSAKeyBits) <= 0)
        {
            err = "rsa keygen set bits failed";
            break;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0 || pkey == nullptr)
        {
            err = "rsa keygen failed";
            break;
        }

        ok = true;

    } while (false);

    EVP_PKEY_CTX_free(ctx);

    if (!ok)
    {
        EVP_PKEY_free(pkey);
        return false;
    }

    // Public key: PEM PKIX (SubjectPublicKeyInfo).
    BIO* pubBio = BIO_new(BIO_s_mem());
    bool pubOk = pubBio != nullptr && PEM_write_bio_PUBKEY(pubBio, pkey) == 1;
    std::string pubPem = pubOk ? BIOToString(pubBio) : std::string{};
    if (pubBio)
    {
        BIO_free(pubBio);
    }

    // Private key: PEM PKCS1 ("RSA PRIVATE KEY").
    BIO* privBio = BIO_new(BIO_s_mem());
    bool privOk = false;
    if (privBio != nullptr)
    {
        RSA* rsa = EVP_PKEY_get1_RSA(pkey);
        if (rsa != nullptr)
        {
            privOk = PEM_write_bio_RSAPrivateKey(privBio, rsa, nullptr, nullptr, 0, nullptr, nullptr) == 1;
            RSA_free(rsa);
        }
    }

    std::string privPem = privOk ? BIOToString(privBio) : std::string{};
    if (privBio)
    {
        BIO_free(privBio);
    }

    EVP_PKEY_free(pkey);

    if (!pubOk || !privOk)
    {
        err = "encode rsa pem failed";
        return false;
    }

    publicKeyB64 = Base64Encode(pubPem);
    privateKeyB64 = Base64Encode(privPem);

    return true;
}

bool RSAEncrypt(const std::string& plaintext, const std::string& publicKeyB64,
                std::string& ciphertextB64, std::string& err) noexcept
{
    EVP_PKEY* pkey = LoadRSAPublicKeyFromB64PEM(publicKeyB64, err);
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
            err = "create rsa encrypt ctx failed";
            break;
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0)
        {
            err = "rsa encrypt init failed";
            break;
        }

        if (!SetupRSAOAEPSha256(ctx, err))
        {
            break;
        }

        size_t outLen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outLen,
                             reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0)
        {
            err = "rsa encrypt size probe failed";
            break;
        }
        ciphertext.resize(outLen);

        if (EVP_PKEY_encrypt(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &outLen,
                             reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0)
        {
            err = "rsa encrypt failed";
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

bool RSADecrypt(const std::string& ciphertextB64, const std::string& privateKeyB64,
                std::string& plaintext, std::string& err) noexcept
{
    const std::string cipherBytes = Base64Decode(ciphertextB64);
    if (cipherBytes.empty())
    {
        err = "base64 decode rsa ciphertext failed";
        return false;
    }

    EVP_PKEY* pkey = LoadRSAPrivateKeyFromB64PEM(privateKeyB64, err);
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
            err = "create rsa decrypt ctx failed";
            break;
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0)
        {
            err = "rsa decrypt init failed";
            break;
        }

        if (!SetupRSAOAEPSha256(ctx, err))
        {
            break;
        }

        size_t outLen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outLen,
                             reinterpret_cast<const unsigned char*>(cipherBytes.data()), cipherBytes.size()) <= 0)
        {
            err = "rsa decrypt size probe failed";
            break;
        }
        plaintext.resize(outLen);

        if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &outLen,
                             reinterpret_cast<const unsigned char*>(cipherBytes.data()), cipherBytes.size()) <= 0)
        {
            err = "rsa decrypt failed";
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
