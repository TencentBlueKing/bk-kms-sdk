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

#include <bk-kms/client.h>

#include <cstdio>
#include <string>
#include <vector>

int main()
{
    // Step 1: platform integration uses direct mode to KMS backend server (23681).
    // Direct mode does not need appCode / appSecret.
    // SaaS via API GW: keep direct=false, set baseUrl to the API GW prefix, and fill in appCode / appSecret.
    bkkms::ClientOptions clientOpts;
    clientOpts.baseUrl = "http://xxxx:23681";
    clientOpts.direct  = true;

    std::string err;
    auto client = bkkms::Client::New(clientOpts, err);
    if (!client)
    {
        std::fprintf(stderr, "failed to create new consume client: %s\n", err.c_str());
        return 1;
    }

    // Step 2: pull the credential envelope instead of the plaintext. The SDK
    // generates a temporary key pair per request and returns the envelope
    // together with the private key, without decrypting anything. Leaving
    // credentialNameList empty returns every credential in the AK's uniquely bound credential group. 
    // Leaving crypto default falls back to RSA + AES(CBC).
    bkkms::ConsumeOptions consumeOpts;
    consumeOpts.accessKey = "your_access_key_xxxx";
    consumeOpts.secretKey = "your_secret_key_xxxx";
    consumeOpts.credentialNameList = {"credential_name_1", "credential_name_2"};

    bkkms::ConsumeEnvelope envelope;
    if (!client->ConsumeCredentialEnvelope(consumeOpts, envelope, err))
    {
        std::fprintf(stderr, "failed to consume credential envelope: %s\n", err.c_str());
        return 1;
    }

    // Step 3: the envelope and the private key are both opaque base64 strings, so they
    // can be stored or handed over to another process that needs the plaintext later.
    std::printf("envelope=%s\nprivate_key=%s\n", envelope.envelope.c_str(), envelope.privateKey.c_str());

    // Step 4: decrypt locally whenever the plaintext is needed.
    std::vector<bkkms::ConsumeResult> results;
    if (!bkkms::DecryptEnvelope(envelope, results, err))
    {
        std::fprintf(stderr, "failed to decrypt credential envelope: %s\n", err.c_str());
        return 1;
    }

    // Step 5: walk each per-credential result. A non-zero errCode means that
    // one entry failed while others may still be usable.
    for (const auto& r : results)
    {
        if (!bkkms::IsOK(r.errCode))
        {
            std::printf("consume credential %lld: code=%d msg=%s\n",
                        static_cast<long long>(r.credentialID), r.errCode, r.errMsg.c_str());
            continue;
        }

        if (!r.hasCredential)
        {
            continue;
        }

        const bkkms::Credential& c = r.credential;

        std::printf("credential %lld: name=%s type=%s annotation=%s\n",
                    static_cast<long long>(r.credentialID), c.name.c_str(), c.type.c_str(), c.annotation.c_str());

        if (c.type == bkkms::CredentialTypeSinglePassword)
        {
            std::printf("  password=%s\n", c.authInfo.password.c_str());
        }
        else if (c.type == bkkms::CredentialTypeUsernamePassword)
        {
            std::printf("  username=%s password=%s\n",
                        c.authInfo.username.c_str(), c.authInfo.password.c_str());
        }
        else if (c.type == bkkms::CredentialTypeSingleSecretKey)
        {
            std::printf("  secret_key=%s\n", c.authInfo.secretKey.c_str());
        }
        else if (c.type == bkkms::CredentialTypeAppIDSecretKey)
        {
            std::printf("  app_id=%s secret_key=%s\n",
                        c.authInfo.appID.c_str(), c.authInfo.secretKey.c_str());
        }
        else
        {
            std::printf("unknown credential type=%s\n", c.type.c_str());
        }
    }

    return 0;
}
