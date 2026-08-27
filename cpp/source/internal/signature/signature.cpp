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

#include "internal/signature/signature.h"

#include "internal/common/hash.h"

namespace bkkms {

bool Sign(const std::string& secretKey, const std::string& nonce, const std::string& timestamp,
          const std::string& signContent, std::string& signature, std::string& err) noexcept
{
    if (secretKey.empty())
    {
        err = "invalid secret key";
        return false;
    }

    if (nonce.empty())
    {
        err = "invalid nonce";
        return false;
    }

    if (timestamp.empty())
    {
        err = "invalid timestamp";
        return false;
    }

    const std::string contentHash = HexEncode(SHA256Sum(signContent));

    std::string sts;
    sts.reserve(timestamp.size() + nonce.size() + contentHash.size() + 2);
    sts.append(timestamp).push_back('\n');
    sts.append(nonce).push_back('\n');
    sts.append(contentHash);

    const std::string signingKey = HMACSHA256(secretKey, nonce);
    if (signingKey.empty())
    {
        err = "derive signing key failed";
        return false;
    }

    const std::string sig = HMACSHA256(signingKey, sts);
    if (sig.empty())
    {
        err = "compute signature failed";
        return false;
    }

    signature = HexEncode(sig);

    return true;
}

} // namespace bkkms
