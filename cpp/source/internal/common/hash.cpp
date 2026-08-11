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

#include "internal/common/hash.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace bkkms {

std::string SHA256Sum(const std::string& data) noexcept
{
    unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);

    return std::string(reinterpret_cast<const char*>(digest), sizeof(digest));
}

std::string HMACSHA256(const std::string& key, const std::string& data) noexcept
{
    unsigned char digest[32] = {0};
    unsigned int digestLen = 0;

    if (HMAC(EVP_sha256(),
             reinterpret_cast<const unsigned char*>(key.data()), static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char*>(data.data()), data.size(),
             digest, &digestLen) == nullptr ||
        digestLen != sizeof(digest))
    {
        return {};
    }

    return std::string(reinterpret_cast<const char*>(digest), sizeof(digest));
}

std::string HexEncode(const std::string& data) noexcept
{
    static const char HEX[] = "0123456789abcdef";

    std::string out;
    out.resize(data.size() * 2);

    for (size_t i = 0; i < data.size(); ++i)
    {
        const unsigned char byte = static_cast<unsigned char>(data[i]);
        out[i * 2] = HEX[(byte >> 4) & 0x0f];
        out[i * 2 + 1] = HEX[byte & 0x0f];
    }

    return out;
}

} // namespace bkkms
