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

#include "internal/common/id.h"

#include <openssl/rand.h>

#include <cstdio>

namespace bkkms {

std::string GenUUID() noexcept
{
    unsigned char bytes[16] = {};

    if (RAND_bytes(bytes, sizeof(bytes)) != 1)
    {
        return {};
    }

    // Apply RFC 4122 v4 version and variant bits.
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0f) | 0x40);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3f) | 0x80);

    char buf[37] = {};
    std::snprintf(buf, sizeof(buf),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  bytes[0], bytes[1], bytes[2], bytes[3],
                  bytes[4], bytes[5], bytes[6], bytes[7],
                  bytes[8], bytes[9], bytes[10], bytes[11],
                  bytes[12], bytes[13], bytes[14], bytes[15]);

    return std::string(buf, 36);
}

std::string GenReqID() noexcept
{
    const std::string uuid = GenUUID();

    std::string out;
    out.reserve(32);

    for (char c : uuid)
    {
        if (c != '-')
        {
            out.push_back(c);
        }
    }

    return out;
}

} // namespace bkkms
