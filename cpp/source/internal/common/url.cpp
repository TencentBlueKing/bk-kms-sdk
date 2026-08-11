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

#include "internal/common/url.h"

#include <vector>

namespace bkkms {

static std::string TrimLeft(const std::string& str, char c) noexcept
{
    size_t i = 0;

    while (i < str.size() && str[i] == c)
    {
        ++i;
    }

    return str.substr(i);
}

static std::string TrimRight(const std::string& str, char c) noexcept
{
    size_t n = str.size();

    while (n > 0 && str[n - 1] == c)
    {
        --n;
    }

    return str.substr(0, n);
}

static std::string Trim(const std::string& str, char c) noexcept
{
    return TrimLeft(TrimRight(str, c), c);
}

std::string JoinURL(std::initializer_list<std::string> segments) noexcept
{
    if (segments.size() == 0)
    {
        return {};
    }

    std::string scheme;
    std::vector<std::string> input(segments.begin(), segments.end());

    const std::string& first = input.front();
    const std::string::size_type idx = first.find("://");

    if (idx != std::string::npos && idx > 0)
    {
        scheme = first.substr(0, idx + 3);
        input[0] = first.substr(idx + 3);
    }

    std::vector<std::string> parts;
    parts.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i)
    {
        if (input[i].empty())
        {
            continue;
        }

        std::string seg = (i == 0) ? TrimRight(input[i], '/') : Trim(input[i], '/');

        if (seg.empty())
        {
            continue;
        }

        parts.push_back(std::move(seg));
    }

    std::string out = scheme;

    for (size_t i = 0; i < parts.size(); ++i)
    {
        if (i > 0)
        {
            out.push_back('/');
        }

        out.append(parts[i]);
    }

    return out;
}

bool SplitBaseURL(const std::string& url,
                  std::string& scheme, std::string& host, uint16_t& port, std::string& pathPrefix) noexcept
{
    // Match either "http://" or "https://" up front so the caller knows
    // which transport httplib should speak.
    uint16_t defaultPort = 0;
    std::string::size_type authorityBegin = 0;

    if (url.compare(0, 7, "http://") == 0)
    {
        scheme = "http";
        defaultPort = 80;
        authorityBegin = 7;
    }
    else if (url.compare(0, 8, "https://") == 0)
    {
        scheme = "https";
        defaultPort = 443;
        authorityBegin = 8;
    }
    else
    {
        return false;
    }

    const std::string::size_type pathBegin = url.find('/', authorityBegin);

    const std::string authority = (pathBegin == std::string::npos)
                                      ? url.substr(authorityBegin)
                                      : url.substr(authorityBegin, pathBegin - authorityBegin);

    const std::string::size_type colon = authority.find(':');

    if (colon == std::string::npos)
    {
        if (authority.empty())
        {
            return false;
        }

        host = authority;
        port = defaultPort;
    }
    else
    {
        host = authority.substr(0, colon);
        if (host.empty())
        {
            return false;
        }

        const std::string portStr = authority.substr(colon + 1);

        if (portStr.empty())
        {
            return false;
        }

        for (char c : portStr)
        {
            if (c < '0' || c > '9')
            {
                return false;
            }
        }

        const unsigned long parsed = std::stoul(portStr);

        if (parsed == 0 || parsed > 65535)
        {
            return false;
        }

        port = static_cast<uint16_t>(parsed);
    }

    if (pathBegin == std::string::npos)
    {
        pathPrefix.clear();
    }
    else
    {
        pathPrefix = url.substr(pathBegin);
        while (!pathPrefix.empty() && pathPrefix.back() == '/')
        {
            pathPrefix.pop_back();
        }
    }

    return true;
}

} // namespace bkkms
