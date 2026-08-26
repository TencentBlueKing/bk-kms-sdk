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

#include "internal/common/time.h"

#include <ctime>

namespace bkkms {

bool ParseHTTPDate(const std::string& date, std::time_t& out) noexcept
{
    if (date.empty())
    {
        return false;
    }

    static const char* const formats[] = {
        "%a, %d %b %Y %H:%M:%S GMT",
        "%A, %d-%b-%y %H:%M:%S GMT",
        "%a %b %e %H:%M:%S %Y",
    };

    for (const char* format : formats)
    {
        std::tm tm = {};

        if (strptime(date.c_str(), format, &tm) == nullptr)
        {
            continue;
        }

        out = timegm(&tm);

        return true;
    }

    return false;
}

} // namespace bkkms
