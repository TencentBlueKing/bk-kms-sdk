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

#ifndef _BK_KMS_COMMON_URL_H_
#define _BK_KMS_COMMON_URL_H_

#include <cstdint>
#include <initializer_list>
#include <string>

namespace bkkms {

// JoinURL joins URL segments with a single '/' between them, collapsing
// redundant slashes at the boundaries. The scheme of the first segment
// (e.g. "http://" or "https://") is preserved. Empty segments are skipped.
std::string JoinURL(std::initializer_list<std::string> segments) noexcept;

// SplitBaseURL parses "http[s]://host[:port]/prefix" into scheme, host, port
// and path prefix. Both http and https are supported (default port 80 / 443).
// Returns false when the URL is malformed. The path prefix keeps its leading
// '/' and drops trailing slashes.
bool SplitBaseURL(const std::string& baseUrl,
                  std::string& scheme, std::string& host, uint16_t& port, std::string& pathPrefix) noexcept;

} // namespace bkkms

#endif // _BK_KMS_COMMON_URL_H_
