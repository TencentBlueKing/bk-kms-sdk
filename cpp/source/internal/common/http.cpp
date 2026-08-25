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

#include "internal/common/http.h"

#include "internal/common/rapidjson_macro.h"

namespace bkkms {

bool GenAuthorizationHeader(const std::string& appCode, const std::string& appSecret, std::string& out) noexcept
{
    rapidjson::StringBuffer buf;
    rapidjson::Writer<rapidjson::StringBuffer> w(buf);

    w.StartObject();

    RAPIDJSON_SET_STRING(w, "bk_app_code", appCode);
    RAPIDJSON_SET_STRING(w, "bk_app_secret", appSecret);

    w.EndObject();

    out.assign(buf.GetString(), buf.GetSize());

    return true;
}

} // namespace bkkms
