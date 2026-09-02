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

#ifndef _BK_KMS_OPTION_H_
#define _BK_KMS_OPTION_H_

#include <string>
#include <vector>

#include "bk-kms/crypto.h"

namespace bkkms {

// Client-level options. baseUrl plus (appCode, appSecret) are required for
// APIGW mode; when direct=true, appCode / appSecret are ignored.
struct ClientOptions
{
    std::string baseUrl;
    bool direct = false;

    std::string appCode;
    std::string appSecret;

    int timeoutSeconds = 30;
};

// Per-request options. accessKey / secretKey are required per request;
// when an empty credentialNameList is provided, the server returns all credentials in the AK's uniquely bound credential group.
struct ConsumeOptions
{
    std::string tenantID;

    std::string accessKey;
    std::string secretKey;

    std::vector<std::string> credentialNameList;
    CryptoInfo crypto;
};

} // namespace bkkms

#endif // _BK_KMS_OPTION_H_
