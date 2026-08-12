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

#ifndef _BK_KMS_CREDENTIAL_H_
#define _BK_KMS_CREDENTIAL_H_

#include <cstdint>
#include <string>

namespace bkkms {

// clang-format off

// CredentialType string constants.
constexpr const char* const CredentialTypeSinglePassword   = "single_password";
constexpr const char* const CredentialTypeUsernamePassword = "username_password";
constexpr const char* const CredentialTypeSingleSecretKey  = "single_secret_key";
constexpr const char* const CredentialTypeAppIDSecretKey   = "app_id_secret_key";

// clang-format on

struct AuthInfo
{
    std::string password;
    std::string username;
    std::string secretKey;
    std::string appID;
};

struct Credential
{
    std::string name;
    std::string type;
    AuthInfo authInfo;
    std::string annotation;
};

// Two-level result: overall RPC success + per-credential errCode. The
// credential field is meaningful only when hasCredential is true (and
// typically only when errCode == ErrCodeOK).
struct ConsumeResult
{
    int64_t credentialID = 0;
    int32_t errCode = 0;
    std::string errMsg;
    bool hasCredential = false;
    Credential credential;
};

} // namespace bkkms

#endif // _BK_KMS_CREDENTIAL_H_
