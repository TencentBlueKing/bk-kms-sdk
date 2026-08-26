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

#ifndef _BK_KMS_COMMON_HTTP_H_
#define _BK_KMS_COMMON_HTTP_H_

#include <string>

namespace bkkms {

// clang-format off
constexpr const char* const DefaultTenantID = "default";
constexpr const char* const Version         = "v1.0.0-alpha.1";

// APIGW / KMS request header names. The values are protocol-defined.
constexpr const char* const BKAPIAuthorizationHeader = "X-Bkapi-Authorization";
constexpr const char* const BKAPIRequestIDHeader     = "X-Bkapi-Request-Id";
constexpr const char* const BKTenantIDHeader         = "X-Bk-Tenant-Id";
constexpr const char* const BKKMSAKHeader            = "X-BKKMS-AK";
constexpr const char* const BKKMSTimestampHeader     = "X-BKKMS-Timestamp";
constexpr const char* const BKKMSNonceHeader         = "X-BKKMS-Nonce";
constexpr const char* const BKKMSSignatureHeader     = "X-BKKMS-Signature";
constexpr const char* const BKKMSSDKVersionHeader    = "X-BKKMS-SDK-Version";

// date and content type headers.
constexpr const char* const DateHeader                 = "Date";
constexpr const char* const ContentTypeHeader          = "Content-Type";
constexpr const char* const ContentTypeJSONCharsetUTF8 = "application/json; charset=utf-8";

// API paths. The signing URL path is always the direct-mode variant so that
// APIGW and direct callers hash the same bytes.
constexpr const char* const ConsumeCredentialAPIGWPath     = "/api/v1/consume_credential";
constexpr const char* const ConsumeCredentialDirectPath    = "/api/v1/consume/credential";
constexpr const char* const ConsumeCredentialSignaturePath = "/api/v1/consume/credential";
// clang-format on

// GenAuthorizationHeader generates the authorization header.
bool GenAuthorizationHeader(const std::string& appCode, const std::string& appSecret, std::string& out) noexcept;

} // namespace bkkms

#endif // _BK_KMS_COMMON_HTTP_H_
