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

#ifndef _BK_KMS_SIGNATURE_H_
#define _BK_KMS_SIGNATURE_H_

#include <string>

namespace bkkms {

// Two-stage HMAC-SHA256 signing:
//   signingKey   = HMAC-SHA256(secretKey, nonce)
//   stringToSign = METHOD "\n" URL_PATH "\n" TIMESTAMP "\n" NONCE "\n" SHA256_HEX(signContent)
//   signature    = HMAC-SHA256(signingKey, stringToSign)
// Returned as a lower-case hex string.
bool Sign(const std::string& secretKey, const std::string& nonce, const std::string& method, const std::string& urlPath,
          const std::string& timestamp, const std::string& signContent, std::string& signature, std::string& err) noexcept;

} // namespace bkkms

#endif // _BK_KMS_SIGNATURE_H_
