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

#ifndef _BK_KMS_ERRORS_H_
#define _BK_KMS_ERRORS_H_

#include <cstdint>

namespace bkkms {

// clang-format off

// Server error codes. Callers can compare ConsumeResult.errCode / response
// code against these constants to branch on specific failures.
constexpr int32_t ErrCodeOK                   = 0;
constexpr int32_t ErrCodeGenericError         = 1034000;
constexpr int32_t ErrCodeNotFound             = 1034003;
constexpr int32_t ErrCodePermissionDenied     = 1034008;
constexpr int32_t ErrCodeAccessKeyDisabled    = 1034011;
constexpr int32_t ErrCodeAccessKeyExpired     = 1034012;
constexpr int32_t ErrCodeAccessKeyNotBound    = 1034013;
constexpr int32_t ErrCodeNonceAlreadyUsed     = 1034014;
constexpr int32_t ErrCodeSignatureMismatch    = 1034015;
constexpr int32_t ErrCodeRequestTimeTooSkewed = 1034016;

// clang-format on

// IsOK returns true when the error code means success.
inline bool IsOK(int32_t code)
{
    return code == ErrCodeOK;
}

} // namespace bkkms

#endif // _BK_KMS_ERRORS_H_
