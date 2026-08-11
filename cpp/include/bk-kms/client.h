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

#ifndef _BK_KMS_CLIENT_H_
#define _BK_KMS_CLIENT_H_

#include <memory>
#include <string>
#include <vector>

#include "bk-kms/credential.h"
#include "bk-kms/crypto.h"
#include "bk-kms/errors.h"
#include "bk-kms/option.h"

namespace bkkms {

/**
 * @brief Client credential consumption facade.
 */
class Client
{
public:
    virtual ~Client() = default;

    /**
     * @brief New constructs a Client from the given options.
     *
     * @param opts client options.
     * @param err  filled with the failure reason when the return value is null.
     *
     * @return owned Client on success, nullptr on failure.
     */
    static std::unique_ptr<Client> New(const ClientOptions& opts, std::string& err) noexcept;

    /**
     * @brief ConsumeCredential fetches credentials from the KMS server.
     *
     * @param opts per-request options.
     * @param err  overall request error; non-empty when the returned vector is
     *             empty because of an end-to-end failure.
     *
     * @return per-credential results. Even on success, individual entries may
     *         report failure via ConsumeResult.errCode.
     */
    virtual std::vector<ConsumeResult> ConsumeCredential(const ConsumeOptions& opts, std::string& err) noexcept = 0;
};

} // namespace bkkms

#endif // _BK_KMS_CLIENT_H_
