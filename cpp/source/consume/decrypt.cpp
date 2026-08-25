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

#include "bk-kms/client.h"

#include "internal/crypto/crypto.h"
#include "types/credential.h"

namespace bkkms {

bool DecryptEnvelope(const ConsumeEnvelope& envelope, std::vector<ConsumeResult>& out, std::string& err) noexcept
{
    if (envelope.envelope.empty() || envelope.privateKey.empty())
    {
        err = "empty envelope or private key";
        return false;
    }

    std::string plaintext;
    if (!HybridDecrypt(envelope.envelope, envelope.privateKey, plaintext, err))
    {
        err = "decrypt consume result error(" + err + ")";
        return false;
    }

    if (!UnmarshalConsumeResults(plaintext, out))
    {
        err = "unmarshal consume result error";
        return false;
    }

    return true;
}

} // namespace bkkms
