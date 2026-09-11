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

#include "include/bk-kms/decrypt.h"

#include "internal/crypto/crypto.h"

namespace bkkms {

bool Decrypt(const std::string& envelope, const std::string& privateKey,
             std::string& plaintext, std::string& err) noexcept
{
    if (envelope.empty())
    {
        err = "empty envelope";
        return false;
    }

    if (privateKey.empty())
    {
        err = "empty private key";
        return false;
    }

    if (!HybridDecrypt(envelope, privateKey, plaintext, err))
    {
        err = "hybrid decrypt: " + err;
        return false;
    }

    return true;
}

} // namespace bkkms
