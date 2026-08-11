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

#include "internal/crypto/key.h"

#include "bk-kms/crypto.h"
#include "internal/crypto/rsa/rsa.h"
#include "internal/crypto/sm2/sm2.h"

namespace bkkms {

bool GenerateKeyPair(const std::string& asymmetricType, KeyPair& out, std::string& err) noexcept
{
    if (asymmetricType == CryptoTypeRSA)
    {
        return GenerateRSAKeyPair(out.publicKey, out.privateKey, err);
    }
    if (asymmetricType == CryptoTypeSM2)
    {
        return GenerateSM2KeyPair(out.publicKey, out.privateKey, err);
    }

    err = "unsupported asymmetric type: " + asymmetricType;

    return false;
}

} // namespace bkkms
