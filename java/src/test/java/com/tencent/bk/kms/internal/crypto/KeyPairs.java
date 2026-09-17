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

package com.tencent.bk.kms.internal.crypto;

import com.tencent.bk.kms.internal.crypto.rsa.Rsa;
import com.tencent.bk.kms.internal.crypto.sm2.Sm2;
import com.tencent.bk.kms.types.CryptoType;
import com.tencent.bk.kms.types.KmsException;

/**
 * Test-only helper that generates an ephemeral {@link KeyPair} for the
 * requested asymmetric algorithm. Used to drive round-trip tests without
 * requiring pre-generated keys on disk.
 */
final class KeyPairs {

    private KeyPairs() {
    }

    static KeyPair newKeyPair(CryptoType type) {
        return switch (type) {
            case RSA -> Rsa.generateKeyPair();
            case SM2 -> Sm2.generateKeyPair();
            default -> throw new KmsException(
                    "unsupported asymmetric type for key pair generation: " + type);
        };
    }
}
