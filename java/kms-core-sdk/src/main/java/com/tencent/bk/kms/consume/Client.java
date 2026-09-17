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

package com.tencent.bk.kms.consume;

import com.tencent.bk.kms.types.ConsumeEnvelope;
import com.tencent.bk.kms.types.ConsumeResult;

import java.util.List;

/**
 * Public entry point for consuming credentials from the BlueKing KMS service.
 * Use {@link #create(ClientOptions)} to build an instance.
 */
public interface Client {

    /**
     * Consumes one or more credentials and returns the decrypted results.
     */
    List<ConsumeResult> consumeCredential(ConsumeOptions options);

    /**
     * Consumes credentials but returns only the encrypted envelope plus the
     * ephemeral private key. The caller can decrypt later via
     * {@link #decryptEnvelope(ConsumeEnvelope)}.
     */
    ConsumeEnvelope consumeCredentialEnvelope(ConsumeOptions options);

    /**
     * Creates a new {@link Client} with the given options.
     */
    static Client create(ClientOptions options) {
        return new DefaultClient(options);
    }

    /**
     * Decrypts a previously fetched envelope into a list of consume results.
     */
    static List<ConsumeResult> decryptEnvelope(ConsumeEnvelope envelope) {
        return DecryptEnvelope.decrypt(envelope);
    }
}
