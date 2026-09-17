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

package com.tencent.bk.kms.spring;

import com.tencent.bk.kms.types.KmsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.PropertySource;

/**
 * {@link PropertySource} decorator that resolves {@code KMS:xxx} placeholders
 * on the fly. Non-string values and values without the {@code KMS:} prefix are
 * forwarded from the delegate unchanged.
 */
public class KmsPropertySource extends PropertySource<PropertySource<?>> {

    private static final Logger LOGGER = LoggerFactory.getLogger(KmsPropertySource.class);

    /** Suffix appended to the delegate name to identify the wrapper. */
    public static final String NAME_SUFFIX = "@bk-kms";

    public KmsPropertySource(PropertySource<?> delegate) {
        super(delegate.getName() + NAME_SUFFIX, delegate);
    }

    @Override
    public Object getProperty(String name) {
        Object value = getSource().getProperty(name);
        if (value instanceof String s && s.startsWith(KmsPropertyResolver.PLACEHOLDER_PREFIX)) {
            try {
                return KmsPropertyResolver.resolve(s);
            } catch (KmsException ex) {
                // Spring will otherwise wrap this into a generic
                // "Could not resolve placeholder '<name>'" IllegalArgumentException,
                // which hides the real KMS root cause. Emit an explicit error log
                // and rethrow so that the KmsException remains in the "Caused by"
                // chain of the final startup failure.
                LOGGER.error("failed to resolve BK-KMS placeholder for property '{}' (value='{}'): {}",
                        name, s, ex.getMessage());
                throw new KmsException(
                        "failed to resolve BK-KMS placeholder for property '" + name + "' (value='" + s + "'): "
                                + ex.getMessage(),
                        ex);
            } catch (RuntimeException ex) {
                LOGGER.error("unexpected error while resolving BK-KMS placeholder for property '{}' (value='{}')",
                        name, s, ex);
                throw new KmsException(
                        "unexpected error while resolving BK-KMS placeholder for property '" + name
                                + "' (value='" + s + "'): " + ex.getMessage(),
                        ex);
            }
        }
        return value;
    }
}
