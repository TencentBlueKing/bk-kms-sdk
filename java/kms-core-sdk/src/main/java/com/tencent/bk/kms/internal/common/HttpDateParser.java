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

package com.tencent.bk.kms.internal.common;

import com.tencent.bk.kms.types.KmsException;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Parses HTTP {@code Date} header values, tolerating the three RFC 7231 formats.
 *
 * <p><b>Internal API.</b> Do not depend on this class from outside the SDK.
 */
public final class HttpDateParser {

    // Preferred RFC 7231 IMF-fixdate, e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
    private static final DateTimeFormatter[] FORMATTERS = new DateTimeFormatter[]{
            DateTimeFormatter.RFC_1123_DATE_TIME,
            DateTimeFormatter.ofPattern("EEEE, dd-MMM-yy HH:mm:ss zzz"),
            DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss yyyy")
    };

    private HttpDateParser() {
    }

    /**
     * Parses an HTTP {@code Date} header value and returns its epoch seconds
     * (UTC). Throws {@link KmsException} when the input cannot be parsed.
     */
    public static long parseEpochSecond(String value) {
        if (value == null || value.isBlank()) {
            throw new KmsException("empty date");
        }
        String trimmed = value.trim();
        for (DateTimeFormatter formatter : FORMATTERS) {
            try {
                ZonedDateTime zdt = ZonedDateTime.parse(trimmed, formatter);
                return zdt.withZoneSameInstant(ZoneOffset.UTC).toEpochSecond();
            } catch (Exception ignored) {
                // try the next formatter
            }
        }
        // Fallback: try Instant (ISO-8601), harmless if it also fails.
        try {
            return Instant.parse(trimmed).getEpochSecond();
        } catch (Exception e) {
            throw new KmsException("parse date error(" + value + ")", e);
        }
    }
}
