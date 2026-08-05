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

package common

import (
	"strings"
)

// JoinURL joins the given segments with a single '/' between them, collapsing
// any redundant '/' at the boundaries. The scheme separator of the first
// segment (e.g. "http://") is preserved. An empty segment is skipped.
func JoinURL(segments ...string) string {
	if len(segments) == 0 {
		return ""
	}

	var scheme string
	first := segments[0]

	if idx := strings.Index(first, "://"); idx > 0 {
		scheme = first[:idx+3]
		segments = append([]string{first[idx+3:]}, segments[1:]...)
	}

	parts := make([]string, 0, len(segments))

	for i, seg := range segments {
		if seg == "" {
			continue
		}

		switch i {
		case 0:
			seg = strings.TrimRight(seg, "/")

		default:
			seg = strings.Trim(seg, "/")
		}

		if seg == "" {
			continue
		}

		parts = append(parts, seg)
	}

	return scheme + strings.Join(parts, "/")
}
