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
	"encoding/json"
	"fmt"
)

const (
	// Version is the version of the sdk.
	Version = "v1.0.0-alpha.1"
)

const (
	// BKAppCodeHeader blueking app code header.
	BKAppCodeHeader = "X-Bk-AppCode"

	// BKAPIAuthorizationHeader blueking apigw authorization header.
	BKAPIAuthorizationHeader = "X-Bkapi-Authorization"

	// BKAPIRequestIDHeader blueking apigw api request id header.
	BKAPIRequestIDHeader = "X-Bkapi-Request-Id"

	// BKTenantIDHeader blueking apigw tenant id header.
	BKTenantIDHeader = "X-Bk-Tenant-Id"

	// BKKMSAKHeader consume credential access key header.
	BKKMSAKHeader = "X-BKKMS-AK"

	// BKKMSTimestampHeader consume credential timestamp header.
	BKKMSTimestampHeader = "X-BKKMS-Timestamp"

	// BKKMSNonceHeader consume credential nonce header.
	BKKMSNonceHeader = "X-BKKMS-Nonce"

	// BKKMSSignatureHeader consume credential signature header.
	BKKMSSignatureHeader = "X-BKKMS-Signature"

	// BKKMSSDKVersionHeader consume credential sdk version header.
	BKKMSSDKVersionHeader = "X-BKKMS-SDK-Version"
)

const (
	// DateHeader http date header.
	DateHeader = "Date"

	// ContentTypeHeader http content type header.
	ContentTypeHeader = "Content-Type"

	// ContentTypeJSONCharsetUTF8 utf-8 json content type.
	ContentTypeJSONCharsetUTF8 = "application/json; charset=utf-8"
)

// GenAuthorizationHeader generates authentication header value.
func GenAuthorizationHeader(appCode, appSecret string) (string, error) {
	auth := struct {
		AppCode   string `json:"bk_app_code"`
		AppSecret string `json:"bk_app_secret"`
	}{
		AppCode:   appCode,
		AppSecret: appSecret,
	}

	authorization, err := json.Marshal(auth)
	if err != nil {
		return "", fmt.Errorf("marshal authorization header error(%+v)", err)
	}

	return string(authorization), nil
}
