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

package signature

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/TencentBlueKing/bk-kms-sdk/go/internal/common"
	"github.com/TencentBlueKing/bk-kms-sdk/go/types"
)

const (
	// ConsumeCredentialSignaturePath consume credential signature path.
	ConsumeCredentialSignaturePath = "/api/v1/consume/credential"
)

// NewNonce creates consume credential request nonce (UUID v4 without dashes).
func NewNonce() (string, error) {
	id, err := common.GenUUID()
	if err != nil {
		return "", fmt.Errorf("generate nonce error(%+v)", err)
	}

	return strings.ReplaceAll(id, "-", ""), nil
}

// SignContent signature content.
type SignContent struct {
	CredentialIDList []int64          `json:"credential_id_list"`
	Crypto           types.CryptoInfo `json:"crypto"`
	PublicKey        string           `json:"public_key"`
}

// ConsumeSignature consume signature.
type ConsumeSignature struct {
	SecretKey   string
	Nonce       string
	Method      string
	URLPath     string
	Timestamp   string
	SignContent SignContent
}

// Sign computes consume credential request signature.
func (s *ConsumeSignature) Sign() (string, error) {
	if s.SecretKey == "" {
		return "", errors.New("invalid secret key")
	}

	if s.Nonce == "" {
		return "", errors.New("invalid nonce")
	}

	if s.Method == "" {
		return "", errors.New("invalid http method")
	}

	if s.URLPath == "" {
		return "", errors.New("invalid url path")
	}

	if s.Timestamp == "" {
		return "", errors.New("invalid timestamp")
	}

	// empty list signs as [], not null.
	if s.SignContent.CredentialIDList == nil {
		s.SignContent.CredentialIDList = []int64{}
	}

	content, err := json.Marshal(s.SignContent)
	if err != nil {
		return "", fmt.Errorf("marshal sign content error(%+v)", err)
	}

	contentHashValue := sha256.Sum256(content)
	contentHash := hex.EncodeToString(contentHashValue[:])
	stringToSign := strings.Join([]string{s.Method, s.URLPath, s.Timestamp, s.Nonce, contentHash}, "\n")

	signingKey, err := common.HMACSHA256([]byte(s.SecretKey), []byte(s.Nonce))
	if err != nil {
		return "", fmt.Errorf("derive signing key error(%+v)", err)
	}

	signature, err := common.HMACSHA256(signingKey, []byte(stringToSign))
	if err != nil {
		return "", fmt.Errorf("compute signature error(%+v)", err)
	}

	return hex.EncodeToString(signature), nil
}
