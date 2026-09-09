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

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/TencentBlueKing/bk-kms-sdk/go/consume"
	"github.com/TencentBlueKing/bk-kms-sdk/go/types"
)

func main() {
	// Step 1: platform integration uses direct mode to KMS backend server (23681).
	// Direct mode needs AppCode.
	// SaaS via API GW: omit WithDirect, set BaseURL to the API GW prefix, and pass consume.WithAppCode / consume.WithAppSecret.
	client, err := consume.New(
		consume.WithBaseURL("http://xxxx:23681"),
		consume.WithDirect(),
		consume.WithAppCode("your_app_code_xxxx"),
	)
	if err != nil {
		log.Fatalf("failed to create new consume client: %+v", err)
	}

	// Step 2: pull the credential envelope instead of the plaintext. The SDK generates a
	// temporary key pair per request and returns the envelope together with the private key.
	// Omitting WithCredentialNameList returns every credential in the AK's uniquely bound credential group.
	// Omitting WithCrypto falls back to the default `RSA + AES(CBC)` hybrid envelope.
	// Multi-tenant callers can pass consume.WithTenantID; otherwise the header is not sent.
	envelope, err := client.ConsumeCredentialEnvelope(context.Background(),
		consume.WithAccessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx"),
		consume.WithCredentialNameList("credential_name_1", "credential_name_2"),
	)
	if err != nil {
		log.Fatalf("failed to consume credential envelope: %+v", err)
	}

	// Step 3: the envelope and the private key are both opaque base64 strings, so they
	// can be stored or handed over to another process that needs the plaintext later.
	fmt.Printf("envelope=%s\nprivate_key=%s\n", envelope.Envelope, envelope.PrivateKey)

	// Step 4: decrypt locally whenever the plaintext is needed.
	results, err := consume.DecryptEnvelope(envelope)
	if err != nil {
		log.Fatalf("failed to decrypt credential envelope: %+v", err)
	}

	// Step 5: walk the per-credential results. A non-zero ErrCode means this single
	// credential failed while the overall request succeeded — keep going instead of aborting.
	for _, result := range results {
		if !types.IsOK(result.ErrCode) {
			fmt.Printf("consume credential %d: code=%d msg=%s\n", result.CredentialID, result.ErrCode, result.ErrMsg)
			continue
		}

		cred := result.Credential
		fmt.Printf("credential %d: name=%s type=%s annotation=%s\n", result.CredentialID, cred.Name, cred.Type, cred.Annotation)

		switch cred.Type {
		case types.CredentialTypeSinglePassword:
			// Single password: only AuthInfo.Password is populated.
			fmt.Printf("  password=%s\n", cred.AuthInfo.Password)

		case types.CredentialTypeUsernamePassword:
			// Username + password: use AuthInfo.Username and AuthInfo.Password.
			fmt.Printf("  username=%s password=%s\n",
				cred.AuthInfo.Username, cred.AuthInfo.Password)

		case types.CredentialTypeSingleSecretKey:
			// Single secret key: only AuthInfo.SecretKey is populated.
			fmt.Printf("  secret_key=%s\n", cred.AuthInfo.SecretKey)

		case types.CredentialTypeAppIDSecretKey:
			// App ID + secret key: use AuthInfo.AppID and AuthInfo.SecretKey.
			fmt.Printf("  app_id=%s secret_key=%s\n",
				cred.AuthInfo.AppID, cred.AuthInfo.SecretKey)

		default:
			fmt.Printf("unknown credential type=%s\n", cred.Type)
		}
	}
}
