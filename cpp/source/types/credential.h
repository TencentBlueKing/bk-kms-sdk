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

#ifndef _BK_KMS_TYPES_CREDENTIAL_H_
#define _BK_KMS_TYPES_CREDENTIAL_H_

#include <cstdint>
#include <string>
#include <vector>

#include "bk-kms/credential.h"
#include "bk-kms/crypto.h"

namespace bkkms {

// clang-format off

// Envelope is the hybrid-crypto payload sent from server to client. Field
// names match the wire format (snake_case). Wire-only type, not exposed to
// SDK users.
struct Envelope
{
    std::string m_asymmetricType = "";
    std::string m_symmetricType  = "";
    std::string m_symmetricMode  = "";
    std::string m_encryptedKey   = "";
    std::string m_ciphertext     = "";
};

// ConsumeCredentialResp mirrors the top-level server response body:
//   { "code": int, "message": string, "data": { "envelope": string } }
// Wire-only type, not exposed to SDK users.
struct ConsumeCredentialResp
{
    int32_t     m_code        = -1;
    std::string m_message     = "";
    bool        m_hasEnvelope = false;
    std::string m_envelope    = "";
};

// clang-format on

// MarshalConsumeCredentialReq serialises the request body sent to
// /consume_credential. Field order is fixed - server signature depends on
// the exact byte sequence:
//   credential_id_list -> credential_name_list -> crypto{asymmetric_type -> symmetric_type -> symmetric_mode} -> public_key
bool MarshalConsumeCredentialReq(const std::vector<int64_t>& credentialIDList, const std::vector<std::string>& credentialNameList,
                                 const CryptoInfo& crypto, const std::string& publicKeyB64, std::string& out) noexcept;

// UnmarshalEnvelope parses the envelope JSON that HybridDecrypt derives from the response body.
bool UnmarshalEnvelope(const std::string& in, Envelope& out) noexcept;

// UnmarshalConsumeCredentialResp parses the top-level response body.
bool UnmarshalConsumeCredentialResp(const std::string& in, ConsumeCredentialResp& out) noexcept;

// UnmarshalConsumeResults parses the decrypted plaintext (a JSON array of ConsumeResult objects).
bool UnmarshalConsumeResults(const std::string& in, std::vector<ConsumeResult>& out) noexcept;

} // namespace bkkms

#endif // _BK_KMS_TYPES_CREDENTIAL_H_
