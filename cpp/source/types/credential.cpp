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

#include "types/credential.h"

#include "internal/common/rapidjson_macro.h"

namespace bkkms {

bool MarshalConsumeCredentialReq(const std::vector<int64_t>& credentialIDList,
                                 const CryptoInfo& crypto, const std::string& publicKeyB64, std::string& out) noexcept
{
    // Fixed field order (must not be changed - server signature depends on this exact byte sequence):
    //   credential_id_list -> crypto{asymmetric_type -> symmetric_type -> symmetric_mode} -> public_key
    rapidjson::StringBuffer buf;
    rapidjson::Writer<rapidjson::StringBuffer> w(buf);

    // root start.
    w.StartObject();

    // credential_id_list start.
    w.Key("credential_id_list");
    w.StartArray();

    for (int64_t id : credentialIDList)
    {
        w.Int64(id);
    }

    // credential_id_list end.
    w.EndArray();

    // crypto start.
    w.Key("crypto");
    w.StartObject();

    RAPIDJSON_SET_STRING(w, "asymmetric_type", crypto.asymmetricType);
    RAPIDJSON_SET_STRING(w, "symmetric_type", crypto.symmetricType);
    RAPIDJSON_SET_STRING(w, "symmetric_mode", crypto.symmetricMode);

    // crypto end.
    w.EndObject();

    RAPIDJSON_SET_STRING(w, "public_key", publicKeyB64);

    // root end.
    w.EndObject();

    out.assign(buf.GetString(), buf.GetSize());

    return true;
}

bool UnmarshalEnvelope(const std::string& in, Envelope& out) noexcept
{
    rapidjson::Document doc;
    if (doc.Parse(in.data(), in.size()).HasParseError() || !doc.IsObject())
    {
        return false;
    }

    if (!RAPIDJSON_CHECK_IS_STRING(doc, "asymmetric_type") ||
        !RAPIDJSON_CHECK_IS_STRING(doc, "symmetric_type") ||
        !RAPIDJSON_CHECK_IS_STRING(doc, "symmetric_mode") ||
        !RAPIDJSON_CHECK_IS_STRING(doc, "encrypted_key") ||
        !RAPIDJSON_CHECK_IS_STRING(doc, "ciphertext"))
    {
        return false;
    }

    out.m_asymmetricType = RAPIDJSON_GET_STRING(doc, "asymmetric_type", "");
    out.m_symmetricType = RAPIDJSON_GET_STRING(doc, "symmetric_type", "");
    out.m_symmetricMode = RAPIDJSON_GET_STRING(doc, "symmetric_mode", "");
    out.m_encryptedKey = RAPIDJSON_GET_STRING(doc, "encrypted_key", "");
    out.m_ciphertext = RAPIDJSON_GET_STRING(doc, "ciphertext", "");

    return true;
}

bool UnmarshalConsumeCredentialResp(const std::string& in, ConsumeCredentialResp& out) noexcept
{
    rapidjson::Document doc;
    if (doc.Parse(in.data(), in.size()).HasParseError() || !doc.IsObject())
    {
        return false;
    }

    out.m_code = RAPIDJSON_GET_INT32(doc, "code", -1);
    out.m_message = RAPIDJSON_GET_STRING(doc, "message", "");

    if (RAPIDJSON_CHECK_IS_OBJECT(doc, "data"))
    {
        const rapidjson::Value& data = doc["data"];
        if (RAPIDJSON_CHECK_IS_STRING(data, "envelope"))
        {
            out.m_hasEnvelope = true;
            out.m_envelope = RAPIDJSON_GET_STRING(data, "envelope", "");
        }
    }

    return true;
}

static void ReadCredential(const rapidjson::Value& node, Credential& cred) noexcept
{
    cred.name = RAPIDJSON_GET_STRING(node, "name", "");
    cred.type = RAPIDJSON_GET_STRING(node, "type", "");
    cred.annotation = RAPIDJSON_GET_STRING(node, "annotation", "");

    if (!RAPIDJSON_CHECK_IS_OBJECT(node, "auth_info"))
    {
        return;
    }

    const rapidjson::Value& authInfo = node["auth_info"];
    cred.authInfo.password = RAPIDJSON_GET_STRING(authInfo, "password", "");
    cred.authInfo.username = RAPIDJSON_GET_STRING(authInfo, "username", "");
    cred.authInfo.secretKey = RAPIDJSON_GET_STRING(authInfo, "secret_key", "");
    cred.authInfo.appID = RAPIDJSON_GET_STRING(authInfo, "app_id", "");
}

static void ReadConsumeResult(const rapidjson::Value& node, ConsumeResult& result) noexcept
{
    result.credentialID = RAPIDJSON_GET_INT64(node, "credential_id", 0);
    result.errCode = RAPIDJSON_GET_INT32(node, "err_code", 0);
    result.errMsg = RAPIDJSON_GET_STRING(node, "err_msg", "");

    if (RAPIDJSON_CHECK_IS_OBJECT(node, "credential"))
    {
        ReadCredential(node["credential"], result.credential);
        result.hasCredential = true;
    }
}

bool UnmarshalConsumeResults(const std::string& in, std::vector<ConsumeResult>& out) noexcept
{
    rapidjson::Document doc;
    if (doc.Parse(in.data(), in.size()).HasParseError() || !doc.IsArray())
    {
        return false;
    }

    out.clear();
    out.reserve(doc.Size());

    for (rapidjson::SizeType i = 0; i < doc.Size(); ++i)
    {
        if (!doc[i].IsObject())
        {
            continue;
        }

        ConsumeResult result;
        ReadConsumeResult(doc[i], result);
        out.push_back(std::move(result));
    }

    return true;
}

} // namespace bkkms
