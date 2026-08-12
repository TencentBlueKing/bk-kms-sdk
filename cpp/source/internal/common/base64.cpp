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

#include "internal/common/base64.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

namespace bkkms {

std::string Base64Encode(const std::string& data) noexcept
{
    if (data.empty())
    {
        return {};
    }

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new(BIO_s_mem());
    BIO* chain = BIO_push(b64, mem);

    BIO_write(chain, data.data(), static_cast<int>(data.size()));
    BIO_flush(chain);

    BUF_MEM* ptr = nullptr;
    BIO_get_mem_ptr(chain, &ptr);
    std::string out(ptr->data, ptr->length);

    BIO_free_all(chain);

    return out;
}

std::string Base64Decode(const std::string& encoded) noexcept
{
    if (encoded.empty())
    {
        return {};
    }

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()));
    BIO* chain = BIO_push(b64, mem);

    std::string out;
    out.resize(encoded.size());
    int decoded = BIO_read(chain, &out[0], static_cast<int>(out.size()));
    BIO_free_all(chain);

    if (decoded <= 0)
    {
        return {};
    }
    out.resize(static_cast<size_t>(decoded));

    return out;
}

} // namespace bkkms
