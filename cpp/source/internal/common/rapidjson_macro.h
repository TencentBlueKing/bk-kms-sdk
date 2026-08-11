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

#ifndef _BK_KMS_COMMON_RAPIDJSON_MACRO_H_
#define _BK_KMS_COMMON_RAPIDJSON_MACRO_H_

#include <string>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

// clang-format off
#define RAPIDJSON_CHECK_IS_BOOL(obj, key)   ((obj).HasMember(key) && (obj)[key].IsBool())
#define RAPIDJSON_CHECK_IS_INT32(obj, key)  ((obj).HasMember(key) && (obj)[key].IsInt())
#define RAPIDJSON_CHECK_IS_INT64(obj, key)  ((obj).HasMember(key) && (obj)[key].IsInt64())
#define RAPIDJSON_CHECK_IS_STRING(obj, key) ((obj).HasMember(key) && (obj)[key].IsString())
#define RAPIDJSON_CHECK_IS_ARRAY(obj, key)  ((obj).HasMember(key) && (obj)[key].IsArray())
#define RAPIDJSON_CHECK_IS_OBJECT(obj, key) ((obj).HasMember(key) && (obj)[key].IsObject())

#define RAPIDJSON_GET_BOOL(obj, key, def)   (RAPIDJSON_CHECK_IS_BOOL(obj, key)   ? (obj)[key].GetBool()   : (def))
#define RAPIDJSON_GET_INT32(obj, key, def)  (RAPIDJSON_CHECK_IS_INT32(obj, key)  ? (obj)[key].GetInt()    : (def))
#define RAPIDJSON_GET_INT64(obj, key, def)  (RAPIDJSON_CHECK_IS_INT64(obj, key)  ? (obj)[key].GetInt64()  : (def))
#define RAPIDJSON_GET_STRING(obj, key, def) (RAPIDJSON_CHECK_IS_STRING(obj, key) ? std::string((obj)[key].GetString(), (obj)[key].GetStringLength()) : std::string(def))

#define RAPIDJSON_SET_BOOL(w, key, value)   do { (w).Key(key); (w).Bool(value);      } while (0)
#define RAPIDJSON_SET_INT32(w, key, value)  do { (w).Key(key); (w).Int(value);       } while (0)
#define RAPIDJSON_SET_INT64(w, key, value)  do { (w).Key(key); (w).Int64(value);     } while (0)
#define RAPIDJSON_SET_STRING(w, key, value) do { (w).Key(key); (w).String(value);    } while (0)
// clang-format on

#endif // _BK_KMS_COMMON_RAPIDJSON_MACRO_H_
