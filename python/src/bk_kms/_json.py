#
# TencentBlueKing is pleased to support the open source community by making
# 蓝鲸智云 - 凭证管理服务(BlueKing - Key Management Service) available.
# Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
# Licensed under the MIT License (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
# http://opensource.org/licenses/MIT
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.We undertake not
# to change the open source license (MIT license) applicable to the current version
# of the project delivered to anyone in the future.
#

"""Wire JSON compatible with the BK-KMS Go implementations."""

import json
from collections.abc import Mapping
from typing import Any

_UTF8_BOM = b"\xef\xbb\xbf"


def loads(value: Any) -> Any:
    """Decode strict JSON and normalize isolated Unicode surrogates."""

    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if raw.startswith(_UTF8_BOM):
            raise ValueError("UTF-8 BOM is not allowed")
        value = raw.decode("utf-8")
    elif isinstance(value, str) and value.startswith("\ufeff"):
        raise ValueError("UTF-8 BOM is not allowed")

    decoded = json.loads(value, parse_constant=_reject_constant)
    return _normalize_surrogates(decoded)


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _normalize_surrogates(value: Any) -> Any:
    """Recursively replace isolated Unicode surrogates to match Go's JSON decoder."""

    if isinstance(value, str):
        return "".join("\ufffd" if 0xD800 <= ord(char) <= 0xDFFF else char for char in value)
    if isinstance(value, list):
        return [_normalize_surrogates(item) for item in value]
    if isinstance(value, Mapping):
        return {_normalize_surrogates(key): _normalize_surrogates(item) for key, item in value.items()}
    return value
