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

"""Canonical request construction and BK-KMS HMAC signing."""

import hashlib
import hmac
import uuid
from collections.abc import Sequence
from typing import Optional

from ._json import dumps_bytes
from .exceptions import ValidationError
from .models import CryptoInfo


def new_nonce() -> str:
    """Return a wire-compatible UUID v4 nonce without dashes."""

    return uuid.uuid4().hex


def build_consume_request(
    *,
    credential_names: Optional[Sequence[str]],
    crypto: CryptoInfo,
    public_key: str,
) -> bytes:
    """Build the canonical consume payload and the exact bytes to sign and send."""

    if isinstance(credential_names, (str, bytes, bytearray)):
        raise ValidationError("credential_names must be a sequence of strings")
    names = list(credential_names) if credential_names is not None else []
    if any(not isinstance(item, str) for item in names):
        raise ValidationError("credential_names must contain strings")
    try:
        for name in names:
            name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError("credential_names must contain valid Unicode strings") from exc

    payload: dict[str, object] = {
        "credential_id_list": [],
        "credential_name_list": names,
        "crypto": crypto.to_wire(),
        "public_key": public_key,
    }
    return dumps_bytes(payload)


def build_authorization_header(app_code: str, app_secret: str) -> str:
    """Serialize API Gateway application credentials as compact JSON."""

    return dumps_bytes(
        {
            "bk_app_code": app_code,
            "bk_app_secret": app_secret,
        }
    ).decode("utf-8")


def sign_request(
    *,
    secret_key: str,
    nonce: str,
    timestamp: str,
    content: bytes,
) -> str:
    """Return the two-stage HMAC-SHA256 signature required by BK-KMS."""

    content_hash = hashlib.sha256(content).hexdigest()
    string_to_sign = "\n".join((timestamp, nonce, content_hash)).encode("utf-8")
    signing_key = hmac.new(secret_key.encode("utf-8"), nonce.encode("utf-8"), hashlib.sha256).digest()
    return hmac.new(signing_key, string_to_sign, hashlib.sha256).hexdigest()
