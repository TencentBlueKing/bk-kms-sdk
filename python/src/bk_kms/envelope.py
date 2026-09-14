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

"""Envelope decoding and local hybrid decryption."""

import base64
import binascii
from collections.abc import Mapping
from typing import Any

from ._crypto import AsymmetricType, CryptoMode, SymmetricType, decrypt_asymmetric, decrypt_symmetric
from ._json import loads
from .exceptions import CryptoBackendUnavailableError, CryptoError, EnvelopeDecodeError


def decrypt(envelope: str, private_key: str) -> str:
    """Decrypt a Base64 envelope using its matching Base64 PEM private key.

    Return the original UTF-8 plaintext without parsing its contents.
    Malformed inputs and decryption failures raise EnvelopeDecodeError;
    an unavailable optional GM backend raises CryptoBackendUnavailableError.
    """

    if not isinstance(envelope, str) or not envelope:
        raise EnvelopeDecodeError("envelope must be a non-empty string")
    if not isinstance(private_key, str) or not private_key:
        raise EnvelopeDecodeError("private key must be a non-empty string")

    payload = _decode_envelope(envelope)
    try:
        asymmetric_type = AsymmetricType(_required_string(payload, "asymmetric_type"))
        symmetric_type = SymmetricType(_required_string(payload, "symmetric_type"))
        symmetric_mode = CryptoMode(_required_string(payload, "symmetric_mode"))
        encrypted_key = _required_string(payload, "encrypted_key")
        ciphertext = _required_string(payload, "ciphertext")
    except ValueError as exc:
        raise EnvelopeDecodeError("envelope contains an unsupported algorithm") from exc

    try:
        symmetric_key = decrypt_asymmetric(encrypted_key, asymmetric_type, private_key)
        plaintext = decrypt_symmetric(ciphertext, symmetric_type, symmetric_mode, symmetric_key)
    except CryptoBackendUnavailableError:
        raise
    except CryptoError as exc:
        raise EnvelopeDecodeError("failed to decrypt credential envelope") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EnvelopeDecodeError("decrypted plaintext is not valid UTF-8") from exc


def _decode_envelope(value: str) -> Mapping[str, Any]:
    """Decode strict Base64 JSON and require an object before crypto dispatch."""

    try:
        decoded = base64.b64decode(value, validate=True)
        payload = loads(decoded)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise EnvelopeDecodeError("credential envelope is not valid base64 JSON") from exc
    if not isinstance(payload, Mapping):
        raise EnvelopeDecodeError("credential envelope must contain a JSON object")
    return payload


def _required_string(payload: Mapping[str, Any], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value:
        raise EnvelopeDecodeError(f"credential envelope field {name!r} must be a non-empty string")
    return value
