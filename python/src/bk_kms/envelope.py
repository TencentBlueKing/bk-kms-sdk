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

"""Credential-envelope decoding and local hybrid decryption."""

import base64
import binascii
from collections.abc import Mapping
from typing import Any

from ._json import loads
from .crypto import decrypt_asymmetric, decrypt_symmetric
from .exceptions import CryptoBackendUnavailableError, CryptoError, EnvelopeDecodeError, ValidationError
from .models import AsymmetricType, ConsumeEnvelope, ConsumeResult, CryptoMode, SymmetricType


def decrypt_envelope(envelope: ConsumeEnvelope) -> list[ConsumeResult]:
    """Decrypt and validate all per-credential results in an envelope.

    Unsupported optional crypto backends remain distinguishable; malformed
    envelopes and other cryptographic failures are reported as decode errors.

    :param envelope: Encrypted response and matching request-scoped private key.
    :return: Validated per-credential results decoded from the envelope.
    :rtype: list[ConsumeResult]
    :raises CryptoBackendUnavailableError: If the selected optional crypto backend is unavailable.
    :raises EnvelopeDecodeError: If the envelope is malformed, unsupported, or cannot be decrypted.
    """

    if not envelope.envelope or not envelope.private_key:
        raise EnvelopeDecodeError("envelope and private key cannot be empty")

    payload = _decode_envelope(envelope.envelope)
    try:
        asymmetric_type = AsymmetricType(_required_string(payload, "asymmetric_type"))
        symmetric_type = SymmetricType(_required_string(payload, "symmetric_type"))
        symmetric_mode = CryptoMode(_required_string(payload, "symmetric_mode"))
        encrypted_key = _required_string(payload, "encrypted_key")
        ciphertext = _required_string(payload, "ciphertext")
    except ValueError as exc:
        raise EnvelopeDecodeError("envelope contains an unsupported algorithm") from exc

    try:
        symmetric_key = decrypt_asymmetric(encrypted_key, asymmetric_type, envelope.private_key)
        plaintext = decrypt_symmetric(ciphertext, symmetric_type, symmetric_mode, symmetric_key)
    except CryptoBackendUnavailableError:
        raise
    except CryptoError as exc:
        raise EnvelopeDecodeError("failed to decrypt credential envelope") from exc

    try:
        raw_results = loads(plaintext)
    except (UnicodeDecodeError, ValueError) as exc:
        raise EnvelopeDecodeError("decrypted credential results are not valid JSON") from exc
    if not isinstance(raw_results, list):
        raise EnvelopeDecodeError("decrypted credential results must be a JSON array")

    results: list[ConsumeResult] = []
    for item in raw_results:
        if not isinstance(item, Mapping):
            raise EnvelopeDecodeError("credential result must be a JSON object")
        try:
            results.append(ConsumeResult.from_wire(item))
        except ValidationError as exc:
            raise EnvelopeDecodeError("credential result contains invalid fields") from exc
    return results


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
