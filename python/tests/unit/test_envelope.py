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

import base64
import importlib
import json
from pathlib import Path

import pytest

from bk_kms import (
    ConsumeEnvelope,
    CredentialType,
    CryptoBackendUnavailableError,
    CryptoError,
    EnvelopeDecodeError,
    decrypt_envelope,
)

FIXTURE = json.loads((Path(__file__).parents[1] / "fixtures" / "interop_vectors.json").read_text(encoding="utf-8"))


def _encode_envelope(payload: object) -> str:
    return base64.b64encode(json.dumps(payload).encode()).decode()


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(
            name,
            marks=pytest.mark.gm if "sm2" in name or "sm4" in name else (),
        )
        for name in sorted(FIXTURE["vectors"])
    ],
)
def test_decrypt_envelope_parses_go_results(name: str) -> None:
    vector = FIXTURE["vectors"][name]

    results = decrypt_envelope(ConsumeEnvelope(vector["envelope"], vector["private_key"]))

    assert len(results) == 2
    assert results[0].ok
    assert results[0].credential is not None
    assert results[0].credential.type is CredentialType.SINGLE_PASSWORD
    assert results[0].credential.auth_info.password == "secret"
    assert not results[1].ok
    assert results[1].credential is None


@pytest.mark.parametrize(
    "envelope",
    [
        ConsumeEnvelope("", "private"),
        ConsumeEnvelope("invalid-base64", "private"),
        ConsumeEnvelope("e30=", "private"),
    ],
)
def test_decrypt_envelope_rejects_malformed_input(envelope: ConsumeEnvelope) -> None:
    with pytest.raises(EnvelopeDecodeError):
        decrypt_envelope(envelope)


def test_decrypt_envelope_rejects_non_object_payload() -> None:
    with pytest.raises(EnvelopeDecodeError, match="JSON object"):
        decrypt_envelope(ConsumeEnvelope(_encode_envelope([]), "private"))


def test_decrypt_envelope_rejects_unsupported_algorithm() -> None:
    payload = {
        "asymmetric_type": "future",
        "symmetric_type": "AES",
        "symmetric_mode": "CBC",
        "encrypted_key": "encrypted-key",
        "ciphertext": "ciphertext",
    }

    with pytest.raises(EnvelopeDecodeError, match="unsupported algorithm"):
        decrypt_envelope(ConsumeEnvelope(_encode_envelope(payload), "private"))


def test_decrypt_envelope_wraps_invalid_symmetric_key_length(monkeypatch: pytest.MonkeyPatch) -> None:
    import bk_kms.envelope as envelope_module

    vector = FIXTURE["vectors"]["rsa_aes_cbc"]
    monkeypatch.setattr(envelope_module, "decrypt_asymmetric", lambda *args: b"short")

    with pytest.raises(EnvelopeDecodeError, match="failed to decrypt") as exc_info:
        decrypt_envelope(ConsumeEnvelope(vector["envelope"], vector["private_key"]))

    assert isinstance(exc_info.value.__cause__, CryptoError)


@pytest.mark.parametrize(
    ("plaintext", "message"),
    [
        (b"not-json", "not valid JSON"),
        (b"{}", "JSON array"),
        (b"[1]", "JSON object"),
    ],
)
def test_decrypt_envelope_rejects_invalid_decrypted_results(
    monkeypatch: pytest.MonkeyPatch,
    plaintext: bytes,
    message: str,
) -> None:
    import bk_kms.envelope as envelope_module

    vector = FIXTURE["vectors"]["rsa_aes_cbc"]
    monkeypatch.setattr(envelope_module, "decrypt_asymmetric", lambda *args: b"0123456789abcdef")
    monkeypatch.setattr(envelope_module, "decrypt_symmetric", lambda *args: plaintext)

    with pytest.raises(EnvelopeDecodeError, match=message):
        decrypt_envelope(ConsumeEnvelope(vector["envelope"], vector["private_key"]))


def test_decrypt_envelope_preserves_missing_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from bk_kms.crypto import bkcrypto as backend

    vector = FIXTURE["vectors"]["sm2_sm4_cbc"]
    original_import_module = importlib.import_module

    def reject_gm_dependency(name: str):
        if name.startswith("tongsuopy"):
            raise ModuleNotFoundError(name)
        return original_import_module(name)

    monkeypatch.setattr(backend.importlib, "import_module", reject_gm_dependency)

    with pytest.raises(CryptoBackendUnavailableError):
        decrypt_envelope(ConsumeEnvelope(vector["envelope"], vector["private_key"]))


def test_decrypt_envelope_wraps_invalid_result_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    import bk_kms.envelope as envelope_module

    vector = FIXTURE["vectors"]["rsa_aes_cbc"]
    monkeypatch.setattr(
        envelope_module,
        "decrypt_asymmetric",
        lambda ciphertext, crypto_type, private_key: b"0123456789abcdef",
    )
    monkeypatch.setattr(
        envelope_module,
        "decrypt_symmetric",
        lambda ciphertext, crypto_type, mode, key: b'[{"credential_id":1,"err_code":0}]',
    )

    with pytest.raises(EnvelopeDecodeError, match="credential result contains invalid fields"):
        decrypt_envelope(ConsumeEnvelope(vector["envelope"], vector["private_key"]))
