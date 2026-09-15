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
import builtins
import json
from pathlib import Path

import pytest

from bk_kms import (
    CryptoBackendUnavailableError,
    CryptoError,
    EnvelopeDecodeError,
    decrypt,
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
def test_decrypt_returns_go_plaintext(name: str) -> None:
    vector = FIXTURE["vectors"][name]

    assert decrypt(vector["envelope"], vector["private_key"]) == FIXTURE["plaintext"]


@pytest.mark.parametrize(
    ("envelope", "private_key"),
    [
        ("", "private"),
        ("e30=", ""),
        (None, "private"),
        ("e30=", None),
        (123, "private"),
        ("e30=", 123),
        ("invalid-base64", "private"),
        ("e30=", "private"),
    ],
)
def test_decrypt_envelope_rejects_malformed_input(envelope: object, private_key: object) -> None:
    with pytest.raises(EnvelopeDecodeError):
        decrypt(envelope, private_key)


def test_decrypt_envelope_rejects_non_object_payload() -> None:
    with pytest.raises(EnvelopeDecodeError, match="JSON object"):
        decrypt(_encode_envelope([]), "private")


def test_decrypt_envelope_rejects_unsupported_algorithm() -> None:
    payload = {
        "asymmetric_type": "future",
        "symmetric_type": "AES",
        "symmetric_mode": "CBC",
        "encrypted_key": "encrypted-key",
        "ciphertext": "ciphertext",
    }

    with pytest.raises(EnvelopeDecodeError, match="unsupported algorithm"):
        decrypt(_encode_envelope(payload), "private")


def test_decrypt_envelope_wraps_invalid_symmetric_key_length(monkeypatch: pytest.MonkeyPatch) -> None:
    import bk_kms.envelope as envelope_module

    vector = FIXTURE["vectors"]["rsa_aes_cbc"]
    monkeypatch.setattr(envelope_module, "decrypt_asymmetric", lambda *args: b"short")

    with pytest.raises(EnvelopeDecodeError, match="failed to decrypt") as exc_info:
        decrypt(vector["envelope"], vector["private_key"])

    assert isinstance(exc_info.value.__cause__, CryptoError)


@pytest.mark.parametrize("plaintext", [b"not-json", b"{}", b"[1]", b"", ' {"密码": "值"} \n'.encode()])
def test_decrypt_preserves_plaintext(monkeypatch: pytest.MonkeyPatch, plaintext: bytes) -> None:
    import bk_kms.envelope as envelope_module

    vector = FIXTURE["vectors"]["rsa_aes_cbc"]
    monkeypatch.setattr(envelope_module, "decrypt_symmetric", lambda *args: plaintext)
    assert decrypt(vector["envelope"], vector["private_key"]) == plaintext.decode("utf-8")


def test_decrypt_rejects_non_utf8_plaintext(monkeypatch: pytest.MonkeyPatch) -> None:
    import bk_kms.envelope as envelope_module

    vector = FIXTURE["vectors"]["rsa_aes_cbc"]
    monkeypatch.setattr(envelope_module, "decrypt_symmetric", lambda *args: b"\xff")
    with pytest.raises(EnvelopeDecodeError, match="UTF-8"):
        decrypt(vector["envelope"], vector["private_key"])


def test_decrypt_envelope_preserves_missing_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:

    vector = FIXTURE["vectors"]["sm2_sm4_cbc"]
    original_import = builtins.__import__

    def reject_gm_dependency(name: str, *args, **kwargs):
        if name in ("bkcrypto.asymmetric.ciphers.sm2", "bkcrypto.symmetric.ciphers.sm4"):
            raise ModuleNotFoundError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_gm_dependency)

    with pytest.raises(CryptoBackendUnavailableError):
        decrypt(vector["envelope"], vector["private_key"])


@pytest.mark.parametrize("mode", ["CBC", "CTR"])
@pytest.mark.parametrize("plaintext", [' {"password": "值"} \n', "plain text", ""])
def test_decrypt_arbitrary_payload_roundtrip(mode: str, plaintext: str) -> None:
    from bkcrypto import constants
    from bkcrypto.asymmetric.ciphers import RSAAsymmetricCipher
    from bkcrypto.symmetric.ciphers import AESSymmetricCipher
    from cryptography.hazmat.primitives import hashes

    vector = FIXTURE["vectors"]["rsa_aes_cbc"]
    rsa = RSAAsymmetricCipher(
        private_key_string=base64.b64decode(vector["private_key"]).decode(),
        padding=constants.RSACipherPadding.PKCS1_OAEP,
        oaep_hash=hashes.SHA256(),
        mgf1_hash=hashes.SHA256(),
        enable_segmented_encryption=False,
    )
    key = b"0123456789abcdef"
    aes = AESSymmetricCipher(
        key=key,
        mode=constants.SymmetricMode(mode),
        padding=constants.SymmetricPadding.PKCS7 if mode == "CBC" else constants.SymmetricPadding.NONE,
        enable_iv=True,
        iv_size=16,
        enable_aad=False,
        encryption_metadata_combination_mode=constants.EncryptionMetadataCombinationMode.BYTES,
    )
    payload = {
        "asymmetric_type": "RSA",
        "symmetric_type": "AES",
        "symmetric_mode": mode,
        "encrypted_key": rsa.encrypt_bytes(key),
        "ciphertext": aes.encrypt_bytes(plaintext.encode()),
    }
    if mode == "CTR" and not plaintext:
        # Go/C++ and Python require at least one payload byte for CTR.
        with pytest.raises(EnvelopeDecodeError):
            decrypt(_encode_envelope(payload), vector["private_key"])
    else:
        assert decrypt(_encode_envelope(payload), vector["private_key"]) == plaintext
