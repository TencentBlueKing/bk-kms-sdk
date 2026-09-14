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
import sys
from pathlib import Path
from types import ModuleType

import pytest

from bk_kms import CryptoBackendUnavailableError, CryptoError
from bk_kms._crypto import AsymmetricType, CryptoMode, SymmetricType, decrypt_asymmetric, decrypt_symmetric

FIXTURE = json.loads((Path(__file__).parents[1] / "fixtures" / "interop_vectors.json").read_text(encoding="utf-8"))
PYTHON_KEY_FIXTURE = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "python_key_interop_vectors.json").read_text(encoding="utf-8")
)

gm = pytest.mark.gm


@gm
def test_sm2_key_generated_by_python_is_accepted_by_go() -> None:
    vector = PYTHON_KEY_FIXTURE["vectors"]["sm2"]

    plaintext = decrypt_asymmetric(
        vector["ciphertext"],
        AsymmetricType.SM2,
        vector["private_key"],
    )

    assert plaintext == base64.b64decode(PYTHON_KEY_FIXTURE["plaintext_b64"])


@pytest.mark.parametrize("name", ["sm2_sm4_cbc", "sm2_sm4_ctr"])
@gm
def test_sm2_decrypts_go_data_key(name: str) -> None:
    vector = FIXTURE["vectors"][name]
    envelope = json.loads(base64.b64decode(vector["envelope"]))

    key = decrypt_asymmetric(
        envelope["encrypted_key"],
        AsymmetricType.SM2,
        vector["private_key"],
    )

    assert key == b"0123456789abcdef"


@gm
def test_sm2_decrypt_preserves_non_utf8_data_key_bytes() -> None:
    vector = json.loads((Path(__file__).parents[1] / "fixtures" / "sm2_binary_key.json").read_text(encoding="utf-8"))

    key = decrypt_asymmetric(
        vector["ciphertext"],
        AsymmetricType.SM2,
        vector["private_key"],
    )

    assert key == base64.b64decode(vector["plaintext_b64"])


@pytest.mark.parametrize(
    ("name", "mode"),
    [
        ("sm2_sm4_cbc", CryptoMode.CBC),
        ("sm2_sm4_ctr", CryptoMode.CTR),
    ],
)
@gm
def test_sm4_decrypts_go_ciphertext(name: str, mode: CryptoMode) -> None:
    envelope = json.loads(base64.b64decode(FIXTURE["vectors"][name]["envelope"]))

    plaintext = decrypt_symmetric(
        envelope["ciphertext"],
        SymmetricType.SM4,
        mode,
        b"0123456789abcdef",
    )

    assert plaintext.decode() == FIXTURE["plaintext"]


@pytest.mark.parametrize("mode", [CryptoMode.CBC, CryptoMode.CTR])
def test_sm4_decrypt_explicitly_disables_bkcrypto_padding(
    monkeypatch: pytest.MonkeyPatch,
    mode: CryptoMode,
) -> None:
    from bkcrypto import constants

    from bk_kms import _crypto as backend

    captured: dict[str, object] = {}

    class FakeSM4:
        def __init__(self, key: bytes, **options: object) -> None:
            captured["key"] = key
            captured.update(options)

        def decrypt_bytes(self, ciphertext: str) -> bytes:
            captured["ciphertext"] = ciphertext
            return b"plaintext\x07\x07\x07\x07\x07\x07\x07" if mode is CryptoMode.CBC else b"plaintext"

    module = ModuleType("bkcrypto.symmetric.ciphers.sm4")
    module.SM4SymmetricCipher = FakeSM4
    monkeypatch.setitem(sys.modules, module.__name__, module)
    raw = b"\x00" * 16 + (b"\x00" * 16 if mode is CryptoMode.CBC else b"payload")
    ciphertext = base64.b64encode(raw).decode("ascii")

    assert backend.decrypt_sm4(ciphertext, b"0123456789abcdef", mode) == b"plaintext"
    assert captured["mode"].value == mode.value
    assert captured["padding"] is constants.SymmetricPadding.NONE
    assert captured["ciphertext"] == ciphertext


@gm
@pytest.mark.parametrize(
    ("mode", "raw"),
    [
        (CryptoMode.CBC, b"\x00" * 16),
        (CryptoMode.CTR, b"\x00" * 16),
    ],
)
def test_sm4_rejects_ciphertext_without_payload(mode: CryptoMode, raw: bytes) -> None:
    with pytest.raises(CryptoError, match="too short"):
        decrypt_symmetric(
            base64.b64encode(raw).decode(),
            SymmetricType.SM4,
            mode,
            b"0123456789abcdef",
        )


def test_missing_gm_backend_does_not_affect_standard_crypto(monkeypatch: pytest.MonkeyPatch) -> None:

    original_import = builtins.__import__

    def reject_gm_dependency(name: str, *args, **kwargs):
        if name in ("bkcrypto.asymmetric.ciphers.sm2", "bkcrypto.symmetric.ciphers.sm4"):
            raise ModuleNotFoundError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_gm_dependency)

    with pytest.raises(CryptoBackendUnavailableError, match=r"bk-kms-sdk\[gm\]"):
        decrypt_asymmetric(
            PYTHON_KEY_FIXTURE["vectors"]["sm2"]["ciphertext"],
            AsymmetricType.SM2,
            PYTHON_KEY_FIXTURE["vectors"]["sm2"]["private_key"],
        )

    test_rsa_vector = PYTHON_KEY_FIXTURE["vectors"]["rsa"]
    assert decrypt_asymmetric(
        test_rsa_vector["ciphertext"], AsymmetricType.RSA, test_rsa_vector["private_key"]
    ) == base64.b64decode(PYTHON_KEY_FIXTURE["plaintext_b64"])


def test_broken_native_gm_backend_preserves_original_error(monkeypatch: pytest.MonkeyPatch) -> None:

    native_error = OSError("missing native library")

    original_import = builtins.__import__

    def reject_gm_dependency(name: str, *args, **kwargs):
        if name in ("bkcrypto.asymmetric.ciphers.sm2", "bkcrypto.symmetric.ciphers.sm4"):
            raise native_error
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_gm_dependency)

    with pytest.raises(CryptoBackendUnavailableError) as exc_info:
        decrypt_asymmetric(
            PYTHON_KEY_FIXTURE["vectors"]["sm2"]["ciphertext"],
            AsymmetricType.SM2,
            PYTHON_KEY_FIXTURE["vectors"]["sm2"]["private_key"],
        )

    assert exc_info.value.__cause__ is native_error


@gm
@pytest.mark.parametrize(
    ("vector_name", "unused_module"),
    [
        ("sm2_aes_cbc", "bkcrypto.symmetric.ciphers.sm4"),
        ("rsa_sm4_cbc", "bkcrypto.asymmetric.ciphers.sm2"),
    ],
)
def test_decrypt_loads_only_required_gm_algorithm(
    monkeypatch: pytest.MonkeyPatch, vector_name: str, unused_module: str
) -> None:
    from bk_kms import decrypt

    original_import = builtins.__import__

    def reject_unused_algorithm(name: str, *args, **kwargs):
        if name == unused_module:
            raise ModuleNotFoundError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_unused_algorithm)
    vector = FIXTURE["vectors"][vector_name]
    assert decrypt(vector["envelope"], vector["private_key"]) == FIXTURE["plaintext"]
