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

"""Public immutable models and wire-value validation."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Optional, Union

from .exceptions import ValidationError

ERR_CODE_OK = 0
ERR_CODE_GENERIC_ERROR = 1034000
ERR_CODE_NOT_FOUND = 1034003
ERR_CODE_PERMISSION_DENIED = 1034008
ERR_CODE_ACCESS_KEY_DISABLED = 1034011
ERR_CODE_ACCESS_KEY_EXPIRED = 1034012
ERR_CODE_ACCESS_KEY_NOT_BOUND = 1034013
ERR_CODE_NONCE_ALREADY_USED = 1034014
ERR_CODE_SIGNATURE_MISMATCH = 1034015
ERR_CODE_REQUEST_TIME_TOO_SKEWED = 1034016


class AsymmetricType(StrEnum):
    """Supported asymmetric algorithms."""

    RSA = "RSA"
    SM2 = "SM2"


class SymmetricType(StrEnum):
    """Supported symmetric algorithms."""

    AES = "AES"
    SM4 = "SM4"


class CryptoMode(StrEnum):
    """Supported symmetric cipher modes."""

    CBC = "CBC"
    CTR = "CTR"


@dataclass(frozen=True)
class CryptoInfo:
    """Algorithm combination used to encrypt a credential response envelope.

    :param asymmetric_type: Algorithm used to encrypt the request-scoped data key.
    :param symmetric_type: Algorithm used to encrypt the credential payload.
    :param symmetric_mode: Mode used by the symmetric algorithm.
    """

    asymmetric_type: AsymmetricType
    symmetric_type: SymmetricType
    symmetric_mode: CryptoMode

    def __post_init__(self) -> None:
        if not isinstance(self.asymmetric_type, AsymmetricType):
            raise ValidationError(f"invalid asymmetric crypto type: {self.asymmetric_type}")
        if not isinstance(self.symmetric_type, SymmetricType):
            raise ValidationError(f"invalid symmetric crypto type: {self.symmetric_type}")
        if not isinstance(self.symmetric_mode, CryptoMode):
            raise ValidationError(f"invalid crypto mode: {self.symmetric_mode}")

    @classmethod
    def rsa_aes_cbc(cls) -> "CryptoInfo":
        """Return the default RSA and AES-CBC algorithm combination.

        :return: RSA for key encryption and AES-CBC for credential encryption.
        :rtype: CryptoInfo
        """

        return cls(AsymmetricType.RSA, SymmetricType.AES, CryptoMode.CBC)

    @classmethod
    def sm2_sm4_cbc(cls) -> "CryptoInfo":
        """Return the optional SM2 and SM4-CBC algorithm combination.

        :return: SM2 for key encryption and SM4-CBC for credential encryption.
        :rtype: CryptoInfo
        """

        return cls(AsymmetricType.SM2, SymmetricType.SM4, CryptoMode.CBC)

    def to_wire(self) -> dict[str, str]:
        """Serialize the validated algorithm selection for a KMS request.

        :return: Wire field names mapped to their protocol enum values.
        :rtype: dict[str, str]
        """

        return {
            "asymmetric_type": self.asymmetric_type.value,
            "symmetric_type": self.symmetric_type.value,
            "symmetric_mode": self.symmetric_mode.value,
        }


class CredentialType(StrEnum):
    """Credential shapes currently understood by this SDK."""

    SINGLE_PASSWORD = "single_password"
    USERNAME_PASSWORD = "username_password"
    SINGLE_SECRET_KEY = "single_secret_key"
    APP_ID_SECRET_KEY = "app_id_secret_key"


_CREDENTIAL_REQUIRED_FIELDS: dict[CredentialType, tuple[str, ...]] = {
    CredentialType.SINGLE_PASSWORD: ("password",),
    CredentialType.USERNAME_PASSWORD: ("username", "password"),
    CredentialType.SINGLE_SECRET_KEY: ("secret_key",),
    CredentialType.APP_ID_SECRET_KEY: ("app_id", "secret_key"),
}


@dataclass(frozen=True)
class AuthInfo:
    """Sensitive authentication fields returned for a credential.

    All fields are excluded from ``repr`` to avoid accidental disclosure.

    :param password: Password for password-based credential types.
    :param username: Username for username/password credentials.
    :param secret_key: Secret key for secret-key credential types.
    :param app_id: Application ID paired with an application secret key.
    """

    password: Optional[str] = field(default=None, repr=False)
    username: Optional[str] = field(default=None, repr=False)
    secret_key: Optional[str] = field(default=None, repr=False)
    app_id: Optional[str] = field(default=None, repr=False)

    @classmethod
    def from_wire(cls, value: Mapping[str, Any]) -> "AuthInfo":
        """Decode authentication fields from a wire object.

        Missing, null, or empty fields are normalized to ``None``.

        :param value: Mapping containing authentication fields returned by KMS.
        :return: Decoded sensitive authentication fields.
        :rtype: AuthInfo
        :raises ValidationError: If a present authentication field is not a string.
        """

        return cls(
            password=_optional_string_field(value, "password"),
            username=_optional_string_field(value, "username"),
            secret_key=_optional_string_field(value, "secret_key"),
            app_id=_optional_string_field(value, "app_id"),
        )


CredentialTypeValue = Union[CredentialType, str]


@dataclass(frozen=True)
class Credential:
    """Credential metadata and its sensitive authentication payload.

    :param name: Credential name returned by KMS.
    :param type: Known credential enum or an unknown future wire value.
    :param auth_info: Sensitive authentication fields for the credential.
    :param annotation: Optional credential annotation returned by KMS.
    """

    name: str
    type: CredentialTypeValue
    auth_info: AuthInfo = field(default_factory=AuthInfo)
    annotation: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.type, CredentialType):
            credential_type = self.type
        elif isinstance(self.type, str):
            try:
                credential_type = CredentialType(self.type)
            except ValueError:
                return
            object.__setattr__(self, "type", credential_type)
        else:
            return

        expected = _CREDENTIAL_REQUIRED_FIELDS[credential_type]
        for name in expected:
            if not getattr(self.auth_info, name):
                raise ValidationError(f"credential auth_info field {name!r} must be a non-empty string")
        for name in ("password", "username", "secret_key", "app_id"):
            if name not in expected and getattr(self.auth_info, name):
                raise ValidationError(f"credential auth_info field {name!r} is not valid for type {credential_type}")

    @classmethod
    def from_wire(cls, value: Mapping[str, Any]) -> "Credential":
        """Decode a credential while preserving unknown future type strings.

        :param value: Mapping containing credential metadata and authentication fields.
        :return: Decoded credential with a typed or forward-compatible type value.
        :rtype: Credential
        :raises ValidationError: If a credential field has an invalid wire type.
        """

        name = _required_string_field(value, "name")
        credential_type = _required_string_field(value, "type")

        raw_auth_info = value.get("auth_info")
        if isinstance(raw_auth_info, Mapping):
            auth_info = AuthInfo.from_wire(raw_auth_info)
        else:
            raise ValidationError("field 'auth_info' must be an object")
        return cls(
            name=name,
            type=credential_type,
            auth_info=auth_info,
            annotation=_string_field(value, "annotation"),
        )


@dataclass(frozen=True)
class ConsumeResult:
    """Outcome for one credential in a successful batch request.

    Request-level failures raise exceptions instead of producing this model.

    :param credential_id: Credential ID returned by KMS.
    :param err_code: Per-credential KMS result code.
    :param err_msg: Per-credential KMS result message.
    :param credential: Resolved credential, or ``None`` when resolution failed.
    """

    credential_id: int
    err_code: int
    err_msg: str
    credential: Optional[Credential] = None

    def __post_init__(self) -> None:
        if self.err_code == ERR_CODE_OK and self.credential is None:
            raise ValidationError("credential must be provided for a successful result")

    @property
    def ok(self) -> bool:
        """Return whether this individual credential was resolved successfully.

        :return: ``True`` only when :attr:`err_code` equals :data:`ERR_CODE_OK`.
        :rtype: bool
        """

        return self.err_code == ERR_CODE_OK

    @classmethod
    def from_wire(cls, value: Mapping[str, Any]) -> "ConsumeResult":
        """Decode and range-check one per-credential result.

        :param value: Mapping containing one result returned by KMS.
        :return: Validated per-credential result.
        :rtype: ConsumeResult
        :raises ValidationError: If a field has an invalid type or integer range.
        """

        credential_id = _required_int_field(value, "credential_id", bits=64)
        err_code = _required_int_field(value, "err_code", bits=32)
        raw_credential = value.get("credential")
        if raw_credential is None:
            credential = None
        elif isinstance(raw_credential, Mapping):
            credential = Credential.from_wire(raw_credential)
        else:
            raise ValidationError("field 'credential' must be an object")
        return cls(
            credential_id=credential_id,
            err_code=err_code,
            err_msg=_string_field(value, "err_msg"),
            credential=credential,
        )


@dataclass(frozen=True)
class ConsumeEnvelope:
    """Encrypted response paired with the private key needed to decrypt it.

    Both values must be protected as secrets because together they can recover
    credential plaintext. They are excluded from ``repr``.

    :param envelope: Base64-encoded encrypted credential response.
    :param private_key: Request-scoped private key used to decrypt the envelope.
    """

    envelope: str = field(repr=False)
    private_key: str = field(repr=False)


def _string_field(value: Mapping[str, Any], name: str) -> str:
    field_value = value.get(name)
    if field_value is None:
        return ""
    if not isinstance(field_value, str):
        raise ValidationError(f"field {name!r} must be a string")
    return field_value


def _required_string_field(value: Mapping[str, Any], name: str) -> str:
    field_value = _string_field(value, name)
    if not field_value:
        raise ValidationError(f"field {name!r} must be a non-empty string")
    return field_value


def _optional_string_field(value: Mapping[str, Any], name: str) -> Optional[str]:
    field_value = _string_field(value, name)
    return field_value or None


def _required_int_field(value: Mapping[str, Any], name: str, *, bits: int) -> int:
    """Decode a required integer field and enforce its signed protocol width.

    Missing and null fields are rejected rather than inheriting Go's zero-value semantics.
    """

    field_value = value.get(name)
    if isinstance(field_value, bool) or not isinstance(field_value, int):
        raise ValidationError(f"field {name!r} must be an integer")
    minimum = -(2 ** (bits - 1))
    maximum = 2 ** (bits - 1) - 1
    if field_value < minimum or field_value > maximum:
        raise ValidationError(f"field {name!r} must fit in signed {bits}-bit integers")
    return field_value
