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

"""Fail-fast Django settings bootstrap for BK-KMS credentials."""

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Optional, Union, cast

# Django doesn't ship inline typing metadata; this integration only needs its public exception class.
from django.core.exceptions import ImproperlyConfigured  # type: ignore[import-untyped]

from ..client import Client
from ..exceptions import BKMSException, ConfigurationError, CryptoBackendUnavailableError
from ..models import ConsumeResult, Credential, CredentialType, CryptoInfo


@dataclass(frozen=True)
class _Binding:
    credential_name: str
    credential_type: CredentialType


class CredentialStore(Mapping[str, Credential]):
    """Resolved KMS credentials indexed by application-defined aliases.

    The input mapping is copied and exposed through an immutable Mapping interface.
    Sensitive values are not included in ``repr``.

    :param credentials: Credentials indexed by the aliases used in application settings.
    """

    def __init__(self, credentials: Mapping[str, Credential]) -> None:
        self._credentials = MappingProxyType(dict(credentials))

    def __getitem__(self, alias: str) -> Credential:
        return self._credentials[alias]

    def __iter__(self) -> Iterator[str]:
        return iter(self._credentials)

    def __len__(self) -> int:
        return len(self._credentials)

    def __repr__(self) -> str:
        return f"CredentialStore(aliases={tuple(self._credentials)!r})"

    def username_password(self, alias: str) -> tuple[str, str]:
        """Return the username and password for a matching credential alias.

        :param alias: Application-defined credential alias.
        :return: Username and password in that order.
        :rtype: tuple[str, str]
        :raises ImproperlyConfigured: If the alias is missing or has the wrong type.
        """

        credential = self._require_type(alias, CredentialType.USERNAME_PASSWORD)
        return cast(str, credential.auth_info.username), cast(str, credential.auth_info.password)

    def database(self, alias: str) -> dict[str, str]:
        """Project a username/password credential into Django database keys.

        :param alias: Application-defined credential alias.
        :return: Mapping with ``USER`` and ``PASSWORD`` keys for a Django database configuration.
        :rtype: dict[str, str]
        :raises ImproperlyConfigured: If the alias is missing or has the wrong type.
        """

        username, password = self.username_password(alias)
        return {"USER": username, "PASSWORD": password}

    def password(self, alias: str) -> str:
        """Return a password from either supported password credential shape.

        :param alias: Application-defined credential alias.
        :return: Password from a single-password or username/password credential.
        :rtype: str
        :raises ImproperlyConfigured: If the alias is missing or has the wrong type.
        """

        credential = self._require_type(
            alias,
            CredentialType.SINGLE_PASSWORD,
            CredentialType.USERNAME_PASSWORD,
        )
        return cast(str, credential.auth_info.password)

    def secret_key(self, alias: str) -> str:
        """Return a secret key from either supported secret-key shape.

        :param alias: Application-defined credential alias.
        :return: Secret key from a single-secret-key or application credential.
        :rtype: str
        :raises ImproperlyConfigured: If the alias is missing or has the wrong type.
        """

        credential = self._require_type(
            alias,
            CredentialType.SINGLE_SECRET_KEY,
            CredentialType.APP_ID_SECRET_KEY,
        )
        return cast(str, credential.auth_info.secret_key)

    def app_id_secret_key(self, alias: str) -> tuple[str, str]:
        """Return the app ID and secret key for a matching credential alias.

        :param alias: Application-defined credential alias.
        :return: Application ID and secret key in that order.
        :rtype: tuple[str, str]
        :raises ImproperlyConfigured: If the alias is missing or has the wrong type.
        """

        credential = self._require_type(alias, CredentialType.APP_ID_SECRET_KEY)
        return cast(str, credential.auth_info.app_id), cast(str, credential.auth_info.secret_key)

    def _require_type(self, alias: str, *expected: CredentialType) -> Credential:
        credential = self._require_alias(alias)
        if credential.type not in expected:
            expected_text = " or ".join(item.value for item in expected)
            raise ImproperlyConfigured(
                f"BK-KMS credential alias {alias!r} has type {credential.type!s}; expected {expected_text}"
            )
        return credential

    def _require_alias(self, alias: str) -> Credential:
        try:
            return self[alias]
        except KeyError as exc:
            raise ImproperlyConfigured(f"Unknown BK-KMS credential alias: {alias!r}") from exc


def load_credentials(config: Mapping[str, Any]) -> CredentialStore:
    """Load and validate all configured credentials in one synchronous KMS request.

    Call this while importing Django settings so incomplete or inconsistent
    credentials stop application startup with ``ImproperlyConfigured``.

    ``BASE_URL``, ``APP_CODE``, ``ACCESS_KEY``, ``SECRET_KEY``, and ``CREDENTIALS`` are required.
    Gateway mode also requires ``APP_SECRET``. ``DIRECT`` defaults to True;
    ``TIMEOUT``, ``TENANT_ID``, and ``CRYPTO`` are optional.

    :param config: Django ``BK_KMS`` setting mapping.
    :return: Immutable credentials indexed by configured aliases.
    :rtype: CredentialStore
    :raises ImproperlyConfigured: If configuration, KMS access, or returned credentials are invalid.
    """

    bindings, credential_names = _parse_bindings(config)
    base_url = _required_string(config, "BASE_URL")
    direct = _boolean(config, "DIRECT", default=True)
    app_code = _optional_string(config, "APP_CODE")
    app_secret = _optional_string(config, "APP_SECRET")
    timeout = _positive_number(config, "TIMEOUT", default=5.0)
    access_key = _required_string(config, "ACCESS_KEY")
    secret_key = _required_string(config, "SECRET_KEY")
    tenant_id = _string(config, "TENANT_ID", default="")
    crypto = _optional_crypto_info(config, "CRYPTO")

    try:
        with Client(
            base_url=base_url,
            direct=direct,
            app_code=app_code,
            app_secret=app_secret,
            timeout=timeout,
            tenant_id=tenant_id,
        ) as client:
            results = client.consume_credential(
                access_key=access_key,
                secret_key=secret_key,
                credential_names=credential_names,
                crypto=crypto,
            )
    except (ConfigurationError, CryptoBackendUnavailableError) as exc:
        raise ImproperlyConfigured(str(exc)) from exc
    except BKMSException as exc:
        raise ImproperlyConfigured("Unable to load BK-KMS credentials") from exc

    results_by_name = _validate_results(results, credential_names)
    resolved: dict[str, Credential] = {}
    for alias, binding in bindings.items():
        result = results_by_name[binding.credential_name]
        credential = cast(Credential, result.credential)
        if credential.type != binding.credential_type:
            raise ImproperlyConfigured(
                f"BK-KMS credential alias {alias!r} has type {credential.type!s}; "
                f"expected {binding.credential_type.value}"
            )
        resolved[alias] = credential

    return CredentialStore(resolved)


def _parse_bindings(config: Mapping[str, Any]) -> tuple[dict[str, _Binding], list[str]]:
    """Validate aliases and deduplicate credential names for the batch request."""

    raw_bindings = config.get("CREDENTIALS")
    if not isinstance(raw_bindings, Mapping) or not raw_bindings:
        raise ImproperlyConfigured("BK_KMS CREDENTIALS must be a non-empty mapping")

    bindings: dict[str, _Binding] = {}
    types_by_name: dict[str, CredentialType] = {}
    credential_names: list[str] = []
    for alias, raw_binding in raw_bindings.items():
        if not isinstance(alias, str) or not alias.strip():
            raise ImproperlyConfigured("BK_KMS credential aliases must be non-empty strings")
        if not isinstance(raw_binding, Mapping):
            raise ImproperlyConfigured(f"BK_KMS CREDENTIALS[{alias!r}] must be a mapping")

        credential_name = raw_binding.get("NAME")
        if not isinstance(credential_name, str) or not credential_name.strip():
            raise ImproperlyConfigured(f"BK_KMS CREDENTIALS[{alias!r}].NAME must be a non-empty string")
        try:
            credential_name.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ImproperlyConfigured(f"BK_KMS CREDENTIALS[{alias!r}].NAME must be valid Unicode") from exc
        credential_type = _credential_type(raw_binding.get("TYPE"), alias)

        existing_type = types_by_name.get(credential_name)
        if existing_type is not None and existing_type != credential_type:
            raise ImproperlyConfigured(f"BK_KMS credential name {credential_name} has conflicting types")
        if existing_type is None:
            types_by_name[credential_name] = credential_type
            credential_names.append(credential_name)
        bindings[alias] = _Binding(credential_name, credential_type)

    return bindings, credential_names


def _credential_type(value: object, alias: str) -> CredentialType:
    if isinstance(value, CredentialType):
        return value
    if isinstance(value, str):
        try:
            return CredentialType(value)
        except ValueError:
            pass
    raise ImproperlyConfigured(f"BK_KMS CREDENTIALS[{alias!r}].TYPE is invalid")


def _validate_results(results: list[ConsumeResult], requested_names: list[str]) -> dict[str, ConsumeResult]:
    """Match successful results by name; any failed or ambiguous result stops startup."""

    requested = set(requested_names)
    results_by_name: dict[str, ConsumeResult] = {}
    for result in results:
        if not result.ok:
            # Failed entries may have no credential/name, so do not infer an alias.
            raise ImproperlyConfigured(
                f"BK-KMS credential failed with err_code={result.err_code}, err_msg={result.err_msg!r}"
            )
        credential = cast(Credential, result.credential)
        name = credential.name
        if name not in requested:
            raise ImproperlyConfigured(f"BK-KMS response contains unexpected credential name: {name!r}")
        if name in results_by_name:
            raise ImproperlyConfigured(f"BK-KMS response contains duplicate credential name: {name!r}")
        results_by_name[name] = result

    missing = requested.difference(results_by_name)
    if missing:
        missing_text = ", ".join(sorted(missing))
        raise ImproperlyConfigured(f"BK-KMS response is missing credential names: {missing_text}")
    return results_by_name


def _required_string(config: Mapping[str, Any], key: str) -> str:
    value = config.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ImproperlyConfigured(f"BK_KMS {key} must be a non-empty string")
    return value


def _optional_string(config: Mapping[str, Any], key: str) -> Optional[str]:
    value = config.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ImproperlyConfigured(f"BK_KMS {key} must be a string")
    return value


def _string(config: Mapping[str, Any], key: str, *, default: str) -> str:
    value = config.get(key, default)
    if not isinstance(value, str):
        raise ImproperlyConfigured(f"BK_KMS {key} must be a string")
    return value


def _boolean(config: Mapping[str, Any], key: str, *, default: bool) -> bool:
    value = config.get(key, default)
    if not isinstance(value, bool):
        raise ImproperlyConfigured(f"BK_KMS {key} must be a boolean")
    return value


def _positive_number(config: Mapping[str, Any], key: str, *, default: float) -> float:
    value: Union[int, float] = config.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ImproperlyConfigured(f"BK_KMS {key} must be greater than zero")
    return float(value)


def _optional_crypto_info(config: Mapping[str, Any], key: str) -> Optional[CryptoInfo]:
    value = config.get(key)
    if value is None:
        return None
    if not isinstance(value, CryptoInfo):
        raise ImproperlyConfigured(f"BK_KMS {key} must be a CryptoInfo instance")
    return value
