# Python SDK Agent Guide

This file applies to every file under `python/`. It is the maintenance contract for the BK-KMS Python SDK. Read it together with the repository-level instructions, and follow the more specific rule when they differ.

## Documentation audiences

- `README.md` and `docs/django.md` are for ordinary application developers using the SDK. Focus on installation, configuration, usage examples, and actionable troubleshooting; do not assume knowledge of SDK internals.
- `docs/design.md` and `AGENTS.md` are for SDK maintainers. Keep implementation details, protocol rationale, maintenance constraints, and verification workflows in these documents.
- When updating documentation, explain public behavior and usage limits in the developer guides; put the internal reasoning and maintenance requirements in the maintainer documents. Ordinary developers should not need to read maintainer documents to integrate the SDK.

## Project purpose and boundaries

`bk-kms-sdk` is the synchronous Python client for consuming credentials from BlueKing KMS. It supports API Gateway and direct KMS access, signs requests with Access Key / Secret Key, and decrypts the returned hybrid-encryption envelope locally.

The Python package is `bk-kms-sdk`; its import name is `bk_kms`. It uses Python `>=3.11,<3.15`, `httpx2`, a `src/` layout, PEP 621 metadata, `setuptools.build_meta`, and strict typing with an included `py.typed` marker.

The maintained scope currently includes:

- a synchronous `Client`; there is no async client;
- gateway and direct modes;
- plaintext credential consumption and delayed envelope decryption;
- RSA/AES on every supported platform;
- optional SM2/SM4 through the `gm` extra;
- settings-time Django credential bootstrap through the `django` extra.

Do not add credential management APIs, caching, background refresh, general HTTP retry, a CLI, a plugin framework, or framework integrations beyond the existing Django bootstrap unless the requested scope explicitly includes them.

## Sources of truth

Use this precedence when facts disagree:

1. Current implementation and tests under `src/bk_kms/` and `tests/` define shipped behavior.
2. `pyproject.toml`, `Makefile`, and `../.github/workflows/python.yml` define supported versions, dependencies, tools, and CI gates.
3. Cross-language fixtures under `tests/fixtures/`, plus the Go and C++ implementations in the repository, define the wire protocol.
4. `README.md` defines the supported user-facing workflow.
5. `CHANGELOG.md` records Python SDK release changes. Do not put Python SDK entries in the repository-level `../CHANGELOG.md`; Python is versioned and released independently from the other language SDKs.
6. `docs/design.md` describes the current implementation, protocol details, and verification boundaries. Resolve any drift against the implementation, tests, and package configuration above.

For protocol work, inspect the corresponding Go and C++ implementation rather than inferring behavior from prose. Important references include:

- `../go/internal/signature/signature.go`
- `../go/consume/client.go`
- `../go/types/credential.go`
- `../cpp/source/internal/signature/signature.cpp`
- `../cpp/source/consume/client.cpp`
- `../cpp/source/types/credential.cpp`

## Package map and ownership

- `src/bk_kms/client.py`: validation, request orchestration, HTTP client ownership and error mapping, tenant configuration, clock-skew correction, and public client lifecycle.
- `src/bk_kms/signature.py`: canonical consume payload, gateway authorization JSON, nonce generation, and HMAC-SHA256 signing.
- `src/bk_kms/_json.py`: the only wire-JSON encoder/decoder. Keep Go `encoding/json` compatibility here.
- `src/bk_kms/envelope.py`: envelope parsing, decryption orchestration, and result deserialization.
- `src/bk_kms/models.py`: public enums, frozen dataclasses, error codes, and wire-model validation.
- `src/bk_kms/exceptions.py`: stable SDK exception hierarchy.
- `src/bk_kms/crypto/__init__.py`: public crypto-package facade.
- `src/bk_kms/crypto/_dispatch.py`: asymmetric and symmetric algorithm dispatch.
- `src/bk_kms/crypto/base.py`: request-scoped `KeyPair` model.
- `src/bk_kms/crypto/bkcrypto.py`: unified RSA/AES/SM2/SM4 operations; standard algorithms are mandatory and GM classes load only when requested.
- `src/bk_kms/django/credentials.py`: fail-fast Django settings bootstrap and safe credential projections.
- `src/bk_kms/__init__.py`: intentional public top-level exports.
- `src/bk_kms/_version.py`: package version and the derived KMS SDK header version.

Keep these boundaries narrow. Do not move protocol serialization into `httpx2`, crypto framing into a third-party high-level format, or Django-specific policy into the core client.

## Non-negotiable wire-protocol rules

The Python SDK must preserve the Go/C++ wire fields and signing algorithm, using Go-compatible canonical JSON bytes. C++ RapidJSON leaves HTML-sensitive characters and U+2028/U+2029 unescaped; see `tests/fixtures/README.md` for the verified scope.

- Gateway requests use `/api/v1/consume_credential`.
- Direct requests use `/api/v1/consume/credential`.
- The signature string is `timestamp + "\n" + nonce + "\n" + SHA256(canonical_body)`; HTTP method and URL path are not signed.
- Preserve a base URL path prefix by joining controlled path segments; do not use a leading-path `urljoin` that discards the prefix.
- Send the exact bytes returned by `_json.dumps_bytes()` through `content=body`; do not use `httpx2`'s `json=` parameter.
- Canonical request field order is `credential_id_list` (always `[]`), then `credential_name_list`, then `crypto` with `asymmetric_type`, `symmetric_type`, and `symmetric_mode`, then `public_key`.
- `credential_names=None` and an empty sequence both serialize as `credential_name_list: []`; the server returns the AK's uniquely bound credential group. Names must be valid Unicode strings and retain their exact value; reject surrogate-containing names rather than rewriting credential identity; response IDs must fit signed 64-bit integers and response codes signed 32-bit integers.
- Canonical JSON is compact UTF-8, rejects NaN and Infinity, escapes `<`, `>`, `&`, U+2028, and U+2029 like Go, rejects a UTF-8 BOM, and normalizes isolated surrogates to U+FFFD when decoding responses.
- The signature is the existing two-stage HMAC-SHA256 construction. Do not simplify or replace it.
- Nonces and request IDs are UUID v4 hex strings without dashes.
- Keep all existing KMS and gateway headers, including `X-BKKMS-SDK-Version` and `X-Bk-Tenant-Id`.
- Preserve the two-level error model: request-level failures raise exceptions; `ConsumeResult.err_code != 0` remains a per-credential result and does not raise automatically.
- Only KMS error `1034016` triggers automatic retry. Error `1034015` means signature mismatch and must not retry. Parse the HTTP `Date`, update the client clock offset, regenerate the key pair and all request identifiers, and retry exactly once. Do not add implicit retry for timeouts, transport errors, HTTP 5xx, other KMS errors, or POST requests generally.

Tenant configuration is also contract behavior:

1. `tenant_id` is configured on Client construction, not on consume methods.
2. Omitted, `None`, and empty values become an empty string. Do not read environment variables or framework settings or synthesize a default tenant.
3. Reject non-string explicit tenant IDs and whitespace-only strings; always send the configured tenant header, including an empty value.
4. Applications own tenant selection and configuration lookup. Global-tenant applications explicitly select their target tenant.

Any protocol change must update focused tests and relevant fixtures, be compared against both Go and C++, and update the README/design documentation if the public contract changed.

## Crypto invariants

The public abstraction is one `CryptoInfo`, and every algorithm is routed through `bk-crypto-python-sdk==4.1.1`.

- RSA/AES use bkcrypto's `cryptography` backend and are mandatory.
- SM2/SM4 use bkcrypto's optional Tongsuo backend and load only when requested.
- Production crypto code may import `cryptography.hazmat.primitives.hashes` only to configure bkcrypto OAEP; it must not create cryptography cipher/key/serialization objects directly.

The `bk-crypto-python-sdk` distribution, imported as `bkcrypto`, is a base dependency, but its `gm` extra is not. `import bk_kms` and the RSA/AES path must work without Tongsuo. Missing or broken GM imports must raise `CryptoBackendUnavailableError` with the original error preserved as `__cause__`.

The default is RSA + AES-CBC. Preserve these formats:

- RSA: 2048 bits, exponent 65537, OAEP with SHA-256 and MGF1-SHA-256, SPKI public PEM, PKCS#1 private PEM, then Base64.
- SM2: SPKI public PEM and PKCS#8 private PEM, then Base64; ciphertext uses the current ASN.1-compatible backend format.
- AES and SM4: 16-byte keys; ciphertext is Base64 of `IV[16] || ciphertext`.
- CBC: strict PKCS#7 unpadding and block-alignment validation.
- CTR: no padding; preserve the full 128-bit counter semantics.
- Envelope: Base64-encoded JSON containing algorithm identifiers, encrypted key, and ciphertext.

Do not implement cryptographic primitives locally, call private CFFI APIs, silently accept malformed Base64/padding, or change CBC/CTR to AEAD unilaterally. A wire-format upgrade requires an explicit versioned protocol design.

The committed fixtures contain ephemeral test-only keys and plaintext. They are not production secrets. Regenerate them only when the protocol or crypto representation changes, document the generator/source, and review serialized bytes before replacement.

## Public API and compatibility

Treat top-level names exported from `bk_kms.__init__`, the Django names exported from `bk_kms.django`, exception types/fields, dataclass fields, enum values, and keyword argument behavior as public API.

- Use keyword-only configuration for the client and preserve the synchronous context-manager lifecycle.
- The SDK owns and closes its internal HTTPX2 client; the public API does not accept a caller-provided HTTP client.
- `close()` is idempotent, and a closed client fails before generating keys or sending a request.
- One SDK Client per thread is the supported usage. Do not claim cross-thread safety unless it is explicitly tested and documented.
- Keep public data models frozen. Sensitive `AuthInfo`, envelope, and key fields must remain excluded from `repr`.
- Keep asymmetric and symmetric algorithm enums separate, and reject invalid `CryptoInfo` values during construction.
- Required response fields must not inherit Go zero-value decoding. Known credential types validate required authentication fields in the core model; absent optional `AuthInfo` fields are `None`.
- Known credential types become `CredentialType`; unknown credential type strings remain raw strings for forward compatibility.
- Crypto algorithm and mode values are strict because they control local dispatch.
- Preserve exception causes with `raise ... from exc`, but never attach full request/response bodies or sensitive headers to public errors.

When adding a public symbol, update `__all__`, typing, README examples, and behavior tests together. Do not rename or remove a public symbol without an explicit compatibility plan.

## Django bootstrap contract

`bk_kms.django.load_credentials()` runs synchronously while settings are imported. It is deliberately fail-fast: incomplete, missing, duplicate, unexpected, mistyped, or failed credentials raise Django `ImproperlyConfigured` and stop startup.

Maintain these rules:

- `CREDENTIALS` is a non-empty alias mapping with non-empty string `NAME` and a valid `CredentialType`/wire string `TYPE`.
- Duplicate names are fetched once. Reusing one name with conflicting types is invalid.
- Fail on any per-credential error before matching names: failed results may have no credential/name, so do not infer their aliases. Validate that every requested name appears exactly once, no unexpected name appears, the credential type matches, and all type-required fields are non-empty.
- `TIMEOUT` defaults to 5 seconds for settings-time fail-fast behavior; the core `Client` default remains 30 seconds.
- `DIRECT` and `CRYPTO` must pass through the core client semantics. `TENANT_ID` must be a string and defaults to an empty string; do not infer it from environment variables or framework settings.
- Preserve actionable local configuration errors and missing-GM installation guidance. Wrap request-level KMS, transport, and other crypto failures in a generic startup message so service responses and secrets are not repeated. Per-credential failures include the KMS-returned `err_code` and `err_msg`; `err_msg` is service-supplied text and is not sanitized by the SDK.
- `CredentialStore` is immutable and its `repr` exposes aliases only.
- KMS provides usernames, passwords, app IDs, secret keys, complete connection URIs, and Base64-encoded TLS materials. Consume URIs as stored; do not assemble them from separate credentials. Applications own connection configuration and TLS material loading.
- Do not move loading into `AppConfig.ready()`, add hidden caching, or imply runtime refresh. Applications own reconnection and refresh if credentials expire while a process is running.
- Access Key / Secret Key used to reach KMS must come from a bootstrap source such as environment, a mounted file, or workload identity; they must not depend on the target service being configured.

## Security rules

- Never log, interpolate into exceptions, snapshot, or include in `repr`: App Secret, Secret Key, access credentials, private keys, decrypted data keys, credential plaintext, full authorization headers, or full request bodies.
- Examples must use placeholders and HTTPS for gateway mode.
- Do not disable TLS verification in SDK code. The public API does not expose custom HTTPX2 client configuration.
- Do not enable redirects for credential POST requests.
- `ConsumeEnvelope.envelope` and `.private_key` together can recover credential plaintext; protect both as secrets.
- Keep dependency upper bounds. Before widening crypto, HTTPX2, Django, or Python support, verify dependency metadata, supported wheels, all cross-language vectors, and the platform matrix.

## Development setup

Run Python SDK commands from `python/`:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,django,gm]"
```

If the GM wheel is unavailable on a non-Linux development machine, install `.[dev,django]` and run the standard-crypto subset with `python -m pytest -m "not gm"`. Do not report that as full verification.

The Makefile accepts a Python override, for example `make test PYTHON=python`.

## Verification commands

Full local gates, from `python/`:

```bash
make lint
make test
make build
```

`make lint` runs Ruff checks, Ruff format verification, and strict mypy. `make test` runs all tests. `make build` creates the sdist and wheel under `dist/`.

Focused commands:

```bash
python -m pytest tests/unit/test_client.py
python -m pytest tests/unit/test_signature.py -k signature
python -m pytest tests/unit/test_django_credentials.py
python -m pytest tests/integration/test_client_roundtrip.py
python -m pytest -m "not gm"
python -m ruff check src tests examples
python -m ruff format --check src tests examples
python -m mypy
```

Bug fixes require a regression test that fails before the fix and passes after it. Prefer behavior tests using an injected recording HTTP client or the local `http.server` integration pattern; do not add a mocking dependency for simple request assertions.

Mark tests that require the optional SM2/SM4 backend with `pytest.mark.gm`. Tests that merely verify missing-GM behavior or standard crypto should remain runnable without the extra.

For code, configuration, dependency, fixture, or generated-artifact changes, run the full applicable gates before completion. For Markdown-only changes, full lint/test/build is not required; run `git diff --check` and verify every referenced path and command against the current tree. State any skipped or unavailable platform gate explicitly.

## CI and release expectations

`../.github/workflows/python.yml` is the executable support matrix:

- Linux runs Python 3.11 through 3.14 with `dev,django,gm`, lint, tests, and build.
- TencentOS 4 runs the full stack on `linux/amd64` and `linux/arm64` using digest-pinned images.
- macOS and Windows test Python 3.11 and 3.14 without GM and run `pytest -m "not gm"`.

The SDK wheel must remain pure Python (`py3-none-any`); native platform constraints belong to the optional GM dependency. A release or dependency upgrade is not complete merely because one local interpreter passes. Preserve the declared Python bounds unless the workflow and dependency wheels prove the new range.

The version source is `src/bk_kms/_version.py`; `SDK_VERSION` is derived from it for the request header. Python SDK releases are independent from the repository-wide and other language SDK releases. Keep package metadata, request-header formatting, `CHANGELOG.md`, and Python release notes consistent when changing the version.

## Code and change style

- Match the existing code: Python 3.11-compatible syntax, built-in generics, `Optional`/`Union` where already used, frozen dataclasses, small module-level helpers, and 120-character Ruff lines.
- Keep mypy strict. Do not add broad `Any`, blanket ignores, or untyped public surfaces to silence errors. A narrow ignore needs a rationale, as with Django's missing inline typing metadata.
- Use the existing exception hierarchy and validate at the boundary that owns the contract.
- Add no dependency when the standard library or an existing dependency is sufficient. Explain and validate every new runtime dependency or extra.
- Keep changes surgical. Do not reformat unrelated files, reorganize modules speculatively, or introduce interfaces with only hypothetical future implementations.

Before finishing a change, check the relevant synchronization set:

- Wire protocol: Python implementation, unit/integration tests, fixtures, Go/C++ compatibility, README, and design notes.
- Public API/model: implementation, top-level exports, typing, tests, and README examples.
- Dependency/Python support: base `bk-crypto-python-sdk==4.1.1` and `httpx2>=2.12,<3`, optional `bk-crypto-python-sdk[gm]==4.1.1`, `pyproject.toml`, CI matrix, README requirements, no-GM installation, platform installability, and Go/C++ crypto vectors.
- Django bootstrap: optional extra, `bk_kms.django` exports, configuration validation, projection tests, README, and CI installation.
- Version/release: `_version.py`, SDK header value, package artifact metadata, and the Python-local `CHANGELOG.md`; do not add Python release entries to `../CHANGELOG.md`.

Use Conventional Commits consistent with repository history, for example `fix(python): ...`, `feat(python): ...`, or `docs(python): ...`. Stage and commit only files in the requested scope.
