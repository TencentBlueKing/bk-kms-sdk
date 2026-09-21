# Python SDK Agent Guide

Applies to `python/`; follow repository guidance and the user's explicit scope.

## Purpose and documentation

This package provides local envelope decryption only. The public entrypoint is
`bk_kms.decrypt(envelope: str, private_key: str) -> str`: return original UTF-8
plaintext, without credential models, JSON payload parsing, network requests,
key generation, caching, or Django configuration. Applications own those concerns.

`README.md` and `examples/decrypt.py` serve application developers; keep them
example-first. `docs/design.md` and this file serve maintainers. Keep implementation
and protocol detail in the maintainer documents.

Implementation/tests define current behavior; `pyproject.toml`, `Makefile`, and
`../.github/workflows/python.yml` define packaging and checks. Compare protocol
changes with `../go/decrypt/decrypt.go`, `../go/internal/crypto/crypto.go`,
`../cpp/source/decrypt/decrypt.cpp`, and
`../java/src/main/java/com/tencent/bk/kms/decrypt/Decrypt.java`, plus the stored
vectors in `tests/fixtures/`.

## Module boundaries

- `envelope.py`: input validation, envelope decoding, local decryption, UTF-8 output.
- `_json.py`: strict envelope JSON decoding compatible with Go.
- `_crypto.py`: internal algorithm enums, selection, and RSA/AES/SM2/SM4 decryption through bkcrypto.
- `exceptions.py`: public decryption exceptions.
- `__init__.py`: intentional public exports; `_version.py`: package version.

Do not add client, request-signing, credential-model, or framework abstractions
without an explicit request. Update exports, typing, tests, and usage documentation
together when changing public behavior. Document intentional API removals.

## Crypto and input invariants

Use `bk-crypto-python-sdk==4.1.1` for all cryptographic operations. Production code
may import `cryptography.hazmat.primitives.hashes` only to configure OAEP; do not
construct cryptography keys/ciphers directly or access private CFFI APIs.

- RSA: OAEP SHA-256/MGF1-SHA-256, no label, no segmented encryption.
- Private keys: Base64 PEM; preserve existing RSA PKCS#1 and SM2 PKCS#8 fixture support.
- SM2 ciphertext: existing ASN.1-compatible backend format.
- AES/SM4: 16-byte keys, Base64 `IV[16] || ciphertext`; strict CBC block alignment
  and PKCS#7 padding, no CTR padding. Preserve the existing CTR minimum payload.
- Envelope: Base64 JSON with strict supported algorithm identifiers and non-empty
  encrypted-key/ciphertext strings. Reject malformed Base64 and invalid JSON.
- Plaintext: return its UTF-8 text unchanged; do not deserialize or normalize it.

Keep RSA/AES usable without GM. Load the optional backend only when needed.
Missing/broken GM imports raise `CryptoBackendUnavailableError`, preserving the
cause. Other public decoding failures raise `EnvelopeDecodeError`. Preserve error
causes and never include envelope/key/plaintext values in SDK messages or logs.
Do not replace CBC/CTR with a new wire format without an explicit protocol design.

Fixtures contain ephemeral test-only keys. Preserve vector provenance and do not
regenerate unrelated fixtures. Stored vectors are not live KMS or platform evidence.

## Development and verification

Python support is `>=3.11,<3.15`; keep strict typing and the `py.typed` marker.
Keep dependency bounds and the pure-Python wheel. Match existing style and Ruff's
120-character lines. Prefer existing dependencies and direct code.

Run from `python/`:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev,gm]"
make lint
make test
make build
```

The Makefile supports `PYTHON=...`, including `PYTHON=.venv/bin/python`.
`make lint` runs Ruff checks, formatting verification, and strict mypy.
`make test` runs all tests; `make build` produces sdist and wheel under `dist/`.
For focused decryption checks use `python -m pytest tests/unit/test_envelope.py`.
On platforms without GM install `.[dev]` and run `python -m pytest -m "not gm"`;
report this as partial algorithm verification. Mark actual GM-dependent tests `gm`.

For behavior changes, run applicable existing tests before and after when feasible.
Bug fixes need a useful failing regression test or concrete reproduction evidence.
Run all local gates for code/config/dependency changes. For prose-only changes,
check the diff, references, and any executable snippets. Report exactly what passed
and which platform/live checks were not run; reuse fresh unchanged evidence.

CI covers Linux Python 3.11–3.14 with GM, TencentOS 4 amd64/arm64 with GM, and
macOS/Windows Python 3.11 and 3.14 without GM. Do not claim platform support from
one local interpreter or widen versions without checking dependencies and CI.

Python release notes belong in `python/CHANGELOG.md`, not the root changelog.
Version source is `src/bk_kms/_version.py`. Preserve unrelated changes and use scoped
Conventional Commits when delivery is requested.
