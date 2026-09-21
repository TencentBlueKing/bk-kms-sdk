# Python SDK design

## Scope and public contract

The SDK implements local envelope decryption, aligned with Go `decrypt.Decrypt`
([source](../../go/decrypt/decrypt.go)), C++ `bkkms::Decrypt`
([source](../../cpp/source/decrypt/decrypt.cpp)), and Java `Decrypt.decrypt`
([source](../../java/src/main/java/com/tencent/bk/kms/decrypt/Decrypt.java)).

`bk_kms.decrypt(envelope: str, private_key: str) -> str` accepts a Base64 JSON
envelope and a matching Base64 PEM private key. It returns the original UTF-8
plaintext without JSON deserialization or credential validation. Unlike Go/C++
byte strings, Python text requires valid UTF-8; invalid text raises
`EnvelopeDecodeError`. Applications own envelope/key acquisition, content parsing,
and framework configuration.

## Data flow

1. `envelope.py` validates non-empty string inputs and decodes the envelope.
2. `_json.py` decodes strict UTF-8 JSON, rejecting BOM and non-JSON constants and
   normalizing isolated surrogates consistently with Go.
3. `_crypto.py` defines the internal algorithm identifiers. Envelope fields
   `asymmetric_type`, `symmetric_type`, `symmetric_mode`, `encrypted_key`, and
   `ciphertext` must be non-empty strings; algorithm dispatch is strict.
4. `_crypto.py` selects the algorithm, unwraps the data key, and decrypts the payload through
   `bk-crypto-python-sdk==4.1.1`.
5. `envelope.py` decodes the plaintext as UTF-8 without changing its contents.

## Cryptographic representation

- RSA uses OAEP SHA-256 with MGF1-SHA-256, no label, and no segmented encryption.
- RSA and SM2 private keys are Base64-encoded PEM. Existing fixtures cover RSA
  PKCS#1 and SM2 PKCS#8 keys and SM2 ASN.1 ciphertext.
- AES/SM4 data keys are exactly 16 bytes. Ciphertext is Base64 of
  `IV[16] || ciphertext`.
- CBC requires block alignment and strict PKCS#7 unpadding; CTR has no padding.
  As in the current Go implementation, CTR requires at least one payload byte.
- RSA/AES use bkcrypto's standard backend. SM2/SM4 load the optional GM backend
  only when selected; importing the SDK and using RSA/AES must work without GM.

Malformed envelopes and cryptographic failures become `EnvelopeDecodeError`.
`CryptoBackendUnavailableError` remains distinguishable and provides installation
instructions. Exception causes are preserved. SDK error messages must not embed
private keys, data keys, envelopes, or plaintext.

## Verification and maintenance

Run `make lint`, `make test`, and `make build` from `python/`. The tests cover all
eight stored Go-generated algorithm combinations, binary SM2 data-key coverage,
malformed input/padding checks, and missing-GM behavior. Real RSA/AES round trips
cover raw JSON objects, plain text, whitespace, Unicode, and empty payload behavior.

See [fixture provenance](../tests/fixtures/README.md) for the stored-vector scope.
Python tests do not execute Go/C++, contact live KMS, or prove every supported
platform. [CI](../../.github/workflows/python.yml) defines the platform matrix.
The wheel remains pure Python; native dependencies belong to the GM extra.

Version metadata comes from `src/bk_kms/_version.py`. Python releases and
[CHANGELOG](../CHANGELOG.md) are independent of the other language SDKs.
