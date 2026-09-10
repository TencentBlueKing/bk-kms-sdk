# Interoperability fixtures

These committed vectors contain ephemeral test-only keys and non-production plaintext. They are inputs to Python tests, not production credentials or live KMS responses.

## Files and consumers

| Fixture | Contents and purpose | Python tests |
| --- | --- | --- |
| [protocol_vectors.json](protocol_vectors.json) | Name-based request fields, canonical body bytes, signing inputs and expected signature | [test_signature.py](../unit/test_signature.py) |
| [interop_vectors.json](interop_vectors.json) | Go-generated envelopes for all eight RSA/SM2 × AES/SM4 × CBC/CTR combinations | [test_envelope.py](../unit/test_envelope.py), [test_crypto_standard.py](../unit/test_crypto_standard.py), [test_crypto_gm.py](../unit/test_crypto_gm.py) |
| [sm2_binary_key.json](sm2_binary_key.json) | Go-generated SM2 ciphertext for a non-UTF-8 binary data key | [test_crypto_gm.py](../unit/test_crypto_gm.py) |
| [python_key_interop_vectors.json](python_key_interop_vectors.json) | Stored Python-generated RSA/SM2 keys and Go-encrypted binary data keys | [test_crypto_standard.py](../unit/test_crypto_standard.py), [test_crypto_gm.py](../unit/test_crypto_gm.py) |

## Provenance and verification limits

The recorded generation baseline for `protocol_vectors.json` is Go commit `fd6a8a9`, using [signature.go](../../../go/internal/signature/signature.go). The names include Chinese text, HTML-sensitive characters, U+2028 and U+2029. Python tests compare the request bytes and signature exactly with the stored vector.

The original verification also checked the same canonical bytes and signing inputs with [C++ signature.cpp](../../../cpp/source/internal/signature/signature.cpp). C++ request serialization was compared for equal JSON fields and values. RapidJSON retains the special characters that Go/Python escape, so C++'s own serialized bytes differ for those names. This does not establish which encodings a deployed KMS server accepts.

The crypto vectors record Go encryption-helper output. They cover RSA-OAEP/SHA-256, SM2 ASN.1 ciphertext, AES/SM4 CBC and CTR, Base64 `IV || ciphertext`, CBC PKCS#7 padding, and binary data-key preservation. The Python-key fixture checks decryption with stored keys; it does not send newly generated Python keys to Go during each test run.

Python tests do not execute Go or C++, and these fixtures do not establish live KMS support for all eight algorithm combinations. Tests requiring SM2/SM4 carry the `gm` marker; excluding that marker leaves only partial algorithm coverage.

## Running and maintaining the vectors

From `python/`, with the development and GM extras installed:

```bash
python -m pytest tests/unit/test_signature.py tests/unit/test_crypto_standard.py tests/unit/test_crypto_gm.py tests/unit/test_envelope.py
```

Without GM support, add `-m "not gm"`; this does not verify the complete vector set.

Regenerate affected fixtures when the wire protocol or crypto representation changes. The repository does not currently include a dedicated fixture-regeneration script. Record the generator source revision and exact commands when replacing vectors, use fresh test-only keys, and review the decoded fields, serialized bytes and cross-language results. Passing tests against replacement fixtures alone does not prove compatibility with the previous protocol.
