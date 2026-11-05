# Interoperability fixtures

These committed vectors contain ephemeral test-only keys and non-production plaintext. They are inputs to Node.js tests, not production credentials or live KMS responses.

## Files and consumers

| Fixture | Contents and purpose | Source |
| --- | --- | --- |
| [interop_vectors.json](interop_vectors.json) | Go-generated envelopes for all eight RSA/SM2 × AES/SM4 × CBC/CTR combinations, each paired with the private key that decrypts it | Copied from [rust/tests/fixtures](../../../rust/tests/fixtures) (identical to the Python copy) |
| [sm2_binary_key.json](sm2_binary_key.json) | Go-generated SM2 ciphertext for a non-UTF-8 binary data key | Copied from [python/tests/fixtures](../../../python/tests/fixtures) |
| [python_key_interop_vectors.json](python_key_interop_vectors.json) | Stored Python-generated RSA/SM2 keys and Go-encrypted binary data keys | Copied from [python/tests/fixtures](../../../python/tests/fixtures) |

All tests live in [decrypt.test.js](../decrypt.test.js). Run them from `nodejs/` with `npm test`.

## Verification limits

Node.js tests do not execute Go, contact live KMS, or prove every supported platform. They pin the wire format, not a server contract. When the upstream fixtures are regenerated, copy them here again; see the [Python fixture notes](../../../python/tests/fixtures/README.md) for regeneration guidance.
