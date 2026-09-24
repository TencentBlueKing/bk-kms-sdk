# Interoperability fixtures

These committed vectors contain ephemeral test-only keys and non-production plaintext. They are inputs to Rust tests, not production credentials or live KMS responses.

## Files and consumers

| Fixture | Contents and purpose | Rust tests |
| --- | --- | --- |
| [interop_vectors.json](interop_vectors.json) | Go-generated envelopes for all eight RSA/SM2 × AES/SM4 × CBC/CTR combinations, each paired with the private key that decrypts it | [interop_vectors.rs](../interop_vectors.rs) |

## Provenance and verification limits

The crypto vectors record Go encryption-helper output. They cover RSA-OAEP/SHA-256, SM2 ASN.1 ciphertext, AES/SM4 CBC and CTR, and Base64 `IV || ciphertext`. All eight vectors share the document-level `plaintext` field, which the tests compare against after decryption.

The stored RSA key is PKCS#1; `rsa_pkcs8_key_decrypts_the_same_envelope` re-encodes it as PKCS#8 so that both encodings stay covered. The stored SM2 key is reused by the negative tests (`mismatched_private_key_is_rejected`, `errors_do_not_leak_secrets`) to prove that a mismatched key fails without echoing key material back to the caller.

Rust tests do not execute Go or C++, and these fixtures do not establish live KMS support for all eight algorithm combinations. They pin the wire format, not a server contract.

## Running and maintaining the vectors

From `rust/`:

```bash
cargo test
```

The fixture is embedded at compile time through `include_str!`, so the test binary reads it without any runtime file access.

Regenerate affected fixtures when the wire protocol or crypto representation changes. The repository does not currently include a dedicated fixture-regeneration script. Record the generator source revision and exact commands when replacing vectors, use fresh test-only keys, and review the decoded fields, serialized bytes and cross-language results. Passing tests against replacement fixtures alone does not prove compatibility with the previous protocol.

`all_eight_stored_vectors_decrypt` asserts that the vector count is exactly 8, so adding or removing an algorithm combination requires updating that assertion as well.
