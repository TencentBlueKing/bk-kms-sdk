# CHANGELOG

## Unreleased

- 提供信封本地解密接口 `decrypt(envelope, private_key) -> str`，返回原始 UTF-8 明文，由应用解析内容。
- 支持 Python `>=3.11,<3.15`；通过 `bk-crypto-python-sdk==4.1.1` 提供 RSA/AES 和可选 SM2/SM4，支持 CBC/CTR。
