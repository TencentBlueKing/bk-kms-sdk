# CHANGELOG

## Unreleased

- 提供信封本地解密接口 `bk_kms::decrypt(envelope, private_key) -> Result<String, Error>`，返回原始 UTF-8 明文，由应用解析内容。
- 支持 `RSA`(OAEP SHA-256) / `SM2`(ASN.1 密文) 与 `AES` / `SM4` 的 `CBC` / `CTR` 全部八种组合。
- 全部算法为纯 Rust 实现，无原生依赖，无需安装国密后端。
- 错误以 `Error` 枚举结构化返回，区分配置错误、信封格式错误与解密失败。
