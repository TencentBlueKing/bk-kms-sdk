# 开发指南

Rust SDK 的开发规范，通用规范（Commit 信息、分支模型等）遵循仓库根 [CONTRIBUTING](../CONTRIBUTING.md)。

## 代码规范

遵循 [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)，格式由 `rustfmt` 默认风格决定。

## 构建与验证

需要 Rust 1.85 或更高版本（国密依赖 `sm2` 的最低要求）。进入本目录（`rust/`）后执行：

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## 文档

- 公共 API 必须带 rustdoc 注释，并提供 `# Errors` 段落说明失败场景。
- 文档示例需可编译，`cargo test --doc` 会执行它们。
- 面向使用者的说明写在 `README.md`，实现细节留在源码注释中。

## 示例

新增能力时请同步在 `examples/` 下补充可运行示例，并在本目录 `README.md` 中登记入口。
`examples/consumer/` 是独立的消费者项目，用于验证「项目引入本 SDK」的路径。

## 协议一致性

信封格式与算法实现需与 Go、C++、Java、Python SDK 保持一致：

- 信封：Base64 JSON，字段 `asymmetric_type` / `symmetric_type` / `symmetric_mode` / `encrypted_key` / `ciphertext`。
- 私钥：Base64 PEM，RSA 支持 PKCS#8 与 PKCS#1，SM2 要求 PKCS#8。
- 对称密钥固定 16 字节；CBC 使用 PKCS#7 填充且要求块对齐，CTR 不填充。
- 密文布局为 Base64 `IV[16] || ciphertext`。

`tests/fixtures/interop_vectors.json` 是从 Go 加密实现导出的跨语言互操作向量，覆盖全部八种算法组合。
修改协议时必须同步更新该文件，并在提交信息中说明来源与生成方式。
