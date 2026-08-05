# BK-KMS-SDK GO版本

提供 Go 语言的 BK-KMS SDK。

## Features

- **凭证消费**: 通过 Access Key / Secret Key 拉取凭证, 无需在业务侧持久化敏感数据;
- **安全传输**: 请求签名 + 混合加密信封安全传输敏感信息 (默认 `RSA + AES`, 兼容国密 `SM2 + SM4`);
- **自动协商**: 上层调用无感知, 由 SDK 自动完成密钥协商与明文解封, 将复杂的认证流程简单化;

## Installation

```bash
go get github.com/TencentBlueKing/bk-kms-sdk/go
```

## Getting started

- [快速上手](docs/quickstart.md)
- [examples/consume](examples/consume)

## License

项目基于 MIT 协议,详细请参考 [LICENSE](../LICENSE)。
