# Go SDK 快速上手

## 1. 安装

```bash
go get github.com/TencentBlueKing/bk-kms-sdk/go
```

## 2. 解密

传入 `envelope` 和 `private_key`，交给 SDK 进行信封解密：

```go

plaintext, err := decrypt.Decrypt(envelope, privateKey)

```

`Decrypt(envelope, privateKey string) (string, error)` 返回录入时的 JSON 明文。信封格式由 KMS服务 约定，调用方无需关心。

## 3. 完整示例

见 [../examples/decrypt](../examples/decrypt)。
