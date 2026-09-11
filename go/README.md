# BK-KMS-SDK GO版本

运行时解密还原凭证明文, 信封格式由 KMS 服务约定，调用方无需关心。

## 运行环境

- Go `>=1.24`（国密依赖 `gmsm` 的最低要求）
- 默认支持 RSA、AES，SM2、SM4 无需额外配置

## 安装

```bash
go get github.com/TencentBlueKing/bk-kms-sdk/go
```

## 示例

见 [examples/decrypt](examples/decrypt)。

## License

项目基于 MIT 协议,详细请参考 [LICENSE](../LICENSE)。
