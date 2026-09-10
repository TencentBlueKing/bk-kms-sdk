# CHANGELOG

## Unreleased

- 在创建 Client 时配置租户 ID，未设置时发送空租户头；租户选择和配置读取由应用负责。

- 支持 Python `>=3.11,<3.15`，提供带类型标注的同步客户端、不可变数据模型和上下文管理器。
- 默认直连 KMS，必填 App Code 通过 `X-Bk-AppCode` 请求头发送；支持显式选择 API 网关模式，通过 Access Key / Secret Key 签名认证。
- 支持按名称消费指定凭证，或获取 Access Key 绑定凭证组内的全部凭证。
- 支持单密码、用户名与密码、单密钥、App ID 与密钥四种凭证类型，以异常报告请求级错误，以 `ConsumeResult.ok` 判断单条结果。
- 支持凭证明文消费、加密信封获取及本地延迟解密；默认 RSA + AES-CBC，可选 AES-CTR、SM2 和 SM4-CBC/CTR。
- 通过 `bk-crypto-python-sdk==4.1.1` 提供密码算法，国密后端通过 `[gm]` extra 安装；HTTP 连接由内部 HTTPX2 client 管理。
- 支持时钟偏差错误 `1034016` 的自动校时及一次重试，提供 Access Key 状态、nonce 重复和签名不匹配等错误码常量。
- 支持 Django settings 启动期按 `NAME + TYPE` 批量加载、校验凭证，并通过应用别名读取凭证或生成连接配置。
