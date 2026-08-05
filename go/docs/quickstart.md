# Go SDK 快速上手

## 1. 安装

```bash
go get github.com/TencentBlueKing/bk-kms-sdk/go
```

## 2. 创建 Client

```go
client, err := consume.New(
    consume.WithBaseURL("http://xxxx:23681"),
)
```

`BaseURL` 需指定到 KMS 的 HTTP 端口 (`23681`)。

| 选项          | 必填 | 默认值             | 说明                                             |
| ------------- | ---- | ------------------ | ------------------------------------------------ |
| `WithBaseURL` | 是   | 无                 | KMS 地址, 需带协议与端口, 如 `http://xxxx:23681` |
| `WithTimeout` | 否   | `30s`              | 单次请求超时时间, 有更长/更短时延要求时可覆盖    |
| `WithClient`  | 否   | 内置 `http.Client` | 自定义 `http.Client`, 用于接入自建连接池等场景   |

## 3. 消费凭证

默认使用国际算法 `RSA + AES(CBC)`:

```go
results, err := client.ConsumeCredential(context.Background(),
    consume.WithAccessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx"),
    consume.WithCredentialIDList(1, 2),
)
```

需要国密时通过 `WithCrypto` 覆盖:

```go
results, err := client.ConsumeCredential(context.Background(),
    consume.WithAccessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx"),
    consume.WithCredentialIDList(1, 2),
    consume.WithCrypto(types.CryptoInfo{
        AsymmetricType: types.CryptoTypeSM2,
        SymmetricType:  types.CryptoTypeSM4,
        SymmetricMode:  types.CryptoModeCBC,
    }),
)
```

| 选项                   | 必填 | 默认值             | 说明                                                       |
| ---------------------- | ---- | ------------------ | ---------------------------------------------------------- |
| `WithAccessKeySecret`  | 是   | 无                 | 调用方的 Access Key / Secret Key                           |
| `WithCredentialIDList` | 否   | 空(返回全部凭证)   | 要消费的凭证 ID 列表, 不指定则返回该 AK 授权范围内全部凭证 |
| `WithCrypto`           | 否   | `RSA + AES(CBC)`   | 混合加密算法组合, 可选取值见下表                           |

当前版本支持的 `WithCrypto` 可选组合:

| 维度     | Go 常量                                          |
| -------- | ------------------------------------------------ |
| 非对称   | `types.CryptoTypeRSA` / `types.CryptoTypeSM2`    |
| 对称     | `types.CryptoTypeAES` / `types.CryptoTypeSM4`    |
| 分组模式 | `types.CryptoModeCBC` / `types.CryptoModeCTR`    |

常见的算法组合:

- 国际算法(默认): `RSA + AES(CBC)`
- 国密算法: `SM2 + SM4(CBC)`

## 4. 处理返回值

`ConsumeCredential` 返回 `([]types.ConsumeResult, error)`, 遵循请求级error + 单条err_code 的两级错误模型:

- `error != nil`: 请求失败, 无结果可处理;
- `error == nil`: 请求成功, 遍历 `results`, 单条是否成功看 `ErrCode`。

### 4.1 ConsumeResult

| 字段           | 类型                 | 说明                      |
| -------------- | -------------------- | ------------------------- |
| `CredentialID` | `int64`              | 凭证 ID                   |
| `ErrCode`      | `int32`              | `0` 成功; 非 `0` 该条失败 |
| `ErrMsg`       | `string`             | 失败原因                  |
| `Credential`   | `*types.Credential`  | 成功时返回, 失败为 `nil`  |

单条 `ErrCode` 常量位于 `types` 包, 可用 `types.IsOK(errCode)` 快速判断:

| 常量                            | 值        | 含义     |
| ------------------------------- | --------- | -------- |
| `types.ErrCodeOK`               | `0`       | 成功     |
| `types.ErrCodeGenericError`     | `1034000` | 系统错误 |
| `types.ErrCodeNotFound`         | `1034003` | 未找到   |
| `types.ErrCodePermissionDenied` | `1034008` | 无权限   |

### 4.2 Credential

| 字段       | 类型                   | 说明                         |
| ---------- | ---------------------- | ---------------------------- |
| `Name`     | `string`               | 凭证名称                     |
| `Type`     | `types.CredentialType` | 凭证类型, 取值见下表         |
| `AuthInfo` | `types.AuthInfo`       | 凭证明文, 字段随 `Type` 而异 |

`Type` 可选值:

| Type                | Go 常量                                | 含义             |
| ------------------- | -------------------------------------- | ---------------- |
| `single_password`   | `types.CredentialTypeSinglePassword`   | 单密码           |
| `username_password` | `types.CredentialTypeUsernamePassword` | 用户名+ 密码     |
| `single_secret_key` | `types.CredentialTypeSingleSecretKey`  | 单密钥           |
| `app_id_secret_key` | `types.CredentialTypeAppIDSecretKey`   | 应用 ID + 密钥   |

### 4.3 AuthInfo

按 `Type` 取对应字段:

| Type                | 取值                         |
| ------------------- | ---------------------------- |
| `single_password`   | `AuthInfo.Password`          |
| `username_password` | `AuthInfo.Username/Password` |
| `single_secret_key` | `AuthInfo.SecretKey`         |
| `app_id_secret_key` | `AuthInfo.AppID/SecretKey`   |

## 5. 完整示例

见 [../examples/consume](../examples/consume)。
