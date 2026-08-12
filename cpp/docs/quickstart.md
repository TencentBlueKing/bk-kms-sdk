# C++ SDK 快速上手

## 1. 安装

安装第三方依赖,

Tongsuo OpenSSL、rapidjson 通过 `third-party/install.sh` 自动下载编译并安装到 `/usr/local`,

```bash
cd cpp
make deps
```

已装过对应依赖会自动跳过, 安装完第三方依赖后开始编译 SDK,

```bash
cd cpp
make          # 生成 build/lib/libbkkms.a
make install  # 安装到 /usr/local
```

链接到用户程序,

SDK 只产出静态库, 无 `.so` 运行时依赖。使用方链接时需要显式指定 Tongsuo 静态库:

```bash
g++ -std=c++11 user_app.cc \
    -I/usr/local/include \
    -L/usr/local/lib -L/usr/local/lib64 \
    -Wl,-Bstatic -lbkkms -lssl -lcrypto -Wl,-Bdynamic \
    -lpthread -ldl -o user_app
```

## 2. 创建 Client

```cpp
#include <bk-kms/client.h>

bkkms::ClientOptions clientOpts;
clientOpts.baseUrl   = "http://xxxx/api/bk-kms/prod";
clientOpts.appCode   = "your_app_code_xxxx";
clientOpts.appSecret = "your_app_secret_xxxx";
```

`baseUrl` 需指定到 KMS 网关对应环境的地址, `appCode` / `appSecret` 为调用方的应用态认证参数。

| 字段              | 必填 | 默认值 | 说明                                                      |
| ----------------- | ---- | ------ | --------------------------------------------------------- |
| `baseUrl`         | 是   | 无     | KMS 网关地址, 如 `http://xxxx/api/bk-kms/prod`            |
| `appCode`         | 是   | 无     | 调用方应用态认证参数 App Code                             |
| `appSecret`       | 是   | 无     | 调用方应用态认证参数 App Secret                           |
| `timeoutSeconds`  | 否   | `30`   | 单次请求超时时间 (秒), 有更长/更短时延要求时可覆盖        |
| `direct`          | 否   | `false`| 不经过网关, 直连 KMS 后端服务, 该模式下无需应用态认证参数 |

特殊情况下需要不经过网关直连 KMS 后端时, 可通过 `direct` 置为 `true` 开启, `baseUrl` 需指定到 KMS 的 HTTP 端口 (`23680`), 常规情况下业务接入请走网关模式:

```cpp
bkkms::ClientOptions clientOpts;
clientOpts.baseUrl = "http://xxxx:23680";
clientOpts.direct  = true;
```

## 3. 消费凭证

默认使用国际算法 `RSA + AES(CBC)`:

```cpp
bkkms::ConsumeOptions consumeOpts;
consumeOpts.accessKey = "your_access_key_xxxx";
consumeOpts.secretKey = "your_secret_key_xxxx";
consumeOpts.credentialIDList = {1, 2};
```

特殊情况下选定直连模式时, 需要通过 `jwtToken` 传入 JWT token 完成直连请求认证, 常规情况下业务接入无需关心:

```cpp
bkkms::ConsumeOptions consumeOpts;
consumeOpts.accessKey = "your_access_key_xxxx";
consumeOpts.secretKey = "your_secret_key_xxxx";
consumeOpts.credentialIDList = {1, 2};
consumeOpts.jwtToken = "your_jwt_token_xxxx";
```

需要国密时通过 `crypto` 覆盖:

```cpp
bkkms::ConsumeOptions consumeOpts;
consumeOpts.accessKey = "your_access_key_xxxx";
consumeOpts.secretKey = "your_secret_key_xxxx";
consumeOpts.credentialIDList = {1, 2};
consumeOpts.crypto.asymmetricType = bkkms::CryptoTypeSM2;
consumeOpts.crypto.symmetricType  = bkkms::CryptoTypeSM4;
consumeOpts.crypto.symmetricMode  = bkkms::CryptoModeCBC;
```

多租户环境下, 可以通过 `tenantID` 指定目标租户, 未设置时 SDK 默认使用 `default` 租户, 非多租户环境无需关心:

```cpp
bkkms::ConsumeOptions consumeOpts;
consumeOpts.accessKey = "your_access_key_xxxx";
consumeOpts.secretKey = "your_secret_key_xxxx";
consumeOpts.credentialIDList = {1, 2};
consumeOpts.tenantID = "tenant_name";
```

| 字段               | 必填 | 默认值            | 说明                                                       |
| ------------------ | ---- | ----------------- | ---------------------------------------------------------- |
| `accessKey`        | 是   | 无                | 调用方的 Access Key                                        |
| `secretKey`        | 是   | 无                | 调用方的 Secret Key                                        |
| `credentialIDList` | 否   | 空 (返回全部凭证) | 要消费的凭证 ID 列表, 不指定则返回该 AK 授权范围内全部凭证 |
| `crypto`           | 否   | `RSA + AES(CBC)`  | 混合加密算法组合, 可选取值见下表                           |
| `tenantID`         | 否   | `default`         | 目标租户 ID, 仅限多租户场景使用, 默认为 default 租户       |
| `jwtToken`         | 否   | 无                | JWT token, 仅限直连模式使用                                |

当前版本支持的 `crypto` 可选组合:

| 维度     | C++ 常量                                        |
| -------- | ----------------------------------------------- |
| 非对称   | `bkkms::CryptoTypeRSA` / `bkkms::CryptoTypeSM2` |
| 对称     | `bkkms::CryptoTypeAES` / `bkkms::CryptoTypeSM4` |
| 分组模式 | `bkkms::CryptoModeCBC` / `bkkms::CryptoModeCTR` |

常见的算法组合:

- 国际算法 (默认): `RSA + AES(CBC)`
- 国密算法: `SM2 + SM4(CBC)`

## 4. 处理返回值

`ConsumeCredential` 返回 `std::vector<bkkms::ConsumeResult>`, 遵循请求级 error + 单条 errCode 的两级错误模型:

- `err` 非空: 请求失败, 无结果可处理;
- `err` 为空: 请求成功, 遍历 `results`, 单条是否成功看 `errCode`。

### 4.1 ConsumeResult

| 字段            | 类型                | 说明                                       |
| --------------- | ------------------- | ------------------------------------------ |
| `credentialID`  | `int64_t`           | 凭证 ID                                    |
| `errCode`       | `int32_t`           | `0` 成功; 非 `0` 该条失败                  |
| `errMsg`        | `std::string`       | 失败原因                                   |
| `hasCredential` | `bool`              | `true` 时 `credential` 有效, 否则表示无值  |
| `credential`    | `bkkms::Credential` | 凭证明文, 仅在 `hasCredential == true` 有效 |

单条 `errCode` 是否成功可通过 `bkkms::IsOK(errCode)` 判断, 非 `0` 时可与下列常量对齐处理:

| 常量                            | 值        | 含义         |
| ------------------------------- | --------- | ------------ |
| `bkkms::ErrCodeOK`              | `0`       | 成功         |
| `bkkms::ErrCodeGenericError`    | `1034000` | 通用错误     |
| `bkkms::ErrCodeNotFound`        | `1034003` | 资源不存在   |
| `bkkms::ErrCodePermissionDenied`| `1034008` | 权限不足     |

### 4.2 Credential

| 字段         | 类型                | 说明                         |
| ------------ | ------------------- | ---------------------------- |
| `name`       | `std::string`       | 凭证名称                     |
| `type`       | `std::string`       | 凭证类型, 取值见下表         |
| `authInfo`   | `bkkms::AuthInfo`   | 凭证明文, 字段随 `type` 而异 |
| `annotation` | `std::string`       | 凭证注解                     |

`type` 可选值:

| type                | C++ 常量                                   | 含义             |
| ------------------- | ------------------------------------------ | ---------------- |
| `single_password`   | `bkkms::CredentialTypeSinglePassword`      | 单密码           |
| `username_password` | `bkkms::CredentialTypeUsernamePassword`    | 用户名 + 密码    |
| `single_secret_key` | `bkkms::CredentialTypeSingleSecretKey`     | 单密钥           |
| `app_id_secret_key` | `bkkms::CredentialTypeAppIDSecretKey`      | 应用 ID + 密钥   |

### 4.3 AuthInfo

按 `type` 取对应字段:

| type                | 取值                          |
| ------------------- | ----------------------------- |
| `single_password`   | `authInfo.password`           |
| `username_password` | `authInfo.username/password`  |
| `single_secret_key` | `authInfo.secretKey`          |
| `app_id_secret_key` | `authInfo.appID/secretKey`    |

## 5. 完整示例

见 [../examples/consume](../examples/consume)。
