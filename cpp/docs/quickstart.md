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

SDK 提供直连与网关两种接入模式, 由调用方类型决定: 蓝鲸平台系统接入采用直连模式, SaaS场景构建的应用采用网关模式。

直连模式需开启 `direct`, `baseUrl` 指向 KMS 的 HTTP 直连端口 (`23681`), 该端口不校验 JWT, 无需提供 App Code / App Secret:

```cpp
#include <bk-kms/client.h>

bkkms::ClientOptions clientOpts;
clientOpts.baseUrl = "http://xxxx:23681";
clientOpts.direct  = true;
```

网关模式无需开启 `direct`, `baseUrl` 指向蓝鲸网关 APIGW 地址, 该入口由 APIGW 注入并校验 JWT, 需通过 `appCode` / `appSecret` 提供 App Code / App Secret:

```cpp
bkkms::ClientOptions clientOpts;
clientOpts.baseUrl   = "http://xxxx/api/bk-kms/prod";
clientOpts.appCode   = "your_app_code_xxxx";
clientOpts.appSecret = "your_app_secret_xxxx";
```

| 字段              | 必填 | 默认值  | 说明                                                                           |
| ----------------- | ---- | ------- | ------------------------------------------------------------------------------ |
| `baseUrl`         | 是   | 无      | KMS 地址, 直连时如 `http://xxxx:23681`, 网关时如 `http://xxxx/api/bk-kms/prod` |
| `direct`          | 否   | `false` | 设为 `true` 开启直连调用, 不经过网关, 无需JWT                                  |
| `appCode`         | 否   | 无      | 应用态认证 App Code (直连不需要)                                               |
| `appSecret`       | 否   | 无      | 应用态认证 App Secret (直连不需要)                                             |
| `timeoutSeconds`  | 否   | `30`    | 单次请求超时时间 (秒), 有更长/更短时延要求时可覆盖                             |

## 3. 消费凭证

### 3.1 明文消费

默认使用国际算法 `RSA + AES(CBC)`:

```cpp
bkkms::ConsumeOptions consumeOpts;
consumeOpts.accessKey = "your_access_key_xxxx";
consumeOpts.secretKey = "your_secret_key_xxxx";
consumeOpts.credentialIDList = {1, 2};
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

当前版本支持的 `crypto` 可选组合:

| 维度     | C++ 常量                                        |
| -------- | ----------------------------------------------- |
| 非对称   | `bkkms::CryptoTypeRSA` / `bkkms::CryptoTypeSM2` |
| 对称     | `bkkms::CryptoTypeAES` / `bkkms::CryptoTypeSM4` |
| 分组模式 | `bkkms::CryptoModeCBC` / `bkkms::CryptoModeCTR` |

常见的算法组合:

- 国际算法 (默认): `RSA + AES(CBC)`
- 国密算法: `SM2 + SM4(CBC)`

### 3.2 信封消费

需要密文信封而非明文时(如先落库或交由其他进程解密), 换用 `ConsumeCredentialEnvelope`, 选项与 3.1 完全一致, 网关与直连模式均适用, 返回 `ConsumeEnvelope`:

```cpp
bkkms::ConsumeEnvelope envelope;
if (!client->ConsumeCredentialEnvelope(consumeOpts, envelope, err))
{
    // handle request failure
}
```

| 字段          | 类型          | 说明                        |
| ------------- | ------------- | --------------------------- |
| `envelope`    | `std::string` | 信封式包裹的密文 (base64)   |
| `privateKey`  | `std::string` | 本次临时生成的私钥 (base64) |

`envelope` 与 `privateKey` 需自行保管, 需要明文时通过 `bkkms::DecryptEnvelope` 本地解密:

```cpp
std::vector<bkkms::ConsumeResult> results;
if (!bkkms::DecryptEnvelope(envelope, results, err))
{
    // handle decrypt failure
}
```

## 4. 处理返回值

`ConsumeCredential` 与 `DecryptEnvelope` 均返回 `std::vector<bkkms::ConsumeResult>`, 遵循请求级 error + 单条 errCode 的两级错误模型:

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

| 常量                                 | 值        | 含义             |
| ------------------------------------ | --------- | ---------------- |
| `bkkms::ErrCodeOK`                   | `0`       | 成功             |
| `bkkms::ErrCodeGenericError`         | `1034000` | 通用错误         |
| `bkkms::ErrCodeNotFound`             | `1034003` | 资源不存在       |
| `bkkms::ErrCodePermissionDenied`     | `1034008` | 权限不足         |
| `bkkms::ErrCodeRequestTimeTooSkewed` | `1034015` | 请求时间偏差过大 |

其中 `ErrCodeRequestTimeTooSkewed` 表示本机与服务端时间偏差过大, 收到该错误, SDK 会依据响应 `Date` 自动校正时钟偏移并重试一次。

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

明文消费见 [../examples/consume](../examples/consume);
信封消费见 [../examples/consume_envelope](../examples/consume_envelope);
