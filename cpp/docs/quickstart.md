# C++ SDK 快速上手

## 1. 安装

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

## 2. 解密

传入 `envelope` 和 `private_key`，交给 SDK 进行信封解密：

```cpp

std::string plaintext;
std::string err;
if (!bkkms::Decrypt(envelope, privateKey, plaintext, err))
{
    // handle decrypt failure
}
```

`Decrypt` 返回录入时的 JSON 明文。信封格式由 KMS服务 约定，调用方无需关心。

## 3. 完整示例

见 [../examples/decrypt](../examples/decrypt)。
