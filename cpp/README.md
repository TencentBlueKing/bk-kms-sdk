# BK-KMS-SDK C++版本

运行时解密还原凭证明文, 信封格式由 KMS 服务约定，调用方无需关心。

## 运行环境

- C++11
- 依赖 Tongsuo OpenSSL、rapidjson，默认支持 RSA、AES 及国密 SM2、SM4

## 安装

Tongsuo OpenSSL、rapidjson 通过 `third-party/install.sh` 自动下载编译并安装到 `/usr/local`，已装过对应依赖会自动跳过：

```bash
cd cpp
make deps
```

安装完第三方依赖后编译并安装 SDK：

```bash
cd cpp
make          # 生成 build/lib/libbkkms.a
make install  # 安装到 /usr/local
```

SDK 只产出静态库，无 `.so` 运行时依赖。链接到用户程序时需要显式指定 Tongsuo 静态库：

```bash
g++ -std=c++11 user_app.cc \
    -I/usr/local/include \
    -L/usr/local/lib -L/usr/local/lib64 \
    -Wl,-Bstatic -lbkkms -lssl -lcrypto -Wl,-Bdynamic \
    -lpthread -ldl -o user_app
```

## 示例

见 [examples/decrypt](examples/decrypt)。

## License

项目基于 MIT 协议, 详细请参考 [LICENSE](../LICENSE)。
