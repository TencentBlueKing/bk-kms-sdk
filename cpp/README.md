# BK-KMS-SDK C++版本

提供 C++11 语言的 BK-KMS SDK。

## Features

- 解密信封: 支持凭证消费运行时解密基础功能

## Installation

安装第三方依赖 (Tongsuo OpenSSL、rapidjson):

```bash
cd cpp
make deps
```

编译并安装 SDK 到 `/usr/local`:

```bash
cd cpp
make          # 生成 build/lib/libbkkms.a
make install  # 安装到 /usr/local
```

## Getting started

- [快速上手](docs/quickstart.md)
- [examples/decrypt](examples/decrypt)

## License

项目基于 MIT 协议, 详细请参考 [LICENSE](../LICENSE)。
