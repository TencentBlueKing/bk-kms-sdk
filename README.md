# BK-KMS-SDK

[![license](https://img.shields.io/badge/license-mit-brightgreen.svg?style=flat)](https://github.com/TencentBlueKing/bk-kms-sdk/blob/1.0.x/LICENSE)
[![Release Version](https://img.shields.io/badge/release-v1-brightgreen.svg)](https://github.com/TencentBlueKing/bk-kms-sdk/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/TencentBlueKing/bk-kms-sdk/pulls)

[English](README_EN.md) | 简体中文

> **重要提示**: `master` 分支在开发过程中可能处于**不稳定或者不可用状态**。
请通过[releases](https://github.com/TencentBlueKing/bk-kms-sdk/releases) 而非 `master` 去获取稳定的版本。

蓝鲸智云凭证管理服务（BlueKing Key Management Service）简称 KMS，本项目提供 KMS 的各语言 SDK。

## Overview

* [golang-sdk](go/README.md)
* [cpp-sdk](cpp/README.md)
* [python-sdk](python/README.md)

## Features

- **凭证消费**: 通过 Access Key / Secret Key 拉取凭证, 无需在业务侧持久化敏感数据;
- **安全传输**: 请求签名 + 混合加密信封安全传输敏感信息 (默认 `RSA + AES`, 兼容国密 `SM2 + SM4`);
- **自动协商**: 上层调用无感知, 由 SDK 自动完成密钥协商与明文解封, 将复杂的认证流程简单化;

## Getting started

* [Go SDK 快速上手](go/docs/quickstart.md)
* [CPP SDK 快速上手](cpp/docs/quickstart.md)
* [Python SDK 快速上手](python/README.md)

## Roadmap

* [版本日志](CHANGELOG.md)

## Support

- [白皮书](https://bk.tencent.com/docs)
- [社区论坛](https://bk.tencent.com/s-mart/community)

## BlueKing Community

- [BK-CMDB](https://github.com/TencentBlueKing/bk-cmdb)：蓝鲸智云配置平台（蓝鲸智云 CMDB）是一个面向资产及应用的企业级配置管理平台。
- [BK-CI](https://github.com/TencentBlueKing/bk-ci)：蓝鲸智云持续集成平台是一个开源的持续集成和持续交付系统，可以轻松将你的研发流程呈现到你面前。
- [BK-BCS](https://github.com/TencentBlueKing/bk-bcs)：蓝鲸智云容器管理平台是以容器技术为基础，为微服务业务提供编排管理的基础服务平台。
- [BK-PaaS](https://github.com/TencentBlueKing/blueking-paas)：蓝鲸智云 PaaS 平台是一个开放式的开发平台，让开发者可以方便快捷地创建、开发、部署和管理 SaaS 应用。

## Contributing

如果你有好的意见或建议，欢迎给我们提Issues 或 Pull Requests，为蓝鲸智云开源社区贡献力量。
请阅读[Contributing Guide](CONTRIBUTING.md)了解项目开发基础规范参与代码贡献。

[腾讯开源激励计划](https://opensource.tencent.com/contribution)鼓励开发者的参与和贡献，期待你的加入。

## License

项目基于 MIT 协议，详细请参考 [LICENSE](LICENSE)。

我们承诺未来不会更改适用于交付给任何人的当前项目版本的开源许可证（MIT 协议）。
