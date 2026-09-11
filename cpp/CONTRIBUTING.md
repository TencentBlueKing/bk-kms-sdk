# 开发指南

C++ SDK 的开发规范, 通用规范 (Commit 信息、分支模型等) 遵循仓库根 [CONTRIBUTING](../CONTRIBUTING.md)。

## 代码规范

[cpp style guide](https://google.github.io/styleguide/cppguide.html)

## 构建与验证

进入本目录 (`cpp/`) 后执行:

```bash
make deps       # 首次构建前安装第三方依赖 (Tongsuo OpenSSL、rapidjson)
make            # 生成 build/lib/libbkkms.a
make install    # 安装头文件与静态库到 /usr/local
make clean      # 清理构建产物
```

`examples/decrypt/` 下的示例是独立的最小工程 (依赖 `make install` 之后的头文件与静态库), 参与开发时不由 SDK 主 Makefile 编译, 需要单独 `cd examples/<capability> && make` 验证。

## 示例

新增能力时请同步在 `examples/<capability>/` 下补充一个可运行的最小示例, 并在本目录 `README.md` 中登记入口。
