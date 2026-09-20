// TencentBlueKing is pleased to support the open source community by making
// 蓝鲸智云 - 凭证管理服务(BlueKing - Key Management Service) available.
// Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
// Licensed under the MIT License (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
// http://opensource.org/licenses/MIT
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
// language governing permissions and limitations under the License.We undertake not
// to change the open source license (MIT license) applicable to the current version
// of the project delivered to anyone in the future.

//! 独立的消费者项目示例：在另一个 Rust 项目中引入并使用 `bk-kms-sdk`。
//!
//! 运行方式（在本目录 `examples/consumer` 下）：
//!
//! ```bash
//! # 信封保存在当前目录的 envelope.txt 中（KMS 下发的 Base64 字符串），
//! # 私钥内容（Base64(PEM)）通过环境变量传入。
//!
//! # Windows PowerShell
//! $env:BK_KMS_PRIVATE_KEY = '<base64(PEM) 私钥内容>'
//! cargo run
//!
//! # Linux / macOS
//! export BK_KMS_PRIVATE_KEY='<base64(PEM) 私钥内容>'
//! cargo run
//! ```

use std::env;
use std::fs;
use std::process::ExitCode;

use bk_kms::decrypt;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("错误: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 读取配置：信封从当前目录的 envelope.txt 读取（KMS 下发的 Base64 字符串），
    //    私钥从环境变量读取（Base64(PEM) 内容本身，不是私钥文件路径）。
    let envelope = fs::read_to_string("envelope.txt")?;
    let private_key = env::var("BK_KMS_PRIVATE_KEY")?;

    // 2. 调用核心接口：没有客户端对象，也没有初始化步骤。
    let plaintext = decrypt(envelope.trim(), private_key.trim())?;

    // 3. 处理返回结果：明文结构由应用定义。示例按 JSON 格式化输出，
    //    不是 JSON 时原样输出，避免对明文结构做强假设。
    match serde_json::from_str::<serde_json::Value>(&plaintext) {
        Ok(value) => println!("解密成功：{value}"),
        Err(_) => println!("解密成功：{plaintext}"),
    }

    Ok(())
}
