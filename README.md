# SNI Prob

一个通过 TLS SNI（Server Name Indication）探测网络封锁的命令行工具。

## 功能特性

- 🔍 通过指定 IP 地址和域名进行 TLS 连接测试
- 🚫 检测域名是否被 SNI 黑名单封锁
- 🔐 自动识别证书错误和连接重置
- 📊 彩色输出和进度条显示
- ⚡ 支持批量测试多个域名和 IP 地址

## 工作原理

该工具通过以下方式探测网络封锁：

1. 向指定的 IP 地址发起 TCP 连接
2. 在 TLS 握手时使用待测域名作为 SNI
3. 观察连接结果：
   - 如果连接被重置（Connection Reset），说明该域名可能在 SNI 黑名单中
   - 如果出现证书错误，说明 TLS 握手成功，只是证书不匹配（未被封锁）
   - 如果连接成功，说明域名未被封锁

## 安装

### 从源码构建

确保已安装 Rust 工具链（1.92+），然后执行：

```bash
git clone https://github.com/mengguyi/sni_prob.git
cd sni_prob
cargo build --release
```

编译后的可执行文件位于 `target/release/sni_prob`

## 使用方法

### 基本用法

```bash
sni_prob -d <域名> -i <IP地址>
```

### 示例

#### 测试单个域名和单个 IP

```bash
sni_prob -d google.com -i 8.8.8.8
```

#### 测试多个域名和多个 IP

```bash
sni_prob -d google.com -d youtube.com -d twitter.com \
         -i 1.1.1.1 -i 8.8.8.8 -i 9.9.9.9
```

#### 自定义端口和超时时间

```bash
sni_prob -d example.com -i 1.1.1.1 -p 8443 -t 10
```

### 命令行参数

```bash
选项:
  -d, --domains <DOMAIN>    要测试的域名列表（可以指定多个）[必需]
  -i, --ips <IP>            要测试的 IP 地址列表（可以指定多个）[必需]
  -t, --timeout <TIMEOUT>   连接超时时间（秒）[默认: 5]
  -p, --port <PORT>         端口号 [默认: 443]
  -h, --help                显示帮助信息
  -V, --version             显示版本信息
```

## 输出说明

工具会为每个 IP 和域名组合显示测试结果：

- ✓ 绿色：连接成功，域名未被封锁
- 🔒 黄色：证书不匹配，但 TLS 握手成功（未被封锁）
- 🚫 红色：连接被重置，域名可能被 SNI 黑名单封锁
- ✗ 红色：其他错误（连接超时、网络错误等）

## 技术栈

- Rust
- rustls - TLS 实现
- clap - 命令行参数解析
- colored - 彩色终端输出
- indicatif - 进度条显示

## 许可证

AGPL License

## 注意事项

1. 该工具仅用于网络诊断和研究目的
2. 测试结果仅供参考，实际网络封锁情况可能更复杂
3. 建议使用已知的公共 DNS 服务器 IP 进行测试（如 1.1.1.1、8.8.8.8 等）
4. 连续测试时会有 500ms 的延迟，避免过于频繁的请求

## 贡献

欢迎提交 Issue 和 Pull Request！

## 相关资源

- [SNI 黑名单原理](https://en.wikipedia.org/wiki/Server_Name_Indication)
- [TLS 握手过程](https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/)
