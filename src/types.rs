use clap::Parser;
use std::fmt;
use std::io::Error;
use std::net::Ipv4Addr;

/// SNI 黑名单探测工具
#[derive(Parser, Debug)]
#[command(name = "sni_prob")]
#[command(about = "通过 TLS SNI 探测网络封锁", long_about = None)]
pub struct Cli {
    /// 要测试的域名列表（可以指定多个）
    #[arg(short, long, value_name = "DOMAIN", required = true)]
    pub domains: Vec<String>,

    /// 要测试的 IP 地址列表（可以指定多个）
    #[arg(short, long, value_name = "IP", required = true)]
    pub ips: Vec<String>,

    /// 连接超时时间（秒）
    #[arg(short, long, default_value = "5")]
    pub timeout: u64,

    /// 端口号
    #[arg(short, long, default_value = "443")]
    pub port: u16,
}

#[derive(Debug)]
pub struct ProbeResult {
    pub domain: String,
    pub ip: Ipv4Addr,
    pub blocked: bool,
    pub cert_mismatch: bool,
    pub stream_size: usize,
    pub error: Option<Error>,
}

impl fmt::Display for ProbeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.blocked {
            write!(
                f,
                "🚫 {} [{}] 被墙 - {:?}",
                self.domain,
                self.ip,
                self.error.as_ref().map(|e| e.kind())
            )
        } else if self.cert_mismatch {
            write!(
                f,
                "✅ {} [{}] 连接成功（证书不匹配，读取 {} 字节）",
                self.domain, self.ip, self.stream_size
            )
        } else if self.error.is_some() {
            write!(
                f,
                "⚠️ {} [{}] 其他错误 - {:?}（读取 {} 字节）",
                self.domain,
                self.ip,
                self.error.as_ref().map(|e| e.kind()),
                self.stream_size
            )
        } else {
            write!(
                f,
                "✅ {} [{}] 连接成功（读取 {} 字节）",
                self.domain, self.ip, self.stream_size
            )
        }
    }
}

#[derive(Clone)]
pub struct ResultEntry {
    pub domain: String,
    pub ip: Ipv4Addr,
    pub blocked: bool,
    pub success: bool,
    pub cert_mismatch: bool,
    pub error: bool,
}
