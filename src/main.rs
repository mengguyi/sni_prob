use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rustls::pki_types::ServerName;
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

mod error;
mod types;
mod utils;

use crate::error::ProbeError;
use crate::types::{Cli, ProbeResult, ResultEntry};
use crate::utils::{
    is_certificate_error, is_connection_reset_error, print_config, print_error, print_header,
    print_ip_section, print_result, print_summary,
};

/// 通过指定 IP 建立 TLS 连接，SNI 设为待测域名
fn probe_domain(
    domain: &str,
    ip: Ipv4Addr,
    port: u16,
    timeout_secs: u64,
) -> Result<ProbeResult, ProbeError> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);

    // 1. 建立 TCP 连接
    let tcp_stream = TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs))?;

    tcp_stream
        .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .ok();
    tcp_stream
        .set_write_timeout(Some(Duration::from_secs(timeout_secs)))
        .ok();

    // 2. 配置 TLS（SNI 设为待测域名）
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from(domain.to_string())?;

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;

    let mut sock = &tcp_stream;

    let mut tls_stream = rustls::Stream::new(&mut conn, &mut sock);

    // 3. 尝试 TLS 握手
    match tls_stream.flush() {
        Ok(_) => {
            // 尝试读取响应
            let mut buf = [0u8; 1024];
            match tls_stream.read(&mut buf) {
                Ok(size) => Ok(ProbeResult {
                    domain: domain.to_string(),
                    ip,
                    blocked: false,
                    cert_mismatch: false,
                    stream_size: size,
                    error: None,
                }),
                Err(e) => {
                    let is_cert_error = is_certificate_error(&e);
                    let is_reset = is_connection_reset_error(&e);

                    // 证书错误说明 TLS 握手成功，不算被墙
                    // 连接重置才是被墙的标志
                    Ok(ProbeResult {
                        domain: domain.to_string(),
                        ip,
                        blocked: !is_cert_error && is_reset,
                        cert_mismatch: is_cert_error,
                        stream_size: 0,
                        error: Some(e),
                    })
                }
            }
        }
        Err(e) => {
            let is_cert_error = is_certificate_error(&e);
            let is_reset = is_connection_reset_error(&e);

            // 证书错误说明 TLS 握手成功，不算被墙
            // 连接重置才是被墙的标志
            Ok(ProbeResult {
                domain: domain.to_string(),
                ip,
                blocked: !is_cert_error && is_reset,
                cert_mismatch: is_cert_error,
                stream_size: 0,
                error: Some(e),
            })
        }
    }
}

fn main() {
    let cli = Cli::parse();

    // 解析 IP 地址
    let ips: Vec<Ipv4Addr> = cli
        .ips
        .iter()
        .filter_map(|s| {
            s.parse::<Ipv4Addr>().ok().or_else(|| {
                eprintln!(
                    "  {} 无法解析 IP 地址: {}",
                    "⚠".bright_yellow(),
                    s.bright_red()
                );
                None
            })
        })
        .collect();

    if ips.is_empty() {
        eprintln!(
            "\n{} {}\n",
            "✗".bright_red().bold(),
            "没有有效的 IP 地址".bright_red()
        );
        std::process::exit(1);
    }

    // 打印标题和配置
    print_header();
    print_config(&cli.domains, &ips, cli.port, cli.timeout);

    let mut all_results: Vec<ResultEntry> = Vec::new();
    let total_tests = ips.len() * cli.domains.len();

    // 创建进度条
    let progress = ProgressBar::new(total_tests as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("█▓▒░"),
    );

    // 对每个 IP 和每个域名进行笛卡尔积测试
    for ip in &ips {
        print_ip_section(ip);

        for domain in &cli.domains {
            progress.inc(1);
            let result = probe_domain(domain, *ip, cli.port, cli.timeout);

            match result {
                Ok(res) => {
                    print_result(&res);

                    all_results.push(ResultEntry {
                        domain: domain.clone(),
                        ip: *ip,
                        blocked: res.blocked,
                        success: !res.blocked && res.error.is_none(),
                        cert_mismatch: res.cert_mismatch,
                        error: false,
                    });
                }
                Err(e) => {
                    print_error(domain, &e);
                    all_results.push(ResultEntry {
                        domain: domain.clone(),
                        ip: *ip,
                        blocked: false,
                        success: false,
                        cert_mismatch: false,
                        error: true,
                    });
                }
            };

            std::thread::sleep(Duration::from_millis(500));
        }
    }

    progress.finish_and_clear();

    // 打印总结
    print_summary(&all_results);
}
