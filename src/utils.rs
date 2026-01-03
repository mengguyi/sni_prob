use colored::Colorize;
use std::{
    io::{Error, ErrorKind},
    net::Ipv4Addr,
};

use crate::error::ProbeError;
use crate::types::ProbeResult;
use crate::types::ResultEntry;

/// 判断是否是网络连接被重置/中断的错误（被墙的标志）
pub fn is_connection_reset_error(err: &Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionRefused
            | ErrorKind::BrokenPipe
    )
}

/// 判断是否是 TLS 证书验证错误
/// 通过检查错误链中是否有 InvalidCertificate 错误
pub fn is_certificate_error(err: &Error) -> bool {
    // 首先检查 kind 是否为 InvalidData
    if err.kind() != ErrorKind::InvalidData {
        return false;
    }

    // 尝试获取内部错误并检查是否是 rustls 的证书错误
    if let Some(inner) = err.get_ref() {
        // 尝试 downcast 到 rustls::Error
        if let Some(rustls_err) = inner.downcast_ref::<rustls::Error>() {
            // 检查是否是 InvalidCertificate 错误
            matches!(rustls_err, rustls::Error::InvalidCertificate(_))
        } else {
            false
        }
    } else {
        false
    }
}

pub fn print_header() {
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════════════╗"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "║                    SNI 黑名单探测工具 v0.1.0                     ║"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "║            TLS SNI Probe - Network Censorship Detector           ║"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════╝"
            .bright_cyan()
            .bold()
    );
    println!();
}

pub fn print_config(domains: &[String], ips: &[Ipv4Addr], port: u16, timeout: u64) {
    println!(
        "{}",
        "┌─ 配置信息 ─────────────────────────────────────────────────────┐".dimmed()
    );
    println!(
        "│ {} {}",
        "域名列表:".bright_white().bold(),
        domains.join(", ").bright_yellow()
    );
    println!(
        "│ {}   {}",
        "IP 列表:".bright_white().bold(),
        ips.iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ")
            .bright_yellow()
    );
    println!(
        "│ {}     {} │ {}   {}",
        "端口:".bright_white().bold(),
        port.to_string().bright_green(),
        "超时:".bright_white().bold(),
        format!("{}秒", timeout).bright_green()
    );
    println!(
        "│ {}     {}",
        "方法:".bright_white().bold(),
        "真实 TLS 连接 + 自定义 SNI".bright_magenta()
    );
    println!(
        "{}",
        "└────────────────────────────────────────────────────────────────┘".dimmed()
    );
    println!();
}

pub fn print_ip_section(ip: &Ipv4Addr) {
    println!();
    println!(
        "{} {} {}",
        "━━━".bright_blue(),
        format!("测试 IP: {}", ip).bright_white().bold(),
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_blue()
    );
}

pub fn print_result(res: &ProbeResult) {
    let status_icon;
    let status_text;
    let domain_display = res.domain.bright_cyan();

    if res.blocked {
        status_icon = "✗".bright_red().bold();
        status_text = "被墙".bright_red().bold();
        let error_info = res
            .error
            .as_ref()
            .map(|e| format!("{:?}", e.kind()))
            .unwrap_or_default();
        println!(
            "  {} {} {} - {}",
            status_icon,
            domain_display,
            status_text,
            error_info.dimmed()
        );
    } else if res.cert_mismatch {
        status_icon = "✓".bright_green().bold();
        status_text = "连接成功".bright_green();
        println!(
            "  {} {} {} {}",
            status_icon,
            domain_display,
            status_text,
            format!("(证书不匹配, {} 字节)", res.stream_size).dimmed()
        );
    } else if res.error.is_some() {
        status_icon = "⚠".bright_yellow().bold();
        status_text = "其他错误".bright_yellow();
        let error_info = res
            .error
            .as_ref()
            .map(|e| format!("{:?}", e.kind()))
            .unwrap_or_default();
        println!(
            "  {} {} {} - {}",
            status_icon,
            domain_display,
            status_text,
            error_info.dimmed()
        );
    } else {
        status_icon = "✓".bright_green().bold();
        status_text = "连接成功".bright_green();
        println!(
            "  {} {} {} {}",
            status_icon,
            domain_display,
            status_text,
            format!("({} 字节)", res.stream_size).dimmed()
        );
    }
}

pub fn print_error(domain: &str, error: &ProbeError) {
    println!(
        "  {} {} {} - {}",
        "✗".bright_red().bold(),
        domain.bright_cyan(),
        "探测失败".bright_red(),
        error.to_string().dimmed()
    );
}

pub fn print_summary(results: &[ResultEntry]) {
    let total = results.len();
    let blocked = results.iter().filter(|r| r.blocked).count();
    let success = results
        .iter()
        .filter(|r| r.success && !r.cert_mismatch)
        .count();
    let cert_mismatch = results.iter().filter(|r| r.cert_mismatch).count();
    let errors = results.iter().filter(|r| r.error).count();

    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════════════╗"
            .bright_white()
            .bold()
    );
    println!(
        "{}",
        "║                          探 测 总 结                             ║"
            .bright_white()
            .bold()
    );
    println!(
        "{}",
        "╠══════════════════════════════════════════════════════════════════╣"
            .bright_white()
            .bold()
    );

    // 统计信息
    println!(
        "║  {} {} │ {} {} │ {} {} │ {} {}",
        "总计:".bright_white(),
        format!("{:3}", total).bright_cyan().bold(),
        "成功:".bright_white(),
        format!("{:3}", success).bright_green().bold(),
        "被墙:".bright_white(),
        format!("{:3}", blocked).bright_red().bold(),
        "错误:".bright_white(),
        format!("{:3}", errors).bright_yellow().bold(),
    );

    if cert_mismatch > 0 {
        println!(
            "║  {} {}",
            "证书不匹配:".bright_white(),
            format!("{}", cert_mismatch).bright_magenta().bold()
        );
    }

    println!(
        "{}",
        "╠══════════════════════════════════════════════════════════════════╣".bright_white()
    );

    // 表头
    println!(
        "║  {:<28} {:<18} {}",
        "域名".bright_white().bold().underline(),
        "IP".bright_white().bold().underline(),
        "状态".bright_white().bold().underline()
    );
    println!(
        "{}",
        "║──────────────────────────────────────────────────────────────────║".dimmed()
    );

    // 结果列表
    for entry in results {
        let status = if entry.blocked {
            "✗ 被墙".bright_red().bold().to_string()
        } else if entry.cert_mismatch {
            "✓ 成功 (证书不匹配)".bright_green().to_string()
        } else if entry.error {
            "⚠ 探测失败".bright_yellow().to_string()
        } else {
            "✓ 成功".bright_green().bold().to_string()
        };

        println!(
            "║  {:<28} {:<18} {}",
            entry.domain.bright_cyan(),
            entry.ip.to_string().bright_yellow(),
            status
        );
    }

    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════╝"
            .bright_white()
            .bold()
    );
    println!();

    // 最终结论
    if blocked > 0 {
        println!(
            "{}",
            format!("  ⚠️  检测到 {} 个域名可能被 SNI 封锁", blocked)
                .bright_red()
                .bold()
        );
    } else {
        println!(
            "{}",
            "  ✅ 所有域名均未检测到 SNI 封锁".bright_green().bold()
        );
    }
    println!();
}
