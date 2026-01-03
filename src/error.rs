use rustls::pki_types::InvalidDnsNameError;
use std::fmt;
use std::io::Error;

#[derive(Debug)]
pub enum ProbeError {
    TCPConnect(Error),
    InvalidDomain(InvalidDnsNameError),
    RustlsError(rustls::Error),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::TCPConnect(e) => write!(f, "TCP 连接错误: {}", e),
            ProbeError::InvalidDomain(e) => write!(f, "无效域名: {}", e),
            ProbeError::RustlsError(e) => write!(f, "TLS 错误: {}", e),
        }
    }
}

impl From<Error> for ProbeError {
    fn from(err: Error) -> Self {
        ProbeError::TCPConnect(err)
    }
}

impl From<InvalidDnsNameError> for ProbeError {
    fn from(err: InvalidDnsNameError) -> Self {
        ProbeError::InvalidDomain(err)
    }
}

impl From<rustls::Error> for ProbeError {
    fn from(err: rustls::Error) -> Self {
        ProbeError::RustlsError(err)
    }
}
