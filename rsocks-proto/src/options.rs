use rsocks_proto::::IntoBytes;
use async_trait::async_trait;

#[derive(Debug)]
pub(crate) enum SocksOption {
    Version(u8),
    SocksCmdCode(u8),
    DstPort(u16),
    DstIP(u32),
    DstAddr(SocksAddress),
    UserID(Vec<u8>),
    ReplyCode(u8),

    UserPassAuthVersion(u8),
    PlaceHolder(u8),

    NumAuthMethods(u8),
    AuthCandidates(Vec<u8>),

    ChosenAuth(u8),
    UserIDLen(u8),
    PassLen(u8),
    Password(Vec<u8>),
}

#[derive(Debug)]
pub enum SocksAddress {
    IPv4(u8, u32),
    Domain(u8, Vec<u8>),
    IPv6(u8, u128),
}

pub(crate) const SOCKS_ADDRESS_TYPE_IPV4: u8 = 0x01;
pub(crate) const SOCKS_ADDRESS_TYPE_DOMAIN: u8 = 0x03;
pub(crate) const SOCKS_ADDRESS_TYPE_IPV6: u8 = 0x04;


pub(crate) const VERSION_V4: u8 = 0x04;
pub(crate) const VERSION_V5: u8 = 0x05;

pub(crate) const SOCKS_CMD_STREAM: u8 = 0x01;
pub(crate) const SOCKS_CMD_BIND: u8 = 0x02;
pub(crate) const SOCKS_CMD_UDP: u8 = 0x03;

pub(crate) const BYTE_RESERVED: u8 = 0x00;

pub(crate) const REPLY_CODE_V4_REQ_GRANTED: u8 = 0x5a;
pub(crate) const REPLY_CODE_V4_REQ_REJECTED: u8 = 0x5b;
pub(crate) const REPLY_CODE_V4_REQ_FAILED_NOT_REACHABLE: u8 = 0x5c;
pub(crate) const REPLY_CODE_V4_REQ_FAILED_USERID_INVALID: u8 = 0x5d;

pub(crate) const REPLY_CHOSEN_NO_AUTH: u8 = 0xff;
pub(crate) const REPLY_STATUS_SUCCESS: u8 = 0x00;

pub(crate) const REPLY_CODE_V5_REQ_GRANTED: u8 = 0x00;
pub(crate) const REPLY_CODE_V5_GENERAL_FAILURE: u8 = 0x01;
pub(crate) const REPLY_CODE_V5_CONNECTION_NOT_ALLOWED_BY_RULESET: u8 = 0x02;
pub(crate) const REPLY_CODE_V5_NETWORK_UNREACHABLE: u8 = 0x03;
pub(crate) const REPLY_CODE_V5_HOST_UNREACHABLE: u8 = 0x04;
pub(crate) const REPLY_CODE_V5_CONNECTION_REFUSED_REMOTE: u8 = 0x05;
pub(crate) const REPLY_CODE_V5_TTL_EXPIRED: u8 = 0x06;
pub(crate) const REPLY_CODE_V5_PROTOCOL_ERROR: u8 = 0x07;
pub(crate) const REPLY_CODE_V5_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

// https://en.wikipedia.org/wiki/SOCKS
pub(crate) const AUTH_NO_AUTH: u8 = 0x00;
pub(crate) const AUTH_GSSAPI: u8 = 0x01;
pub(crate) const AUTH_USER_PASS: u8 = 0x02;
// 0x03–0x7F: methods assigned by IANA
pub(crate) const AUTH_IANA_CHALLENGE_HANDSHAKE: u8 = 0x03;
pub(crate) const AUTH_IANA_UNASSIGNED: u8 = 0x04;
pub(crate) const AUTH_IANA_CHALLENGE_RESPONSE: u8 = 0x05;
pub(crate) const AUTH_IANA_SSL: u8 = 0x06;
pub(crate) const AUTH_IANA_NDS: u8 = 0x07;
pub(crate) const AUTH_IANA_MULTI_AUTH: u8 = 0x08;
pub(crate) const AUTH_IANA_JSON_PARAM_BLOCK: u8 = 0x09;
// 0x0A–0x7F: Unassigned
// 0x80–0xFE: methods reserved for private use

pub(crate) const USER_PASS_AUTH_VERSION: u8 = 0x01;

pub(crate) const NULL_TERMINATOR: u8 = 0x00;
pub(crate) const BYTE_TERMINATOR: u8 = 0xff;

#[async_trait]
impl IntoBytes for SocksAddress {
    async  fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            SocksAddress::IPv4(flag, ipv4) => {
                bytes.push(*flag);
                bytes.extend(ipv4.to_be_bytes());
            }
            SocksAddress::Domain(flag, domain) => {
                bytes.push(*flag);
                bytes.extend(domain);
            }
            SocksAddress::IPv6(flag, ipv6) => {
                bytes.push(*flag);
                bytes.extend(ipv6.to_be_bytes());
            }
        }
        bytes
    }
}

#[async_trait]
impl IntoBytes for SocksOption {
    async fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            SocksOption::Version(ver) |
            SocksOption::UserPassAuthVersion(ver) => {
                bytes.push(*ver)
            }
            SocksOption::SocksCmdCode(cmd) => {
                bytes.push(*cmd)
            }
            SocksOption::DstPort(port) => {
                bytes.extend(port.to_be_bytes())
            }
            SocksOption::DstIP(ip) => {
                bytes.extend(ip.to_be_bytes())
            }
            SocksOption::DstAddr(addr) => {
                bytes.extend(addr.to_bytes().await)
            }
            SocksOption::UserID(id) => {
                bytes.extend(id)
            }
            SocksOption::ReplyCode(code) => {
                bytes.push(*code)
            }
            SocksOption::PlaceHolder(code) => {
                bytes.push(*code)
            }
            SocksOption::NumAuthMethods(num) => {
                bytes.push(*num)
            }
            SocksOption::AuthCandidates(methods) => {
                bytes.extend(methods)
            }
            SocksOption::ChosenAuth(auth) => {
                bytes.push(*auth)
            }
            SocksOption::UserIDLen(len) => {
                bytes.push(*len)
            }
            SocksOption::PassLen(len) => {
                bytes.push(*len)
            }
            SocksOption::Password(pass) => {
                bytes.extend(pass)
            }
        }
        bytes
    }
}

