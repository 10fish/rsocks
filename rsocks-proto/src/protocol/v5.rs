use tracing::{debug, error};
use tokio::{
    net::TcpStream,
    io::ErrorKind,
};
use std::{
    net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr},
    error::Error,
};
use lazy_static::lazy_static;
use rsocks::dns::Resolve;

lazy_static! {
    static ref DNS_RESOLVER: crate::dns::DNSResolver = crate::dns::DNSResolver::new();
}

pub async fn handle_request(req: &Socks5ConnectionRequest)
                            -> Result<(Option<TcpStream>, Socks5ConnectionResponse), Box<dyn Error + Send + Sync>> {
    debug!("socks5 connection request: {:?}", req);
    let ip: IpAddr = match &req.dst_addr {
        SocksAddress::IPv4(_, ipv4) => {
            IpAddr::V4(Ipv4Addr::from(*ipv4))
        }
        SocksAddress::Domain(_, domain) => {
            let addr = unsafe { String::from_utf8_unchecked(domain.clone()) };
            DNS_RESOLVER.look_ip(addr).await?
        }
        SocksAddress::IPv6(_, ipv6) => {
            IpAddr::V6(Ipv6Addr::from(*ipv6))
        }
    };
    let mut tcp_proxy: Option<TcpStream> = None;
    let resp = match req.cmd {
        options::SOCKS_CMD_STREAM => {
            let mut bnd_port: u16 = 0;
            let mut status: u8 = options::REPLY_CODE_V5_GENERAL_FAILURE;
            let conn = TcpStream::connect(format!("{}:{}", ip, req.dst_port)).await;
            let bnd_addr = match conn {
                Ok(tcp) => {
                    let socket = tcp.local_addr()?;
                    bnd_port = socket.port();
                    status = options::REPLY_CODE_V5_REQ_GRANTED;
                    tcp_proxy = Some(tcp);
                    match socket {
                        SocketAddr::V4(ipv4) => {
                            SocksAddress::IPv4(options::SOCKS_ADDRESS_TYPE_IPV4, u32::from_be_bytes(ipv4.ip().octets()))
                        }
                        SocketAddr::V6(ipv6) => {
                            SocksAddress::IPv6(options::SOCKS_ADDRESS_TYPE_IPV6, u128::from_be_bytes(ipv6.ip().octets()))
                        }
                    }
                }
                Err(err) => {
                    match err.kind() {
                        ErrorKind::ConnectionRefused => {
                            status = options::REPLY_CODE_V5_CONNECTION_REFUSED_REMOTE
                        }
                        ErrorKind::ConnectionReset => {
                            status = options::REPLY_CODE_V5_PROTOCOL_ERROR
                        }
                        ErrorKind::NotConnected => {
                            status = options::REPLY_CODE_V5_NETWORK_UNREACHABLE
                        }
                        ErrorKind::AddrInUse => {
                            status = options::REPLY_CODE_V5_PROTOCOL_ERROR
                        }
                        ErrorKind::AddrNotAvailable => {
                            status = options::REPLY_CODE_V5_ADDRESS_TYPE_NOT_SUPPORTED
                        }
                        ErrorKind::TimedOut => {
                            status = options::REPLY_CODE_V5_HOST_UNREACHABLE
                        }
                        ErrorKind::UnexpectedEof => {
                            status = options::REPLY_CODE_V5_PROTOCOL_ERROR
                        }
                        _ => {}
                    }
                    SocksAddress::IPv4(options::SOCKS_ADDRESS_TYPE_IPV4, 0)
                }
            };
            Socks5ConnectionResponse {
                ver: req.ver,
                status,
                rsv: options::BYTE_RESERVED,
                bnd_addr,
                bnd_port,
            }
        }
        options::SOCKS_CMD_BIND => {
            Socks5ConnectionResponse {
                ver: req.ver,
                status: options::REPLY_CODE_V5_GENERAL_FAILURE,
                rsv: options::BYTE_RESERVED,
                bnd_addr: SocksAddress::IPv4(options::SOCKS_ADDRESS_TYPE_IPV4, 0),
                bnd_port: 0,
            }
        }
        options::SOCKS_CMD_UDP => {
            Socks5ConnectionResponse {
                ver: req.ver,
                status: options::REPLY_CODE_V5_GENERAL_FAILURE,
                rsv: options::BYTE_RESERVED,
                bnd_addr: SocksAddress::IPv4(options::SOCKS_ADDRESS_TYPE_IPV4, 0),
                bnd_port: 0,
            }
        }
        _ => {
            Socks5ConnectionResponse {
                ver: req.ver,
                status: options::REPLY_CODE_V5_GENERAL_FAILURE,
                rsv: options::BYTE_RESERVED,
                bnd_addr: SocksAddress::IPv4(options::SOCKS_ADDRESS_TYPE_IPV4, 0),
                bnd_port: 0,
            }
        }
    };
    Ok((tcp_proxy, resp))
}