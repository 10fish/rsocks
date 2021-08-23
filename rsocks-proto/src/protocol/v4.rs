use std::{
    error::Error,
    net::{Ipv4Addr, IpAddr}
};
use tokio::{
    net::TcpStream,
    io::ErrorKind
};
use tracing::{debug, error};


pub async fn handle_request(req: &Socks4ConnectionRequest)
                            -> Result<(Option<TcpStream>, Socks4ConnectionResponse), Box<dyn Error + Send + Sync>> {
    debug!("socks4 connection request: {:?}", req);
    let mut tcp_proxy: Option<TcpStream> = None;
    let resp = match req.cmd {
        options::SOCKS_CMD_STREAM => {
            let mut bnd_port: u16 = 0;
            let mut status = options::REPLY_CODE_V4_REQ_REJECTED;
            let ip = IpAddr::from(Ipv4Addr::from(req.dst_ip));
            let conn = TcpStream::connect(format!("{}:{}", ip, req.dst_port)).await;
            let bnd_addr = match conn {
                Ok(tcp) => {
                    let socket = tcp.local_addr()?;
                    bnd_port = socket.port();
                    status = options::REPLY_CODE_V4_REQ_GRANTED;
                    tcp_proxy = Some(tcp);
                    match socket.ip() {
                        IpAddr::V4(ipv4) => {
                            u32::from_be_bytes(ipv4.octets())
                        }
                        IpAddr::V6(_) => {
                            // TODO: socks4 does not support ipv6
                            0u32
                        }
                    }
                }
                Err(err) => {
                    match err.kind() {
                        ErrorKind::NotConnected | ErrorKind::AddrNotAvailable | ErrorKind::ConnectionReset | ErrorKind::TimedOut => {
                            status = options::REPLY_CODE_V4_REQ_FAILED_NOT_REACHABLE
                        }
                        _ => {}
                    }
                    0u32
                }
            };
            Socks4ConnectionResponse {
                // socks 4 use null byte other than version in response packet
                ver: NULL_TERMINATOR,
                rep: status,
                dst_port: bnd_port,
                dst_ip: bnd_addr
            }
        }
        options::SOCKS_CMD_BIND => {
            // TODO: command bind
            Socks4ConnectionResponse {
                ver: req.ver,
                rep: options::REPLY_CODE_V4_REQ_GRANTED,
                dst_port: 0,
                dst_ip: 0
            }
        }
        _ => {
            // no possible, unsupported command
            Socks4ConnectionResponse {
                ver: req.ver,
                rep: options::REPLY_CODE_V4_REQ_REJECTED,
                dst_port: 0,
                dst_ip: 0
            }
        }
    };
    Ok((tcp_proxy, resp))
}