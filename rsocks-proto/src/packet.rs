use crate::options::*;
use nom::{
    error::ErrorKind,
    bytes::complete::take,
    number::complete::{be_u8, be_u32, be_u128, be_u16},
};
use nom::combinator::rest_len;
use rsocks_proto::IntoBytes;
use async_trait::async_trait;


#[derive(Debug)]
pub enum SocksErr<I> {
    NomError(nom::Err<(I, nom::error::ErrorKind)>),
    NonUtf8String,
    UnknownPacket,
    InconsistentLen,
    UnknownAddressType,
}

type BResult<In, Out> = nom::IResult<In, Out, SocksErr<In>>;

#[derive(Debug)]
pub struct Socks4ConnectionRequest {
    pub ver: u8,
    pub cmd: u8,
    pub dst_port: u16,
    pub dst_ip: u32,
    pub usr_id: Vec<u8>,
}


#[derive(Debug)]
pub struct Socks4ConnectionResponse {
    pub ver: u8,
    pub rep: u8,
    pub dst_port: u16,
    pub dst_ip: u32,
}


#[derive(Debug)]
pub struct Socks5InitiationRequest {
    pub ver: u8,
    pub n_auth: u8,
    pub auths: Vec<u8>,
}

#[derive(Debug)]
pub struct Socks5InitiationResponse {
    pub ver: u8,
    pub chosen: u8,
}

#[derive(Debug)]
pub struct Socks5AuthRequest {
    pub auth_ver: u8,
    pub len_user: u8,
    pub user: Vec<u8>,
    pub len_pass: u8,
    pub pass: Vec<u8>,
}

#[derive(Debug)]
pub struct Socks5AuthResponse {
    pub auth_ver: u8,
    pub status: u8,
}

#[derive(Debug)]
pub struct Socks5ConnectionRequest {
    pub ver: u8,
    pub cmd: u8,
    pub rsv: u8,
    pub dst_addr: SocksAddress,
    pub dst_port: u16,
}

#[derive(Debug)]
pub struct Socks5ConnectionResponse {
    pub ver: u8,
    pub status: u8,
    pub rsv: u8,
    pub bnd_addr: SocksAddress,
    pub bnd_port: u16,
}

#[derive(Debug)]
pub enum SocksRequest {
    Socks4Connection(Socks4ConnectionRequest),
    Socks5Initiation(Socks5InitiationRequest),
    Socks5Auth(Socks5AuthRequest),
    Socks5Connection(Socks5ConnectionRequest),
    Unknown,
}

pub async fn decode_input(input: &[u8]) -> BResult<&[u8], SocksRequest> {
    let (input, ver) = take(1u8)(input)?;
    match ver[0] {
        crate::options::VERSION_V4 => {
            if input.len() < 8 {
                return Err(nom::Err::Error(SocksErr::InconsistentLen));
            }
            // resolve cmd
            let (input, cmd) = be_u8(input)?;
            let cmd = match cmd {
                SOCKS_CMD_STREAM | SOCKS_CMD_BIND => {
                    cmd
                }
                _ => {
                    return Err(nom::Err::Error(SocksErr::InconsistentLen));
                }
            };

            // resolve port and ip
            let (input, port) = be_u16(input)?;
            let (input, ip) = be_u32(input)?;

            // resolve user_id
            let mut id: &[u8] = input;
            let (mut input, rst_len) = rest_len(input)?;
            if rst_len > 1 {
                let (u_input, u_id) = take(rst_len - 1)(input)?;
                input = u_input;
                id = u_id;
            }
            assert_eq!(input[0], NULL_TERMINATOR);
            Ok((input,
                SocksRequest::Socks4Connection(Socks4ConnectionRequest {
                    ver: ver[0],
                    cmd,
                    dst_port: port,
                    dst_ip: ip,
                    usr_id: id.to_vec(),
                })
            ))
        }
        crate::options::VERSION_V5 => {
            let (input, len) = be_u8(input)?;

            // Socks5InitiationRequest
            if len as usize == input.len() {
                let (input, meths) = take(len)(input)?;
                Ok((input,
                    SocksRequest::Socks5Initiation(Socks5InitiationRequest {
                        ver: ver[0],
                        n_auth: len,
                        auths: meths.to_vec(),
                    })
                ))
            } else {
                let cmd = len;
                let (input, rsv) = be_u8(input)?;
                assert_eq!(rsv, BYTE_RESERVED);
                let (input, addr) = decode_input_addr(input).await?;
                assert_eq!(input.len(), 2);
                let (input, port) = be_u16(input)?;
                Ok((input,
                    SocksRequest::Socks5Connection(Socks5ConnectionRequest {
                        ver: ver[0],
                        cmd,
                        rsv,
                        dst_addr: addr,
                        dst_port: port,
                    })
                ))
            }
        }
        _ => {
            tracing::error!("ingress data packet decode error: incomplete packet");
            Err(nom::Err::Error(SocksErr::UnknownPacket))
        }
    }
}

pub async fn decode_input_addr(input: &[u8]) -> BResult<&[u8], SocksAddress> {
    let (input, ver) = be_u8(input)?;
    match ver {
        SOCKS_ADDRESS_TYPE_IPV4 => {
            let (input, ipv4) = be_u32(input)?;
            Ok((input, SocksAddress::IPv4(ver, ipv4)))
        }
        SOCKS_ADDRESS_TYPE_DOMAIN => {
            let (input, len) = be_u8(input)?;
            let (input, addr) = take(len)(input)?;
            Ok((input, SocksAddress::Domain(ver, addr.to_vec())))
        }
        SOCKS_ADDRESS_TYPE_IPV6 => {
            let (input, ipv6) = be_u128(input)?;
            Ok((input, SocksAddress::IPv6(ver, ipv6)))
        }
        _ => {
            Err(nom::Err::Error(SocksErr::UnknownAddressType))
        }
    }
}

impl<In> nom::error::ParseError<In> for SocksErr<In> {
    fn from_error_kind(input: In, kind: ErrorKind) -> Self {
        SocksErr::NomError(nom::Err::Error((input, kind)))
    }

    fn append(input: In, kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl From<&[u8]> for SocksRequest {
    fn from(_: &[u8]) -> Self {
        let (input, ver) = take(1u8)(input)?;
        match ver[0] {
            crate::options::VERSION_V4 => {
                if input.len() < 8 {
                    return Err(nom::Err::Error(SocksErr::InconsistentLen));
                }
                // resolve cmd
                let (input, cmd) = be_u8(input)?;
                let cmd = match cmd {
                    SOCKS_CMD_STREAM | SOCKS_CMD_BIND => {
                        cmd
                    }
                    _ => {
                        return Err(nom::Err::Error(SocksErr::InconsistentLen));
                    }
                };

                // resolve port and ip
                let (input, port) = be_u16(input)?;
                let (input, ip) = be_u32(input)?;

                // resolve user_id
                let mut id: &[u8] = input;
                let (mut input, rst_len) = rest_len(input)?;
                if rst_len > 1 {
                    let (u_input, u_id) = take(rst_len - 1)(input)?;
                    input = u_input;
                    id = u_id;
                }
                assert_eq!(input[0], NULL_TERMINATOR);
                Ok((input,
                    SocksRequest::Socks4Connection(Socks4ConnectionRequest {
                        ver: ver[0],
                        cmd,
                        dst_port: port,
                        dst_ip: ip,
                        usr_id: id.to_vec(),
                    })
                ))
            }
            crate::options::VERSION_V5 => {
                let (input, len) = be_u8(input)?;

                // Socks5InitiationRequest
                if len as usize == input.len() {
                    let (input, meths) = take(len)(input)?;
                    Ok((input,
                        SocksRequest::Socks5Initiation(Socks5InitiationRequest {
                            ver: ver[0],
                            n_auth: len,
                            auths: meths.to_vec(),
                        })
                    ))
                } else {
                    let cmd = len;
                    let (input, rsv) = be_u8(input)?;
                    assert_eq!(rsv, BYTE_RESERVED);
                    let (input, addr) = decode_input_addr(input).await?;
                    assert_eq!(input.len(), 2);
                    let (input, port) = be_u16(input)?;
                    Ok((input,
                        SocksRequest::Socks5Connection(Socks5ConnectionRequest {
                            ver: ver[0],
                            cmd,
                            rsv,
                            dst_addr: addr,
                            dst_port: port,
                        })
                    ))
                }
            }
            _ => {
                tracing::error!("ingress data packet decode error: incomplete packet");
                Err(nom::Err::Error(SocksErr::UnknownPacket))
            }
        }
    }
}

impl From<&[u8]> for SocksAddress {
    fn from(_: &[u8]) -> Self {
        todo!()
    }
}

impl Into<Vec<u8>> for Socks4ConnectionResponse {
    fn into(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.ver);
        bytes.push(self.rep);
        bytes.extend(self.dst_port.to_be_bytes());
        bytes.extend(self.dst_ip.to_be_bytes());
        bytes
    }
}

impl Into<Vec<u8>> for Socks5InitiationResponse {
    fn into(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.ver);
        bytes.push(self.chosen);
        bytes
    }
}

impl Into<Vec<u8>> for Socks5AuthResponse {
    fn into(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.auth_ver);
        bytes.push(self.status);
        bytes
    }
}

impl Into<Vec<u8>> for Socks5ConnectionResponse {
    fn into(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.ver);
        bytes.push(self.status);
        bytes.push(self.rsv);
        bytes.extend(self.bnd_addr.to_bytes().await);
        bytes.extend(self.bnd_port.to_be_bytes());
        bytes
    }
}
