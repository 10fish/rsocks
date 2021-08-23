pub mod v4;
pub mod v5;

use tracing::{debug, warn, error};
use tokio::sync::RwLock;
use tokio::net::TcpStream;
use std::sync::Arc;
use tokio::io::{ErrorKind, AsyncWriteExt};

pub async fn handle_request(req: SocksRequest, stream: Arc<RwLock<TcpStream>>) {
    match req {
        SocksRequest::Socks4Connection(req) => {
            let uid = req.usr_id.clone();
            // TODO: authentication
            let reply = v4::handle_request(&req).await;
            match reply {
                Ok((Some(conn), resp)) => {
                    stream.write().await.write_all(resp.to_bytes().await.as_slice()).await.unwrap();
                    tcp_steam_proxy(stream.clone(), conn).await;
                }
                Ok((_, resp)) => {
                    warn!("socks protocol error...");
                    stream.write().await.write_all(resp.to_bytes().await.as_slice()).await.unwrap();
                }
                Err(err) => {
                    // TODO: error
                    error!("ingress data packet decode error: {:?}", err);
                }
            }
        }
        SocksRequest::Socks5Initiation(req) => {
            let mut chosen: u8 = 0x00;
            if req.n_auth > 0 && req.auths.len() > 0 {
                chosen = req.auths[0];
            }
            stream.write().await.write_all(Socks5InitiationResponse {
                ver: req.ver,
                chosen,
            }.to_bytes().await.as_slice()).await.unwrap();
        }
        SocksRequest::Socks5Auth(req) => {
            // TODO: authorize
            let mut status: u8 = 0x00;
            stream.write().await.write_all(Socks5AuthResponse {
                auth_ver: req.auth_ver,
                status,
            }.to_bytes().await.as_slice()).await.unwrap();
        }
        SocksRequest::Socks5Connection(req) => {
            let reply = v5::handle_request(&req).await;
            match reply {
                Ok((Some(conn), resp)) => {
                    stream.write().await.write_all(resp.to_bytes().await.as_slice()).await.unwrap();
                    tcp_steam_proxy(stream.clone(), conn).await;
                }
                Ok((_, resp)) => {
                    warn!("socks protocol error...");
                    stream.write().await.write_all(resp.to_bytes().await.as_slice()).await.unwrap();
                }
                Err(err) => {
                    // TODO: error
                    error!("ingress data packet decode error: {:?}", err);
                }
            }
        }
        _ => {}
    }
}


async fn tcp_steam_proxy(client: Arc<RwLock<TcpStream>>, mut remote: TcpStream) {
    let mut stream = client.write().await;
    let (mut client_read, mut client_write) = stream.split();
    let (mut remote_read, mut remote_write) = remote.split();

    let client_to_remote = async {
        match tokio::io::copy(&mut client_read, &mut remote_write).await {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::ConnectionReset => {
                warn!("connection closed by remote server.");
            }
            Err(err) => {
                error!("local to remote forward error: {:?}", err);
            }
        };
        remote_write.shutdown().await
    };

    let remote_to_client = async {
        match tokio::io::copy(&mut remote_read, &mut client_write).await {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::ConnectionReset => {
                warn!("connection closed by remote server.");
            }
            Err(err) => {
                error!("remote to local proxy error: {:?}", err);
            }
        }
        client_write.shutdown().await
    };

    let output = tokio::try_join!(client_to_remote,remote_to_client);
    match output {
        Ok(_) => {}
        Err(err) => {
            error!("tcp proxy error: {:?}", err);
        }
    }
}
