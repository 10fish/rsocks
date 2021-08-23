#[macro_use]
extern crate async_trait;

mod options;
mod packet;
mod dns;

use std::net::{SocketAddr, TcpStream};
use std::error::Error;
use std::io::ErrorKind;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info, warn};
use tokio::io::ErrorKind;
use rsocks_proto::handle_request;

const MTU_SIZE: usize = 1500;

async fn handle_stream<'a>(stream: TcpStream) {
    let mut buf: [u8; MTU_SIZE] = [0; MTU_SIZE];
    let stream = Arc::new(RwLock::new(stream));
    loop {
        let read_result = stream.write().await.read(&mut buf).await;

        match read_result {
            Ok(size_read) if size_read > 0 => {
                let data = buf[..size_read].to_vec();
                let result = packet::decode_input(data.as_slice()).await;
                match result {
                    Ok((_, req)) => {
                        debug!("req: {:?}", req);
                        handle_request(req, stream.clone()).await;
                    }
                    Err(err) => {
                        error!("ingress data packet decode error: {:?}", err);
                    }
                }
            }
            Err(err) if err.kind() == ErrorKind::ConnectionReset => {
                warn!("connection closed by requesting client.");
            }
            Err(err) => {
                error!("socket read error {:?}", err);
            }
            _ => {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(1, 1);
    }
}
