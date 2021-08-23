use std::error::Error;

pub async fn run() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let addr = SocketAddr::from(([127, 0, 0, 1], 1080));
    debug!("listening on {}", addr);
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, socket) = listener.accept().await?;
        debug!("accepted client sock on {:?}", socket);

        tokio::spawn(handle_stream(stream));
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut settings = config::Config::default();
    settings.merge(config::File::with_name("server"))?;
    rsocks::run().await
}