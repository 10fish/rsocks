use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut settings = config::Config::default();
    settings.merge(config::File::with_name("server"))?;
    rsocks::run().await
}