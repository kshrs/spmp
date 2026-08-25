use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting SPMP Rust Client Daemon on 127.0.0.1:8080...");
    Ok(())
}
