use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting SPMP Rust Provider Daemon on 0.0.0.0:9000...");
    Ok(())
}
