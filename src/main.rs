use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let landing = resolved::landing_glue::LandingConfig::default();
    // Optionally overlay from resolved.conf parser here.
    resolved::landing_glue::run(landing).await
}
