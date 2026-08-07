#![allow(warnings)]
// In async main after config load:
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing_subscriber::fmt::init();
    // let cfg = config::load()?;
    let landing = resolved::landing_glue::LandingConfig::default();
    resolved::landing_glue::run(landing).await
}
