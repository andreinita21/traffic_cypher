/// Traffic Cypher Password Manager — Web UI
///
/// Starts an axum web server on 127.0.0.1:9876 serving the password manager
/// dashboard with liquid glass UI.

use anyhow::Result;
use std::sync::Arc;
use tracing::info;

use traffic_cypher::web;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    println!(r#"
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║     T R A F F I C   C Y P H E R                          ║
║   Entropy-Driven Password Manager                        ║
║                                                          ║
║   Dashboard: http://127.0.0.1:9876                       ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"#);

    let state = Arc::new(web::state::AppState::new());
    let router = web::create_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:9876").await?;
    info!("Listening on http://127.0.0.1:9876");

    axum::serve(listener, router).await?;

    Ok(())
}
