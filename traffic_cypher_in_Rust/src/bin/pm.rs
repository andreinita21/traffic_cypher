//! Traffic Cypher Password Manager — Web UI
//!
//! Starts an axum web server serving the password manager dashboard.
//! Bind address/port default to 127.0.0.1:9876; override with the
//! TC_BIND_ADDR and TC_PORT environment variables.

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

    // Bind address and port are configurable for LAN / reverse-proxy / tunnel
    // deployments (e.g. a cloudflared tunnel). Defaults stay 127.0.0.1:9876 so
    // the documented localhost-only threat model holds unless an operator
    // explicitly opts in by setting these env vars.
    let bind_addr = std::env::var("TC_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("TC_PORT").unwrap_or_else(|_| "9876".to_string());
    let listen = format!("{bind_addr}:{port}");

    println!(
        r#"
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║     T R A F F I C   C Y P H E R                          ║
║   Entropy-Driven Password Manager                        ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"#
    );
    println!("   Dashboard: http://{listen}\n");

    let state = Arc::new(web::state::AppState::new());
    let router = web::create_router(state);

    let listener = tokio::net::TcpListener::bind(listen.as_str()).await?;
    info!("Listening on http://{listen}");

    axum::serve(listener, router).await?;

    Ok(())
}
