pub mod state;
pub mod routes;
pub mod auth;

use axum::Router;
use std::sync::Arc;
use tower_http::cors::{CorsLayer, Any};

use state::AppState;

pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .merge(routes::static_routes())
        .nest("/api", routes::api_routes(state.clone()))
        .layer(cors)
        .with_state(state)
}
