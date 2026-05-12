pub mod state;
pub mod routes;
pub mod auth;

use axum::Router;
use axum::http::{HeaderValue, Method, header};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use state::AppState;

pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin("http://127.0.0.1:9876".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE]);

    Router::new()
        .merge(routes::static_routes())
        .nest("/api", routes::api_routes(state.clone()))
        .layer(cors)
        .with_state(state)
}
