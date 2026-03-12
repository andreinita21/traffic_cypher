use axum::http::HeaderMap;
use std::sync::Arc;

use super::state::AppState;

/// Extract and validate session token from Authorization header
pub async fn validate_session(headers: &HeaderMap, state: &Arc<AppState>) -> bool {
    let token = match headers.get("authorization") {
        Some(val) => {
            let val_str = val.to_str().unwrap_or("");
            if val_str.starts_with("Bearer ") {
                val_str[7..].to_string()
            } else {
                return false;
            }
        }
        None => return false,
    };

    let session = state.session_token.read().await;
    match &*session {
        Some(stored) => {
            if stored == &token {
                // Check auto-lock
                if state.check_auto_lock().await {
                    return false;
                }
                state.touch_activity().await;
                true
            } else {
                false
            }
        }
        None => false,
    }
}
