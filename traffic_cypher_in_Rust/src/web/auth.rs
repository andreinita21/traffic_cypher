use axum::http::HeaderMap;
use std::sync::Arc;

use super::state::AppState;

/// Extract and validate session token from Authorization header
pub async fn validate_session(headers: &HeaderMap, state: &Arc<AppState>) -> bool {
    let token = match headers.get("authorization") {
        Some(val) => {
            let val_str = val.to_str().unwrap_or("");
            if let Some(stripped) = val_str.strip_prefix("Bearer ") {
                stripped.to_string()
            } else {
                return false;
            }
        }
        None => return false,
    };

    let session = state.session_token.read().await;
    let Some(stored) = session.as_deref() else {
        return false;
    };
    if stored != token {
        return false;
    }
    // Check auto-lock (drops the read guard implicitly when we leave scope).
    if state.check_auto_lock().await {
        return false;
    }
    state.touch_activity().await;
    true
}
