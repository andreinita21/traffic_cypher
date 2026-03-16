use axum::{
    extract::State,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put, delete},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use super::auth::validate_session;
use super::state::AppState;
use crate::{vault, totp, password_gen, key_rotation, multi_stream};

// ---------------------------------------------------------------------------
// Static file serving (embedded frontend)
// ---------------------------------------------------------------------------

const INDEX_HTML: &str = include_str!("../frontend/index.html");
const APP_JS: &str = include_str!("../frontend/app.js");
const STYLE_CSS: &str = include_str!("../frontend/style.css");

pub fn static_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(serve_index))
        .route("/app.js", get(serve_js))
        .route("/style.css", get(serve_css))
}

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn serve_js() -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/javascript")],
        APP_JS,
    )
        .into_response()
}

async fn serve_css() -> Response {
    (
        StatusCode::OK,
        [("content-type", "text/css")],
        STYLE_CSS,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// API routes
// ---------------------------------------------------------------------------

pub fn api_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        // Auth
        .route("/auth/unlock", post(unlock))
        .route("/auth/lock", post(lock))
        .route("/auth/status", get(auth_status))
        .route("/auth/verify-password", post(verify_password))
        // Credentials
        .route("/credentials", get(list_credentials))
        .route("/credentials", post(create_credential))
        .route("/credentials/{id}", get(get_credential))
        .route("/credentials/{id}", put(update_credential))
        .route("/credentials/{id}", delete(delete_credential))
        .route("/credentials/{id}/totp", get(get_totp))
        // Password generator
        .route("/generate-password", post(generate_password))
        // Key rotation
        .route("/rotate-key", post(rotate_key))
        // Streams
        .route("/streams", get(list_streams))
        .route("/streams", post(add_stream))
        .route("/streams/{index}", delete(remove_stream))
        .route("/streams/{index}", put(update_stream))
        // Status & entropy
        .route("/status", get(get_status))
        .route("/entropy-snapshot", get(entropy_snapshot))
        // Settings
        .route("/settings", get(get_settings))
        .route("/settings", put(update_settings))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct UnlockRequest {
    master_password: String,
}

#[derive(Serialize)]
struct UnlockResponse {
    token: String,
    entry_count: usize,
    entropy_source: String,
}

#[derive(Serialize)]
struct AuthStatusResponse {
    unlocked: bool,
}

#[derive(Deserialize)]
struct VerifyPasswordRequest {
    master_password: String,
}

#[derive(Deserialize)]
struct CreateCredentialRequest {
    label: String,
    website: Option<String>,
    username: Option<String>,
    password: Option<String>,
    totp_secret: Option<String>,
    notes: Option<String>,
    tags: Option<Vec<String>>,
    generate_password: Option<bool>,
    password_length: Option<usize>,
}

#[derive(Deserialize)]
struct UpdateCredentialRequest {
    label: Option<String>,
    website: Option<String>,
    username: Option<String>,
    password: Option<String>,
    totp_secret: Option<String>,
    notes: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct GeneratePasswordRequest {
    length: Option<usize>,
    uppercase: Option<bool>,
    lowercase: Option<bool>,
    digits: Option<bool>,
    symbols: Option<bool>,
}

#[derive(Serialize)]
struct GeneratePasswordResponse {
    password: String,
    strength: password_gen::PasswordStrength,
}

#[derive(Deserialize)]
struct AddStreamRequest {
    url: String,
    label: String,
}

#[derive(Deserialize)]
struct UpdateStreamRequest {
    url: Option<String>,
    label: Option<String>,
}

#[derive(Serialize)]
struct TotpResponse {
    code: String,
    seconds_remaining: u32,
}

#[derive(Serialize)]
struct StatusResponse {
    rotation: key_rotation::KeyRotationStatus,
    stream_count: usize,
    streams: Vec<multi_stream::StreamStatus>,
    entry_count: usize,
    entropy_source: String,
}

#[derive(Serialize)]
struct EntropySnapshotResponse {
    key_epoch: u64,
    frames_processed: u64,
    pool_depth: usize,
    has_traffic_entropy: bool,
    is_running: bool,
    entropy_source: String,
    latest_key_hex: String,
}

#[derive(Serialize)]
struct SettingsResponse {
    auto_lock_minutes: u64,
    streams: Vec<vault::StreamEntry>,
}

#[derive(Deserialize)]
struct UpdateSettingsRequest {
    auto_lock_minutes: Option<u64>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct RotateKeyResponse {
    status: String,
    entropy_source: String,
}

fn err_json(status: StatusCode, msg: &str) -> Response {
    (status, Json(ErrorResponse { error: msg.to_string() })).into_response()
}

fn unauthorized() -> Response {
    err_json(StatusCode::UNAUTHORIZED, "Not authenticated")
}

// ---------------------------------------------------------------------------
// Helper: save vault using current DEK from state
// ---------------------------------------------------------------------------

async fn save_vault_with_state(state: &Arc<AppState>) -> Result<(), String> {
    let v = state.vault.read().await;
    let master = state.master_password.read().await;
    let dek_opt = state.current_dek.read().await;
    let entropy_src = state.entropy_source.read().await;

    let dek = dek_opt.ok_or("No DEK available — vault not unlocked")?;
    vault::save_vault(&v, &master, &dek, &entropy_src)
        .map_err(|e| format!("Save failed: {}", e))
}

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

async fn unlock(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnlockRequest>,
) -> Response {
    // Try to load vault with master password only (envelope encryption)
    match vault::load_vault(&req.master_password) {
        Ok(unlocked) => {
            let entry_count = unlocked.vault.entries.len();
            let entropy_source = unlocked.entropy_source.clone();
            let token = Uuid::new_v4().to_string();

            // Store session
            *state.session_token.write().await = Some(token.clone());
            *state.master_password.write().await = req.master_password.clone();
            *state.vault.write().await = unlocked.vault;
            *state.is_unlocked.write().await = true;
            *state.current_dek.write().await = Some(unlocked.dek);
            *state.entropy_source.write().await = entropy_source.clone();
            state.touch_activity().await;

            // Load stream config and start streams
            let config = vault::load_stream_config();
            let auto_lock = config.settings.auto_lock_minutes;
            *state.auto_lock_minutes.write().await = auto_lock;

            // Start streams in background
            let sm = state.stream_manager.clone();
            let streams = config.streams.clone();
            tokio::spawn(async move {
                for stream_entry in streams {
                    if stream_entry.enabled {
                        let mut mgr = sm.lock().await;
                        if let Err(e) = mgr.add_stream(stream_entry.url.clone(), stream_entry.label.clone()).await {
                            tracing::warn!("Failed to connect stream '{}': {}", stream_entry.label, e);
                        }
                    }
                }
            });

            // Start entropy collection daemon
            let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
            *state.rotation_cancel.write().await = Some(cancel_tx);

            let sm_clone = state.stream_manager.clone();
            let rs_clone = state.rotation_state.clone();
            tokio::spawn(async move {
                key_rotation::start_rotation_daemon(
                    sm_clone, rs_clone, cancel_rx,
                ).await;
            });

            (StatusCode::OK, Json(UnlockResponse { token, entry_count, entropy_source })).into_response()
        }
        Err(e) => {
            err_json(StatusCode::UNAUTHORIZED, &format!("Failed to unlock: {}", e))
        }
    }
}

async fn lock(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    // Stop entropy collection daemon
    if let Some(cancel) = state.rotation_cancel.write().await.take() {
        let _ = cancel.send(true);
    }

    // Clear session and DEK from memory
    *state.session_token.write().await = None;
    *state.master_password.write().await = String::new();
    *state.vault.write().await = vault::Vault::default();
    *state.is_unlocked.write().await = false;
    *state.current_dek.write().await = None;

    (StatusCode::OK, Json(serde_json::json!({"status": "locked"}))).into_response()
}

async fn auth_status(
    State(state): State<Arc<AppState>>,
) -> Json<AuthStatusResponse> {
    let unlocked = *state.is_unlocked.read().await;
    // Check auto-lock
    if unlocked && state.check_auto_lock().await {
        // Auto-lock: clear DEK and session
        if let Some(cancel) = state.rotation_cancel.write().await.take() {
            let _ = cancel.send(true);
        }
        *state.session_token.write().await = None;
        *state.is_unlocked.write().await = false;
        *state.current_dek.write().await = None;
        return Json(AuthStatusResponse { unlocked: false });
    }
    Json(AuthStatusResponse { unlocked })
}

async fn verify_password(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyPasswordRequest>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let master = state.master_password.read().await;
    if *master == req.master_password {
        (StatusCode::OK, Json(serde_json::json!({"valid": true}))).into_response()
    } else {
        (StatusCode::OK, Json(serde_json::json!({"valid": false}))).into_response()
    }
}

// ---------------------------------------------------------------------------
// Credential handlers
// ---------------------------------------------------------------------------

async fn list_credentials(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let v = state.vault.read().await;
    let mut entries: Vec<&vault::VaultEntry> = v.entries.iter().collect();

    // Search filter
    if let Some(q) = params.get("q") {
        let q_lower = q.to_lowercase();
        entries.retain(|e| {
            e.label.to_lowercase().contains(&q_lower)
                || e.username.as_deref().unwrap_or("").to_lowercase().contains(&q_lower)
                || e.website.as_deref().unwrap_or("").to_lowercase().contains(&q_lower)
                || e.tags.iter().any(|t| t.to_lowercase().contains(&q_lower))
        });
    }

    // Tag filter
    if let Some(tag) = params.get("tag") {
        let tag_lower = tag.to_lowercase();
        entries.retain(|e| e.tags.iter().any(|t| t.to_lowercase() == tag_lower));
    }

    // Sort by label
    let mut entries: Vec<vault::VaultEntry> = entries.into_iter().cloned().collect();
    entries.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()));

    (StatusCode::OK, Json(entries)).into_response()
}

async fn get_credential(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let v = state.vault.read().await;
    match v.get_by_id(&id) {
        Some(entry) => (StatusCode::OK, Json(entry.clone())).into_response(),
        None => err_json(StatusCode::NOT_FOUND, "Credential not found"),
    }
}

async fn create_credential(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateCredentialRequest>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let password = if req.generate_password.unwrap_or(false) {
        let opts = password_gen::PasswordOptions {
            length: req.password_length.unwrap_or(24),
            ..Default::default()
        };
        password_gen::generate(&opts)
    } else {
        req.password.unwrap_or_default()
    };

    let entry = vault::VaultEntry::new(
        req.label,
        req.website,
        req.username,
        password,
        req.totp_secret,
        req.notes,
        req.tags.unwrap_or_default(),
    );

    let mut v = state.vault.write().await;
    let id = entry.id.clone();
    v.add_or_update(entry);

    // Save to disk using current DEK
    drop(v); // release write lock before calling save
    if let Err(e) = save_vault_with_state(&state).await {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e);
    }

    let v = state.vault.read().await;
    match v.get_by_id(&id) {
        Some(entry) => (StatusCode::CREATED, Json(entry.clone())).into_response(),
        None => err_json(StatusCode::INTERNAL_SERVER_ERROR, "Entry created but not found"),
    }
}

async fn update_credential(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateCredentialRequest>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let mut v = state.vault.write().await;

    let entry = match v.entries.iter_mut().find(|e| e.id == id) {
        Some(e) => e,
        None => return err_json(StatusCode::NOT_FOUND, "Credential not found"),
    };

    if let Some(label) = req.label {
        entry.label = label;
    }
    if let Some(website) = req.website {
        entry.website = Some(website);
    }
    if let Some(username) = req.username {
        entry.username = Some(username);
    }
    if let Some(password) = req.password {
        // Push old password to history
        let old = std::mem::replace(&mut entry.password, password);
        entry.password_history.push(vault::PasswordHistoryEntry {
            password: old,
            changed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });
        // Keep max 10 history entries
        if entry.password_history.len() > 10 {
            entry.password_history.remove(0);
        }
    }
    if let Some(totp_secret) = req.totp_secret {
        entry.totp_secret = if totp_secret.is_empty() { None } else { Some(totp_secret) };
    }
    if let Some(notes) = req.notes {
        entry.notes = Some(notes);
    }
    if let Some(tags) = req.tags {
        entry.tags = tags;
    }

    entry.updated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let entry_clone = entry.clone();

    // Save
    drop(v);
    if let Err(e) = save_vault_with_state(&state).await {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e);
    }

    (StatusCode::OK, Json(entry_clone)).into_response()
}

async fn delete_credential(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let mut v = state.vault.write().await;
    if !v.delete_by_id(&id) {
        return err_json(StatusCode::NOT_FOUND, "Credential not found");
    }

    // Save
    drop(v);
    if let Err(e) = save_vault_with_state(&state).await {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e);
    }

    (StatusCode::OK, Json(serde_json::json!({"status": "deleted"}))).into_response()
}

async fn get_totp(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let v = state.vault.read().await;
    let entry = match v.get_by_id(&id) {
        Some(e) => e,
        None => return err_json(StatusCode::NOT_FOUND, "Credential not found"),
    };

    let secret = match &entry.totp_secret {
        Some(s) => s,
        None => return err_json(StatusCode::BAD_REQUEST, "No TOTP secret configured"),
    };

    match totp::generate_totp(secret) {
        Ok((code, remaining)) => {
            (StatusCode::OK, Json(TotpResponse { code, seconds_remaining: remaining })).into_response()
        }
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("TOTP error: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// Password generator handler
// ---------------------------------------------------------------------------

async fn generate_password(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<GeneratePasswordRequest>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let opts = password_gen::PasswordOptions {
        length: req.length.unwrap_or(24),
        uppercase: req.uppercase.unwrap_or(true),
        lowercase: req.lowercase.unwrap_or(true),
        digits: req.digits.unwrap_or(true),
        symbols: req.symbols.unwrap_or(true),
    };

    let password = password_gen::generate(&opts);
    let strength = password_gen::calculate_strength(&password);

    (StatusCode::OK, Json(GeneratePasswordResponse { password, strength })).into_response()
}

// ---------------------------------------------------------------------------
// Key rotation handler
// ---------------------------------------------------------------------------

async fn rotate_key(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    // Try to generate a new DEK from traffic entropy
    let (new_dek, source) = match state.rotation_state.generate_traffic_dek().await {
        Some(dek) => (dek, "traffic"),
        None => {
            // Fallback to OS entropy
            (vault::generate_dek_from_os(), "os")
        }
    };

    // Re-encrypt vault with new DEK
    let v = state.vault.read().await;
    let master = state.master_password.read().await;
    if let Err(e) = vault::rotate_dek(&v, &master, &new_dek, source) {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("Key rotation failed: {}", e));
    }

    // Update in-memory DEK
    *state.current_dek.write().await = Some(new_dek);
    *state.entropy_source.write().await = source.to_string();

    (StatusCode::OK, Json(RotateKeyResponse {
        status: "rotated".to_string(),
        entropy_source: source.to_string(),
    })).into_response()
}

// ---------------------------------------------------------------------------
// Stream handlers
// ---------------------------------------------------------------------------

async fn list_streams(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let mgr = state.stream_manager.lock().await;
    let statuses = mgr.get_statuses();
    (StatusCode::OK, Json(statuses)).into_response()
}

async fn add_stream(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddStreamRequest>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    // Start the stream resolution in the background (non-blocking).
    // Config is saved only after the stream is successfully added to the manager.
    let sm = state.stream_manager.clone();
    let url = req.url.clone();
    let label = req.label.clone();
    tokio::spawn(async move {
        let mut mgr = sm.lock().await;
        match mgr.add_stream(url.clone(), label.clone()).await {
            Ok(_) => {
                // Persist to config only on success
                let mut config = vault::load_stream_config();
                config.streams.push(vault::StreamEntry {
                    url,
                    label: label.clone(),
                    enabled: true,
                });
                if let Err(e) = vault::save_stream_config(&config) {
                    tracing::warn!("Config save failed for '{}': {}", label, e);
                }
            }
            Err(e) => {
                tracing::warn!("Background stream resolution failed for '{}': {}", label, e);
            }
        }
    });

    (StatusCode::CREATED, Json(serde_json::json!({"status": "connecting", "label": req.label}))).into_response()
}

async fn remove_stream(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(index): Path<usize>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let mut mgr = state.stream_manager.lock().await;
    match mgr.remove_stream(index) {
        Ok(()) => {
            // Update config
            let mut config = vault::load_stream_config();
            if index < config.streams.len() {
                config.streams.remove(index);
                let _ = vault::save_stream_config(&config);
            }
            (StatusCode::OK, Json(serde_json::json!({"status": "removed"}))).into_response()
        }
        Err(e) => err_json(StatusCode::BAD_REQUEST, &format!("{}", e)),
    }
}

async fn update_stream(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(index): Path<usize>,
    Json(req): Json<UpdateStreamRequest>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let mut mgr = state.stream_manager.lock().await;
    match mgr.update_stream(index, req.label.clone(), req.url.clone()) {
        Ok(()) => {
            // Persist to config
            let mut config = vault::load_stream_config();
            if index < config.streams.len() {
                if let Some(ref l) = req.label {
                    config.streams[index].label = l.clone();
                }
                if let Some(ref u) = req.url {
                    config.streams[index].url = u.clone();
                }
                let _ = vault::save_stream_config(&config);
            }
            (StatusCode::OK, Json(serde_json::json!({"status": "updated"}))).into_response()
        }
        Err(e) => err_json(StatusCode::BAD_REQUEST, &format!("{}", e)),
    }
}

// ---------------------------------------------------------------------------
// Status & Settings handlers
// ---------------------------------------------------------------------------

async fn get_status(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let rotation = state.rotation_state.status().await;
    let mgr = state.stream_manager.lock().await;
    let streams = mgr.get_statuses();
    let stream_count = mgr.stream_count();
    let v = state.vault.read().await;
    let entry_count = v.entries.len();
    let entropy_source = state.entropy_source.read().await.clone();

    (StatusCode::OK, Json(StatusResponse {
        rotation,
        stream_count,
        streams,
        entry_count,
        entropy_source,
    })).into_response()
}

async fn entropy_snapshot(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let rotation = state.rotation_state.status().await;
    let entropy_source = state.entropy_source.read().await.clone();
    let latest_entropy = state.rotation_state.latest_entropy.read().await;
    let latest_key_hex = if latest_entropy.is_empty() {
        "0000000000000000".to_string()
    } else {
        hex::encode(&latest_entropy[..std::cmp::min(latest_entropy.len(), 32)])
    };

    (StatusCode::OK, Json(EntropySnapshotResponse {
        key_epoch: rotation.key_epoch,
        frames_processed: rotation.frames_processed,
        pool_depth: rotation.pool_depth,
        has_traffic_entropy: rotation.has_traffic_entropy,
        is_running: rotation.is_running,
        entropy_source,
        latest_key_hex,
    })).into_response()
}

async fn get_settings(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    let auto_lock = *state.auto_lock_minutes.read().await;
    let config = vault::load_stream_config();

    (StatusCode::OK, Json(SettingsResponse {
        auto_lock_minutes: auto_lock,
        streams: config.streams,
    })).into_response()
}

async fn update_settings(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateSettingsRequest>,
) -> Response {
    if !validate_session(&headers, &state).await {
        return unauthorized();
    }

    if let Some(mins) = req.auto_lock_minutes {
        *state.auto_lock_minutes.write().await = mins;
        let mut config = vault::load_stream_config();
        config.settings.auto_lock_minutes = mins;
        let _ = vault::save_stream_config(&config);
    }

    (StatusCode::OK, Json(serde_json::json!({"status": "updated"}))).into_response()
}
