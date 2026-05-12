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
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::auth::validate_session;
use super::state::AppState;
use crate::{vault, totp, password_gen, key_rotation, multi_stream};

// ---------------------------------------------------------------------------
// Static file serving (embedded frontend)
// ---------------------------------------------------------------------------

// Frontend is single-source-of-truth at repo root `frontend/`.
// Path is relative to this .rs file: web/ → src/ → traffic_cypher_in_Rust/ → repo root.
const INDEX_HTML: &str = include_str!("../../../frontend/index.html");
const APP_JS: &str = include_str!("../../../frontend/app.js");
const STYLE_CSS: &str = include_str!("../../../frontend/style.css");

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
        // Build descriptor — no auth (mirrors C build's /api/build/info).
        // Frontends fetch this at init to decide whether to show the
        // "OS entropy only" banner. The Rust build advertises traffic
        // entropy = true because MultiStreamManager is wired here.
        .route("/build/info", get(build_info))
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

    // `Zeroizing<[u8; 32]>` is not Copy — borrow via `as_ref()` so the secret
    // stays owned by the lock guard and is not moved out.
    let dek = dek_opt
        .as_ref()
        .ok_or("No DEK available — vault not unlocked")?;
    vault::save_vault(&v, master.as_str(), dek, &entropy_src)
        .map_err(|e| format!("Save failed: {}", e))
}

// ---------------------------------------------------------------------------
// Build descriptor handler (no auth)
// ---------------------------------------------------------------------------

async fn build_info() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "build": "rust",
            "traffic_entropy": true,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

// Rate-limit constants for /api/auth/unlock.
//
// Threat model: localhost-only listener, single user. After 5 failed unlocks
// within `UNLOCK_WINDOW`, lock out *all* unlock attempts for `unlock_lockout_secs()`
// — see REMEDIATION_PLAN.md §8. Lockout duration is overridable via the
// `TC_UNLOCK_LOCKOUT_S` env var (default 30 s) so the test suite can drive
// this without sleeping 31 s of wall time.
const UNLOCK_WINDOW: Duration = Duration::from_secs(60);
const UNLOCK_FAIL_LIMIT: usize = 5;

fn unlock_lockout_secs() -> u64 {
    std::env::var("TC_UNLOCK_LOCKOUT_S")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(30)
}

/// Returns `Some(seconds_remaining)` if a lockout is currently active.
/// On expiry, clears BOTH the lockout AND the failure ring — punishment
/// served, fresh window. Otherwise a single post-cooldown wrong attempt
/// would re-arm the lockout because the stale timestamps still sit within
/// the 60 s window.
async fn check_unlock_lockout(state: &Arc<AppState>) -> Option<u64> {
    let now = Instant::now();
    let mut guard = state.unlock_lockout_until.write().await;
    if let Some(until) = *guard {
        if now < until {
            let secs = until.duration_since(now).as_secs().max(1);
            return Some(secs);
        }
        *guard = None;
        drop(guard);
        *state.unlock_failure_times.write().await = [None; 5];
    }
    None
}

/// Record a failed unlock. If the ring buffer now holds 5 timestamps all
/// within `UNLOCK_WINDOW` of `now`, arm a lockout.
async fn record_unlock_failure(state: &Arc<AppState>) {
    let now = Instant::now();
    let mut times = state.unlock_failure_times.write().await;

    // Overwrite the oldest slot (smallest Instant; empty slots count as oldest).
    let mut oldest_idx = 0usize;
    for i in 1..UNLOCK_FAIL_LIMIT {
        match (times[oldest_idx], times[i]) {
            (None, _) => break,
            (_, None) => { oldest_idx = i; break; }
            (Some(a), Some(b)) => if b < a { oldest_idx = i; }
        }
    }
    times[oldest_idx] = Some(now);

    // If all 5 slots are populated and all within the 60 s window, lock out.
    if times.iter().all(|t| matches!(t, Some(t0) if now.duration_since(*t0) <= UNLOCK_WINDOW)) {
        *state.unlock_lockout_until.write().await =
            Some(now + Duration::from_secs(unlock_lockout_secs()));
    }
}

async fn reset_unlock_rate_state(state: &Arc<AppState>) {
    *state.unlock_failure_times.write().await = [None; 5];
    *state.unlock_lockout_until.write().await = None;
}

fn rate_limited_response(retry_after_secs: u64) -> Response {
    let body = Json(ErrorResponse {
        error: format!(
            "Too many failed unlock attempts; retry after {} s",
            retry_after_secs
        ),
    });
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("retry-after", retry_after_secs.to_string())],
        body,
    )
        .into_response()
}

async fn unlock(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnlockRequest>,
) -> Response {
    // Rate-limit gate. During lockout, *all* unlock attempts (right or wrong)
    // return 429 — we don't even call load_vault.
    if let Some(secs) = check_unlock_lockout(&state).await {
        return rate_limited_response(secs);
    }

    // Try to load vault with master password only (envelope encryption)
    match vault::load_vault(&req.master_password) {
        Ok(unlocked) => {
            let entry_count = unlocked.vault.entries.len();
            let entropy_source = unlocked.entropy_source.clone();
            let token = Uuid::new_v4().to_string();

            // Store session. Wrap secrets in `Zeroizing` so their backing
            // buffers are wiped when replaced or dropped.
            *state.session_token.write().await = Some(token.clone());
            *state.master_password.write().await =
                zeroize::Zeroizing::new(req.master_password.clone());
            *state.vault.write().await = unlocked.vault;
            *state.is_unlocked.write().await = true;
            *state.current_dek.write().await = Some(unlocked.dek);
            *state.entropy_source.write().await = entropy_source.clone();
            state.touch_activity().await;
            // Successful unlock resets the rate-limit window.
            reset_unlock_rate_state(&state).await;

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
            // Record failure; if 5-in-60s tripped, the NEXT attempt is the
            // one that gets 429 (per spec: "5 failures → next attempt locks").
            record_unlock_failure(&state).await;
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

    // Clear session and DEK from memory. Assigning a fresh empty
    // `Zeroizing<String>` triggers Drop on the old value, wiping the bytes.
    *state.session_token.write().await = None;
    *state.master_password.write().await = zeroize::Zeroizing::new(String::new());
    *state.vault.write().await = vault::Vault::default();
    *state.is_unlocked.write().await = false;
    *state.current_dek.write().await = None;

    // Drain all streams to ensure ffmpeg children are killed on lock.
    let mut mgr = state.stream_manager.lock().await;
    while mgr.stream_count() > 0 {
        let _ = mgr.remove_stream(0).await;
    }

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
    if master.as_str() == req.master_password.as_str() {
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
    entries.sort_by_key(|e| e.label.to_lowercase());

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
    if let Err(e) = vault::rotate_dek(&v, master.as_str(), &new_dek, source) {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("Key rotation failed: {}", e));
    }

    // Update in-memory DEK. Wrap in `Zeroizing` so the prior key bytes are
    // overwritten when this slot is later cleared or replaced.
    *state.current_dek.write().await = Some(zeroize::Zeroizing::new(new_dek));
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
    match mgr.remove_stream(index).await {
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
