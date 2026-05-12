//! HTTP integration tests against the real `web::create_router`.
//!
//! These tests drive the router via `tower::ServiceExt::oneshot` — no
//! socket, no `TcpListener`, no port allocation. Each test gets its own
//! `tempfile::tempdir()` so vault state never leaks across tests.
//!
//! **MUST be run with `--test-threads=1`** because `AppState::for_test`
//! mutates the process-global `TRAFFIC_CYPHER_VAULT_PATH` env var. The
//! shell wrapper `tests/17_rust_http.sh` enforces this.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

use traffic_cypher::web::{create_router, state::AppState};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a fresh router + tempdir pair. Caller must keep the `TempDir`
/// alive for the duration of the test — dropping it deletes the vault file.
fn fresh_app() -> (axum::Router, TempDir) {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let vault_path = tmp.path().join("vault.json");
    // Point HOME at the tempdir too, so stream-config writes don't touch
    // the developer's real ~/.traffic_cypher_streams.json.
    std::env::set_var("HOME", tmp.path());
    let state = Arc::new(AppState::for_test(vault_path));
    let app = create_router(state);
    (app, tmp)
}

/// Send a JSON request and parse the JSON response.
/// Returns `(status, body_value)`. `body_value` is `Value::Null` if the
/// response body is empty or not JSON.
async fn send_json(
    app: axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let body_bytes = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&body).expect("serialize body")
    };

    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {}", t));
    }
    let req = req.body(Body::from(body_bytes)).expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let val = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, val)
}

/// Send a request with a raw (possibly malformed) body — for tests
/// that need to assert how the server reacts to non-JSON input.
async fn send_raw(
    app: axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: &str,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {}", t));
    }
    let req = req
        .body(Body::from(body.to_string()))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let val = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, val)
}

/// Unlock a fresh vault and return the bearer token. The Rust unlock
/// handler creates an empty vault on first contact, so any non-empty
/// password works against a fresh tempdir.
async fn unlock_fresh(app: axum::Router, password: &str) -> String {
    let (status, body) = send_json(
        app,
        "POST",
        "/api/auth/unlock",
        None,
        json!({ "master_password": password }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unlock failed: {:?}", body);
    body["token"]
        .as_str()
        .expect("token in unlock response")
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_credential_lifecycle() {
    let (app, _tmp) = fresh_app();

    // 1. Unlock — fresh vault is created on first unlock.
    let token = unlock_fresh(app.clone(), "lifecycle-pw").await;

    // 2. List is initially empty.
    let (status, list0) = send_json(
        app.clone(),
        "GET",
        "/api/credentials",
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list0.as_array().map(|a| a.len()), Some(0));

    // 3. Create credential with tags.
    let (status, created) = send_json(
        app.clone(),
        "POST",
        "/api/credentials",
        Some(&token),
        json!({
            "label": "GitHub",
            "website": "https://github.com",
            "username": "dev@example.com",
            "password": "gh-secret-123",
            "tags": ["dev", "code"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create failed: {:?}", created);
    let id = created["id"].as_str().expect("id field").to_string();
    assert_eq!(created["label"], "GitHub");

    // 4. List sees 1 entry.
    let (status, list1) = send_json(
        app.clone(),
        "GET",
        "/api/credentials",
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list1.as_array().map(|a| a.len()), Some(1));

    // 5. Get by id.
    let (status, got) = send_json(
        app.clone(),
        "GET",
        &format!("/api/credentials/{}", id),
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got["password"], "gh-secret-123");

    // 6. Update.
    let (status, updated) = send_json(
        app.clone(),
        "PUT",
        &format!("/api/credentials/{}", id),
        Some(&token),
        json!({ "label": "GitHub Renamed" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update failed: {:?}", updated);
    assert_eq!(updated["label"], "GitHub Renamed");

    // 7. Delete.
    let (status, _) = send_json(
        app.clone(),
        "DELETE",
        &format!("/api/credentials/{}", id),
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 8. List is empty again.
    let (status, list2) = send_json(
        app,
        "GET",
        "/api/credentials",
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list2.as_array().map(|a| a.len()), Some(0));
}

#[tokio::test]
async fn unlock_wrong_password_401() {
    let (app, _tmp) = fresh_app();

    // First, create a vault by unlocking once and creating an entry —
    // this persists a vault file encrypted with the "right" password.
    let token = unlock_fresh(app.clone(), "right-password").await;
    let (status, _) = send_json(
        app.clone(),
        "POST",
        "/api/credentials",
        Some(&token),
        json!({ "label": "anchor", "password": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Now attempt to unlock the existing vault with the wrong password.
    // The handler must return 401.
    let (status, body) = send_json(
        app,
        "POST",
        "/api/auth/unlock",
        None,
        json!({ "master_password": "wrong-password" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {:?}", body);
}

#[tokio::test]
async fn protected_routes_require_auth() {
    let (app, _tmp) = fresh_app();

    // No Authorization header.
    let (status, _) = send_json(
        app,
        "GET",
        "/api/credentials",
        None,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_json_400() {
    let (app, _tmp) = fresh_app();

    let token = unlock_fresh(app.clone(), "malformed-pw").await;

    // Send syntactically invalid JSON. Axum's `Json` extractor returns 4xx
    // (typically 400 BAD_REQUEST or 422 UNPROCESSABLE_ENTITY) for parse
    // failures. The contract this test pins is: NOT 5xx, NOT 2xx.
    let (status, _) = send_raw(
        app,
        "POST",
        "/api/credentials",
        Some(&token),
        "{not valid json",
    )
    .await;
    assert!(
        status.is_client_error(),
        "expected 4xx for malformed JSON, got {}",
        status
    );
    assert_ne!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_id_404() {
    let (app, _tmp) = fresh_app();
    let token = unlock_fresh(app.clone(), "unknown-pw").await;

    let (status, _) = send_json(
        app,
        "GET",
        "/api/credentials/nonexistent-id-xyz",
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn double_delete_404() {
    let (app, _tmp) = fresh_app();
    let token = unlock_fresh(app.clone(), "double-del-pw").await;

    // Create an entry to delete.
    let (status, created) = send_json(
        app.clone(),
        "POST",
        "/api/credentials",
        Some(&token),
        json!({ "label": "doomed", "password": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["id"].as_str().unwrap().to_string();

    // First DELETE: 200.
    let (status, _) = send_json(
        app.clone(),
        "DELETE",
        &format!("/api/credentials/{}", id),
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Second DELETE: 404.
    let (status, _) = send_json(
        app,
        "DELETE",
        &format!("/api/credentials/{}", id),
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tags_round_trip() {
    // Parity with `tests/30_c_tags_persisted.sh`: the Rust build must
    // round-trip tags on create→list. Regression of #8 would fail here.
    let (app, _tmp) = fresh_app();
    let token = unlock_fresh(app.clone(), "tags-pw").await;

    let (status, _created) = send_json(
        app.clone(),
        "POST",
        "/api/credentials",
        Some(&token),
        json!({
            "label": "Tagged Entry",
            "password": "p",
            "tags": ["a", "b"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, list) = send_json(
        app,
        "GET",
        "/api/credentials",
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = list.as_array().expect("list is array");
    assert_eq!(arr.len(), 1);
    let tags = arr[0]["tags"].as_array().expect("tags array");
    let tag_strs: Vec<&str> = tags.iter().filter_map(|v| v.as_str()).collect();
    assert!(tag_strs.contains(&"a"), "missing tag 'a' in {:?}", tag_strs);
    assert!(tag_strs.contains(&"b"), "missing tag 'b' in {:?}", tag_strs);
}

#[tokio::test]
async fn build_info_no_auth() {
    let (app, _tmp) = fresh_app();

    // /api/build/info is the one /api/* endpoint that is explicitly
    // unauthenticated — frontends call it at init to decide whether to
    // show the "OS entropy only" banner.
    let (status, body) = send_json(
        app,
        "GET",
        "/api/build/info",
        None,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["traffic_entropy"], json!(true));
    assert_eq!(body["build"], json!("rust"));
}
