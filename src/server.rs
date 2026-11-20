use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::Value;

use crate::provider::{Provider, Report};

/// Serves `POST /evaluate`, which evaluates the JSON body against every policy
/// and returns a [`Report`], and `GET /healthz`.
pub async fn serve(provider: Provider, addr: SocketAddr) -> std::io::Result<()> {
    let app = router(Arc::new(provider));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await
}

fn router(provider: Arc<Provider>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/evaluate", post(evaluate))
        .with_state(provider)
}

async fn evaluate(
    State(provider): State<Arc<Provider>>,
    Json(object): Json<Value>,
) -> Result<Json<Report>, StatusCode> {
    // CEL evaluation is synchronous: keep it off the async workers.
    tokio::task::spawn_blocking(move || provider.evaluate(&object))
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
