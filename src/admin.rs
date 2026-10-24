//! Admin HTTP: `/metrics`, `/healthz`, `/readyz` and `/pools`.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::app::App;

pub async fn serve(app: Arc<App>, listener: TcpListener) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => {
                tracing::warn!(%error, "admin accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let app = app.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let app = app.clone();
                async move { Ok::<_, Infallible>(route(&app, &request)) }
            });
            if let Err(error) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(%error, "admin connection failed");
            }
        });
    }
}

fn respond(
    status: StatusCode,
    content_type: &str,
    body: impl Into<Bytes>,
) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    if let Ok(value) = content_type.parse() {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    response
}

fn route(app: &App, request: &Request<Incoming>) -> Response<Full<Bytes>> {
    if request.method() != Method::GET {
        return respond(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain",
            "method not allowed\n",
        );
    }
    match request.uri().path() {
        "/metrics" => {
            let mut body = String::new();
            match prometheus_client::encoding::text::encode(&mut body, &app.registry) {
                Ok(()) => respond(
                    StatusCode::OK,
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                    body,
                ),
                Err(_) => respond(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "text/plain",
                    "cannot encode metrics\n",
                ),
            }
        }
        "/healthz" => respond(StatusCode::OK, "text/plain", "ok\n"),
        "/readyz" if app.draining() => {
            respond(StatusCode::SERVICE_UNAVAILABLE, "text/plain", "draining\n")
        }
        "/readyz" => respond(StatusCode::OK, "text/plain", "ready\n"),
        "/pools" => {
            let pools: Vec<serde_json::Value> = app
                .pools
                .list()
                .iter()
                .map(|pool| {
                    let key = pool.key();
                    let stats = pool.stats();
                    serde_json::json!({
                        "user": key.user,
                        "database": key.database,
                        "options": key.options,
                        "clients": stats.clients,
                        "clients_active": stats.clients_active,
                        "clients_waiting": stats.clients_waiting,
                        "servers_active": stats.servers_active,
                        "servers_idle": stats.servers_idle,
                    })
                })
                .collect();
            let body = serde_json::to_vec_pretty(&pools).unwrap_or_default();
            respond(StatusCode::OK, "application/json", body)
        }
        _ => respond(StatusCode::NOT_FOUND, "text/plain", "not found\n"),
    }
}
