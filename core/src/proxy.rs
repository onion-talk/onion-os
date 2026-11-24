//! Authenticated HTTP & WebSocket (`websockify`) Reverse Proxy for Isolated Containers:
//! - `/ot` & `/ot/{*path}` -> `ONIONTALK_INTERNAL_URL` (`http://10.250.0.11:8420`)
//! - `/sandbox` & `/sandbox/{*path}` -> `SANDBOX_BROWSER_URL` (`http://10.250.0.20:6901`)
//! - `POST /api/sandbox/reset` -> `SANDBOX_RESET_URL` (`http://10.250.0.20:6902/reset`)

use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::ws::{Message as AxumWsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::FromRequestParts;
use axum::http::header::{HeaderName, HeaderValue, COOKIE, UPGRADE};
use axum::http::{Request, Response, StatusCode};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as UpstreamWsMessage;

const MAX_PROXY_BODY_BYTES: usize = 28 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxResetResponse {
    pub ok: bool,
    pub reset: bool,
    pub status: u16,
    pub message: String,
}

pub async fn forward_reverse_proxy(
    http_client: &reqwest::Client,
    upstream_base: &str,
    subpath: &str,
    mount_prefix: Option<&str>,
    req: Request<Body>,
) -> Response<Body> {
    let query_opt = req.uri().query().map(str::to_owned);
    let target_http_url = build_upstream_url(upstream_base, subpath, query_opt.as_deref());

    if is_websocket_upgrade(&req) {
        return handle_ws_proxy(target_http_url, req).await;
    }

    handle_http_proxy(http_client, &target_http_url, mount_prefix, req).await
}

fn build_upstream_url(base: &str, subpath: &str, query: Option<&str>) -> String {
    let trimmed_base = base.trim_end_matches('/');
    let trimmed_sub = subpath.trim_start_matches('/');
    let mut out = if trimmed_sub.is_empty() {
        format!("{trimmed_base}/")
    } else {
        format!("{trimmed_base}/{trimmed_sub}")
    };
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        out.push('?');
        out.push_str(q);
    }
    out
}

fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    req.headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

fn to_ws_scheme(http_url: &str) -> String {
    if let Some(rest) = http_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = http_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("ws://{http_url}")
    }
}

async fn handle_ws_proxy(target_http_url: String, req: Request<Body>) -> Response<Body> {
    let ws_url = to_ws_scheme(&target_http_url);

    let requested_protocols: Vec<String> = req
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| {
                    !s.is_empty()
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                })
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let downstream_cookie = scrub_onionos_cookie(
        req.headers()
            .get(COOKIE)
            .and_then(|v| v.to_str().ok()),
    );

    let (mut parts, _body) = req.into_parts();
    let ws_upgrade = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(up) => up,
        Err(rej) => return rej.into_response(),
    };

    let ws_upgrade = if requested_protocols.is_empty() {
        ws_upgrade
    } else {
        ws_upgrade.protocols(requested_protocols.clone())
    };

    ws_upgrade
        .on_upgrade(move |client_ws| async move {
            bridge_websockets(client_ws, ws_url, requested_protocols, downstream_cookie).await;
        })
        .into_response()
}

async fn bridge_websockets(
    client_ws: WebSocket,
    ws_url: String,
    protocols: Vec<String>,
    downstream_cookie: Option<String>,
) {
    let Ok(mut upstream_req) = ws_url.as_str().into_client_request() else {
        return;
    };

    if !protocols.is_empty() {
        let joined = protocols.join(", ");
        if let Ok(hv) = HeaderValue::from_str(&joined) {
            upstream_req
                .headers_mut()
                .insert("sec-websocket-protocol", hv);
        }
    }
    if let Some(c) = downstream_cookie {
        if let Ok(hv) = HeaderValue::from_str(&c) {
            upstream_req.headers_mut().insert(COOKIE, hv);
        }
    }

    let connect_res =
        tokio::time::timeout(Duration::from_secs(8), tokio_tungstenite::connect_async(upstream_req))
            .await;

    let Ok(Ok((upstream_ws, _))) = connect_res else {
        let (mut c_tx, _) = client_ws.split();
        let _ = c_tx.send(AxumWsMessage::Close(None)).await;
        return;
    };

    let (mut c_tx, mut c_rx) = client_ws.split();
    let (mut u_tx, mut u_rx) = upstream_ws.split();

    let client_to_upstream = async {
        while let Some(Ok(msg)) = c_rx.next().await {
            let mapped = match msg {
                AxumWsMessage::Text(t) => UpstreamWsMessage::Text(t.as_str().into()),
                AxumWsMessage::Binary(b) => UpstreamWsMessage::Binary(Vec::from(b.as_ref()).into()),
                AxumWsMessage::Ping(p) => UpstreamWsMessage::Ping(Vec::from(p.as_ref()).into()),
                AxumWsMessage::Pong(p) => UpstreamWsMessage::Pong(Vec::from(p.as_ref()).into()),
                AxumWsMessage::Close(_) => {
                    let _ = u_tx.send(UpstreamWsMessage::Close(None)).await;
                    break;
                }
            };
            if u_tx.send(mapped).await.is_err() {
                break;
            }
        }
    };

    let upstream_to_client = async {
        while let Some(Ok(msg)) = u_rx.next().await {
            let mapped = match msg {
                UpstreamWsMessage::Text(t) => AxumWsMessage::Text(t.as_str().into()),
                UpstreamWsMessage::Binary(b) => AxumWsMessage::Binary(Vec::from(b.as_ref()).into()),
                UpstreamWsMessage::Ping(p) => AxumWsMessage::Ping(Vec::from(p.as_ref()).into()),
                UpstreamWsMessage::Pong(p) => AxumWsMessage::Pong(Vec::from(p.as_ref()).into()),
                UpstreamWsMessage::Close(_) => {
                    let _ = c_tx.send(AxumWsMessage::Close(None)).await;
                    break;
                }
                UpstreamWsMessage::Frame(_) => continue,
            };
            if c_tx.send(mapped).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = client_to_upstream => {},
        _ = upstream_to_client => {},
    }
}

async fn handle_http_proxy(
    http_client: &reqwest::Client,
    target_url: &str,
    mount_prefix: Option<&str>,
    req: Request<Body>,
) -> Response<Body> {
    let method = match reqwest::Method::from_bytes(req.method().as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => return bad_gateway_response("Unsupported HTTP method"),
    };

    let upstream_port = reqwest::Url::parse(target_url)
        .ok()
        .and_then(|u| u.port_or_known_default())
        .unwrap_or(80);
    let loopback_host = format!("127.0.0.1:{upstream_port}");
    let loopback_origin = format!("http://127.0.0.1:{upstream_port}");

    let req_headers = req.headers().clone();
    let body_bytes = match to_bytes(req.into_body(), MAX_PROXY_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"error":"Proxy payload too large"}"#))
                .unwrap_or_else(|_| Response::new(Body::empty()));
        }
    };

    let mut builder = http_client
        .request(method, target_url)
        .header("host", &loopback_host);

    for (name, val) in &req_headers {
        let key = name.as_str();
        if is_hop_by_hop_header(key) || key.eq_ignore_ascii_case("host") {
            continue;
        }
        if mount_prefix.is_some() && key.eq_ignore_ascii_case("accept-encoding") {
            continue;
        }
        if key.eq_ignore_ascii_case("origin") {
            builder = builder.header("origin", &loopback_origin);
            continue;
        }
        if key.eq_ignore_ascii_case("referer") {
            builder = builder.header("referer", format!("{loopback_origin}/"));
            continue;
        }
        if key.eq_ignore_ascii_case("cookie") {
            if let Some(clean_cookie) = scrub_onionos_cookie(val.to_str().ok()) {
                builder = builder.header("cookie", clean_cookie);
            }
            continue;
        }
        builder = builder.header(key, val.as_bytes());
    }

    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes.to_vec());
    }

    let upstream_resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            return bad_gateway_response(&format!(
                "Isolated container upstream unreachable ({target_url}): {e}"
            ));
        }
    };

    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let upstream_headers = upstream_resp.headers().clone();
    let resp_bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => return bad_gateway_response(&format!("Upstream body read error: {e}")),
    };

    let is_html = upstream_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/html"));

    let (final_bytes, body_rewritten) = if let Some(prefix) = mount_prefix.filter(|_| is_html) {
        if let Ok(html_str) = std::str::from_utf8(&resp_bytes) {
            let rewritten = html_str
                .replace("'/api/", &format!("'{prefix}/api/"))
                .replace("\"/api/", &format!("\"{prefix}/api/"))
                .replace("href=\"/manifest.json\"", &format!("href=\"{prefix}/manifest.json\""));
            (rewritten.into_bytes(), true)
        } else {
            (resp_bytes.to_vec(), false)
        }
    } else {
        (resp_bytes.to_vec(), false)
    };

    let mut resp_builder = Response::builder().status(status);
    for (name, val) in &upstream_headers {
        let key = name.as_str();
        if is_hop_by_hop_header(key)
            || key.eq_ignore_ascii_case("x-frame-options")
            || key.eq_ignore_ascii_case("content-security-policy")
            || (body_rewritten && key.eq_ignore_ascii_case("content-length"))
        {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_bytes(val.as_bytes()),
        ) {
            resp_builder = resp_builder.header(hn, hv);
        }
    }

    resp_builder
        .body(Body::from(final_bytes))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

pub async fn reset_sandbox_profile(
    http_client: &reqwest::Client,
    sandbox_reset_url: &str,
) -> SandboxResetResponse {
    let req = http_client
        .post(sandbox_reset_url)
        .timeout(Duration::from_secs(3));

    match req.send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let ok = resp.status().is_success();
            SandboxResetResponse {
                ok,
                reset: ok,
                status: code,
                message: if ok {
                    "Sandbox browser volatile profile wiped and restarted".into()
                } else {
                    format!("Sandbox control endpoint returned HTTP {code}")
                },
            }
        }
        Err(e) => SandboxResetResponse {
            ok: false,
            reset: false,
            status: 0,
            message: format!("Sandbox control endpoint offline or starting: {e}"),
        },
    }
}

fn scrub_onionos_cookie(raw_cookie: Option<&str>) -> Option<String> {
    let raw = raw_cookie?;
    let kept: Vec<&str> = raw
        .split(';')
        .map(str::trim)
        .filter(|pair| !pair.is_empty() && !pair.starts_with("onionos_sid="))
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join("; "))
    }
}

fn is_hop_by_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailers")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
}

fn bad_gateway_response(detail: &str) -> Response<Body> {
    let body = serde_json::json!({
        "error": "Bad Gateway",
        "detail": detail,
    })
    .to_string();

    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "application/json; charset=utf-8")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
