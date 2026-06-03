//! Shared POST transport for the operator admin plane and the reference
//! client: dial a mint or auth endpoint over a Unix-domain socket
//! (`unix:<path>`) or TCP (`http(s)://host`). The `unix:` prefix selects
//! UDS; anything else is taken as a TCP base URL. `reqwest` has no UDS
//! support, so the UDS leg drops to `hyper` + `hyperlocal`'s
//! `UnixConnector`.
//!
//! Callers supply every header (including `content-type`); nothing is
//! injected here. Errors collapse to a single string — there is nothing
//! a caller branches on beyond the HTTP status it gets back.

enum Target<'a> {
    Tcp(&'a str),
    Uds(&'a str),
}

fn parse_target(base: &str) -> Target<'_> {
    match base.strip_prefix("unix:") {
        Some(path) => Target::Uds(path),
        None => Target::Tcp(base),
    }
}

/// POST `body` to `<base><endpoint>` with `headers`, returning
/// `(status, response_text)`. `base` is `unix:<socket>` or
/// `http(s)://host`; `endpoint` is the request path (e.g. `/v1/login`).
pub async fn post(
    base: &str,
    endpoint: &str,
    headers: &[(&str, String)],
    body: String,
) -> Result<(u16, String), String> {
    match parse_target(base) {
        Target::Tcp(base) => {
            let mut req = reqwest::Client::new().post(format!("{base}{endpoint}"));
            for (k, v) in headers {
                req = req.header(*k, v);
            }
            let resp = req.body(body).send().await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let text = resp.text().await.map_err(|e| e.to_string())?;
            Ok((status, text))
        }
        Target::Uds(socket) => {
            use http_body_util::{BodyExt, Full};
            use hyper_util::client::legacy::Client;
            use hyper_util::rt::TokioExecutor;

            let client: Client<_, Full<bytes::Bytes>> =
                Client::builder(TokioExecutor::new()).build(hyperlocal::UnixConnector);
            let uri: hyper::Uri = hyperlocal::Uri::new(socket, endpoint).into();
            let mut builder = hyper::Request::builder()
                .method(hyper::Method::POST)
                .uri(uri);
            for (k, v) in headers {
                builder = builder.header(*k, v);
            }
            let req = builder
                .body(Full::new(bytes::Bytes::from(body)))
                .map_err(|e| e.to_string())?;
            let resp = client.request(req).await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let bytes = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_splits_on_unix_prefix() {
        assert!(matches!(
            parse_target("unix:/tmp/x.sock"),
            Target::Uds("/tmp/x.sock")
        ));
        assert!(matches!(
            parse_target("unix:rel/x.sock"),
            Target::Uds("rel/x.sock")
        ));
        assert!(matches!(
            parse_target("http://127.0.0.1:8085"),
            Target::Tcp("http://127.0.0.1:8085")
        ));
    }
}
