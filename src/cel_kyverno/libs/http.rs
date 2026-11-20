use std::fmt;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use cel::common::types::{DYN_TYPE, Kind, MAP_TYPE, STRING_TYPE, Type};
use cel::common::value::CowVal;
use cel::objects::Key;
use cel::{DeclarationError, Env, ExecutionError, Library, Value};
use kube_cel::cel;
use ureq::tls::{PemItem, RootCerts, TlsConfig};

use super::common::{
    json_to_value, opaque_val, receiver, string_arg, to_cow, to_go_json, value_arg, value_to_json,
};

pub static HTTP_TYPE: Type = Type::simple_type(Kind::Opaque, "http.Context");

/// How long a request may take, connecting and reading the body included.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Create an instance of the Http type that implements Val, stored in a lazy lock. With
/// certs from the OS as the trusted base.
pub static HTTP: LazyLock<Http> = LazyLock::new(|| {
    Http::new(
        TlsConfig::builder()
            .root_certs(RootCerts::PlatformVerifier)
            .build(),
    )
});

/// The value bound to `http`: the receiver of `Get`, `Post` and `Client`. It
/// holds the agent requests are sent with; `Client(caBundle)` derives one that
/// trusts that bundle.
#[derive(Clone)]
pub struct Http {
    agent: ureq::Agent,
}

impl fmt::Debug for Http {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("http")
    }
}

opaque_val!(Http, HTTP_TYPE);

impl Http {
    fn new(tls: TlsConfig) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            // Kyverno returns the status code with the body instead of failing.
            .http_status_as_error(false)
            .tls_config(tls)
            .build()
            .into();
        Http { agent }
    }
}

/// Kyverno's `http` CEL library: blocking requests through methods on the
/// `http` variable:
///
/// - `http.Get(url)`, `http.Get(url, headers)`
/// - `http.Post(url, data)`, `http.Post(url, data, headers)`: `data` is sent as JSON
/// - `http.Client(caBundle)`: a client trusting only the PEM CA bundle given
///
/// A response's JSON body is returned with `statusCode` added. A body that
/// isn't a JSON object comes back as `{"body": ..., "statusCode": ...}`, with
/// `body` null if it isn't JSON at all.
pub struct HttpLib;

impl HttpLib {
    pub fn new() -> Self {
        HttpLib
    }
}

impl Library for HttpLib {
    fn name(&self) -> Option<&str> {
        Some("kyverno.http")
    }

    fn register(&self, env: &mut Env) -> Result<(), DeclarationError> {
        env.add_type(HTTP_TYPE.to_owned())?;
        let target = || HTTP_TYPE.to_owned();
        env.add_member_overload(
            "Get",
            "http_get_string",
            target(),
            vec![STRING_TYPE],
            http_get,
        )?;
        env.add_member_overload(
            "Get",
            "http_get_string_headers",
            target(),
            vec![STRING_TYPE, MAP_TYPE],
            http_get,
        )?;
        env.add_member_overload(
            "Post",
            "http_post_string_any",
            target(),
            vec![STRING_TYPE, DYN_TYPE],
            http_post,
        )?;
        env.add_member_overload(
            "Post",
            "http_post_string_any_headers",
            target(),
            vec![STRING_TYPE, DYN_TYPE, MAP_TYPE],
            http_post,
        )?;
        env.add_member_overload(
            "Client",
            "http_client_string",
            target(),
            vec![STRING_TYPE],
            http_client,
        )?;
        Ok(())
    }
}

/// `http.Get(url[, headers])`: args are the receiver, the URL and the optional headers.
// cel's `Function` type takes the arguments by value.
#[allow(clippy::needless_pass_by_value)]
fn http_get<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    let http = receiver::<Http>(&args)?;
    let mut request = http.agent.get(string_arg(&args, 1)?);
    if args.len() == 3 {
        for (name, value) in headers(&args, 2)? {
            request = request.header(name, value);
        }
    }
    respond("http.Get", request.call())
}

/// `http.Post(url, data[, headers])`: `data` is sent JSON-encoded.
// cel's `Function` type takes the arguments by value.
#[allow(clippy::needless_pass_by_value)]
fn http_post<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    let http = receiver::<Http>(&args)?;
    // Create the request type from the endpoint address parsed with string_arg
    let mut request = http.agent.post(string_arg(&args, 1)?);
    if args.len() == 4 {
        for (name, value) in headers(&args, 3)? {
            request = request.header(name, value);
        }
    }
    // As Go's json.Encoder writes it: with a trailing newline.
    let body = format!("{}\n", to_go_json(&value_to_json(&value_arg(&args, 2)?)?));
    respond("http.Post", request.send(body))
}

/// Create a HTTP client with a custom trust bundle.
#[allow(clippy::needless_pass_by_value)]
fn http_client<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    let http = receiver::<Http>(&args)?;
    let bundle = string_arg(&args, 1)?;
    if bundle.is_empty() {
        return Ok(CowVal::Owned(Box::new(http.clone())));
    }
    // Only certificates that parse count, as with Go's AppendCertsFromPEM.
    let certs: Vec<_> = ureq::tls::parse_pem(bundle.as_bytes())
        .filter_map(|item| match item {
            Ok(PemItem::Certificate(cert))
                if x509_parser::parse_x509_certificate(cert.der()).is_ok() =>
            {
                Some(cert)
            }
            _ => None,
        })
        .collect();
    if certs.is_empty() {
        return Err(ExecutionError::function_error(
            "http.Client",
            "failed to parse PEM CA bundle",
        ));
    }
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::Specific(Arc::new(certs)))
        .build();
    Ok(CowVal::Owned(Box::new(Http::new(tls))))
}

/// The headers map at `index`, whose keys and values must be strings.
fn headers(args: &[CowVal<'_, '_>], index: usize) -> Result<Vec<(String, String)>, ExecutionError> {
    let Value::Map(map) = value_arg(args, index)? else {
        return Err(ExecutionError::function_error(
            "http",
            "headers must be a map",
        ));
    };
    map.map
        .iter()
        .map(|(key, value)| match (key, value) {
            (Key::String(k), Value::String(v)) => Ok((k.to_string(), v.to_string())),
            _ => Err(ExecutionError::function_error(
                "http",
                "headers must map strings to strings",
            )),
        })
        .collect()
}

/// We must eventually return a `CowVal`, but the return type of request.send is a
/// `ureq::http::Response`. Transform that into `CowVal`.
fn respond<'b, 'v>(
    function: &str,
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<CowVal<'b, 'v>, ExecutionError> {
    let fail =
        |e: ureq::Error| ExecutionError::function_error(function, format!("request failed: {e}"));
    let mut response = response.map_err(fail)?;
    let status = serde_json::Value::from(response.status().as_u16());
    // Like Go's json.Decoder: the first JSON value, or null if the body can't
    // be read or holds none.
    let bytes = response.body_mut().read_to_vec().unwrap_or_default();
    let body = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<serde_json::Value>()
        .next()
        .and_then(Result::ok)
        .unwrap_or_default();
    let result = match body {
        serde_json::Value::Object(mut fields) => {
            fields.insert("statusCode".to_owned(), status);
            serde_json::Value::Object(fields)
        }
        body => serde_json::json!({ "body": body, "statusCode": status }),
    };
    to_cow(json_to_value(&result))
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    use crate::cel_kyverno::compiler::compile::eval;
    use kube_cel::cel::Value;

    /// Serves `responses` in order, one per connection, and returns the base URL.
    fn serve(responses: Vec<&'static str>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for (body, stream) in responses.into_iter().zip(listener.incoming()) {
                let mut stream = stream.unwrap();
                let mut buf = [0; 4096];
                let _ = stream.read(&mut buf);
                let reply = format!(
                    "HTTP/1.1 201 Created\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(reply.as_bytes()).unwrap();
            }
        });
        url
    }

    #[test]
    fn returns_the_body_with_the_status_code() {
        let url = serve(vec![r#"{"ok": true}"#, "[1, 2]", "not json"]);
        for check in [
            format!("http.Get('{url}', {{'X-Test': '1'}}) == {{'ok': true, 'statusCode': 201}}"),
            format!("http.Post('{url}', {{'a': 1}}) == {{'body': [1, 2], 'statusCode': 201}}"),
            format!("http.Get('{url}') == {{'body': null, 'statusCode': 201}}"),
        ] {
            assert_eq!(eval(&check), Ok(Value::Bool(true)), "{check}");
        }
    }

    #[test]
    fn rejects_an_invalid_ca_bundle() {
        assert!(eval("http.Client('not pem')").is_err());
        assert_eq!(
            eval("type(http.Client('')) == type(http)"),
            Ok(Value::Bool(true))
        );
    }
}
