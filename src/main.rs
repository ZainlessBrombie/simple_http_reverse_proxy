use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use hyper::header::HeaderValue;
use hyper::service::{make_service_fn, service_fn, Service};
use hyper::{Body, Client, Request, Response};
use hyper_tls::HttpsConnector;
use std::borrow::BorrowMut;
use std::task::Context;
use tokio::macros::support::Poll;

//#[derive(Clone)]
struct Server {
    target: String,
    basic_auth: Option<String>,
}

impl Server {
    async fn do_proxy(self: Arc<Server>, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        return match self.do_proxy_internal(req).await {
            Ok(r) => Ok(r),
            Err(e) => {
                println!("Proxy error: {}", e);
                Ok(Response::builder()
                    .status(503)
                    .body(Body::from("Gateway Error"))
                    .expect("N/A"))
            }
        };
    }

    async fn do_proxy_internal(
        self: Arc<Server>,
        req: Request<Body>,
    ) -> Result<Response<Body>, String> {
        let authed: bool;
        if self.basic_auth != None {
            authed = match &req.headers().get("Authorization") {
                None => false,
                Some(basic_header) => self.is_basic_authed(basic_header),
            };
        } else {
            authed = true;
        }

        if !authed {
            return Ok(hyper::http::response::Builder::new()
                .status(401)
                .header("www-authenticate", "Basic realm=\"Proxy\"")
                .header("Access-Control-Allow-Origin", "*")
                .body(hyper::body::Body::empty())
                .expect(""));
        }

        let https = HttpsConnector::new();
        let client = Client::builder().build(https);
        let uri = req.uri();
        let mut uri_builder =
            hyper::http::Uri::builder().scheme(if self.target.starts_with("https://") {
                "https"
            } else {
                "http"
            });
        let mut authority = self.target.as_str();
        if authority.starts_with("https://") {
            authority = &authority["https://".len()..];
        } else if authority.starts_with("http://") {
            authority = &authority["http://".len()..];
        }
        uri_builder = uri_builder.authority(authority);
        uri_builder = uri_builder.path_and_query(match uri.path_and_query() {
            Some(pq) => pq.as_str(),
            None => uri.path(),
        });

        let proxy_uri = match uri_builder.build() {
            Ok(u) => u,
            Err(e) => return Err(format!("Error occurred: {}", e)),
        };
        let mut proxy_request_builder = Request::builder().method(req.method()).uri(proxy_uri);
        for (k, v) in req.headers() {
            if k.as_str() == "authorization" || k.as_str() == "host" {
                continue;
            }
            if k.as_str() == "x-proxy-authorization" {
                proxy_request_builder = proxy_request_builder.header("Authorization", v);
            } else {
                proxy_request_builder = proxy_request_builder.header(k, v);
            }
        }

        proxy_request_builder = proxy_request_builder.header("Host", authority);

        let proxy_req = match proxy_request_builder.body(req.into_body()) {
            Ok(r) => r,
            Err(e) => return Err(format!("Could not build request: {}", e)),
        };
        let res = client.request(proxy_req).await;
        return match res {
            Ok(r) => Ok(r),
            Err(e) => Err(format!("Err: {}", e)),
        };
    }

    fn is_basic_authed(&self, header_value: &HeaderValue) -> bool {
        let required_auth = match &self.basic_auth {
            None => return true,
            Some(s) => s,
        };
        let mut header_value_copy = match header_value.to_str() {
            Err(_) => return false,
            Ok(v) => v,
        };
        if header_value_copy.starts_with("Basic ") {
            header_value_copy = &header_value_copy["Basic ".len()..];
        }

        let received_header_bytes = match base64::decode(header_value_copy) {
            Err(_) => return false,
            Ok(decoded) => decoded,
        };

        let received_header = String::from_utf8_lossy(received_header_bytes.as_slice());

        return required_auth == &(*received_header).to_string();
    }
}

#[tokio::main]
async fn main() {
    let target = match std::env::var_os("PROXY_TARGET") {
        Some(s) => s,
        None => {
            println!("Missing variable PROXY_TARGET");
            return;
        }
    };

    let basic_auth = match std::env::var_os("BASIC_AUTH") {
        Some(s) => match s.into_string() {
            Ok(s) => Some(s),
            Err(_) => {
                println!("Invalid BASIC_AUTH variable");
                None
            }
        },
        None => None,
    };

    match basic_auth {
        Some(_) => {
            println!("Using basic auth");
        }
        None => println!(
            "Not using basic auth, set BASIC_AUTH env variable to <user>:<password> if needed"
        ),
    }

    let server_state = Arc::new(Server {
        target: match target.into_string() {
            Ok(s) => s.clone(),
            Err(_) => {
                println!("PROXY_TARGET variable contains invalid string");
                return;
            }
        },
        basic_auth,
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    let make_svc = make_service_fn(move |_conn| {
        let c = server_state.clone();

        return async move {
            return Ok::<_, Infallible>(hyper::service::service_fn(move |req: Request<Body>| {
                let c = c.clone();
                return async move {
                    return Ok::<_, Infallible>(
                        c.do_proxy(req).await.expect("This method is infallible"),
                        //Response::new(Body::empty()),
                    );
                };
            }));
        };
        // Ok::<_, Infallible>(service_fn(Server::hello))
    });

    let hyper_server = hyper::server::Server::bind(&addr).serve(make_svc);

    println!("Proxy is running");

    if let Err(e) = hyper_server.await {
        eprintln!("server error: {}", e);
    }
}
