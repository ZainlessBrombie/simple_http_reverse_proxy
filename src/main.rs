use std::borrow::BorrowMut;
use std::convert::Infallible;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::task::Context;

use hyper::header::HeaderValue;
use hyper::server::conn::{AddrIncoming, Http};
use hyper::server::Builder;
use hyper::service::{make_service_fn, service_fn, Service};
use hyper::{Body, Client, Request, Response};
use hyper_tls::native_tls::{TlsAcceptor, TlsAcceptorBuilder};
use hyper_tls::HttpsConnector;
use openssl::error::ErrorStack;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};
use tokio::macros::support::Poll;
use tokio_proto::TcpServer;
use tokio_tls::TlsStream;

mod tls_redirector;

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

fn ssl_acceptor(pk_file: &str, chain_file: &str) -> Result<SslAcceptor, ErrorStack> {
    let mut ssl = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    ssl.set_private_key_file(pk_file, openssl::ssl::SslFiletype::PEM)?;
    ssl.set_certificate_chain_file(chain_file)?;
    ssl.check_private_key()?;
    ssl.set_verify_callback(openssl::ssl::SslVerifyMode::NONE, |_, _| {
        return true;
    });
    return Ok(ssl.build());
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

    let basic_auth = get_env_var("BASIC_AUTH");

    let port_var = get_env_var("PROXY_PORT");

    let private_key_location = get_env_var("SSL_PRIVATE_FILE");
    let cert_location = get_env_var("SSL_SERVER_CERT");

    let ssl_a;
    if private_key_location != None || cert_location != None {
        if private_key_location == None || cert_location == None {
            println!("Either both of SSL_PRIVATE_FILE and SSL_SERVER_CERT need to be specified or neither.");
            return;
        }
        let ssl_result = ssl_acceptor(
            private_key_location.expect("pk var not found").as_str(),
            cert_location.expect("Cert var not found").as_str(),
        );
        ssl_a = match ssl_result {
            Ok(acceptor) => Some(acceptor),
            Err(ssl_err) => {
                println!("openssl reported the following errors:");
                for err in ssl_err.errors() {
                    println!("{}", err);
                }
                println!("exiting.");
                return;
            }
        };
    } else {
        ssl_a = None;
        println!("Not using https. Set SSL_PRIVATE_FILE and SSL_SERVER_CERT to use https.");
    }

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

    let addr = SocketAddr::from((
        [0, 0, 0, 0],
        match port_var {
            Some(p) => match p.as_str().parse() {
                Ok(n) => {
                    println!("Using port {}", n);
                    n
                }
                Err(_) => {
                    println!("Invalid port specified: {}", p);
                    3000
                }
            },
            None => {
                println!("PROXY_PORT not set, defaulting to 3000");
                3000
            }
        },
    ));

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

    match ssl_a {
        Some(ssl) => {
            match tls_redirector::listen_tls(addr, ssl) {
                Ok(tcp) => {
                    let hyper_server_builder =
                        hyper::server::Server::from_tcp(tcp).expect("Could not bind server to tcp");
                    let hyper_server = hyper_server_builder.serve(make_svc);
                    println!("Proxy is running in https mode");

                    if let Err(e) = hyper_server.await {
                        eprintln!("server error: {}", e);
                    }
                }
                Err(e) => {
                    println!("Could not listen: {}", e);
                    return;
                }
            };
        }
        None => {
            let hyper_server = match hyper::server::Server::try_bind(&addr) {
                Ok(r) => r,
                Err(e) => {
                    println!("Could not listen: {}", e);
                    return;
                }
            }
            .serve(make_svc);
            println!("Proxy is running");

            if let Err(e) = hyper_server.await {
                eprintln!("server error: {}", e);
            }
        }
    }
}

fn get_env_var(key: &str) -> Option<String> {
    return match std::env::var_os(key) {
        Some(s) => match s.into_string() {
            Ok(s) => Some(s),
            Err(_) => {
                println!("Invalid {} variable", key);
                None
            }
        },
        None => None,
    };
}
