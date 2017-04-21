extern crate iron_cors2;
extern crate router;
extern crate iron;
extern crate unicase;
extern crate hyper;
extern crate mount;
use iron::Listening;
use self::router::Router;
use iron::prelude::*;
use iron::status;
use self::mount::Mount;
use self::hyper::Client;
use self::hyper::header::Headers;
use std::io::Read;
use iron::headers::{Origin, AccessControlRequestMethod, AccessControlRequestHeaders,
                    AccessControlAllowOrigin, AccessControlAllowHeaders, AccessControlMaxAge,
                    AccessControlAllowMethods};
use iron::method::Method::*;
use iron::middleware::Handler;
use iron_cors2::{CorsMiddleware, AllowedOrigins};
use std::str::FromStr;
use std::collections::HashSet;
use unicase::UniCase;

struct AutoServer {
    listening: Listening,
    port: u16,
}

impl AutoServer {
    pub fn new() -> AutoServer {
        AutoServer::with_cors(CorsMiddleware::new())
    }

    pub fn with_cors(cors: CorsMiddleware) -> AutoServer {
        let get_handler = |_: &mut Request| Ok(Response::with((status::ImATeapot, "")));
        let put_handler = |_: &mut Request| Ok(Response::with((status::BadRequest, "")));

        let mut router = Router::new();
        router.get("", get_handler, "get_a");
        router.put("", put_handler, "put_a");

        let mut chain = Chain::new(router);
        chain.link_around(cors);
        let mut mount = Mount::new();

        mount.mount("/a", chain);
        AutoServer::with_handler(mount)
    }

    pub fn with_handler<H: Handler>(handler: H) -> AutoServer {
        let l = Iron::new(handler).http(format!("localhost:0")).unwrap();
        let p = l.socket.port();
        AutoServer {
            listening: l,
            port: p,
        }
    }
}

impl Drop for AutoServer {
    fn drop(&mut self) {
        // Workaround for https://github.com/hyperium/hyper/issues/338
        self.listening.close().unwrap();
    }
}

#[test]
fn normal_request_possible() {
    let server = AutoServer::new();
    let client = Client::new();
    let res = client.get(&format!("http://127.0.0.1:{}/a", server.port)).send().unwrap();
    assert_eq!(res.status, status::ImATeapot);
}

fn to_string(res: &mut hyper::client::Response) -> String {
    let mut s = String::new();
    res.read_to_string(&mut s).unwrap();
    s
}

#[test]
fn preflight_to_nonexistent_route_fails() {
    let server = AutoServer::new();
    let client = Client::new();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    headers.set(Origin::from_str("http://www.a.com:8080").unwrap());
    let mut res = client.request(Options, &format!("http://127.0.0.1:{}/b", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::NotFound);
    assert_eq!(to_string(&mut res), "");
}

#[test]
fn preflight_without_origin_is_bad_request() {
    let server = AutoServer::new();
    let client = Client::new();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    let mut res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::BadRequest);
    let mut payload = String::new();
    res.read_to_string(&mut payload).unwrap();
    assert_eq!(payload, "Preflight request without Origin header");
}

#[test]
fn preflight_with_allowed_origin_sets_all_headers() {
    let server = AutoServer::new();
    let client = Client::new();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    headers.set(Origin::from_str("http://www.a.com:8080").unwrap());
    let mut res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    let mut payload = String::new();
    res.read_to_string(&mut payload).unwrap();
    assert_eq!(payload, "");
    assert_eq!(res.status, status::NoContent);
    let allow_origin = res.headers.get::<AccessControlAllowOrigin>().unwrap();
    assert_eq!(format!("{}", allow_origin), "http://www.a.com:8080");
    let allow_headers = res.headers.get::<AccessControlAllowHeaders>().unwrap();
    assert_eq!(format!("{}", allow_headers),
               "Content-Type, X-Requested-With");
    let allow_methods = res.headers.get::<AccessControlAllowMethods>().unwrap();
    assert_eq!(format!("{}", allow_methods),
               "OPTIONS, GET, POST, PUT, DELETE, HEAD, TRACE, CONNECT, PATCH");
    let max_age = res.headers.get::<AccessControlMaxAge>().unwrap();
    assert_eq!(max_age.0, 60 * 60u32);
}

#[test]
fn preflight_with_disallowed_origin_is_error() {
    let mut cors = CorsMiddleware::new();
    let origins: HashSet<String> = vec!["http://www.a.com".to_owned()].into_iter().collect();
    cors.allowed_origins = AllowedOrigins::Specific(origins);
    let server = AutoServer::with_cors(cors);
    let client = Client::new();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    headers.set(Origin::from_str("http://www.a.com:8080").unwrap());
    let mut res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::BadRequest);
    assert_eq!(to_string(&mut res),
               "Preflight request requesting disallowed origin 'http://www.a.com:8080'");
}

#[test]
fn preflight_with_disallowed_header_is_error() {
    let mut cors = CorsMiddleware::new();
    cors.allowed_headers = vec![];
    let server = AutoServer::with_cors(cors);
    let client = Client::new();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    let head_vec = vec![UniCase("DoesNotExist".to_owned())];
    headers.set(AccessControlRequestHeaders(head_vec));
    headers.set(Origin::from_str("http://www.a.com:8080").unwrap());
    let mut res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::BadRequest);
    assert_eq!(to_string(&mut res),
               "Preflight request requesting disallowed header(s) DoesNotExist");
}

#[test]
fn options_without_method_is_normal_request() {
    // A requestion with options and origin but without
    // method is considers non-preflight
    let server = AutoServer::new();
    let client = Client::new();
    let mut headers = Headers::new();
    headers.set(Origin::from_str("http://a.com").unwrap());
    let mut res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::Ok);
    let mut payload = String::new();
    res.read_to_string(&mut payload).unwrap();
    assert_eq!(payload, "");
}

#[test]
fn preflight_with_disallowed_method_is_error() {
    // A requestion with options and origin but without
    // method is considers non-preflight
    let cm = CorsMiddleware::new();
    let cm2 = CorsMiddleware { allowed_methods: vec![], ..cm };
    let server = AutoServer::with_cors(cm2);
    let client = Client::new();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Patch));
    headers.set(Origin::from_str("http://a.com").unwrap());
    let mut res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::BadRequest);
    let mut payload = String::new();
    res.read_to_string(&mut payload).unwrap();
    assert_eq!(payload,
               "Preflight request requesting disallowed method PATCH");
}

#[test]
fn normal_request_allows_origin() {
    let server = AutoServer::new();
    let client = Client::new();
    let mut headers = Headers::new();
    headers.set(Origin::from_str("http://www.a.com:8080").unwrap());
    let res = client.get(&format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::ImATeapot);
    let allow_origin = res.headers.get::<AccessControlAllowOrigin>().unwrap();
    assert_eq!(format!("{}", allow_origin), "http://www.a.com:8080");
    assert!(res.headers.get::<AccessControlAllowHeaders>().is_none());
    assert!(res.headers.get::<AccessControlAllowMethods>().is_none());
    assert!(res.headers.get::<AccessControlMaxAge>().is_none());
}

#[test]
fn normal_request_without_origin_is_passthrough() {
    let server = AutoServer::new();
    let client = Client::new();
    let res = client.get(&format!("http://127.0.0.1:{}/a", server.port)).send().unwrap();
    assert_eq!(res.status, status::ImATeapot);
    assert!(res.headers.get::<AccessControlAllowOrigin>().is_none());
    assert!(res.headers.get::<AccessControlAllowHeaders>().is_none());
    assert!(res.headers.get::<AccessControlAllowMethods>().is_none());
    assert!(res.headers.get::<AccessControlMaxAge>().is_none());
}
