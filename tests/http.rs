extern crate corsware;
extern crate router;
extern crate iron;
extern crate unicase;
#[macro_use]
extern crate hyper;
extern crate mount;
use self::router::Router;
use iron::prelude::*;
use iron::status;
use self::hyper::Client;
use self::hyper::header::Headers;
use std::io::Read;
use iron::headers::Origin as OriginHeader;
use iron::headers::{AccessControlRequestMethod, AccessControlRequestHeaders,
                    AccessControlAllowOrigin, AccessControlAllowHeaders, AccessControlAllowMethods,
                    AccessControlAllowCredentials, AccessControlExposeHeaders, AccessControlMaxAge,
                    Vary};
use iron::method::Method::*;
use corsware::{CorsMiddleware, AllowedOrigins, Origin};
use std::str::FromStr;
use std::collections::HashSet;
use unicase::UniCase;



mod autoserver;
use autoserver::{AutoServer, cors};

fn client() -> Client {
    Client::with_pool_config(hyper::client::pool::Config{
        max_idle: 1
    })
}

#[test]
fn normal_request_possible() {
    let server = AutoServer::new();
    let client = client();
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
    let client = client();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    headers.set(OriginHeader::from_str("http://www.a.com:8080").unwrap());
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
    let client = client();
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
    let client = client();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    headers.set(OriginHeader::from_str("http://www.a.com:8080").unwrap());
    let mut res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    let mut payload = String::new();
    res.read_to_string(&mut payload).unwrap();
    assert_eq!(payload, "");
    assert_eq!(res.status, status::NoContent);
    let allow_origin = res.headers.get::<AccessControlAllowOrigin>().unwrap();
    assert_eq!(allow_origin.to_string(), "http://www.a.com:8080");
    let allow_headers = res.headers.get::<AccessControlAllowHeaders>().unwrap();
    assert_eq!(allow_headers.to_string(),
               "Authorization, Content-Type, X-Requested-With");
    let allow_methods = res.headers.get::<AccessControlAllowMethods>().unwrap();
    assert_eq!(allow_methods.to_string(),
               "OPTIONS, GET, POST, PUT, DELETE, HEAD, TRACE, CONNECT, PATCH");
    let max_age = res.headers.get::<AccessControlMaxAge>().unwrap();
    assert_eq!(max_age.0, 60 * 60u32);
    let vary = res.headers.get::<Vary>().unwrap();
    assert_eq!(vary.to_string(),
               "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
}

#[test]
fn disallowing_credentials_unsets_allow_credentials_header_in_response() {
    let c = CorsMiddleware { allow_credentials: false, ..cors() };
    let server = AutoServer::with_cors(c);
    let client = client();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    headers.set(OriginHeader::from_str("http://www.a.com:8080").unwrap());
    let res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    let allow_origin = res.headers.get::<AccessControlAllowCredentials>();
    assert_eq!(allow_origin, None);
}

#[test]
fn allowing_credentials_sets_allow_credentials_header_in_response() {
    let c = CorsMiddleware { allow_credentials: true, ..cors() };
    let server = AutoServer::with_cors(c);
    let client = client();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    headers.set(OriginHeader::from_str("http://www.a.com:8080").unwrap());
    let res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    let allow_origin = res.headers.get::<AccessControlAllowCredentials>();
    assert!(allow_origin.is_some());
}

#[test]
fn preflight_with_disallowed_origin_is_error() {
    let mut cors = cors();
    let origins: HashSet<Origin> =
        vec![Origin::parse("http://www.a.com").unwrap()].into_iter().collect();
    cors.allowed_origins = AllowedOrigins::Specific(origins);
    let server = AutoServer::with_cors(cors);
    let client = client();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    headers.set(OriginHeader::from_str("http://www.a.com:8080").unwrap());
    let mut res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::BadRequest);
    assert_eq!(to_string(&mut res),
               "Preflight request requesting disallowed origin 'http://www.a.com:8080'");
}

header! { (NullableOrigin, "Origin") => [String] }

#[test]
fn preflight_with_null_origin_is_not_allowed_by_default() {
    // According to https://tools.ietf.org/id/draft-abarth-origin-03.html#rfc.section.6
    // you shouldn't be able to whitelist a "null" Origin.
    //
    // The "null" origin indicates that the Server has hid the Origin since it couldn't
    // property determine it and is set on data: and file: -Url and such.
    //
    // There have been real vulns due to this:
    // https://security.stackexchange.com/questions/145326/
    // how-did-the-facebook-originull-vulnerablity-of-access-control-allow-origin-null
    //
    // Seems as if Iron refuses to parse the Origin header if its null as is:
    // http://azerupi.github.io/mdBook/iron/headers/struct.Origin.html
    let server = AutoServer::new();
    let client = client();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    headers.set(NullableOrigin("null".to_owned()));
    let mut res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::BadRequest);
    assert_eq!(to_string(&mut res),
               "Preflight request requesting disallowed origin 'null'");
}

#[test]
fn preflight_with_null_origin_can_be_allowed() {
    let cm = cors();
    let cors = CorsMiddleware {
        allowed_origins: AllowedOrigins::Any { allow_null: true },
        prefer_wildcard: true,
        ..cm
    };
    let server = AutoServer::with_cors(cors);
    let client = client();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    headers.set(NullableOrigin("null".to_owned()));
    let res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::NoContent);
}

#[test]
fn preflight_with_null_origin_can_be_specifically_allowed() {
    let origins: HashSet<Origin> = vec![Origin::Null].into_iter().collect();
    let cm = cors();
    let cors = CorsMiddleware { allowed_origins: AllowedOrigins::Specific(origins), ..cm };
    let server = AutoServer::with_cors(cors);
    let client = client();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    headers.set(NullableOrigin("null".to_owned()));
    let res = client.request(Options, &format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::NoContent);
}

#[test]
fn preflight_with_disallowed_header_is_error() {
    let mut cors = cors();
    cors.allowed_headers = vec![];
    let server = AutoServer::with_cors(cors);
    let client = client();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Get));
    let head_vec = vec![UniCase("DoesNotExist".to_owned())];
    headers.set(AccessControlRequestHeaders(head_vec));
    headers.set(OriginHeader::from_str("http://www.a.com:8080").unwrap());
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
    // A request with options and OriginHeader but without
    // method is considered non-preflight
    let server = AutoServer::new();
    let client = client();
    let mut headers = Headers::new();
    headers.set(OriginHeader::from_str("http://a.com").unwrap());
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
    let cm = cors();
    let cm2 = CorsMiddleware { allowed_methods: vec![], ..cm };
    let server = AutoServer::with_cors(cm2);
    let client = client();
    let mut headers = Headers::new();
    headers.set(AccessControlRequestMethod(Patch));
    headers.set(OriginHeader::from_str("http://a.com").unwrap());
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
fn normal_request_sets_right_headers() {
    let cm = cors();
    let server = AutoServer::with_cors(cm);
    let client = client();
    let mut headers = Headers::new();
    headers.set(OriginHeader::from_str("http://www.a.com:8080").unwrap());
    let res = client.get(&format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::ImATeapot);
    assert!(res.headers.get::<AccessControlExposeHeaders>().is_none());
    assert_eq!(res.headers
                   .get::<AccessControlAllowOrigin>()
                   .unwrap()
                   .to_string(),
               "http://www.a.com:8080");
    assert!(res.headers.get::<AccessControlAllowCredentials>().is_none());
    assert!(res.headers.get::<AccessControlAllowHeaders>().is_none());
    assert!(res.headers.get::<AccessControlMaxAge>().is_none());
    assert!(res.headers.get::<AccessControlAllowMethods>().is_none());
    assert_eq!(res.headers
                   .get::<Vary>()
                   .unwrap()
                   .to_string(),
               "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
}

#[test]
fn expose_headers() {
    let cm1 = cors();
    let cm = CorsMiddleware { exposed_headers: vec![UniCase("X-ExposeMe".to_owned())], ..cm1 };
    let server = AutoServer::with_cors(cm);
    let client = client();
    let mut headers = Headers::new();
    headers.set(OriginHeader::from_str("http://www.a.com:8080").unwrap());
    let res = client.get(&format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::ImATeapot);
    let expose_headers = res.headers.get::<AccessControlExposeHeaders>().unwrap();
    assert_eq!(expose_headers.0, vec![UniCase("X-ExposeMe")]);
    assert_eq!(res.headers
                   .get::<AccessControlAllowOrigin>()
                   .unwrap()
                   .to_string(),
               "http://www.a.com:8080");
    assert!(res.headers.get::<AccessControlAllowCredentials>().is_none());
    assert!(res.headers.get::<AccessControlAllowHeaders>().is_none());
    assert!(res.headers.get::<AccessControlMaxAge>().is_none());
    assert!(res.headers.get::<AccessControlAllowMethods>().is_none());
}

#[test]
fn allow_credentials() {
    let cm1 = cors();
    let cm = CorsMiddleware {
        exposed_headers: vec![UniCase("X-ExposeMe".to_owned())],
        allow_credentials: true,
        ..cm1
    };
    let server = AutoServer::with_cors(cm);
    let client = client();
    let mut headers = Headers::new();
    headers.set(OriginHeader::from_str("http://www.a.com:8080").unwrap());
    let res = client.get(&format!("http://127.0.0.1:{}/a", server.port))
        .headers(headers)
        .send()
        .unwrap();
    assert_eq!(res.status, status::ImATeapot);
    let expose_headers = res.headers.get::<AccessControlExposeHeaders>().unwrap();
    assert_eq!(expose_headers.0, vec![UniCase("X-ExposeMe")]);
    assert_eq!(res.headers
                   .get::<AccessControlAllowOrigin>()
                   .unwrap()
                   .to_string(),
               "http://www.a.com:8080");
    assert_eq!(res.headers
                   .get::<AccessControlAllowCredentials>()
                   .unwrap()
                   .to_string(),
               "true");
    assert!(res.headers.get::<AccessControlAllowHeaders>().is_none());
    assert!(res.headers.get::<AccessControlMaxAge>().is_none());
    assert!(res.headers.get::<AccessControlAllowMethods>().is_none());
}

#[test]
fn normal_request_without_origin_is_passthrough() {
    let server = AutoServer::new();
    let client = client();
    let res = client.get(&format!("http://127.0.0.1:{}/a", server.port)).send().unwrap();
    assert_eq!(res.status, status::ImATeapot);
    assert!(res.headers.get::<AccessControlAllowOrigin>().is_none());
    assert!(res.headers.get::<AccessControlAllowHeaders>().is_none());
    assert!(res.headers.get::<AccessControlAllowMethods>().is_none());
    assert!(res.headers.get::<AccessControlExposeHeaders>().is_none());
    assert!(res.headers.get::<AccessControlMaxAge>().is_none());
}

#[test]
fn handler_ergonomy() {
    let get_handler = |_: &mut Request| Ok(Response::with((status::ImATeapot, "get")));
    let put_handler = |_: &mut Request| Ok(Response::with((status::ImATeapot, "put")));

    let mut router = Router::new();
    router.get("", get_handler, "get_a");
    router.put("", put_handler, "put_a");

    let cors = cors();
    let chain = cors.decorate(router);

    let server = AutoServer::with_handler(chain);

    let client = client();
    let res = client.get(&format!("http://127.0.0.1:{}", server.port)).send().unwrap();
    assert_eq!(res.status, status::ImATeapot);
}
