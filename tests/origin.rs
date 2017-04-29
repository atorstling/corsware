extern crate iron_cors2;
extern crate router;
extern crate iron;
extern crate unicase;
extern crate hyper;
extern crate mount;
use iron_cors2::{Origin};
use std::io::Read;
use iron::headers::{AccessControlRequestMethod, AccessControlRequestHeaders,
                    AccessControlAllowOrigin, AccessControlAllowHeaders, AccessControlMaxAge,
                    AccessControlAllowMethods, AccessControlAllowCredentials};
use iron::method::Method::*;
use iron::middleware::Handler;
use std::str::FromStr;
use std::collections::HashSet;
use unicase::UniCase;
use hyper::Url;

#[test]
fn identical_origin_is_equal() {
    let o1 = Origin::parse("http://www.google.com");
    let o2 = Origin::parse("http://www.google.com");
    assert_eq!(o1, o2);
}

#[test]
fn different_protocol_matters() {
    let o1 = Origin::parse("http://www.google.com");
    let o2 = Origin::parse("https://www.google.com");
    assert_ne!(o1, o2);
}

#[test]
fn casing_does_not_matter() {
    let o1 = Origin::parse("hTtP://wWw.gOogLe.cOm");
    let o2 = Origin::parse("HtTp://wwW.GooglE.coM");
    assert_eq!(o1, o2);
}

#[test]
fn explicit_default_port_does_not_matter() {
    let o1 = Origin::parse("http://example.com");
    let o2 = Origin::parse("http://example.com:80");
    assert_eq!(o1, o2);
    let o3 = Origin::parse("https://example.com");
    let o4 = Origin::parse("https://example.com:443");
    assert_eq!(o3, o4);
}

#[test]
fn explicit_wrong_port_does_matter() {
    let o1 = Origin::parse("http://example.com");
    let o2 = Origin::parse("http://example.com:8080");
    assert_ne!(o1, o2);
}

#[test]
fn path_does_not_matter() {
    let o1 = Origin::parse("http://example.com");
    let o2 = Origin::parse("http://example.com/a/b/c");
    assert_eq!(o1, o2);
}

#[test]
fn user_pass_does_not_matter() {
    let o1 = Origin::parse("http://example.com");
    let o2 = Origin::parse("http://user:password@example.com");
    assert_eq!(o1, o2);
}

#[test]
fn different_subdomain_does_matter() {
    let o1 = Origin::parse("http://example.com");
    let o2 = Origin::parse("http://www.example.com");
    assert_ne!(o1, o2);
}

#[test]
fn very_different_url_but_still_same_origin() {
    let o1 = Origin::parse("http://example.com");
    let o2 = Origin::parse("hTtP://user:password@eXampLe.cOm:80/a/path.html");
    assert_eq!(o1, o2);
}
