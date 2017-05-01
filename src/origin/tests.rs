use super::Origin;
use std::collections::HashSet;

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

#[test]
fn hashing_works() {
    let o1 = Origin::parse("http://example.com").unwrap();
    let o2 = Origin::parse("http://example.com").unwrap();
    let mut s: HashSet<Origin> = HashSet::new();
    s.insert(o1);
    assert!(s.contains(&o2));
}

#[test]
fn bogus_url_gives_nice_error() {
    let o1 = Origin::parse("lsakdjf[]");
    assert_eq!(o1,
               Err("Could not be parsed as URL: 'lsakdjf[]'".to_owned()));
}

#[test]
fn relative_uri_gives_nice_error() {
    let o1 = Origin::parse("/icons/logo.gif");
    assert_eq!(o1,
               Err("Could not be parsed as URL: '/icons/logo.gif'".to_owned()));
}

#[test]
fn data_url_gives_nice_error() {
    let o1 = Origin::parse("data:image/gif;base64,R0lGODdhMAAwAP");
    assert_eq!(o1,
               Err("No host in URL 'data:image/gif;base64,R0lGODdhMAAwAP'".to_owned()));
}

#[test]
fn can_access_fields() {
    //should not compile
    //let o = Origin{ scheme, host, port: 16 };
    let o = Origin::parse("s://h:16").unwrap();
    assert_eq!(o.scheme(), &"s".to_owned());
    assert_eq!(o.host(), &"h".to_owned());
    assert_eq!(o.port(), 16);
}
