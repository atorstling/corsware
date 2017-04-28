extern crate iron;
extern crate unicase;
extern crate hyper;

use unicase::UniCase;
use iron::prelude::*;
use iron::method::Method;
use iron::method::Method::*;
use iron::status;
use iron::headers::Origin as OriginHeader;
use iron::headers::{AccessControlRequestMethod, AccessControlRequestHeaders,
                    AccessControlAllowOrigin, AccessControlAllowHeaders, AccessControlMaxAge,
                    AccessControlAllowMethods, AccessControlAllowCredentials};
use iron::middleware::{AroundMiddleware, Handler};
use std::collections::HashSet;
use std::iter::FromIterator;
use hyper::Url;
use std::ascii::AsciiExt;

// A struct which implements origin as defined in
// https://tools.ietf.org/html/rfc6454
//
// Does not cover the unique identifyer approach for
// non-hierarchical naming authority
//
// also see https://en.wikipedia.org/wiki/Same-origin_policy
//
#[derive(PartialEq, Hash)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
}

impl Origin {
    fn parse(s: &str) -> Result<Origin, String> {
        match Url::parse(s) {
            Err(_) => Err("Could not be parsed as Url".to_owned()),
            Ok(url) => {
                // - 1.  If the URI does not use a hierarchical element as a naming
                // - authority (see [RFC3986], Section 3.2) or if the URI is not an
                // - absolute URI, then generate a fresh globally unique identifier
                // - and return that value.
                //
                // From https://hyper.rs/hyper/0.8.0/hyper/struct.Url.html#method.host:
                // host(): If the URL is in a relative scheme, return its structured host.
                match url.host_str() {
                    None => Err(format!("No host in URL '{}'", url)),
                    Some(host_str) => {
                        // - 2. Let uri-scheme be the scheme component of the URI, converted to
                        // - lowercase.
                        let uri_scheme = url.scheme().to_owned().to_lowercase();


                        //  4.  If uri-scheme is "file", the implementation MAY return an
                        //  - implementation-defined value...
                        // NOTE: file scheme not supported, would have bailed already

                        // - 5. Let uri-host be the host component of the URI, converted to lower
                        // - case (using the i;ascii-casemap collation defined in [RFC4790]).
                        //
                        // regarding i;ascii-casemap:
                        // - Its equality, ordering, and substring operations are as for i;octet,
                        // - except that at first, the lower-case letters (octet values 97-122) in
                        // - each input string are changed to upper case (octet values 65-90).

                        let uri_host = host_str.to_ascii_lowercase();

                        // 6.  If there is no port component of the URI:
                        //    1.  Let uri-port be the default port for the protocol given by
                        //        uri-scheme.
                        //        Otherwise:
                        //    2.  Let uri-port be the port component of the URI.
                        let uri_port = url.port_or_known_default();

                        // - 3.  If the implementation doesn't support the protocol given by uri-
                        // - scheme, then generate a fresh globally unique identifier and
                        // - return that value.
                        match uri_port {
                            None => Err(format!("Unsupported URL scheme	'{}'", uri_scheme)),
                            Some(port) => {

                            //   7.  Return the triple (uri-scheme, uri-host, uri-port).
                            Ok(Origin {
                                   scheme: uri_scheme,
                                   host: uri_host,
                                   port: uri_port,
                               })
                               }
                        }
                    }
                }
            }
        }
    }
}

// Using case-sensitive match of protocol://host:port
// For a formal definition, see
// https://tools.ietf.org/html/rfc6454#section-4
pub enum AllowedOrigins {
    Any { prefer_wildcard: bool },
    Specific(HashSet<Url>),
}

impl AllowedOrigins {
    fn allowed_for(&self, origin: &String, allow_credentials: bool) -> Option<String> {
        match Url::parse(origin) {
            Err(_) => None,
            Ok(origin_url) => {
                match self {
                    &AllowedOrigins::Any { prefer_wildcard } => {
                        if allow_credentials {
                            // Allow credentials does not permit using wildcard
                            Some(origin.clone())
                        } else {
                            // Use wildcard if preferred
                            Some(if prefer_wildcard {
                                     "*".to_owned()
                                 } else {
                                     origin.clone()
                                 })
                        }
                    }
                    &AllowedOrigins::Specific(ref allowed) => {
                        if allowed.contains(&origin_url) {
                            Some(origin.clone())
                        } else {
                            None
                        }
                    }
                }
            }
        }

    }
}


pub struct CorsMiddleware {
    pub allowed_origins: AllowedOrigins,
    // Having allowed methods "any" would not make much sense
    // since we need to enumerate all methods when returning
    // the allowed-methods header
    pub allowed_methods: Vec<Method>,
    pub allowed_headers: Vec<UniCase<String>>,
    pub exposed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age_seconds: u32,
}

impl CorsMiddleware {
    pub fn new() -> CorsMiddleware {
        let allowed_methods: Vec<Method> = vec![Options, Get, Post, Put, Delete, Head, Trace,
                                                Connect, Patch];
        let allowed_headers: Vec<unicase::UniCase<String>> =
            vec![// To allow application/json
                 UniCase("Content-Type".to_owned()),
                 // Set by some js libs
                 UniCase("X-Requested-With".to_owned())];
        let exposed_headers: Vec<String> = Vec::new();
        CorsMiddleware {
            allowed_origins: AllowedOrigins::Any { prefer_wildcard: false },
            allowed_methods: allowed_methods,
            allowed_headers: allowed_headers,
            exposed_headers: exposed_headers,
            allow_credentials: false,
            max_age_seconds: 60 * 60,
        }
    }

    fn handle(&self, req: &mut Request, handler: &Handler) -> IronResult<Response> {
        // http://stackoverflow.com/questions/14015118/
        // what-is-the-expected-response-to-an-invalid-cors-request
        // http://stackoverflow.com/questions/32331737/
        // how-can-i-identify-a-cors-preflight-request
        if req.method == Options && req.headers.get::<AccessControlRequestMethod>().is_some() {
            self.handle_preflight(req, handler)
        } else {
            self.handle_normal(req, handler)
        }
    }

    fn handle_preflight(&self, req: &mut Request, _: &Handler) -> IronResult<Response> {
        // Successful preflight status code is NoContent
        let mut res = Response::with((status::NoContent));

        // - Preflight request
        // - 1.If the Origin header is not present terminate this set of steps. The request is
        // - outside the scope of this specification.
        let maybe_origin = req.headers.get::<OriginHeader>();
        if maybe_origin.is_none() {
            let resp = Response::with((status::BadRequest,
                                       "Preflight request without Origin header"));
            return Ok(resp);
        }
        let origin = maybe_origin.unwrap();
        //
        // - 2.If the value of the Origin header is not a case-sensitive match for any of the
        // - values in list of origins do not set any additional headers and terminate this
        // - set of steps.
        //
        // - Note: Always matching is acceptable since the list of origins can be unbounded.
        //
        // - Note: The Origin header can only contain a single origin as the user agent
        //       will not follow redirects.
        //
        let origin_str = origin.to_string();
        let allowed_origin = self.allowed_origins.allowed_for(&origin_str, self.allow_credentials);
        if allowed_origin.is_none() {
            let resp = Response::with((status::BadRequest,
                                       format!("Preflight request requesting \
                                       disallowed origin '{}'",
                                               origin_str)));
            return Ok(resp);
        }
        //
        // - 3. Let method be the value as result of parsing the Access-Control-Request-Method
        // - header.
        //
        // - If there is no Access-Control-Request-Method header or if parsing failed, do not
        // - set any additional headers and terminate this set of steps. The request is
        // - outside the scope of this specification.

        // We can assume that this header exists, since we already checked that before
        // classifying the request as preflight
        let requested_method = req.headers.get::<AccessControlRequestMethod>().unwrap();

        //
        // - 4. Let header field-names be the values as result of parsing the
        // - Access-Control-Request-Headers headers.
        //
        // - If there are no Access-Control-Request-Headers headers let header field-names be
        // - the empty list.
        //
        // - If parsing failed do not set any additional headers and terminate this set of
        // - steps. The request is outside the scope of this specification.
        //
        let empty_vec: Vec<UniCase<String>> = vec![];
        let maybe_requested_headers = req.headers.get::<AccessControlRequestHeaders>();
        let requested_headers: &Vec<UniCase<String>> = if maybe_requested_headers.is_some() {
            &maybe_requested_headers.unwrap().0
        } else {
            &empty_vec
        };
        // - 5.If method is not a case-sensitive match for any of the values in list of
        // -   methods do not set any additional headers and terminate this set of steps.
        //
        // - Always matching is acceptable since the list of methods can be unbounded.
        //
        if !self.allowed_methods.contains(requested_method) {
            return Ok(Response::with((status::BadRequest,
                                      format!("Preflight request requesting disallowed method {}",
                                              requested_method))));
        }
        // - 6. If any of the header field-names is not a ASCII case-insensitive match for any
        // - of the values in list of headers do not set any additional headers and terminate
        // - this set of steps.
        let requested_headers_set: HashSet<UniCase<String>> =
            HashSet::from_iter(requested_headers.iter().cloned());
        let allowed_headers_set: HashSet<UniCase<String>> =
            HashSet::from_iter(self.allowed_headers.iter().cloned());
        let disallowed_headers: HashSet<UniCase<String>> =
            requested_headers_set.difference(&allowed_headers_set).cloned().collect();
        if !disallowed_headers.is_empty() {
            let a = disallowed_headers.iter()
                .map(|uh| uh.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let msg = format!("Preflight request requesting disallowed header(s) {}", a);
            return Ok(Response::with((status::BadRequest, msg)));

        }
        //
        // - Always matching is acceptable since the list of headers can be unbounded.
        //
        // - 7. If the resource supports credentials add a single Access-Control-Allow-Origin
        // - header, with the value of the Origin header as value, and add a single
        // - Access-Control-Allow-Credentials header with the case-sensitive string "true" as
        // - value.
        //
        // - Otherwise, add a single Access-Control-Allow-Origin header, with either the
        // - value of the Origin header or the string "*" as value.
        //
        // - The string "*" cannot be used for a resource that supports credentials.
        //
        if self.allow_credentials {
            res.headers.set(AccessControlAllowCredentials);
        }
        res.headers.set(AccessControlAllowOrigin::Value(allowed_origin.unwrap()));
        // - 8. Optionally add a single Access-Control-Max-Age header with as value the amount
        // - of seconds the user agent is allowed to cache the result of the request.
        res.headers.set(AccessControlMaxAge(self.max_age_seconds));
        //
        // - 9. If method is a simple method this step may be skipped.
        //
        // - Add one or more Access-Control-Allow-Methods headers consisting of (a subset of)
        // - the list of methods.
        //
        // - If a method is a simple method it does not need to be listed, but this is not
        // - prohibited.
        //
        // - Since the list of methods can be unbounded, simply returning the method
        // - indicated by Access-Control-Request-Method (if supported) can be enough.
        //
        res.headers.set(AccessControlAllowMethods(self.allowed_methods.clone()));
        // - 10.If each of the header field-names is a simple header and none is Content-Type,
        // - this step may be skipped.
        //
        // - Add one or more Access-Control-Allow-Headers headers consisting of (a subset of)
        // - the list of headers.
        //
        // - If a header field name is a simple header and is not Content-Type, it is not
        // - required to be listed. Content-Type is to be listed as only a subset of its
        // - values makes it qualify as simple header.
        //
        // - Since the list of headers can be unbounded, simply returning supported headers
        // - from Access-Control-Allow-Headers can be enough.
        res.headers.set(AccessControlAllowHeaders(self.allowed_headers.clone()));
        Ok(res)
    }

    fn handle_normal(&self, req: &mut Request, handler: &Handler) -> IronResult<Response> {
        // Normal request
        // 1.If the Origin header is not present terminate this set of steps. The request is
        // outside the scope of this specification.
        let has_origin = req.headers.get::<OriginHeader>().is_some();
        if !has_origin {
            return handler.handle(req);
        }
        //
        // 2.If the value of the Origin header is not a case-sensitive match for any of the
        // values in list of origins, do not set any additional headers and terminate this
        // set of steps.
        //
        // Note: Always matching is acceptable since the list of origins can be unbounded.
        //
        // 3. If the resource supports credentials add a single Access-Control-Allow-Origin
        // header, with the value of the Origin header as value, and add a single
        // Access-Control-Allow-Credentials header with the case-sensitive string "true" as
        // value.
        //
        // Otherwise, add a single Access-Control-Allow-Origin header, with either the
        // value of the Origin header or the string "*" as value.
        //
        // Note: The string "*" cannot be used for a resource that supports credentials.
        //
        // 4. If the list of exposed headers is not empty add one or more
        // Access-Control-Expose-Headers headers, with as values the header field names
        // given in the list of exposed headers.
        let result = handler.handle(req);
        match result {
            Ok(mut res) => {
                // And set CORS headers
                let origin = req.headers.get::<OriginHeader>().unwrap();
                res.headers.set(AccessControlAllowOrigin::Value(format!("{}", origin)));
                Ok(res)
            }
            _ => result,
        }
    }
}

impl AroundMiddleware for CorsMiddleware {
    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(move |req: &mut Request| self.handle(req, &handler))
    }
}
