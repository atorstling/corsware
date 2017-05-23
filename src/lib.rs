extern crate iron;
extern crate unicase;
#[macro_use]
extern crate hyper;

pub use unicase::UniCase;
use iron::prelude::*;
use iron::method::Method;
use iron::method::Method::*;
use iron::status;
//use iron::headers::Origin as OriginHeader;
use iron::headers::{AccessControlRequestMethod, AccessControlRequestHeaders,
                    AccessControlAllowOrigin, AccessControlAllowHeaders, AccessControlMaxAge,
                    AccessControlAllowMethods, AccessControlAllowCredentials,
                    AccessControlExposeHeaders, Vary};
use iron::middleware::{AroundMiddleware, Handler};
use std::collections::HashSet;
use std::iter::FromIterator;
pub use origin::Origin;

mod origin;

/// Use custom Origin header to allow for null Origin, which the standard
/// iron header does not allow
header! { (OriginHeader, "Origin") => [String] }

/// Specifies which Origins are allowed to access this resource
#[derive(Clone)]
pub enum AllowedOrigins {
    /// Any Origin is allowed.
    Any {
        /// Allowing a null origin is a separate setting, since it's
        /// risky to trust sources with a null Origin, see
        /// https://tools.ietf.org/id/draft-abarth-origin-03.html#rfc.section.6
        /// https://w3c.github.io/webappsec-cors-for-developers/
        allow_null: bool,
    },
    /// Allow a specific set of origins. Remember that allowing
    /// for a null header is risky.
    Specific(HashSet<Origin>),
}

impl AllowedOrigins {
    /// Allow the provided origin access. Respond with the appropriate
    /// AccessControlAllowOrigin header.
    fn allow(&self,
             origin_string: &str,
             prefer_wildcard: bool,
             allow_credentials: bool)
             -> Option<String> {
        {
            if allow_credentials {
                // Allow credentials does not permit using wildcard
                Some(origin_string.to_owned())
            } else {
                // Use wildcard if preferred
                Some(if prefer_wildcard {
                         "*".to_owned()
                     } else {
                         origin_string.to_owned()
                     })
            }
        }
    }
    /// Returns the value of AccessControlAllowOrigin
    /// given the specified Origin header in the request. The allow_credentials
    /// flag is supplied since AccessControlAllowOrigin * is forbidden when credentials
    /// are allowed.
    ///
    /// We're not using the iron Origin header to construct an Origin directly, since
    /// we are dependent on url.port_or_known_default() to get the default port. This
    /// method is only available after parsing the Origin header to an URL.
    pub fn allowed_for(&self,
                       origin_string: &str,
                       allow_credentials: bool,
                       prefer_wildcard: bool)
                       -> Option<String> {
        match Origin::parse_allow_null(origin_string) {
            Err(_) => None,
            Ok(origin) => {
                match *self {
                    AllowedOrigins::Any { allow_null } => {
                        // Any origin is allowed, but this does not include Null,
                        // special check for that
                        if origin == Origin::Null && !allow_null {
                            None
                        } else {
                            self.allow(origin_string, prefer_wildcard, allow_credentials)
                        }
                    }
                    AllowedOrigins::Specific(ref allowed) => {
                        if allowed.contains(&origin) {
                            self.allow(origin_string, prefer_wildcard, allow_credentials)
                        } else {
                            None
                        }
                    }
                }
            }
        }

    }
}

/// An Iron middleware which implements CORS.
///
/// Note: Not using `Vec<Header>` to represent
/// headers since the Iron `Header`
/// type is representing a `Key=Value` pair and not just the key.
/// In other words, the Header type represents an instance of
/// a HTTP header. What we need here is something representing the
/// type of header. Since the Header trait defines a a method
/// `fn header_name() -> &'static str`, we conclude that Iron uses
/// strings to represent this.
///
/// # Simple Example
/// ```
/// extern crate iron;
/// extern crate corsware;
/// use corsware::CorsMiddleware;
/// use iron::prelude::*;
/// use iron::status;
///
/// fn main() {
///   let handler = |_: &mut Request| {
///       Ok(Response::with((status::Ok, "Hello world!")))
///   };
///   let mut chain = Chain::new(handler);
///   chain.link_around(CorsMiddleware::permissive());
///   let mut listening = Iron::new(chain).http("localhost:0").unwrap();
///   listening.close().unwrap();
/// }
/// ```
/// # A More Elaborate Example
/// ```
/// extern crate iron;
/// extern crate corsware;
/// use corsware::{CorsMiddleware, AllowedOrigins, UniCase};
/// use iron::method::Method::{Get,Post};
/// use iron::prelude::*;
/// use iron::status;
///
/// fn main() {
///   let handler = |_: &mut Request| {
///       Ok(Response::with((status::Ok, "Hello world!")))
///   };
///   let cors = CorsMiddleware {
///     allowed_origins : AllowedOrigins::Any { allow_null: false },
///     allowed_headers: vec![UniCase("Content-Type".to_owned())],
///     allowed_methods : vec![ Get, Post ],
///     exposed_headers: vec![],
///     allow_credentials: false,
///     max_age_seconds: 60 * 60,
///     prefer_wildcard: true
///   };
///
///   let chain = cors.decorate(handler);
///   let mut listening = Iron::new(chain).http("localhost:0").unwrap();
///   listening.close().unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct CorsMiddleware {
    /// The origins which are allowed to access this resource
    pub allowed_origins: AllowedOrigins,
    /// The methods allowed to perform on this resource
    pub allowed_methods: Vec<Method>,
    /// The headers allowed to send to this resource
    pub allowed_headers: Vec<UniCase<String>>,
    /// The headers allowed to read from the response from this resource
    pub exposed_headers: Vec<UniCase<String>>,
    /// Whether to allow clients to send cookies to this resource or not
    pub allow_credentials: bool,
    /// Defines the max cache lifetime for operations allowed on this
    /// resource
    pub max_age_seconds: u32,
    /// If set, wildcard ('*') will be used as value
    /// for AccessControlAllowOrigin if possible. If not set,
    /// echoing the incoming Origin will be preferred.
    /// If credentials are allowed, echoing will always be used.
    pub prefer_wildcard: bool,
}

/// Returns all standard HTTP verbs:
/// `[Options, Get, Post, Put, Delete, Head, Trace, Connect, Patch]``
pub fn all_std_methods() -> Vec<Method> {
    vec![Options, Get, Post, Put, Delete, Head, Trace, Connect, Patch]
}

/// Returns HTTP Headers commonly set by clients (js frontend frameworks and the like):
/// `Authorization, Content-Type and X-Requested-With`
pub fn common_req_headers() -> Vec<unicase::UniCase<String>> {
    vec![UniCase("Authorization".to_owned()),
         UniCase("Content-Type".to_owned()),
         UniCase("X-Requested-With".to_owned())]
}

impl CorsMiddleware {
    /// New middleware with sensible permissive settings.
    /// Allows any origin.
    /// Allows all standard HTTP methods.
    /// Allows common request headers (as defined by `common_req_headers()`.
    /// Does not expose any headers.
    /// Does not allow credentials.
    /// Sets MaxAge to 60 minutes.
    pub fn permissive() -> CorsMiddleware {
        CorsMiddleware {
            allowed_origins: AllowedOrigins::Any { allow_null: false },
            allowed_methods: all_std_methods(),
            allowed_headers: common_req_headers(),
            exposed_headers: vec![],
            allow_credentials: false,
            max_age_seconds: 60 * 60,
            prefer_wildcard: false,
        }
    }

    /// These are all headers which can influence the outcome of
    /// any given CORS request.
    fn vary_headers() -> Vec<UniCase<String>> {
        vec![UniCase("Origin".to_owned()),
             UniCase("Access-Control-Request-Method".to_owned()),
             UniCase("Access-Control-Request-Headers".to_owned())]
    }

    /// Handle a potential CORS request. Detects if this is a
    /// preflight or normal method, adding CORS headers as appropriate
    fn handle(&self, req: &mut Request, handler: &Handler) -> IronResult<Response> {
        // http://stackoverflow.com/questions/14015118/
        // what-is-the-expected-response-to-an-invalid-cors-request
        // http://stackoverflow.com/questions/32331737/
        // how-can-i-identify-a-cors-preflight-request
        let res = if req.method == Options &&
                     req.headers.get::<AccessControlRequestMethod>().is_some() {
            self.handle_preflight(req, handler)
        } else {
            self.handle_normal(req, handler)
        };
        // Vary-Headers are outside the CORS specification, but still important for
        // caching. These should be set unconditionally for all resources covered by CORS
        match res {
            Ok(mut r) => {
                r.headers.set(Vary::Items(CorsMiddleware::vary_headers()));
                Ok(r)
            }
            x => x,
        }
    }

    /// Handle a preflight request
    fn handle_preflight(&self, req: &mut Request, _: &Handler) -> IronResult<Response> {
        // Successful preflight status code is NoContent
        let mut res = Response::with(status::NoContent);

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
        let allowed_origin =
            self.allowed_origins.allowed_for(&origin_str,
                                             self.allow_credentials,
                                             self.prefer_wildcard);
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

    /// Handle a normal (i.e non-preflight) CORS request
    fn handle_normal(&self, req: &mut Request, handler: &Handler) -> IronResult<Response> {
        // Normal request
        // - 1.If the Origin header is not present terminate this set of steps. The request is
        // - outside the scope of this specification.
        let have_origin;
        {
            let maybe_origin = req.headers.get::<OriginHeader>();
            have_origin = maybe_origin.is_some();
        }
        if !have_origin {
            // No origin, treat as normal request.
            // We could return error here if we wanted according to
            // https://tools.ietf.org/id/draft-abarth-origin-03.html#rfc.section.6
            return handler.handle(req);
        }
        //
        // - 2.If the value of the Origin header is not a case-sensitive match for any of the
        // - values in list of origins, do not set any additional headers and terminate this
        // - set of steps.
        //
        // - Note: Always matching is acceptable since the list of origins can be unbounded.
        //
        let origin = req.headers
            .get::<OriginHeader>()
            .unwrap()
            .clone();
        let origin_str = origin.to_string();
        let allowed_origin =
            self.allowed_origins.allowed_for(&origin_str,
                                             self.allow_credentials,
                                             self.prefer_wildcard);
        if allowed_origin.is_none() {
            let resp = Response::with((status::BadRequest,
                                       format!("Normal request requesting \
                                       disallowed origin '{}'",
                                               origin_str)));
            return Ok(resp);
        }
        let result = handler.handle(req);
        match result {
            Ok(mut res) => {
                //
                // - 3. If the resource supports credentials add a single
                // - Access-Control-Allow-Origin
                // - header, with the value of the Origin header as value, and add a single
                // - Access-Control-Allow-Credentials header with the case-sensitive string
                // - "true" as value.
                //
                // - Otherwise, add a single Access-Control-Allow-Origin header, with either the
                // - value of the Origin header or the string "*" as value.
                //
                // - Note: The string "*" cannot be used for a resource that supports credentials.
                if self.allow_credentials {
                    res.headers.set(AccessControlAllowCredentials);
                }
                res.headers.set(AccessControlAllowOrigin::Value(allowed_origin.unwrap()));
                //
                // - 4. If the list of exposed headers is not empty add one or more
                // - Access-Control-Expose-Headers headers, with as values the header field names
                // - given in the list of exposed headers.
                if !self.exposed_headers.is_empty() {
                    res.headers.set(AccessControlExposeHeaders(self.exposed_headers.clone()));
                }
                Ok(res)
            }
            _ => result,
        }

    }

    /// Util function for wrapping the supplied handler with this CorsMiddleware.
    /// Works by constructing a chain with only this middleware linked.
    pub fn decorate<T: Handler>(self, handler: T) -> Chain {
        let mut chain = Chain::new(handler);
        chain.link_around(self);
        chain
    }
}

impl AroundMiddleware for CorsMiddleware {
    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(move |req: &mut Request| self.handle(req, &handler))
    }
}
