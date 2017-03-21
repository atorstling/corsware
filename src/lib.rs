extern crate iron;
extern crate unicase;
struct CorsMiddleware;

use unicase::UniCase;
use iron::prelude::*;
use iron::method::Method;
use iron::status;
use iron::headers::{Origin,
					ContentType,
                    AccessControlRequestMethod,
                    AccessControlAllowOrigin,
                    AccessControlAllowHeaders,
                    AccessControlAllowMethods};
use iron::middleware::{AroundMiddleware, Handler};

impl AroundMiddleware for CorsMiddleware {

    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(move | req: &mut Request | {
            let allowed_headers: Vec<unicase::UniCase<String>> = vec![
                    // To allow application/json
                    UniCase("Content-Type".to_owned()),
                    // Set by some js libs 
                    UniCase("X-Requested-With".to_owned()),
                    ];
            let allowed_methods: Vec<Method> = vec![ Method::Get, Method::Put, Method::Post ];
            if req.method == Method::Options && 
                req.headers.get::<AccessControlRequestMethod>().is_some() {
                // Preflight request
                // 1.If the Origin header is not present terminate this set of steps. The request is
                // outside the scope of this specification.
                if req.headers.get::<Origin>().is_none() {
                    
                }
                //
                // 2.If the value of the Origin header is not a case-sensitive match for any of the
                // values in list of origins do not set any additional headers and terminate this
                // set of steps.
                //
                // Note: Always matching is acceptable since the list of origins can be unbounded.
                //
                // Note: The Origin header can only contain a single origin as the user agent 
                //       will not follow redirects.
                //
                // 3. Let method be the value as result of parsing the Access-Control-Request-Method
                // header.
                //
                // If there is no Access-Control-Request-Method header or if parsing failed, do not
                // set any additional headers and terminate this set of steps. The request is
                // outside the scope of this specification.
                //
                // 4. Let header field-names be the values as result of parsing the
                // Access-Control-Request-Headers headers.
                //
                // If there are no Access-Control-Request-Headers headers let header field-names be
                // the empty list.
                //
                // If parsing failed do not set any additional headers and terminate this set of
                // steps. The request is outside the scope of this specification.
                //
                // 5.If method is not a case-sensitive match for any of the values in list of 
                //   methods do not set any additional headers and terminate this set of steps.
                //
                // Always matching is acceptable since the list of methods can be unbounded.
                //
                // 6. If any of the header field-names is not a ASCII case-insensitive match for any
                // of the values in list of headers do not set any additional headers and terminate
                // this set of steps.
                //
                // Always matching is acceptable since the list of headers can be unbounded.
                //
                // 7. If the resource supports credentials add a single Access-Control-Allow-Origin
                // header, with the value of the Origin header as value, and add a single
                // Access-Control-Allow-Credentials header with the case-sensitive string "true" as
                // value.
                //
                // Otherwise, add a single Access-Control-Allow-Origin header, with either the
                // value of the Origin header or the string "*" as value.
                //
                // The string "*" cannot be used for a resource that supports credentials.
                //
                // 8. Optionally add a single Access-Control-Max-Age header with as value the amount
                // of seconds the user agent is allowed to cache the result of the request.
                //
                // 9. If method is a simple method this step may be skipped.
                //
                // Add one or more Access-Control-Allow-Methods headers consisting of (a subset of)
                // the list of methods.
                //
                // If a method is a simple method it does not need to be listed, but this is not
                // prohibited.
                //
                // Since the list of methods can be unbounded, simply returning the method
                // indicated by Access-Control-Request-Method (if supported) can be enough.
                //
                // 10.If each of the header field-names is a simple header and none is Content-Type,
                // this step may be skipped.
                //
                // Add one or more Access-Control-Allow-Headers headers consisting of (a subset of)
                // the list of headers.
                //
                // If a header field name is a simple header and is not Content-Type, it is not
                // required to be listed. Content-Type is to be listed as only a subset of its
                // values makes it qualify as simple header.
                //
                // Since the list of headers can be unbounded, simply returning supported headers
                // from Access-Control-Allow-Headers can be enough.
                let mut res = Response::with((status::NoContent));
                res.headers.set(AccessControlAllowHeaders(allowed_headers));
                res.headers.set(AccessControlAllowMethods(allowed_methods));
                Ok(res)

            } else {
                // Normal request
                // 1.If the Origin header is not present terminate this set of steps. The request is
                // outside the scope of this specification.
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
                    Ok(mut resp) => {
                        // And set CORS headers
                        resp.headers.set(AccessControlAllowOrigin::Value("*".to_string()));
                        Ok(resp)
                    }
                    _ => result
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
	extern crate router;
	extern crate hyper;
	use iron::Listening;
	use self::router::Router;
	use iron::prelude::*;
	use iron::status;
	use self::hyper::Client;
	use std::io::Read;

	struct AutoServer {
		listening: Listening,
		port: u16
	}

	impl AutoServer {
		pub fn new() -> AutoServer {
			let mut router = Router::new();
			router.get("/a",
               |_: &mut Request| Ok(Response::with((status::ImATeapot, ""))),
               "get_a");
    		let l = Iron::new(router).http(format!("localhost:0")).unwrap();
			let p = l.socket.port();
			AutoServer { listening: l, port: p }
		}
	}

	impl Drop for AutoServer {
		fn drop(&mut self) {
			// Workaround for https://github.com/hyperium/hyper/issues/338
			self.listening.close().unwrap();
		}
	}

    #[test]
    fn options_with_requested_methods_but_no_origin_invalid() {
		let server = AutoServer::new();
		let port = server.port ;
		println!("port is {}", port);
		let client = Client::new();
		let res = client.get(&format!("http://127.0.0.1:{}/a", port)).send().unwrap();
		assert_eq!(res.status, status::ImATeapot);
	}
}
