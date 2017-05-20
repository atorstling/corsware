# Corsware

Corsware is yet another implementation of the [CORS Specification][CORS Spec] for [Iron](Iron). The ambition of this implementation is to make a more or less complete implementation following the spec as closely as possible. This means supporting preflight request detection, normal request decoration, allowing credentials, origins, methods and headers, exposing headers, handling null Origins and setting Max-Age.

The middleware itself is simply a standard Iron `AroundMiddleware` and contains no special routing logic.

# Simple Example
```
extern crate iron;
extern crate corsware;
use corsware::CorsMiddleware;
use iron::prelude::*;
use iron::status;

fn main() {
  let handler = |_: &mut Request| {
      Ok(Response::with((status::Ok, "Hello world!")))
  };
  let mut chain = Chain::new(handler);
  chain.link_around(CorsMiddleware::permissive());
  let mut listening = Iron::new(chain).http("localhost:0").unwrap();
  listening.close().unwrap();
}
```

# [Documentation](https://atorstling.github.io/corsware/corsware/index.html)
https://atorstling.github.io/corsware/corsware/index.html

## References
[CORS Spec]: https://www.w3.org/TR/cors/
[Iron]: http://ironframework.io/

## Links
[Origin Spec](https://tools.ietf.org/html/rfc6454)

[Origin Casemap Spec](https://tools.ietf.org/html/rfc4790)
