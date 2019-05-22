# Corsware

[![Build Status](https://travis-ci.org/atorstling/corsware.svg?branch=master)](https://travis-ci.org/atorstling/corsware)

Corsware is a by-the-book and feature complete implementation of the [CORS Specification][CORS Spec] for [Iron][Iron]. Corsware supports many features, including authentication, preflight request detection, normal request decoration, allowing credentials, origins, methods and headers, exposing headers, handling null Origins and setting Max-Age.

The middleware itself is simply a standard Iron `AroundMiddleware` and contains no special routing logic.

# Simple Example
```rust
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
[CORS Spec]: https://www.w3.org/TR/cors/
[Iron]: http://ironframework.io/

# [Documentation]
[https://docs.rs/corsware/0.2.0/corsware/](https://docs.rs/corsware/0.2.0/corsware/)

## Links
[Origin Spec](https://tools.ietf.org/html/rfc6454)

[Origin Casemap Spec](https://tools.ietf.org/html/rfc4790)
