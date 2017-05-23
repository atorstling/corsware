/// Test fixture for browser tests
extern crate iron;
extern crate unicase;
extern crate hyper;
extern crate corsware;

use corsware::CorsMiddleware;
use iron::prelude::*;
use iron::status;

mod autoserver;
use autoserver::AutoServer;

fn main() {
    let handler = |_: &mut Request| Ok(Response::with((status::Ok, "Hello world!")));
    let mut chain = Chain::new(handler);
    chain.link_around(CorsMiddleware::permissive());
    let mut listening = Iron::new(chain).http("localhost:6200").unwrap();
    println!("OK, listening on port {}", listening.socket.port());
    //listening.close().unwrap();
}
