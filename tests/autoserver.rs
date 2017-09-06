extern crate iron;
extern crate hyper;
extern crate router;
extern crate corsware;
extern crate unicase;
extern crate mount;

use iron::prelude::*;
use iron::Listening;
use iron::Timeouts;
use iron::status;
use iron::middleware::Handler;
use self::router::Router;
use self::mount::Mount;
use corsware::CorsMiddleware;

pub struct AutoServer {
    pub listening: Listening,
    pub port: u16,
}

pub fn cors() -> CorsMiddleware {
    CorsMiddleware::permissive()
}

impl Default for AutoServer {
    fn default() -> Self {
        Self::new()
    }
}


impl AutoServer {
    pub fn new() -> AutoServer {
        AutoServer::with_cors(cors())
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
        let i = Iron {
            handler: handler,
            timeouts: Timeouts { keep_alive: None, .. Timeouts::default()},
            threads: 1
        };
        let l = i.http("127.0.0.1:0".to_owned()).unwrap();
        //let l = Iron::new(handler).http("127.0.0.1:0".to_owned()).unwrap();
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
