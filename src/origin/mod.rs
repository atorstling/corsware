extern crate url;
extern crate iron;

use self::url::Url;
use std::ascii::AsciiExt;

/// A struct which implements the concept 'Web Origin' as defined in
/// https://tools.ietf.org/html/rfc6454.
///
/// This implementation only considers hierarchical URLs and null.
///
/// The rationale behind skipping random id:s is that any such random origin should
/// never be equal to another random origin.
/// This has the implication that it's unneccesary to compare them to
/// each other and we might as well return parse error and handle that
/// case separately.
///
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub enum Origin {
    /// The `Null` origin, indicating that a resource lacks a proper origin.
    /// This value is commonly used in the Origin header to indicate that an origin couldn't be
    /// deduced or was deliberitely left out. This value is set instead of omitting the Origin
    //  header, since ommiting the header could just signal a client unaware of the origin concept.
    Null,
    /// The common origin, formed from a `(schem, host, port)` triple.
    Triple {
        /// Lower-case scheme
        scheme: String,
        /// Host with all ascii chars lowercased and punycoded
        host: String,
        /// The explicit port or scheme default port if not explicity set
        port: u16,
    },
}

impl Origin {
    /// Parses the given string as an origin.
    /// #Errors
    /// Errors are returned if
    ///
    /// * The argument cannot be parsed as an URL
    /// * There's no host in the URL
    /// * The URL scheme is not supported by the URL parser (rust-url)
    /// * If there is no known default port for the scheme
    ///
    /// #Examples
    /// ```
    /// use corsware::Origin;
    /// let o1 = Origin::parse("http://exämple.com");
    /// let o2 = Origin::parse("hTtP://user:password@eXämpLe.cOm:80/a/path.html");
    /// assert_eq!(o1, o2);
    /// ```
    pub fn parse(s: &str) -> Result<Origin, String> {
        match Url::parse(s) {
            Err(_) => Err(format!("Could not be parsed as URL: '{}'", s)),
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
                        //
                        // We support all schemes wich have a default port known by hyper
                        match uri_port {
                            None => Err(format!("Unsupported URL scheme	'{}'", uri_scheme)),
                            Some(port) => {
                                //   7.  Return the triple (uri-scheme, uri-host, uri-port).
                                Ok(Origin::Triple {
                                       scheme: uri_scheme,
                                       host: uri_host,
                                       port,
                                   })
                            }
                        }
                    }
                }
            }
        }
    }

    /// Parses the given string as an origin. Allows for
    /// "null" to be parsed as Origin::Null and should only
    /// be used in cases where getting Null origin is not a
    /// security problem. Remember that Null origin should be treated
    /// as "Origin could not be deduced"
    ///
    /// #Examples
    /// ```
    /// use corsware::Origin;
    /// let o1 = Origin::parse_allow_null("null");
    /// assert_eq!(o1, Ok(Origin::Null));
    /// let o2 = Origin::parse_allow_null("http://www.a.com");
    /// assert_eq!(o2, Ok(Origin::Triple {
    ///         scheme: "http".to_owned(),
    ///         host: "www.a.com".to_owned(),
    ///         port: 80u16
    ///         }));
    /// ```
    pub fn parse_allow_null(s: &str) -> Result<Origin, String> {
        match s {
            "null" => Ok(Origin::Null),
            _ => Origin::parse(s),
        }
    }

    /// Returns the scheme of the origin in lower case.
    /// #Example
    /// ```
    /// use corsware::Origin;
    /// assert_eq!(Origin::parse("hTtP://a.com").unwrap().scheme(), &"http".to_owned());
    /// ```
    pub fn scheme(&self) -> &String {
        match *self {
            Origin::Null => panic!("Null Origin has no scheme"),
            Origin::Triple { ref scheme, .. } => scheme,
        }
    }

    /// Returns the host of the origin in ascii lower case.
    /// #Example
    /// ```
    /// use corsware::Origin;
    /// assert_eq!(Origin::parse("ftp://Aö.coM").unwrap().host(), &"xn--a-1ga.com".to_owned());
    /// ```
    pub fn host(&self) -> &String {
        match *self {
            Origin::Null => panic!("Null Origin has no host"),
            Origin::Triple { ref host, .. } => host,
        }
    }

    /// Returns the port of the origin. Will return the default
    /// port if not set explicitly
    /// #Example
    /// ```
    /// use corsware::Origin;
    /// assert_eq!(Origin::parse("ftp://a.com").unwrap().port(), 21);
    /// ```
    pub fn port(&self) -> u16 {
        match *self {
            Origin::Null => panic!("Null Origin has no port"),
            Origin::Triple { ref port, .. } => *port,
        }
    }
}

#[cfg(test)]
mod tests;
