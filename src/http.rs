use crate::rparser::*;
use crate::{gen_get_variants, Variant};
use httparse::{Request, Response, EMPTY_HEADER};

pub struct HTTPBuilder {}
impl RBuilder for HTTPBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(HTTPParser::new(b"HTTP"))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(http_probe)
    }
}

pub struct HTTPParser<'a> {
    _name: Option<&'a [u8]>,

    // request
    pub version: Option<String>,
    pub method: Option<String>,
    pub uri: Option<String>,
    // response
    pub code: Option<u16>,
}

impl<'a> HTTPParser<'a> {
    pub fn new(name: &'a [u8]) -> Self {
        HTTPParser {
            _name: Some(name),
            version: None,
            method: None,
            uri: None,
            code: None,
        }
    }
}

impl<'a> RParser for HTTPParser<'a> {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        // apache usually sets a limit of 100 headers max
        const NUM_OF_HEADERS: usize = 20;
        let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
        if direction == STREAM_TOSERVER {
            let mut req = Request::new(&mut headers[..]);
            let status = req.parse(i);
            trace!("{:?}", status);
            trace!("{:?}", req);
            if let Some(version) = req.version {
                self.version = Some(format!("HTTP/1.{}", version));
            }
            if let Some(method) = req.method {
                self.method = Some(method.to_owned());
            }
            if let Some(uri) = req.path {
                self.uri = Some(uri.to_owned());
            }
        } else {
            let mut resp = Response::new(&mut headers[..]);
            let status = resp.parse(i);
            trace!("{:?}", status);
            trace!("{:?}", resp);
            if let Some(code) = resp.code {
                self.code = Some(code);
            }
        }
        R_STATUS_OK
    }

    gen_get_variants! {HTTPParser, "http.",
        // version     => |s| Some(Variant::from(&s.version)),
        version => map_as_ref,
        method  => map_as_ref,
        uri     => map_as_ref,
        code    => map,
    }
}

pub fn http_probe(i: &[u8], _l4info: &L4Info) -> ProbeResult {
    // number of headers to parse at once
    const NUM_OF_HEADERS: usize = 4;

    if i.len() < 6 {
        return ProbeResult::Unsure;
    }
    // check if first characters match start of "request-line"
    match &i[..4] {
        b"OPTI" | b"GET " | b"HEAD" | b"POST" | b"PUT " | b"PATC" | b"COPY" | b"MOVE" | b"DELE"
        | b"LINK" | b"UNLI" | b"TRAC" | b"WRAP" => (),
        _ => return ProbeResult::NotForUs,
    }
    // try parsing request
    let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    let mut req = Request::new(&mut headers[..]);
    let status = req.parse(i);
    if let Err(e) = status {
        if e != httparse::Error::TooManyHeaders {
            trace!(
                "data could be HTTP, but got error {:?} while parsing",
                status
            );
            return ProbeResult::Unsure;
        }
    }
    // println!("probe {:?}", status);
    // println!("probe {:?}", req);
    ProbeResult::Certain
}

#[cfg(test)]
mod test {
    use super::http_probe;
    use crate::probe::{L4Info, ProbeResult};

    #[test]
    fn http_parse() {
        let l4_info = L4Info {
            src_port: 1234,
            dst_port: 80,
            l4_proto: 6,
        };
        println!("http request");
        let data = b"GET /foo/:foo.com HTTP/1.1\r\nHost: example.org\r\n\r\n";
        assert_eq!(http_probe(data, &l4_info), ProbeResult::Certain);
        println!("binary");
        let data = b"\x00\x30\x00\x00\x00\x00";
        assert_eq!(http_probe(data, &l4_info), ProbeResult::NotForUs);
    }
}
