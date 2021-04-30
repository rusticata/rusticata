use crate::rparser::*;
use radius_parser::parse_radius_data;

pub struct RadiusBuilder {}
impl RBuilder for RadiusBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(RadiusParser::new(b"Radius"))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(radius_probe)
    }
}

pub struct RadiusParser<'a> {
    _name: Option<&'a [u8]>,
}

impl<'a> RadiusParser<'a> {
    pub fn new(name: &'a [u8]) -> RadiusParser<'a> {
        RadiusParser { _name: Some(name) }
    }
}

impl<'a> RParser for RadiusParser<'a> {
    fn parse_l4(&mut self, data: &[u8], _direction: Direction) -> ParseResult {
        match parse_radius_data(data) {
            Ok((rem, ref rad)) => {
                debug!("parse_radius_data: {:?}", rad);
                if !rem.is_empty() {
                    warn!("Extra bytes after Radius data");
                }
                ParseResult::Ok
            }
            _ => ParseResult::Error,
        }
    }
}

#[allow(clippy::manual_range_contains)]
pub fn radius_probe(i: &[u8], _l4info: &L4Info) -> ProbeResult {
    let sz = i.len();
    if sz <= 2 {
        return ProbeResult::NotForUs;
    }
    // RFC 2865: size must be >= 20 and <= 4096
    if sz < 20 || sz > 4096 {
        return ProbeResult::NotForUs;
    }
    match parse_radius_data(i) {
        Ok((rem, r)) => {
            if r.code.0 == 0 || r.code.0 > 13 || r.length as usize != i.len() {
                return ProbeResult::NotForUs;
            }
            if !rem.is_empty() {
                warn!("Extra bytes after Radius data");
                ProbeResult::NotForUs
            } else {
                ProbeResult::Certain
            }
        }
        _ => ProbeResult::NotForUs,
    }
}
