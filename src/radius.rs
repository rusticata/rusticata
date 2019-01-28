use radius_parser::parse_radius_data;

use rparser::{RParser,R_STATUS_OK,R_STATUS_FAIL};

pub struct RadiusParser<'a> {
    _name: Option<&'a[u8]>,
}

impl<'a> RadiusParser<'a> {
    pub fn new(name: &'a[u8]) -> RadiusParser<'a> {
        RadiusParser{
            _name: Some(name),
        }
    }
}


impl<'a> RParser for RadiusParser<'a> {
    fn parse(&mut self, i: &[u8], _direction: u8) -> u32 {
        match parse_radius_data(i) {
            Ok((rem,ref rad)) => {
                debug!("parse_radius_data: {:?}", rad);
                if rem.len() > 0 {
                    warn!("Extra bytes after Radius data");
                }
                R_STATUS_OK
            },
            _ => R_STATUS_FAIL,
        }
    }
}

#[allow(dead_code)]
pub fn radius_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    parse_radius_data(i).is_ok()
}

