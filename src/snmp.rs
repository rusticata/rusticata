use nom::IResult;
use snmp_parser::parse_snmp_v1;

use rparser::{RParser,R_STATUS_OK,R_STATUS_FAIL};

pub struct SnmpParser<'a> {
    _name: Option<&'a[u8]>,
    _version: u8,
}

impl<'a> SnmpParser<'a> {
    pub fn new(name: &'a[u8], version: u8) -> SnmpParser<'a> {
        SnmpParser{
            _name: Some(name),
            _version: version,
        }
    }
}


impl<'a> RParser for SnmpParser<'a> {
    fn parse(&mut self, i: &[u8], _direction: u8) -> u32 {
        match parse_snmp_v1(i) {
            IResult::Done(_rem,r) => {
                debug!("parse_snmp_v1: {:?}", r);
                R_STATUS_OK
            },
            e @ _ => {
                warn!("parse_snmp_v1 failed: {:?}", e);
                R_STATUS_FAIL
            },
        }
    }
}

#[allow(dead_code)]
pub fn snmp_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    true
}

