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

pub fn snmp_probe(i: &[u8]) -> bool {
    if i.len() <= 20 { return false; }
    // XXX a better strategy would be to parse the enveloppe, then check the number of
    // XXX items and the version
    match (i[0],i[2],i[3],i[4]) {
        (0x30,2,1,1) => true, // possibly SNMPv1
        (0x30,2,1,2) => true, // possibly SNMPv2
        _ => false,
    }
}

