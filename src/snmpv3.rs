use nom::IResult;
use snmp_parser::parse_snmp_v3;

use rparser::{RParser,R_STATUS_OK,R_STATUS_FAIL};

pub struct SnmpV3Parser<'a> {
    _name: Option<&'a[u8]>,
}

impl<'a> SnmpV3Parser<'a> {
    pub fn new(name: &'a[u8]) -> SnmpV3Parser<'a> {
        SnmpV3Parser{
            _name: Some(name),
        }
    }
}


impl<'a> RParser for SnmpV3Parser<'a> {
    fn parse(&mut self, i: &[u8], _direction: u8) -> u32 {
        match parse_snmp_v3(i) {
            IResult::Done(_rem,r) => {
                debug!("parse_snmp_v3: {:?}", r);
                R_STATUS_OK
            },
            e @ _ => {
                warn!("parse_snmp_v3 failed: {:?}", e);
                R_STATUS_FAIL
            },
        }
    }
}

pub fn snmpv3_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    // XXX a better strategy would be to parse the enveloppe, then check the number of
    // XXX items and the version
    match (i[0],i[2],i[3],i[4]) {
        (0x30,2,1,3) => true, // possibly SNMPv3
        _ => false,
    }
}

