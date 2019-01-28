use snmp_parser::parse_snmp_v3;

use rparser::{RParser,R_STATUS_OK,R_STATUS_FAIL};
use snmp::parse_pdu_enveloppe_version;

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
            Ok((_rem,r)) => {
                debug!("parse_snmp_v3: {:?}", r);
                R_STATUS_OK
            },
            e => {
                warn!("parse_snmp_v3 failed: {:?}", e);
                R_STATUS_FAIL
            },
        }
    }
}

pub fn snmpv3_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    match parse_pdu_enveloppe_version(i) {
        Some(3)   => true,
        _         => false,
    }
}

