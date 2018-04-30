use nom::IResult;
use snmp_parser::parse_snmp_v1;
use der_parser::{DerObjectContent,parse_der_sequence};

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

// Read PDU sequence and extract version, if similar to SNMP definition
pub fn parse_pdu_enveloppe_version(i:&[u8]) -> Option<u32> {
    match parse_der_sequence(i) {
        IResult::Done(_,x) => {
            match x.content {
                DerObjectContent::Sequence(ref v) => {
                    if v.len() == 3 {
                        match v[0].as_u32()  {
                            Ok(0) => Some(1), // possibly SNMPv1
                            Ok(1) => Some(2), // possibly SNMPv2c
                            _     => None
                        }
                    } else if v.len() == 4 && v[0].as_u32() == Ok(3) {
                        Some(3) // possibly SNMPv3
                    } else {
                        None
                    }
                },
                _ => None
            }
        },
        _ => None
    }
}

pub fn snmp_probe(i: &[u8]) -> bool {
    if i.len() <= 20 { return false; }
    match parse_pdu_enveloppe_version(i) {
        Some(1) |
        Some(2)   => true,
        _         => false,
    }
}

