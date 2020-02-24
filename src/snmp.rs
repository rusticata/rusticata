use crate::rparser::{RBuilder,RParser,R_STATUS_OK,R_STATUS_FAIL, STREAM_TOSERVER};
use crate::{gen_get_variants, Variant};
use der_parser::ber::{BerObjectContent, parse_ber_sequence};
use snmp_parser::{parse_snmp_v1,parse_snmp_v2c, PduType};

pub struct SNMPv1Builder {}
impl RBuilder for SNMPv1Builder {
    fn build(&self) -> Box<dyn RParser> { Box::new(SNMPParser::new(b"SNMPv1",1)) }
    fn probe(&self, i:&[u8]) -> bool { snmpv1_probe(i) }
}

pub struct SNMPv2cBuilder {}
impl RBuilder for SNMPv2cBuilder {
    fn build(&self) -> Box<dyn RParser> { Box::new(SNMPParser::new(b"SNMPv2c",2)) }
    fn probe(&self, i:&[u8]) -> bool { snmpv2c_probe(i) }
}

pub struct SNMPParser<'a> {
    _name: Option<&'a[u8]>,
    version: u8,
    community: Option<String>,
    req_type: Option<PduType>,
}

impl<'a> From<PduType> for Variant<'a> {
    fn from(input: PduType) -> Self {
        input.0.into()
    }
}

impl<'a> SNMPParser<'a> {
    pub fn new(name: &'a[u8], version: u8) -> SNMPParser<'a> {
        SNMPParser{
            _name: Some(name),
            version: version,
            community: None,
            req_type: None,
        }
    }
}


impl<'a> RParser for SNMPParser<'a> {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        let parser = match self.version {
            1 => parse_snmp_v1,
            2 => parse_snmp_v2c,
            _ => return R_STATUS_FAIL,
        };
        match parser(i) {
            Ok((_rem,r)) => {
                debug!("parse_snmp({}): {:?}", self.version, r);
                self.community = Some(r.community);
                if direction == STREAM_TOSERVER {
                    self.req_type = Some(r.pdu.pdu_type());
                }
                R_STATUS_OK
            },
            e => {
                warn!("parse_snmp({}) failed: {:?}", self.version, e);
                R_STATUS_FAIL
            },
        }
    }

    gen_get_variants!{SNMPParser, "snmp.",
        version   => into,
        community => map_as_ref,
        req_type  => map,
    }
}

// Read PDU sequence and extract version, if similar to SNMP definition
pub fn parse_pdu_enveloppe_version(i:&[u8]) -> Option<u32> {
    match parse_ber_sequence(i) {
        Ok((_,x)) => {
            match x.content {
                BerObjectContent::Sequence(ref v) => {
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

pub fn snmpv1_probe(i: &[u8]) -> bool {
    if i.len() <= 20 { return false; }
    parse_pdu_enveloppe_version(i) == Some(1)
}

pub fn snmpv2c_probe(i: &[u8]) -> bool {
    if i.len() <= 20 { return false; }
    parse_pdu_enveloppe_version(i) == Some(2)
}
