use crate::rparser::{RBuilder,RParser,R_STATUS_OK,R_STATUS_FAIL};
use crate::snmp::parse_pdu_enveloppe_version;
use crate::{gen_get_variants, Variant};
use snmp_parser::{parse_snmp_v3, SecurityModel};

pub struct SNMPv3Builder {}
impl RBuilder for SNMPv3Builder {
    fn build(&self) -> Box<dyn RParser> { Box::new(SNMPv3Parser::new(b"SNMPv3")) }
    fn probe(&self, i:&[u8]) -> bool { snmpv3_probe(i) }
}

pub struct SNMPv3Parser<'a> {
    _name: Option<&'a[u8]>,
    version: u8,
    req_flags: u8,
    security_model: SecurityModel,
}

impl<'a> From<SecurityModel> for Variant<'a> {
    fn from(input: SecurityModel) -> Self {
        input.0.into()
    }
}

impl<'a> SNMPv3Parser<'a> {
    pub fn new(name: &'a[u8]) -> SNMPv3Parser<'a> {
        SNMPv3Parser{
            _name: Some(name),
            version: 0,
            req_flags: 0,
            security_model: SecurityModel(0),
        }
    }
}

impl<'a> RParser for SNMPv3Parser<'a> {
    fn parse(&mut self, i: &[u8], _direction: u8) -> u32 {
        match parse_snmp_v3(i) {
            Ok((_rem,r)) => {
                debug!("parse_snmp_v3: {:?}", r);
                self.version = r.version as u8;
                self.req_flags = r.header_data.msg_flags;
                self.security_model = r.header_data.msg_security_model;
                R_STATUS_OK
            },
            e => {
                warn!("parse_snmp_v3 failed: {:?}", e);
                R_STATUS_FAIL
            },
        }
    }

    gen_get_variants!{SNMPv3Parser, "snmpv3.",
        version   => into,
        encrypted => |s| { Some(Variant::Bool(s.req_flags & 0b010 != 0)) },
        security_model => into,
    }
}

pub fn snmpv3_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    match parse_pdu_enveloppe_version(i) {
        Some(3)   => true,
        _         => false,
    }
}
