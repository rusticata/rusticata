use crate::rparser::*;
use crate::snmp::parse_pdu_enveloppe_version;
use crate::{gen_get_variants, Variant};
use snmp_parser::{parse_snmp_v3, SecurityModel};

pub struct SNMPv3Builder {}
impl RBuilder for SNMPv3Builder {
    fn build(&self) -> Box<dyn RParser> { Box::new(SNMPv3Parser::new(b"SNMPv3")) }
    fn get_l4_probe(&self) -> Option<ProbeL4> { Some(snmpv3_probe) }
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
    fn parse_l4(&mut self, data: &[u8], _direction: Direction) -> ParseResult {
        match parse_snmp_v3(data) {
            Ok((_rem,r)) => {
                debug!("parse_snmp_v3: {:?}", r);
                self.version = r.version as u8;
                self.req_flags = r.header_data.msg_flags;
                self.security_model = r.header_data.msg_security_model;
                ParseResult::Ok
            },
            e => {
                warn!("parse_snmp_v3 failed: {:?}", e);
                ParseResult::Error
            },
        }
    }

    gen_get_variants!{SNMPv3Parser, "snmpv3.",
        version   => into,
        encrypted => |s| { Some(Variant::Bool(s.req_flags & 0b010 != 0)) },
        security_model => into,
    }
}

pub fn snmpv3_probe(i: &[u8], _l4info: &L4Info) -> ProbeResult {
    if i.len() <= 2 { return ProbeResult::NotForUs; }
    match parse_pdu_enveloppe_version(i) {
        Some(3)   => ProbeResult::Certain,
        _         => ProbeResult::NotForUs,
    }
}
