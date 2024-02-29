use crate::ipsec::{ipsec_probe, IPsecParser};
use crate::rparser::*;
use nom::number::streaming::be_u32;

pub struct IPsecNatTBuilder {}
impl RBuilder for IPsecNatTBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(IPsecNatTParser::new(b"IKEv2-NatT"))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(ikev2_natt_probe)
    }
}

pub struct IPsecNatTParser<'a> {
    _name: Option<&'a [u8]>,
    pub parser: IPsecParser<'a>,
}

impl<'a> IPsecNatTParser<'a> {
    pub fn new(name: &'a [u8]) -> IPsecNatTParser<'a> {
        IPsecNatTParser {
            _name: Some(name),
            parser: IPsecParser::new(name),
        }
    }
}

impl<'a> RParser for IPsecNatTParser<'a> {
    fn parse_l4(&mut self, data: &[u8], direction: Direction) -> ParseResult {
        match be_u32::<&[u8], ()>(data) {
            Ok((rem, mark)) => {
                if mark != 0 {
                    return ParseResult::Ok;
                }
                self.parser.parse_l4(rem, direction)
            }
            _ => {
                warn!("ikev2-natt: reading record mark failed!");
                ParseResult::Error
            }
        }
    }
}

pub fn ikev2_natt_probe(i: &[u8], l4info: &L4Info) -> ProbeResult {
    if i.len() <= 20 {
        return ProbeResult::Unsure;
    }
    match be_u32::<&[u8], ()>(i) {
        Ok((rem, 0)) => ipsec_probe(rem, l4info),
        _ => ProbeResult::NotForUs,
    }
}
