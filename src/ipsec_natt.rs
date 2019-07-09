use crate::rparser::{RBuilder, RParser, R_STATUS_FAIL, R_STATUS_OK};
use crate::ipsec::{IPsecParser, ipsec_probe};
use nom::be_u32;

pub struct IPsecNatTBuilder {}
impl RBuilder for IPsecNatTBuilder {
    fn new(&self) -> Box<RParser> { Box::new(IPsecNatTParser::new(b"IKEv2-NatT")) }
    fn probe(&self, i:&[u8]) -> bool { ipsec_probe(i) }
}

pub struct IPsecNatTParser<'a> {
    _name: Option<&'a[u8]>,
    pub parser: IPsecParser<'a>,
}

impl<'a> IPsecNatTParser<'a> {
    pub fn new(name: &'a[u8]) -> IPsecNatTParser<'a> {
        IPsecNatTParser{
            _name: Some(name),
            parser: IPsecParser::new(name),
        }
    }
}

impl<'a> RParser for IPsecNatTParser<'a> {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        match be_u32(i) {
            Ok((rem,mark)) => {
                if mark != 0 { return R_STATUS_OK; }
                self.parser.parse(rem, direction)
            },
            _ => {
                warn!("ikev2-natt: reading record mark failed!");
                return R_STATUS_FAIL;
            }
        }
    }
}

pub fn ikev2_natt_probe(i: &[u8]) -> bool {
    if i.len() <= 20 { return false; }
    match be_u32(i) {
        Ok((rem,mark)) if mark == 0 => {
            ipsec_probe(rem)
        }
        _ => false,
    }
}
