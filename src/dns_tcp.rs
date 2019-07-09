use crate::{dns_probe_udp, DnsUDPParser};
use crate::rparser::{RBuilder, RParser, R_STATUS_FAIL};
use nom::be_u16;

pub struct DnsTCPBuilder {}
impl RBuilder for DnsTCPBuilder {
    fn new(&self) -> Box<RParser> {
        Box::new(DnsTCPParser::new(b"DNS/TCP"))
    }
    fn probe(&self, i: &[u8]) -> bool {
        dns_probe_tcp(i)
    }
}

pub struct DnsTCPParser<'a> {
    _name: Option<&'a [u8]>,
    parser: DnsUDPParser<'a>,
}

impl<'a> DnsTCPParser<'a> {
    pub fn new(name: &'a [u8]) -> DnsTCPParser<'a> {
        DnsTCPParser {
            _name: Some(name),
            parser: DnsUDPParser::new(name),
        }
    }
}

impl<'a> RParser for DnsTCPParser<'a> {
    fn parse(&mut self, buf: &[u8], direction: u8) -> u32 {
        match be_u16(buf) {
            Ok((rem,l)) => {
                if l > rem.len() as u16 {
                    return R_STATUS_FAIL;
                }
                self.parser.parse(rem, direction)
            }
            _ => R_STATUS_FAIL
        }
    }
}

pub fn dns_probe_tcp(i: &[u8]) -> bool {
    if i.len() <= 14 {
        return false;
    }
    match be_u16(i) {
        Ok((rem, record_len)) => {
            if record_len < i.len() as u16 {
                return false;
            }
            if record_len > rem.len() as u16 {
                return false;
            }
            return dns_probe_udp(rem);
        }
        _ => {
            return false;
        }
    }
}
