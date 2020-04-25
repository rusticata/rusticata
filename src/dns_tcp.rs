use crate::dns_udp::{dns_probe_udp, DnsUDPParser};
use crate::rparser::*;
use nom::error::ErrorKind;
use nom::number::streaming::be_u16;

pub struct DnsTCPBuilder {}
impl RBuilder for DnsTCPBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(DnsTCPParser::new(b"DNS/TCP"))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(dns_probe_tcp)
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
        match be_u16::<(&[u8],ErrorKind)>(buf) {
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

pub fn dns_probe_tcp(i: &[u8], l4info: &L4Info) -> ProbeResult {
    if i.len() <= 14 {
        return ProbeResult::Unsure;
    }
    match be_u16::<(&[u8],ErrorKind)>(i) {
        Ok((rem, record_len)) => {
            if record_len < rem.len() as u16 {
                return ProbeResult::NotForUs;
            }
            if record_len > rem.len() as u16 {
                return ProbeResult::NotForUs;
            }
            dns_probe_udp(rem, l4info)
        }
        _ => {
            ProbeResult::NotForUs
        }
    }
}
