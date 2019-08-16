use crate::rparser::{RBuilder, RParser, R_STATUS_FAIL, R_STATUS_OK};
use dns_parser::Packet;

pub struct DnsUDPBuilder {}
impl RBuilder for DnsUDPBuilder {
    fn new(&self) -> Box<dyn RParser> { Box::new(DnsUDPParser::new(b"DNS/UDP")) }
    fn probe(&self, i:&[u8]) -> bool { dns_probe_udp(i) }
}

pub struct DnsUDPParser<'a> {
    _name: Option<&'a[u8]>,
}

impl<'a> DnsUDPParser<'a> {
    pub fn new(name:&[u8]) -> DnsUDPParser {
        DnsUDPParser {
            _name: Some(name),
        }
    }
}

impl<'a> RParser for DnsUDPParser<'a> {
    fn parse(&mut self, i: &[u8], _direction: u8) -> u32 {
        match Packet::parse(i) {
            Ok(pkt) => {
                if pkt.header.query {
                    debug!("DNS query");
                    for q in &pkt.questions {
                        debug!("  query: {}/{:?}", q.qname, q.qtype);
                    }
                } else {
                    debug!("DNS answer");
                    for answer in &pkt.answers {
                        debug!("  answer: {}/{:?}", answer.name, answer.data);
                    }
                }
                // debug!("pkt: {:?}", pkt);
                R_STATUS_OK
            }
            _ => R_STATUS_FAIL
        }
    }
}

pub fn dns_probe_udp(i: &[u8]) -> bool {
    Packet::parse(i).is_ok()
}
