use crate::rparser::*;
use crate::{gen_get_variants, Variant};
use dns_parser::Packet;

pub struct DnsUDPBuilder {}
impl RBuilder for DnsUDPBuilder {
    fn build(&self) -> Box<dyn RParser> { Box::new(DnsUDPParser::new(b"DNS/UDP")) }
    fn get_l4_probe(&self) -> Option<ProbeL4> { Some(dns_probe_udp) }
}

pub struct DnsUDPParser<'a> {
    _name: Option<&'a[u8]>,

    queries: Vec<String>,

    answers: Vec<String>,
}

impl<'a> DnsUDPParser<'a> {
    pub fn new(name:&[u8]) -> DnsUDPParser {
        DnsUDPParser {
            _name: Some(name),
            queries: Vec::new(),
            answers: Vec::new(),
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
                        self.queries.push(q.qname.to_string());
                        // XXX query type is lost
                    }
                } else {
                    debug!("DNS answer");
                    for answer in &pkt.answers {
                        debug!("  answer: {}/{:?}", answer.name, answer.data);
                        self.answers.push(format!("{:?}", answer.data));
                    }
                }
                // debug!("pkt: {:?}", pkt);
                R_STATUS_OK
            }
            _ => R_STATUS_FAIL
        }
    }

    gen_get_variants!{DnsUDPParser, "dns.",
        queries => |s| Some(Variant::from_slice(&s.queries)),
        answers => |s| Some(Variant::from_slice(&s.answers)),
    }
}

pub fn dns_probe_udp(i: &[u8], _l4info: &L4Info) -> ProbeResult {
    Packet::parse(i).is_ok().into()
}
