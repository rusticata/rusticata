use crate::rparser::*;
use crate::{gen_get_variants, Variant};
use dns_parser::Packet;

pub struct DnsUDPBuilder {}
impl RBuilder for DnsUDPBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(DnsUDPParser::new(b"DNS/UDP"))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(dns_probe_udp)
    }
}

pub struct DnsUDPParser<'a> {
    _name: Option<&'a [u8]>,

    queries: Vec<String>,

    answers: Vec<String>,
}

impl<'a> DnsUDPParser<'a> {
    pub fn new(name: &[u8]) -> DnsUDPParser {
        DnsUDPParser {
            _name: Some(name),
            queries: Vec::new(),
            answers: Vec::new(),
        }
    }
}

impl<'a> RParser for DnsUDPParser<'a> {
    fn parse_l4(&mut self, data: &[u8], _direction: Direction) -> ParseResult {
        match Packet::parse(data) {
            Ok(pkt) => {
                if pkt.header.query {
                    trace!("DNS query");
                    for q in &pkt.questions {
                        debug!("  query: {}/{:?}", q.qname, q.qtype);
                        self.queries.push(q.qname.to_string());
                        // XXX query type is lost
                    }
                } else {
                    trace!("DNS answer");
                    for answer in &pkt.answers {
                        debug!("  answer: {}/{:?}", answer.name, answer.data);
                        self.answers.push(format!("{:?}", answer.data));
                    }
                }
                // debug!("pkt: {:?}", pkt);
                ParseResult::Ok
            }
            e => {
                debug!("parse error: {:?}", e);
                ParseResult::Error
            }
        }
    }

    gen_get_variants! {DnsUDPParser, "dns.",
        queries => |s| Some(Variant::from_slice(&s.queries)),
        answers => |s| Some(Variant::from_slice(&s.answers)),
    }
}

pub fn dns_probe_udp(i: &[u8], l4info: &L4Info) -> ProbeResult {
    match Packet::parse(i) {
        Ok(packet) => {
            if packet.header.query {
                if packet.questions.is_empty() {
                    return ProbeResult::NotForUs;
                }
            } else if packet.answers.is_empty() ||
                    // if all of the above is wrong, test port
                    ![53, 5353].contains(&l4info.dst_port)
            {
                return ProbeResult::NotForUs;
            }
            // XXX dns_parser does not return remaining bytes
            ProbeResult::Certain
        }
        _ => ProbeResult::NotForUs,
    }
}
