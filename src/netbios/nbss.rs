use crate::rparser::*;
use crate::{gen_get_variants, Variant};
use netbios_parser::*;

pub struct NBSSBuilder {}
impl RBuilder for NBSSBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(NBSSParser::new(b"NetBIOS/NBSS"))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(nbss_udp_probe)
    }
}

pub struct NBSSParser<'a> {
    _name: Option<&'a [u8]>,

    questions: Vec<NetbiosName>,
    // XXX also save content of replies
    answers: Vec<NetbiosName>,
}

impl<'a> NBSSParser<'a> {
    pub fn new(name: &'a [u8]) -> NBSSParser<'a> {
        NBSSParser {
            _name: Some(name),
            questions: Vec::new(),
            answers: Vec::new(),
        }
    }
}

impl<'a> RParser for NBSSParser<'a> {
    fn parse_l4(&mut self, data: &[u8], _direction: Direction) -> ParseResult {
        match parse_nbss_packet(data) {
            Ok((_rem, packet)) => {
                if packet.header.request() {
                    debug!("NBSS request");
                    debug!("  req: {:?}", packet);
                    for q in packet.questions {
                        match q.qname.decode() {
                            Ok(name) => self.questions.push(name),
                            _ => warn!("Invalid NetBIOS name {}", q.qname.raw_str()),
                        }
                    }
                } else {
                    debug!("NBSS answer");
                    debug!("  req: {:?}", packet);
                    // XXX usually, queries are broadcasted, so answer will be associated to a different flow
                    for rr in packet.rr_answer {
                        match rr.rr_name.decode() {
                            Ok(name) => self.answers.push(name),
                            _ => warn!("Invalid NetBIOS name {}", rr.rr_name.raw_str()),
                        }
                    }
                }
                ParseResult::Ok
            }
            _ => ParseResult::Error,
        }
    }

    gen_get_variants! {NBSSParser, "nbss.",
        queries => |s| Some(Variant::from_slice(&s.questions)),
        answers => |s| Some(Variant::from_slice(&s.answers)),
    }
}

pub fn nbss_udp_probe(i: &[u8], l4info: &L4Info) -> ProbeResult {
    if l4info.l4_proto != 17 {
        return ProbeResult::NotForUs;
    }
    match parse_nbss_packet(i) {
        Ok((rem, _packet)) => {
            if !rem.is_empty() {
                ProbeResult::NotForUs
            } else {
                ProbeResult::Certain
            }
        }
        _ => ProbeResult::NotForUs,
    }
}

impl<'a> From<&NetbiosName> for Variant<'a> {
    fn from(input: &NetbiosName) -> Self {
        Variant::OwnedStr(input.to_string())
    }
}
