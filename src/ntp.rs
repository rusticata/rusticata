use crate::rparser::*;
use ntp_parser::*;

pub struct NTPBuilder {}
impl RBuilder for NTPBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(NtpParser::new(b"NTP"))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(ntp_probe)
    }
}

pub struct NtpParser<'a> {
    _name: Option<&'a [u8]>,
}

impl<'a> RParser for NtpParser<'a> {
    fn parse_l4(&mut self, data: &[u8], _direction: Direction) -> ParseResult {
        match parse_ntp(data) {
            Ok((rem, ref res)) => {
                debug!("parse_ntp: {:?}", res);
                if !rem.is_empty() {
                    warn!("Extra bytes after NTP data");
                }
            }
            e => warn!("parse_ntp: {:?}", e),
        };
        ParseResult::Ok
    }
}

impl<'a> NtpParser<'a> {
    pub fn new(name: &'a [u8]) -> NtpParser<'a> {
        NtpParser { _name: Some(name) }
    }
}

pub fn ntp_probe(i: &[u8], l4info: &L4Info) -> ProbeResult {
    if i.len() <= 2 {
        return ProbeResult::Unsure;
    }
    if l4info.l4_proto != 17 {
        return ProbeResult::NotForUs;
    }
    match parse_ntp(i) {
        Ok((rem, _)) => {
            if rem.is_empty() {
                // version was already tested
                ProbeResult::Certain
            } else {
                ProbeResult::Unsure
            }
        }
        _ => ProbeResult::NotForUs,
    }
}
