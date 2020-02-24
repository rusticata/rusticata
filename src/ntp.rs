use crate::rparser::*;

use ntp_parser::*;

pub struct NTPBuilder {}
impl RBuilder for NTPBuilder {
    fn new(&self) -> Box<dyn RParser> { Box::new(NtpParser::new(b"NTP")) }
    fn probe(&self, i:&[u8]) -> bool { ntp_probe(i) }
}

pub struct NtpParser<'a> {
    _name: Option<&'a[u8]>,
}

impl<'a> RParser for NtpParser<'a> {
    fn parse(&mut self, i: &[u8], _direction: u8) -> u32 {
        match parse_ntp(i) {
            Ok((rem,ref res)) => {
                debug!("parse_ntp: {:?}",res);
                if rem.len() > 0 {
                    warn!("Extra bytes after NTP data");
                }
            },
            e => warn!("parse_ntp: {:?}",e),
        };
        R_STATUS_OK
    }
}

impl<'a> NtpParser<'a> {
    pub fn new(name: &'a[u8]) -> NtpParser<'a> {
        NtpParser{
            _name: Some(name),
        }
    }
}

pub fn ntp_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    match parse_ntp(i) {
        Ok((_,ref msg)) => {
            if msg.version == 3 || msg.version == 4 {
                true
            } else {
                false
            }
        },
        _ => false,
    }
}