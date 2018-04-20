use rparser::*;

use nom::{IResult,be_u32};

use kerberos_udp::{KerberosParserUDP,kerberos_probe_udp};

pub struct KerberosParserTCP<'a> {
    _name:  Option<&'a[u8]>,
    parser: KerberosParserUDP<'a>,
}

impl<'a> RParser for KerberosParserTCP<'a> {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        if i.len() < 4 { return R_STATUS_FAIL; }
        else { return self.parser.parse(&i[4..], direction); }
    }
}

impl<'a> KerberosParserTCP<'a> {
    pub fn new(name: &'a[u8]) -> KerberosParserTCP<'a> {
        KerberosParserTCP{
            _name: Some(name),
            parser: KerberosParserUDP::new(name),
        }
    }
}

pub fn kerberos_probe_tcp(i: &[u8]) -> bool {
    if i.len() <= 14 { return false; }
    match be_u32(i) {
        IResult::Done(rem, record_mark) => {
            if record_mark != rem.len() as u32 { return false; }
            return kerberos_probe_udp(rem);
        },
        IResult::Incomplete(_) => {
            return false;
        },
        IResult::Error(_) => {
            return false;
        },
    }
}

