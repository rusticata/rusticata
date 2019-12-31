use crate::rparser::*;
use crate::kerberos_udp::{KerberosParserUDP,kerberos_probe_udp};
use crate::Variant;
use nom::error::ErrorKind;
use nom::number::streaming::be_u32;

pub struct KerberosTCPBuilder {}
impl RBuilder for KerberosTCPBuilder {
    fn new(&self) -> Box<dyn RParser> { Box::new(KerberosParserTCP::new(b"Kerberos/TCP")) }
    fn probe(&self, i:&[u8]) -> bool { kerberos_probe_tcp(i) }
}

pub struct KerberosParserTCP<'a> {
    _name:  Option<&'a[u8]>,
    parser: KerberosParserUDP<'a>,

    pub record_ts: usize,
    pub defrag_buf_ts: Vec<u8>,
    pub record_tc: usize,
    pub defrag_buf_tc: Vec<u8>,
}

impl<'a> RParser for KerberosParserTCP<'a> {
    fn parse(&mut self, buf: &[u8], direction: u8) -> u32 {
        // handle tcp buffering
        // XXX we use only one buffer for both sides
        let mut v : Vec<u8>;
        let mut status = R_STATUS_OK;
        let tcp_buffer = match self.record_ts {
            0 => buf,
            _ => {
                // sanity check to avoid memory exhaustion
                if self.defrag_buf_ts.len() + buf.len() > 100000 {
                    warn!("krb5_parse_tcp: TCP buffer exploded {} {}",
                                self.defrag_buf_ts.len(), buf.len());
                    return R_STATUS_FAIL;
                }
                v = self.defrag_buf_ts.split_off(0);
                v.extend_from_slice(buf);
                v.as_slice()
            }
        };
        let mut cur_i = tcp_buffer;
        while cur_i.len() > 0 {
            if self.record_ts == 0 {
                match be_u32::<(&[u8],ErrorKind)>(cur_i) {
                    Ok((rem,record)) => {
                        self.record_ts = record as usize;
                        cur_i = rem;
                    },
                    _ => {
                        warn!("krb5_parse_tcp: reading record mark failed!");
                        return R_STATUS_FAIL;
                    }
                }
            }
            if cur_i.len() >= self.record_ts {
                status |= self.parser.parse(cur_i, direction);
                cur_i = &cur_i[self.record_ts..];
                self.record_ts = 0;
            } else {
                debug!("KerberosParserTCP: more fragments required have {}, need {}", cur_i.len(), self.record_ts);
                self.defrag_buf_ts.extend_from_slice(cur_i);
                return R_STATUS_OK;
            }
        }
        status
    }

    /// Request data from key
    fn get(&self, key: &str) -> Option<Variant> {
        self.parser.get(key)
    }

    /// Returns the available keys for the `get` function
    fn keys(&self) -> ::std::slice::Iter<&str> {
        self.parser.keys()
    }
}

impl<'a> KerberosParserTCP<'a> {
    pub fn new(name: &'a[u8]) -> KerberosParserTCP<'a> {
        KerberosParserTCP{
            _name: Some(name),
            parser: KerberosParserUDP::new(name),
            record_ts: 0,
            defrag_buf_ts: Vec::new(),
            record_tc: 0,
            defrag_buf_tc: Vec::new(),
        }
    }
}

pub fn kerberos_probe_tcp(i: &[u8]) -> bool {
    if i.len() <= 14 { return false; }
    match be_u32::<(&[u8],ErrorKind)>(i) {
        Ok((rem, record_mark)) => {
            if record_mark != rem.len() as u32 { return false; }
            return kerberos_probe_udp(rem);
        },
        _ => {
            return false;
        },
    }
}

