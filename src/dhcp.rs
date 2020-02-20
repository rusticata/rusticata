use crate::rparser::{RBuilder, RParser, R_STATUS_FAIL, R_STATUS_OK};
use crate::{gen_get_variants, Variant};
use dhcp4r::packet::Packet;

pub struct DHCPBuilder {}
impl RBuilder for DHCPBuilder {
    fn new(&self) -> Box<dyn RParser> { Box::new(DHCPParser::new(b"DHCP")) }
    fn probe(&self, i:&[u8]) -> bool { dhcp_probe(i) }
}

pub struct DHCPParser<'a> {
    _name: Option<&'a[u8]>,
    reply: bool,
    xid: u32,
}

impl<'a> DHCPParser<'a> {
    pub fn new(name:&[u8]) -> DHCPParser {
        DHCPParser {
            _name: Some(name),
            reply: false,
            xid: 0,
        }
    }
}

impl<'a> RParser for DHCPParser<'a> {
    fn parse(&mut self, i: &[u8], _direction: u8) -> u32 {
        match Packet::from(i) {
            Ok(pkt) => {
                // debug!("pkt: {:?}", pkt);
                self.reply = pkt.reply;
                if self.xid == 0 {
                    self.xid = pkt.xid;
                }
                R_STATUS_OK
            }
            _ => R_STATUS_FAIL
        }
    }

    gen_get_variants!{DHCPParser, "dhcp.",
        reply => into,
        xid => into,
    }
}

pub fn dhcp_probe(i: &[u8]) -> bool {
    Packet::from(i).is_ok()
}
