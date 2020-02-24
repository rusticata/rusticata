use crate::rparser::{RBuilder, RParser, R_STATUS_FAIL, R_STATUS_OK};
use crate::{gen_get_variants, Variant};
use dhcp4r::{
    options::DhcpOption,
    packet::Packet
};
use std::net::Ipv4Addr;

pub struct DHCPBuilder {}
impl RBuilder for DHCPBuilder {
    fn build(&self) -> Box<dyn RParser> { Box::new(DHCPParser::new(b"DHCP")) }
    fn probe(&self, i:&[u8]) -> bool { dhcp_probe(i) }
}

#[derive(Default)]
pub struct DHCPParser<'a> {
    _name: Option<&'a[u8]>,
    reply: bool,
    xid: u32,
    chaddr: Option<[u8; 6]>,
    hostname: Option<String>,
    server_identifier: Option<Ipv4Addr>,
}

impl<'a> DHCPParser<'a> {
    pub fn new(name:&[u8]) -> DHCPParser {
        DHCPParser {
            _name: Some(name),
            ..DHCPParser::default()
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
                if self.chaddr.is_none() {
                    self.chaddr = Some(pkt.chaddr.clone());
                }
                for option in pkt.options.iter() {
                    debug!("  DHCP option: {}", option.code());
                    match option {
                        DhcpOption::HostName(s) => {
                            self.hostname = Some(s.clone());
                        },
                        DhcpOption::ServerIdentifier(ip4) => {
                            self.server_identifier = Some(ip4.clone());
                        },
                        _ => {},
                    }
                }
                R_STATUS_OK
            }
            _ => R_STATUS_FAIL
        }
    }

    gen_get_variants!{DHCPParser, "dhcp.",
        reply => into,
        xid => into,
        chaddr => |s| {
            s.chaddr.as_ref().map(|x| Variant::OwnedStr(
                    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", x[0], x[1], x[2], x[3], x[4], x[5])))
        },
        hostname => |s| { s.hostname.as_ref().map(|x| Variant::OwnedStr(x.clone())) },
        server_identifier => |s| { s.server_identifier.as_ref().map(|x| Variant::OwnedStr(x.to_string())) },
    }
}

pub fn dhcp_probe(i: &[u8]) -> bool {
    Packet::from(i).is_ok()
}
