use openvpn_parser::{parse_openvpn_tcp,Payload,P_CONTROL_V1,P_ACK_V1};
use tls::TlsParser;

use rparser::{RParser,R_STATUS_OK,R_STATUS_FAIL};

pub struct OpenVPNTCPParser<'a> {
    _name: Option<&'a[u8]>,
    defrag_buf: Vec<u8>,

    tls_parser: TlsParser<'a>,
}

impl<'a> OpenVPNTCPParser<'a> {
    pub fn new(name: &'a[u8]) -> OpenVPNTCPParser<'a> {
        OpenVPNTCPParser{
            _name: Some(name),
            defrag_buf: Vec::new(),
            tls_parser: TlsParser::new(b"OpenVPN/TLS"),
        }
    }
}


impl<'a> RParser for OpenVPNTCPParser<'a> {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        let mut cur_i = i;
        loop {
            match parse_openvpn_tcp(cur_i) {
                Ok((rem,r)) => {
                    debug!("parse_openvpn_tcp: {:?}", r);
                    if let Payload::Control(ref ctrl) = r.msg {
                        // XXX check number, and if packets needs to be reordered
                        self.defrag_buf.extend_from_slice(ctrl.payload);
                    }
                    if rem.len() == 0 { break; }
                    debug!("Remaining bytes: {}", rem.len());
                    cur_i = rem;
                },
                e => {
                    warn!("parse_openvpn_tcp failed: {:?}", e);
                    // warn!("input buffer:\n{}",i.to_hex(16));
                    return R_STATUS_FAIL;
                },
            }
        }
        if self.defrag_buf.len() > 0 {
            // inscpect TLS message
            // debug!("TLS message:\n{}", self.defrag_buf.to_hex(16));
            self.tls_parser.parse_tcp_level(&self.defrag_buf, direction);
            self.defrag_buf.clear();
        }
        R_STATUS_OK
    }
}

pub fn openvpn_tcp_probe(i: &[u8]) -> bool {
    if i.len() <= 20 { return false; }
    // XXX
    match parse_openvpn_tcp(i) {
        Ok((rem,pkt)) => {
            match pkt.hdr.opcode {
                P_CONTROL_V1 => {
                    if rem.len() > 3 && &rem[0..1] == &[0x16, 0x03] { true }
                    else { false }
                },
                P_ACK_V1 => {
                    if rem.is_empty() { true } else { false }
                },
                _ => false,
            }
        },
        _ => false,
    }
}

