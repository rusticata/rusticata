use crate::rparser::*;
use crate::tls::TlsParser;
use openvpn_parser::{parse_openvpn_tcp,Payload,Opcode};

pub struct OpenVPNTCPBuilder {}
impl RBuilder for OpenVPNTCPBuilder {
    fn build(&self) -> Box<dyn RParser> { Box::new(OpenVPNTCPParser::new(b"OpenVPN/TCP")) }
    fn get_l4_probe(&self) -> Option<ProbeL4> { Some(openvpn_tcp_probe) }
}

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
    fn parse_l4(&mut self, data: &[u8], direction: Direction) -> ParseResult {
        let mut cur_i = data;
        loop {
            match parse_openvpn_tcp(cur_i) {
                Ok((rem,r)) => {
                    debug!("parse_openvpn_tcp: {:?}", r);
                    if let Payload::Control(ref ctrl) = r.msg {
                        // XXX check number, and if packets needs to be reordered
                        self.defrag_buf.extend_from_slice(ctrl.payload);
                    }
                    if rem.is_empty() { break; }
                    debug!("Remaining bytes: {}", rem.len());
                    cur_i = rem;
                },
                e => {
                    warn!("parse_openvpn_tcp failed: {:?}", e);
                    // warn!("input buffer:\n{}",i.to_hex(16));
                    return ParseResult::Error;
                },
            }
        }
        if !self.defrag_buf.is_empty() {
            // inspect TLS message
            // debug!("TLS message:\n{}", self.defrag_buf.to_hex(16));
            self.tls_parser.parse_tcp_level(&self.defrag_buf, direction);
            self.defrag_buf.clear();
        }
        ParseResult::Ok
    }
}

pub fn openvpn_tcp_probe(i: &[u8], _l4info: &L4Info) -> ProbeResult {
    if i.len() <= 20 { return ProbeResult::Unsure; }
    // XXX
    match parse_openvpn_tcp(i) {
        Ok((rem,pkt)) => {
            match pkt.hdr.opcode {
                Opcode::P_CONTROL_V1 => {
                    rem.len() > 3 && rem[0..1] == [0x16, 0x03]
                },
                Opcode::P_ACK_V1 => {
                    rem.is_empty()
                },
                _ => false,
            }
        },
        _ => false,
    }.into()
}

