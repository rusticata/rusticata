use crate::rparser::*;
use crate::tls::TlsParser;
use openvpn_parser::*;

pub struct OpenVPNUDPBuilder {}
impl RBuilder for OpenVPNUDPBuilder {
    fn build(&self) -> Box<dyn RParser> { Box::new(OpenVPNUDPParser::new(b"OpenVPN/UDP")) }
    fn get_l4_probe(&self) -> Option<ProbeL4> { Some(openvpn_udp_probe) }
}

pub struct OpenVPNUDPParser<'a> {
    _name: Option<&'a[u8]>,
    defrag_buf: Vec<u8>,

    tls_parser: TlsParser<'a>,
}

impl<'a> OpenVPNUDPParser<'a> {
    pub fn new(name: &'a[u8]) -> OpenVPNUDPParser<'a> {
        OpenVPNUDPParser{
            _name: Some(name),
            defrag_buf: Vec::new(),
            tls_parser: TlsParser::new(b"OpenVPN/TLS"),
        }
    }
}


impl<'a> RParser for OpenVPNUDPParser<'a> {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        let mut cur_i = i;
        loop {
            match parse_openvpn_udp(cur_i) {
                Ok((rem,r)) => {
                    debug!("parse_openvpn_udp: {:?}", r);
                    if let Payload::Control(ref ctrl) = r.msg {
                        // XXX check number, and if packets needs to be reordered
                        self.defrag_buf.extend_from_slice(ctrl.payload);
                    }
                    if rem.is_empty() { break; }
                    debug!("Remaining bytes: {}", rem.len());
                    cur_i = rem;
                },
                e => {
                    warn!("parse_openvpn_udp failed: {:?}", e);
                    return R_STATUS_FAIL;
                },
            }
        }
        if !self.defrag_buf.is_empty() {
            // inscpect TLS message
            // debug!("TLS message:\n{}", self.defrag_buf.to_hex(16));
            self.tls_parser.parse_tcp_level(&self.defrag_buf, direction);
            self.defrag_buf.clear();
        }
        R_STATUS_OK
    }
}

pub fn openvpn_udp_probe(i: &[u8], _l4info: &L4Info) -> ProbeResult {
    if i.len() <= 20 { return ProbeResult::NotForUs; }
    // XXX
    match parse_openvpn_udp(i) {
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

