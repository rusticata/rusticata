use crate::gssapi::*;
use crate::rparser::*;
use crate::sasl::parse_sasl_buffer;
use crate::tls::TlsParser;
use crate::{gen_get_variants, Variant};
use der_parser::ber::*;
use der_parser::error::*;
use ldap_parser::ldap::*;
use ldap_parser::*;
use std::collections::BTreeMap;

pub struct LDAPBuilder {}
impl RBuilder for LDAPBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(LDAPParser::new(b"LDAP"))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(ldap_probe)
    }
}

pub struct LDAPParser<'a> {
    _name: Option<&'a [u8]>,
    has_sasl_layers: bool,
    bind_dn: Option<String>,
    sasl_mech: Option<String>,
    // operation tag of current request, if present
    protocol_op: Option<ProtocolOpTag>,
    // message ID of LDAP request, if present
    ldap_request: Option<MessageID>,
    // numeric result code of LDAP response, if present
    ldap_result_code: Option<u32>,
    // message ID of TLS request, if present
    tls_request: Option<MessageID>,
    has_starttls: bool,
    transactions: BTreeMap<MessageID, LDAPTransaction>,

    defrag_buffer: Vec<u8>,
    tls_parser: Option<TlsParser<'a>>,
}

#[derive(Debug)]
pub struct LDAPTransaction {
    message_id: MessageID,
    tx_op: ProtocolOpTag,
    result_code: Option<u32>,
    bind_dn: Option<String>,
}

impl<'a> RParser for LDAPParser<'a> {
    fn parse_l4(&mut self, data: &[u8], direction: Direction) -> ParseResult {
        if self.has_starttls {
            return self.parse_ldap_starttls(data, direction);
        }
        // debug: check if we missed TLS
        if self.defrag_buffer.is_empty() && data.len() >= 2 && &data[..2] == b"\x16\x03" {
            warn!("LDAP: missed STARTTLS ?!");
        }
        if self.has_sasl_layers {
            self.parse_ldap_sasl(data, direction)
        } else {
            self.parse_ldap_messages(data, direction)
        }
    }

    gen_get_variants! {LDAPParser, "ldap.",
        ldap_request => |s| {
            s.ldap_request.map(|op| op.0.into())
        },
        ldap_result_code      => map,
        protocol_op => |s| {
            s.protocol_op.map(|op| Variant::OwnedStr(op.to_string()))
        },
        bind_dn               => map_as_ref,
        sasl_mech             => map_as_ref,
        has_starttls          => into,
        tls_client_version => |s| {
            s.tls_parser.as_ref().map(|p|
                p.get("tls.client_version")
            ).flatten()
        },
        tls_ssl_record_version => |s| {
            s.tls_parser.as_ref().map(|p|
                p.get("tls.ssl_record_version")
            ).flatten()
        },
        tls_compression => |s| {
            s.tls_parser.as_ref().map(|p|
                p.get("tls.compression")
            ).flatten()
        },
        tls_cipher => |s| {
            s.tls_parser.as_ref().map(|p|
                p.get("tls.cipher")
            ).flatten()
        },
    }
}

impl<'a> LDAPParser<'a> {
    pub fn new(name: &'a [u8]) -> LDAPParser<'a> {
        LDAPParser {
            _name: Some(name),
            has_sasl_layers: false,
            bind_dn: None,
            sasl_mech: None,
            tls_request: None,
            has_starttls: false,
            defrag_buffer: Vec::new(),
            ldap_request: None,
            ldap_result_code: None,
            transactions: BTreeMap::new(),
            protocol_op: None,
            tls_parser: None,
        }
    }

    pub fn parse_ldap_starttls(&mut self, data: &[u8], direction: Direction) -> ParseResult {
        if let Some(parser) = &mut self.tls_parser {
            parser.parse_tcp_level(data, direction)
        } else {
            warn!("Should not happen: could not instantiate TLS parser");
            ParseResult::Fatal
        }
    }

    pub fn parse_ldap_sasl(&mut self, data: &[u8], direction: Direction) -> ParseResult {
        // are we already waiting for more data (defragmentation)?
        if !self.defrag_buffer.is_empty() {
            return self.parse_ldap_messages(data, direction);
        }
        // are we really using SASL?
        // sometimes, SASL is negotiated but the next packets are sent in clear
        //
        // check if first byte is 0 (sasl layer length is 4 bytes, so this is OK if the packet does not exceed 16 MB)
        // if LDAP, first byte should be 0x30 anyway
        if !data.is_empty() && data[0] != 0 {
            warn!("XXX CLEAR TEXT LDAP after SASL");
            return self.parse_ldap_messages(data, direction);
        }
        let mech = match &self.sasl_mech {
            Some(s) => s,
            None => {
                debug!("SASL mechanism unknown, stopping following LDAP session");
                return ParseResult::Stop;
            }
        };
        match mech.as_ref() {
            "GSSAPI" | "GSS-SPNEGO" => {
                // use nom::HexDisplay;
                // debug!("\n{}", data.to_hex(16));
                let (_rem, sasl) = match parse_sasl_buffer(data) {
                    Ok(x) => x,
                    Err(e) => {
                        debug!("LDAP: parsing SASL buffer failed: {:?}", e);
                        return ParseResult::Error;
                    }
                };
                let (_rem, gss) = match parse_gssapi(sasl.0) {
                    Ok(x) => x,
                    Err(e) => {
                        debug!("LDAP: parsing GSS-API buffer failed: {:?}", e);
                        return ParseResult::Error;
                    }
                };
                match &gss {
                    GssApiBuffer::Wrapped(buffer) => {
                        if buffer.token.seal_alg == 0xffff {
                            // no encryption, only integrity
                            // debug!("Integrity-only GSS-API KRB5 encapsulation detected");
                            // XXX remove padding
                            //
                            // integrity-only messages seem to always end up by hex '01', though I could not find why
                            self.parse_ldap_messages(buffer.payload, direction)
                        } else {
                            trace!(
                                "Encrypted GSS-API KRB5 encapsulation detected, activating bypass"
                            );
                            ParseResult::Stop
                        }
                    }
                    GssApiBuffer::GssCfxWrap { token, payload } => {
                        if token.flags & KRB_CFX_FLAG_SEALED != 0 {
                            trace!(
                                "Encrypted GSS-API CFX KRB5 encapsulation detected, activating bypass"
                            );
                            return ParseResult::Stop;
                        }
                        // no encryption, only integrity
                        // debug!("Integrity-only GSS-API KRB5 encapsulation detected");
                        // XXX remove padding
                        //
                        self.parse_ldap_messages(payload, direction)
                    }
                    _ => {
                        trace!("Unknown GSS-API encapsulation, activating bypass");
                        ParseResult::Stop
                    }
                }
            }
            _ => {
                trace!("Unknown SASL layer {}, activating bypass", mech);
                ParseResult::Stop
            }
        }
    }

    pub fn parse_ldap_messages(&mut self, data: &[u8], direction: Direction) -> ParseResult {
        let mut v: Vec<u8>;
        // Check if TCP data is being defragmented
        let defrag_buffer = match self.defrag_buffer.len() {
            0 => data,
            _ => {
                // sanity check vector length to avoid memory exhaustion
                if self.defrag_buffer.len() + data.len() > 16_777_216 {
                    warn!("LDAP: defrag buffer overflow");
                    return ParseResult::Error;
                };
                v = self.defrag_buffer.split_off(0);
                v.extend_from_slice(data);
                v.as_slice()
            }
        };
        let mut cur_i = defrag_buffer;
        loop {
            if cur_i.is_empty() {
                break;
            }
            // read header and see if we have a complete message
            if check_ldap_message_complete(cur_i).is_err() {
                // XXX if bytes are exactly "01", drop? (often happens with GSS-API)
                if cur_i.len() == 1
                    && cur_i[0] == 1
                    && self.sasl_mech == Some("GSS-SPNEGO".to_string())
                {
                    warn!("Fixup for SASL/GSS-API: removing 1 byte");
                    // cur_i = &cur_i[1..];
                    break;
                }
                trace!("Fragmentation required (TCP level)");
                // if not complete, add to defrag buffer
                self.defrag_buffer.extend_from_slice(cur_i);
                // panic!("XXX Fragmented LDAP");
                break;
            }
            match parse_ldap_message(cur_i) {
                Ok((rem, msg)) => {
                    trace!("parse_ldap_message: {:?}", msg);
                    self.handle_message(&msg, direction);
                    cur_i = rem;
                }
                e => {
                    warn!("parse_ldap_message failed: {:?}", e);
                    break;
                }
            };
        }
        trace!("current transactions: {:?}", self.transactions);
        // if !cur_i.is_empty() {
        //     // XXX if bytes are exactly "01", drop? (often happens with GSS-API)
        //     warn!("Extra bytes after LDAP data");
        //     use nom::HexDisplay;
        //     println!("{}", cur_i.to_hex(16));
        // }
        ParseResult::Ok
    }

    pub fn handle_message(&mut self, msg: &LdapMessage, _direction: Direction) {
        let tx_op = msg.protocol_op.tag();
        let bind_dn = &self.bind_dn;
        let mut tx = self
            .transactions
            .entry(msg.message_id)
            .or_insert_with(|| LDAPTransaction::new(msg.message_id, tx_op, bind_dn));
        self.protocol_op = Some(tx_op);
        match &msg.protocol_op {
            ProtocolOp::BindRequest(req) => {
                // store msg_id
                self.ldap_request = Some(msg.message_id);
                // store bind DN
                self.bind_dn = Some(req.name.0.to_string());
                tx.bind_dn = Some(req.name.0.to_string());
                // if SASL, store mechanism
                if let AuthenticationChoice::Sasl(creds) = &req.authentication {
                    self.sasl_mech = Some(creds.mechanism.0.to_string());
                    if let Some(data) = &creds.credentials {
                        if !data.is_empty() {
                            use nom::HexDisplay;
                            println!("XXX\n{}", data.to_hex(16));
                            let (_, xxx) = parse_gssapi(data).unwrap(); // XXX
                            println!("{:?}", xxx);
                        }
                    }
                } else {
                    // XXX one connection can bind multiple times (and/or do stuff unbound)
                    self.sasl_mech = None;
                }
            }
            ProtocolOp::BindResponse(resp) => {
                self.ldap_result_code = Some(resp.result.result_code.0);
                tx.result_code = Some(resp.result.result_code.0);
                // check msg_id
                // check for success
                if resp.result.result_code == ResultCode::Success {
                    // if SASL authentication succeeded, SASL layers are now active
                    if self.sasl_mech.is_some() {
                        self.has_sasl_layers = true;
                    }
                } else {
                    self.bind_dn = None;
                }
            }
            ProtocolOp::ExtendedRequest(req) => {
                self.ldap_request = Some(msg.message_id);
                // check for STARTTLS
                if req.request_name.0 == "1.3.6.1.4.1.1466.20037" {
                    self.tls_request = Some(msg.message_id);
                }
            }
            ProtocolOp::ExtendedResponse(res) => {
                if let Some(req_id) = self.tls_request {
                    self.ldap_result_code = Some(res.result.result_code.0);
                    tx.result_code = Some(res.result.result_code.0);
                    if res.result.result_code == ResultCode::Success && msg.message_id == req_id {
                        self.has_starttls = true;
                        self.tls_parser = Some(TlsParser::new(b"LDAP/TLS"));
                    }
                }
            }
            ProtocolOp::SearchRequest(_)
            | ProtocolOp::ModifyRequest(_)
            | ProtocolOp::AddRequest(_)
            | ProtocolOp::ModDnRequest(_)
            | ProtocolOp::CompareRequest(_)
            | ProtocolOp::AbandonRequest(_) => {
                self.ldap_request = Some(msg.message_id);
            }
            ProtocolOp::ModifyResponse(r) => {
                self.ldap_result_code = Some(r.result.result_code.0);
                tx.result_code = Some(r.result.result_code.0);
            }
            ProtocolOp::SearchResultDone(r)
            | ProtocolOp::AddResponse(r)
            | ProtocolOp::ModDnResponse(r)
            | ProtocolOp::CompareResponse(r) => {
                self.ldap_result_code = Some(r.result_code.0);
                tx.result_code = Some(r.result_code.0);
            }
            _ => (),
        }
    }
}

impl LDAPTransaction {
    pub fn new(message_id: MessageID, tx_op: ProtocolOpTag, bind_dn: &Option<String>) -> Self {
        LDAPTransaction {
            message_id,
            tx_op,
            result_code: None,
            bind_dn: bind_dn.clone(),
        }
    }
}

const COMMON_LDAP_PORTS: &[u16] = &[389, 3268];

pub fn ldap_probe(i: &[u8], l4info: &L4Info) -> ProbeResult {
    if i.len() <= 2 {
        return ProbeResult::Unsure;
    }
    // debug!("Probing for LDAP");
    if parse_ldap_message(i).is_ok() {
        if COMMON_LDAP_PORTS.contains(&l4info.src_port)
            || COMMON_LDAP_PORTS.contains(&l4info.dst_port)
        {
            ProbeResult::Certain
        } else {
            ProbeResult::Unsure
        }
    } else {
        ProbeResult::NotForUs
    }
}

fn check_ldap_message_complete(i: &[u8]) -> BerResult<()> {
    let (i, header) = ber_read_element_header(i)?;
    let len = header.len.primitive()?;
    if i.len() >= len {
        Ok((i, ()))
    } else {
        Err(BerError::InvalidLength.into())
    }
}
