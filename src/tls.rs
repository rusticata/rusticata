extern crate libc;

use std;
use std::mem;
use libc::c_char;
use std::ffi::CStr;

use nom::*;

use rparser::*;

use tls_parser::tls::{TlsMessage,TlsMessageHandshake,TlsRecordType,TlsRawRecord,parse_tls_raw_record,parse_tls_record_with_header};
use tls_parser::tls_ciphers::*;
use tls_parser::tls_dh::*;
use tls_parser::tls_ec::*;
use tls_parser::tls_extensions::*;
use tls_parser::tls_sign_hash::*;
use tls_parser::tls_states::{TlsState,tls_state_transition};

// --------------------------------------------
// example implementation: TLS parser

#[repr(u32)]
pub enum TlsParserEvents {
    HeartbeatOverflow = 1,
    InvalidState = 2,

    RecordIncomplete = 3,
    RecordWithExtraBytes = 4,
    RecordOverflow = 5,
}

pub struct TlsParserState<'a> {
    pub o: Option<&'a[u8]>,

    events: Vec<u32>,

    compression: Option<u8>,
    cipher: Option<&'a TlsCipherSuite>,
    state: TlsState,

    kx_bits: Option<u32>,

    /// TCP segments defragmentation buffer
    tcp_buffer: Vec<u8>,

    /// Handshake defragmentation buffer
    buffer: Vec<u8>,

    has_signature_algorithms: bool,
}

impl<'a> TlsParserState<'a> {
    pub fn new(i: &'a[u8]) -> TlsParserState<'a> {
        TlsParserState{
            o:Some(i),
            events:Vec::new(),
            compression:None,
            cipher:None,
            state:TlsState::None,
            kx_bits: None,
            // capacity is the amount of space allocated, which means elements can be added
            // without reallocating the vector
            tcp_buffer:Vec::with_capacity(16384),
            buffer:Vec::with_capacity(16384),
            has_signature_algorithms:false,
        }
    }

    /// Message-level TLS parsing
    fn parse_message_level(self: &mut TlsParserState<'a>, msg: &TlsMessage) -> u32 {
        debug!("parse_message_level {:?}",msg);
        let mut status = R_STATUS_OK;
        if self.state == TlsState::ClientChangeCipherSpec {
            // Ignore records from now on, they are encrypted
            return status;
        };
        // update state machine
        match tls_state_transition(self.state, msg) {
            Ok(s)  => self.state = s,
            Err(_) => {
                self.state = TlsState::Invalid;
                self.events.push(TlsParserEvents::InvalidState as u32);
                status |= R_STATUS_EVENTS;
            },
        };
        debug!("TLS new state: {:?}",self.state);
        // extract variables
        match *msg {
            TlsMessage::Handshake(ref m) => {
                match *m {
                    TlsMessageHandshake::ClientHello(ref content) => {
                        let ext = parse_tls_extensions(content.ext.unwrap_or(b""));
                        match &ext {
                            &IResult::Done(_,ref l) => {
                                for extension in l {
                                    match *extension {
                                        TlsExtension::SignatureAlgorithms(_) => self.has_signature_algorithms = true,
                                        _ => (),
                                    }
                                }
                            },
                            e @ _ => error!("Could not parse extentions: {:?}",e),
                        };
                        debug!("ext {:?}", ext);
                    },
                    TlsMessageHandshake::ServerHello(ref content) => {
                        self.compression = Some(content.compression);
                        self.cipher = TlsCipherSuite::from_id(content.cipher);
                        match self.cipher {
                            Some(c) => {
                                debug!("Selected cipher: {:?}", c)
                            },
                            _ => warn!("Unknown cipher 0x{:x}", content.cipher),
                        };
                        let ext = parse_tls_extensions(content.ext.unwrap_or(b""));
                        debug!("extensions: {:?}", ext);
                    },
                    TlsMessageHandshake::Certificate(ref content) => {
                        debug!("cert chain length: {}",content.cert_chain.len());
                        for cert in &content.cert_chain {
                            debug!("cert: {:?}",cert);
                        }
                    },
                    TlsMessageHandshake::ServerKeyExchange(ref content) => {
                        // The SKE contains the chosen algorithm for the ephemeral key
                        match self.cipher {
                            None => (),
                            Some (c) => { self.kx_bits = rusticata_tls_get_kx_bits(c,content.parameters,self.has_signature_algorithms) },
                        }
                    },
                    _ => (),
                }
            },
            TlsMessage::Heartbeat(ref d) => {
                if d.payload_len as usize > d.payload.len() {
                    warn!("Heartbeat message with incorrect length {}. Heartbleed attempt ?",d.payload.len());
                    self.events.push(TlsParserEvents::HeartbeatOverflow as u32);
                    status |= R_STATUS_EVENTS;
                }
            },
            _ => (),
        }

        status
    }

    fn parse_record_level<'b>(self: &mut TlsParserState<'a>, r: &TlsRawRecord<'b>) -> u32 {
        let mut v : Vec<u8>;
        let mut status = R_STATUS_OK;

        debug!("parse_record_level {}",r.data.len());
        // debug!("{:?}",r.data);

        // only parse some message types
        match TlsRecordType::try_from_u8(r.hdr.record_type) {
            Ok(TlsRecordType::ChangeCipherSpec) => (),
            Ok(TlsRecordType::Handshake)        => (),
            _ => return status,
        }

        // Check if a record is being defragmented
        let record_buffer = match self.buffer.len() {
            0 => r.data,
            _ => {
                v = self.buffer.split_off(0);
                // sanity check vector length to avoid memory exhaustion
                // maximum length may be 2^24 (handshake message)
                if self.buffer.len() + r.data.len() > 16777216 {
                    self.events.push(TlsParserEvents::RecordOverflow as u32);
                    return R_STATUS_EVENTS;
                };
                v.extend_from_slice(r.data);
                v.as_slice()
            },
        };
        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            return status;
        };
        // XXX record may be compressed
        //
        // XXX Parse one message at a time ?
        // Parse record contents as plaintext
        match parse_tls_record_with_header(record_buffer,r.hdr.clone()) {
            IResult::Done(rem2,ref msg_list) => {
                for msg in msg_list {
                    status |= self.parse_message_level(msg);
                };
                if rem2.len() > 0 {
                    warn!("extra bytes in TLS record: {:?}",rem2);
                    self.events.push(TlsParserEvents::RecordWithExtraBytes as u32);
                    status |= R_STATUS_EVENTS;
                };
            }
            IResult::Incomplete(_) => {
                debug!("Defragmentation required (TLS record)");
                // Record is fragmented
                self.buffer.extend_from_slice(r.data);
            },
            IResult::Error(e) => { warn!("parse_tls_record_with_header failed: {:?}",e); status |= R_STATUS_FAIL; },
        };

        status
    }

    pub fn parse_tcp_level<'b>(self: &mut TlsParserState<'a>, i: &'b[u8]) -> u32 {
        let mut v : Vec<u8>;
        let mut status = R_STATUS_OK;
        debug!("parse_tcp_level ({})",i.len());
        // debug!("{:?}",i);
        // Check if TCP data is being defragmented
        let tcp_buffer = match self.tcp_buffer.len() {
            0 => i,
            _ => {
                v = self.tcp_buffer.split_off(0);
                // sanity check vector length to avoid memory exhaustion
                // maximum length may be 2^24 (handshake message)
                if self.tcp_buffer.len() + i.len() > 16777216 {
                    self.events.push(TlsParserEvents::RecordOverflow as u32);
                    return R_STATUS_EVENTS;
                };
                v.extend_from_slice(i);
                v.as_slice()
            },
        };
        // debug!("tcp_buffer ({})",tcp_buffer.len());
        let mut cur_i = tcp_buffer;
        while cur_i.len() > 0 {
            match parse_tls_raw_record(cur_i) {
                IResult::Done(rem, ref r) => {
                    // debug!("rem: {:?}",rem);
                    cur_i = rem;
                    status |= self.parse_record_level(r);
                },
                IResult::Incomplete(_) => {
                    debug!("Fragmentation required (TCP level)");
                    self.tcp_buffer.extend_from_slice(cur_i);
                    break;
                },
                IResult::Error(e) => { warn!("Parsing failed: {:?}",e); break },
            }
        };
        status
    }
}

r_declare_state_new!(r_tls_state_new,TlsParserState,b"TLS parser");
r_declare_state_free!(r_tls_state_free,TlsParserState,{ () });

struct TlsParser;

impl<'a> RParser<TlsParserState<'a>> for TlsParser {
    fn new_state() -> TlsParserState<'a> {
        TlsParserState::new(b"TLS parser")
    }

    fn probe(i: &[u8]) -> bool {
        if i.len() <= 2 { return false; }
        // first byte is record type (between 0x14 and 0x17, 0x16 is handhake)
        // second is TLS version major (0x3)
        // third is TLS version minor (0x0 for SSLv3, 0x1 for TLSv1.0, etc.)
        match (i[0],i[1],i[2]) {
            (0x14...0x17,0x03,0...3) => true,
            _ => false,
        }
    }

    fn parse(parser_state: &mut TlsParserState, i: &[u8], direction: u8) -> u32 {
        debug!("[TLS->parse: direction={}, len={}]",direction,i.len());

        if i.len() == 0 {
            // Connection closed ?
            return R_STATUS_OK;
        };

        parser_state.parse_tcp_level(i)
    }
}

r_implement_probe!(r_tls_probe,TlsParser);
r_implement_parse!(r_tls_parse,TlsParser);

// --------------------------------------------





#[no_mangle]
pub extern fn r_tls_get_next_event(ptr: *mut libc::c_char) -> u32
// pub extern fn r_tls_get_next_event<'a>(this: &mut TlsParserState<'a>) -> u32
{
    assert!(!ptr.is_null());
    let this: &mut TlsParserState = unsafe { mem::transmute(ptr) };
    match this.events.pop() {
        None     => 0xffffffff,
        Some(ev) => ev,
    }
}

#[no_mangle]
// pub extern fn rusticata_tls_get_cipher(ptr: *mut libc::c_char) -> u32
// or
pub extern fn rusticata_tls_get_cipher<'a>(this: &TlsParserState<'a>) -> u32
// but this gives a warning:
// warning: generic functions must be mangled, #[warn(no_mangle_generic_items)] on by default
{
    // let this: &Box<TlsParserState> = unsafe { mem::transmute(ptr) };
    match this.cipher {
        None    => 0,
        Some(c) => c.id.into(),
    }
}

#[no_mangle]
pub extern fn rusticata_tls_get_compression<'a>(this: &TlsParserState<'a>) -> u32
{
    this.compression.unwrap_or(0) as u32
}

#[no_mangle]
pub extern fn rusticata_tls_get_dh_key_bits<'a>(this: &TlsParserState<'a>) -> u32
{
    this.kx_bits.unwrap_or(0) as u32
}





#[no_mangle]
pub extern fn rusticata_tls_cipher_of_string(value: *const c_char) -> u32
{
    let c_str = unsafe { CStr::from_ptr(value) };
    let s = c_str.to_str().unwrap();
    match TlsCipherSuite::from_name(s) {
        Some(c) => c.id as u32,
        None    => 0,
    }
}

#[no_mangle]
pub extern fn rusticata_tls_kx_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.kx.clone() as u32,
        None    => 0,
    }
}

#[no_mangle]
pub extern fn rusticata_tls_au_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.au.clone() as u32,
        None    => 0,
    }
}

#[no_mangle]
pub extern fn rusticata_tls_enc_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.enc.clone() as u32,
        None    => 0,
    }
}

#[no_mangle]
pub extern fn rusticata_tls_encmode_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.enc_mode.clone() as u32,
        None    => 0,
    }
}

#[no_mangle]
pub extern fn rusticata_tls_mac_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.mac.clone() as u32,
        None    => 0,
    }
}

fn rusticata_tls_get_kx_bits(cipher: &TlsCipherSuite, parameters: &[u8], extended: bool) -> Option<u32> {
    match cipher.kx {
        TlsCipherKx::Ecdhe |
        TlsCipherKx::Ecdh    => {
            // Signed ECDH params
            match parse_content_and_signature(parameters,parse_ecdh_params,extended) {
                IResult::Done(_,ref parsed) => {
                    debug!("ECDHE Parameters: {:?}",parsed);
                    info!("Temp key: using cipher {:?}",parsed.0.curve_params);
                    match &parsed.0.curve_params.params_content {
                        &ECParametersContent::NamedCurve(curve_id) => {
                            match named_curve_of_u16(curve_id) {
                                None => (),
                                Some(named_curve) => {
                                    let key_bits = named_curve.key_bits().unwrap_or(0);
                                    debug!("NamedCurve: {:?}, key={:?} bits",named_curve,key_bits);
                                    return Some(key_bits as u32);
                                },
                            }
                        },
                        c @ _ => info!("Request for key_bits of unknown curve {:?}",c),
                    }
                },
                e @ _ => error!("Could not parse ECDHE parameters {:?}",e),
            };
            ()
        },
        TlsCipherKx::Dhe => {
            // Signed DH params
            match parse_content_and_signature(parameters,parse_dh_params,extended) {
                IResult::Done(_,ref parsed) => {
                    debug!("DHE Parameters: {:?}",parsed);
                    info!("Temp key: using DHE size_p={:?} bits",parsed.0.dh_p.len() * 8);
                    return Some((parsed.0.dh_p.len() * 8) as u32);
                },
                e @ _ => error!("Could not parse DHE parameters {:?}",e),
            };
            ()
        },
        TlsCipherKx::Dh => {
            // Anonymous DH params
            match parse_dh_params(parameters) {
                IResult::Done(_,ref parsed) => {
                    debug!("ADH Parameters: {:?}",parsed);
                    info!("Temp key: using ADH size_p={:?} bits",parsed.dh_p.len() * 8);
                    return Some((parsed.dh_p.len() * 8) as u32);
                },
                e @ _ => error!("Could not parse ADH parameters {:?}",e),
            };
            ()
        },
        ref kx @ _ => debug!("unhandled KX algorithm: {:?}",kx),
    };
    None
}
