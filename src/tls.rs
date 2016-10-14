extern crate libc;

use std;
use std::mem;
use libc::c_char;
use std::ffi::CStr;

use nom::*;

use rparser::*;

use tls_parser::tls::{TlsMessage,TlsMessageHandshake,parse_tls_raw_record,parse_tls_record_with_header};
use tls_parser::tls_ciphers::TlsCipherSuite;
use tls_parser::tls_extensions::parse_tls_extensions;
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

    cipher: u16,
    state: TlsState,

    /// Handshake defragmentation buffer
    buffer: Vec<u8>,
}

impl<'a> TlsParserState<'a> {
    pub fn new(i: &'a[u8]) -> TlsParserState<'a> {
        TlsParserState{
            o:Some(i),
            events:Vec::new(),
            cipher:0,
            state:TlsState::None,
            // capacity is the amount of space allocated, which means elements can be added
            // without reallocating the vector
            buffer:Vec::with_capacity(16384),
        }
    }

    fn append_buffer<'b>(self: &mut TlsParserState<'a>, buf: &'b[u8]) {
        self.buffer.extend_from_slice(&buf);
    }

    /// Message-level TLS parsing
    fn handle_parsed_tls_msg(self: &mut TlsParserState<'a>, msg: &TlsMessage) -> u32 {
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
        // extract variables
        match *msg {
            TlsMessage::Handshake(ref m) => {
                match *m {
                    TlsMessageHandshake::ClientHello(ref content) => {
                        let ext = parse_tls_extensions(content.ext.unwrap_or(b""));
                        debug!("ext {:?}", ext);
                    },
                    TlsMessageHandshake::ServerHello(ref content) => {
                        self.cipher = content.cipher;
                        match TlsCipherSuite::from_id(content.cipher) {
                            Some(c) => debug!("Selected cipher: {:?}", c),
                            _ => warn!("Unknown cipher 0x{:x}", content.cipher),
                        };
                        let ext = parse_tls_extensions(content.ext.unwrap_or(b""));
                        debug!("extensions: {:?}", ext);
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

    fn parse(this: &mut TlsParserState, i: &[u8], direction: u8) -> u32 {
        debug!("[TLS->parse: direction={}, len={}]",direction,i.len());

        if i.len() == 0 {
            // Connection closed ?
            return R_STATUS_OK;
        };

        let mut status = R_STATUS_OK;
        let mut v : Vec<u8>;
        let mut cur_i = i;

        while cur_i.len() > 0 {
            match parse_tls_raw_record(cur_i) {
                IResult::Done(rem, ref r) => {
                    // advance next parsing slice
                    cur_i = rem;
                    // Record length must not be greater than 2^14 ([RFC5246] section 6.2.1)
                    if r.hdr.len > 16384 {
                        this.events.push(TlsParserEvents::RecordOverflow as u32);
                        status |= R_STATUS_EVENTS;
                        continue;
                    };
                    // XXX record may be compressed
                    // Check if a record is being defragmented
                    let buffer = match this.buffer.len() {
                        0 => r.data,
                        _ => {
                            v = this.buffer.split_off(0);
                            // sanity check vector length to avoid memory exhaustion
                            // maximum length may be 2^24 (handshake message)
                            if this.buffer.len() + r.data.len() > 16777216 {
                                this.events.push(TlsParserEvents::RecordOverflow as u32);
                                status |= R_STATUS_EVENTS;
                                continue;
                            };
                            v.extend_from_slice(r.data);
                            v.as_slice()
                        },
                    };
                    // do not parse if session is encrypted
                    if this.state == TlsState::ClientChangeCipherSpec {
                        continue;
                    };
                    // XXX Parse one message at a time ?
                    // Parse record contents as plaintext
                    match parse_tls_record_with_header(buffer,r.hdr.clone()) {
                        IResult::Done(rem2,ref msg_list) => {
                            for msg in msg_list {
                                status |= this.handle_parsed_tls_msg(msg);
                            };
                            if rem2.len() > 0 {
                                warn!("extra bytes in TLS record: {:?}",rem2);
                                this.events.push(TlsParserEvents::RecordWithExtraBytes as u32);
                                status |= R_STATUS_EVENTS;
                            };
                        }
                        IResult::Incomplete(_) => {
                            debug!("Defragmentation required (TLS record)");
                            // Record is fragmented
                            this.append_buffer(r.data);
                        },
                        IResult::Error(e) => { warn!("parse_tls_record_with_header failed: {:?}",e); break; },
                    };
                },
                IResult::Incomplete(_) => {
                    warn!("Fragmentation required (TCP level ?) {:?}", cur_i);
                    this.events.push(TlsParserEvents::RecordIncomplete as u32);
                    status |= R_STATUS_EVENTS;
                    break;
                },
                IResult::Error(e) => { warn!("Parsing failed: {:?}",e); break; },
            }
        };

        status
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
pub extern fn rusticata_tls_get_cipher(ptr: *mut libc::c_char) -> u32
// or
// pub extern fn rusticata_tls_get_cipher<'a>(this: &TlsParserState<'a>) -> u32
// but this gives a warning:
// warning: generic functions must be mangled, #[warn(no_mangle_generic_items)] on by default
{
    let this: &Box<TlsParserState> = unsafe { mem::transmute(ptr) };
    this.cipher as u32
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

