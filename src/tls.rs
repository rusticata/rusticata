extern crate libc;

use std;
use std::mem;
use libc::c_char;
use std::ffi::CStr;

use std::io::Write;
use std::io::stdout;

use nom::*;

use rparser::*;

use tls_parser::tls::{TlsMessage,TlsMessageHandshake,tls_parser_many};
use tls_parser::tls_ciphers::TlsCipherSuite;
use tls_parser::tls_extensions::parse_tls_extensions;

// --------------------------------------------
// example implementation: TLS parser

#[repr(u32)]
pub enum TlsParserEvents {
    HeartbeatOverflow = 1,
}

pub struct TlsParserState<'a> {
    pub o: Option<&'a[u8]>,

    events: Vec<u32>,

    cipher: u16,
}

impl<'a> TlsParserState<'a> {
    pub fn new(i: &'a[u8]) -> TlsParserState<'a> {
        TlsParserState{o:Some(i),events:Vec::new(),cipher:0}
    }

    fn send(&self, value: i32) -> bool {
        debug!("=============================================================");
        debug!("inner send: {}", value);
        debug!("o: {:?}", self.o);
        debug!("cipher: {:?}", self.cipher);
        debug!("=============================================================");
        let _ = stdout().flush();
        true
    }
}

r_declare_state_new!(r_tls_state_new,TlsParserState,b"blah");
r_declare_state_free!(r_tls_state_free,TlsParserState,{ debug!("Drop TlsParserState"); });

struct TlsParser;

impl<'a> RParser<TlsParserState<'a>> for TlsParser {
    fn new_state() -> TlsParserState<'a> {
        TlsParserState::new(b"blah")
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
        debug!("[TLS->parse]");
        debug!("  direction: {}", direction);
        debug!("  len: {}", i.len());
        debug!("  data: {:?}", i);


        let d = tls_parser_many(i);
        debug!("d: {:?}", d);

        let mut status = R_STATUS_OK;

        match d {
            IResult::Done(rem,p) => {
                debug!("TLS parser successful {} element(s)", p.len());
                for ref record in &p {
                    debug!("{:?}", record);
                    for msg in &record.msg {
                        match *msg {
                            TlsMessage::Handshake(ref m) => {
                                match *m {
                                    TlsMessageHandshake::ClientHello(ref content) => {
                                        let blah = parse_tls_extensions(content.ext.unwrap_or(b""));
                                        debug!("ext {:?}", blah);
                                    },
                                    TlsMessageHandshake::ServerHello(ref content) => {
                                        this.cipher = content.cipher;
                                        match TlsCipherSuite::from_id(content.cipher) {
                                            Some(c) => debug!("Selected cipher: {:?}", c),
                                            _ => warn!("Unknown cipher 0x{:x}", content.cipher),
                                        };
                                        let blah = parse_tls_extensions(content.ext.unwrap_or(b""));
                                        debug!("extensions: {:?}", blah);
                                    },
                                    _ => (),
                                }
                            },
                            TlsMessage::Heartbeat(ref d) => {
                                if d.payload_len as usize > d.payload.len() {
                                    warn!("Heartbeat message with incorrect length {}. Heartbleed attempt ?",d.payload.len());
                                    this.events.push(TlsParserEvents::HeartbeatOverflow as u32);
                                    println!("{:?}", this.events);
                                    status |= R_STATUS_EVENTS;
                                }
                            },
                            _ => (),
                        }
                    }
                }
                if rem.len() > 0 { warn!("** unparsed ** {:?}",rem); };
            },
            IResult::Error(e) => error!("TLS parser reported an error: {:?}", e),
            IResult::Incomplete(e) => error!("TLS parser reported incomplete input: {:?}", e),
        };

        println!("status: {:x}",status);
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
    debug!("r_tls_get_next_event");
    println!("{:?}", this.events);
    match this.events.pop() {
        None     => 0xffff,
        Some(ev) => ev,
    }
}

#[no_mangle]
pub extern fn rusticata_use_tls_parser_state(ptr: *mut libc::c_char, value: i32) -> bool
{
    let this: &Box<TlsParserState> = unsafe { mem::transmute(ptr) };
    debug!("rusticata_use_tls_parser_state({:?})", value);
    this.send(value)
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

