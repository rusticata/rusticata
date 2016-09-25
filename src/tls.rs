extern crate libc;

use std;
use libc::c_char;
use std::ffi::CStr;

use std::io::Write;
use std::io::stdout;

use nom::*;

use tls_parser::tls::{TlsMessage,TlsMessageHandshake,tls_parser_many};
use tls_parser::tls_ciphers::TlsCipherSuite;
use tls_parser::tls_extensions::parse_tls_extensions;
use der_parser::der::parse_der;


pub struct TlsParserState<'a> {
    pub o: Option<&'a[u8]>,

    cipher: u16,
}

impl<'a> TlsParserState<'a> {
    pub fn new(i: &'a[u8]) -> TlsParserState<'a> {
        TlsParserState{o:Some(i),cipher:0}
    }

    fn send(&self, value: i32) -> bool {
        println!("=============================================================");
        println!("inner send: {}", value);
        println!("o: {:?}", self.o);
        println!("cipher: {:?}", self.cipher);
        println!("=============================================================");
        let _ = stdout().flush();
        true
    }
}

impl<'a> Drop for TlsParserState<'a> {
    fn drop(&mut self) {
        println!("DROP");
    }
}

#[no_mangle]
pub extern "C" fn rusticata_new_tls_parser_state<'a>() -> Box<TlsParserState<'a>> {
    Box::new(TlsParserState::new(b"blah"))
}

#[no_mangle]
pub extern fn rusticata_free_tls_parser_state<'a>(_: Box<TlsParserState<'a>>)
{
    println!("rusticata_free_tls_parser_state()");
}

#[no_mangle]
pub extern fn rusticata_use_tls_parser_state<'a>(this: &TlsParserState<'a>, value: i32) -> bool
{
    println!("rusticata_use_tls_parser_state({:?})", value);
    this.send(value)
}

#[no_mangle]
pub extern fn rusticata_tls_get_cipher<'a>(this: &TlsParserState<'a>) -> u32
{
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





#[no_mangle]
pub extern "C" fn rusticata_parse_der(value: *const c_char, len: u32) -> i32 {
    SCLogDebug!("[rust] rusticata_parse_der");

    let data_len = len as usize;
    let data : &[u8] = unsafe { std::slice::from_raw_parts(value as *mut u8, data_len) };

    let d = parse_der(data);
    SCLogDebug!(format!("d: {:?}", d).as_str());

    0
}

#[no_mangle]
pub extern "C" fn rusticata_tls_decode<'a>(direction: u8, value: *const c_char, len: u32, this: &'a mut TlsParserState<'a>) -> &'a mut TlsParserState<'a> {
    SCLogDebug!("[rust] suri_tls_decode");

    let data_len = len as usize;
    let data : &[u8] = unsafe { std::slice::from_raw_parts(value as *mut u8, data_len) };

    SCLogDebug!(format!("  direction: {}", direction).as_str());
    SCLogDebug!(format!("  len: {}", data_len).as_str());
    SCLogDebug!(format!("  data: {:?}", data).as_str());


    let d = tls_parser_many(data);
    SCLogDebug!(format!("d: {:?}", d).as_str());


    // XXX match d with nom::IResult::Done, check if ServerHello, and print selected cipher
    match d {
        IResult::Done(rem,p) => {
            SCLogDebug!(format!("TLS parser successful {} element(s)", p.len()).as_str());
            for ref record in &p {
                SCLogDebug!(format!("{:?}", record).as_str());
                match record.msg {
                    TlsMessage::Handshake(ref m) => {
                        match *m {
                            TlsMessageHandshake::ClientHello(ref content) => {
                                let blah = parse_tls_extensions(content.ext);
                                SCLogDebug!(format!("ext {:?}", blah).as_str());
                            },
                            TlsMessageHandshake::ServerHello(ref content) => {
                                this.cipher = content.cipher;
                                match TlsCipherSuite::from_id(content.cipher) {
                                    Some(c) => SCLogDebug!(format!("Selected cipher: {:?}", c).as_str()),
                                    _ => SCLogWarning!(format!("Unknown ciphe 0x{:x}", content.cipher).as_str()),
                                };
                                let blah = parse_tls_extensions(content.ext);
                                SCLogDebug!(format!("extensions: {:?}", blah).as_str());
                            },
                            _ => (),
                        }
                    },
                    TlsMessage::Heartbeat(ref d) => {
                        if d.payload_len as usize > d.payload.len() {
                            SCLogWarning!(format!("Heartbeat message with incorrect length {}. Heartbleed attempt ?",d.payload.len()).as_str());
                        }
                    },
                    _ => (),
                }
            }
            if rem.len() > 0 { SCLogWarning!(format!("** unparsed ** {:?}",rem).as_str()); };
        },
        IResult::Error(e) => SCLogError!(format!("TLS parser reported an error: {:?}", e).as_str()),
        IResult::Incomplete(e) => SCLogError!(format!("TLS parser reported incomplete input: {:?}", e).as_str()),
    };

    this
}
