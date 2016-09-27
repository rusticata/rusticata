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
        debug!("=============================================================");
        debug!("inner send: {}", value);
        debug!("o: {:?}", self.o);
        debug!("cipher: {:?}", self.cipher);
        debug!("=============================================================");
        let _ = stdout().flush();
        true
    }
}

impl<'a> Drop for TlsParserState<'a> {
    fn drop(&mut self) {
        debug!("DROP");
    }
}

#[no_mangle]
pub extern "C" fn rusticata_new_tls_parser_state<'a>() -> Box<TlsParserState<'a>> {
    Box::new(TlsParserState::new(b"blah"))
}

#[no_mangle]
pub extern fn rusticata_free_tls_parser_state<'a>(_: Box<TlsParserState<'a>>)
{
    debug!("rusticata_free_tls_parser_state()");
}

#[no_mangle]
pub extern fn rusticata_use_tls_parser_state<'a>(this: &TlsParserState<'a>, value: i32) -> bool
{
    debug!("rusticata_use_tls_parser_state({:?})", value);
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
pub extern "C" fn rusticata_probe_tls(input: *const c_char, input_len: u32, _offset: *const c_char) -> u32 {
    let data_len = input_len as usize;
    let data : &[u8] = unsafe { std::slice::from_raw_parts(input as *mut u8, data_len) };

    if data.len() > 2 {
        // first byte is record type (between 0x14 and 0x17, 0x16 is handhake)
        // second is TLS version major (0x3)
        // third is TLS version minor (0x0 for SSLv3, 0x1 for TLSv1.0, etc.)
        match (data[0],data[1],data[2]) {
            (0x14...0x17,0x03,0...3) => return 1,
            _ => (),
        };
    };

    return 0;
}

#[no_mangle]
pub extern "C" fn rusticata_parse_der(value: *const c_char, len: u32) -> i32 {
    debug!("[rust] rusticata_parse_der");

    let data_len = len as usize;
    let data : &[u8] = unsafe { std::slice::from_raw_parts(value as *mut u8, data_len) };

    let d = parse_der(data);
    debug!("d: {:?}", d);

    0
}

#[no_mangle]
pub extern "C" fn rusticata_tls_decode<'a>(direction: u8, value: *const c_char, len: u32, this: &'a mut TlsParserState<'a>) -> &'a mut TlsParserState<'a> {
    debug!("[rust] suri_tls_decode");

    let data_len = len as usize;
    let data : &[u8] = unsafe { std::slice::from_raw_parts(value as *mut u8, data_len) };

    debug!("  direction: {}", direction);
    debug!("  len: {}", data_len);
    debug!("  data: {:?}", data);


    let d = tls_parser_many(data);
    debug!("d: {:?}", d);


    // XXX match d with nom::IResult::Done, check if ServerHello, and print selected cipher
    match d {
        IResult::Done(rem,p) => {
            debug!("TLS parser successful {} element(s)", p.len());
            for ref record in &p {
                debug!("{:?}", record);
                match record.msg {
                    TlsMessage::Handshake(ref m) => {
                        match *m {
                            TlsMessageHandshake::ClientHello(ref content) => {
                                let blah = parse_tls_extensions(content.ext);
                                debug!("ext {:?}", blah);
                            },
                            TlsMessageHandshake::ServerHello(ref content) => {
                                this.cipher = content.cipher;
                                match TlsCipherSuite::from_id(content.cipher) {
                                    Some(c) => debug!("Selected cipher: {:?}", c),
                                    _ => warn!("Unknown cipher 0x{:x}", content.cipher),
                                };
                                let blah = parse_tls_extensions(content.ext);
                                debug!("extensions: {:?}", blah);
                            },
                            _ => (),
                        }
                    },
                    TlsMessage::Heartbeat(ref d) => {
                        if d.payload_len as usize > d.payload.len() {
                            warn!("Heartbeat message with incorrect length {}. Heartbleed attempt ?",d.payload.len());
                        }
                    },
                    _ => (),
                }
            }
            if rem.len() > 0 { warn!("** unparsed ** {:?}",rem); };
        },
        IResult::Error(e) => error!("TLS parser reported an error: {:?}", e),
        IResult::Incomplete(e) => error!("TLS parser reported incomplete input: {:?}", e),
    };

    this
}
