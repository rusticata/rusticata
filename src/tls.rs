extern crate libc;

use std;
use libc::c_char;

use nom::*;

use tls_parser::tls::{TlsMessage,TlsMessageHandshake,tls_parser_many};
use tls_parser::tls_ciphers::TlsCipherSuite;
use tls_parser::tls_extensions::parse_tls_extensions;
use tls_parser::der::parse_der;



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
pub extern "C" fn rusticata_tls_decode(direction: u8, value: *const c_char, len: u32) -> i32 {
    SCLogDebug!("[rust] suri_tls_decode");

    let data_len = len as usize;
    let data : &[u8] = unsafe { std::slice::from_raw_parts(value as *mut u8, data_len) };

    SCLogDebug!(format!("  direction: {}\0", direction).as_str());
    SCLogDebug!(format!("  len: {}\0", data_len).as_str());
    SCLogDebug!(format!("  data: {:?}\0", data).as_str());


    let d = tls_parser_many(data);
    SCLogDebug!(format!("d: {:?}\0", d).as_str());


    // XXX match d with nom::IResult::Done, check if ServerHello, and print selected cipher
    match d {
        IResult::Done(rem,p) => {
            SCLogDebug!(format!("TLS parser successful {} element(s)\0", p.len()).as_str());
            for ref record in &p {
                SCLogDebug!(format!("{:?}\0", record).as_str());
                match record.msg {
                    TlsMessage::Handshake(ref m) => {
                        match *m {
                            TlsMessageHandshake::ClientHello(ref content) => {
                                let blah = parse_tls_extensions(content.ext);
                                SCLogDebug!(format!("ext {:?}\0", blah).as_str());
                            },
                            TlsMessageHandshake::ServerHello(ref content) => {
                                let lu /* cipher */ : TlsCipherSuite = content.cipher.into();
                                SCLogDebug!(format!("Selected cipher: {:?}\0", lu).as_str());
                                let blah = parse_tls_extensions(content.ext);
                                SCLogDebug!(format!("ext {:?}\0", blah).as_str());
                            },
                            _ => (),
                        }
                    },
                    _ => (),
                }
            }
            if rem.len() > 0 { SCLogWarning!(format!("** unparsed ** {:?}\0",rem).as_str()); };
        },
        IResult::Error(e) => SCLogError!(format!("TLS parser reported an error: {:?}\0", e).as_str()),
        IResult::Incomplete(e) => SCLogError!(format!("TLS parser reported incomplete input: {:?}\0", e).as_str()),
    }

    0
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
