extern crate libc;

#[macro_use]
extern crate nom;
use nom::*;

use libc::{c_char,c_void};

extern crate tls_parser;
use tls_parser::tls::{TlsMessage,TlsMessageHandshake,tls_parser_many};
use tls_parser::tls_ciphers::TlsCipherSuite;
use tls_parser::tls_extensions::parse_tls_extensions;
use tls_parser::der::parse_der;

// //extern crate untrusted;
// //extern crate webpki;
// //use webpki::{EndEntityCert, TrustAnchor};


type LogCallback = extern "C" fn (lvl: u32, file: *const c_void, line: u32, func: *const c_void, err: u32, msg: *const c_void);
// 
// static RAW_LOG : *mut LogCallback = ||{};
// 
// #[macro_export]
// macro_rules! SCLogMessage (
//   ($lvl:expr, $msg:expr) => (
//     {
//         unsafe {  }
//     }
//   );
//   ($lvl:expr, $msg:expr) => (
//     SCLogMessage!($i, $cond, $err);
//   );
// );

#[repr(C)]
pub struct SuricataConfig {
    magic: u32,
    log: LogCallback,
    // other members
}

const SURICATA_RUST_MAGIC : u32 = 0x1234;

pub static mut suricata_config : Option<&'static SuricataConfig> = None;

pub fn raw_sclog_message<'a,'b>(lvl: u32, msg: &'a str, file: &'b str, line: u32) {
    match unsafe{suricata_config} {
        None => println!("({}:{}) [{}]: {}", file, line, lvl, msg),
        Some(c) => {
            let c_file = file.as_ptr() as *const c_void;
            let c_func = "<rust function>".as_ptr() as *const c_void;
            let c_ptr = msg.as_ptr() as *const c_void;

            (c.log)(lvl, c_file, line, c_func, 0, c_ptr);
        },
    };
}

#[macro_export]
macro_rules! SCLogMessage (
  ($lvl:expr, $msg:expr, $file:expr, $line:expr) => (
    {
        raw_sclog_message($lvl,$msg, $file, $line)
    }
  );
  ($lvl:expr, $msg:expr) => (
    SCLogMessage!($lvl, $msg, file!(), line!());
  );
);

#[macro_export]
macro_rules! SCLogAlert (
  ($msg:expr) => ( { SCLogMessage!(2,$msg); });
  ($msg:expr) => ( SCLogAlert!($msg););
);

#[macro_export]
macro_rules! SCLogError (
  ($msg:expr) => ( { SCLogMessage!(4,$msg); });
  ($msg:expr) => ( SCLogError!($msg););
);

#[macro_export]
macro_rules! SCLogWarning (
  ($msg:expr) => ( { SCLogMessage!(5,$msg); });
  ($msg:expr) => ( SCLogWarning!($msg););
);

#[macro_export]
macro_rules! SCLogNotice (
  ($msg:expr) => ( { SCLogMessage!(6,$msg); });
  ($msg:expr) => ( SCLogNotice!($msg););
);

#[macro_export]
macro_rules! SCLogInfo (
  ($msg:expr) => ( { SCLogMessage!(7,$msg); });
  ($msg:expr) => ( SCLogInfo!($msg););
);

#[macro_export]
macro_rules! SCLogDebug (
  ($msg:expr) => ( { SCLogMessage!(10,$msg); });
  ($msg:expr) => ( SCLogDebug!($msg););
);

#[no_mangle]
pub extern "C" fn suri_init(config: &'static mut SuricataConfig) -> i32 {
    // println!("Hello from rust");

    assert!(std::ptr::null_mut() != config);
    unsafe { suricata_config = Some(config) };

    assert_eq!(config.magic,SURICATA_RUST_MAGIC);

    SCLogError!("test error");
    SCLogInfo!("test info");
    SCLogDebug!("test debug");

    0
}



#[no_mangle]
pub extern "C" fn suri_parse_der(value: *const c_char, len: u32) -> i32 {
    SCLogDebug!("Hello from rust");

    let data_len = len as usize;
    let data : &[u8] = unsafe { std::slice::from_raw_parts(value as *mut u8, data_len) };

    let d = parse_der(data);
    SCLogDebug!(format!("d: {:?}", d).as_str());

    0
}

#[no_mangle]
pub extern "C" fn suri_ssl_decode(direction: u8, value: *const c_char, len: u32) -> i32 {
    SCLogDebug!("[rust] suri_ssl_decode");

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
