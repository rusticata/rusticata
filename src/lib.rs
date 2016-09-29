extern crate libc;

#[macro_use]
extern crate nom;

#[macro_use]
extern crate log;

use log::LogLevelFilter;

extern crate tls_parser;

const SURICATA_RUST_MAGIC : u32 = 0x1234;

pub use common::*;
#[macro_use]
pub mod common;

pub use logger::*;
pub mod logger;

pub use rparser::*;
#[macro_use]
pub mod rparser;

pub use tls::*;
pub mod tls;

use tls_parser::tls_ciphers::CIPHERS;

#[no_mangle]
pub extern "C" fn rusticata_init(config: &'static mut SuricataConfig) -> i32 {
    // println!("Hello from rust");

    assert!(std::ptr::null_mut() != config);
    unsafe { suricata_config = Some(config) };

    assert_eq!(config.magic,SURICATA_RUST_MAGIC);

    let log_level = match config.log_level {
        0...4 => LogLevelFilter::Error,
        5 => LogLevelFilter::Warn,
        6...7 => LogLevelFilter::Info,
        8...11 => LogLevelFilter::Debug,
        _ => LogLevelFilter::Off,
    };

    logger::init(log_level).unwrap();

    info!("Rusticata TLS parser ready, {} ciphers loaded",CIPHERS.len());

    error!("test error");
    info!("test info");
    debug!("test debug");

    0
}
