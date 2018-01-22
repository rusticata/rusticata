extern crate libc;

extern crate nom;

#[macro_use]
extern crate log;

use log::LogLevelFilter;

extern crate num_traits;
extern crate itertools;

extern crate md5;

extern crate ipsec_parser;
extern crate ntp_parser;
extern crate openvpn_parser;
extern crate radius_parser;
extern crate snmp_parser;
extern crate ssh_parser;
extern crate tls_parser;
extern crate x509_parser;

const SURICATA_RUST_MAGIC : u32 = 0x1234;

pub use common::*;
#[macro_use]
pub mod common;

pub use logger::*;
pub mod logger;

pub use rparser::*;
#[macro_use]
pub mod rparser;

mod ipsec;
pub use ipsec::*;

pub use ntp::*;
pub mod ntp;

mod openvpn;
pub use openvpn::{OpenVPNTCPParser,openvpn_tcp_probe};
mod openvpn_udp;
pub use openvpn_udp::{OpenVPNUDPParser,openvpn_udp_probe};

mod radius;
pub use radius::RadiusParser;

mod snmp;
pub use snmp::{SnmpParser,snmp_probe};
mod snmpv3;
pub use snmpv3::{SnmpV3Parser,snmpv3_probe};

mod ssh;
pub use ssh::{SSHParser,ssh_probe};

pub use tls::*;
pub mod tls;

use tls_parser::tls_ciphers::CIPHERS;

/// Rusticata crate init function
///
/// This function **must** be called by the client application (Suricata) to initialize the
/// rusticata library functions.
///
/// The argument is a pointer to a configuration structure, containing a magic number,
/// a pointer to the C log function, and the log level of the client application.
/// Rusticata will use the same log level, and configure a Rust Logger object to send logs
/// to Suricata.
///
/// The lifetime of the configuration **must** be greater or equal to the one of the
/// rusticata crate.
#[no_mangle]
pub extern "C" fn rusticata_init(config: &'static mut SuricataConfig) -> i32 {
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

    0
}
