//! TLS parser
//!
//! The TLS parser is based on the `tls-parser` crate to parse the handshake phase
//! of a TLS connection. It stores the selected parameters (like the negociated ciphersuite,
//! compression method, etc.) in the parser state.
//!
//! It handles defragmentation (TCP chunks, or TLS record and messages fragmentation), and
//! updates the TLS state machine to detect invalid transitions (for ex, unexpected messages,
//! or messages sent in wrong order).
//!
//! When the session becomes encrypted, messages are not parsed anymore.

extern crate libc;

use std;
use std::mem;
use libc::c_char;

use nom::*;

use num_traits::cast::FromPrimitive;
use itertools::Itertools;

use md5;

use rparser::*;
use x509_parser::parse_x509_der;

use tls_parser::tls::*;
use tls_parser::tls_ciphers::*;
use tls_parser::tls_dh::*;
use tls_parser::tls_ec::*;
use tls_parser::tls_extensions::*;
use tls_parser::tls_sign_hash::*;
use tls_parser::tls_states::{TlsState,tls_state_transition};

/// TLS parser events
#[repr(u32)]
pub enum TlsParserEvents {
    /// Heartbeat record wrong length (heartbleed attack)
    HeartbeatOverflow = 1,
    /// Transition not allowed by TLS state machine
    InvalidState = 2,

    /// Incomplete record
    RecordIncomplete = 3,
    /// Record contains extra bytes after message(s)
    RecordWithExtraBytes = 4,
    /// TLS record exceeds allowed size (2^24 bytes)
    RecordOverflow = 5,
}

/// TLS parser state
pub struct TlsParser<'a> {
    _o: Option<&'a[u8]>,

    /// Events raised during parsing. These events should be read (and removed)
    /// by the client application after checking the parsing return value.
    pub events: Vec<u32>,

    /// Selected compression method
    ///
    /// Only valid after the ServerHello message
    pub compression: Option<TlsCompressionID>,
    /// Selected ciphersuite
    ///
    /// Only valid after the ServerHello message
    pub cipher: Option<&'a TlsCipherSuite>,
    /// TLS state
    pub state: TlsState,

    /// Exchanged key size
    ///
    /// This value is known only for Diffie-Hellman ciphersuites, and after
    /// the ServerKeyExchange message.
    pub kx_bits: Option<u32>,

    pub sni: Vec<String>,

    /// TCP chunks defragmentation buffer
    pub tcp_buffer: Vec<u8>,

    /// Handshake defragmentation buffer
    pub buffer: Vec<u8>,

    /// Flag set if the signature_algorithms extension was sent by the client
    pub has_signature_algorithms: bool,

    /// JA3 hash
    pub ja3: Option<String>,
}

impl<'a> TlsParser<'a> {
    /// Allocation function for a new TLS parser instance
    pub fn new(i: &'a[u8]) -> TlsParser<'a> {
        TlsParser{
            _o:Some(i),
            events:Vec::new(),
            compression:None,
            cipher:None,
            state:TlsState::None,
            kx_bits: None,
            sni: Vec::new(),
            // capacity is the amount of space allocated, which means elements can be added
            // without reallocating the vector
            tcp_buffer:Vec::with_capacity(16384),
            buffer:Vec::with_capacity(16384),
            has_signature_algorithms:false,
            ja3:None,
        }
    }

    /// Message-level TLS parsing
    pub fn parse_message_level(&mut self, msg: &TlsMessage, direction:u8) -> u32 {
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
                        debug!("TLS ClientHello version=0x{:x}", content.version);
                        let ext = parse_tls_extensions(content.ext.unwrap_or(b""));
                        match &ext {
                            Ok((rem ,ref l)) => {
                                if ! rem.is_empty() {
                                    warn!("extensions not entirely parsed");
                                }
                                let ja3 = build_ja3_fingerprint(content, l);
                                let digest = md5::compute(&ja3);
                                debug!("JA3: {} --> {:x}", ja3, digest);
                                self.ja3 = Some(ja3);
                                for extension in l {
                                    match *extension {
                                        TlsExtension::SignatureAlgorithms(_) => self.has_signature_algorithms = true,
                                        TlsExtension::SNI(ref v) => {
                                            for &(t,sni) in v {
                                                let s = String::from_utf8(sni.to_vec());
                                                match s {
                                                    Ok(name) => {
                                                        debug!("SNI: {} {:?}",t,name);
                                                        self.sni.push(name)
                                                    },
                                                    Err(e) => {
                                                        warn!("Invalid UTF-8 data in SNI ({})",e);
                                                        self.sni.push("<Invalid UTF-8 data>".to_string())
                                                    },
                                                };
                                            }
                                        },
                                        _ => (),
                                    }
                                }
                            },
                            e  => error!("Could not parse extentions: {:?}",e),
                        };
                        debug!("ext {:?}", ext);
                    },
                    TlsMessageHandshake::ServerHello(ref content) => {
                        debug!("TLS ServerHello version=0x{:x}", content.version);
                        self.compression = Some(content.compression);
                        self.cipher = content.cipher.get_ciphersuite();
                        match self.cipher {
                            Some(c) => {
                                debug!("Selected cipher: {:?}", c)
                            },
                            _ => warn!("Unknown cipher 0x{:x}", content.cipher),
                        };
                        let ext = parse_tls_extensions(content.ext.unwrap_or(b""));
                        debug!("extensions: {:?}", ext);
                        if let Ok((_,ref extensions)) = ext {
                            if is_tls13(content, extensions) {
                                debug!("TLS 1.3 found");
                                // check ciphers
                                self.cipher.map(|c| {
                                    if c.kx != TlsCipherKx::Tls13 {
                                        warn!("TLS 1.3 ServerHello with invalid cipher {:?}", c);
                                    }
                                });
                            }
                        }
                    },
                    TlsMessageHandshake::ServerHelloV13Draft18(ref content) => {
                        debug!("TLS ServerHelloV13Draft18 version=0x{:x}", content.version);
                        // XXX Tls 1.3 ciphers are different
                        self.cipher = content.cipher.get_ciphersuite();
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
                        if direction == STREAM_TOSERVER {
                            debug!("Client certificate");
                        } else {
                            debug!("Server certificate");
                        }
                        debug!("cert chain length: {}",content.cert_chain.len());
                        for cert in &content.cert_chain {
                            debug!("cert: {:?}",cert);
                            match parse_x509_der(cert.data) {
                                Ok((_rem,x509)) => {
                                    let tbs = &x509.tbs_certificate;
                                    debug!("X.509 Subject: {}",tbs.subject);
                                    debug!("X.509 Serial: {:X}",tbs.serial);
                                    debug!("X.509 is CA?: {}",tbs.is_ca());
                                },
                                _ => warn!("Could not decode X.509 certificate"),
                            }
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

    /// Record-level TLS parsing
    pub fn parse_record_level<'b>(&mut self, r: &TlsRawRecord<'b>, direction:u8) -> u32 {
        let mut v : Vec<u8>;
        let mut status = R_STATUS_OK;

        debug!("parse_record_level {}",r.data.len());
        // debug!("{:?}",r.hdr);
        // debug!("{:?}",r.data);

        // only parse some message types
        match r.hdr.record_type {
            TlsRecordType::ChangeCipherSpec => (),
            TlsRecordType::Handshake        => (),
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
        // Parse record contents as plaintext
        match parse_tls_record_with_header(record_buffer,r.hdr.clone()) {
            Ok((rem2,ref msg_list)) => {
                for msg in msg_list {
                    status |= self.parse_message_level(msg, direction);
                };
                if rem2.len() > 0 {
                    warn!("extra bytes in TLS record: {:?}",rem2);
                    self.events.push(TlsParserEvents::RecordWithExtraBytes as u32);
                    status |= R_STATUS_EVENTS;
                };
            }
            Err(Err::Incomplete(needed)) => {
                debug!("Defragmentation required (TLS record)");
                debug!("Missing {:?} bytes",needed);
                // Record is fragmented
                self.buffer.extend_from_slice(r.data);
            },
           Err(e) => { warn!("parse_tls_record_with_header failed: {:?}",e); status |= R_STATUS_FAIL; },
        };

        status
    }

    /// Parsing function, handling TCP chunks fragmentation
    pub fn parse_tcp_level<'b>(&mut self, i: &'b[u8], direction:u8) -> u32 {
        let mut v : Vec<u8>;
        let mut status = R_STATUS_OK;
        debug!("parse_tcp_level ({})",i.len());
        debug!("defrag buffer size: {}",self.tcp_buffer.len());
        // debug!("{:?}",i);
        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            return status;
        };
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
                Ok((rem, ref r)) => {
                    // debug!("rem: {:?}",rem);
                    cur_i = rem;
                    status |= self.parse_record_level(r, direction);
                },
                Err(Err::Incomplete(needed)) => {
                    debug!("Fragmentation required (TCP level)");
                    debug!("Missing {:?} bytes",needed);
                    self.tcp_buffer.extend_from_slice(cur_i);
                    break;
                },
                Err(e) => { warn!("Parsing failed: {:?}",e); break },
            }
        };
        status
    }
}

r_declare_state_new!(r_tls_state_new,TlsParser,b"TLS parser");
r_declare_state_free!(r_tls_state_free,TlsParser,{ () });

impl<'a> RParser for TlsParser<'a> {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        debug!("[TLS->parse: direction={}, len={}]",direction,i.len());

        if i.len() == 0 {
            // Connection closed ?
            return R_STATUS_OK;
        };

        self.parse_tcp_level(i, direction)
    }
}

pub fn tls_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    // first byte is record type (between 0x14 and 0x17, 0x16 is handhake)
    // second is TLS version major (0x3)
    // third is TLS version minor (0x0 for SSLv3, 0x1 for TLSv1.0, etc.)
    match (i[0],i[1],i[2]) {
        (0x14...0x17,0x03,0...3) => true,
        _ => false,
    }
}

r_implement_probe!(r_tls_probe,tls_probe);
r_implement_parse!(r_tls_parse,TlsParser);

// --------------------------------------------





#[no_mangle]
pub extern fn r_tls_get_next_event(this: &mut TlsParser) -> u32
{
    match this.events.pop() {
        None     => 0xffffffff,
        Some(ev) => ev,
    }
}

/// Get the select ciphersuite
///
/// Returns the selected ciphersuite identifier, or 0 if not yet known.
#[no_mangle]
pub extern fn rusticata_tls_get_cipher(this: &TlsParser) -> u32
{
    match this.cipher {
        None    => 0,
        Some(c) => c.id.into(),
    }
}

/// Get the select compression method
///
/// Returns the selected compression method, or 0 if not yet known.
#[no_mangle]
pub extern fn rusticata_tls_get_compression(this: &TlsParser) -> u32
{
    match this.compression {
        None    => 0,
        Some(c) => c.0 as u32
    }
}

/// Get the exchanged key size
///
/// Returns the selected size of the key exchange, or 0 if not yet known.
#[no_mangle]
pub extern fn rusticata_tls_get_dh_key_bits(this: &TlsParser) -> u32
{
    this.kx_bits.unwrap_or(0) as u32
}




// /// Get the ciphersuite IANA identifier
// ///
// /// Given a ciphersuite name, return the IANA identifier, or 0 if not found
// #[no_mangle]
// pub extern fn rusticata_tls_cipher_of_string(value: *const c_char) -> u32
// {
//     let c_str = unsafe { CStr::from_ptr(value) };
//     let s = c_str.to_str().unwrap();
//     match TlsCipherSuite::from_name(s) {
//         Some(c) => c.id as u32,
//         None    => 0,
//     }
// }

/// Get the ciphersuite key exchange method
#[no_mangle]
pub extern fn rusticata_tls_kx_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.kx.clone() as u32,
        None    => 0,
    }
}

/// Get the ciphersuite authentication method
#[no_mangle]
pub extern fn rusticata_tls_au_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.au.clone() as u32,
        None    => 0,
    }
}

/// Get the ciphersuite encryption method
#[no_mangle]
pub extern fn rusticata_tls_enc_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.enc.clone() as u32,
        None    => 0,
    }
}

/// Get the ciphersuite encryption mode
#[no_mangle]
pub extern fn rusticata_tls_encmode_of_cipher(id: u16) -> u32
{
    match TlsCipherSuite::from_id(id) {
        Some(c) => c.enc_mode.clone() as u32,
        None    => 0,
    }
}

/// Get the ciphersuite MAC method
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
                Ok((_,ref parsed)) => {
                    debug!("ECDHE Parameters: {:?}",parsed);
                    info!("Temp key: using cipher {:?}",parsed.0.curve_params);
                    match &parsed.0.curve_params.params_content {
                        &ECParametersContent::NamedGroup(group) => {
                            // let key_bits = group.key_bits().unwrap_or(0);
                            // debug!("NamedGroup: {}, key={:?} bits", group, key_bits);
                            // return Some(key_bits as u32);
                            match NamedGroup::from_u16(group) {
                                None => (),
                                Some(named_group) => {
                                    let key_bits = named_group.key_bits().unwrap_or(0);
                                    debug!("NamedGroup: {:?}, key={:?} bits",named_group,key_bits);
                                    return Some(key_bits as u32);
                                },
                            }
                        },
                        c => info!("Request for key_bits of unknown group {:?}",c),
                    }
                },
                e => error!("Could not parse ECDHE parameters {:?}",e),
            };
            ()
        },
        TlsCipherKx::Dhe => {
            // Signed DH params
            match parse_content_and_signature(parameters,parse_dh_params,extended) {
                Ok((_,ref parsed)) => {
                    debug!("DHE Parameters: {:?}",parsed);
                    info!("Temp key: using DHE size_p={:?} bits",parsed.0.dh_p.len() * 8);
                    return Some((parsed.0.dh_p.len() * 8) as u32);
                },
                e => error!("Could not parse DHE parameters {:?}",e),
            };
            ()
        },
        TlsCipherKx::Dh => {
            // Anonymous DH params
            match parse_dh_params(parameters) {
                Ok((_,ref parsed)) => {
                    debug!("ADH Parameters: {:?}",parsed);
                    info!("Temp key: using ADH size_p={:?} bits",parsed.dh_p.len() * 8);
                    return Some((parsed.dh_p.len() * 8) as u32);
                },
                e => error!("Could not parse ADH parameters {:?}",e),
            };
            ()
        },
        ref kx @ _ => debug!("unhandled KX algorithm: {:?}",kx),
    };
    None
}

/// https://tools.ietf.org/html/draft-davidben-tls-grease-00
const GREASE_TABLE : &[u16] = &[
    0x0a0a,
    0x1a1a,
    0x2a2a,
    0x3a3a,
    0x4a4a,
    0x5a5a,
    0x6a6a,
    0x7a7a,
    0x8a8a,
    0x9a9a,
    0xaaaa,
    0xbaba,
    0xcaca,
    0xdada,
    0xeaea,
    0xfafa
];


/// SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
pub fn build_ja3_fingerprint(content: &TlsClientHelloContents, extensions: &Vec<TlsExtension>) -> String {
    let mut ja3 = format!("{},",u16::from(content.version));

    let ciphers = content.ciphers.iter().join("-");
    ja3.push_str(&ciphers);
    ja3.push(',');

    let ext_str = extensions.iter()
        .map(|x| TlsExtensionType::from(x))
        .map(|x| u16::from(x))
        .filter(|x| !(GREASE_TABLE.iter().any(|g| g == x)))
        .join("-");
    ja3.push_str(&ext_str);
    ja3.push(',');

    for ext in extensions {
        match ext {
            &TlsExtension::EllipticCurves(ref ec) => {
                ja3.push_str(&ec.iter()
                             // .map(|x| x.0)
                             .filter(|&x| !(GREASE_TABLE.iter().any(|g| g == x)))
                             .join("-"));
            },
            _ => (),
        }
    }
    ja3.push(',');

    for ext in extensions {
        match ext {
            &TlsExtension::EcPointFormats(ref pf) => {
                ja3.push_str(&pf.iter().join("-"));
            },
            _ => (),
        }
    }

    ja3
}

fn is_tls13(_content: &TlsServerHelloContents, extensions: &Vec<TlsExtension>) -> bool {
    // look extensions, find the TlsSupportedVersion
    extensions.iter()
        .find(|&ext| TlsExtensionType::SupportedVersions == ext.into())
        .map(|ref ext| {
            if let TlsExtension::SupportedVersions(ref versions) = ext {
                versions.len() == 1 && versions[0] == TlsVersion::Tls13.0
            } else {
                false
            }
        })
        .unwrap_or(false)
}
