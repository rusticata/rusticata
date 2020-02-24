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

use std::convert::From;

use nom::*;

use itertools::Itertools;

use md5;

use crate::rparser::*;
use crate::{gen_get_variants, Variant};
use x509_parser::parse_x509_der;

use tls_parser::tls::*;
use tls_parser::tls_alert::{TlsAlertDescription, TlsAlertSeverity};
use tls_parser::tls_ciphers::*;
use tls_parser::tls_dh::*;
use tls_parser::tls_ec::*;
use tls_parser::tls_extensions::*;
use tls_parser::tls_sign_hash::*;
use tls_parser::tls_states::{TlsState,tls_state_transition};

pub struct TLSBuilder {}
impl RBuilder for TLSBuilder {
    fn build(&self) -> Box<dyn RParser> { Box::new(TlsParser::new(b"TLS")) }
    fn probe(&self, i:&[u8]) -> bool { tls_probe(i) }
}

impl<'a> From<TlsVersion> for Variant<'a> {
    fn from(input: TlsVersion) -> Self {
        Variant::U16(input.0)
    }
}

impl<'a> From<TlsCompressionID> for Variant<'a> {
    fn from(input: TlsCompressionID) -> Self {
        Variant::U8(input.0)
    }
}

impl<'a> From<&TlsCipherSuite> for Variant<'a> {
    fn from(input: &TlsCipherSuite) -> Self {
        Variant::U16(input.id)
    }
}

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

    pub client_version: TlsVersion,
    pub ssl_record_version: TlsVersion,

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
    /// if a fatal alert was encountered, store it
    pub fatal_alert: Option<TlsAlertDescription>,

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
            client_version: TlsVersion(0),
            ssl_record_version: TlsVersion(0),
            compression:None,
            cipher:None,
            state:TlsState::None,
            fatal_alert: None,
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
    #[allow(clippy::cognitive_complexity)]
    pub fn parse_message_level(&mut self, msg: &TlsMessage, direction:u8) -> u32 {
        trace!("parse_message_level {:?}",msg);
        let mut status = R_STATUS_OK;
        if self.state == TlsState::ClientChangeCipherSpec {
            // Ignore records from now on, they are encrypted
            return status;
        };
        // update state machine
        match tls_state_transition(self.state, msg, direction == STREAM_TOSERVER) {
            Ok(s)  => self.state = s,
            Err(_) => {
                self.state = TlsState::Invalid;
                self.events.push(TlsParserEvents::InvalidState as u32);
                status |= R_STATUS_EVENTS;
            },
        };
        trace!("TLS new state: {:?}",self.state);
        // extract variables
        match *msg {
            TlsMessage::Handshake(ref m) => {
                match *m {
                    TlsMessageHandshake::ClientHello(ref content) => {
                        debug!("TLS ClientHello version=0x{:x} ({:?})", content.version, content.version);
                        self.client_version = content.version;
                        let ext = parse_tls_extensions(content.ext.unwrap_or(b""));
                        match &ext {
                            Ok((rem ,ref l)) => {
                                if ! rem.is_empty() {
                                    warn!("extensions not entirely parsed");
                                }
                                let ja3 = build_ja3_fingerprint(content, l);
                                let digest = md5::compute(&ja3);
                                debug!("JA3: {} --> {:x}", ja3, digest);
                                self.ja3 = Some(format!("{:?}", digest));
                                for extension in l {
                                    match *extension {
                                        TlsExtension::SignatureAlgorithms(_) => self.has_signature_algorithms = true,
                                        TlsExtension::SNI(ref v) => {
                                            for &(t,sni) in v {
                                                match String::from_utf8(sni.to_vec()) {
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
                        debug!("TLS ServerHello version=0x{:x} ({:?})", content.version, content.version);
                        self.compression = Some(content.compression);
                        self.cipher = content.cipher.get_ciphersuite();
                        match self.cipher {
                            Some(c) => {
                                debug!("Selected cipher: {:?}", c)
                            },
                            _ => warn!("Unknown cipher 0x{:x}", content.cipher),
                        };
                        if content.version.0 < 0x0303 { // "signature_algorithms" was introduced with TLS 1.2
                            self.has_signature_algorithms = false;
                        }
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
                        self.parse_dh_parameters(content);
                    },
                    _ => (),
                }
            },
            TlsMessage::Alert(ref a) => {
                info!("TLS alert: severity: {} code: {}", a.severity, a.code);
                if a.severity == TlsAlertSeverity::Fatal {
                    self.fatal_alert = Some(a.code);
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

        trace!("parse_record_level {}",r.data.len());
        // trace!("{:?}",r.hdr);
        // trace!("{:?}",r.data);

        // only parse some message types
        match r.hdr.record_type {
            TlsRecordType::ChangeCipherSpec => (),
            TlsRecordType::Handshake        => (),
            TlsRecordType::Alert            => (),
            _ => return status,
        }

        // Check if a record is being defragmented
        let record_buffer = match self.buffer.len() {
            0 => r.data,
            _ => {
                v = self.buffer.split_off(0);
                // sanity check vector length to avoid memory exhaustion
                // maximum length may be 2^24 (handshake message)
                if self.buffer.len() + r.data.len() > 16_777_216 {
                    self.events.push(TlsParserEvents::RecordOverflow as u32);
                    return R_STATUS_EVENTS;
                };
                v.extend_from_slice(r.data);
                v.as_slice()
            },
        };
        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec || self.state == TlsState::Invalid {
            return status;
        };
        // XXX record may be compressed
        //
        // Parse record contents as plaintext
        match parse_tls_record_with_header(record_buffer,&r.hdr) {
            Ok((rem2,ref msg_list)) => {
                self.ssl_record_version = r.hdr.version;
                for msg in msg_list {
                    status |= self.parse_message_level(msg, direction);
                };
                if !rem2.is_empty() {
                    warn!("extra bytes in TLS record: {:?}",rem2);
                    self.events.push(TlsParserEvents::RecordWithExtraBytes as u32);
                    status |= R_STATUS_EVENTS;
                };
            }
            Err(Err::Incomplete(needed)) => {
                trace!("Defragmentation required (TLS record)");
                trace!("Missing {:?} bytes",needed);
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
        trace!("parse_tcp_level ({})",i.len());
        trace!("defrag buffer size: {}",self.tcp_buffer.len());
        // trace!("{:?}",i);
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
                if self.tcp_buffer.len() + i.len() > 16_777_216 {
                    self.events.push(TlsParserEvents::RecordOverflow as u32);
                    return R_STATUS_EVENTS;
                };
                v.extend_from_slice(i);
                v.as_slice()
            },
        };
        // trace!("tcp_buffer ({})",tcp_buffer.len());
        let mut cur_i = tcp_buffer;
        while !cur_i.is_empty() {
            match parse_tls_raw_record(cur_i) {
                Ok((rem, ref r)) => {
                    // trace!("rem: {:?}",rem);
                    cur_i = rem;
                    status |= self.parse_record_level(r, direction);
                },
                Err(Err::Incomplete(needed)) => {
                    trace!("Fragmentation required (TCP level)");
                    trace!("Missing {:?} bytes",needed);
                    self.tcp_buffer.extend_from_slice(cur_i);
                    break;
                },
                Err(e) => { warn!("Parsing failed: {:?}",e); break },
            }
        };
        status
    }


    fn parse_dh_parameters(&mut self, content: &TlsServerKeyExchangeContents) {
        let cipher = match self.cipher {
            Some(ref c) => c,
            None => {
                warn!("Trying to parse DH parameters with no ciphersuite");
                return;
            }
        };
        let extended = self.has_signature_algorithms;
        match &cipher.kx {
            TlsCipherKx::Ecdhe |
            TlsCipherKx::Ecdh    => {
                // Signed ECDH params
                match parse_content_and_signature(content.parameters, parse_ecdh_params, extended) {
                    Ok((rem,ref parsed)) => {
                        info!("ECDHE Parameters: {:?}", parsed);
                        debug!("Temp key: using cipher {:?}",parsed.0.curve_params);
                        if !rem.is_empty() {
                            warn!("parse_content_and_signature: rem not empty ({} bytes)", rem.len());
                        }
                        match &parsed.0.curve_params.params_content {
                            &ECParametersContent::NamedGroup(group) => {
                                let key_bits = group.key_bits().unwrap_or(0);
                                debug!("NamedGroup: {}, key={:?} bits", group, key_bits);
                                self.kx_bits = Some(key_bits as u32);
                            },
                            c => info!("Request for key_bits of unknown group {:?}",c),
                        }
                    },
                    e => error!("Could not parse ECDHE parameters {:?}",e),
                };
            },
            TlsCipherKx::Dhe => {
                // Signed DH params
                match parse_content_and_signature(content.parameters, parse_dh_params, extended) {
                    Ok((rem,ref parsed)) => {
                        if !rem.is_empty() {
                            warn!("parse_content_and_signature: rem not empty ({} bytes)", rem.len());
                        }
                        info!("DHE Parameters: {:?}", parsed);
                        debug!("Temp key: using DHE size_p={:?} bits",parsed.0.dh_p.len() * 8);
                        self.kx_bits = Some((parsed.0.dh_p.len() * 8) as u32);
                    },
                    e => error!("Could not parse DHE parameters {:?}",e),
                };
            },
            TlsCipherKx::Dh => {
                // Anonymous DH params
                match parse_dh_params(content.parameters) {
                    Ok((_,ref parsed)) => {
                        info!("ADH Parameters: {:?}", parsed);
                        debug!("Temp key: using ADH size_p={:?} bits",parsed.dh_p.len() * 8);
                        self.kx_bits = Some((parsed.dh_p.len() * 8) as u32);
                    },
                    e => error!("Could not parse ADH parameters {:?}",e),
                };
            },
            kx => info!("unhandled KX algorithm: {:?}",kx),
        };
    }
}

impl<'a> RParser for TlsParser<'a> {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        trace!("[TLS->parse: direction={}, len={}]",direction,i.len());

        if i.is_empty() {
            // Connection closed ?
            return R_STATUS_OK;
        };

        self.parse_tcp_level(i, direction)
    }

    gen_get_variants!{TlsParser, "tls.",
        client_version     => into,
        ssl_record_version => into,
        ja3                => map_as_ref,
        compression        => map,
        cipher             => map,
        kx_bits            => map,
        sni                => |s| Some(Variant::from_slice(&s.sni)),
    }
}

pub fn tls_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    // first byte is record type (between 0x14 and 0x17, 0x16 is handhake)
    // second is TLS version major (0x3)
    // third is TLS version minor (0x0 for SSLv3, 0x1 for TLSv1.0, etc.)
    match (i[0],i[1],i[2]) {
        (0x14..=0x17,0x03,0..=3) => true,
        _ => false,
    }
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
            TlsExtension::EllipticCurves(ref ec) => {
                ja3.push_str(&ec.iter()
                             .map(|x| x.0)
                             .filter(|x| !(GREASE_TABLE.iter().any(|g| g == x)))
                             .join("-"));
            },
            _ => (),
        }
    }
    ja3.push(',');

    for ext in extensions {
        match ext {
            TlsExtension::EcPointFormats(ref pf) => {
                ja3.push_str(&pf.iter().join("-"));
            },
            _ => (),
        }
    }

    ja3
}

fn is_tls13(_content: &TlsServerHelloContents, extensions: &[TlsExtension]) -> bool {
    // look extensions, find the TlsSupportedVersion
    extensions.iter()
        .find(|&ext| TlsExtensionType::SupportedVersions == ext.into())
        .map(|ref ext| {
            if let TlsExtension::SupportedVersions(ref versions) = ext {
                versions.len() == 1 && versions[0] == TlsVersion::Tls13
            } else {
                false
            }
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    static CH: &[u8] = include_bytes!("../assets/client-hello.bin");

    #[test]
    fn tls_get() {
        let mut parser = TlsParser::new(b"foo");
        parser.parse(CH, 0);
        let _ = parser.get("tls.sni");
        for key in parser.keys() {
            println!(" [{}] => {:?}", key, parser.get(key));
        }
        assert_eq!(parser.get("tls.client_version"), Some(Variant::U16(0x0301)));
        assert_eq!(parser.get("tls.ssl_record_version"), Some(Variant::U16(0x0301)));
        assert_eq!(parser.get("tls.ja3"), Some(Variant::Str("e2121ae1544cd5acae048d03505068a6")));
        assert_eq!(parser.get("invalid key"), None);
        parser.sni.push("foo.com".into());
        if let Some(Variant::List(v)) = parser.get("tls.sni") {
            assert_eq!(v.len(), 1);
        } else {
            panic!("wrong variant type for SNI");
        }
    }

    #[test]
    fn tls_get_keys() {
        let parser = TlsParser::new(b"foo");
        println!("keys: {:?}", parser.keys().as_slice());
        for k in parser.keys() {
            println!("key: {}", k);
        }
    }
}
