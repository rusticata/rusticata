use crate::rparser::*;
use crate::{gen_get_variants, Variant};
use tls_parser::*;
use x509_parser::parse_x509_certificate;

pub struct DTLSBuilder {}
impl RBuilder for DTLSBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(DTLSParser::new(b"DTLS"))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(dtls_probe)
    }
}

pub struct DTLSParser<'a> {
    _name: Option<&'a [u8]>,

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
}

impl<'a> RParser for DTLSParser<'a> {
    fn parse_l4(&mut self, data: &[u8], direction: Direction) -> ParseResult {
        match parse_dtls_plaintext_records(data) {
            Ok((rem, res)) => {
                debug!("parse_dtls_plaintext_records: {:?}", res);
                for record in &res {
                    self.ssl_record_version = record.header.version;
                    for msg in &record.messages {
                        if *msg == DTLSMessage::ChangeCipherSpec {
                            debug!("DTLS: stop following session");
                            // Ignore records from now on, they are encrypted
                            return ParseResult::Stop;
                        };
                        self.parse_message(msg, direction);
                    }
                }
                if !rem.is_empty() {
                    warn!("Extra bytes after DTLS data");
                    use nom::HexDisplay;
                    println!("{}", rem.to_hex(16));
                }
            }
            e => warn!("parse_dtls: {:?}", e),
        };
        ParseResult::Ok
    }

    gen_get_variants! {DTLSParser, "dtls.",
        client_version     => into,
        ssl_record_version => into,
        compression        => map,
        cipher             => map,
    }
}

impl<'a> DTLSParser<'a> {
    pub fn new(name: &'a [u8]) -> DTLSParser<'a> {
        DTLSParser {
            _name: Some(name),
            client_version: TlsVersion(0),
            ssl_record_version: TlsVersion(0),
            compression: None,
            cipher: None,
        }
    }

    fn parse_message(&mut self, msg: &DTLSMessage, direction: Direction) {
        if let DTLSMessage::Handshake(m) = msg {
            self.parse_message_handshake(m, direction);
        }
    }

    fn parse_message_handshake(&mut self, msg: &DTLSMessageHandshake, direction: Direction) {
        match &msg.body {
            DTLSMessageHandshakeBody::ClientHello(ch) => {
                self.client_version = ch.version;
            }
            DTLSMessageHandshakeBody::ServerHello(sh) => {
                self.client_version = sh.version;
                self.cipher = sh.cipher.get_ciphersuite();
                self.compression = Some(sh.compression);
            }
            DTLSMessageHandshakeBody::Certificate(content) => {
                if direction == Direction::ToServer {
                    debug!("Client certificate");
                } else {
                    debug!("Server certificate");
                }
                debug!("cert chain length: {}", content.cert_chain.len());
                for cert in &content.cert_chain {
                    debug!("cert: {:?}", cert);
                    match parse_x509_certificate(cert.data) {
                        Ok((_rem, x509)) => {
                            let tbs = &x509.tbs_certificate;
                            debug!("X.509 Subject: {}", tbs.subject);
                            debug!("X.509 Serial: {:X}", tbs.serial);
                            debug!("X.509 is CA?: {}", tbs.is_ca());
                        }
                        _ => warn!("Could not decode X.509 certificate"),
                    }
                }
            }
            _ => (),
        }
    }
}

pub fn dtls_probe(i: &[u8], l4info: &L4Info) -> ProbeResult {
    if i.len() <= 2 {
        return ProbeResult::Unsure;
    }
    // test if UDP
    if l4info.l4_proto != 17 {
        return ProbeResult::Unsure;
    }
    // first byte is record type (between 0x14 and 0x17, 0x16 is handhake)
    // second and third bytes usually are the is the 1's complement of DTLS version (0xfe 0xff for
    // 1.0, etc.)
    match (i[0], i[1], i[2]) {
        (0x14..=0x17, 0xfe, 0xfd..=0xff) => ProbeResult::Certain,
        // but some pcap traces show that openssl pre-0.9.8f used the TLS version 1.0 (no
        // complement)
        (0x14..=0x17, 0x01, 0x00) => ProbeResult::Certain,
        _ => ProbeResult::NotForUs,
    }
}
