use crate::rparser::*;
use crate::{gen_get_variants, Variant};
use der_parser::der::der_read_element_header;
use kerberos_parser::krb5_parser;
use kerberos_parser::krb5::{EncryptionType, ErrorCode, PAType, PrincipalName, Realm};

pub struct KerberosUDPBuilder {}
impl RBuilder for KerberosUDPBuilder {
    fn new(&self) -> Box<dyn RParser> { Box::new(KerberosParserUDP::new(b"Kerberos/UDP")) }
    fn probe(&self, i:&[u8]) -> bool { kerberos_probe_udp(i) }
}

#[derive(Default)]
pub struct KerberosParserUDP<'a> {
    _name: Option<&'a[u8]>,
    pub(crate) req_type: u32,
    pub(crate) req_cname: Option<PrincipalName>,
    pub(crate) req_sname: Option<PrincipalName>,
    pub(crate) req_crealm: Option<Realm>,
    pub(crate) rep_type: u32,
    pub(crate) rep_etype: Option<EncryptionType>,
    pub(crate) ticket_realm: Option<Realm>,
    pub(crate) ticket_sname: Option<PrincipalName>,
    // pub(crate) ticket_etype: Option<EncryptionType>,
    pub(crate) error_code: Option<ErrorCode>,
}

impl<'a> From<EncryptionType> for Variant<'a> {
    fn from(input: EncryptionType) -> Self {
        input.0.into()
    }
}

impl<'a> From<ErrorCode> for Variant<'a> {
    fn from(input: ErrorCode) -> Self {
        input.0.into()
    }
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        s.push_str(&format!("{:02X}", b));
    }
    s
}

impl<'a> RParser for KerberosParserUDP<'a> {
    fn parse(&mut self, i: &[u8], _direction: u8) -> u32 {
        match der_read_element_header(i) {
            Ok((_rem,hdr)) => {
                // Kerberos messages start with an APPLICATION header
                if hdr.class != 0b01 { return 1; }
                debug!("hdr: {:?}", hdr);
                match hdr.tag.0 {
                    10 => {
                        self.req_type = hdr.tag.0;
                        let res = krb5_parser::parse_as_req(i);
                        debug!("AS-REQ: {:?}", res);
                        if let Ok((_,kdc_req)) = res {
                            debug!("AS-REQ cname: {:?}", kdc_req.req_body.cname);
                            debug!("AS-REQ realm: {:?}", kdc_req.req_body.realm);
                            debug!("AS-REQ sname: {:?}", kdc_req.req_body.sname);
                            debug!("AS-REQ addrs: {:?}", kdc_req.req_body.addresses);
                            match kdc_req.req_body.kdc_options.as_slice() {
                                Ok(s)  => debug!("AS-REQ kdc_options: {}", to_hex_string(s)),
                                Err(_) => (),
                            }
                            self.req_cname = kdc_req.req_body.cname;
                            self.req_sname = kdc_req.req_body.sname;
                            self.req_crealm = Some(kdc_req.req_body.realm);
                        };
                    },
                    11 => {
                        self.rep_type = hdr.tag.0;
                        let res = krb5_parser::parse_as_rep(i);
                        debug!("AS-REP: {:?}", res);
                        if let Ok((_,kdc_rep)) = res {
                            debug!("AS-REP cname: {:?}", kdc_rep.cname);
                            debug!("AS-REP crealm: {:?}", kdc_rep.crealm);
                            debug!("AS-REP ticket.sname: {:?}", kdc_rep.ticket.sname);
                            debug!("AS-REP ticket.realm: {:?}", kdc_rep.ticket.realm);
                            debug!("AS-REP enc-part.etype: {:?}", kdc_rep.enc_part.etype);
                            self.ticket_realm = Some(kdc_rep.ticket.realm);
                            self.ticket_sname = Some(kdc_rep.ticket.sname);
                            // XXX not decoded yet
                            // self.ticket_etype = Some(kdc_rep.ticket.enc_part.etype);
                            self.rep_etype = Some(kdc_rep.enc_part.etype);
                            if test_weak_crypto(kdc_rep.enc_part.etype) {
                                debug!("AS-REP weak crypto");
                            }
                        };
                    },
                    12 => {
                        self.req_type = hdr.tag.0;
                        let res = krb5_parser::parse_tgs_req(i);
                        debug!("TGS-REQ: {:?}", res);
                        if let Ok((_,kdc_req)) = res {
                            debug!("TGS-REQ cname: {:?}", kdc_req.req_body.cname);
                            debug!("TGS-REQ realm: {:?}", kdc_req.req_body.realm);
                            debug!("TGS-REQ sname: {:?}", kdc_req.req_body.sname);
                            self.req_cname = kdc_req.req_body.cname;
                            self.req_sname = kdc_req.req_body.sname;
                            self.req_crealm = Some(kdc_req.req_body.realm);
                            for ref padata in kdc_req.padata.iter() {
                                // SCLogInfo!("TGS-REQ padata: {:?}", padata);
                                if padata.padata_type == PAType::PA_TGS_REQ {
                                    match krb5_parser::parse_ap_req(padata.padata_value) {
                                        Ok((_,ap_req)) => {
                                            // SCLogInfo!("parse_ap_req: {:?}",ap_req);
                                            match ap_req.ap_options.as_slice() {
                                                Ok(s)  => debug!("TGS-REQ AP-REQ ap_options: {}", to_hex_string(s)),
                                                Err(_) => (),
                                            }
                                            debug!("TGS-REQ AP-REQ ticket.sname: {:?}", ap_req.ticket.sname);
                                            debug!("TGS-REQ AP-REQ ticket.realm: {:?}", ap_req.ticket.realm);
                                        }
                                        x => debug!("ERROR parse_ap_req: {:?}",x),
                                    }
                                }
                            }
                        };
                    },
                    13 => {
                        self.rep_type = hdr.tag.0;
                        let res = krb5_parser::parse_tgs_rep(i);
                        debug!("TGS-REP: {:?}", res);
                        if let Ok((_,kdc_rep)) = res {
                            debug!("TGS-REP cname: {:?}", kdc_rep.cname);
                            debug!("TGS-REP ticket sname: {:?}", kdc_rep.ticket.sname);
                            debug!("TGS-REP ticket.realm: {:?}", kdc_rep.ticket.realm);
                            self.ticket_realm = Some(kdc_rep.ticket.realm);
                            self.ticket_sname = Some(kdc_rep.ticket.sname);
                            self.rep_etype = Some(kdc_rep.enc_part.etype);
                            if test_weak_crypto(kdc_rep.enc_part.etype) {
                                debug!("AS-REP weak crypto");
                            }
                        };
                    },
                    14 => {
                        self.req_type = hdr.tag.0;
                        let res = krb5_parser::parse_ap_req(i);
                        debug!("AP-REQ: {:?}", res);
                        if let Ok((_,ap_req)) = res {
                            debug!("AP-REQ ticket sname: {:?}", ap_req.ticket.sname);
                            debug!("AP-REQ ticket.realm: {:?}", ap_req.ticket.realm);
                        };
                    },
                    15 => {
                        self.rep_type = hdr.tag.0;
                        let res = krb5_parser::parse_ap_rep(i);
                        debug!("AP-REP {:?}", res);
                    },
                    30 => {
                        self.rep_type = hdr.tag.0;
                        let res = krb5_parser::parse_krb_error(i);
                        debug!("KRB-ERROR: {:?}", res);
                        debug!("KRB-ERROR: failed request: {:?}", self.req_type);
                        if let Ok((_,error)) = res {
                            debug!("KRB-ERROR: cname: {:?}", error.cname);
                            debug!("KRB-ERROR: realm: {:?}", error.realm);
                            debug!("KRB-ERROR: sname: {:?}", error.sname);
                            debug!("KRB-ERROR: error_code: {:?}", error.error_code);
                            self.error_code = Some(error.error_code);
                        };
                    },
                    _ => debug!("unknown/unsupported tag {}", hdr.tag),
                }
                R_STATUS_OK
            },
            _ => R_STATUS_FAIL
        }
    }

    gen_get_variants!{KerberosParserUDP, "kerberos.",
        req_type      => into,
        req_cname     => |s| { s.req_cname.as_ref().map(|x| Variant::OwnedStr(x.to_string())) },
        req_sname     => |s| { s.req_sname.as_ref().map(|x| Variant::OwnedStr(x.to_string())) },
        req_crealm    => |s| { s.req_crealm.as_ref().map(|x| Variant::Str(&x.0)) },
        rep_type      => into,
        rep_etype     => map,
        ticket_sname  => |s| { s.ticket_sname.as_ref().map(|x| Variant::OwnedStr(x.to_string())) },
        ticket_realm  => |s| { s.ticket_realm.as_ref().map(|x| Variant::Str(&x.0)) },
        error_code    => map,
    }
}

impl<'a> KerberosParserUDP<'a> {
    pub fn new(name: &'a[u8]) -> KerberosParserUDP<'a> {
        KerberosParserUDP{
            _name: Some(name),
            ..KerberosParserUDP::default()
        }
    }
}

/// Return true if Kerberos `EncryptionType` is weak
pub fn test_weak_crypto(alg:EncryptionType) -> bool {
    match alg {
        EncryptionType::AES128_CTS_HMAC_SHA1_96 |
        EncryptionType::AES256_CTS_HMAC_SHA1_96 |
        EncryptionType::AES128_CTS_HMAC_SHA256_128 |
        EncryptionType::AES256_CTS_HMAC_SHA384_192 |
        EncryptionType::CAMELLIA128_CTS_CMAC |
        EncryptionType::CAMELLIA256_CTS_CMAC => false,
        _ => true, // all other ciphers are weak or deprecated
    }
}

pub fn kerberos_probe_udp(i: &[u8]) -> bool {
    if i.len() <= 10 { return false; }
    match der_read_element_header(i) {
        Ok((rem,hdr)) => {
            // Kerberos messages start with an APPLICATION header
            if hdr.class != 0b01 { return false; }
            // Tag number should be <= 30
            if hdr.tag.0 >= 30 { return false; }
            // Kerberos messages contain sequences
            if rem.is_empty() || rem[0] != 0x30 { return false; }
            // Check kerberos version
            // debug!("hdr: {:?}", hdr);
            if let Ok((rem,_hdr)) = der_read_element_header(rem) {
                if rem.len() > 5 {
                    match (rem[2],rem[3],rem[4]) {
                        // Encoding of DER integer 5 (version)
                        (2,1,5) => { return true; },
                        _       => (),
                    }
                }
            }
            false
        },
        _ => false,
    }
}
