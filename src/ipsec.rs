extern crate libc;

use std;
use std::mem;
use libc::c_char;

use rparser::*;

use ipsec_parser::*;
use num_traits::cast::FromPrimitive;

use nom::IResult;

pub struct IPsecParser<'a> {
    _name: Option<&'a[u8]>,

    pub client_proposals : Vec<Vec<IkeV2Transform>>,
    pub server_proposals : Vec<Vec<IkeV2Transform>>,

    pub dh_group: Option<IkeTransformDHType>,
}

impl<'a> RParser for IPsecParser<'a> {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        match parse_ikev2_header(i) {
            IResult::Done(rem,ref hdr) => {
                debug!("parse_ikev2_header: {:?}",hdr);
                if rem.len() == 0 && hdr.length == 28 {
                    return R_STATUS_OK;
                }
                // Rule 0: check version
                if hdr.maj_ver != 2 || hdr.min_ver != 0 {
                    warn!("Unknown header version: {}.{}", hdr.maj_ver, hdr.min_ver);
                }
                match parse_ikev2_payload_list(rem,hdr.next_payload) {
                    IResult::Done(_,Ok(ref p)) => {
                        debug!("parse_ikev2_payload_with_type: {:?}",p);
                        for payload in p {
                            match payload.content {
                                IkeV2PayloadContent::SA(ref prop) => {
                                    // if hdr.flags & IKEV2_FLAG_INITIATOR != 0 {
                                        self.add_proposals(prop, direction);
                                    // }
                                },
                                IkeV2PayloadContent::KE(ref kex) => {
                                    self.dh_group = IkeTransformDHType::from_u16(kex.dh_group);
                                    // XXX if self.dh_group == None, raise decoder event
                                    debug!("KEX {}/{:?}", kex.dh_group, self.dh_group);
                                },
                                IkeV2PayloadContent::Nonce(ref n) => {
                                    debug!("Nonce: {:?}", n);
                                },
                                IkeV2PayloadContent::Notify(ref n) => {
                                    debug!("Notify: {:?}", n);
                                },
                                _ => {
                                    debug!("Unknown payload content {:?}", payload.content);
                                },
                            }
                        }
                    },
                    e @ _ => warn!("parse_ikev2_payload_with_type: {:?}",e),
                };
            },
            e @ _ => warn!("parse_ikev2_header: {:?}",e),
        };
        R_STATUS_OK
    }
}

impl<'a> IPsecParser<'a> {
    pub fn new(name: &'a[u8]) -> IPsecParser<'a> {
        IPsecParser{
            _name: Some(name),
            client_proposals: Vec::new(),
            server_proposals: Vec::new(),
            dh_group: None,
        }
    }

    fn add_proposals(&mut self, prop: &Vec<IkeV2Proposal>, direction: u8) {
        debug!("num_proposals: {}",prop.len());
        for ref p in prop {
            debug!("proposal: {:?}",p);
            debug!("num_transforms: {}",p.num_transforms);
            for ref xform in &p.transforms {
                debug!("transform: {:?}",xform);
                let xty = IkeTransformType::from_u8(xform.transform_type);
                debug!("\ttype: {:?} / {}",xty,xform.transform_type);
                match xty {
                    Some(IkeTransformType::EncryptionAlgorithm) => {
                        debug!("\tEncryptionAlgorithm: {:?}",IkeTransformEncType::from_u16(xform.transform_id));
                    },
                    Some(IkeTransformType::PseudoRandomFunction) => {
                        debug!("\tPseudoRandomFunction: {:?}",IkeTransformPRFType::from_u16(xform.transform_id));
                    },
                    Some(IkeTransformType::IntegrityAlgorithm) => {
                        debug!("\tIntegrityAlgorithm: {:?}",IkeTransformAuthType::from_u16(xform.transform_id));
                    },
                    Some(IkeTransformType::DiffieHellmanGroup) => {
                        debug!("\tDiffieHellmanGroup: {:?}",IkeTransformDHType::from_u16(xform.transform_id));
                    },
                    Some(IkeTransformType::ExtendedSequenceNumbers) => {
                        debug!("\tExtendedSequenceNumbers: {:?}",IkeTransformESNType::from_u16(xform.transform_id));
                    },
                    _ => warn!("\tUnknown transform type {}",xform.transform_type),
                }
                if xform.transform_id == 0 {
                    warn!("\tTransform ID == 0 (choice left to responder)");
                };
            }
            let proposals : Vec<IkeV2Transform> = p.transforms.iter().map(|x| x.into()).collect();
            debug!("Proposals\n{:?}",proposals);
            // Rule 1: warn on weak or unknown transforms
            for prop in &proposals {
                match prop {
                    &IkeV2Transform::Encryption(ref enc) => {
                        match enc {
                            &IkeTransformEncType::DesIV64 |
                            &IkeTransformEncType::Des |
                            &IkeTransformEncType::TripleDes |
                            &IkeTransformEncType::Rc5 |
                            &IkeTransformEncType::Idea |
                            &IkeTransformEncType::Cast |
                            &IkeTransformEncType::Blowfish |
                            &IkeTransformEncType::TripleIdea |
                            &IkeTransformEncType::DesIV32 |
                            &IkeTransformEncType::Null => {
                                warn!("Weak Encryption: {:?}", enc);
                            },
                            _ => (),
                        }
                    },
                    &IkeV2Transform::Auth(ref auth) => {
                        match auth {
                            &IkeTransformAuthType::None => {
                                // Note: this could be expected with an AEAD encription alg.
                                // See rule 4
                                ()
                            },
                            &IkeTransformAuthType::HmacMd5s96 |
                            &IkeTransformAuthType::HmacSha1s96 |
                            &IkeTransformAuthType::DesMac |
                            &IkeTransformAuthType::KpdkMd5 |
                            &IkeTransformAuthType::AesXCBC96 |
                            &IkeTransformAuthType::HmacMd5s128 |
                            &IkeTransformAuthType::HmacMd5s160 => {
                                warn!("Weak auth: {:?}", auth);
                            },
                            _ => (),
                        }
                    },
                    &IkeV2Transform::DH(ref dh) => {
                        match dh {
                            &IkeTransformDHType::None => {
                                warn!("'None' DH transform proposed");
                            },
                            &IkeTransformDHType::Modp768 |
                            &IkeTransformDHType::Modp1024 |
                            &IkeTransformDHType::Modp1024s160 |
                            &IkeTransformDHType::Modp1536 => {
                                warn!("Weak DH: {:?}", dh);
                            },
                            _ => (),
                        }
                    },
                    &IkeV2Transform::Unknown(tx_type,tx_id) => {
                        warn!("Unknown proposal: type={}, id={}", tx_type, tx_id);
                    },
                    _ => (),
                }
            }
            // Rule 2: check if no DH was proposed
            if ! proposals.iter().any(|x| {
                if let &IkeV2Transform::DH(_) = x { true } else { false }
            })
            {
                warn!("No DH transform found");
            }
            // Rule 3: check if proposing AH ([RFC7296] section 3.3.1)
            if p.protocol_id == 2 {
                warn!("Proposal uses protocol AH - no confidentiality");
            }
            // Rule 4: lack of integrity is accepted only if using an AEAD proposal
            // Look if no auth was proposed, including if proposal is Auth::None
            if ! proposals.iter().any(|x| {
                match x {
                    &IkeV2Transform::Auth(IkeTransformAuthType::None) => false,
                    &IkeV2Transform::Auth(_)                          => true,
                    _                                                 => false,
                }
            })
            {
                if ! proposals.iter().any(|x| {
                    if let &IkeV2Transform::Encryption(ref enc) = x {
                        enc.is_aead()
                    } else { false }
                }) {
                    warn!("No integrity transform found");
                }
            }
            // Finally
            if direction == TO_SERVER {
                self.client_proposals.push(proposals);
            } else {
                self.server_proposals.push(proposals);
            }
        }
        debug!("client_proposals: {:?}", self.client_proposals);
        debug!("server_proposals: {:?}", self.server_proposals);
    }
}

#[allow(dead_code)]
fn ipsec_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    true
}

r_declare_state_new!(r_ipsec_state_new,IPsecParser,b"IPsec state");
r_declare_state_free!(r_ipsec_state_free,IPsecParser,{ () });

r_implement_probe!(r_ipsec_probe,ipsec_probe);
r_implement_parse!(r_ipsec_parse,IPsecParser);

