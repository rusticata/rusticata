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

    pub client_proposals : Vec<IkeV2Transform>,

    pub dh_group: Option<IkeTransformDHType>,
}

impl<'a> RParser for IPsecParser<'a> {
    fn parse(&mut self, i: &[u8], _direction: u8) -> u32 {
        match parse_ikev2_header(i) {
            IResult::Done(rem,ref hdr) => {
                debug!("parse_ikev2_header: {:?}",hdr);
                if rem.len() == 0 && hdr.length == 28 {
                    return R_STATUS_OK;
                }
                match parse_ikev2_payload_list(rem,hdr.next_payload) {
                    IResult::Done(_,Ok(ref p)) => {
                        debug!("parse_ikev2_payload_with_type: {:?}",p);
                        for payload in p {
                            match payload.content {
                                IkeV2PayloadContent::SA(ref prop) => {
                                    if hdr.flags & IKEV2_FLAG_INITIATOR != 0 {
                                        self.add_client_proposals(prop);
                                    }
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
            dh_group: None,
        }
    }

    fn add_client_proposals(&mut self, prop: &Vec<IkeV2Proposal>) {
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
            let client_proposals : Vec<IkeV2Transform> = p.transforms.iter().map(|x| x.into()).collect();
            debug!("Client proposals\n{:?}",client_proposals);
            for prop in &client_proposals {
                match prop {
                    &IkeV2Transform::DH(ref dh) => {
                        match dh {
                            &IkeTransformDHType::Modp768 |
                            &IkeTransformDHType::Modp1024 |
                            &IkeTransformDHType::Modp1024s160 => {
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
            self.client_proposals = client_proposals;
        }
    }
}

fn ipsec_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    true
}

r_declare_state_new!(r_ipsec_state_new,IPsecParser,b"IPsec state");
r_declare_state_free!(r_ipsec_state_free,IPsecParser,{ () });

r_implement_probe!(r_ipsec_probe,ipsec_probe);
r_implement_parse!(r_ipsec_parse,IPsecParser);

