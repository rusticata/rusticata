pub use nom::{Err, IResult};
use nom::error::{make_error, ErrorKind};
use nom::bytes::complete::take;
use nom::named;
use nom::number::streaming::{be_u32,be_u64,be_i64};
use nfs_parsable_from_stream_derive::*;
//use std::fmt;



#[derive(Debug, PartialEq, Copy, Clone)]
pub enum RpcMsgType {
    RpcCall,
    RpcReply
}
#[derive(Debug, PartialEq)]
pub struct RpcFragmentHeader {
    pub last_fragment: bool,
    pub fragment_length: u32
}
#[derive(Debug, PartialEq)]
pub struct RpcPacket<'a> {
    pub fragment_header: RpcFragmentHeader,
    pub xid: u32,
    pub msg_type: RpcMsgType,
    pub rpc_params: Box<RpcParams<'a>>
}
#[derive(Clone,Debug,PartialEq)]
pub struct RpcCredentials<'a>{
    pub rpc_cred_flavor: u32,
    pub rpc_cred_length: u32, // length of everything except the flavor and length fields
    pub rpc_cred_aux: Box<RpcCredAux<'a>>,
}

#[derive(Clone,Debug,PartialEq)]
pub struct RpcOpaque<'a> {
    pub opaque_data : &'a [u8]
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSBitmap4 {
    array: Vec<u32>
}

#[derive(Clone,Debug,PartialEq)]
pub enum RpcCredAux<'a> {
    RpcAuthUnix(RpcAuthUnix),
    RpcAuthNone,
    RpcAuthUnimplemented(RpcOpaque<'a>),
    RpcAuthShort(RpcAuthShort),
    RpcAuthDH(RpcAuthDH),
    RpcAuthRpcsecGSS(RpcAuthRpcsecGSS)
}
#[derive(Copy,Clone,Debug,PartialEq)]
pub struct RpcAuthShort {}
#[derive(Copy,Clone,Debug,PartialEq)]
pub struct RpcAuthDH {}
#[derive(Copy,Clone,Debug,PartialEq)]
pub struct RpcAuthRpcsecGSS {
    
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct RpcAuthUnix { // AUTH_UNIX AKA AUTH_SYS
    rpc_auth_stamp: u32,
    rpc_machine_name: Vec<u8>,
    rpc_primary_uid: u32,
    rpc_primary_gid: u32,
    rpc_aux_gids: Vec<u32>
}
#[derive(Clone,Debug,PartialEq)]
pub struct RpcCallData<'a> {
        rpc_version: u32,
        rpc_program_num: u32,
        rpc_program_ver: u32,
        rpc_procedure: u32,
        rpc_creds: Box<RpcCredentials<'a>>,
        rpc_verifier: Box<RpcCredentials<'a>>,
        rpc_appdata: Box<RpcAppdata<'a>>,
    }
#[derive(Copy, Clone,Debug,PartialEq)]
pub struct RpcReplyData<'a> {
        rest_data: &'a [u8]
    }
#[derive(Clone,Debug,PartialEq)]
pub enum RpcParams<'a> {
    RpcCallData(RpcCallData<'a>),
    RpcReplyData(RpcReplyData<'a>)
}

pub fn parse_rpc(i: &[u8]) -> IResult<&[u8], RpcPacket> {

    let (rest, maybe_fh) = be_u32(i)?;
    let islast = (maybe_fh >> 31) == 1;
    let fragment_header = RpcFragmentHeader { last_fragment: islast, fragment_length: maybe_fh & 0x7fff};
//    debug!("fragment header {:?}",fragment_header);
    let (rest, maybe_xid) = be_u32(rest)?;
    debug!("xid {:x?}",maybe_xid);
    let (rest, maybe_msg_type) = be_u32(rest)?;
    let msg_type = match maybe_msg_type {
        0 => Ok(RpcMsgType::RpcCall),
        1 => Ok(RpcMsgType::RpcReply),
        wrong => { debug!("the heck msg_type {:x?}",wrong);
                   //debug!("the heck rest of payload {:x?}",rest);
                   Err(Err::Error(make_error(i,ErrorKind::TooLarge))) }
    }?;
    
    let res = match msg_type {
        RpcMsgType::RpcCall => { let (rest, rpc_call_data) = parse_rpc_call(rest)?;
                     
                     Ok((rest,RpcPacket { fragment_header :  fragment_header,
                                 xid : maybe_xid,
                                 msg_type: msg_type,
                                 rpc_params: rpc_call_data
                                 }))
                   }
        RpcMsgType::RpcReply => { let (rest, rpc_reply_data) = parse_rpc_reply(rest)?;
                      Ok((rest,RpcPacket { fragment_header :  fragment_header,
                                 xid : maybe_xid,
                                 msg_type: msg_type,
                                 rpc_params: rpc_reply_data
                                 }))
        }
    };
    res
}

fn skip_rpc_auth_unimplemented(length: u32, data: &[u8]) -> IResult<&[u8], Box<RpcCredAux>> {
    let (rest, opaque_data) = take(length)(data)?;
    Ok((rest,Box::new(RpcCredAux::RpcAuthUnimplemented (RpcOpaque {opaque_data}))))
}

fn parse_rpc_creds(data: &[u8]) -> IResult<&[u8], Box<RpcCredentials>> {
    let (rest, cred_flav) = be_u32(data)?;
    let (rest, cred_length) = be_u32(rest)?;
    let (thetail, res) = match cred_flav {
        0 => Ok((rest,Box::new(RpcCredentials {rpc_cred_flavor: cred_flav, rpc_cred_length: cred_length, rpc_cred_aux: Box::new(RpcCredAux::RpcAuthNone)}))),
        1 => {
            let (really_tail, rca) = parse_rpc_auth_unix(rest)?;
            Ok((really_tail, Box::new(RpcCredentials {rpc_cred_flavor: cred_flav, rpc_cred_length: cred_length, rpc_cred_aux: rca})))
        },
        _ => { let (really_tail, rca) = skip_rpc_auth_unimplemented(cred_length, rest)?;
            Ok((really_tail,Box::new(RpcCredentials {rpc_cred_flavor: cred_flav, rpc_cred_length: cred_length, rpc_cred_aux: rca})))} // not implemented yet
    }?;
    
    Ok((thetail, res))
}

fn align_fill_bytes(length: u32) -> u32 {
    (4 - (length % 4)) % 4 // pick a really good number
}


fn parse_rpc_auth_unix(data: &[u8]) -> IResult<&[u8], Box<RpcCredAux>> {
    let (rest, stamp) = be_u32(data)?;
    let (rest, machine_name_length) = be_u32(rest)?;
    let (rest, machine_name) = take(machine_name_length)(rest)?;
    let (rest, _) = take(align_fill_bytes(machine_name_length))(rest)?;
    let (rest, primary_uid) = be_u32(rest)?;
    let (rest, primary_gid) = be_u32(rest)?;

    let (mut rest, num_aux_gids) = be_u32(rest)?;
    let mut aux_gids = Vec::new();
    for i in 0 .. num_aux_gids {
        
        let (rest_, aux_gid) = be_u32(rest)?;
        aux_gids.push(aux_gid);
        rest = rest_;
    }
    Ok((rest,Box::new(RpcCredAux::RpcAuthUnix( RpcAuthUnix {rpc_auth_stamp: stamp, rpc_machine_name: machine_name.to_vec(), rpc_primary_uid : primary_uid, rpc_primary_gid: primary_gid, rpc_aux_gids: aux_gids}))))

}

fn parse_rpc_call(data: &[u8]) -> IResult<&[u8], Box<RpcParams>> {
    let (rest, rpc_version) = be_u32(data)?;
    let (rest, rpc_program_num) = be_u32(rest)?;
    let (rest, rpc_program_ver) = be_u32(rest)?;
    let (rest, rpc_procedure) = be_u32(rest)?;
    let (rest, rpc_creds) = parse_rpc_creds(rest)?;
    let (rest, rpc_verifier) = parse_rpc_creds(rest)?;
    let (rest, rpc_appdata) = parse_rpc_appdata(rest, rpc_procedure, rpc_program_num, rpc_program_ver)?;
//    if rest.is_empty() {}
    Ok((rest,
        Box::new(RpcParams::RpcCallData(RpcCallData{rpc_creds: rpc_creds, rpc_verifier: rpc_verifier, rpc_version: rpc_version, rpc_program_num: rpc_program_num, rpc_program_ver: rpc_program_ver, rpc_procedure: rpc_procedure, rpc_appdata: rpc_appdata}))))}

fn parse_rpc_reply(data: &[u8]) -> IResult<&[u8], Box<RpcParams>> {
    Ok((&[] as &[u8],
        Box::new(RpcParams::RpcReplyData(RpcReplyData{rest_data: data}))))
}
#[derive(Clone,Debug,PartialEq)]
enum RpcAppdata<'a> {
    RpcUnimplementedAppAppdata(RpcOpaque<'a>),
    RpcNFSNullAppdata,
    RpcNFSCompoundAppdata(RpcNFSAppdata<'a>)
}
#[derive(Clone,Debug,PartialEq)]
pub struct RpcNFSAppdata<'a> {
    nfs_tag_length: u32, // in BYTES if it's a string
    nfs_tag_contents: &'a str,
    nfs_minor: u32,
    nfs_op_count: u32,
    nfs_ops: Vec<NFSOp>

}

fn parse_rpc_appdata(data: &[u8], rpc_procedure: u32, rpc_program_num: u32, rpc_program_ver: u32) -> IResult<&[u8], Box<RpcAppdata>> {
    match rpc_procedure {
        0 => Ok((data, Box::new(RpcAppdata::RpcNFSNullAppdata))),
        1 => {
            let res = match rpc_program_num {
                100003 => parse_nfs_data(data,rpc_program_ver),
                _ => Ok((&[] as &[u8],Box::new(RpcAppdata::RpcUnimplementedAppAppdata(RpcOpaque {opaque_data: data}))))
            }?;
            Ok((res))},
        _ => Err(Err::Error(make_error(data,ErrorKind::Digit))) 
    }
}
fn parse_nfs_data(data: &[u8], rpc_program_ver: u32) -> IResult<&[u8], Box<RpcAppdata>> {
    let res = match rpc_program_ver {
        4 => parse_nfs4_data(data),
        _ => Ok((&[] as &[u8],Box::new(RpcAppdata::RpcUnimplementedAppAppdata(RpcOpaque {opaque_data: data}))))

    }?;
    Ok((res))
}

fn parse_nfs4_data(data: &[u8]) -> IResult<&[u8], Box<RpcAppdata>> {
    let (rest, nfs_tag_length) = be_u32(data)?;
    let (rest, nfs_tag_contents) = take(nfs_tag_length)(rest)?;
    let (rest, _) = take(align_fill_bytes(nfs_tag_length))(rest)?; // padding
    let (rest, nfs_minor) = be_u32(rest)?;
    let (mut rest, nfs_op_count) = be_u32(rest)?;
    let mut nfs_ops: Vec<NFSOp> = Vec::new();
    for _ in 0 .. nfs_op_count {
        if (rest.is_empty()) {return Err(Err::Incomplete(nom::Needed::Unknown))} else {
            let (rest_ , nfs_op_num) = be_u32(rest)?;
            let (rest_, nfs_op) = resolve_and_build_nfs_op(nfs_op_num,rest_)?;
            nfs_ops.push(nfs_op);
            rest = rest_;
            }
    }
    
    Ok((rest, Box::new(RpcAppdata::RpcNFSCompoundAppdata(RpcNFSAppdata {nfs_tag_length: nfs_tag_length,
                                                                nfs_tag_contents: std::str::from_utf8(nfs_tag_contents).unwrap(), nfs_minor: nfs_minor, nfs_op_count: nfs_op_count, nfs_ops: nfs_ops}))))

}

pub trait NFSParsable<'a,T> {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], T>;
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NF4LNK {
    linktext: Vec<u8>,
} // linktext4 is an opaque<> that's only listed once

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NF4DEVTYPE {
    devmajor: u32,
    devminor: u32
}

#[derive(Clone,Debug,PartialEq)]
pub enum NFSFType {
    NF4REG,
    NF4DIR,
    NF4BLK(NF4DEVTYPE),
    NF4CHR(NF4DEVTYPE),
    NF4LNK(NF4LNK),
    NF4SOCK,
    NF4FIFO,
    NF4ATTRDIR,
    NF4NAMEDATTR,
    NF4INVALIDFTYPE
}
impl<'a> NFSParsable<'a,NFSFType> for NFSFType {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSFType> {
        nfs_match_ftype(data)        
    }
}

fn nfs_match_ftype(data: &[u8]) -> IResult<&[u8],NFSFType> {
    let (rest, ftnum) = be_u32(data)?;
    match ftnum {
        1 => Ok((rest, NFSFType::NF4REG)),
        2 => Ok((rest, NFSFType::NF4DIR)),
        3 => {
            let (rest, devtype) = NF4DEVTYPE::from_stream(rest)?;
            Ok((rest, NFSFType::NF4BLK(devtype)))
        },
        4 => {
            let (rest, devtype) = NF4DEVTYPE::from_stream(rest)?;
            Ok((rest, NFSFType::NF4CHR(devtype)))
    },
        5 => {
            let (rest, thelink) = NF4LNK::from_stream(rest)?;
            Ok((rest, NFSFType::NF4LNK(thelink)))
        },
        6 => Ok((rest, NFSFType::NF4SOCK)),
        7 => Ok((rest, NFSFType::NF4FIFO)),
        8 => Ok((rest, NFSFType::NF4ATTRDIR)),
        9 => Ok((rest, NFSFType::NF4NAMEDATTR)),
        _ => Ok((rest, NFSFType::NF4INVALIDFTYPE)) // maybe Error ?
           
    }
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSAttrlist4 {
    list: Option<Vec<u8>>
}
impl<'a> NFSParsable<'a, Option<Vec<u8>>> for Option<Vec<u8>> {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], Option<Vec<u8>>> {
        let maybe_size: IResult<&[u8], u32> = be_u32(data);
        match maybe_size {
            Ok((_rest,4)) => match NFSOpClose::from_stream(data) {
                Err(_) => {let (rest, d) = Vec::<u8>::from_stream(data)?; Ok((rest, Some(d)))}
                Ok((_rest,_)) => Ok((data,None))
            },
            Ok((_rest,8)) => match NFSOpDelegReturn::from_stream(data) {
                Err(_) => {let (rest, d) = Vec::<u8>::from_stream(data)?; Ok((rest, Some(d)))}
                Ok((_rest,_)) => Ok((data,None))
            },
            Ok((_rest, size)) if size >= 32768 => {debug!("Probably got another rpc packet, first bit on in u32. Size was {:?}",size); Ok((data,None)) } 
            Ok((_rest, size)) => {debug!("size of optional attrlist: {:?}",size); let (rest, d) = Vec::<u8>::from_stream(data)?; Ok((rest, Some(d)))},
            Err(_) => Ok((data,None))
        }
    }
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSFATTR4 {
    fattr_mask: NFSBitmap4,
    fattr_attrlist: NFSAttrlist4
}

#[derive(Clone,Debug,PartialEq)]
pub struct NFSStateid {
    seqid: NFSSeqid,
    other: [u32;3]
}
impl<'a> NFSParsable<'a,NFSStateid> for NFSStateid {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSStateid> {
        let (mut rest, seqid) = NFSSeqid::from_stream(data)?;
        let mut other: [u32;3] = [0,0,0] as [u32;3];
        for i in 0..3 {
            let (rest_, element) = be_u32(rest)?;
            rest = rest_;
            other[i] = element;
        }
        Ok((rest, NFSStateid {seqid: seqid, other: other}))

    }
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSSeqid {
    seqid: u32,
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpCreate {
    objtype: NFSFType,
    objname: NFSComponent4,
    obj_fattr: NFSFATTR4
}


#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpAccess { check_access: u32 }

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpGetattr {
    obj_fattr: NFSFATTR4
}

impl<'a> NFSParsable<'a,u64> for u64 {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8],u64> {
        let (rest, mything) = be_u64(data)?;
        Ok((rest,mything))
    }

}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSClientID {
    clientid: u64
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpenOwner {
    open_seqid: NFSSeqid,
    open_stateid: NFSStateid,
    lock_seqid: NFSSeqid,
    lock_owner_owner: NFSLockOwnerOwner
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSLockOwnerOwner {
    clientid: NFSClientID,
    owner_contents: Vec<u8>
}

#[derive(Clone,Debug,PartialEq, NFSParsable)]
pub struct NFSLockOwner {
    lock_stateid: NFSStateid,
    lock_seqid: NFSSeqid
}

#[derive(Clone,Debug,PartialEq)]
pub enum NFSLocker {
    NFSOpenOwner(NFSOpenOwner),
    NFSLockOwner(NFSLockOwner),
    NFSLockerInvalid
}

impl<'a> NFSParsable<'a,NFSLocker> for NFSLocker {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8],NFSLocker> {
        let (rest, new_lock_owner) = be_u32(data)?;
        match new_lock_owner {
            0 => { let (rest, owner) = NFSLockOwner::from_stream(rest)?; Ok((rest, NFSLocker::NFSLockOwner (owner)))},
            1 => { let (rest, owner) = NFSOpenOwner::from_stream(rest)?; Ok((rest, NFSLocker::NFSOpenOwner (owner)))},
            _ => Ok((rest,NFSLocker::NFSLockerInvalid))
        }

    }

}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpLink {
    link_name: NFSComponent4
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSBool {
    value: u32 // bool is _probably_ encoded as u32
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOffset {
    offset: u64
}

#[derive(Clone,Debug,PartialEq, NFSParsable)]
pub struct NFSLength {
    length: u64
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpLock {
    locktype: NFSLockType,
    reclaim: NFSBool,
    offset: NFSOffset,
    length: NFSLength,
    locker: NFSLocker
}


#[derive(Clone,Debug,PartialEq)]
pub enum NFSLockType {
    READ_LT,
    WRITE_LT,
    READW_LT, // blocking variant
    WRITEW_LT, // blocking variant
    INVALID_LT
}
impl<'a> NFSParsable<'a,NFSLockType> for NFSLockType {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSLockType> {
        let (rest, locktypenum) = be_u32(data)?;
        Ok((rest, resolve_lock_type(locktypenum)))
}
}
fn resolve_lock_type(num: u32) -> NFSLockType {
    match num {
        1 => NFSLockType::READ_LT,
        2 => NFSLockType::WRITE_LT,
        3 => NFSLockType::READW_LT,
        4 => NFSLockType::WRITEW_LT,
        _ => NFSLockType::INVALID_LT
    }
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpLockT {
    locktype: NFSLockType,
    offset: NFSOffset,
    length: NFSLength,
    owner: NFSLockOwnerOwner
}


#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpLockU {
    locktype: NFSLockType,
    seqid: NFSSeqid,
    stateid: NFSStateid, // 12 bytes
    offset: NFSOffset,
    length: NFSLength
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpLookup {
    objname: NFSComponent4
}

impl<'a> NFSParsable<'a,u32> for u32 {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], u32> {
        let (rest, mything) = be_u32(data)?;
        Ok((rest, mything))
    }
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpOpen {
    seqid: NFSSeqid,
    share_access: u32,
    share_deny: u32,
    owner: NFSLockOwnerOwner,
    opentype: NFSOpenType,
    claim: NFSOpenClaimType
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSComponent4 {
    component_name: Vec<u8>,
}

#[derive(Clone,Debug,PartialEq, NFSParsable)]
pub struct NFSClaimNULL {
    file: NFSComponent4
}

#[derive(Clone,Debug,PartialEq)]
pub enum NFSOpenDelegationType {
    OPEN_DELEGATE_NONE,
    OPEN_DELEGATE_READ,
    OPEN_DELEGATE_WRITE,
    OPEN_DELEGATE_INVALID
}
impl<'a> NFSParsable<'a,NFSOpenDelegationType> for NFSOpenDelegationType {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSOpenDelegationType> {
        let (rest, num) = be_u32(data)?;
        Ok((rest, resolve_open_delegation_type(num)))
    }
}
fn resolve_open_delegation_type(num: u32) -> NFSOpenDelegationType {
    match num {
        0 => NFSOpenDelegationType::OPEN_DELEGATE_NONE,
        1 => NFSOpenDelegationType::OPEN_DELEGATE_READ,
        2 => NFSOpenDelegationType::OPEN_DELEGATE_WRITE,
        _ => NFSOpenDelegationType::OPEN_DELEGATE_INVALID
    }
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSClaimDelegateCur {
    stateid: NFSStateid,
    file: NFSComponent4,
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSClaimDelegatePrev {
    file_delegate_prev: NFSComponent4
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSClaimPrevious {
    open_delegation_type: NFSOpenDelegationType
}

#[derive(Clone,Debug,PartialEq)]
pub enum NFSOpenClaimType {
    CLAIM_NULL(NFSClaimNULL),
    CLAIM_PREVIOUS(NFSClaimPrevious),
    CLAIM_DELEGATE_CUR(NFSClaimDelegateCur),
    CLAIM_DELEGATE_PREV(NFSClaimDelegatePrev),
    CLAIM_INVALID
}
impl<'a> NFSParsable<'a,NFSOpenClaimType> for NFSOpenClaimType {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8],NFSOpenClaimType> {
        let (rest, claimtype) = be_u32(data)?;
        match claimtype {
            0 => {let (rest, claim) = NFSClaimNULL::from_stream(rest)?;
                  return Ok((rest,NFSOpenClaimType::CLAIM_NULL(claim)))},
            1 => {let (rest, claim) = NFSClaimPrevious::from_stream(rest)?;
                  return Ok((rest, NFSOpenClaimType::CLAIM_PREVIOUS (claim)))},
            2 => {let (rest, claim) = NFSClaimDelegateCur::from_stream(rest)?;
                  return Ok((rest, NFSOpenClaimType::CLAIM_DELEGATE_CUR(claim)))},
            3 => {let (rest, claim) = NFSClaimDelegatePrev::from_stream(rest)?;
                  return Ok((rest, NFSOpenClaimType::CLAIM_DELEGATE_PREV(claim)))},
            _ => Ok((rest,NFSOpenClaimType::CLAIM_INVALID))
        }

}
}


#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSCreateUnchecked {
    obj_fattr: NFSFATTR4
}

#[derive(Clone,Debug,PartialEq, NFSParsable)]
pub struct NFSCreateGuarded {
    obj_fattr: NFSFATTR4
}

#[derive(Clone,Debug,PartialEq, NFSParsable)]
pub struct NFSVerifier {
    verifier: u64 // fixed size opaque 8 bytes
}

#[derive(Clone,Debug,PartialEq, NFSParsable)]
pub struct NFSCreateExclusive4 {
    createverifier: NFSVerifier
}

#[derive(Clone,Debug,PartialEq, NFSParsable)]
pub struct NFSCreateExclusive41 {
    ch_createboth: NFSCreateVerFattr
}

#[derive(Clone,Debug,PartialEq, NFSParsable)]
pub struct NFSCreateVerFattr {
    cva_verf: NFSVerifier,
    cva_attrs: NFSFATTR4
}

#[derive(Clone,Debug,PartialEq)]
pub enum NFSCreateHow {
    NFSCreateUnchecked(NFSCreateUnchecked),
    NFSCreateGuarded(NFSCreateGuarded),
    NFSCreateExclusive4(NFSCreateExclusive4),
    NFSCreateExclusive41(NFSCreateExclusive41),
    NFSCreateInvalid
}

impl<'a> NFSParsable<'a,NFSCreateHow> for NFSCreateHow {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8],NFSCreateHow> {
        let (rest, createmode) = be_u32(data)?;
        match createmode {
            0 => {let (rest, thec) = NFSCreateUnchecked::from_stream(rest)?;Ok((rest, NFSCreateHow::NFSCreateUnchecked(thec)))},
            1 => {let (rest, thec) = NFSCreateGuarded::from_stream(rest)?; Ok((rest, NFSCreateHow::NFSCreateGuarded(thec)))},
            2 => {let (rest, thec) = NFSCreateExclusive4::from_stream(rest)?; Ok((rest, NFSCreateHow::NFSCreateExclusive4(thec)))},
            3 => {let (rest, thec) = NFSCreateExclusive41::from_stream(rest)?; Ok((rest, NFSCreateHow::NFSCreateExclusive41(thec)))},
            _ => Ok((rest, NFSCreateHow::NFSCreateInvalid))
            
        }
}
}
#[derive(Clone,Debug,PartialEq)]
pub enum NFSOpenType {
    OpenNoCreate,
    OpenCreate(NFSCreateHow),
    OpenInvalidType
}
impl NFSOpenType { 
    fn from_stream(data: &[u8]) -> IResult<&[u8],NFSOpenType> {
        let (rest, opentype) = be_u32(data)?;
        match opentype {
            0 => Ok((rest, NFSOpenType::OpenNoCreate)),
            1 => {
                let (rest, createhow) = NFSCreateHow::from_stream(rest)?;
                Ok((rest, NFSOpenType::OpenCreate(createhow)))
            },
            _ => Ok((rest, NFSOpenType::OpenInvalidType))
        }
    }
}

#[derive(Clone,Debug,PartialEq, NFSParsable)]
pub struct NFSCount {
    count: u32
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpRead {
    stateid: NFSStateid,
    offset: NFSOffset,
    count: NFSCount
}
#[derive(Clone,Debug,PartialEq, NFSParsable)]
pub struct NFSCookie {
    cookie: u64
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpReadDir {
    cookie: NFSCookie,
    verifier: NFSVerifier,
    dircount: NFSCount,
    maxcount: NFSCount,
    attr_request: NFSBitmap4
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpRemove {
    target: NFSComponent4
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpRename {
    oldname: NFSComponent4,
    newname: NFSComponent4
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpSetattr {
    stateid: NFSStateid,
    obj_fattr: NFSFATTR4
}
#[derive(Clone,Debug,PartialEq)]
pub enum NFSStableHow {
    UNSTABLE,
    DATA_SYNC,
    FILE_SYNC,
    STABLE_HOW_INVALID
}

fn resolve_nfs_stable_how(num: u32) -> NFSStableHow {
    match num {
        0 => NFSStableHow::UNSTABLE,
        1 => NFSStableHow::DATA_SYNC,
        2 => NFSStableHow::FILE_SYNC,
        _ => NFSStableHow::STABLE_HOW_INVALID
    }
}
impl<'a> NFSParsable<'a,NFSStableHow> for NFSStableHow {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8],NFSStableHow> {
        let (rest, num) = be_u32(data)?;
        Ok((rest,resolve_nfs_stable_how(num)))
    }
}
impl<'a> NFSParsable<'a,Vec<u8>> for Vec<u8> {
    fn from_stream(data: &'a[u8]) -> IResult<&'a [u8],Vec<u8>> {
        let (rest, length) = be_u32(data)?;
        let (rest, d) = take(length)(rest)?;
        let f = Vec::from(d);
        let (rest, _) = take(align_fill_bytes(length))(rest)?;
        Ok((rest, f))
    }
}
impl<'a> NFSParsable<'a,Vec<u32>> for Vec<u32> {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8],Vec<u32>> {
        let (mut rest, length) = be_u32(data)?;
        let mut data = Vec::new();
        for i in 0 .. length {
            let (rest_,item) = be_u32(rest)?;
            data.push(item);
            rest = rest_;
        }
        Ok((rest, data))
}
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpWrite {
    stateid: NFSStateid,
    offset: NFSOffset,
    stable: NFSStableHow,
    data: NFSWriteDataMaybeIncomplete
//    data: Vec<u8>
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSCompleteData {
    data: Vec<u8>
}
#[derive(Clone,Debug,PartialEq)]
pub struct NFSIncompleteData {
    length: u32,
    data: Vec<u8>
}
#[derive(Clone,Debug,PartialEq)]
pub enum NFSWriteDataMaybeIncomplete { // a hack to parse only the length: field from an OpWrite until I figure out how to re-feed a reassembled tcp stream to a parser
    CompleteData(NFSCompleteData),
    IncompleteData(NFSIncompleteData)
}

impl<'a> NFSParsable<'a,NFSWriteDataMaybeIncomplete> for NFSWriteDataMaybeIncomplete {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSWriteDataMaybeIncomplete> {
        let test = Vec::<u8>::from_stream(data);
        match test {
            Ok((rest, res)) => {debug!("Got complete data for write. Size is {:?}",res.len()); Ok((rest, NFSWriteDataMaybeIncomplete::CompleteData( NFSCompleteData {data: res})))},
            Err(_) => { Err(Err::Incomplete(nom::Needed::Unknown))}
        }
    }
}
#[derive(Clone,Debug,PartialEq)]
pub enum NFSCallbackSecParms {
    ParmsNONE,
    ParmsSYS(RpcAuthUnix),
    ParmsGSS(NFSGSSCBHandles),
    ParmsInvalid,
}
impl<'a> NFSParsable<'a,NFSCallbackSecParms> for NFSCallbackSecParms {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSCallbackSecParms> {
        let (rest, num) = be_u32(data)?;
        match num {
            0 => Ok((rest, NFSCallbackSecParms::ParmsNONE)),
            1 => {let (rest, p) = RpcAuthUnix::from_stream(rest)?; Ok((rest, NFSCallbackSecParms::ParmsSYS( p)))},
            6 => {let (rest, p) = NFSGSSCBHandles::from_stream(rest)?; Ok((rest, NFSCallbackSecParms::ParmsGSS( p)))},
            _ => Ok((rest, NFSCallbackSecParms::ParmsInvalid))

        }

    }

}
impl<'a> NFSParsable<'a, Vec<NFSCallbackSecParms>> for Vec<NFSCallbackSecParms> { // list of raw utf8 strings really
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], Vec<NFSCallbackSecParms>> {
        let (mut rest, length) = be_u32(data)?;
        let mut theVector = Vec::new();
        for i in 0 .. length {
            let (rest_, theDE) = NFSCallbackSecParms::from_stream(rest)?;

            theVector.push(theDE);
            rest = rest_;
        }
        Ok((rest, theVector))
    }
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSGSSCBHandles {
    gcbp_service: u32,
    gcbp_handle_from_server: Vec<u8>,
    gcbp_handle_from_client: Vec<u8>
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpBackchannelCtl {
    bca_cb_program: u32,
    bca_sec_parms: NFSCallbackSecParms
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpCommit {
    offset: NFSOffset,
    count: NFSCount
}
#[derive(Clone,Debug,PartialEq)]
pub struct NFSSessionid {
    sessionid: [u32;4]
}
impl<'a> NFSParsable<'a,NFSSessionid> for NFSSessionid {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSSessionid> {
        let (mut rest, first) = be_u32(data)?;
        let mut mydings: [u32;4] = [0,0,0,0];
        mydings[0] = first;
        for i in 1..4 {
            let (rest_,ding) = be_u32(rest)?;
            mydings[i] = ding;
            rest = rest_;
        }
        Ok((rest, NFSSessionid {sessionid: mydings} ))
    }
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpBindConnToSession {
    bctsa_sessid: NFSSessionid,
    btsa_dir: u32,
    bctsa_use_conn_in_rdma_mode: NFSBool
}
impl<'a> NFSParsable<'a,i64> for i64 {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], i64> {
        let (rest, i) = be_i64(data)?;
        Ok((rest, i))
    }

}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSTime {
    seconds: i64,
    nfseconds: u32
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpGetDirDelegation {
    gdda_signal_deleg_avail: NFSBool,
    gdda_notification_types: NFSBitmap4,
    gdda_child_attr_delay: NFSTime,
    gdda_dir_attr_delay: NFSTime,
    gdda_child_attributes: NFSBitmap4,
    gdda_dir_attributes: NFSBitmap4
}
#[derive(Clone,Debug,PartialEq)]
pub struct NFSDeviceid {
    deviceid: [u32;4]
}
impl<'a> NFSParsable<'a,NFSDeviceid> for NFSDeviceid {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSDeviceid> {
        let (mut rest, first) = be_u32(data)?;
        let mut mydings: [u32;4] = [0,0,0,0];
        mydings[0] = first;
        for i in 1..4 {
            let (rest_,ding) = be_u32(rest)?;
            mydings[i] = ding;
            rest = rest_;
        }
        Ok((rest, NFSDeviceid {deviceid: mydings} ))
    }
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpGetDeviceInfo {
    gdia_device_id: NFSDeviceid,
    gdia_layout_type: NFSLayoutType,
    gdia_maxcount: NFSCount,
    gdia_notify_types: NFSBitmap4
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSLayoutType {
    layouttype: u32
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpGetDeviceList {
    gdla_layout_type: NFSLayoutType,
    gdla_maxdevices: NFSCount,
    gdla_cookie: NFSCookie,
    gdla_cookieverf: NFSVerifier
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSLayoutUpdate {
    lou_type: NFSLayoutType,
    lou_body: Vec<u8>
}
#[derive(Clone,Debug,PartialEq)]
pub enum NFSNewOffset {
    YES(NFSOffset),
    NO,
    INVALID
}
impl<'a> NFSParsable<'a, NFSNewOffset> for NFSNewOffset {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSNewOffset> {
        let (rest, thebool) = be_u32(data)?;
        match thebool {
            0 => Ok((rest, NFSNewOffset::NO)),
            1 => {let (rest, o) = NFSOffset::from_stream(rest)?; Ok((rest, NFSNewOffset::YES(o)))},
            _ => Ok((rest, NFSNewOffset::INVALID))
        }
    }
}

#[derive(Clone,Debug,PartialEq)]
pub enum NFSNewTime {
    YES(NFSTime),
    NO,
    INVALID
}
impl<'a> NFSParsable<'a, NFSNewTime> for NFSNewTime {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSNewTime> {
        let (rest, thebool) = be_u32(data)?;
        match thebool {
            0 => Ok((rest, NFSNewTime::NO)),
            1 => {let (rest, o) = NFSTime::from_stream(rest)?; Ok((rest, NFSNewTime::YES(o)))},
            _ => Ok((rest, NFSNewTime::INVALID))
        }
    }
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSLayoutIOMode {
    layoutiomode: u32
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpLayoutCommit {
           loca_offset: NFSOffset,
           loca_length: NFSLength,
           loca_reclaim: NFSBool,
           loca_stateid: NFSStateid,
           loca_last_write_offset: NFSNewOffset,
           loca_time_modify: NFSNewTime,
           loca_layoutupdate: NFSLayoutUpdate
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpLayoutGet {
           loga_signal_layout_avail: NFSBool,
           loga_layout_type: NFSLayoutType,
           loga_iomode: NFSLayoutIOMode,
           loga_offset: NFSOffset,
           loga_length: NFSLength,
           loga_minlength: NFSLength,
           loga_stateid: NFSStateid,
           loga_maxcount: NFSCount,
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSLayoutReturnFile {
               lrf_offset: NFSOffset,
           lrf_length: NFSLength,
           lrf_stateid: NFSStateid,
           lrf_body: Vec<u8>
}

#[derive(Clone,Debug,PartialEq)]
pub enum NFSLayoutReturn {
    LayoutReturnFile(NFSLayoutReturnFile),
    LayoutReturnFSID,
    LayoutReturnAll,
    LayoutReturnInvalid
}
impl<'a> NFSParsable<'a,NFSLayoutReturn> for NFSLayoutReturn {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSLayoutReturn> {
        let (rest, num) = be_u32(data)?;
        match num {
            1 => {let (rest, rff) = NFSLayoutReturnFile::from_stream(rest)?; Ok((rest, NFSLayoutReturn::LayoutReturnFile(rff)))},
            2 => Ok((rest,NFSLayoutReturn::LayoutReturnFSID)),
            3 => Ok((rest, NFSLayoutReturn::LayoutReturnAll)),
            _ => Ok((rest, NFSLayoutReturn::LayoutReturnInvalid))
        }
    }

}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpLayoutReturn {
           lora_reclaim: NFSBool,
           lora_layout_type: NFSLayoutType,
           lora_iomode: NFSLayoutIOMode,
           lora_layoutreturn: NFSLayoutReturn
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSSecinfoStyle {
    secinfostyle: u32
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSSecinfoNoName {
    secinfostyle: NFSSecinfoStyle
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSSlotid {
    slotid: u32
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpSequence {
    sa_sessionid: NFSSessionid,
    sa_sequenceid: NFSSequenceID,
    sa_slotid: NFSSlotid,
    sa_highest_slotid: NFSSlotid,
    sa_cachethis: NFSBool
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpSetSSV {
    ssa_ssv: Vec<u8>,
    ssa_digest: Vec<u8>
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpDestroyClientid {
    clientid: NFSClientID
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpReclaimComplete {
    rca_one_fs: NFSBool,
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpAllocate {
    aa_stateid: NFSStateid,
    aa_offset: NFSOffset,
    aa_length: NFSLength
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSNetLocName {
    name: Vec<u8>
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSNetLocUrl {
    url: Vec<u8>
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSNetLocNetAddr {
    netaddr: NFSNetAddr
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSNetAddr {
    na_r_netid: Vec<Vec<u8>>,
    na_r_addr: Vec<Vec<u8>>,
}
impl<'a> NFSParsable<'a, Vec<Vec<u8>>> for Vec<Vec<u8>> { // list of raw utf8 strings really
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], Vec<Vec<u8>>> {
        let (mut rest, length) = be_u32(data)?;
        let mut theVector = Vec::new();
        for i in 0..length {
            let (rest_, theString) = Vec::<u8>::from_stream(rest)?;
            theVector.push(theString);
            rest = rest_;
        }
        Ok((rest, theVector))
        
    }
}

#[derive(Clone,Debug,PartialEq)]
pub enum NFSNetLoc {
    NetLocName(NFSNetLocName),
    NetLocUrl(NFSNetLocUrl),
    NetLocNetAddr(NFSNetLocNetAddr),
    NetLocInvalidType
}
impl<'a> NFSParsable<'a, NFSNetLoc> for NFSNetLoc {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSNetLoc> {
        let (rest, num) = be_u32(data)?;
        match num {
            1 => {let (rest, nl) = NFSNetLocName::from_stream(rest)?; Ok((rest, NFSNetLoc::NetLocName(nl)))},
            2 => {let (rest, nl) = NFSNetLocUrl::from_stream(rest)?; Ok((rest, NFSNetLoc::NetLocUrl(nl)))},
            3 =>{let (rest, nl) = NFSNetLocNetAddr::from_stream(rest)?; Ok((rest, NFSNetLoc::NetLocNetAddr(nl)))}, 
            _ => Ok((rest, NFSNetLoc::NetLocInvalidType))
        }

    }
}
impl<'a> NFSParsable<'a, Vec<NFSNetLoc>> for Vec<NFSNetLoc> { // list of raw utf8 strings really
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], Vec<NFSNetLoc>> {
        let (mut rest, length) = be_u32(data)?;
        let mut theVector = Vec::new();
        for i in 0 .. length {
            let (rest_, theLoc) = NFSNetLoc::from_stream(rest)?;

            theVector.push(theLoc);
            rest = rest_;
        }
        Ok((rest, theVector))
    }
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpCopy {
           ca_src_stateid: NFSStateid,
           ca_dst_stateid: NFSStateid,
           ca_src_offset: NFSOffset,
           ca_dst_offset: NFSOffset,
           ca_count: NFSLength,
           ca_consecutive: NFSBool,
           ca_synchronous: NFSBool,
           ca_source_server: Vec<NFSNetLoc>
}

#[derive(Clone,Debug,PartialEq)]
pub enum NFSOp {
    NFSOpAccess (NFSOpAccess), // bitmask one be_u32 - probably useful
    NFSOpClose (NFSOpClose) , // u32 seqid,  3 x u32 stateid other - probably useful
    NFSOpCommit (NFSOpCommit), // offset 2 x u32, count u32 - whatever but need to skip
    NFSOpCreate (NFSOpCreate), // create  non-regular file // f**ed if I know what they mean with that discriminate union in the spec, check data in packet dump - possibly useful
    NFSOpDelegPurge(NFSOpDelegPurge), // 1x u64 clientid - skip
    NFSOpDelegReturn(NFSOpDelegReturn), // u32 seqid, 3x u32 stateid other - skip
    NFSOpGetattr(NFSOpGetattr), // bitmap = u32 length + array of masks - useful
    NFSOpGetFH, // no args! - also useless for us
    NFSOpLink(NFSOpLink), // component4 aka length + actual string + fill bytes to align - tangentially useful if someone's making lots of those things
    NFSOpLock(NFSOpLock), // see struct
    NFSOpLockT(NFSOpLockT), // see struct
    NFSOpLockU(NFSOpLockU), // unlock (has args)
    NFSOpLookup(NFSOpLookup), // component4 arg
    NFSOpLookupP, // no args yoohoo!
    NFSOpNVerify(NFSOpNVerify), // fattr4 args - dont care about contents
    NFSOpOpen(NFSOpOpen), // actually need this one
    NFSOpOpenAttr(NFSOpOpenAttr), // don't care, skip single bool (probably u32)
    NFSOpOpenConfirm(NFSOpOpenConfirm), // don't care, skip stateid (12 bytes) + seqid (u32)
    NFSOpOpenDowngrade(NFSOpOpenDowngrade), // don't care, skip stateid (12b) + seqid (u32) + 2xu32 (share_access,share_deny)
    NFSOpPutFH(NFSOpPutFH), // we would care about this one if we could resolve the filehandles easily, skip filehandle_length u32 + filehandle as per length
    NFSOpPutPubFH, // no args and don't care
    NFSOpPutRootFH, // no args and don't care
    NFSOpRead(NFSOpRead), // definitely want this
    NFSOpReadDir(NFSOpReadDir), // want
    NFSOpReadLink, // want, no args
    NFSOpRemove(NFSOpRemove), // want
    NFSOpRename(NFSOpRename), // want
    NFSOpRenew(NFSOpRenew), // don't care, skip clientid u64
    NFSOpRestoreFH, // no args, don't care
    NFSOpSaveFH, // no args, don't care
    NFSOpSecinfo(NFSOpSecinfo), // don't care, skip component4
    NFSOpSetattr(NFSOpSetattr), // want    
    NFSOpSetClientid(NFSOpSetClientid), // don't want, skip nfs_client_id4, cb_client4 + u32
    NFSOpSetClientidConfirm(NFSOpSetClientidConfirm), // don't want, skip clientid4, verifier4
    NFSOpVerify(NFSOpVerify), // probably don't need this, one set of fattr4
    NFSOpWrite(NFSOpWrite), // definitely want this
    NFSOpReleaseLockowner(NFSOpReleaseLockowner), // don't care, skip lock_owner
    NFSOpBackchannelCtl(NFSOpBackchannelCtl), // don't want this but it's complicated, probably need to describe struct
    NFSOpBindConnToSession(NFSOpBindConnToSession), // don't want, skip sessionid,  u32 enum, u32 bool
    NFSOpExchangeID(NFSOpExchangeID), // don't want, complex logic, need to describe struct
    NFSOpCreateSession(NFSOpCreateSession), // don't want, skip clientid, sequenceid, u32 flags, 2x channelattrs 6xcount4 + u32 rdma_id, u32 program, callback_sec_parms ( define this for backchannel_ctl and for here)
    NFSOpDestroySession(NFSOpDestroySession), // dont need this, skip sessionid 16B
    NFSOpFreeStateid(NFSOpFreeStateid), // dont need this, skip stateid
    NFSOpGetDirDelegation(NFSOpGetDirDelegation), // dont want this, skip bool, bitmap, 2x attr_notice4 ( nfstime4 signed i64 seconds + u32 nseconds), 2x bitmap
    NFSOpGetDeviceInfo(NFSOpGetDeviceInfo), // dont want, skip deviceid 16 bytes, layouttype (an enum), count4, bitmap
    NFSOpGetDeviceList(NFSOpGetDeviceList), // dont want, skip layouttype, count, cookie, verifier
    NFSOpLayoutCommit(NFSOpLayoutCommit), // dont want, complex logic
    NFSOpLayoutGet(NFSOpLayoutGet), // dont want, skip bool, layouttype, layoutiomode (an enum), offset, 2x length, stateid, count
    NFSOpLayoutReturn(NFSOpLayoutReturn), // dont want, complex logic
    NFSOpSecinfoNoName(NFSOpSecinfoNoName), // dont want, skip secinfo_style (an enum)
    NFSOpSequence(NFSOpSequence), // // dont need this, skip sessionid (4xu32), seqid u32, slotid u32, highslot u32, cache u32
    NFSOpSetSSV(NFSOpSetSSV), // dont want, skip 2x opaque varlength
    NFSOpTestStateid(NFSOpTestStateid), // dont want, skip stateid
//    NFSOpWantDelegation(NFSOpWantDelegation), // dont want, complex logic
    NFSOpDestroyClientid(NFSOpDestroyClientid), // dont need this, skip clientid u32
    NFSOpReclaimComplete(NFSOpReclaimComplete), // dont want, skip a bool
    NFSOpAllocate(NFSOpAllocate), // possibly useful, stateid, offset, length
    NFSOpCopy(NFSOpCopy), // possibly useful, 2x stateid, 2x offset, length, 2x bool, netloc4 ( need to define that)
    NFSOpCopyNotify(NFSOpCopyNotify), // dont want this, skip stateid and netloc
    NFSOpDeallocate(NFSOpDeallocate), // probably useful, stateid, offset, length
    NFSOpIOAdvise(NFSOpIOAdvise), // ehhh probably useful, enum + stateid + offset + length + bitmap
    NFSOpLayoutError(NFSOpLayoutError), // dont want, offset, length, stateid, device_error4 (deviceid, nfsstat4, nfs_opnum4)
  //  NFSOpLayoutStats(NFSOpLayoutStats), // dont want, offset, length, stateid, io_info4 (2xu64), deviceid, layoutupdate4 (layouttype + opaque varlength)
    NFSOpOffloadCancel(NFSOpOffloadCancel), // dont want, stateid
    NFSOpOffloadStatus(NFSOpOffloadStatus), // dont want, stateid
    NFSOpReadPlus(NFSOpReadPlus), // borderline useful.. stateid, offset, count
    NFSOpSeek(NFSOpSeek), // useful, stateid, offset, data_content4 (enum)
    //NFSOpWriteSame(NFSOpWriteSame), // probably useful, complex logic
    NFSOpClone(NFSOpClone), // useful, 2x stateid, 2xoffset, length
    OpILLEGAL, // call the police
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpClose {
    seqid: NFSSeqid,
    open_stateid: NFSStateid
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpDelegPurge {
    clientid: NFSClientID
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpDelegReturn {
    deleg_stateid: NFSStateid
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpNVerify {
    obj_attributes: NFSFATTR4
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpOpenAttr {
    createdir: NFSBool
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpOpenConfirm {
    open_stateid: NFSStateid,
    seqid: NFSSeqid
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpOpenDowngrade {
    open_stateid: NFSStateid,
    seqid: NFSSeqid,
    share_access: u32,
    share_deny: u32
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSFH4 {
    fh: Vec<u8>
}

//impl NFSFH4 {
//    fn from_stream(data: &[u8]) -> IResult<&[u8],NFSFH4> {
//        let (rest,fh) = Vec::<u8>::from_stream(data)?;
//        Ok((rest, NFSFH4 {fh}))
//    }
//}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpPutFH {
    object: NFSFH4
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpRenew {
    clientid: NFSClientID
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpSecinfo {
    name: NFSComponent4
}

#[derive(Clone,Debug,PartialEq,NFSParsable)] 
pub struct NFSOpSetClientidConfirm {
    clientid: NFSClientID,
    setclientid_confirm: NFSVerifier
}
#[derive(Clone,Debug,PartialEq,NFSParsable)] 
pub struct NFSClient_ID {
    verifier: NFSVerifier,
    id: Vec<u8>
}
#[derive(Clone,Debug,PartialEq,NFSParsable)] 
pub struct NFSClientAddr {
    r_netid: Vec<u8>,
    r_addr: Vec<u8>
}
#[derive(Clone,Debug,PartialEq,NFSParsable)] 
pub struct NFSCBClient {
    cb_program: u32,
    cb_location: NFSClientAddr
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpSetClientid {
    client: NFSClient_ID,
    setclientid_confirm: NFSVerifier
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpVerify {
    obj_attributes: NFSFATTR4,
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpReleaseLockowner {
    lock_owner: NFSLockOwnerOwner
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpDestroySession {
    dsa_sessionid: NFSSessionid
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpFreeStateid {
    fsa_stateid: NFSStateid

}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpSecinfoNoName {
    secinfo_style: u32,
}

impl<'a> NFSParsable<'a,Vec<NFSStateid>> for Vec<NFSStateid> {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8],Vec<NFSStateid>> {
        let (mut rest, length) = be_u32(data)?;
        let mut sids = Vec::new();
        for i in 0..length {
            let (rest_, sid) = NFSStateid::from_stream(rest)?;
            sids.push(sid);
            rest = rest_;
        }
        Ok((rest,sids))
    }
                                           
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpTestStateid {
    ts_stateids: Vec<NFSStateid>
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSClientOwner {
    co_verifier: NFSVerifier,
    co_ownerid: Vec<u8>
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSStateProtectOps {
    spo_must_enforce: NFSBitmap4,
    spo_must_allow: NFSBitmap4
}
#[derive(Clone,Debug,PartialEq)]
pub enum NFSStateProtect {
    SP4_NONE,
    SP4_MACH_CRED(NFSStateProtectOps),
    SP4_SSV(NFSStateProtectSSVParms),
    SP4_INVALID
}
impl<'a> NFSParsable<'a,NFSStateProtect> for NFSStateProtect {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], NFSStateProtect> {
        let (rest, num) = be_u32(data)?;
        match num {
            0 => Ok((rest, NFSStateProtect::SP4_NONE)),
            1 => {let (rest, sp) = NFSStateProtectOps::from_stream(rest)?; Ok((rest, NFSStateProtect::SP4_MACH_CRED(sp)))},
            2 => {let (rest, sp) = NFSStateProtectSSVParms::from_stream(rest)?; Ok((rest, NFSStateProtect::SP4_SSV(sp)))}
            _ => Ok((rest, NFSStateProtect::SP4_INVALID))
        }
    }

}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSStateProtectSSVParms {
    ssp_ops: NFSStateProtectOps,
    ssp_hash_algs: Vec<u8>,
    ssp_encr_algs: Vec<u8>,
    ssp_window: u32,
    ssp_num_gss_handles: u32
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSImplID4 {
    nii_domain: Vec<u8>,
    nii_name: Vec<u8>,
    nii_date: NFSTime
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpExchangeID {
    eia_clientowner: NFSClientOwner,
    eia_flags: u32,
    eia_state_protect: NFSStateProtect,
    eia_client_impl_id: Vec<NFSImplID4>
}
impl<'a> NFSParsable<'a, Vec<NFSImplID4>> for Vec<NFSImplID4> {
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], Vec<NFSImplID4>> {
        let (mut rest, num) = be_u32(data)?;
        let mut xs = Vec::new();
        for i in 0 .. num {
            let (rest_, x) = NFSImplID4::from_stream(rest)?;
            xs.push(x);
            rest = rest_;
        }
        Ok((rest, xs))
}

}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSChannelAttrs {
           ca_headerpadsize: NFSCount,
           ca_maxrequestsize: NFSCount,
           ca_maxresponsesize: NFSCount,
           ca_maxresponsesize_cached: NFSCount,
           ca_maxoperations: NFSCount,
           ca_maxrequests: NFSCount,
           ca_rdma_ird: u32 // u32<max 1> // seems to be set to 0 even if missing
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSSequenceID {
    sequenceid: u32
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpCreateSession {
    csa_clientid: NFSClientID,
    csa_sequence: NFSSequenceID,
    csa_flags: u32,
    csa_fore_chan_attrs: NFSChannelAttrs,
    csa_back_chan_attrs: NFSChannelAttrs,
    csa_cb_program: u32,
    csa_sec_parms: Vec<NFSCallbackSecParms>
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpCopyNotify {
           cna_src_stateid: NFSStateid,
           cna_destination_server: NFSNetLoc
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpDeallocate {
           da_stateid: NFSStateid,
           da_offset: NFSOffset,
           da_length: NFSLength
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpIOAdvise {
    io_advise_type: u32,
    iaa_stateid: NFSStateid,
    iaa_offset: NFSOffset,
    iaa_count: NFSLength,
    iaa_hints: NFSBitmap4
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSStat4 {
    status: u32, // TODO: enum with all the statuses..
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpNum {
    status: u32, // TODO: enum with all the op numbers
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSDeviceError {
    de_deviceid: NFSDeviceid,
    de_status: NFSStat4,
    de_opnum: NFSOpNum
}

impl<'a> NFSParsable<'a, Vec<NFSDeviceError>> for Vec<NFSDeviceError> { // list of raw utf8 strings really
    fn from_stream(data: &'a [u8]) -> IResult<&'a [u8], Vec<NFSDeviceError>> {
        let (mut rest, length) = be_u32(data)?;
        let mut theVector = Vec::new();
        for i in 0 .. length {
            let (rest_, theDE) = NFSDeviceError::from_stream(rest)?;

            theVector.push(theDE);
            rest = rest_;
        }
        Ok((rest, theVector))
    }
}

#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpLayoutError {
           lea_offset: NFSOffset,
           lea_length: NFSLength,
           lea_stateid: NFSStateid,
           lea_errors: Vec<NFSDeviceError>
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpOffloadCancel {
    oca_stateid: NFSStateid
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpOffloadStatus {
    osa_stateid: NFSStateid
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpReadPlus {
           rpa_stateid: NFSStateid,
           rpa_offset: NFSOffset,
           rpa_count: NFSCount
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpSeek {
           sa_stateid: NFSStateid,
           sa_offset: NFSOffset,
           sa_what: u32
}
#[derive(Clone,Debug,PartialEq,NFSParsable)]
pub struct NFSOpClone {
           cl_src_stateid: NFSStateid,
           cl_dst_stateid: NFSStateid,
           cl_src_offset: NFSOffset,
           cl_dst_offset: NFSOffset,
           cl_count: NFSLength
}


fn resolve_and_build_nfs_op(opnum: u32, data: &[u8]) -> IResult<&[u8],NFSOp>{
    match opnum {
        3 => { let (rest, builtop) = NFSOpAccess::from_stream(data)?; Ok((rest, NFSOp::NFSOpAccess(builtop))) } //
        4 => { let (rest, builtop) = NFSOpClose::from_stream(data)?; Ok((rest, NFSOp::NFSOpClose(builtop))) }
        5 => { let (rest, builtop) = NFSOpCommit::from_stream(data)?; Ok((rest, NFSOp::NFSOpCommit(builtop))) }
        6 => { let (rest, builtop) = NFSOpCreate::from_stream(data)?; Ok((rest, NFSOp::NFSOpCreate(builtop))) }
        7 => { let (rest, builtop) = NFSOpDelegPurge::from_stream(data)?; Ok((rest, NFSOp::NFSOpDelegPurge(builtop))) }
        8 => { let (rest, builtop) = NFSOpDelegReturn::from_stream(data)?; Ok((rest, NFSOp::NFSOpDelegReturn(builtop))) }
        9 => { let (rest, builtop) = NFSOpGetattr::from_stream(data)?; Ok((rest, NFSOp::NFSOpGetattr(builtop))) },
        10 => Ok((data,NFSOp::NFSOpGetFH)), //
        11 => { let (rest, builtop) = NFSOpLink::from_stream(data)?; Ok((rest, NFSOp::NFSOpLink(builtop))) }
        12 => { let (rest, builtop) = NFSOpLock::from_stream(data)?; Ok((rest, NFSOp::NFSOpLock(builtop))) }
        13 => { let (rest, builtop) = NFSOpLockT::from_stream(data)?; Ok((rest, NFSOp::NFSOpLockT(builtop))) }
        14 => { let (rest, builtop) = NFSOpLockU::from_stream(data)?; Ok((rest, NFSOp::NFSOpLockU(builtop))) }
        15 => { let (rest, builtop) = NFSOpLookup::from_stream(data)?; Ok((rest, NFSOp::NFSOpLookup(builtop))) }
        16 => Ok((data,NFSOp::NFSOpLookupP)), //
        17 => { let (rest, builtop) = NFSOpNVerify::from_stream(data)?; Ok((rest, NFSOp::NFSOpNVerify(builtop))) }
        18 => { let (rest, builtop) = NFSOpOpen::from_stream(data)?; Ok((rest, NFSOp::NFSOpOpen(builtop))) } //
        19 => { let (rest, builtop) = NFSOpOpenAttr::from_stream(data)?; Ok((rest, NFSOp::NFSOpOpenAttr(builtop))) }
        20 => { let (rest, builtop) = NFSOpOpenConfirm::from_stream(data)?; Ok((rest, NFSOp::NFSOpOpenConfirm(builtop))) }
        21 => { let (rest, builtop) = NFSOpOpenDowngrade::from_stream(data)?; Ok((rest, NFSOp::NFSOpOpenDowngrade(builtop))) }
        22 => { let (rest, builtop) = NFSOpPutFH::from_stream(data)?; Ok((rest, NFSOp::NFSOpPutFH(builtop))) }
        23 => Ok((data,NFSOp::NFSOpPutPubFH)),
        24 => Ok((data, NFSOp::NFSOpPutRootFH)),
        25 => { let (rest, builtop) = NFSOpRead::from_stream(data)?; Ok((rest, NFSOp::NFSOpRead(builtop))) } //
        26 => { let (rest, builtop) = NFSOpReadDir::from_stream(data)?; Ok((rest, NFSOp::NFSOpReadDir(builtop))) }
        27 => Ok((data,NFSOp::NFSOpReadLink)), //
        28 => { let (rest, builtop) = NFSOpRemove::from_stream(data)?; Ok((rest, NFSOp::NFSOpRemove(builtop))) }
        29 => { let (rest, builtop) = NFSOpRename::from_stream(data)?; Ok((rest, NFSOp::NFSOpRename(builtop))) }
        30 => { let (rest, builtop) = NFSOpRenew::from_stream(data)?; Ok((rest, NFSOp::NFSOpRenew(builtop))) }
        31 => Ok((data, NFSOp::NFSOpRestoreFH)),
        32 => Ok((data,NFSOp::NFSOpSaveFH)), //
        33 => { let (rest, builtop) = NFSOpSecinfo::from_stream(data)?; Ok((rest, NFSOp::NFSOpSecinfo(builtop))) }
        34 => { let (rest, builtop) = NFSOpSetattr::from_stream(data)?; Ok((rest, NFSOp::NFSOpSetattr(builtop))) }
        35 => { let (rest, builtop) = NFSOpSetClientid::from_stream(data)?; Ok((rest, NFSOp::NFSOpSetClientid(builtop))) }
        36 => { let (rest, builtop) = NFSOpSetClientidConfirm::from_stream(data)?; Ok((rest, NFSOp::NFSOpSetClientidConfirm(builtop))) }
        37 => { let (rest, builtop) = NFSOpVerify::from_stream(data)?; Ok((rest, NFSOp::NFSOpVerify(builtop))) }
        38 => { let (rest, builtop) = NFSOpWrite::from_stream(data)?; Ok((rest, NFSOp::NFSOpWrite(builtop))) }
        39 => { let (rest, builtop) = NFSOpReleaseLockowner::from_stream(data)?; Ok((rest, NFSOp::NFSOpReleaseLockowner(builtop))) }
        40 => { let (rest, builtop) = NFSOpBackchannelCtl::from_stream(data)?; Ok((rest, NFSOp::NFSOpBackchannelCtl(builtop))) }
        41 => { let (rest, builtop) = NFSOpBindConnToSession::from_stream(data)?; Ok((rest, NFSOp::NFSOpBindConnToSession(builtop))) }
        42 => { let (rest, builtop) = NFSOpExchangeID::from_stream(data)?; Ok((rest, NFSOp::NFSOpExchangeID(builtop))) }
        43 => { let (rest, builtop) = NFSOpCreateSession::from_stream(data)?; Ok((rest, NFSOp::NFSOpCreateSession(builtop))) }
        44 => { let (rest, builtop) = NFSOpDestroySession::from_stream(data)?; Ok((rest, NFSOp::NFSOpDestroySession(builtop))) }
        45 => { let (rest, builtop) = NFSOpFreeStateid::from_stream(data)?; Ok((rest, NFSOp::NFSOpFreeStateid(builtop))) }
        46 => { let (rest, builtop) = NFSOpGetDirDelegation::from_stream(data)?; Ok((rest, NFSOp::NFSOpGetDirDelegation(builtop))) }
        47 => { let (rest, builtop) = NFSOpGetDeviceInfo::from_stream(data)?; Ok((rest, NFSOp::NFSOpGetDeviceInfo(builtop))) }
        48 => { let (rest, builtop) = NFSOpGetDeviceList::from_stream(data)?; Ok((rest, NFSOp::NFSOpGetDeviceList(builtop))) }
        49 => { let (rest, builtop) = NFSOpLayoutCommit::from_stream(data)?; Ok((rest, NFSOp::NFSOpLayoutCommit(builtop))) }
        50 => { let (rest, builtop) = NFSOpLayoutGet::from_stream(data)?; Ok((rest, NFSOp::NFSOpLayoutGet(builtop))) }
        51 => { let (rest, builtop) = NFSOpLayoutReturn::from_stream(data)?; Ok((rest, NFSOp::NFSOpLayoutReturn(builtop))) }
        52 => { let (rest, builtop) = NFSOpSecinfoNoName::from_stream(data)?; Ok((rest, NFSOp::NFSOpSecinfoNoName(builtop))) }
        53 => { let (rest, builtop) = NFSOpSequence::from_stream(data)?; Ok((rest, NFSOp::NFSOpSequence(builtop))) }
        54 => { let (rest, builtop) = NFSOpSetSSV::from_stream(data)?; Ok((rest, NFSOp::NFSOpSetSSV(builtop))) }
        55 => { let (rest, builtop) = NFSOpTestStateid::from_stream(data)?; Ok((rest, NFSOp::NFSOpTestStateid(builtop))) }
//        56 => { let (rest, builtop) = NFSOpWantDelegation::from_stream(data)?; Ok((rest, NFSOp::NFSOpWantDelegation(builtop))) }
        57 => { let (rest, builtop) = NFSOpDestroyClientid::from_stream(data)?; Ok((rest, NFSOp::NFSOpDestroyClientid(builtop))) }
        58 => { let (rest, builtop) = NFSOpReclaimComplete::from_stream(data)?; Ok((rest, NFSOp::NFSOpReclaimComplete(builtop))) }
        59 => { let (rest, builtop) = NFSOpAllocate::from_stream(data)?; Ok((rest, NFSOp::NFSOpAllocate(builtop))) }
        60 => { let (rest, builtop) = NFSOpCopy::from_stream(data)?; Ok((rest, NFSOp::NFSOpCopy(builtop))) }
        61 => { let (rest, builtop) = NFSOpCopyNotify::from_stream(data)?; Ok((rest, NFSOp::NFSOpCopyNotify(builtop))) }
        62 => { let (rest, builtop) = NFSOpDeallocate::from_stream(data)?; Ok((rest, NFSOp::NFSOpDeallocate(builtop))) }
        63 => { let (rest, builtop) = NFSOpIOAdvise::from_stream(data)?; Ok((rest, NFSOp::NFSOpIOAdvise(builtop))) }
        64 => { let (rest, builtop) = NFSOpLayoutError::from_stream(data)?; Ok((rest, NFSOp::NFSOpLayoutError(builtop))) }
  //      65 => { let (rest, builtop) = NFSOpLayoutStats::from_stream(data)?; Ok((rest, NFSOp::NFSOpLayoutStats(builtop))) }
        66 => { let (rest, builtop) = NFSOpOffloadCancel::from_stream(data)?; Ok((rest, NFSOp::NFSOpOffloadCancel(builtop))) }
        67 => { let (rest, builtop) = NFSOpOffloadStatus::from_stream(data)?; Ok((rest, NFSOp::NFSOpOffloadStatus(builtop))) }
        68 => { let (rest, builtop) = NFSOpReadPlus::from_stream(data)?; Ok((rest, NFSOp::NFSOpReadPlus(builtop))) }
        69 => { let (rest, builtop) = NFSOpSeek::from_stream(data)?; Ok((rest, NFSOp::NFSOpSeek(builtop))) }
    //    70 => { let (rest, builtop) = NFSOpWriteSame::from_stream(data)?; Ok((rest, NFSOp::NFSOpWriteSame(builtop))) }
        71 => { let (rest, builtop) = NFSOpClone::from_stream(data)?; Ok((rest, NFSOp::NFSOpClone(builtop))) }
        10044 => {debug!("got op num {:x?} for data {:x?}",opnum,data); Ok((data, NFSOp::OpILLEGAL))}, //
        _ => {debug!("got op num {:x?} for data {:x?}",opnum,data); Ok((data, NFSOp::OpILLEGAL))}, //
    }

}

