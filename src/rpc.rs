use crate::rparser::*;
use crate::rpc_parser::*;

pub struct RpcBuilder {}
impl RBuilder for RpcBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(RpcParser::new(b"rpc"))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(rpc_probe)
    }
}
pub struct RpcParser<'a> {
    _name: Option<&'a [u8]>,
    defrag_buf: Vec<u8>
}

impl<'a> RParser for RpcParser<'a> {
    fn parse_l4(&mut self, data: &[u8], _direction: Direction) -> ParseResult {
        let mut v: Vec<u8>;
        let data = if(  self.defrag_buf.is_empty() || _direction == Direction::ToClient) {data} else {
            
            v = self.defrag_buf.split_off(0); v.extend_from_slice(data); v.as_slice()};
        
        match parse_rpc(data) {
            Ok((rem, ref res)) => {
                debug!("parse_rpc: {:x?}", res);
                if !rem.is_empty() {
                    debug!("Extra bytes after RPC data, reassembling. {:x?}, {:?}",rem,rem.len());
                    self.defrag_buf.extend_from_slice(rem);
                }
            },
            Err(Err::Incomplete(needed)) => { warn!("short {:x?} bytes",needed); self.defrag_buf.extend_from_slice(data)},
//            Err(Err::Error(e)) if (e.code == nom::error::ErrorKind::Eof && _direction == Direction::ToServer) => { debug!("parse_rpc Error error code: {:x?}", e.code); self.defrag_buf.extend_from_slice(data)},
            Err(Err::Error(e)) => debug!("parse_rpc error code: {:x?}", e.code),
//            Err(Err::Failure(e))  if (e.code == nom::error::ErrorKind::Eof && _direction == Direction::ToServer) => debug!("parse_rpc Failure error code: {:x?}", e.code),
            Err(Err::Failure(e)) => debug!("parse_rpc error code: {:x?}", e.code),
        };
        ParseResult::Ok
    }
}

impl<'a> RpcParser<'a> {
    pub fn new(name: &'a [u8]) -> RpcParser<'a> {
        RpcParser { _name: Some(name), defrag_buf: Vec::new() }
    }
}

pub fn rpc_probe(i: &[u8], l4info: &L4Info) -> ProbeResult {
    if i.len() <= 2 {
        return ProbeResult::Unsure;
    }
//    if l4info.l4_proto != 6 {
//        return ProbeResult::NotForUs;
//    }
    match parse_rpc(i) {
        Ok((rem, _)) => {
//            debug!("why the heck did the probe return ok");
            if rem.is_empty() {

                ProbeResult::Certain
            } else {
                ProbeResult::Certain
            }
        },
        
        wtf => { trace!("parse_rpc: {:x?}",wtf);  ProbeResult::Certain },
    }
}
