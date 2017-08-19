use std::str;
use nom::{IResult,HexDisplay};
use ssh_parser::ssh;

use rparser::{RParser,R_STATUS_OK,R_STATUS_FAIL};

enum SSHConnectionState {
    Start,
    ClientIdent,
    ServerIdent,
    Next,

    Error
}

pub struct SSHParser<'a> {
    _name: Option<&'a[u8]>,

    state: SSHConnectionState,
    buffer_clt: Vec<u8>,
    buffer_srv: Vec<u8>,
}

impl<'a> SSHParser<'a> {
    pub fn new(name: &'a[u8]) -> SSHParser<'a> {
        SSHParser{
            _name: Some(name),
            state: SSHConnectionState::Start,
            buffer_clt: Vec::new(),
            buffer_srv: Vec::new(),
        }
    }

    fn parse_ident(&mut self, i: &[u8]) -> u32 {
        match ssh::parse_ssh_identification(i) {
            IResult::Done(rem,(ref crap, ref res)) => {
                // In version 2.0, the SSH server is allowed to send an arbitrary number of
                // UTF-8 lines before the final identification line containing the server
                // version.
                if crap.len() > 0 {
                    info!("Extra lines before SSH version:");
                    for line in crap.iter() {
                        info!("{}", line.to_hex(16));
                    }
                }
                debug!("parse_ssh_identification: {:?}",res);
                self.state = match self.state {
                    SSHConnectionState::Start       => SSHConnectionState::ClientIdent,
                    SSHConnectionState::ClientIdent => SSHConnectionState::ServerIdent,
                    _ => { return R_STATUS_FAIL; },
                };
                info!("protocol\n{}", res.proto.to_hex(16));
                info!("software\n{}", res.software.to_hex(16));
            },
            e @ _ => {
                warn!("parse_ssh_identification: {:?}",e);
                self.state = SSHConnectionState::Error;
            },
        };
        R_STATUS_OK
    }

    fn parse_packet(&mut self, i: &[u8], direction:u8) -> u32 {
        debug!("parse_ssh_packet direction: {}", direction);
        debug!("\tbuffer_clt size: {}", self.buffer_clt.len());
        debug!("\tbuffer_srv size: {}", self.buffer_srv.len());
        let mut v : Vec<u8>;
        // Check if a record is being defragmented
        let self_buffer =
            if direction == 0 { &mut self.buffer_srv }
            else { &mut self.buffer_clt };
        let buf = match self_buffer.len() {
            0 => i,
            _ => {
                v = self_buffer.split_off(0);
                v.extend_from_slice(i);
                v.as_slice()
            },
        };
        // info!("parsing:\n{}", buf.to_hex(16));
        match ssh::parse_ssh_packet(buf) {
            IResult::Done(rem,ref res) => {
                debug!("parse_ssh_packet: {:?}",res);
            },
            IResult::Incomplete(_e) => {
                debug!("Defragmentation required (SSH packet): {:?}", _e);
                self_buffer.extend_from_slice(buf);
            },
            e @ _ => {
                warn!("parse_ssh_packet: {:?}",e);
                self.state = SSHConnectionState::Error;
            },
        };
        // info!("after parsing:\n{}", self_buffer.to_hex(16));
        R_STATUS_OK
    }
}


impl<'a> RParser for SSHParser<'a> {
    fn parse(&mut self, i: &[u8], direction: u8) -> u32 {
        match self.state {
            SSHConnectionState::Start |
            SSHConnectionState::ClientIdent  => self.parse_ident(i),
            SSHConnectionState::ServerIdent |
            SSHConnectionState::Next         => self.parse_packet(i,direction),
            SSHConnectionState::Error        => R_STATUS_FAIL,
        }
    }
}

pub fn ssh_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    true
}

