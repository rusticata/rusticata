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
}

impl<'a> SSHParser<'a> {
    pub fn new(name: &'a[u8]) -> SSHParser<'a> {
        SSHParser{
            _name: Some(name),
            state: SSHConnectionState::Start,
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
                debug!("parse_ssh: {:?}",res);
                self.state = match self.state {
                    SSHConnectionState::Start       => SSHConnectionState::ClientIdent,
                    SSHConnectionState::ClientIdent => SSHConnectionState::ServerIdent,
                    _ => { return R_STATUS_FAIL; },
                };
                info!("protocol\n{}", res.proto.to_hex(16));
                info!("software\n{}", res.software.to_hex(16));
            },
            e @ _ => warn!("parse_ssh: {:?}",e),
        };
        R_STATUS_OK
    }

    fn parse_packet(&mut self, i: &[u8]) -> u32 {
        match ssh::parse_ssh_packet(i) {
            IResult::Done(rem,ref res) => {
                debug!("parse_ssh: {:?}",res);
            },
            e @ _ => warn!("parse_ssh: {:?}",e),
        };
        R_STATUS_OK
    }
}


impl<'a> RParser for SSHParser<'a> {
    fn parse(&mut self, i: &[u8], _direction: u8) -> u32 {
        match self.state {
            SSHConnectionState::Start |
            SSHConnectionState::ClientIdent  => self.parse_ident(i),
            SSHConnectionState::ServerIdent |
            SSHConnectionState::Next         => self.parse_packet(i),
            SSHConnectionState::Error        => R_STATUS_FAIL,
        }
    }
}

pub fn ssh_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    true
}

