//! common functions for all parsers

pub use crate::probe::{L3Info, L4Info, ProbeL4, ProbeResult};
use crate::Variant;

/// Direction of current packet in current stream
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Packet is sent from client to server
    ToServer,
    /// Packet is sent from server to client
    ToClient,
}

/// Return value from protocol probe trying to identify a protocol.
#[derive(Debug, Eq, PartialEq)]
pub enum ParseResult {
    /// No error
    ///
    /// Note that this does not mean that the parser has successfully extracted data, only that
    /// there is no error
    Ok,
    /// Parser will not analyzer more data of this protocol
    ///
    /// For ex, this can be used to add stream to bypass list
    Stop,
    /// Content is not this protocol anymore (please do not send more data, and re-analyse current)
    ProtocolChanged,
    /// An error occurred (continue calling parser)
    Error,
    /// A fatal error occurred (never call this parser again)
    Fatal,
}

/// Interface of all Rusticata parsers.
///
/// A object implementing the RParser trait is an instance of a parser,
/// including the state (and all associated variables).
pub trait RParser: Send + Sync {
    // XXX static functions seem to cause problems with hashmaps
    // fn probe(&[u8]) -> bool;

    /// Configure parser
    ///
    /// It is up to each parser to describe valid keys and expected types for values
    fn configure(&mut self, _key: u32, _value: &Variant) {}

    /// Parsing function
    ///
    /// This function is called for every packet of a connection.
    ///
    /// Arguments:
    ///
    /// - `self`: the state (parser instance)
    /// - a slice on the packet data
    /// - the direction of this packet (0: to server, 1: to client)
    ///
    /// Return value:
    ///
    /// `R_STATUS_OK` or `R_STATUS_FAIL`, possibly or'ed with
    /// `R_STATUS_EVENTS` if parsing events were raised.
    fn parse(&mut self, data: &[u8], direction: u8) -> u32 {
        let d = if direction == STREAM_TOSERVER {
            Direction::ToServer
        } else {
            Direction::ToClient
        };
        match self.parse_l4(data, d) {
            ParseResult::Ok => R_STATUS_OK,
            _ => R_STATUS_FAIL,
        }
    }

    /// Parsing function
    ///
    /// This function is called for every packet of a connection.
    fn parse_l4(&mut self, data: &[u8], direction: Direction) -> ParseResult;

    /// Request data from key
    fn get(&self, _key: &str) -> Option<Variant> {
        None
    }

    /// Returns the available keys for the `get` function
    fn keys(&self) -> ::std::slice::Iter<&str> {
        [].iter()
    }
}

/// Interface of a parser builder
pub trait RBuilder: Send + Sync {
    fn build(&self) -> Box<dyn RParser>;

    fn get_l4_probe(&self) -> Option<ProbeL4> {
        None
    }
}

// status: return code, events

pub const R_STATUS_EVENTS: u32 = 0x0100;

pub const R_STATUS_OK: u32 = 0x0000;
pub const R_STATUS_FAIL: u32 = 0x0001;

pub const R_STATUS_EV_MASK: u32 = 0x0f00;
pub const R_STATUS_MASK: u32 = 0x00ff;

#[macro_export]
macro_rules! r_status_is_ok {
    ($status:expr) => {
        ($status & $crate::R_STATUS_MASK) == $crate::R_STATUS_MASK
    };
}

#[macro_export]
macro_rules! r_status_has_events {
    ($status:expr) => {
        ($status & $crate::R_STATUS_EV_MASK) == $crate::R_STATUS_EVENTS
    };
}

// Constants
pub const STREAM_TOSERVER: u8 = 0;
pub const STREAM_TOCLIENT: u8 = 1;
