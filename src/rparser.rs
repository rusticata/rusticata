//! common functions for all parsers

use crate::Variant;

/// Interface of all Rusticata parsers.
///
/// A object implementing the RParser trait is an instance of a parser,
/// including the state (and all associated variables).
pub trait RParser : Send + Sync {
    // XXX static functions seem to cause problems with hashmaps
    // fn probe(&[u8]) -> bool;

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
    fn parse(&mut self, data:&[u8], direction:u8) -> u32;

    /// Request data from key
    fn get(&self, _key: &str) -> Option<Variant> { None }

    /// Returns the available keys for the `get` function
    fn keys(&self) -> ::std::slice::Iter<&str> { [].iter() }
}

/// Interface of a parser builder
pub trait RBuilder : Send + Sync {
    fn new(&self) -> Box<dyn RParser>;

    fn probe(&self, data:&[u8]) -> bool;
}

// status: return code, events

pub const R_STATUS_EVENTS : u32  = 0x0100;

pub const R_STATUS_OK : u32      = 0x0000;
pub const R_STATUS_FAIL : u32    = 0x0001;

pub const R_STATUS_EV_MASK : u32 = 0x0f00;
pub const R_STATUS_MASK : u32    = 0x00ff;

#[macro_export]
macro_rules! r_status_is_ok {
    ($status:expr) => { ($status & $crate::R_STATUS_MASK) == $crate::R_STATUS_MASK }
}

#[macro_export]
macro_rules! r_status_has_events {
    ($status:expr) => { ($status & $crate::R_STATUS_EV_MASK) == $crate::R_STATUS_EVENTS }
}

// Constants
pub const STREAM_TOSERVER : u8 = 0;
pub const STREAM_TOCLIENT : u8 = 1;