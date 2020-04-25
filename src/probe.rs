use std::net::IpAddr;

/// Return value from protocol probe trying to identify a protocol.
pub enum ProbeResult {
    /// The format was recognized with great probability
    Certain,
    /// The format was recognized with great probability, in opposite direction
    Reverse,
    /// The format is recognized, but could be something else.
    /// Continue sending more data
    Unsure,
    /// The format is identified as not for this parser, do not send more data
    NotForUs,
    /// An error occurred in the format probe (fatal)
    Fatal,
}

pub struct L3Info {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u16,
}

pub struct L4Info {
    pub src_port: u16,
    pub dst_port: u16,
    pub l4_proto: u8,
}

/// Stateless probe for Layer 3 protocol identification
pub type ProbeL3 = fn (&[u8], &L3Info) -> ProbeResult;
/// Stateless probe for Layer 4 protocol identification
pub type ProbeL4 = fn (&[u8], &L3Info, &L4Info) -> ProbeResult;

/// Stateful probe for Layer 3 protocol identification
pub trait StateProbeL3 {
    /// Update probing state and try to identify protocol
    fn probe_l3(&mut self, data: &[u8], l3_info: &L3Info) -> ProbeResult;
}

/// Stateful probe for Layer 3 protocol identification
pub trait StateProbeL4 {
    /// Update probing state and try to identify protocol
    fn probe_l4(
        &mut self,
        data: &[u8],
        l3_info: &L3Info, // option ?
        l4_info: &L4Info,
    ) -> ProbeResult;
}
