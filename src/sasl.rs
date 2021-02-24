use nom::combinator::map;
use nom::multi::length_data;
use nom::number::streaming::be_u32;
use nom::IResult;

#[derive(Debug, PartialEq)]
pub struct SaslBuffer<'a>(pub &'a [u8]);

pub fn parse_sasl_buffer(i: &[u8]) -> IResult<&[u8], SaslBuffer> {
    map(length_data(be_u32), SaslBuffer)(i)
}
