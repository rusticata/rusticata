/// A type to represent all supported types for parser 'get'-like functions
#[derive(Clone, Debug, PartialEq)]
pub enum Variant<'a> {
    Bool(bool),
    Bytes(&'a [u8]),
    Str(&'a str),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    USize(usize),

    List(Box<Vec<Variant<'a>>>),
}

impl<'a> Variant<'a> {
    pub fn from_slice<T>(v: &'a [T]) -> Variant<'a>
    where
        Variant<'a>: From<&'a T>,
    {
        let v = v.iter().map(|s| Variant::from(s)).collect();
        Variant::List(Box::new(v))
    }

    pub fn from_vec<T>(v: &'a Vec<T>) -> Variant<'a>
    where
        Variant<'a>: From<&'a T>,
    {
        let v = v.iter().map(|s| Variant::from(s)).collect();
        Variant::List(Box::new(v))
    }
}

use std::convert::From;

macro_rules! variant_from_primitive {
    ( $t:ty, $it:expr ) => {
        impl<'a> From<$t> for Variant<'a> {
            fn from(input: $t) -> Self {
                $it(input)
            }
        }
    };
}

variant_from_primitive!(bool, Variant::Bool);
variant_from_primitive!(u8, Variant::U8);
variant_from_primitive!(u16, Variant::U16);
variant_from_primitive!(u32, Variant::U32);
variant_from_primitive!(u64, Variant::U64);
variant_from_primitive!(usize, Variant::USize);
impl<'a> From<&'a [u8]> for Variant<'a> {
    fn from(input: &'a [u8]) -> Self {
        Variant::Bytes(input)
    }
}

impl<'a> From<&'a str> for Variant<'a> {
    fn from(input: &'a str) -> Self {
        Variant::Str(input)
    }
}

impl<'a> From<&'a String> for Variant<'a> {
    fn from(input: &'a String) -> Self {
        Variant::Str(&input)
    }
}

#[cfg(test)]
mod tests {
    use super::Variant;
    use std::mem;

    #[test]
    fn variant_size() {
        // expected: 24: 8 (variant) + 16 (slice)
        println!("sizeof Variant: {}", mem::size_of::<Variant>());
    }
}
