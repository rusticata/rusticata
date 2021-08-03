/// A type to represent all supported types for parser 'get'-like functions
#[derive(Clone, Debug, PartialEq)]
pub enum Variant<'a> {
    Bool(bool),
    Bytes(&'a [u8]),
    Str(&'a str),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    USize(usize),

    List(Vec<Variant<'a>>),

    OwnedStr(String),
}

impl<'a> Variant<'a> {
    pub fn from_slice<T>(v: &'a [T]) -> Variant<'a>
    where
        Variant<'a>: From<&'a T>,
    {
        let v = v.iter().map(|s| Variant::from(s)).collect();
        Variant::List(v)
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
variant_from_primitive!(i8, Variant::I8);
variant_from_primitive!(i16, Variant::I16);
variant_from_primitive!(i32, Variant::I32);
variant_from_primitive!(i64, Variant::I64);
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
        Variant::Str(input)
    }
}

#[macro_export]
macro_rules! gen_get_variants {
    // Entry point
    ($t:ident, $ns:tt, $($body:tt)* ) => {
        fn get<'b>(&'b self, key: &str) -> Option<Variant<'b>> {
            gen_get_variants!{ @gen_match $ns $t {}, self, key, $($body)* }
        }
        fn keys(&self) -> ::std::slice::Iter<&str> {
            gen_get_variants!{ @gen_keys $ns [], $($body)* }
        }
    };
    //
    // MATCH ARMS
    //
    // Simple closure case
    (@gen_match $ns:tt $t:ident {$($arms:tt)*}, $self:ident, $key:ident, $pattern:ident => |$s:ident| $closure:expr, $($tail:tt)*) => {
        gen_get_variants!{
            @gen_match
            $ns
            $t
            {
                $($arms)*
                concat!($ns, stringify!{$pattern}) => {
                    let closure = |$s: &'b $t| $closure;
                    closure($self)
                },
            },
            $self,
            $key,
            $($tail)*
        }
    };
    // Shortcut: into
    (@gen_match $ns:tt $t:ident {$($arms:tt)*}, $self:ident, $key:ident, $pattern:ident => into, $($tail:tt)*) => {
        gen_get_variants!{
            @gen_match
            $ns
            $t
            {
                $($arms)*
                concat!($ns, stringify!{$pattern}) => {
                    Some($self.$pattern.into())
                },
            },
            $self,
            $key,
            $($tail)*
        }
    };
    // Shortcut: map
    (@gen_match $ns:tt $t:ident {$($arms:tt)*}, $self:ident, $key:ident, $pattern:ident => map, $($tail:tt)*) => {
        gen_get_variants!{
            @gen_match
            $ns
            $t
            {
                $($arms)*
                concat!($ns, stringify!{$pattern}) => {
                    $self.$pattern.map(|p| p.into())
                },
            },
            $self,
            $key,
            $($tail)*
        }
    };
    // Shortcut: map_as_ref
    (@gen_match $ns:tt $t:ident {$($arms:tt)*}, $self:ident, $key:ident, $pattern:ident => map_as_ref, $($tail:tt)*) => {
        gen_get_variants!{
            @gen_match
            $ns
            $t
            {
                $($arms)*
                concat!($ns, stringify!{$pattern}) => {
                    $self.$pattern.as_ref().map(|p| p.into())
                },
            },
            $self,
            $key,
            $($tail)*
        }
    };
    // Termination rule
    (@gen_match $ns:tt $t:ident {$($arms:tt)*}, $self:ident, $key:ident, /* $($body:tt)* */  $(,)* ) => {
        match $key {
            $($arms)*
            _ => None
        }
    };
    //
    // KEYS
    //
    // Simple closure case
    (@gen_keys $ns:tt [$($arms:tt)*], $pattern:tt => |$s:ident| $closure:expr, $($tail:tt)*) => {
        gen_get_variants!{
            @gen_keys
            $ns
            [
                $($arms)* concat!($ns, stringify!{$pattern}),
            ],
            $($tail)*
        }
    };
    // Shortcut: into
    (@gen_keys $ns:tt [$($arms:tt)*], $pattern:ident => $kw:tt, $($tail:tt)*) => {
        gen_get_variants!{
            @gen_keys
            $ns
            [
                $($arms)* concat!($ns, stringify!{$pattern}),
            ],
            $($tail)*
        }
    };
    // Termination rule
    (@gen_keys $ns:tt [$($keys:tt)*], /* $($body:tt)* */  $(,)* ) => {
        [
            $($keys)*
        ].iter()
    };
}

#[cfg(test)]
mod tests {
    use super::Variant;
    use std::mem;

    #[test]
    fn variant_size() {
        // expected: 32: 8 (variant) + 24 (String)
        println!("sizeof Variant: {}", mem::size_of::<Variant>());
    }
}
