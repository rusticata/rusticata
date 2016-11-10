extern crate tls_parser;

use tls_parser::*;

#[macro_use] extern crate enum_primitive;
use enum_primitive::FromPrimitive;

pub fn main() {
    println!(r#"#ifndef __RUSTICATA_CIPHERSUITE_PARAMS__
#define __RUSTICATA_CIPHERSUITE_PARAMS__

// THIS FILE IS AUTO-GENERATED
// DO NOT EDIT IT

"#);

    // Kx ciphers
    println!("enum TlsCipherKx {{");
    for i in 0..255 {
        match TlsCipherKx::from_u8(i) {
            Some(kx) => println!("\tKx_{:?} = {},",kx,i),
            None => break,
        }
    }
    println!("}};\n");

    // Au ciphers
    println!("enum TlsCipherAu {{");
    for i in 0..255 {
        match TlsCipherAu::from_u8(i) {
            Some(au) => println!("\tAu_{:?} = {},",au,i),
            None => break,
        }
    }
    println!("}};\n");

    // Enc ciphers
    println!("enum TlsCipherEnc {{");
    for i in 0..255 {
        match TlsCipherEnc::from_u8(i) {
            Some(enc) => println!("\tEnc_{:?} = {},",enc,i),
            None => break,
        }
    }
    println!("}};\n");

    // EncMode ciphers
    println!("enum TlsCipherEncMode {{");
    for i in 0..255 {
        match TlsCipherEncMode::from_u8(i) {
            Some(encm) => println!("\tEncMode_{:?} = {},",encm,i),
            None => break,
        }
    }
    println!("}};\n");

    // Mac ciphers
    println!("enum TlsCipherMac {{");
    for i in 0..255 {
        match TlsCipherMac::from_u8(i) {
            Some(mac) => println!("\tMac_{:?} = {},",mac,i),
            None => break,
        }
    }
    println!("}};\n");

    println!("#endif // __RUSTICATA_CIPHERSUITE_PARAMS__");
}
