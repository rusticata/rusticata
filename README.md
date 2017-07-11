# Rusticata

[![Build Status](https://travis-ci.org/rusticata/rusticata.svg?branch=master)](https://travis-ci.org/rusticata/rusticata)

## Overview

Rusticata is a proof-of-concept implementation of using Rust parsers in
Suricata.

This project is based on:
- [nom](https://github.com/Geal/nom) a Rust parser combinator framework
- a nom [TLS parser](https://github.com/rusticata/tls-parser)

**This is proof-of-concept code** to show to feasibility of the implementation of safe and efficient parsers
in suricata.

## Build

Run `cargo build` for a build in debug mode, `cargo build --release` for release mode.

Use `cargo install` to install the library, or set the `LD_LIBRARY_PATH` environment variable.

## Testing with suricata

You need the [suricata](https://github.com/rusticata/suricata) version from the [rusticata project](https://github.com/rusticata/rusticata)

Checkout the `rust` branch.

```
git clone https://github.com/rusticata/suricata.git
cd suricata
git checkout rust
```

Configure suricata to enable the Rust app-layer:
```
./configure --enable-rusticata --with-librusticata-libraries=PATH_TO/rusticata/target/debug/
```

Build and install as usual.

Enable the Rust app-layer in your suricata config:
```
app-layer:
  protocols:
    rust:
      enabled: yes
```

For the moment, only the Rust TLS parser is enabled. Due to the fact that only one parser can handle a protocol,
you have to disable the default TLS parser in suricata config:
```
app-layer:
  protocols:
    tls:
      enabled: no
```

## Rules
Here are a few examples of rules:
```
alert rust any any -> any any (msg:"Rust TLS Ciphers test match"; rust.tls.cipher:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; sid:123456; rev:1;)

alert rust any any -> any any (msg:"Rust TLS heartbeat overflow attempt"; flow:established; app-layer-event:rust.overflow_heartbeat_message; flowint:rust.anomaly.count,+,1; classtype:protocol-command-decode; sid:123457; rev:1;)
alert rust any any -> any any (msg:"Rust TLS invalid state"; flow:established; app-layer-event:rust.invalid_state; flowint:rust.anomaly.count,+,1; classtype:protocol-command-decode; sid:123458; rev:1;)
```

## Debug
The Rust layer uses the global log level from suricata. To get (really) verbose information about TLS parsing, run
```
SC_LOG_LEVEL=Debug suricata -k none -vvvvv -r tls-example.pcapng
```


## License

This library is licensed under the GNU Lesser General Public License version 2.1, or (at your option) any later version.
