# wind-tuiche

TUIC protocol implementation using Cloudflare's quiche library.

## Overview

`wind-tuiche` is a TUIC (TCP/UDP over QUIC) implementation using the [quiche](https://github.com/cloudflare/quiche) library from Cloudflare. It provides an alternative to `wind-tuic` which uses the quinn library.

## Features

- Complete TUIC v5 protocol support
- QUIC Datagram support (RFC 9221)
- BoringSSL integration via quiche
- Async/await architecture with tokio
- Server and client implementations

## Usage

### Server

```rust
use wind_tuiche::{TuicheInboundBuilder, CongestionControl};
use uuid::Uuid;

let server = TuicheInboundBuilder::new()
    .listen_addr("0.0.0.0:443".parse()?)
    .certificate(cert)
    .private_key(key)
    .user(uuid, "password".to_string())
    .build()
    .await?;
```

### Client

```rust
use wind_tuiche::TuicheOutboundBuilder;

let client = TuicheOutboundBuilder::new()
    .server_addr("server.example.com:443".parse()?)
    .server_name("server.example.com".to_string())
    .uuid(uuid)
    .password("password".to_string())
    .build()?;
```

## Building

```bash
cargo build --features "server,client"
```

## Testing

```bash
cargo test
```

## License

MIT OR Apache-2.0