# wind-tuiche

TUIC protocol implementation built on the [`tokio-quiche`](https://docs.rs/tokio-quiche) backend.

## Overview

`wind-tuiche` is a TUIC (TCP/UDP over QUIC) implementation that drives the
underlying QUIC stack with Cloudflare's [`tokio-quiche`](https://github.com/cloudflare/quiche/tree/master/tokio-quiche)
library (an async wrapper around `quiche`). It is the counterpart to
`wind-tuic`, which uses the [quinn](https://github.com/quinn-rs/quinn) stack
instead.

## Status

The **server** path implements the TUIC protocol on top of `tokio-quiche`'s
`ApplicationOverQuic` worker (see `driver.rs`):

- **Authentication** over a unidirectional stream.
- **TCP `CONNECT`** relay over bidirectional streams, bridged to the `wind-core`
  `handle_tcpstream` callback via a channel-backed duplex stream (`stream.rs`).
- **UDP** native relay over QUIC DATAGRAMs (RFC 9221) and `Packet` commands on
  unidirectional streams, using the shared `tuic-core`
  `FragmentReassemblyBuffer` for reassembly and re-encoding responses as
  datagrams (with fragmentation).
- **Heartbeat** and **Dissociate** handling.

The **client** (outbound) path is still a configuration-only placeholder.

### Authentication limitation

TUIC derives its auth token from the TLS keying-material exporter (RFC 5705).
`quiche` does not expose that exporter, so this backend **cannot
cryptographically verify the token** — it gates on the UUID being a registered
user instead. This is weaker than the quinn-based `wind-tuic` backend; treat the
quiche backend as experimental and do not rely on token secrecy alone.

## Features

- TCP-over-QUIC (`CONNECT`) relay
- UDP-over-QUIC relay with RFC 9221 DATAGRAMs + fragment reassembly
- BoringSSL via `tokio-quiche` / `quiche`
- Async/await architecture with tokio
- Server and client builder APIs

## Usage

### Server

```rust
use wind_tuiche::TuicheInboundBuilder;
use uuid::Uuid;

let server = TuicheInboundBuilder::new()
    .listen_addr("0.0.0.0:443".parse()?)
    .certificate_path("cert.pem")
    .private_key_path("key.pem")
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
