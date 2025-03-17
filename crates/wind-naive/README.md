# wind-naive

NaiveProxy outbound for the [Wind](https://github.com/rust-proxy/wind) proxy toolkit.

Uses [cronet-rs](https://github.com/rust-proxy/cronet-rs) (Chromium Cronet C API bindings) to
establish HTTP/2 or QUIC CONNECT tunnels with NaiveProxy padding protocol.

## Usage

```toml
[dependencies]
wind-naive = "0.1"
# feature "dynamic" (default): load libcronet at runtime via dlopen
# feature "static-link":      link libcronet.a at compile time
```

```rust
use wind_naive::{NaiveOutbound, NaiveOutboundOpts};

let outbound = NaiveOutbound::new(NaiveOutboundOpts {
    server_address: "your-server.com:443".into(),
    username: Some("user".into()),
    password: Some("pass".into()),
    quic_enabled: true,
    ..Default::default()
}).await?;
```

## Configuration

### In Wind CLI (`config.yaml`)

```yaml
inbounds:
  - type: socks
    tag: socks-in
    listen_addr: "127.0.0.1:6666"

outbounds:
  - type: naive
    tag: naive-out
    server_address: "your-server.com:443"
    username: "user"
    password: "pass"
    quic_enabled: true
    cronet_lib_path: "/usr/lib/libcronet.so.119"   # optional
```

### Standalone Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server_address` | `String` | required | NaiveProxy server (host:port) |
| `server_name` | `Option<String>` | server host | SNI override |
| `username` | `Option<String>` | `None` | Basic auth |
| `password` | `Option<String>` | `None` | Basic auth |
| `concurrency` | `u32` | `1` | Cronet connection pool size |
| `quic_enabled` | `bool` | `false` | Use QUIC instead of HTTP/2 |
| `quic_congestion_control` | enum | `Default` | BBR / BbrV2 / Cubic / Reno |
| `trusted_root_certificates` | `Option<String>` | `None` | Custom CA PEM |
| `ech_enabled` | `bool` | `false` | Encrypted Client Hello |
| `extra_headers` | `HashMap<String,String>` | `{}` | Extra CONNECT headers |
| `cronet_lib_path` | `Option<String>` | `None` | Path to libcronet.so |

## libcronet

`wind-naive` requires the **Chromium Cronet** C shared library at runtime.

### Quick start (Linux)

| Step | Command |
|------|---------|
| 1. Get libcronet | Download from [naiveproxy releases](https://github.com/klzgrad/naiveproxy/releases) or build from Chromium |
| 2. Place it | `cp libcronet.so.119 /usr/local/lib/libcronet.so` |
| 3. Set path | `cronet_lib_path: "/usr/local/lib/libcronet.so"` in config, or `LD_LIBRARY_PATH` |

### Search order

When `cronet_lib_path` is `None`, the loader tries (in order):

```
1. libcronet.so            ← LD_LIBRARY_PATH / system default
2. ./libcronet.so          ← CWD
3. /usr/local/lib/libcronet.so
4. /opt/cronet/libcronet.so
```

## Architecture

```
[SOCKS5 :6666]
     │
     ▼
NaiveOutbound (cronet-rs)
     │
     ├── load_library("libcronet.so")
     ├── NaiveClient::start()        ── Cronet engine init
     ├── dial_and_handshake(target)  ── HTTP/2 CONNECT + padding
     │
     ▼
[NaiveProxy Server :443]
     │
     ▼
[Internet]
```

### Data relay

```
┌─────────────────────────┐
│    tokio async task     │
│  ┌───────────────────┐  │
│  │ select! loop      │  │
│  │ stream.read()    ──┼──┐ write_tx
│  │ read_rx.recv()  ◀──┼──┘ read_tx
│  └───────────────────┘  │
└─────────────────────────┘
         │ channels
┌─────────────────────────┐
│   std::thread (sync)    │
│  ┌───────────────────┐  │
│  │ NaiveConn         │  │  ← owns the Cronet stream
│  │ read() / write()  │  │  ← blocking FFI calls
│  └───────────────────┘  │
└─────────────────────────┘
```

## Building

```bash
# Default (dynamic loading)
cargo build

# With wind CLI integration
cargo build --features naive -p wind

# Static link (macOS/iOS recommended)
cargo build --no-default-features --features static-link
```

## License

MIT OR Apache-2.0
