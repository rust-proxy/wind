# wind-naive

NaiveProxy outbound for the [Wind](https://github.com/rust-proxy/wind) proxy toolkit.

Uses [cronet-rs](https://github.com/rust-proxy/cronet-rs) (Chromium Cronet C API bindings) to
establish HTTP/2 or QUIC CONNECT tunnels with NaiveProxy padding protocol.

On Linux, callers can pass a `LinuxSocketPolicy` and a TCP connect timeout to
`NaiveOutbound::new_with_socket_policy`. The policy applies to every TCP and QUIC socket
in that engine. Keep separate outbounds for different interface or mark values.

## Usage

```toml
[dependencies]
wind-naive = "0.2"
# feature "dynamic":          prefer runtime loading on desktop (also the platform default)
# feature "static-link":      embed Cronet on desktop unless "dynamic" is enabled
# feature "download":         fetch + SHA-256-verify a prebuilt libcronet
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
    quic_congestion_control: "bbr"                  # default|bbr|bbrv2|cubic|reno
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
| `quic_congestion_control` | `String` | `default` | `default` / `bbr` / `bbrv2` / `cubic` / `reno` |
| `trusted_root_certificates` | `Option<String>` | `None` | Custom CA PEM |
| `ech_enabled` | `bool` | `false` | Encrypted Client Hello |
| `extra_headers` | `HashMap<String,String>` | `{}` | Extra CONNECT headers |
| `cronet_lib_path` | `Option<String>` | `None` | Path to libcronet.so |

## libcronet

`wind-naive` requires the **Chromium Cronet** C shared library at runtime,
unless built with `--features download` (see [Auto-downloading
libcronet](#auto-downloading-libcronet)).

### Quick start (Linux)

| Step | Command |
|------|---------|
| 1. Get libcronet | Download from [naiveproxy releases](https://github.com/klzgrad/naiveproxy/releases) or build from Chromium |
| 2. Place it | `cp libcronet.so.119 /usr/local/lib/libcronet.so` |
| 3. Set path | `cronet_lib_path: "/usr/local/lib/libcronet.so"` in config, or `LD_LIBRARY_PATH` |

### Search order

When `cronet_lib_path` is `None`, the loader tries (in order; the build-time
downloaded library, when the `download` feature is enabled, comes first):

```
0. <OUT_DIR>/libcronet-<platform>.so   ← only with `--features download`
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
     ├── dial(target) + handshake()  ── HTTP/2 CONNECT + padding
     │
     ▼
[NaiveProxy Server :443]
     │
     ▼
[Internet]
```

### Data relay

Dropping a pending TCP or UDP-over-TCP dial cancels its native CONNECT stream.
This wakes the worker waiting for response headers and keeps the shared engine
available for other requests.

```
tokio stream.read()  ── bounded queue ──▶ blocking NaiveWriteHalf
tokio stream.write() ◀─ bounded queue ─── blocking NaiveReadHalf
                                              │
                                   shared Cronet stream/engine
```

Reading and writing run on separate workers: an idle blocking read cannot stall
the next outgoing request. Each worker retains the engine until its native I/O
half is dropped. TCP EOF closes only its own direction: local EOF drains the
write queue and sends native `END_STREAM`, while responses continue until remote
EOF. Remote EOF shuts down the local write half without stopping uploads.
The relay waits for both directions on clean shutdown and propagates I/O errors.
When the relay ends or is cancelled, a guard cancels native
I/O, channels close, and session guards join both workers on blocking threads.
Read buffers remain alive until Cronet reports completion or cancellation.

## UDP (UDP-over-TCP v2)

NaiveProxy's classic protocol only tunnels **TCP** (an HTTP `CONNECT` byte
stream). To carry UDP, `wind-naive` layers [sing-box's UDP-over-TCP **v2**
framing](https://github.com/sagernet/sing/tree/main/common/uot) over a single
CONNECT tunnel:

- All datagrams for one UDP association are multiplexed over **one** tunnel,
  opened to the magic authority `sp.v2.udp-over-tcp.arpa` (instead of a literal
  TCP CONNECT per packet).
- Each frame is `address ‖ u16 length ‖ payload`, so replies flow back to the
  client (no more black-holed responses), and a single tunnel can fan out to
  many destinations.

> **Server requirement:** the upstream must understand UoT v2 (e.g. a sing-box
> server with a `naive` inbound). A stock Chromium NaiveProxy server only speaks
> TCP CONNECT and will reject the magic authority.

```
UdpStream ── frame queue ──▶ write worker ──▶ Naive/UoT server
UdpStream ◀─ packet queue ── read worker  ◀── Naive/UoT server
```

## Building

```bash
# Default (dynamic loading; needs a system/installed libcronet)
cargo build

# Wind CLI with the naive outbound and a build-time auto-downloaded libcronet
cargo build -p wind --features download

# Static link (macOS/iOS recommended)
cargo build --no-default-features --features static-link
```

### Auto-downloading libcronet

The `download` feature delegates to `cronet-sys`'s build script, which fetches
the prebuilt library matching the target from
[rust-proxy/cronet-binaries](https://github.com/rust-proxy/cronet-binaries/releases)
into `OUT_DIR` and verifies its **SHA-256** against a pinned checksum. No network
is touched unless the feature is enabled. In dynamic mode the downloaded path is
tried automatically (after an explicit `cronet_lib_path`, before the system
search paths); in static mode the archive is staged and linked automatically.

## Half-close end-to-end tests

`tests/half_close_e2e.rs` exercises Wind's public outbound through a real Cronet
library, a Docker sing-box Naive server, and a Python TCP target container sharing
the server network namespace.
The destination waits for request EOF before sending a 256 KiB response. Both
HTTP/2 and HTTP/3 cover empty, 7-byte, and 256 KiB requests, including repeated
client shutdown, repeated with three fresh clients per transport. The HTTP/3
server listens only on UDP to prevent H2 fallback.
Temporary certificates and configuration are uploaded through the Docker API;
containers are removed on success or failure. No production configuration or
public proxy is used.

Start Docker with Linux containers. The tests pull the pinned
`ghcr.io/sagernet/sing-box:v1.14.4` image and a digest-pinned
`python:3.13-alpine` target image; no host server binary is used.
Run from the Wind repository root:

```powershell
$env:WIND_NAIVE_CRONET_LIB = 'C:\tools\libcronet-windows-amd64.dll'
cargo test -p wind-naive --test half_close_e2e --locked -- --ignored
```

Set `DOCKER_HOST` for a remote daemon (TCP/HTTP or a local socket); otherwise
the platform default Docker socket is used. Targets listen only on loopback
inside the shared container namespace; no container-to-host callback route or
`CLIENT_IP` is needed. Fixtures are uploaded rather than bind-mounted, including
with remote daemons.
On Unix, export the same variables with the corresponding shared library path.
These tests are explicitly ignored in ordinary test runs; when
selected, missing dependencies or startup failures fail the test instead of
silently skipping it. Reverse-direction half-close and cancellation remain
covered by the bridge unit tests; this interoperability suite specifically
guards responses to EOF-delimited client requests.

## License

MIT OR Apache-2.0

### Static linking

Use `CRONET_LIB_DIR=/path/to/lib cargo build -p wind-naive --features static-link`.
The CLI forwards this as `--features naive-static`. On desktop an explicit
`dynamic` (`naive-dynamic` in the CLI) selects runtime loading when both modes are enabled. Linux glibc and musl
require different native archives. Windows requires MSVC, `cronet.lib`, and the
`link_flags.txt` generated by cronet-binaries. No runtime `cronet_lib_path` is
needed. Docker E2E tests also run without `WIND_NAIVE_CRONET_LIB` in static mode.

Windows downloads automatically match Rust's CRT. The default `/MD` archive
needs no extra `RUSTFLAGS`; it statically links Cronet and uses the MSVC runtime
DLLs. Explicit `+crt-static` builds select the `/MT` archive and should also
pass `--target`. A manually supplied archive must match the application's CRT.


### Optional static archive download

```sh
cargo build -p wind-naive --features static-link,download-static
```

The download switch does not select a backend. In dynamic mode it keeps
runtime `libloading` and performs no download. With the static backend it fetches
the target's archive and verifies SHA-256 before linking. A supplied
`CRONET_LIB_DIR` overrides downloading. The legacy `download` feature retains
its existing behavior.

Static archives for Linux (glibc/musl), Windows MSVC, Apple, and Android
are pinned to the `static-20261116.1` release with SHA-256 verification.
Custom unpinned assets require `CRONET_DOWNLOAD_SHA256`. Windows also downloads
the matching `.link-flags.txt` and requires its pinned checksum or
`CRONET_DOWNLOAD_LINK_FLAGS_SHA256`.
