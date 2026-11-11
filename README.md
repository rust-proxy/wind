# Wind

[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://app.codspeed.io/rust-proxy/wind?utm_source=badge)

## QUIC backends

Quiche is compiled unconditionally by `wind-quic` and `wind-tuic`, including
32-bit targets and `--no-default-features` builds. There is no `quiche` Cargo
feature. Quinn remains an optional backend with a separately selected Rustls
crypto provider. Applications still select their backend at runtime.

Building the Quiche backend requires the target's BoringSSL C/C++ toolchain,
CMake and libclang; Windows builds also require NASM. Cross builds need the
corresponding compiler and sysroot. The workspace patches the core `quiche`,
`tokio-quiche` and `datagram-socket` crates to the same pinned Git revision of
`rust-proxy/quiche` so every backend consumer receives the same portability
fixes. The `forks/quiche` submodule is the reference and editing checkout.

## Naive / cronet

The `naive` outbound (`crates/wind-naive`) uses Chromium Cronet through the
[`cronet-rs`](https://github.com/rust-proxy/cronet-rs) bindings, which need a
`libcronet` shared library at runtime. To avoid a manual install, build with the
opt-in `download` feature:

```bash
cargo build -p wind --features download
```

`cronet-sys`'s build script then fetches the prebuilt matching the target from
[`rust-proxy/cronet-binaries`](https://github.com/rust-proxy/cronet-binaries/releases)
into `OUT_DIR` and verifies its SHA-256 against a pinned checksum. The feature is
off by default so ordinary builds never touch the network. See
[`crates/wind-naive/README.md`](crates/wind-naive/README.md) for details.

## Acknowledgments

- [fast-socks5](https://github.com/dizda/fast-socks5)
- [yimu-rs](https://github.com/yfaming/yimu-rs)