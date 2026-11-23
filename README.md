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

To embed a locally built Cronet archive instead of loading a shared library:

```bash
CRONET_LIB_DIR=/path/to/native/lib cargo build -p wind --features naive-static
```

On desktop, `naive-dynamic` selects runtime loading even when `naive-static` is enabled. Use a matching glibc or
musl archive on Linux, or `cronet.lib` and its generated `link_flags.txt` on
Windows MSVC. Existing Apple/Android archives also support static linking.
A supplied `CRONET_LIB_DIR` takes precedence over automatic downloads.

Windows downloads automatically match Rust's CRT. The default `/MD` archive
needs no extra `RUSTFLAGS`; it statically links Cronet and uses the MSVC runtime
DLLs. Explicit `+crt-static` builds select the `/MT` archive and should also
pass `--target`. A manually supplied archive must match the application's CRT.


### Optional static archive download

```sh
cargo build -p wind --features naive-static,naive-download
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

## Acknowledgments

- [fast-socks5](https://github.com/dizda/fast-socks5)
- [yimu-rs](https://github.com/yfaming/yimu-rs)
