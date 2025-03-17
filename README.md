# Wind

[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)[![License: AGPLv3](https://img.shields.io/badge/License-AGPL%20v3-red.svg)](https://www.gnu.org/licenses/agpl-3.0)

Wind is a high-performance network proxy tool written in Rust, designed to provide secure and efficient proxy services with support for multiple protocols.

## Features

- **SOCKS5 Protocol Support**: Complete implementation of the SOCKS5 protocol
- **TUIC Integration**: High-performance UDP over QUIC protocol
- **Modular Architecture**: Easily extend with new protocols and features
- **Async Runtime**: Built on Tokio for high concurrency and performance
- **Low Resource Consumption**: Efficient memory and CPU usage

## Project Structure

The project is organized as a Rust workspace with multiple crates:

- **wind**: Main binary crate with CLI interface
- **wind-core**: Core abstractions and types
- **wind-socks**: SOCKS5 protocol implementation
- **wind-tuic**: TUIC protocol implementation
- **wind-test**: Testing utilities and benchmarks

## Quick Start


## License

This project uses multiple licenses:

- The main `wind` crate is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**
- The supporting libraries (`wind-core`, `wind-socks`, `wind-tuic`, `wind-test`) are dual-licensed under **MIT** and **Apache 2.0** licenses

Please see the respective LICENSE files in each crate directory for full license texts.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- [fast-socks5](https://github.com/dizda/fast-socks5)
- [yimu-rs](https://github.com/yfaming/yimu-rs)