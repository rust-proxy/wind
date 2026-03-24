set shell := ["nu", "-c"]

run:
    cargo run --package wind --bin wind -- -f config.toml
test:
    cargo test -- --ignored