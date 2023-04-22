# Serve ML

Serve ML models

### Build and run
```
cargo build --release --bin serve_ml
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/serve_ml -c <path/to/config.toml>
```
