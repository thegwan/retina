# Connection Features Logger

Demonstrates logging connection features to a file.

### Build and run
```
cargo build --release --bin log_features
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/log_features -c <path/to/config.toml>
```
