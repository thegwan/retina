/// Build: cargo b --features label,d_ttl_mean,d_ttl_max,d_ttl_med,d_ttl_min,d_winsize_med,d_winsize_min,d_winsize_mean,d_winsize_sum,d_winsize_std,d_ttl_sum --bin log_features
/// Run: sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=info ./target/debug/log_features -c configs/offline.toml

use retina_core::config::load_config;
use retina_core::subscription::features::Features;
use retina_core::Runtime;
use retina_filtergen::filter;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use anyhow::Result;
use clap::Parser;

// Define command-line arguments.
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "features.jsonl"
    )]
    outfile: PathBuf,
}

//#[filter("ipv4 and tcp and tls and (tls.sni ~ 'zoom\\.us' or tls.sni ~ 'nflxvideo\\.net' or tls.sni ~ 'ttvnw\\.net' or tls.sni ~ 'teams\\.microsoft\\.com')")]
//#[filter("ipv4 and tcp and tls and (tls.sni ~ 'zoom\\.us' or tls.sni ~ 'nflxvideo\\.net' or tls.sni ~ 'ttvnw\\.net' or tls.sni ~ 'teams\\.microsoft\\.com' or tls.sni ~ 'facebook\\.com' or tls.sni ~ 'fbcdn\\.net' or tls.sni ~ 'twitter\\.com' or tls.sni ~ 'twimg\\.com')")]
//#[filter("ipv4 and tcp and tls and (tls.sni ~ 'meet\\.google\\.com')")]
//#[filter("ipv4 and tcp and tls and (tls.sni ~ 'teams\\.microsoft\\.com')")]
#[filter("ipv4 and tcp and tls")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    // Use `BufWriter` to improve the speed of repeated write calls to the same file.
    let file = Mutex::new(BufWriter::new(File::create(&args.outfile)?));
    let cnt = AtomicUsize::new(0);

    let callback = |conn: Features| {
        if let Ok(serialized) = serde_json::to_string(&conn) {
            // println!("{}", conn);
            let mut wtr = file.lock().unwrap();
            wtr.write_all(serialized.as_bytes()).unwrap();
            wtr.write_all(b"\n").unwrap();
            cnt.fetch_add(1, Ordering::Relaxed);
        }
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();

    let mut wtr = file.lock().unwrap();
    wtr.flush()?;
    println!("Done. Logged {:?} connections to {:?}", cnt, &args.outfile);
    Ok(())
}
