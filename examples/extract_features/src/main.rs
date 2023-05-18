use retina_core::config::load_config;
use retina_core::subscription::Features;
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
}

#[filter("ipv4 and tcp")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let cnt = AtomicUsize::new(0);

    let callback = |conn: Features| {
        cnt.fetch_add(1, Ordering::Relaxed);
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();

    println!("Done. Extract features from {:?} connections", cnt);
    Ok(())
}
