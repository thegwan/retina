use retina_core::config::load_config;
use retina_core::rte_lcore_id;
use retina_core::subscription::ConnFeatures;
use retina_core::{rte_rdtsc, Runtime};
use retina_filtergen::filter;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc,Mutex};

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
        default_value = "connfeatures.jsonl"
    )]
    outfile: PathBuf,
}

//#[filter("ipv4 and tls and (tls.sni ~ 'nflxvideo\\.net$' or tls.sni ~ 'row\\.aiv-cdn\\.net$' or tls.sni ~ 'media\\.dssott\\.com$' or tls.sni ~ 'vod-adaptive\\.akamaized\\.net$' or tls.sni ~ 'hls\\.ttvnw\\.net$' or tls.sni ~ 'aoc\\.tv\\.apple\\.com$' or tls.sni ~ 'airspace-.*\\.cbsivideo\\.com$' or tls.sni ~ 'prod\\.gccrunchyroll\\.com$' or tls.sni ~ 'vrv\\.akamaized\\.net$')")]
#[filter("ipv4 and tls")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    // Use `BufWriter` to improve the speed of repeated write calls to the same file.
    let file = Mutex::new(BufWriter::new(File::create(&args.outfile)?));
    let cnt = AtomicUsize::new(0);

    let mut writers: Vec<BufWriter<File>> = vec![];
    for i in 0..8 {
        let extension = &args.outfile.extension().expect("no extension");
        let base_name = &args.outfile.file_stem().expect("no file name");

        let fname = format!(
            "{}_{}.{}",
            base_name.to_string_lossy(),
            i + 1,
            extension.to_string_lossy()
        );
        println!("{}", fname);
        writers.push(BufWriter::new(File::create(&fname)?));
    }

    let mut core_counts = vec![0,0,0,0,0,0,0,0];

    let callback = |conn: ConnFeatures| {
        let core = unsafe { rte_lcore_id() } as usize;
        let ptr = core_counts.as_ptr();
        let mut core_cnt = unsafe { *ptr.offset(0) };
        core_cnt += 1;
        println!("{}: {}", core, core_cnt);
        if let Ok(serialized) = serde_json::to_string(&conn) {
            // println!("{}", conn);
            // let mut wtr = file.lock().unwrap();
            // let wtr = &writers[core];
            // let mut core_count = &mut core_counts[core];
            // *core_count += 1;
            // println!("{}", core_count);
            // wtr.write_all(serialized.as_bytes()).unwrap();
            // wtr.write_all(b"\n").unwrap();
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
