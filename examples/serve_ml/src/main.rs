use retina_core::config::load_config;
use retina_core::subscription::ConnectionFeatures;
use retina_core::Runtime;
use retina_filtergen::filter;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use anyhow::Result;
use clap::Parser;

use smartcore::dataset::Dataset;
use smartcore::linalg::basic::arrays::{Array, Array2};
use smartcore::linalg::basic::matrix::DenseMatrix;
// use smartcore::metrics::accuracy;
// use smartcore::model_selection::train_test_split;
use smartcore::tree::decision_tree_classifier::DecisionTreeClassifier;

// Define command-line arguments.
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(short, long, parse(from_os_str), value_name = "MODEL_FILE")]
    model_file: PathBuf,
}

//#[filter("ipv4 and tls and (tls.sni ~ 'nflxvideo\\.net$' or tls.sni ~ 'row\\.aiv-cdn\\.net$' or tls.sni ~ 'media\\.dssott\\.com$' or tls.sni ~ 'vod-adaptive\\.akamaized\\.net$' or tls.sni ~ 'hls\\.ttvnw\\.net$' or tls.sni ~ 'aoc\\.tv\\.apple\\.com$' or tls.sni ~ 'airspace-.*\\.cbsivideo\\.com$' or tls.sni ~ 'prod\\.gccrunchyroll\\.com$' or tls.sni ~ 'vrv\\.akamaized\\.net$')")]
#[filter("ipv4 and tls")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    // Use `BufWriter` to improve the speed of repeated write calls to the same file.
    // let file = Mutex::new(BufWriter::new(File::create(&args.outfile)?));
    let cnt = AtomicUsize::new(0);
    let clf = load_clf(&args.model_file)?;

    let callback = |conn: ConnectionFeatures| {
        
        // if let Ok(serialized) = serde_json::to_string(&conn) {
        //     // println!("{}", conn);
        //     let mut wtr = file.lock().unwrap();
        //     wtr.write_all(serialized.as_bytes()).unwrap();
        //     wtr.write_all(b"\n").unwrap();
        //     cnt.fetch_add(1, Ordering::Relaxed);
        // }
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();

    // let mut wtr = file.lock().unwrap();
    // wtr.flush()?;
    // println!("Done. Logged {:?} connections to {:?}", cnt, &args.outfile);
    Ok(())
}

/// Loads a trained classifier from `file`.
fn load_clf(
    fname: &PathBuf,
) -> Result<DecisionTreeClassifier<f32, usize, DenseMatrix<f32>, Vec<usize>>> {
    let mut file = File::open(fname)?;
    let clf: DecisionTreeClassifier<f32, usize, DenseMatrix<f32>, Vec<usize>> =
        bincode::deserialize_from(&mut file)?;
    Ok(clf)
}
