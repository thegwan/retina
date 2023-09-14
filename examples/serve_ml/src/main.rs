/// Build: cargo b --features dur,s_bytes_sum,s_bytes_mean --bin serve_ml
/// Run: sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=info ./target/debug/serve_ml -c configs/offline.toml -m /mnt/netml/datasets/app_class/test/rust_rf.bin -o pred.json
/// /mnt/netml/datasets/iot_lite/pkts_5/features_40961


use retina_core::config::load_config;
use retina_core::config::RuntimeConfig;
use retina_core::subscription::features::Features;
use retina_core::Runtime;
use retina_filtergen::filter;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

// use smartcore::dataset::Dataset;
// use smartcore::linalg::basic::arrays::{Array, Array2};
use smartcore::linalg::basic::matrix::DenseMatrix;
// use smartcore::metrics::accuracy;
// use smartcore::model_selection::train_test_split;
use smartcore::tree::decision_tree_classifier::DecisionTreeClassifier;
// use smartcore::ensemble::random_forest_classifier::RandomForestClassifier;

// Define command-line arguments.
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "CONFIG_FILE")]
    config: PathBuf,
    #[clap(short, long, parse(from_os_str), value_name = "MODEL_FILE")]
    model_file: PathBuf,
    #[clap(short, long, parse(from_os_str), value_name = "OUT_FILE")]
    outfile: PathBuf,
}

#[filter("ipv4 and tcp and tls")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let mut file = File::create(args.outfile)?;
    let cnt = AtomicUsize::new(0);
    let clf = load_clf(&args.model_file)?;

    let callback = |features: Features| {
        // //#[cfg(feature = "capture_start")]
        // println!("Syn ts: {}", features.syn_ts);
        let feature_vec = features.feature_vec;
        let instance = DenseMatrix::new(1, feature_vec.len(), feature_vec, false);
        //   let start = Instant::now();
        let pred = clf.predict(&instance).unwrap();
        //   println!("predict: {:?}", start.elapsed());
        //println!("{:?}", pred);
        
        cnt.fetch_add(1, Ordering::Relaxed);
        // let res = serde_json::to_string(&(conn.sni, pred[0])).unwrap();
        // let res = serde_json::to_string(&pred[0]).unwrap();
        // let mut wtr = file.lock().unwrap();
        // wtr.write_all(res.as_bytes()).unwrap();
        // wtr.write_all(b"\n").unwrap();
    };
    let mut runtime = Runtime::new(config.clone(), filter, callback)?;
    runtime.run();

    let output = Output {
        config,
        num_conns: cnt.load(Ordering::SeqCst),
    };
    if let Ok(serialized) = serde_json::to_string(&output) {
        file.write_all(serialized.as_bytes())?;
    }

    println!("Done. Processed {:?} connections", cnt);
    Ok(())
}

/// Loads a trained classifier from `file`.
fn load_clf(
    fname: &PathBuf,
) -> Result<DecisionTreeClassifier<f64, usize, DenseMatrix<f64>, Vec<usize>>> {
    let mut file = File::open(fname)?;
    let clf: DecisionTreeClassifier<f64, usize, DenseMatrix<f64>, Vec<usize>> =
        bincode::deserialize_from(&mut file)?;
    Ok(clf)
}

#[derive(Debug, Serialize)]
struct Output {
    config: RuntimeConfig,
    num_conns: usize,
}
