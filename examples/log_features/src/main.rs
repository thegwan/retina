use retina_core::config::load_config;
use retina_core::subscription::packet_features::PacketFeature;
use retina_core::subscription::PacketFeatures;
use retina_core::Runtime;
use retina_filtergen::filter;

use std::fs::{read, File};
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::Result;
use clap::Parser;
use serde::Serialize;

// Define command-line arguments.
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    keyfile: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "pktfeatures.jsonl"
    )]
    outfile: PathBuf,
}

#[filter("ipv4 and tcp")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let key_bytes = read(&args.keyfile).expect("Failed to read key file.");
    let key: [u8; 16] = key_bytes.try_into().expect("Incorrect key size.");

    // Use `BufWriter` to improve the speed of repeated write calls to the same file.
    let file = Mutex::new(BufWriter::new(File::create(&args.outfile)?));
    let cnt = AtomicUsize::new(0);

    let callback = |conn: PacketFeatures| {
        let record = FlowRecord {
            c_ip: encrypt_ip(conn.five_tuple.orig.ip(), &key).unwrap(),
            c_port: conn.five_tuple.orig.port(),
            s_ip: encrypt_ip(conn.five_tuple.resp.ip(), &key).unwrap(),
            s_port: conn.five_tuple.resp.port(),
            proto: conn.five_tuple.proto,
            ts: conn.ts,
            pkts: conn.packets,
        };
        if let Ok(serialized) = serde_json::to_string(&record) {
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

#[derive(Debug, Serialize)]
struct FlowRecord {
    c_ip: IpAddr,
    c_port: u16,
    s_ip: IpAddr,
    s_port: u16,
    proto: usize,
    ts: i64,
    pkts: Vec<PacketFeature>,
}

fn encrypt_ip(ip: IpAddr, key: &[u8; 16]) -> Result<IpAddr> {
    match ip {
        IpAddr::V4(ipv4) => {
            let ipv4_enc = ipcrypt::encrypt(ipv4, key);
            Ok(IpAddr::V4(ipv4_enc))
        }
        IpAddr::V6(ipv6) => {
            let cipher = Aes128::new(GenericArray::from_slice(key));
            let mut octets = ipv6.octets();
            let block = GenericArray::from_mut_slice(&mut octets);
            cipher.encrypt_block(block);
            let bytes: [u8; 16] = block.as_slice().try_into()?;
            Ok(IpAddr::from(bytes))
        }
    }
}
