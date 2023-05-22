use retina_core::config::load_config;
use retina_core::subscription::ConnectionFrame;
use retina_core::Runtime;
use retina_filtergen::filter;

use std::fs::{read, File};
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Result;
use clap::Parser;
use pcap_file::pcap::PcapWriter;

use pnet::packet::ethernet::MutableEthernetPacket as Ethernet;
use pnet::packet::ipv4::MutableIpv4Packet as Ipv4;
use pnet::packet::MutablePacket;
use pnet::packet::Packet;

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
        default_value = "dump.pcap"
    )]
    outfile: PathBuf,
}

#[filter("ipv4 and tls")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let key_bytes = read(&args.keyfile).expect("Failed to read key file.");
    let key: [u8; 16] = key_bytes.try_into().expect("Incorrect key size.");

    let file = File::create(&args.outfile)?;
    let pcap_writer = Mutex::new(PcapWriter::new(file)?);

    let callback = |pkt: ConnectionFrame| {
        if let Some(mut eth) = Ethernet::owned(pkt.data) {
            let payload = Ethernet::payload_mut(&mut eth);
            if let Some(mut ipv4) = Ipv4::new(payload) {
                let src_anon = ipcrypt::encrypt(Ipv4::get_source(&ipv4), &key);
                let dst_anon = ipcrypt::encrypt(Ipv4::get_destination(&ipv4), &key);
                Ipv4::set_source(&mut ipv4, src_anon);
                Ipv4::set_destination(&mut ipv4, dst_anon);
            }
            let mut pcap_writer = pcap_writer.lock().unwrap();
            pcap_writer
                .write(1, 0, &eth.packet(), eth.packet().len() as u32)
                .unwrap();
        }
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();
    Ok(())
}
