use retina_core::config::load_config;
use retina_core::protocols::packet::ethernet::Ethernet;
use retina_core::protocols::packet::ipv4::Ipv4;
use retina_core::protocols::packet::Packet;
use retina_core::subscription::ZcFrame;
use retina_core::Runtime;
use retina_filtergen::filter;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

#[filter("")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let callback = |mbuf: ZcFrame| {
        if let Ok(eth) = mbuf.parse_to::<Ethernet>() {
            if let Ok(ipv4) = eth.parse_to::<Ipv4>() {
                println!("ihl: {}", ipv4.ihl());
                println!(
                    "flags_to_fragment_offset: {}",
                    ipv4.flags_to_fragment_offset()
                );
                println!("flags: {}", ipv4.flags());
                println!("RF: {}", ipv4.rf());
                println!("DF: {}", ipv4.df());
                println!("MF: {}", ipv4.mf());
                println!("fragment_offset: {}", ipv4.fragment_offset());
            } else {
                println!("not ipv4");
            }
        } else {
            println!("not ethernet");
        }
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();
    Ok(())
}
