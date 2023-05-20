//! Features.

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::dpdk::{rte_get_tsc_hz, rte_rdtsc};
use crate::filter::FilterResult;
use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::ethernet::Ethernet;
use crate::protocols::packet::ipv4::Ipv4;
use crate::protocols::packet::tcp::Tcp;
use crate::protocols::packet::Packet;
use crate::protocols::stream::{ConnParser, Session};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};

use std::fmt;

use anyhow::Result;
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;

use lazy_static::lazy_static;

lazy_static! {
    static ref TSC_HZ: f32 = unsafe { rte_get_tsc_hz() as f32 };
}

/// A features record.
#[derive(Debug)]
pub struct Features {
    // /// Server name (for TLS connections)
    // pub sni: String,
    /// Features,
    pub features: Vec<f32>,
}

impl Features {}

impl Serialize for Features {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Features", 1)?;
        // state.serialize_field("sni", &self.sni)?;
        state.serialize_field("fts", &self.features)?;
        state.end()
    }
}

impl fmt::Display for Features {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.features,)?;
        Ok(())
    }
}

impl Subscribable for Features {
    type Tracked = TrackedFeatures;

    fn level() -> Level {
        Level::Connection
    }

    // TODO: return a vector of all known parsers.
    fn parsers() -> Vec<ConnParser> {
        vec![]
    }

    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
    ) {
        match subscription.filter_packet(&mbuf) {
            FilterResult::MatchTerminal(idx) | FilterResult::MatchNonTerminal(idx) => {
                if let Ok(ctxt) = L4Context::new(&mbuf, idx) {
                    conn_tracker.process(mbuf, ctxt, subscription);
                }
            }
            FilterResult::NoMatch => drop(mbuf),
        }
    }
}

/// Tracks a feature record throughout its lifetime.
///
/// ## Note
/// Internal connection state is an associated type of a `pub` trait, and therefore must also be
/// public. Documentation is hidden by default to avoid confusing users.
#[doc(hidden)]
pub struct TrackedFeatures {
    #[cfg(feature = "timing")]
    compute_cycles: u64,
    // sni: String,
    //   syn_tsc: i32,
    //   syn_ack_tsc: i32,
    //   ack_tsc: i32,
    //   s_last_tsc: i32,
    //   d_last_tsc: i32,
    //   s_pkt_cnt: i32,
    //   d_pkt_cnt: i32,
      s_bytes_sum: i32,
    //   d_bytes_sum: i32,
    //   s_ttl_sum: i32,
    //   d_ttl_sum: i32,
    //   proto: i32,
}

impl TrackedFeatures {
    #[inline]
    fn update(&mut self, segment: L4Pdu) -> Result<()> {
        #[cfg(feature = "timing")]
        let start_tsc = unsafe { rte_rdtsc() };
        // let curr_tsc = unsafe { rte_rdtsc() } as i32;
        let mbuf = segment.mbuf_ref();
        let eth = mbuf.parse_to::<Ethernet>()?;
        let ipv4 = eth.parse_to::<Ipv4>()?;

        if segment.dir {
            // self.s_last_tsc = curr_tsc;
            // self.s_pkt_cnt += 1;
            self.s_bytes_sum += ipv4.total_length() as i32;
            // self.s_ttl_sum += ipv4.time_to_live() as i32;
            // if self.syn_ack_tsc != -1 && self.ack_tsc == -1 {
            //     let tcp = ipv4.parse_to::<Tcp>()?;
            //     if tcp.ack() {
            //         self.ack_tsc = curr_tsc;
            //     }
            // }
        } else {
        //     self.d_last_tsc = curr_tsc;
        //     self.d_pkt_cnt += 1;
        //     self.d_bytes_sum += ipv4.total_length() as i32;
        //     self.d_ttl_sum += ipv4.time_to_live() as i32;
        //     if self.syn_ack_tsc == -1 && self.ack_tsc == -1 {
        //         let tcp = ipv4.parse_to::<Tcp>()?;
        //         if tcp.synack() {
        //             self.syn_ack_tsc = curr_tsc;
        //         }
        //     }
        }
        // self.proto = ipv4.protocol() as i32;
        #[cfg(feature = "timing")]
        {
            self.compute_cycles += unsafe { rte_rdtsc() } - start_tsc;
        }
        Ok(())
    }

    #[inline]
    fn extract_features(&mut self) -> Vec<f32> {
        #[cfg(feature = "timing")]
        let start_tsc = unsafe { rte_rdtsc() };
        // let dur =
        //     (self.s_last_tsc.max(self.d_last_tsc)).saturating_sub(self.syn_tsc) as f32 / *TSC_HZ;
        // let s_ttl_mean = self.s_ttl_sum as f32 / self.s_pkt_cnt as f32;
        // let d_ttl_mean = self.d_ttl_sum as f32 / self.d_pkt_cnt as f32;
        // let s_load = self.s_bytes_sum as f32 * 8.0 / dur;
        // let d_load = self.d_bytes_sum as f32 * 8.0 / dur;
        // let s_bytes_mean = self.s_bytes_sum as f32 / self.s_pkt_cnt as f32;
        // let d_bytes_mean = self.d_bytes_sum as f32 / self.d_pkt_cnt as f32;
        // let s_iat_mean =
        //     self.s_last_tsc.saturating_sub(self.syn_tsc) as f32 / *TSC_HZ / self.s_pkt_cnt as f32;
        // let d_iat_mean = self.d_last_tsc.saturating_sub(self.syn_ack_tsc) as f32
        //     / *TSC_HZ
        //     / self.d_pkt_cnt as f32;
        // let syn_ack = self.syn_ack_tsc.saturating_sub(self.syn_tsc) as f32 / *TSC_HZ;
        // let ack_dat = self.ack_tsc.saturating_sub(self.syn_ack_tsc) as f32 / *TSC_HZ;
        // let tcp_rtt = syn_ack + ack_dat;
        let features = vec![
            // dur,
            // self.proto as f32,
            self.s_bytes_sum as f32,
            // self.d_bytes_sum as f32,
            // s_ttl_mean,
            // d_ttl_mean,
            // s_load,
            // d_load,
            // self.s_pkt_cnt as f32,
            // self.d_pkt_cnt as f32,
            // s_bytes_mean,
            // d_bytes_mean,
            // s_iat_mean,
            // d_iat_mean,
            // tcp_rtt,
            // syn_ack,
            // ack_dat,
        ];
        #[cfg(feature = "timing")]
        {
        self.compute_cycles += unsafe { rte_rdtsc() } - start_tsc;
        }
        features
    }
}

impl Trackable for TrackedFeatures {
    type Subscribed = Features;

    fn new(_five_tuple: FiveTuple) -> Self {
        // let tsc = unsafe { rte_rdtsc() } as i32;
        TrackedFeatures {
            #[cfg(feature = "timing")]
            compute_cycles: 0,
            // sni: String::new(),
            // syn_tsc: tsc,
            // syn_ack_tsc: -1,
            // ack_tsc: -1,
            // s_last_tsc: tsc,
            // d_last_tsc: -1,
            // s_pkt_cnt: 0,
            // d_pkt_cnt: 0,
            s_bytes_sum: 0,
            // d_bytes_sum: 0,
            // s_ttl_sum: 0,
            // d_ttl_sum: 0,
            // proto: -1,
        }
    }

    fn pre_match(&mut self, pdu: L4Pdu, _session_id: Option<usize>, subscription: &Subscription<Self::Subscribed>) {
        tsc_start!(t);
        self.update(pdu).unwrap_or(());
        tsc_elapsed!(subscription.timers, "update", t);
    }

    fn on_match(&mut self, _session: Session, _subscription: &Subscription<Self::Subscribed>) {
        // if let SessionData::Tls(tls) = session.data {
        //     self.sni = tls.sni().to_string();
        // }
    }

    fn post_match(&mut self, pdu: L4Pdu, subscription: &Subscription<Self::Subscribed>) {
        tsc_start!(t);
        self.update(pdu).unwrap_or(());
        tsc_elapsed!(subscription.timers, "update", t);
    }

    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>) {
        tsc_start!(t);
        let features = self.extract_features();
        tsc_elapsed!(subscription.timers, "extract_features", t);
        let conn = Features {
            // sni: self.sni.clone(),
            features,
        };
        tsc_record!(subscription.timers, "compute_cycles", self.compute_cycles);
        subscription.invoke(conn);
    }

    fn early_terminate(&self) -> bool {
        // self.ctos.packet_cnt + self.stoc.packet_cnt >= 4
        false
    }
}
