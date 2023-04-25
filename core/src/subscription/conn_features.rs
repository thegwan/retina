//! Connection features.
//!
//! This is a connection-level subscription that provides TCP and/or UDP
//! connection features. It does not deliver payload data.
//!
//!
//! ## Example
//! Logs TCP/22 and TCP/23 connection records to a file:
//! ```
//! #[filter("tcp.port = 80 or tcp.port = 443")]
//! fn main() {
//!     // TBD
//! }
//! ```

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
use crate::protocols::stream::{ConnParser, Session, SessionData};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};

// use std::collections::HashMap;
// use std::collections::HashSet;
use std::fmt;
// use std::ops::Index;

use anyhow::Result;
// use ndarray::Array;
// use ndarray_stats::SummaryStatisticsExt;
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;
// use statrs::statistics::Data;
// use statrs::statistics::{Distribution, Max, Min, OrderStatistics};

use lazy_static::lazy_static;

lazy_static! {
    static ref TSC_HZ: f64 = unsafe { rte_get_tsc_hz() as f64 };
}

/// A connection features record.
///
/// This subscribable type returns general information regarding TCP and UDP connections but does
/// does not track payload data. If applicable, Retina internally manages stream reassembly. All
/// connections are interpreted using flow semantics.
#[derive(Debug)]
pub struct ConnFeatures {
    /// Server name (for TLS connections)
    pub sni: String,
    /// Features,
    pub features: Vec<f64>,
}

impl ConnFeatures {
   
}

impl Serialize for ConnFeatures {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ConnFeatures", 2)?;
        state.serialize_field("sni", &self.sni)?;
        state.serialize_field("fts", &self.features)?;
        state.end()
    }
}

impl fmt::Display for ConnFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}> {}<",
            self.sni, self.features[0], self.features[4],
        )?;
        Ok(())
    }
}

impl Subscribable for ConnFeatures {
    type Tracked = TrackedConnFeatures;

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

/// Tracks a connection record throughout its lifetime.
///
/// ## Note
/// Internal connection state is an associated type of a `pub` trait, and therefore must also be
/// public. Documentation is hidden by default to avoid confusing users.
#[doc(hidden)]
pub struct TrackedConnFeatures {
    sni: String,
    ctos: FlowFeatures,
    stoc: FlowFeatures,
}

impl TrackedConnFeatures {
    #[inline]
    fn update(&mut self, segment: L4Pdu) {
        if segment.dir {
            self.ctos.insert_segment(segment);
        } else {
            self.stoc.insert_segment(segment);
        }
    }

    #[inline]
    fn extract_features(&self) -> Vec<f64> {
        // up_pkt_cnt, up_pkt_size_mean, up_win_size_mean, up_iat_mean
        // dn_pkt_cnt, dn_pkt_size_mean, dn_win_size_mean, dn_iat_mean
        let mut features = vec![];
        self.ctos.extract_features(&mut features);
        self.stoc.extract_features(&mut features);
        features
    }
}

impl Trackable for TrackedConnFeatures {
    type Subscribed = ConnFeatures;

    fn new(_five_tuple: FiveTuple) -> Self {
        TrackedConnFeatures {
            sni: String::new(),
            ctos: FlowFeatures::new(),
            stoc: FlowFeatures::new(),
        }
    }

    fn pre_match(&mut self, pdu: L4Pdu, _session_id: Option<usize>) {
        self.update(pdu);
    }

    fn on_match(&mut self, session: Session, _subscription: &Subscription<Self::Subscribed>) {
        if let SessionData::Tls(tls) = session.data {
            self.sni = tls.sni().to_string();
        }
    }

    fn post_match(&mut self, pdu: L4Pdu, _subscription: &Subscription<Self::Subscribed>) {
        self.update(pdu)
    }

    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>) {
        let conn = ConnFeatures {
            sni: self.sni.clone(),
            features: self.extract_features(),
        };
        subscription.invoke(conn);
    }

    fn early_terminate(&self) -> bool {
        self.ctos.packet_cnt + self.stoc.packet_cnt >= 4
    }
}

/// A uni-directional flow.
#[derive(Debug, Clone, Serialize)]
pub struct FlowFeatures {
    /// connection start timestamp
    pub start_tsc: u32,
    /// time offset from start of connection in ns
    pub delta_ns: Vec<u32>,
    /// number of packets observed in flow
    pub packet_cnt: u32,
    /// sum of IP packet lengths
    pub ip_total_length: u32,
    /// sum of TCP window sizes
    pub tcp_window_size: u32,
}

impl FlowFeatures {
    fn new() -> Self {
        FlowFeatures {
            start_tsc: unsafe { rte_rdtsc() } as u32,
            delta_ns: vec![],
            packet_cnt: 0,
            ip_total_length: 0,
            tcp_window_size: 0,
        }
    }

    #[inline]
    fn insert_segment(&mut self, segment: L4Pdu) {
        let mbuf = segment.mbuf_ref();
        if let Ok(eth) = mbuf.parse_to::<Ethernet>() {
            if let Ok(ipv4) = eth.parse_to::<Ipv4>() {
                if let Ok(tcp) = ipv4.parse_to::<Tcp>() {
                    let curr_tsc = unsafe { rte_rdtsc() } as u32;
                    let delta_ns =
                        ((curr_tsc.saturating_sub(self.start_tsc)) as f64 / *TSC_HZ * 1e9) as u32;
                    self.delta_ns.push(delta_ns);
                    self.packet_cnt += 1;
                    self.ip_total_length += ipv4.total_length() as u32;
                    self.tcp_window_size += tcp.window() as u32;
                }
            }
        }
    }

    fn extract_features(&self, features: &mut Vec<f64>) {
        if self.packet_cnt == 0 {
            features.push(0.0); // packet count
            features.push(0.0); // mean packet size (bytes)
            features.push(0.0); // mean window size (window-size units)
            features.push(0.0); // mean inter-arrival time (ns)
        } else {
            let pktsize_mean = self.ip_total_length as f64 / self.packet_cnt as f64;
            let winsize_mean = self.tcp_window_size as f64 / self.packet_cnt as f64;

            let mut iat_sum = 0.0;
            let mut cnt = 0;
            for i in 1..self.delta_ns.len() {
                iat_sum += (self.delta_ns[i] - self.delta_ns[i - 1]) as f64;
                cnt += 1;
            }

            let iat_mean = if cnt > 0 { iat_sum / (cnt as f64) } else { 0.0 };

            features.extend_from_slice(&[
                self.packet_cnt as f64,
                pktsize_mean,
                winsize_mean,
                iat_mean,
            ]);
        }
    }
}
