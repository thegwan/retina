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

use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::ops::Index;

use anyhow::Result;
use ndarray::Array;
use ndarray_stats::SummaryStatisticsExt;
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;
use statrs::statistics::Data;
use statrs::statistics::{Distribution, Max, Min, OrderStatistics};

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
    /// Originator flow features.
    pub orig: FlowFeatures,
    /// Responder flow features.
    pub resp: FlowFeatures,
}

impl ConnFeatures {
    // pub fn features(&self, n_pkts: Option<usize>) -> Vec<f64> {
    //     let mut orig_features = self.orig.get_features(n_pkts);
    //     let mut resp_features = self.resp.get_features(n_pkts);
    //     orig_features.append(&mut resp_features);
    //     orig_features
    // }
}

impl Serialize for ConnFeatures {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ConnFeatures", 3)?;
        state.serialize_field("sni", &self.sni)?;
        state.serialize_field("orig", &self.orig)?;
        state.serialize_field("resp", &self.resp)?;
        state.end()
    }
}

impl fmt::Display for ConnFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}> {}<",
            self.sni, self.orig.byte_cnt, self.resp.byte_cnt
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
            orig: self.ctos.clone(),
            resp: self.stoc.clone(),
        };
        subscription.invoke(conn);
    }
}

/// A uni-directional flow.
#[derive(Debug, Clone, Serialize)]
pub struct FlowFeatures {
    pub start_tsc: u32,
    pub packet_cnt: u32,
    pub byte_cnt: u32,
    pub delta_ns: Vec<u32>,
    pub pkt_data: HashMap<&'static str, Vec<u32>>,
}

impl FlowFeatures {
    fn new() -> Self {
        FlowFeatures {
            start_tsc: unsafe { rte_rdtsc() } as u32,
            packet_cnt: 0,
            byte_cnt: 0,
            delta_ns: vec![],
            pkt_data: hashmap!{},
        }
    }


    #[inline]
    fn insert_segment(&mut self, segment: L4Pdu) {
        let mbuf = segment.mbuf_ref();
        if let Ok(eth) = mbuf.parse_to::<Ethernet>() {
            let curr_tsc = unsafe { rte_rdtsc() } as u32;
            let delta_ns =
                ((curr_tsc.saturating_sub(self.start_tsc)) as f64 / *TSC_HZ * 1e9) as u32;
            self.delta_ns.push(delta_ns);
            if let Ok(ipv4) = eth.parse_to::<Ipv4>() {
                self.packet_cnt += 1;
                self.byte_cnt += ipv4.total_length() as u32;
                self.pkt_data
                    .get_mut("ip_ihl")
                    .unwrap()
                    .push(ipv4.ihl().into());
                self.pkt_data
                    .get_mut("ip_dscp")
                    .unwrap()
                    .push(ipv4.dscp().into());
                self.pkt_data
                    .get_mut("ip_ecn")
                    .unwrap()
                    .push(ipv4.ecn().into());
                self.pkt_data
                    .get_mut("ip_total_length")
                    .unwrap()
                    .push(ipv4.total_length().into());
                self.pkt_data
                    .get_mut("ip_id")
                    .unwrap()
                    .push(ipv4.identification().into());
                self.pkt_data
                    .get_mut("ip_flags_rf")
                    .unwrap()
                    .push(ipv4.rf().into());
                self.pkt_data
                    .get_mut("ip_flags_df")
                    .unwrap()
                    .push(ipv4.df().into());
                self.pkt_data
                    .get_mut("ip_flags_mf")
                    .unwrap()
                    .push(ipv4.mf().into());
                self.pkt_data
                    .get_mut("ip_fragment_offset")
                    .unwrap()
                    .push(ipv4.fragment_offset().into());
                self.pkt_data
                    .get_mut("ip_ttl")
                    .unwrap()
                    .push(ipv4.time_to_live().into());
                self.pkt_data
                    .get_mut("ip_protocol")
                    .unwrap()
                    .push(ipv4.protocol().into());
                self.pkt_data
                    .get_mut("ip_header_checksum")
                    .unwrap()
                    .push(ipv4.header_checksum().into());
                if let Ok(tcp) = ipv4.parse_to::<Tcp>() {
                    self.pkt_data
                        .get_mut("tcp_src_port")
                        .unwrap()
                        .push(tcp.src_port().into());
                    self.pkt_data
                        .get_mut("tcp_dst_port")
                        .unwrap()
                        .push(tcp.dst_port().into());
                    self.pkt_data
                        .get_mut("tcp_seq_num")
                        .unwrap()
                        .push(tcp.seq_no().into());
                    self.pkt_data
                        .get_mut("tcp_ack_num")
                        .unwrap()
                        .push(tcp.ack_no().into());
                    self.pkt_data
                        .get_mut("tcp_data_offset")
                        .unwrap()
                        .push(tcp.data_offset().into());
                    self.pkt_data
                        .get_mut("tcp_reserved")
                        .unwrap()
                        .push(tcp.reserved().into());
                    self.pkt_data
                        .get_mut("tcp_flags_cwr")
                        .unwrap()
                        .push(tcp.cwr().into());
                    self.pkt_data
                        .get_mut("tcp_flags_ece")
                        .unwrap()
                        .push(tcp.ece().into());
                    self.pkt_data
                        .get_mut("tcp_flags_urg")
                        .unwrap()
                        .push(tcp.urg().into());
                    self.pkt_data
                        .get_mut("tcp_flags_ack")
                        .unwrap()
                        .push(tcp.ack().into());
                    self.pkt_data
                        .get_mut("tcp_flags_psh")
                        .unwrap()
                        .push(tcp.psh().into());
                    self.pkt_data
                        .get_mut("tcp_flags_rst")
                        .unwrap()
                        .push(tcp.rst().into());
                    self.pkt_data
                        .get_mut("tcp_flags_syn")
                        .unwrap()
                        .push(tcp.syn().into());
                    self.pkt_data
                        .get_mut("tcp_flags_fin")
                        .unwrap()
                        .push(tcp.fin().into());
                    self.pkt_data
                        .get_mut("tcp_window_size")
                        .unwrap()
                        .push(tcp.window().into());
                    self.pkt_data
                        .get_mut("tcp_checksum")
                        .unwrap()
                        .push(tcp.checksum().into());
                    self.pkt_data
                        .get_mut("tcp_urgent_ptr")
                        .unwrap()
                        .push(tcp.urgent_pointer().into());
                }
            }
        }
    }
}