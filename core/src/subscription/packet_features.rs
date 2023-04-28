//! Packet features.
//!
//! This is a connection-level subscription that provides raw features for
//! individual packets in each connection
//!
//!
//! ## Example
//! Logs TLS packet features to a file:
//! ```
//! #[filter("tls")]
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

/// A packet features record.
#[derive(Debug)]
pub struct PacketFeatures {
    /// Server name (for TLS connections)
    pub sni: String,
    /// Features,
    pub packets: Vec<PacketFeature>,
}

impl PacketFeatures {}

impl Serialize for PacketFeatures {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PacketFeatures", 2)?;
        state.serialize_field("sni", &self.sni)?;
        state.serialize_field("fts", &self.packets)?;
        state.end()
    }
}

impl fmt::Display for PacketFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} packets",
            self.sni, self.packets.len(),
        )?;
        Ok(())
    }
}

impl Subscribable for PacketFeatures {
    type Tracked = TrackedPacketFeatures;

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

/// Tracks a connection's packet features throughout its lifetime.
///
/// ## Note
/// Internal connection state is an associated type of a `pub` trait, and therefore must also be
/// public. Documentation is hidden by default to avoid confusing users.
#[doc(hidden)]
pub struct TrackedPacketFeatures {
    start_tsc: u64,
    sni: String,
    packets: Vec<PacketFeature>,
}

impl TrackedPacketFeatures {
    #[inline]
    fn update(&mut self, segment: L4Pdu) {
        if let Ok(packet) = PacketFeature::from(segment, self.start_tsc) {
            self.packets.push(packet);
        }
    }

}

impl Trackable for TrackedPacketFeatures {
    type Subscribed = PacketFeatures;

    fn new(_five_tuple: FiveTuple) -> Self {
        TrackedPacketFeatures {
            start_tsc: unsafe { rte_rdtsc() },
            sni: String::new(),
            packets: vec![],
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
        let conn = PacketFeatures {
            sni: self.sni.clone(),
            packets: self.packets.clone(),
        };
        subscription.invoke(conn);
    }

    fn early_terminate(&self) -> bool {
        self.packets.len() >= 8
    }
}


/// Subset of packet features
#[derive(Debug, Clone, Serialize)]
pub struct PacketFeature {
    /// direction `True` for up, `False` for down
    pub dir: bool,
    /// time offset from start of connection in ns
    pub delta_ns: u32,
    /// IP packet length
    pub pktsize: u32,
    /// TCP window size
    pub winsize: u32,
}

impl PacketFeature {
    fn from(segment: L4Pdu, start_tsc: u64) -> Result<Self> {
        let curr_tsc = unsafe { rte_rdtsc() };
        let delta_ns = ((curr_tsc.saturating_sub(start_tsc)) as f64 / *TSC_HZ * 1e9) as u32;
        let mbuf: &Mbuf = segment.mbuf_ref();
        let eth = mbuf.parse_to::<Ethernet>()?;
        
        let ipv4 = eth.parse_to::<Ipv4>()?;

        let tcp = ipv4.parse_to::<Tcp>()?; 
        let packet = PacketFeature {
            dir: segment.dir,
            delta_ns,
            pktsize: ipv4.total_length() as u32,
            winsize: tcp.window() as u32,
        };
        Ok(packet)
    }
}
