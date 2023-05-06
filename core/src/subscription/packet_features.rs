//! Packet features.
//!
//! This is a connection-level subscription that provides raw features for
//! individual packets in each connection
//!
//!
//! ## Example
//! Logs TLS packet features to a file:
//! ```
//! #[filter("ipv4 and tcp")]
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
use crate::protocols::packet::Packet;
use crate::protocols::stream::{ConnParser, Session};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};

use std::fmt;

use anyhow::Result;
use chrono::Utc;
use serde::ser::{SerializeSeq, Serializer};
use serde::Serialize;

use lazy_static::lazy_static;

lazy_static! {
    static ref TSC_HZ: f64 = unsafe { rte_get_tsc_hz() as f64 };
}

/// A packet features record.
#[derive(Debug, Serialize)]
pub struct PacketFeatures {
    /// 5-tuple
    pub five_tuple: FiveTuple,
    /// Starting UNIX timestamp
    pub ts: i64,
    /// Features
    pub packets: Vec<PacketFeature>,
}

impl PacketFeatures {}

// impl Serialize for PacketFeatures {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let mut state = serializer.serialize_struct("PacketFeatures", 3)?;
//         state.serialize_field("sni", &self.sni)?;
//         state.serialize_field("fts", &self.packets)?;
//         state.end()
//     }
// }

impl fmt::Display for PacketFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: ts: {}, {} packets",
            self.five_tuple,
            self.ts,
            self.packets.len(),
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
    five_tuple: FiveTuple,
    ts: i64,
    start_tsc: u64,
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

    fn new(five_tuple: FiveTuple) -> Self {
        TrackedPacketFeatures {
            five_tuple,
            ts: Utc::now().timestamp(),
            start_tsc: unsafe { rte_rdtsc() },
            packets: vec![],
        }
    }

    fn pre_match(&mut self, pdu: L4Pdu, _session_id: Option<usize>) {
        self.update(pdu);
    }

    fn on_match(&mut self, _session: Session, _subscription: &Subscription<Self::Subscribed>) {
        // do nothing, stay tracked
    }

    fn post_match(&mut self, pdu: L4Pdu, _subscription: &Subscription<Self::Subscribed>) {
        self.update(pdu)
    }

    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>) {
        let conn = PacketFeatures {
            five_tuple: self.five_tuple,
            ts: self.ts,
            packets: self.packets.clone(),
        };
        subscription.invoke(conn);
    }

    fn early_terminate(&self) -> bool {
        // self.packets.len() >= 2048
        false
    }
}

/// Subset of packet features
#[derive(Debug, Clone)]
pub struct PacketFeature {
    /// direction 1 for client->server, 0 for server->client
    pub dir: u32,
    /// time offset from start of connection in ns
    pub offset: u32,
    /// size of IP packet (IPv4 total length)
    pub sz: u32,
}

impl Serialize for PacketFeature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut arr = serializer.serialize_seq(Some(33))?;
        arr.serialize_element(&self.dir)?;
        arr.serialize_element(&self.offset)?;
        arr.serialize_element(&self.sz)?;
        arr.end()
    }
}

impl PacketFeature {
    fn from(segment: L4Pdu, start_tsc: u64) -> Result<Self> {
        let curr_tsc = unsafe { rte_rdtsc() };
        let delta_ns = ((curr_tsc.saturating_sub(start_tsc)) as f64 / *TSC_HZ * 1e9) as u32;
        let mbuf: &Mbuf = segment.mbuf_ref();
        let eth = mbuf.parse_to::<Ethernet>()?;
        let ipv4 = eth.parse_to::<Ipv4>()?;
        let packet = PacketFeature {
            dir: segment.dir.into(),
            offset: delta_ns,
            sz: ipv4.total_length().into(),
        };
        Ok(packet)
    }
}
