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

use crate::conntrack::conn::tcp_conn::reassembly::wrapping_lt;
use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::FilterResult;
use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::ethernet::Ethernet;
use crate::protocols::packet::ipv4::Ipv4;
use crate::protocols::packet::tcp::{Tcp, ACK, FIN, RST, SYN};
use crate::protocols::packet::Packet;
use crate::protocols::stream::{ConnParser, Session};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};

use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// A connection features record.
///
/// This subscribable type returns general information regarding TCP and UDP connections but does
/// does not track payload data. If applicable, Retina internally manages stream reassembly. All
/// connections are interpreted using flow semantics.
#[derive(Debug)]
pub struct ConnectionFeatures {
    /// Originator flow features.
    pub orig: FlowFeatures,
    /// Responder flow features.
    pub resp: FlowFeatures,
}

impl ConnectionFeatures {}

impl Serialize for ConnectionFeatures {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ConnectionFeatures", 2)?;
        state.serialize_field("orig", &self.orig)?;
        state.serialize_field("resp", &self.resp)?;
        state.end()
    }
}

// impl fmt::Display for ConnectionFeatures {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "{}: {}", self.five_tuple, self.history())?;
//         Ok(())
//     }
// }

impl Subscribable for ConnectionFeatures {
    type Tracked = TrackedConnectionFeatures;

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
pub struct TrackedConnectionFeatures {
    ctos: FlowFeatures,
    stoc: FlowFeatures,
}

impl TrackedConnectionFeatures {
    #[inline]
    fn update(&mut self, segment: L4Pdu) {
        if segment.dir {
            self.ctos.insert_segment(segment);
        } else {
            self.stoc.insert_segment(segment);
        }
    }
}

impl Trackable for TrackedConnectionFeatures {
    type Subscribed = ConnectionFeatures;

    fn new(five_tuple: FiveTuple) -> Self {
        TrackedConnectionFeatures {
            ctos: FlowFeatures::new(),
            stoc: FlowFeatures::new(),
        }
    }

    fn pre_match(&mut self, pdu: L4Pdu, _session_id: Option<usize>) {
        self.update(pdu);
    }

    fn on_match(&mut self, _session: Session, _subscription: &Subscription<Self::Subscribed>) {
        // do nothing, should stay tracked
    }

    fn post_match(&mut self, pdu: L4Pdu, _subscription: &Subscription<Self::Subscribed>) {
        self.update(pdu)
    }

    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>) {
        let conn = ConnectionFeatures {
            orig: self.ctos.clone(),
            resp: self.stoc.clone(),
        };
        subscription.invoke(conn);
    }
}

/// A uni-directional flow.
#[derive(Debug, Clone, Serialize)]
pub struct FlowFeatures {
    pub ip_dscp: Vec<u8>,
    pub ip_ecn: Vec<u8>,
    pub ip_id: Vec<u16>,
    pub ip_df: Vec<bool>,
    pub ip_mf: Vec<bool>,
    pub ip_fragment_offset: Vec<bool>,
    pub ip_ttl: Vec<u8>,
    pub nb_pkts: u64,
}

impl FlowFeatures {
    fn new() -> Self {
        FlowFeatures {
            ip_dscp: vec![],
            ip_ecn: vec![],
            ip_id: vec![],
            ip_df: vec![],
            ip_mf: vec![],
            ip_fragment_offset: vec![],
            ip_ttl: vec![],
            nb_pkts: 0,
        }
    }

    #[inline]
    fn insert_segment(&mut self, segment: L4Pdu) {
        let mbuf = segment.mbuf_ref();
        if let Ok(eth) = mbuf.parse_to::<Ethernet>() {
            if let Ok(ipv4) = eth.parse_to::<Ipv4>() {
                if let Ok(tcp) = ipv4.parse_to::<Tcp>() {
                    self.ip_dscp.push(ipv4.dscp());
                    self.ip_ecn.push(ipv4.ecn());
                    self.ip_id.push(ipv4.identification());
                    self.ip_df
                        .push((ipv4.flags_to_fragment_offset() >> 14) & 0b1 == 0b1);
                }
            }
        }
        self.nb_pkts += 1;
    }
}
