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

use std::fmt;

use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;

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
pub struct ConnectionFeatures {
    /// Server name (for TLS connections)
    pub sni: String,
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
        let mut state = serializer.serialize_struct("ConnectionFeatures", 3)?;
        state.serialize_field("sni", &self.sni)?;
        state.serialize_field("orig", &self.orig)?;
        state.serialize_field("resp", &self.resp)?;
        state.end()
    }
}

impl fmt::Display for ConnectionFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}> {}<",
            self.sni, self.orig.byte_cnt, self.resp.byte_cnt
        )?;
        Ok(())
    }
}

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
    sni: String,
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

    fn new(_five_tuple: FiveTuple) -> Self {
        TrackedConnectionFeatures {
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
        let conn = ConnectionFeatures {
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
    pub start_tsc: u64,
    pub packet_cnt: u64,
    pub byte_cnt: u64,
    pub delta_ns: Vec<u64>,
    pub ip_ihl: Vec<u8>,
    pub ip_dscp: Vec<u8>,
    pub ip_ecn: Vec<u8>,
    pub ip_total_length: Vec<u16>,
    pub ip_id: Vec<u16>,
    pub ip_flags_rf: Vec<bool>,
    pub ip_flags_df: Vec<bool>,
    pub ip_flags_mf: Vec<bool>,
    pub ip_fragment_offset: Vec<u16>,
    pub ip_ttl: Vec<u8>,
    pub ip_protocol: Vec<u8>,
    pub ip_header_checksum: Vec<u16>,
    pub tcp_src_port: Vec<u16>,
    pub tcp_dst_port: Vec<u16>,
    pub tcp_seq_num: Vec<u32>,
    pub tcp_ack_num: Vec<u32>,
    pub tcp_data_offset: Vec<u8>,
    pub tcp_reserved: Vec<u8>,
    pub tcp_flags_cwr: Vec<bool>,
    pub tcp_flags_ece: Vec<bool>,
    pub tcp_flags_urg: Vec<bool>,
    pub tcp_flags_ack: Vec<bool>,
    pub tcp_flags_psh: Vec<bool>,
    pub tcp_flags_rst: Vec<bool>,
    pub tcp_flags_syn: Vec<bool>,
    pub tcp_flags_fin: Vec<bool>,
    pub tcp_window_size: Vec<u16>,
    pub tcp_checksum: Vec<u16>,
    pub tcp_urgent_ptr: Vec<u16>,
}

impl FlowFeatures {
    fn new() -> Self {
        FlowFeatures {
            start_tsc: unsafe { rte_rdtsc() },
            packet_cnt: 0,
            byte_cnt: 0,
            delta_ns: vec![],
            ip_ihl: vec![],
            ip_dscp: vec![],
            ip_ecn: vec![],
            ip_total_length: vec![],
            ip_id: vec![],
            ip_flags_rf: vec![],
            ip_flags_df: vec![],
            ip_flags_mf: vec![],
            ip_fragment_offset: vec![],
            ip_ttl: vec![],
            ip_protocol: vec![],
            ip_header_checksum: vec![],
            tcp_src_port: vec![],
            tcp_dst_port: vec![],
            tcp_seq_num: vec![],
            tcp_ack_num: vec![],
            tcp_data_offset: vec![],
            tcp_reserved: vec![],
            tcp_flags_cwr: vec![],
            tcp_flags_ece: vec![],
            tcp_flags_urg: vec![],
            tcp_flags_ack: vec![],
            tcp_flags_psh: vec![],
            tcp_flags_rst: vec![],
            tcp_flags_syn: vec![],
            tcp_flags_fin: vec![],
            tcp_window_size: vec![],
            tcp_checksum: vec![],
            tcp_urgent_ptr: vec![],
        }
    }

    #[inline]
    fn insert_segment(&mut self, segment: L4Pdu) {
        let mbuf = segment.mbuf_ref();
        if let Ok(eth) = mbuf.parse_to::<Ethernet>() {
            let curr_tsc = unsafe { rte_rdtsc() };
            self.delta_ns
                .push(((curr_tsc - self.start_tsc) as f64 / *TSC_HZ * 1e9) as u64);
            if let Ok(ipv4) = eth.parse_to::<Ipv4>() {
                self.packet_cnt += 1;
                self.byte_cnt += ipv4.total_length() as u64;

                self.ip_ihl.push(ipv4.ihl());
                self.ip_dscp.push(ipv4.dscp());
                self.ip_ecn.push(ipv4.ecn());
                self.ip_total_length.push(ipv4.total_length());
                self.ip_id.push(ipv4.identification());
                self.ip_flags_rf.push(ipv4.rf());
                self.ip_flags_df.push(ipv4.df());
                self.ip_flags_mf.push(ipv4.mf());
                self.ip_fragment_offset.push(ipv4.fragment_offset());
                self.ip_ttl.push(ipv4.time_to_live());
                self.ip_protocol.push(ipv4.protocol());
                self.ip_header_checksum.push(ipv4.header_checksum());
                if let Ok(tcp) = ipv4.parse_to::<Tcp>() {
                    self.tcp_src_port.push(tcp.src_port());
                    self.tcp_dst_port.push(tcp.dst_port());
                    self.tcp_seq_num.push(tcp.seq_no());
                    self.tcp_ack_num.push(tcp.ack_no());
                    self.tcp_data_offset.push(tcp.data_offset());
                    self.tcp_reserved.push(tcp.reserved());
                    self.tcp_flags_cwr.push(tcp.cwr());
                    self.tcp_flags_ece.push(tcp.ece());
                    self.tcp_flags_urg.push(tcp.urg());
                    self.tcp_flags_ack.push(tcp.ack());
                    self.tcp_flags_psh.push(tcp.psh());
                    self.tcp_flags_rst.push(tcp.rst());
                    self.tcp_flags_syn.push(tcp.syn());
                    self.tcp_flags_fin.push(tcp.fin());
                    self.tcp_window_size.push(tcp.window());
                    self.tcp_checksum.push(tcp.checksum());
                    self.tcp_urgent_ptr.push(tcp.urgent_pointer());
                }
            }
        }
    }
}
