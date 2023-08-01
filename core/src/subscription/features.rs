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
use crate::protocols::stream::{ConnParser, Session, SessionData};
use crate::subscription::*;

use std::fmt;

use anyhow::Result;
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;

use lazy_static::lazy_static;

lazy_static! {
    static ref TSC_GHZ: f64 = unsafe { rte_get_tsc_hz() } as f64 / 1e9;
}

/// A features record.
#[cfg(any(feature = "timing", feature = "collect"))]
#[derive(Debug, Serialize)]
pub struct Features {
    #[cfg(feature = "dur")]
    dur: f64,
    #[cfg(feature = "proto")]
    proto: f64,
    #[cfg(feature = "s_port")]
    s_port: f64,
    #[cfg(feature = "d_port")]
    d_port: f64,

    #[cfg(feature = "s_load")]
    s_load: f64,
    #[cfg(feature = "d_load")]
    d_load: f64,
    #[cfg(feature = "s_pkt_cnt")]
    s_pkt_cnt: f64,
    #[cfg(feature = "d_pkt_cnt")]
    d_pkt_cnt: f64,

    #[cfg(feature = "cwr_cnt")]
    cwr_cnt: f64,
    #[cfg(feature = "ece_cnt")]
    ece_cnt: f64,
    #[cfg(feature = "urg_cnt")]
    urg_cnt: f64,
    #[cfg(feature = "ack_cnt")]
    ack_cnt: f64,
    #[cfg(feature = "psh_cnt")]
    psh_cnt: f64,
    #[cfg(feature = "rst_cnt")]
    rst_cnt: f64,
    #[cfg(feature = "syn_cnt")]
    syn_cnt: f64,
    #[cfg(feature = "fin_cnt")]
    fin_cnt: f64,

    #[cfg(feature = "tcp_rtt")]
    tcp_rtt: f64,
    #[cfg(feature = "syn_ack")]
    syn_ack: f64,
    #[cfg(feature = "ack_dat")]
    ack_dat: f64,

    #[cfg(feature = "s_bytes_sum")]
    s_bytes_sum: f64,
    #[cfg(feature = "d_bytes_sum")]
    d_bytes_sum: f64,
    #[cfg(feature = "s_bytes_mean")]
    s_bytes_mean: f64,
    #[cfg(feature = "d_bytes_mean")]
    d_bytes_mean: f64,
    #[cfg(feature = "s_bytes_min")]
    s_bytes_min: f64,
    #[cfg(feature = "d_bytes_min")]
    d_bytes_min: f64,
    #[cfg(feature = "s_bytes_max")]
    s_bytes_max: f64,
    #[cfg(feature = "d_bytes_max")]
    d_bytes_max: f64,
    #[cfg(feature = "s_bytes_med")]
    s_bytes_med: f64,
    #[cfg(feature = "d_bytes_med")]
    d_bytes_med: f64,
    #[cfg(feature = "s_bytes_std")]
    s_bytes_std: f64,
    #[cfg(feature = "d_bytes_std")]
    d_bytes_std: f64,

    #[cfg(feature = "s_iat_sum")]
    s_iat_sum: f64,
    #[cfg(feature = "d_iat_sum")]
    d_iat_sum: f64,
    #[cfg(feature = "s_iat_mean")]
    s_iat_mean: f64,
    #[cfg(feature = "d_iat_mean")]
    d_iat_mean: f64,
    #[cfg(feature = "s_iat_min")]
    s_iat_min: f64,
    #[cfg(feature = "d_iat_min")]
    d_iat_min: f64,
    #[cfg(feature = "s_iat_max")]
    s_iat_max: f64,
    #[cfg(feature = "d_iat_max")]
    d_iat_max: f64,
    #[cfg(feature = "s_iat_med")]
    s_iat_med: f64,
    #[cfg(feature = "d_iat_med")]
    d_iat_med: f64,
    #[cfg(feature = "s_iat_std")]
    s_iat_std: f64,
    #[cfg(feature = "d_iat_std")]
    d_iat_std: f64,

    #[cfg(feature = "s_winsize_sum")]
    s_winsize_sum: f64,
    #[cfg(feature = "d_winsize_sum")]
    d_winsize_sum: f64,
    #[cfg(feature = "s_winsize_mean")]
    s_winsize_mean: f64,
    #[cfg(feature = "d_winsize_mean")]
    d_winsize_mean: f64,
    #[cfg(feature = "s_winsize_min")]
    s_winsize_min: f64,
    #[cfg(feature = "d_winsize_min")]
    d_winsize_min: f64,
    #[cfg(feature = "s_winsize_max")]
    s_winsize_max: f64,
    #[cfg(feature = "d_winsize_max")]
    d_winsize_max: f64,
    #[cfg(feature = "s_winsize_med")]
    s_winsize_med: f64,
    #[cfg(feature = "d_winsize_med")]
    d_winsize_med: f64,
    #[cfg(feature = "s_winsize_std")]
    s_winsize_std: f64,
    #[cfg(feature = "d_winsize_std")]
    d_winsize_std: f64,

    #[cfg(feature = "s_ttl_sum")]
    s_ttl_sum: f64,
    #[cfg(feature = "d_ttl_sum")]
    d_ttl_sum: f64,
    #[cfg(feature = "s_ttl_mean")]
    s_ttl_mean: f64,
    #[cfg(feature = "d_ttl_mean")]
    d_ttl_mean: f64,
    #[cfg(feature = "s_ttl_min")]
    s_ttl_min: f64,
    #[cfg(feature = "d_ttl_min")]
    d_ttl_min: f64,
    #[cfg(feature = "s_ttl_max")]
    s_ttl_max: f64,
    #[cfg(feature = "d_ttl_max")]
    d_ttl_max: f64,
    #[cfg(feature = "s_ttl_med")]
    s_ttl_med: f64,
    #[cfg(feature = "d_ttl_med")]
    d_ttl_med: f64,
    #[cfg(feature = "s_ttl_std")]
    s_ttl_std: f64,
    #[cfg(feature = "d_ttl_std")]
    d_ttl_std: f64,

    #[cfg(feature = "label")]
    #[serde(serialize_with = "serialize_mac_addr")]
    s_mac: pnet::datalink::MacAddr,
    #[cfg(feature = "label")]
    #[serde(serialize_with = "serialize_mac_addr")]
    d_mac: pnet::datalink::MacAddr,
    #[cfg(feature = "capture_start")]
    syn_ts: f64,
}

#[cfg(not(any(feature = "timing", feature = "collect")))]
#[derive(Debug, Serialize)]
pub struct Features {
    #[cfg(feature = "capture_start")]
    pub syn_ts: f64,
    #[cfg(feature = "label")]
    #[serde(serialize_with = "serialize_mac_addr")]
    pub s_mac: pnet::datalink::MacAddr,
    #[cfg(feature = "label")]
    #[serde(serialize_with = "serialize_mac_addr")]
    pub d_mac: pnet::datalink::MacAddr,
    pub feature_vec: Vec<f64>,
}

impl Features {}

fn serialize_mac_addr<S>(mac: &pnet::datalink::MacAddr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&mac.to_string())
}

impl Subscribable for Features {
    type Tracked = TrackedFeatures;

    fn level() -> Level {
        Level::Connection
    }

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
    compute_ns: u64,
    #[cfg(feature = "label")]
    s_mac: pnet::datalink::MacAddr,
    #[cfg(feature = "label")]
    d_mac: pnet::datalink::MacAddr,
    cnt: u64,
    #[cfg(any(
        feature = "capture_start",
        feature = "dur",
        feature = "s_load",
        feature = "d_load",
        feature = "s_iat_mean",
        feature = "tcp_rtt",
        feature = "syn_ack",
        feature = "s_iat_sum",
    ))]
    syn_ts: f64,
    #[cfg(any(
        feature = "d_iat_mean",
        feature = "tcp_rtt",
        feature = "syn_ack",
        feature = "ack_dat",
        feature = "d_iat_sum",
    ))]
    syn_ack_ts: f64,
    #[cfg(any(feature = "tcp_rtt", feature = "ack_dat",))]
    ack_ts: f64,

    #[cfg(any(
        feature = "dur",
        feature = "s_load",
        feature = "d_load",
        feature = "s_iat_mean",
        feature = "s_iat_sum",
        feature = "s_iat_min",
        feature = "s_iat_max",
        feature = "s_iat_med",
        feature = "s_iat_std",
    ))]
    s_last_ts: f64,
    #[cfg(any(
        feature = "dur",
        feature = "s_load",
        feature = "d_load",
        feature = "d_iat_mean",
        feature = "d_iat_sum",
        feature = "d_iat_min",
        feature = "d_iat_max",
        feature = "d_iat_med",
        feature = "d_iat_std",
    ))]
    d_last_ts: f64,

    #[cfg(any(
        feature = "s_pkt_cnt",
        feature = "s_bytes_mean",
        feature = "s_iat_mean",
        feature = "s_winsize_mean",
        feature = "s_ttl_mean",
    ))]
    s_pkt_cnt: f64,
    #[cfg(any(
        feature = "d_pkt_cnt",
        feature = "d_bytes_mean",
        feature = "d_iat_mean",
        feature = "d_winsize_mean",
        feature = "d_ttl_mean",
    ))]
    d_pkt_cnt: f64,

    #[cfg(feature = "cwr_cnt")]
    cwr_cnt: f64,
    #[cfg(feature = "ece_cnt")]
    ece_cnt: f64,
    #[cfg(feature = "urg_cnt")]
    urg_cnt: f64,
    #[cfg(feature = "ack_cnt")]
    ack_cnt: f64,
    #[cfg(feature = "psh_cnt")]
    psh_cnt: f64,
    #[cfg(feature = "rst_cnt")]
    rst_cnt: f64,
    #[cfg(feature = "syn_cnt")]
    syn_cnt: f64,
    #[cfg(feature = "fin_cnt")]
    fin_cnt: f64,

    #[cfg(feature = "proto")]
    proto: f64,
    #[cfg(feature = "s_port")]
    s_port: f64,
    #[cfg(feature = "d_port")]
    d_port: f64,

    #[cfg(any(feature = "s_bytes_sum", feature = "s_bytes_mean", feature = "s_load"))]
    s_bytes_sum: f64,
    #[cfg(any(feature = "d_bytes_sum", feature = "d_bytes_mean", feature = "d_load"))]
    d_bytes_sum: f64,
    #[cfg(feature = "s_bytes_min")]
    s_bytes_min: f64,
    #[cfg(feature = "d_bytes_min")]
    d_bytes_min: f64,
    #[cfg(feature = "s_bytes_max")]
    s_bytes_max: f64,
    #[cfg(feature = "d_bytes_max")]
    d_bytes_max: f64,
    #[cfg(any(feature = "s_bytes_med", feature = "s_bytes_std"))]
    s_bytes_hist: Vec<f64>,
    #[cfg(any(feature = "d_bytes_med", feature = "d_bytes_std"))]
    d_bytes_hist: Vec<f64>,

    #[cfg(feature = "s_iat_min")]
    s_iat_min: f64,
    #[cfg(feature = "d_iat_min")]
    d_iat_min: f64,
    #[cfg(feature = "s_iat_max")]
    s_iat_max: f64,
    #[cfg(feature = "d_iat_max")]
    d_iat_max: f64,
    #[cfg(any(feature = "s_iat_med", feature = "s_iat_std"))]
    s_iat_hist: Vec<f64>,
    #[cfg(any(feature = "d_iat_med", feature = "d_iat_std"))]
    d_iat_hist: Vec<f64>,

    #[cfg(any(feature = "s_winsize_sum", feature = "s_winsize_mean"))]
    s_winsize_sum: f64,
    #[cfg(any(feature = "d_winsize_sum", feature = "d_winsize_mean"))]
    d_winsize_sum: f64,
    #[cfg(feature = "s_winsize_min")]
    s_winsize_min: f64,
    #[cfg(feature = "d_winsize_min")]
    d_winsize_min: f64,
    #[cfg(feature = "s_winsize_max")]
    s_winsize_max: f64,
    #[cfg(feature = "d_winsize_max")]
    d_winsize_max: f64,
    #[cfg(any(feature = "s_winsize_med", feature = "s_winsize_std"))]
    s_winsize_hist: Vec<f64>,
    #[cfg(any(feature = "d_winsize_med", feature = "d_winsize_std"))]
    d_winsize_hist: Vec<f64>,

    #[cfg(any(feature = "s_ttl_sum", feature = "s_ttl_mean"))]
    s_ttl_sum: f64,
    #[cfg(any(feature = "d_ttl_sum", feature = "d_ttl_mean"))]
    d_ttl_sum: f64,
    #[cfg(feature = "s_ttl_min")]
    s_ttl_min: f64,
    #[cfg(feature = "d_ttl_min")]
    d_ttl_min: f64,
    #[cfg(feature = "s_ttl_max")]
    s_ttl_max: f64,
    #[cfg(feature = "d_ttl_max")]
    d_ttl_max: f64,
    #[cfg(any(feature = "s_ttl_med", feature = "s_ttl_std"))]
    s_ttl_hist: Vec<f64>,
    #[cfg(any(feature = "d_ttl_med", feature = "d_ttl_std"))]
    d_ttl_hist: Vec<f64>,

}

impl TrackedFeatures {
    #[inline]
    fn update(&mut self, segment: L4Pdu) -> Result<()> {
        self.cnt += 1;
        #[cfg(feature = "timing")]
        let start_ts = (unsafe { rte_rdtsc() } as f64 / *TSC_GHZ) as u64;

        #[cfg(any(
            feature = "capture_start",
            feature = "dur",
            feature = "s_load",
            feature = "d_load",
            feature = "tcp_rtt",
            feature = "syn_ack",
            feature = "ack_dat",
            feature = "s_iat_sum",
            feature = "d_iat_sum",
            feature = "s_iat_mean",
            feature = "d_iat_mean",
            feature = "s_iat_min",
            feature = "d_iat_min",
            feature = "s_iat_max",
            feature = "d_iat_max",
            feature = "s_iat_med",
            feature = "d_iat_med",
            feature = "s_iat_std",
            feature = "d_iat_std",
        ))]
        let curr_ts = unsafe { rte_rdtsc() } as f64 / *TSC_GHZ;
        // #[cfg(not(feature = "timing"))]
        // let curr_ts = segment.mbuf_ref().timestamp() as f64 * 1e3;

        #[cfg(any(
            feature = "proto",
            feature = "s_port",
            feature = "d_port",
            feature = "cwr_cnt",
            feature = "ece_cnt",
            feature = "urg_cnt",
            feature = "ack_cnt",
            feature = "psh_cnt",
            feature = "rst_cnt",
            feature = "syn_cnt",
            feature = "fin_cnt",
            feature = "s_load",
            feature = "d_load",
            feature = "d_iat_mean",
            feature = "tcp_rtt",
            feature = "syn_ack",
            feature = "ack_dat",
            feature = "s_bytes_sum",
            feature = "d_bytes_sum",
            feature = "s_bytes_mean",
            feature = "d_bytes_mean",
            feature = "s_bytes_min",
            feature = "d_bytes_min",
            feature = "s_bytes_max",
            feature = "d_bytes_max",
            feature = "s_bytes_med",
            feature = "d_bytes_med",
            feature = "s_bytes_std",
            feature = "d_bytes_std",
            feature = "s_winsize_sum",
            feature = "d_winsize_sum",
            feature = "s_winsize_mean",
            feature = "d_winsize_mean",
            feature = "s_winsize_min",
            feature = "d_winsize_min",
            feature = "s_winsize_max",
            feature = "d_winsize_max",
            feature = "s_winsize_med",
            feature = "d_winsize_med",
            feature = "s_winsize_std",
            feature = "d_winsize_std",
            feature = "s_ttl_sum",
            feature = "d_ttl_sum",
            feature = "s_ttl_mean",
            feature = "d_ttl_mean",
            feature = "s_ttl_min",
            feature = "d_ttl_min",
            feature = "s_ttl_max",
            feature = "d_ttl_max",
            feature = "s_ttl_med",
            feature = "d_ttl_med",
            feature = "s_ttl_std",
            feature = "d_ttl_std",
        ))]
        let mbuf = segment.mbuf_ref();
        #[cfg(any(
            feature = "proto",
            feature = "s_port",
            feature = "d_port",
            feature = "cwr_cnt",
            feature = "ece_cnt",
            feature = "urg_cnt",
            feature = "ack_cnt",
            feature = "psh_cnt",
            feature = "rst_cnt",
            feature = "syn_cnt",
            feature = "fin_cnt",
            feature = "s_load",
            feature = "d_load",
            feature = "d_iat_mean",
            feature = "tcp_rtt",
            feature = "syn_ack",
            feature = "ack_dat",
            feature = "s_bytes_sum",
            feature = "d_bytes_sum",
            feature = "s_bytes_mean",
            feature = "d_bytes_mean",
            feature = "s_bytes_min",
            feature = "d_bytes_min",
            feature = "s_bytes_max",
            feature = "d_bytes_max",
            feature = "s_bytes_med",
            feature = "d_bytes_med",
            feature = "s_bytes_std",
            feature = "d_bytes_std",
            feature = "s_winsize_sum",
            feature = "d_winsize_sum",
            feature = "s_winsize_mean",
            feature = "d_winsize_mean",
            feature = "s_winsize_min",
            feature = "d_winsize_min",
            feature = "s_winsize_max",
            feature = "d_winsize_max",
            feature = "s_winsize_med",
            feature = "d_winsize_med",
            feature = "s_winsize_std",
            feature = "d_winsize_std",
            feature = "s_ttl_sum",
            feature = "d_ttl_sum",
            feature = "s_ttl_mean",
            feature = "d_ttl_mean",
            feature = "s_ttl_min",
            feature = "d_ttl_min",
            feature = "s_ttl_max",
            feature = "d_ttl_max",
            feature = "s_ttl_med",
            feature = "d_ttl_med",
            feature = "s_ttl_std",
            feature = "d_ttl_std",
        ))]
        let eth = mbuf.parse_to::<Ethernet>()?;
        #[cfg(any(
            feature = "proto",
            feature = "s_port",
            feature = "d_port",
            feature = "cwr_cnt",
            feature = "ece_cnt",
            feature = "urg_cnt",
            feature = "ack_cnt",
            feature = "psh_cnt",
            feature = "rst_cnt",
            feature = "syn_cnt",
            feature = "fin_cnt",
            feature = "s_load",
            feature = "d_load",
            feature = "d_iat_mean",
            feature = "tcp_rtt",
            feature = "syn_ack",
            feature = "ack_dat",
            feature = "s_bytes_sum",
            feature = "d_bytes_sum",
            feature = "s_bytes_mean",
            feature = "d_bytes_mean",
            feature = "s_bytes_min",
            feature = "d_bytes_min",
            feature = "s_bytes_max",
            feature = "d_bytes_max",
            feature = "s_bytes_med",
            feature = "d_bytes_med",
            feature = "s_bytes_std",
            feature = "d_bytes_std",
            feature = "s_winsize_sum",
            feature = "d_winsize_sum",
            feature = "s_winsize_mean",
            feature = "d_winsize_mean",
            feature = "s_winsize_min",
            feature = "d_winsize_min",
            feature = "s_winsize_max",
            feature = "d_winsize_max",
            feature = "s_winsize_med",
            feature = "d_winsize_med",
            feature = "s_winsize_std",
            feature = "d_winsize_std",
            feature = "s_ttl_sum",
            feature = "d_ttl_sum",
            feature = "s_ttl_mean",
            feature = "d_ttl_mean",
            feature = "s_ttl_min",
            feature = "d_ttl_min",
            feature = "s_ttl_max",
            feature = "d_ttl_max",
            feature = "s_ttl_med",
            feature = "d_ttl_med",
            feature = "s_ttl_std",
            feature = "d_ttl_std",
        ))]
        let ipv4 = eth.parse_to::<Ipv4>()?;

        if segment.dir {
            #[cfg(feature = "label")]
            if self.cnt == 1 {
                let mbuf = segment.mbuf_ref();
                let eth = mbuf.parse_to::<Ethernet>()?;
                self.s_mac = eth.src();
                self.d_mac = eth.dst();
            }

            #[cfg(any(
                feature = "capture_start",
                feature = "dur",
                feature = "s_load",
                feature = "d_load",
                feature = "s_iat_mean",
                feature = "tcp_rtt",
                feature = "syn_ack",
                feature = "s_iat_sum",
            ))]
            if self.syn_ts.is_nan() {
                self.syn_ts = curr_ts;
            }

            #[cfg(feature = "s_iat_min")]
            {
                self.s_iat_min = self.s_iat_min.min(curr_ts - self.s_last_ts);
            }
            #[cfg(feature = "s_iat_max")]
            {
                self.s_iat_max = self.s_iat_max.max(curr_ts - self.s_last_ts);
            }
            #[cfg(any(feature = "s_iat_med", feature = "s_iat_std"))]
            {
                let s_iat = curr_ts - self.s_last_ts;
                if !s_iat.is_nan() {
                    self.s_iat_hist.push(curr_ts - self.s_last_ts);
                }
            }
            #[cfg(any(
                feature = "dur",
                feature = "s_load",
                feature = "d_load",
                feature = "s_iat_mean",
                feature = "s_iat_sum",
                feature = "s_iat_min",
                feature = "s_iat_max",
                feature = "s_iat_med",
                feature = "s_iat_std",
            ))]
            {
                self.s_last_ts = curr_ts;
            }
            #[cfg(any(
                feature = "s_pkt_cnt",
                feature = "s_bytes_mean",
                feature = "s_iat_mean",
                feature = "s_winsize_mean",
                feature = "s_ttl_mean",
            ))]
            {
                self.s_pkt_cnt += 1.0;
            }
            #[cfg(any(feature = "s_bytes_sum", feature = "s_bytes_mean", feature = "s_load"))]
            {
                self.s_bytes_sum += ipv4.total_length() as f64;
            }
            #[cfg(feature = "s_bytes_min")]
            {
                self.s_bytes_min = self.s_bytes_min.min(ipv4.total_length() as f64);
            }
            #[cfg(feature = "s_bytes_max")]
            {
                self.s_bytes_max = self.s_bytes_max.max(ipv4.total_length() as f64);
            }
            #[cfg(any(feature = "s_bytes_med", feature = "s_bytes_std"))]
            {
                self.s_bytes_hist.push(ipv4.total_length() as f64);
            }

            #[cfg(any(feature = "s_ttl_sum", feature = "s_ttl_mean"))]
            {
                self.s_ttl_sum += ipv4.time_to_live() as f64;
            }
            #[cfg(feature = "s_ttl_min")]
            {
                self.s_ttl_min = self.s_ttl_min.min(ipv4.time_to_live() as f64);
            }
            #[cfg(feature = "s_ttl_max")]
            {
                self.s_ttl_max = self.s_ttl_max.max(ipv4.time_to_live() as f64);
            }
            #[cfg(any(feature = "s_ttl_med", feature = "s_ttl_std"))]
            {
                self.s_ttl_hist.push(ipv4.time_to_live() as f64);
            }
            #[cfg(any(feature = "tcp_rtt", feature = "ack_dat",))]
            if !self.syn_ack_ts.is_nan() && self.ack_ts.is_nan() {
                let tcp = ipv4.parse_to::<Tcp>()?;
                if tcp.ack() {
                    self.ack_ts = curr_ts;
                }
            }
            #[cfg(any(
                feature = "s_winsize_sum",
                feature = "s_winsize_mean",
                feature = "s_winsize_min",
                feature = "s_winsize_max",
                feature = "s_winsize_med",
                feature = "s_winsize_std",
                feature = "cwr_cnt",
                feature = "ece_cnt",
                feature = "urg_cnt",
                feature = "ack_cnt",
                feature = "psh_cnt",
                feature = "rst_cnt",
                feature = "syn_cnt",
                feature = "fin_cnt",
                feature = "s_port",
                feature = "d_port",
            ))]
            {
                let tcp = ipv4.parse_to::<Tcp>()?;
                #[cfg(any(
                    feature = "s_winsize_sum",
                    feature = "s_winsize_mean",
                    feature = "s_winsize_min",
                    feature = "s_winsize_max",
                    feature = "s_winsize_med",
                    feature = "s_winsize_std",
                ))]
                {
                    let winsize = tcp.window() as f64;
                    #[cfg(any(feature = "s_winsize_sum", feature = "s_winsize_mean"))]
                    {
                        self.s_winsize_sum += winsize;
                    }
                    #[cfg(feature = "s_winsize_min")]
                    {
                        self.s_winsize_min = self.s_winsize_min.min(winsize);
                    }
                    #[cfg(feature = "s_winsize_max")]
                    {
                        self.s_winsize_max = self.s_winsize_max.max(winsize);
                    }
                    #[cfg(any(feature = "s_winsize_med", feature = "s_winsize_std"))]
                    {
                        self.s_winsize_hist.push(winsize);
                    }
                }

                #[cfg(feature = "cwr_cnt")]
                {
                    if tcp.cwr() {
                        self.cwr_cnt += 1.0;
                    }
                }
                #[cfg(feature = "ece_cnt")]
                {
                    if tcp.ece() {
                        self.ece_cnt += 1.0;
                    }
                }
                #[cfg(feature = "urg_cnt")]
                {
                    if tcp.urg() {
                        self.urg_cnt += 1.0;
                    }
                }
                #[cfg(feature = "ack_cnt")]
                {
                    if tcp.ack() {
                        self.ack_cnt += 1.0;
                    }
                }
                #[cfg(feature = "psh_cnt")]
                {
                    if tcp.psh() {
                        self.psh_cnt += 1.0;
                    }
                }
                #[cfg(feature = "rst_cnt")]
                {
                    if tcp.rst() {
                        self.rst_cnt += 1.0;
                    }
                }
                #[cfg(feature = "syn_cnt")]
                {
                    if tcp.syn() {
                        self.syn_cnt += 1.0;
                    }
                }
                #[cfg(feature = "fin_cnt")]
                {
                    if tcp.fin() {
                        self.fin_cnt += 1.0;
                    }
                }
                #[cfg(feature = "s_port")]
                {
                    self.s_port = tcp.src_port() as f64;
                }
                #[cfg(feature = "d_port")]
                {
                    self.d_port = tcp.dst_port() as f64;
                }
            }
            #[cfg(feature = "proto")]
            {
                self.proto = ipv4.protocol() as f64;
            }
        } else {
            #[cfg(feature = "d_iat_min")]
            {
                self.d_iat_min = self.d_iat_min.min(curr_ts - self.d_last_ts);
            }
            #[cfg(feature = "d_iat_max")]
            {
                self.d_iat_max = self.d_iat_max.max(curr_ts - self.d_last_ts);
            }
            #[cfg(any(feature = "d_iat_med", feature = "d_iat_std"))]
            {
                let d_iat = curr_ts - self.d_last_ts;
                if !d_iat.is_nan() {
                    self.d_iat_hist.push(curr_ts - self.d_last_ts);
                }
            }
            #[cfg(any(
                feature = "dur",
                feature = "s_load",
                feature = "d_load",
                feature = "d_iat_mean",
                feature = "d_iat_sum",
                feature = "d_iat_min",
                feature = "d_iat_max",
                feature = "d_iat_med",
                feature = "d_iat_std",
            ))]
            {
                self.d_last_ts = curr_ts;
            }
            #[cfg(any(
                feature = "d_pkt_cnt",
                feature = "d_bytes_mean",
                feature = "d_iat_mean",
                feature = "d_winsize_mean",
                feature = "d_ttl_mean",
            ))]
            {
                self.d_pkt_cnt += 1.0;
            }
            #[cfg(any(feature = "d_bytes_sum", feature = "d_bytes_mean", feature = "d_load"))]
            {
                self.d_bytes_sum += ipv4.total_length() as f64;
            }
            #[cfg(feature = "d_bytes_min")]
            {
                self.d_bytes_min = self.d_bytes_min.min(ipv4.total_length() as f64);
            }
            #[cfg(feature = "d_bytes_max")]
            {
                self.d_bytes_max = self.d_bytes_max.max(ipv4.total_length() as f64);
            }
            #[cfg(any(feature = "d_bytes_med", feature = "d_bytes_std"))]
            {
                self.d_bytes_hist.push(ipv4.total_length() as f64);
            }

            #[cfg(any(feature = "d_ttl_sum", feature = "d_ttl_mean"))]
            {
                self.d_ttl_sum += ipv4.time_to_live() as f64;
            }
            #[cfg(feature = "d_ttl_min")]
            {
                self.d_ttl_min = self.d_ttl_min.min(ipv4.time_to_live() as f64);
            }
            #[cfg(feature = "d_ttl_max")]
            {
                self.d_ttl_max = self.d_ttl_max.max(ipv4.time_to_live() as f64);
            }
            #[cfg(any(feature = "d_ttl_med", feature = "d_ttl_std"))]
            {
                self.d_ttl_hist.push(ipv4.time_to_live() as f64);
            }
            #[cfg(any(
                feature = "d_iat_mean",
                feature = "tcp_rtt",
                feature = "syn_ack",
                feature = "ack_dat",
                feature = "d_iat_sum",
            ))]
            if self.syn_ack_ts.is_nan() {
                let tcp = ipv4.parse_to::<Tcp>()?;
                if tcp.synack() {
                    self.syn_ack_ts = curr_ts;
                }
            }
            #[cfg(any(
                feature = "d_winsize_sum",
                feature = "d_winsize_mean",
                feature = "d_winsize_min",
                feature = "d_winsize_max",
                feature = "d_winsize_med",
                feature = "d_winsize_std",
                feature = "cwr_cnt",
                feature = "ece_cnt",
                feature = "urg_cnt",
                feature = "ack_cnt",
                feature = "psh_cnt",
                feature = "rst_cnt",
                feature = "syn_cnt",
                feature = "fin_cnt",
            ))]
            {
                let tcp = ipv4.parse_to::<Tcp>()?;
                #[cfg(any(
                    feature = "s_winsize_sum",
                    feature = "s_winsize_mean",
                    feature = "s_winsize_min",
                    feature = "s_winsize_max",
                    feature = "s_winsize_med",
                    feature = "s_winsize_std",
                ))]
                {
                    let winsize = tcp.window() as f64;
                    #[cfg(any(feature = "d_winsize_sum", feature = "d_winsize_mean"))]
                    {
                        self.d_winsize_sum += winsize;
                    }
                    #[cfg(feature = "d_winsize_min")]
                    {
                        self.d_winsize_min = self.d_winsize_min.min(winsize);
                    }
                    #[cfg(feature = "d_winsize_max")]
                    {
                        self.d_winsize_max = self.d_winsize_max.max(winsize);
                    }
                    #[cfg(any(feature = "d_winsize_med", feature = "d_winsize_std"))]
                    {
                        self.d_winsize_hist.push(winsize);
                    }
                }

                #[cfg(feature = "cwr_cnt")]
                {
                    if tcp.cwr() {
                        self.cwr_cnt += 1.0;
                    }
                }
                #[cfg(feature = "ece_cnt")]
                {
                    if tcp.ece() {
                        self.ece_cnt += 1.0;
                    }
                }
                #[cfg(feature = "urg_cnt")]
                {
                    if tcp.urg() {
                        self.urg_cnt += 1.0;
                    }
                }
                #[cfg(feature = "ack_cnt")]
                {
                    if tcp.ack() {
                        self.ack_cnt += 1.0;
                    }
                }
                #[cfg(feature = "psh_cnt")]
                {
                    if tcp.psh() {
                        self.psh_cnt += 1.0;
                    }
                }
                #[cfg(feature = "rst_cnt")]
                {
                    if tcp.rst() {
                        self.rst_cnt += 1.0;
                    }
                }
                #[cfg(feature = "syn_cnt")]
                {
                    if tcp.syn() {
                        self.syn_cnt += 1.0;
                    }
                }
                #[cfg(feature = "fin_cnt")]
                {
                    if tcp.fin() {
                        self.fin_cnt += 1.0;
                    }
                }
            }
        }
        #[cfg(feature = "timing")]
        {
            let end_ts = (unsafe { rte_rdtsc() } as f64 / *TSC_GHZ) as u64;
            self.compute_ns += end_ts - start_ts;
        }
        Ok(())
    }

    #[inline]
    fn extract_features(&mut self) -> Features {
        #[cfg(feature = "timing")]
        let start_ts = (unsafe { rte_rdtsc() } as f64 / *TSC_GHZ) as u64;

        #[cfg(any(feature = "dur", feature = "s_load", feature = "d_load",))]
        let dur = self.s_last_ts.max(self.d_last_ts) - self.syn_ts;
        #[cfg(any(feature = "s_load",))]
        let s_load = self.s_bytes_sum * 8e9 / dur;
        #[cfg(any(feature = "d_load",))]
        let d_load = self.d_bytes_sum * 8e9 / dur;

        #[cfg(any(feature = "syn_ack", feature = "tcp_rtt"))]
        let syn_ack = self.syn_ack_ts - self.syn_ts;
        #[cfg(any(feature = "ack_dat", feature = "tcp_rtt"))]
        let ack_dat = self.ack_ts - self.syn_ack_ts;
        #[cfg(feature = "tcp_rtt")]
        let tcp_rtt = syn_ack + ack_dat;

        #[cfg(any(feature = "s_bytes_mean"))]
        let s_bytes_mean = self.s_bytes_sum / self.s_pkt_cnt;
        #[cfg(any(feature = "d_bytes_mean"))]
        let d_bytes_mean = self.d_bytes_sum / self.d_pkt_cnt;
        #[cfg(any(feature = "s_bytes_med"))]
        let s_bytes_med = median(&mut self.s_bytes_hist);
        #[cfg(any(feature = "d_bytes_med"))]
        let d_bytes_med = median(&mut self.d_bytes_hist);
        #[cfg(any(feature = "s_bytes_std"))]
        let s_bytes_std = stddev(&mut self.s_bytes_hist);
        #[cfg(any(feature = "d_bytes_std"))]
        let d_bytes_std = stddev(&mut self.d_bytes_hist);

        #[cfg(feature = "s_iat_sum")]
        let s_iat_sum = self.s_last_ts - self.syn_ts;
        #[cfg(feature = "d_iat_sum")]
        let d_iat_sum = self.d_last_ts - self.syn_ack_ts;
        #[cfg(feature = "s_iat_mean")]
        let s_iat_mean = (self.s_last_ts - self.syn_ts) / (self.s_pkt_cnt - 1.0);
        #[cfg(feature = "d_iat_mean")]
        let d_iat_mean = (self.d_last_ts - self.syn_ack_ts) / (self.d_pkt_cnt - 1.0);
        #[cfg(any(feature = "s_iat_med"))]
        let s_iat_med = median(&mut self.s_iat_hist);
        #[cfg(any(feature = "d_iat_med"))]
        let d_iat_med = median(&mut self.d_iat_hist);
        #[cfg(any(feature = "s_iat_std"))]
        let s_iat_std = stddev(&mut self.s_iat_hist);
        #[cfg(any(feature = "d_iat_std"))]
        let d_iat_std = stddev(&mut self.d_iat_hist);

        #[cfg(any(feature = "s_winsize_mean"))]
        let s_winsize_mean = self.s_winsize_sum / self.s_pkt_cnt;
        #[cfg(any(feature = "d_winsize_mean"))]
        let d_winsize_mean = self.d_winsize_sum / self.d_pkt_cnt;
        #[cfg(any(feature = "s_winsize_med"))]
        let s_winsize_med = median(&mut self.s_winsize_hist);
        #[cfg(any(feature = "d_winsize_med"))]
        let d_winsize_med = median(&mut self.d_winsize_hist);
        #[cfg(any(feature = "s_winsize_std"))]
        let s_winsize_std = stddev(&mut self.s_winsize_hist);
        #[cfg(any(feature = "d_winsize_std"))]
        let d_winsize_std = stddev(&mut self.d_winsize_hist);

        #[cfg(any(feature = "s_ttl_mean"))]
        let s_ttl_mean = self.s_ttl_sum / self.s_pkt_cnt;
        #[cfg(any(feature = "d_ttl_mean"))]
        let d_ttl_mean = self.d_ttl_sum / self.d_pkt_cnt;
        #[cfg(any(feature = "s_ttl_med"))]
        let s_ttl_med = median(&mut self.s_ttl_hist);
        #[cfg(any(feature = "d_ttl_med"))]
        let d_ttl_med = median(&mut self.d_ttl_hist);
        #[cfg(any(feature = "s_ttl_std"))]
        let s_ttl_std = stddev(&mut self.s_ttl_hist);
        #[cfg(any(feature = "d_ttl_std"))]
        let d_ttl_std = stddev(&mut self.d_ttl_hist);

        #[cfg(any(feature = "timing", feature = "collect"))]
        let features = Features {
            #[cfg(feature = "dur")]
            dur,
            #[cfg(feature = "proto")]
            proto: self.proto,
            #[cfg(feature = "s_port")]
            s_port: self.s_port,
            #[cfg(feature = "d_port")]
            d_port: self.d_port,

            #[cfg(feature = "s_load")]
            s_load,
            #[cfg(feature = "d_load")]
            d_load,
            #[cfg(feature = "s_pkt_cnt")]
            s_pkt_cnt: self.s_pkt_cnt,
            #[cfg(feature = "d_pkt_cnt")]
            d_pkt_cnt: self.d_pkt_cnt,

            #[cfg(feature = "tcp_rtt")]
            tcp_rtt,
            #[cfg(feature = "syn_ack")]
            syn_ack,
            #[cfg(feature = "ack_dat")]
            ack_dat,

            #[cfg(feature = "cwr_cnt")]
            cwr_cnt: self.cwr_cnt,
            #[cfg(feature = "ece_cnt")]
            ece_cnt: self.ece_cnt,
            #[cfg(feature = "urg_cnt")]
            urg_cnt: self.urg_cnt,
            #[cfg(feature = "ack_cnt")]
            ack_cnt: self.ack_cnt,
            #[cfg(feature = "psh_cnt")]
            psh_cnt: self.psh_cnt,
            #[cfg(feature = "rst_cnt")]
            rst_cnt: self.rst_cnt,
            #[cfg(feature = "syn_cnt")]
            syn_cnt: self.syn_cnt,
            #[cfg(feature = "fin_cnt")]
            fin_cnt: self.fin_cnt,

            #[cfg(feature = "s_bytes_sum")]
            s_bytes_sum: self.s_bytes_sum,
            #[cfg(feature = "d_bytes_sum")]
            d_bytes_sum: self.d_bytes_sum,
            #[cfg(feature = "s_bytes_mean")]
            s_bytes_mean,
            #[cfg(feature = "d_bytes_mean")]
            d_bytes_mean,
            #[cfg(feature = "s_bytes_min")]
            s_bytes_min: self.s_bytes_min,
            #[cfg(feature = "d_bytes_min")]
            d_bytes_min: self.d_bytes_min,
            #[cfg(feature = "s_bytes_max")]
            s_bytes_max: self.s_bytes_max,
            #[cfg(feature = "d_bytes_max")]
            d_bytes_max: self.d_bytes_max,
            #[cfg(feature = "s_bytes_med")]
            s_bytes_med,
            #[cfg(feature = "d_bytes_med")]
            d_bytes_med,
            #[cfg(feature = "s_bytes_std")]
            s_bytes_std,
            #[cfg(feature = "d_bytes_std")]
            d_bytes_std,

            #[cfg(feature = "s_iat_sum")]
            s_iat_sum,
            #[cfg(feature = "d_iat_sum")]
            d_iat_sum,
            #[cfg(feature = "s_iat_mean")]
            s_iat_mean,
            #[cfg(feature = "d_iat_mean")]
            d_iat_mean,
            #[cfg(feature = "s_iat_min")]
            s_iat_min: self.s_iat_min,
            #[cfg(feature = "d_iat_min")]
            d_iat_min: self.d_iat_min,
            #[cfg(feature = "s_iat_max")]
            s_iat_max: self.s_iat_max,
            #[cfg(feature = "d_iat_max")]
            d_iat_max: self.d_iat_max,
            #[cfg(feature = "s_iat_med")]
            s_iat_med,
            #[cfg(feature = "d_iat_med")]
            d_iat_med,
            #[cfg(feature = "s_iat_std")]
            s_iat_std,
            #[cfg(feature = "d_iat_std")]
            d_iat_std,

            #[cfg(feature = "s_winsize_sum")]
            s_winsize_sum: self.s_winsize_sum,
            #[cfg(feature = "d_winsize_sum")]
            d_winsize_sum: self.d_winsize_sum,
            #[cfg(feature = "s_winsize_mean")]
            s_winsize_mean,
            #[cfg(feature = "d_winsize_mean")]
            d_winsize_mean,
            #[cfg(feature = "s_winsize_min")]
            s_winsize_min: self.s_winsize_min,
            #[cfg(feature = "d_winsize_min")]
            d_winsize_min: self.d_winsize_min,
            #[cfg(feature = "s_winsize_max")]
            s_winsize_max: self.s_winsize_max,
            #[cfg(feature = "d_winsize_max")]
            d_winsize_max: self.d_winsize_max,
            #[cfg(feature = "s_winsize_med")]
            s_winsize_med,
            #[cfg(feature = "d_winsize_med")]
            d_winsize_med,
            #[cfg(feature = "s_winsize_std")]
            s_winsize_std,
            #[cfg(feature = "d_winsize_std")]
            d_winsize_std,

            #[cfg(feature = "s_ttl_sum")]
            s_ttl_sum: self.s_ttl_sum,
            #[cfg(feature = "d_ttl_sum")]
            d_ttl_sum: self.d_ttl_sum,
            #[cfg(feature = "s_ttl_mean")]
            s_ttl_mean,
            #[cfg(feature = "d_ttl_mean")]
            d_ttl_mean,
            #[cfg(feature = "s_ttl_min")]
            s_ttl_min: self.s_ttl_min,
            #[cfg(feature = "d_ttl_min")]
            d_ttl_min: self.d_ttl_min,
            #[cfg(feature = "s_ttl_max")]
            s_ttl_max: self.s_ttl_max,
            #[cfg(feature = "d_ttl_max")]
            d_ttl_max: self.d_ttl_max,
            #[cfg(feature = "s_ttl_med")]
            s_ttl_med,
            #[cfg(feature = "d_ttl_med")]
            d_ttl_med,
            #[cfg(feature = "s_ttl_std")]
            s_ttl_std,
            #[cfg(feature = "d_ttl_std")]
            d_ttl_std,

            #[cfg(feature = "label")]
            s_mac: self.s_mac,
            #[cfg(feature = "label")]
            d_mac: self.d_mac,
            #[cfg(feature = "capture_start")]
            syn_ts: self.syn_ts,
        };

        #[cfg(not(any(feature = "timing", feature = "collect")))]
        let features = Features {
            #[cfg(feature = "capture_start")]
            syn_ts: self.syn_ts,
            #[cfg(feature = "label")]
            s_mac: self.s_mac,
            #[cfg(feature = "label")]
            d_mac: self.d_mac,
            feature_vec: vec![
                #[cfg(feature = "dur")]
                dur,
                #[cfg(feature = "proto")]
                self.proto,
                #[cfg(feature = "s_port")]
                self.s_port,
                #[cfg(feature = "d_port")]
                self.d_port,

                #[cfg(feature = "s_load")]
                s_load,
                #[cfg(feature = "d_load")]
                d_load,
                #[cfg(feature = "s_pkt_cnt")]
                self.s_pkt_cnt,
                #[cfg(feature = "d_pkt_cnt")]
                self.d_pkt_cnt,

                #[cfg(feature = "tcp_rtt")]
                tcp_rtt,
                #[cfg(feature = "syn_ack")]
                syn_ack,
                #[cfg(feature = "ack_dat")]
                ack_dat,

                #[cfg(feature = "cwr_cnt")]
                self.cwr_cnt,
                #[cfg(feature = "ece_cnt")]
                self.ece_cnt,
                #[cfg(feature = "urg_cnt")]
                self.urg_cnt,
                #[cfg(feature = "ack_cnt")]
                self.ack_cnt,
                #[cfg(feature = "psh_cnt")]
                self.psh_cnt,
                #[cfg(feature = "rst_cnt")]
                self.rst_cnt,
                #[cfg(feature = "syn_cnt")]
                self.syn_cnt,
                #[cfg(feature = "fin_cnt")]
                self.fin_cnt,

                #[cfg(feature = "s_bytes_sum")]
                self.s_bytes_sum,
                #[cfg(feature = "d_bytes_sum")]
                self.d_bytes_sum,
                #[cfg(feature = "s_bytes_mean")]
                s_bytes_mean,
                #[cfg(feature = "d_bytes_mean")]
                d_bytes_mean,
                #[cfg(feature = "s_bytes_min")]
                self.s_bytes_min,
                #[cfg(feature = "d_bytes_min")]
                self.d_bytes_min,
                #[cfg(feature = "s_bytes_max")]
                self.s_bytes_max,
                #[cfg(feature = "d_bytes_max")]
                self.d_bytes_max,
                #[cfg(feature = "s_bytes_med")]
                s_bytes_med,
                #[cfg(feature = "d_bytes_med")]
                d_bytes_med,
                #[cfg(feature = "s_bytes_std")]
                s_bytes_std,
                #[cfg(feature = "d_bytes_std")]
                d_bytes_std,

                #[cfg(feature = "s_iat_sum")]
                s_iat_sum,
                #[cfg(feature = "d_iat_sum")]
                d_iat_sum,
                #[cfg(feature = "s_iat_mean")]
                s_iat_mean,
                #[cfg(feature = "d_iat_mean")]
                d_iat_mean,
                #[cfg(feature = "s_iat_min")]
                self.s_iat_min,
                #[cfg(feature = "d_iat_min")]
                self.d_iat_min,
                #[cfg(feature = "s_iat_max")]
                self.s_iat_max,
                #[cfg(feature = "d_iat_max")]
                self.d_iat_max,
                #[cfg(feature = "s_iat_med")]
                s_iat_med,
                #[cfg(feature = "d_iat_med")]
                d_iat_med,
                #[cfg(feature = "s_iat_std")]
                s_iat_std,
                #[cfg(feature = "d_iat_std")]
                d_iat_std,

                #[cfg(feature = "s_winsize_sum")]
                self.s_winsize_sum,
                #[cfg(feature = "d_winsize_sum")]
                self.d_winsize_sum,
                #[cfg(feature = "s_winsize_mean")]
                s_winsize_mean,
                #[cfg(feature = "d_winsize_mean")]
                d_winsize_mean,
                #[cfg(feature = "s_winsize_min")]
                self.s_winsize_min,
                #[cfg(feature = "d_winsize_min")]
                self.d_winsize_min,
                #[cfg(feature = "s_winsize_max")]
                self.s_winsize_max,
                #[cfg(feature = "d_winsize_max")]
                self.d_winsize_max,
                #[cfg(feature = "s_winsize_med")]
                s_winsize_med,
                #[cfg(feature = "d_winsize_med")]
                d_winsize_med,
                #[cfg(feature = "s_winsize_std")]
                s_winsize_std,
                #[cfg(feature = "d_winsize_std")]
                d_winsize_std,

                #[cfg(feature = "s_ttl_sum")]
                self.s_ttl_sum,
                #[cfg(feature = "d_ttl_sum")]
                self.d_ttl_sum,
                #[cfg(feature = "s_ttl_mean")]
                s_ttl_mean,
                #[cfg(feature = "d_ttl_mean")]
                d_ttl_mean,
                #[cfg(feature = "s_ttl_min")]
                self.s_ttl_min,
                #[cfg(feature = "d_ttl_min")]
                self.d_ttl_min,
                #[cfg(feature = "s_ttl_max")]
                self.s_ttl_max,
                #[cfg(feature = "d_ttl_max")]
                self.d_ttl_max,
                #[cfg(feature = "s_ttl_med")]
                s_ttl_med,
                #[cfg(feature = "d_ttl_med")]
                d_ttl_med,
                #[cfg(feature = "s_ttl_std")]
                s_ttl_std,
                #[cfg(feature = "d_ttl_std")]
                d_ttl_std,
            ]
        };

        #[cfg(feature = "timing")]
        {
            let end_ts = (unsafe { rte_rdtsc() } as f64 / *TSC_GHZ) as u64;
            self.compute_ns += end_ts - start_ts;
        }
        features
    }
}

impl Trackable for TrackedFeatures {
    type Subscribed = Features;

    fn new(_five_tuple: FiveTuple) -> Self {
        TrackedFeatures {
            #[cfg(feature = "timing")]
            compute_ns: 0,
            #[cfg(feature = "label")]
            s_mac: pnet::datalink::MacAddr::zero(),
            #[cfg(feature = "label")]
            d_mac: pnet::datalink::MacAddr::zero(),
            cnt: 0,
            #[cfg(any(
                feature = "capture_start",
                feature = "dur",
                feature = "s_load",
                feature = "d_load",
                feature = "s_iat_mean",
                feature = "tcp_rtt",
                feature = "syn_ack",
                feature = "s_iat_sum",
            ))]
            syn_ts: f64::NAN,
            #[cfg(any(
                feature = "d_iat_mean",
                feature = "tcp_rtt",
                feature = "syn_ack",
                feature = "ack_dat",
                feature = "d_iat_sum",
            ))]
            syn_ack_ts: f64::NAN,
            #[cfg(any(feature = "tcp_rtt", feature = "ack_dat"))]
            ack_ts: f64::NAN,
            #[cfg(any(
                feature = "dur",
                feature = "s_load",
                feature = "d_load",
                feature = "s_iat_mean",
                feature = "s_iat_sum",
                feature = "s_iat_min",
                feature = "s_iat_max",
                feature = "s_iat_med",
                feature = "s_iat_std",
            ))]
            s_last_ts: f64::NAN,
            #[cfg(any(
                feature = "dur",
                feature = "s_load",
                feature = "d_load",
                feature = "d_iat_mean",
                feature = "d_iat_sum",
                feature = "d_iat_min",
                feature = "d_iat_max",
                feature = "d_iat_med",
                feature = "d_iat_std",
            ))]
            d_last_ts: f64::NAN,
            #[cfg(any(
                feature = "s_pkt_cnt",
                feature = "s_bytes_mean",
                feature = "s_iat_mean",
                feature = "s_winsize_mean",
                feature = "s_ttl_mean",
            ))]
            s_pkt_cnt: 0.0,
            #[cfg(any(
                feature = "d_pkt_cnt",
                feature = "d_bytes_mean",
                feature = "d_iat_mean",
                feature = "d_winsize_mean",
                feature = "d_ttl_mean",
            ))]
            d_pkt_cnt: 0.0,

            #[cfg(feature = "cwr_cnt")]
            cwr_cnt: 0.0,
            #[cfg(feature = "ece_cnt")]
            ece_cnt: 0.0,
            #[cfg(feature = "urg_cnt")]
            urg_cnt: 0.0,
            #[cfg(feature = "ack_cnt")]
            ack_cnt: 0.0,
            #[cfg(feature = "psh_cnt")]
            psh_cnt: 0.0,
            #[cfg(feature = "rst_cnt")]
            rst_cnt: 0.0,
            #[cfg(feature = "syn_cnt")]
            syn_cnt: 0.0,
            #[cfg(feature = "fin_cnt")]
            fin_cnt: 0.0,

            #[cfg(feature = "proto")]
            proto: f64::NAN,
            #[cfg(feature = "s_port")]
            s_port: f64::NAN,
            #[cfg(feature = "d_port")]
            d_port: f64::NAN,

            #[cfg(any(feature = "s_bytes_sum", feature = "s_bytes_mean", feature = "s_load"))]
            s_bytes_sum: 0.0,
            #[cfg(any(feature = "d_bytes_sum", feature = "d_bytes_mean", feature = "d_load"))]
            d_bytes_sum: 0.0,
            #[cfg(feature = "s_bytes_min")]
            s_bytes_min: f64::NAN,
            #[cfg(feature = "d_bytes_min")]
            d_bytes_min: f64::NAN,
            #[cfg(feature = "s_bytes_max")]
            s_bytes_max: f64::NAN,
            #[cfg(feature = "d_bytes_max")]
            d_bytes_max: f64::NAN,
            #[cfg(any(feature = "s_bytes_med", feature = "s_bytes_std"))]
            s_bytes_hist: vec![],
            #[cfg(any(feature = "d_bytes_med", feature = "d_bytes_std"))]
            d_bytes_hist: vec![],

            #[cfg(feature = "s_iat_min")]
            s_iat_min: f64::NAN,
            #[cfg(feature = "d_iat_min")]
            d_iat_min: f64::NAN,
            #[cfg(feature = "s_iat_max")]
            s_iat_max: f64::NAN,
            #[cfg(feature = "d_iat_max")]
            d_iat_max: f64::NAN,
            #[cfg(any(feature = "s_iat_med", feature = "s_iat_std"))]
            s_iat_hist: vec![],
            #[cfg(any(feature = "d_iat_med", feature = "d_iat_std"))]
            d_iat_hist: vec![],

            #[cfg(any(feature = "s_winsize_sum", feature = "s_winsize_mean"))]
            s_winsize_sum: 0.0,
            #[cfg(any(feature = "d_winsize_sum", feature = "d_winsize_mean"))]
            d_winsize_sum: 0.0,
            #[cfg(feature = "s_winsize_min")]
            s_winsize_min: f64::NAN,
            #[cfg(feature = "d_winsize_min")]
            d_winsize_min: f64::NAN,
            #[cfg(feature = "s_winsize_max")]
            s_winsize_max: f64::NAN,
            #[cfg(feature = "d_winsize_max")]
            d_winsize_max: f64::NAN,
            #[cfg(any(feature = "s_winsize_med", feature = "s_winsize_std"))]
            s_winsize_hist: vec![],
            #[cfg(any(feature = "d_winsize_med", feature = "d_winsize_std"))]
            d_winsize_hist: vec![],

            #[cfg(any(feature = "s_ttl_sum", feature = "s_ttl_mean"))]
            s_ttl_sum: 0.0,
            #[cfg(any(feature = "d_ttl_sum", feature = "d_ttl_mean"))]
            d_ttl_sum: 0.0,
            #[cfg(feature = "s_ttl_min")]
            s_ttl_min: f64::NAN,
            #[cfg(feature = "d_ttl_min")]
            d_ttl_min: f64::NAN,
            #[cfg(feature = "s_ttl_max")]
            s_ttl_max: f64::NAN,
            #[cfg(feature = "d_ttl_max")]
            d_ttl_max: f64::NAN,
            #[cfg(any(feature = "s_ttl_med", feature = "s_ttl_std"))]
            s_ttl_hist: vec![],
            #[cfg(any(feature = "d_ttl_med", feature = "d_ttl_std"))]
            d_ttl_hist: vec![],

        }
    }

    fn pre_match(
        &mut self,
        pdu: L4Pdu,
        _session_id: Option<usize>,
        subscription: &Subscription<Self::Subscribed>,
    ) {
        timer_start!(t);
        self.update(pdu).unwrap_or(());
        timer_elapsed_nanos!(subscription.timers, "update", t);
    }

    fn on_match(&mut self, session: Session, _subscription: &Subscription<Self::Subscribed>) {
    }

    fn post_match(&mut self, pdu: L4Pdu, subscription: &Subscription<Self::Subscribed>) {
        timer_start!(t);
        self.update(pdu).unwrap_or(());
        timer_elapsed_nanos!(subscription.timers, "update", t);
    }

    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>) {
        timer_start!(t);
        let features = self.extract_features();
        timer_elapsed_nanos!(subscription.timers, "extract_features", t);

        let conn = features;
        timer_record!(subscription.timers, "compute_ns", self.compute_ns);
        subscription.invoke(conn);
    }

    fn early_terminate(&self) -> bool {
        self.cnt >= 1
    }
}

fn median(numbers: &mut [f64]) -> f64 {
    if numbers.is_empty() {
        return f64::NAN;
    }
    numbers.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = numbers.len() / 2;
    if numbers.len() % 2 == 1 {
        numbers[mid]
    } else {
        (numbers[mid - 1] + numbers[mid]) / 2.0
    }
}

fn stddev(numbers: &mut [f64]) -> f64 {
    if numbers.is_empty() {
        return f64::NAN;
    }
    let mean = numbers.iter().sum::<f64>() / (numbers.len() as f64);
    let squared_diff_sum = numbers.iter().map(|&num| (num - mean).powi(2)).sum::<f64>();
    (squared_diff_sum / numbers.len() as f64).sqrt()
}
