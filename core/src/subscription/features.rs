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
#[derive(Debug, Serialize)]
pub struct Features {
    #[cfg(feature = "dur")]
    dur: f64,
    #[cfg(feature = "proto")]
    proto: f64,
    #[cfg(feature = "s_bytes_sum")]
    s_bytes_sum: f64,
    #[cfg(feature = "d_bytes_sum")]
    d_bytes_sum: f64,
    #[cfg(feature = "s_ttl_mean")]
    s_ttl_mean: f64,
    #[cfg(feature = "d_ttl_mean")]
    d_ttl_mean: f64,
    #[cfg(feature = "s_load")]
    s_load: f64,
    #[cfg(feature = "d_load")]
    d_load: f64,
    #[cfg(feature = "s_pkt_cnt")]
    s_pkt_cnt: f64,
    #[cfg(feature = "d_pkt_cnt")]
    d_pkt_cnt: f64,
    #[cfg(feature = "s_bytes_mean")]
    s_bytes_mean: f64,
    #[cfg(feature = "d_bytes_mean")]
    d_bytes_mean: f64,
    #[cfg(feature = "s_iat_mean")]
    s_iat_mean: f64,
    #[cfg(feature = "d_iat_mean")]
    d_iat_mean: f64,
    #[cfg(feature = "tcp_rtt")]
    tcp_rtt: f64,
    #[cfg(feature = "syn_ack")]
    syn_ack: f64,
    #[cfg(feature = "ack_dat")]
    ack_dat: f64,
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

    #[serde(serialize_with = "serialize_mac_addr")]
    #[cfg(not(feature = "timing"))]
    s_mac: pnet::datalink::MacAddr,
    #[serde(serialize_with = "serialize_mac_addr")]
    #[cfg(not(feature = "timing"))]
    d_mac: pnet::datalink::MacAddr,
    sni: String,
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
    sni: String,
    cnt: u64,
    #[cfg(any(
        feature = "dur",
        feature = "s_load",
        feature = "d_load",
        feature = "s_iat_mean",
        feature = "tcp_rtt",
        feature = "syn_ack",
    ))]
    syn_ts: f64,
    #[cfg(any(
        feature = "d_iat_mean",
        feature = "tcp_rtt",
        feature = "syn_ack",
        feature = "ack_dat",
    ))]
    syn_ack_ts: f64,
    #[cfg(any(feature = "tcp_rtt", feature = "ack_dat",))]
    ack_ts: f64,
    #[cfg(any(
        feature = "dur",
        feature = "s_load",
        feature = "d_load",
        feature = "s_iat_mean",
    ))]
    s_last_ts: f64,
    #[cfg(any(
        feature = "dur",
        feature = "s_load",
        feature = "d_load",
        feature = "d_iat_mean",
    ))]
    d_last_ts: f64,
    #[cfg(any(
        feature = "s_ttl_mean",
        feature = "s_pkt_cnt",
        feature = "s_bytes_mean",
        feature = "s_iat_mean",
    ))]
    s_pkt_cnt: f64,
    #[cfg(any(
        feature = "d_ttl_mean",
        feature = "d_pkt_cnt",
        feature = "d_bytes_mean",
        feature = "d_iat_mean"
    ))]
    d_pkt_cnt: f64,
    #[cfg(any(feature = "s_bytes_sum", feature = "s_load", feature = "s_bytes_mean"))]
    s_bytes_sum: f64,
    #[cfg(any(feature = "d_bytes_sum", feature = "d_load", feature = "d_bytes_mean"))]
    d_bytes_sum: f64,
    #[cfg(feature = "s_ttl_mean")]
    s_ttl_sum: f64,
    #[cfg(feature = "d_ttl_mean")]
    d_ttl_sum: f64,
    #[cfg(feature = "proto")]
    proto: f64,
    #[cfg(feature = "s_bytes_min")]
    s_bytes_min: f64,
    #[cfg(feature = "d_bytes_min")]
    d_bytes_min: f64,
    #[cfg(feature = "s_bytes_max")]
    s_bytes_max: f64,
    #[cfg(feature = "d_bytes_max")]
    d_bytes_max: f64,
    #[cfg(feature = "s_bytes_med")]
    s_bytes_hist: Vec<f64>,
    #[cfg(feature = "d_bytes_med")]
    d_bytes_hist: Vec<f64>,
    #[cfg(not(feature = "timing"))]
    s_mac: pnet::datalink::MacAddr,
    #[cfg(not(feature = "timing"))]
    d_mac: pnet::datalink::MacAddr,
}

impl TrackedFeatures {
    #[inline]
    fn update(&mut self, segment: L4Pdu) -> Result<()> {
        self.cnt += 1;
        #[cfg(feature = "timing")]
        let start_ts = (unsafe { rte_rdtsc() } as f64 / *TSC_GHZ) as u64;

        #[cfg(any(
            feature = "dur",
            feature = "s_load",
            feature = "d_load",
            feature = "s_iat_mean",
            feature = "d_iat_mean",
            feature = "tcp_rtt",
            feature = "syn_ack",
            feature = "ack_dat",
        ))]
        let curr_ts = unsafe { rte_rdtsc() } as f64 / *TSC_GHZ;
        #[cfg(not(feature = "timing"))]
        let curr_ts = segment.mbuf_ref().timestamp() as f64 * 1e3;

        #[cfg(any(
            feature = "proto",
            feature = "s_bytes_sum",
            feature = "d_bytes_sum",
            feature = "s_ttl_mean",
            feature = "d_ttl_mean",
            feature = "s_load",
            feature = "d_load",
            feature = "s_bytes_mean",
            feature = "d_bytes_mean",
            feature = "d_iat_mean",
            feature = "tcp_rtt",
            feature = "syn_ack",
            feature = "ack_dat",
            feature = "s_bytes_min",
            feature = "d_bytes_min",
            feature = "s_bytes_max",
            feature = "d_bytes_max",
            feature = "s_bytes_med",
            feature = "d_bytes_med",
        ))]
        let mbuf = segment.mbuf_ref();
        #[cfg(any(
            feature = "proto",
            feature = "s_bytes_sum",
            feature = "d_bytes_sum",
            feature = "s_ttl_mean",
            feature = "d_ttl_mean",
            feature = "s_load",
            feature = "d_load",
            feature = "s_bytes_mean",
            feature = "d_bytes_mean",
            feature = "d_iat_mean",
            feature = "tcp_rtt",
            feature = "syn_ack",
            feature = "ack_dat",
            feature = "s_bytes_min",
            feature = "d_bytes_min",
            feature = "s_bytes_max",
            feature = "d_bytes_max",
            feature = "s_bytes_med",
            feature = "d_bytes_med",
        ))]
        let eth = mbuf.parse_to::<Ethernet>()?;
        #[cfg(any(
            feature = "proto",
            feature = "s_bytes_sum",
            feature = "d_bytes_sum",
            feature = "s_ttl_mean",
            feature = "d_ttl_mean",
            feature = "s_load",
            feature = "d_load",
            feature = "s_bytes_mean",
            feature = "d_bytes_mean",
            feature = "d_iat_mean",
            feature = "tcp_rtt",
            feature = "syn_ack",
            feature = "ack_dat",
            feature = "s_bytes_min",
            feature = "d_bytes_min",
            feature = "s_bytes_max",
            feature = "d_bytes_max",
            feature = "s_bytes_med",
            feature = "d_bytes_med",
        ))]
        let ipv4 = eth.parse_to::<Ipv4>()?;

        if segment.dir {
            #[cfg(not(feature = "timing"))]
            if self.cnt == 1 {
                let mbuf = segment.mbuf_ref();
                let eth = mbuf.parse_to::<Ethernet>()?;
                self.s_mac = eth.src();
                self.d_mac = eth.dst();
            }

            #[cfg(any(
                feature = "dur",
                feature = "s_load",
                feature = "d_load",
                feature = "s_iat_mean",
                feature = "tcp_rtt",
                feature = "syn_ack",
            ))]
            if self.syn_ts.is_nan() {
                self.syn_ts = curr_ts;
            }

            #[cfg(any(
                feature = "dur",
                feature = "s_load",
                feature = "d_load",
                feature = "s_iat_mean",
            ))]
            {
                self.s_last_ts = curr_ts;
            }
            #[cfg(any(
                feature = "s_ttl_mean",
                feature = "s_pkt_cnt",
                feature = "s_bytes_mean",
                feature = "s_iat_mean",
            ))]
            {
                self.s_pkt_cnt += 1.0;
            }
            #[cfg(any(feature = "s_bytes_sum", feature = "s_load", feature = "s_bytes_mean"))]
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
            #[cfg(any(feature = "s_bytes_med"))]
            {
                self.s_bytes_hist.push(ipv4.total_length() as f64);
            }
            #[cfg(feature = "s_ttl_mean")]
            {
                self.s_ttl_sum += ipv4.time_to_live() as f64;
            }
            #[cfg(any(feature = "tcp_rtt", feature = "ack_dat",))]
            if !self.syn_ack_ts.is_nan() && self.ack_ts.is_nan() {
                let tcp = ipv4.parse_to::<Tcp>()?;
                if tcp.ack() {
                    self.ack_ts = curr_ts;
                }
            }
            #[cfg(feature = "proto")]
            {
                self.proto = ipv4.protocol() as f64;
            }
        } else {
            #[cfg(any(
                feature = "dur",
                feature = "s_load",
                feature = "d_load",
                feature = "d_iat_mean",
            ))]
            {
                self.d_last_ts = curr_ts;
            }
            #[cfg(any(
                feature = "d_ttl_mean",
                feature = "d_pkt_cnt",
                feature = "d_bytes_mean",
                feature = "d_iat_mean"
            ))]
            {
                self.d_pkt_cnt += 1.0;
            }
            #[cfg(any(feature = "d_bytes_sum", feature = "d_load", feature = "d_bytes_mean"))]
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
            #[cfg(any(feature = "d_bytes_med"))]
            {
                self.d_bytes_hist.push(ipv4.total_length() as f64);
            }
            #[cfg(any(feature = "d_ttl_mean"))]
            {
                self.d_ttl_sum += ipv4.time_to_live() as f64;
            }
            #[cfg(any(
                feature = "d_iat_mean",
                feature = "tcp_rtt",
                feature = "syn_ack",
                feature = "ack_dat",
            ))]
            if self.syn_ack_ts.is_nan() {
                let tcp = ipv4.parse_to::<Tcp>()?;
                if tcp.synack() {
                    self.syn_ack_ts = curr_ts;
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
        #[cfg(any(feature = "s_ttl_mean"))]
        let s_ttl_mean = self.s_ttl_sum / self.s_pkt_cnt;
        #[cfg(any(feature = "d_ttl_mean"))]
        let d_ttl_mean = self.d_ttl_sum / self.d_pkt_cnt;
        #[cfg(any(feature = "s_load",))]
        let s_load = self.s_bytes_sum * 8e9 / dur;
        #[cfg(any(feature = "d_load",))]
        let d_load = self.d_bytes_sum * 8e9 / dur;
        #[cfg(any(feature = "s_bytes_mean"))]
        let s_bytes_mean = self.s_bytes_sum / self.s_pkt_cnt;
        #[cfg(any(feature = "d_bytes_mean"))]
        let d_bytes_mean = self.d_bytes_sum / self.d_pkt_cnt;
        #[cfg(feature = "s_iat_mean")]
        let s_iat_mean = (self.s_last_ts - self.syn_ts) / (self.s_pkt_cnt - 1.0);
        #[cfg(feature = "d_iat_mean")]
        let d_iat_mean = (self.d_last_ts - self.syn_ack_ts) / (self.d_pkt_cnt - 1.0);
        #[cfg(any(feature = "syn_ack", feature = "tcp_rtt"))]
        let syn_ack = self.syn_ack_ts - self.syn_ts;
        #[cfg(any(feature = "ack_dat", feature = "tcp_rtt"))]
        let ack_dat = self.ack_ts - self.syn_ack_ts;
        #[cfg(feature = "tcp_rtt")]
        let tcp_rtt = syn_ack + ack_dat;
        #[cfg(any(feature = "s_bytes_med"))]
        let s_bytes_med = median(&mut self.s_bytes_hist);
        #[cfg(any(feature = "d_bytes_med"))]
        let d_bytes_med = median(&mut self.d_bytes_hist);
        let features = Features {
            #[cfg(feature = "dur")]
            dur,
            #[cfg(feature = "proto")]
            proto: self.proto,
            #[cfg(feature = "s_bytes_sum")]
            s_bytes_sum: self.s_bytes_sum,
            #[cfg(feature = "d_bytes_sum")]
            d_bytes_sum: self.d_bytes_sum,
            #[cfg(feature = "s_ttl_mean")]
            s_ttl_mean,
            #[cfg(feature = "d_ttl_mean")]
            d_ttl_mean,
            #[cfg(feature = "s_load")]
            s_load,
            #[cfg(feature = "d_load")]
            d_load,
            #[cfg(feature = "s_pkt_cnt")]
            s_pkt_cnt: self.s_pkt_cnt,
            #[cfg(feature = "d_pkt_cnt")]
            d_pkt_cnt: self.d_pkt_cnt,
            #[cfg(feature = "s_bytes_mean")]
            s_bytes_mean,
            #[cfg(feature = "d_bytes_mean")]
            d_bytes_mean,
            #[cfg(feature = "s_iat_mean")]
            s_iat_mean,
            #[cfg(feature = "d_iat_mean")]
            d_iat_mean,
            #[cfg(feature = "tcp_rtt")]
            tcp_rtt,
            #[cfg(feature = "syn_ack")]
            syn_ack,
            #[cfg(feature = "ack_dat")]
            ack_dat,
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

            #[cfg(not(feature = "timing"))]
            s_mac: self.s_mac,
            #[cfg(not(feature = "timing"))]
            d_mac: self.d_mac,
            sni: self.sni.clone(),
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
            sni: "".to_string(),
            cnt: 0,
            #[cfg(any(
                feature = "dur",
                feature = "s_load",
                feature = "d_load",
                feature = "s_iat_mean",
                feature = "tcp_rtt",
                feature = "syn_ack",
            ))]
            syn_ts: f64::NAN,
            #[cfg(any(
                feature = "d_iat_mean",
                feature = "tcp_rtt",
                feature = "syn_ack",
                feature = "ack_dat"
            ))]
            syn_ack_ts: f64::NAN,
            #[cfg(any(feature = "tcp_rtt", feature = "ack_dat"))]
            ack_ts: f64::NAN,
            #[cfg(any(
                feature = "dur",
                feature = "s_load",
                feature = "d_load",
                feature = "s_iat_mean",
            ))]
            s_last_ts: f64::NAN,
            #[cfg(any(
                feature = "dur",
                feature = "s_load",
                feature = "d_load",
                feature = "d_iat_mean",
            ))]
            d_last_ts: f64::NAN,
            #[cfg(any(
                feature = "s_ttl_mean",
                feature = "s_pkt_cnt",
                feature = "s_bytes_mean",
                feature = "s_iat_mean",
            ))]
            s_pkt_cnt: 0.0,
            #[cfg(any(
                feature = "d_ttl_mean",
                feature = "d_pkt_cnt",
                feature = "d_bytes_mean",
                feature = "d_iat_mean",
            ))]
            d_pkt_cnt: 0.0,
            #[cfg(any(feature = "s_bytes_sum", feature = "s_load", feature = "s_bytes_mean"))]
            s_bytes_sum: 0.0,
            #[cfg(any(feature = "d_bytes_sum", feature = "d_load", feature = "d_bytes_mean"))]
            d_bytes_sum: 0.0,
            #[cfg(feature = "s_ttl_mean")]
            s_ttl_sum: 0.0,
            #[cfg(feature = "d_ttl_mean")]
            d_ttl_sum: 0.0,
            #[cfg(feature = "proto")]
            proto: f64::NAN,
            #[cfg(feature = "s_bytes_min")]
            s_bytes_min: f64::NAN,
            #[cfg(feature = "d_bytes_min")]
            d_bytes_min: f64::NAN,
            #[cfg(feature = "s_bytes_max")]
            s_bytes_max: f64::NAN,
            #[cfg(feature = "d_bytes_max")]
            d_bytes_max: f64::NAN,
            #[cfg(any(feature = "s_bytes_med"))]
            s_bytes_hist: vec![],
            #[cfg(any(feature = "d_bytes_med"))]
            d_bytes_hist: vec![],

            #[cfg(not(feature = "timing"))]
            s_mac: pnet::datalink::MacAddr::zero(),
            #[cfg(not(feature = "timing"))]
            d_mac: pnet::datalink::MacAddr::zero(),
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
        if let SessionData::Tls(tls) = session.data {
            self.sni = tls.sni().to_string();
        }
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
        false
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
        (numbers[mid-1] + numbers[mid]) / 2.0
    }
}
