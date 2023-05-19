macro_rules! tsc_start {
    ( $start:ident ) => {
        #[cfg(feature = "timing")]
        let $start = unsafe { $crate::dpdk::rte_rdtsc() };
    };
}

macro_rules! tsc_elapsed {
    ( $timers:expr, $timer:expr, $start:ident ) => {
        #[cfg(feature = "timing")]
        $timers.record($timer, unsafe { $crate::dpdk::rte_rdtsc() } - $start, 1);
    };
    ( $timers:expr, $timer:expr, $start:ident, $sample:literal ) => {
        #[cfg(feature = "timing")]
        $timers.record(
            $timer,
            unsafe { $crate::dpdk::rte_rdtsc() } - $start,
            $sample,
        );
    };
}

macro_rules! tsc_record {
    ( $timers:expr, $timer:expr, $time:expr ) => {
        #[cfg(feature = "timing")]
        $timers.record($timer, $time, 1);
    };
    ( $timers:expr, $timer:expr, $time:expr, $sample:literal ) => {
        #[cfg(feature = "timing")]
        $timers.record(
            $timer,
            $time,
            $sample,
        );
    };
}


