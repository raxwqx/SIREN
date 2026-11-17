//! Detectors. Each one is a pure function over `Features`, so it can be unit
//! tested and explained independently.

use crate::model::{Features, Signal};

pub struct Detector {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub weight: f64,
    pub mitre: &'static [&'static str],
    pub run: fn(&Features) -> Option<Signal>,
}

/// Signals fire only above these thresholds. Kept as constants so the README,
/// the tests and the code cannot drift apart silently.
pub const ENTROPY_MIN: f64 = 4.3;
pub const LABEL_LEN_MIN: usize = 20;
pub const QPS_MIN: f64 = 0.3;
pub const NXDOMAIN_MIN: f64 = 0.25;
/// A single NXDOMAIN answer out of a hundred queries must not read as 100%.
pub const NXDOMAIN_MIN_RESPONSES: usize = 3;
pub const TXT_RATIO_MIN: f64 = 0.30;
pub const ENCODING_MIN: f64 = 0.20;
pub const BEACON_CV_MAX: f64 = 0.35;
pub const FANOUT_MIN: usize = 20;

pub const DETECTORS: &[Detector] = &[
    Detector {
        id: "entropy",
        name: "High label entropy",
        description: "Variable labels carry near-random data (base64/base32 payloads).",
        weight: 0.20,
        mitre: &["T1001"],
        run: entropy,
    },
    Detector {
        id: "label-length",
        name: "Long labels",
        description: "Labels far longer than human-readable hostnames.",
        weight: 0.16,
        mitre: &["T1071.004"],
        run: label_length,
    },
    Detector {
        id: "query-rate",
        name: "Sustained query rate",
        description: "Queries per second above normal client behaviour for one domain.",
        weight: 0.18,
        mitre: &["T1048"],
        run: query_rate,
    },
    Detector {
        id: "nxdomain",
        name: "NXDOMAIN ratio",
        description: "Many answers do not exist, typical of polling tunnels and DGA.",
        weight: 0.11,
        mitre: &["T1568.002"],
        run: nxdomain,
    },
    Detector {
        id: "qtype",
        name: "Unusual record types",
        description: "TXT/NULL-heavy traffic used to smuggle payloads.",
        weight: 0.09,
        mitre: &["T1071.004"],
        run: qtype,
    },
    Detector {
        id: "encoding",
        name: "Encoded labels",
        description: "Labels match hex / base32 / base64 alphabets.",
        weight: 0.15,
        mitre: &["T1001"],
        run: encoding,
    },
    Detector {
        id: "beaconing",
        name: "Periodic timing",
        description: "Inter-arrival times are too regular; looks like a beacon.",
        weight: 0.07,
        mitre: &["T1071.004"],
        run: beaconing,
    },
    Detector {
        id: "fanout",
        name: "Subdomain fanout",
        description: "Many distinct labels under one domain in a short window.",
        weight: 0.04,
        mitre: &["T1568.002"],
        run: fanout,
    },
];

fn entropy(f: &Features) -> Option<Signal> {
    if f.entropy <= ENTROPY_MIN {
        return None;
    }
    let score = ((f.entropy - ENTROPY_MIN) / 1.7).clamp(0.0, 1.0);
    Some(Signal {
        id: "entropy",
        score,
        detail: format!(
            "mean label entropy {:.2} bits/char (normal < {ENTROPY_MIN})",
            f.entropy
        ),
    })
}

fn label_length(f: &Features) -> Option<Signal> {
    if f.max_label_len <= LABEL_LEN_MIN {
        return None;
    }
    let score = ((f.max_label_len - LABEL_LEN_MIN) as f64 / 40.0).clamp(0.0, 1.0);
    Some(Signal {
        id: "label-length",
        score,
        detail: format!(
            "longest label {} chars (normal <= {LABEL_LEN_MIN})",
            f.max_label_len
        ),
    })
}

fn query_rate(f: &Features) -> Option<Signal> {
    if f.qps <= QPS_MIN {
        return None;
    }
    let score = ((f.qps - QPS_MIN) / 4.0).clamp(0.0, 1.0);
    Some(Signal {
        id: "query-rate",
        score,
        detail: format!("{:.2} q/s for one domain (baseline < {QPS_MIN})", f.qps),
    })
}

fn nxdomain(f: &Features) -> Option<Signal> {
    if f.responses < NXDOMAIN_MIN_RESPONSES || f.nxdomain_ratio <= NXDOMAIN_MIN {
        return None;
    }
    let score = ((f.nxdomain_ratio - NXDOMAIN_MIN) / 0.6).clamp(0.0, 1.0);
    Some(Signal {
        id: "nxdomain",
        score,
        detail: format!(
            "{:.0}% NXDOMAIN across {} responses (normal < {:.0}%)",
            f.nxdomain_ratio * 100.0,
            f.responses,
            NXDOMAIN_MIN * 100.0
        ),
    })
}

fn qtype(f: &Features) -> Option<Signal> {
    if f.txt_ratio <= TXT_RATIO_MIN {
        return None;
    }
    let score = ((f.txt_ratio - TXT_RATIO_MIN) / 0.7).clamp(0.0, 1.0);
    Some(Signal {
        id: "qtype",
        score,
        detail: format!(
            "{:.0}% TXT queries (normal < {:.0}%)",
            f.txt_ratio * 100.0,
            TXT_RATIO_MIN * 100.0
        ),
    })
}

fn encoding(f: &Features) -> Option<Signal> {
    if f.encoding_ratio <= ENCODING_MIN {
        return None;
    }
    let score = ((f.encoding_ratio - ENCODING_MIN) / 0.8).clamp(0.0, 1.0);
    Some(Signal {
        id: "encoding",
        score,
        detail: format!(
            "{:.0}% of labels look encoded (hex/base32/base64)",
            f.encoding_ratio * 100.0
        ),
    })
}

fn beaconing(f: &Features) -> Option<Signal> {
    if f.queries < 6 || f.interval_cv >= BEACON_CV_MAX {
        return None;
    }
    let score = ((BEACON_CV_MAX - f.interval_cv) / BEACON_CV_MAX).clamp(0.0, 1.0);
    Some(Signal {
        id: "beaconing",
        score,
        detail: format!(
            "inter-arrival CV {:.2} (periodic < {BEACON_CV_MAX})",
            f.interval_cv
        ),
    })
}

fn fanout(f: &Features) -> Option<Signal> {
    if f.fanout < FANOUT_MIN {
        return None;
    }
    let score = ((f.fanout - FANOUT_MIN) as f64 / 200.0).clamp(0.0, 1.0);
    Some(Signal {
        id: "fanout",
        score,
        detail: format!("{} distinct labels under one domain", f.fanout),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Features {
        Features {
            queries: 10,
            qps: 0.1,
            mean_qname_len: 20.0,
            max_label_len: 10,
            mean_label_len: 8.0,
            entropy: 3.0,
            unique_ratio: 0.8,
            responses: 10,
            nxdomain_ratio: 0.0,
            txt_ratio: 0.0,
            encoding_ratio: 0.0,
            interval_cv: 0.9,
            fanout: 5,
        }
    }

    #[test]
    fn quiet_traffic_fires_nothing() {
        let f = base();
        for detector in DETECTORS {
            assert!(
                (detector.run)(&f).is_none(),
                "{} fired unexpectedly",
                detector.id
            );
        }
    }

    #[test]
    fn each_detector_fires_on_its_signal() {
        let mut f = base();
        f.entropy = 6.0;
        assert!((entropy)(&f).is_some());
        f = base();
        f.max_label_len = 50;
        assert!((label_length)(&f).is_some());
        f = base();
        f.qps = 5.0;
        assert!((query_rate)(&f).is_some());
        f = base();
        f.nxdomain_ratio = 0.9;
        assert!((nxdomain)(&f).is_some());
        f = base();
        f.txt_ratio = 0.9;
        assert!((qtype)(&f).is_some());
        f = base();
        f.encoding_ratio = 1.0;
        assert!((encoding)(&f).is_some());
        f = base();
        f.queries = 20;
        f.interval_cv = 0.01;
        assert!((beaconing)(&f).is_some());
        f = base();
        f.fanout = 100;
        assert!((fanout)(&f).is_some());
    }

    #[test]
    fn nxdomain_needs_more_than_one_answer() {
        let mut f = base();
        f.responses = 1;
        f.nxdomain_ratio = 1.0;
        assert!((nxdomain)(&f).is_none());
        f.responses = NXDOMAIN_MIN_RESPONSES;
        assert!((nxdomain)(&f).is_some());
    }

    #[test]
    fn weights_sum_to_one() {
        let sum: f64 = DETECTORS.iter().map(|d| d.weight).sum();
        assert!((sum - 1.0).abs() < 1e-9, "weights sum to {sum}");
    }
}
