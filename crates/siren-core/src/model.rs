use serde::{Deserialize, Serialize};

/// One DNS query observed on the wire (or loaded from a JSONL log).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEvent {
    /// Unix timestamp in seconds.
    pub ts: f64,
    /// Client that asked the question.
    pub client: String,
    pub qname: String,
    pub qtype: u16,
    /// Response code, if a matching response was seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcode: Option<u8>,
    /// Size of the DNS payload in bytes.
    #[serde(default)]
    pub size: u32,
    /// Ground-truth label for evaluation sets. `None` on live traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<u8>,
}

impl DnsEvent {
    pub fn base_domain(&self) -> String {
        registrable_domain(&self.qname)
    }
}

/// Single detector output, kept explainable on purpose.
#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub id: &'static str,
    /// Normalized 0.0 ..= 1.0 strength.
    pub score: f64,
    pub detail: String,
}

/// Aggregated verdict for one (client, domain, window) bucket.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub client: String,
    pub domain: String,
    pub window_start: f64,
    pub window_end: f64,
    pub queries: usize,
    pub qps: f64,
    /// 0 ..= 100.
    pub risk: u8,
    pub severity: &'static str,
    pub mitre: Vec<&'static str>,
    pub signals: Vec<Signal>,
    pub features: Features,
}

/// Behavioral features extracted from one bucket.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Features {
    pub queries: usize,
    pub qps: f64,
    pub mean_qname_len: f64,
    pub max_label_len: usize,
    pub mean_label_len: f64,
    /// Mean Shannon entropy (bits/char) of the variable label.
    pub entropy: f64,
    pub unique_ratio: f64,
    /// Number of queries with a matched response (`rcode` is known).
    #[serde(default)]
    pub responses: usize,
    pub nxdomain_ratio: f64,
    pub txt_ratio: f64,
    /// Share of variable labels that look hex / base32 / base64.
    pub encoding_ratio: f64,
    /// Coefficient of variation of inter-arrival times. Low = beaconing.
    pub interval_cv: f64,
    /// Distinct variable labels seen for this domain.
    pub fanout: usize,
}

pub fn severity_for(risk: u8) -> &'static str {
    match risk {
        60..=100 => "critical",
        40..=59 => "high",
        25..=39 => "medium",
        12..=24 => "low",
        _ => "info",
    }
}

/// Public suffixes that force a three-label registrable domain.
/// Deliberately small: a full PSL parser is on the roadmap, not in the hot path.
const MULTI_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "com.tr", "net.tr", "org.tr",
    "gen.tr", "bel.tr", "edu.tr", "gov.tr", "co.jp", "ne.jp", "or.jp", "com.au", "net.au",
    "org.au", "co.nz", "co.in", "co.za", "co.kr", "com.br", "com.cn", "com.mx", "com.ar", "com.sg",
    "com.hk", "com.tw", "co.il",
];

/// Best-effort registrable domain (`a.b.example.co.uk` -> `example.co.uk`).
pub fn registrable_domain(qname: &str) -> String {
    let name = qname.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return name;
    }
    let tail = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if MULTI_SUFFIXES.contains(&tail.as_str()) && labels.len() >= 3 {
        return format!("{}.{}", labels[labels.len() - 3], tail);
    }
    tail
}

/// The part of the name the client controls: everything left of the
/// registrable domain. Falls back to the leftmost label for apex queries.
pub fn variable_part(qname: &str) -> String {
    let name = qname.trim_end_matches('.').to_ascii_lowercase();
    let base = registrable_domain(&name);
    if let Some(prefix) = name.strip_suffix(&base) {
        let v = prefix.trim_end_matches('.');
        if !v.is_empty() {
            return v.to_string();
        }
    }
    name.split('.').next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_handles_multi_part_suffixes() {
        assert_eq!(registrable_domain("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("mail.google.com"), "google.com");
        assert_eq!(registrable_domain("example.com."), "example.com");
        assert_eq!(registrable_domain("localhost"), "localhost");
    }

    #[test]
    fn variable_part_strips_the_base_domain() {
        assert_eq!(
            variable_part("k3j4h5g6.tunnel.example.com"),
            "k3j4h5g6.tunnel"
        );
        assert_eq!(variable_part("www.google.com"), "www");
        assert_eq!(variable_part("google.com"), "google");
    }

    #[test]
    fn severity_buckets_are_monotonic() {
        assert_eq!(severity_for(100), "critical");
        assert_eq!(severity_for(40), "high");
        assert_eq!(severity_for(25), "medium");
        assert_eq!(severity_for(12), "low");
        assert_eq!(severity_for(0), "info");
    }
}
