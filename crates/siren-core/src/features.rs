//! Feature extraction over one (client, domain, window) bucket.

use std::collections::HashSet;

use crate::model::{variable_part, DnsEvent, Features};

/// Shannon entropy in bits per character.
pub fn shannon(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn is_hex(s: &str) -> bool {
    s.len() >= 8 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_base32(s: &str) -> bool {
    s.len() >= 8
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
}

fn is_base64ish(s: &str) -> bool {
    s.len() >= 16
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        && s.bytes().any(|b| b.is_ascii_uppercase())
        && s.bytes().any(|b| b.is_ascii_digit())
}

/// True when a label looks like a machine-encoded blob rather than a word.
pub fn looks_encoded(s: &str) -> bool {
    is_hex(s) || is_base32(s) || is_base64ish(s)
}

fn coefficient_of_variation(times: &mut [f64]) -> f64 {
    if times.len() < 3 {
        return 1.0;
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let diffs: Vec<f64> = times.windows(2).map(|w| w[1] - w[0]).collect();
    let n = diffs.len() as f64;
    let mean = diffs.iter().sum::<f64>() / n;
    if mean <= 1e-9 {
        return 1.0;
    }
    let var = diffs.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / n;
    var.sqrt() / mean
}

pub fn compute(events: &[DnsEvent], window: f64) -> Features {
    let n = events.len();
    if n == 0 {
        return Features::default();
    }

    let mut qname_len = 0usize;
    let mut max_label_len = 0usize;
    let mut label_len_sum = 0usize;
    let mut label_count = 0usize;
    let mut entropy_sum = 0.0;
    let mut unique_qnames = HashSet::new();
    let mut rcode_seen = 0usize;
    let mut nxdomain = 0usize;
    let mut txt = 0usize;
    let mut encoded = 0usize;
    let mut variables = HashSet::new();
    let mut times = Vec::with_capacity(n);

    for event in events {
        let qname = event.qname.trim_end_matches('.').to_ascii_lowercase();
        qname_len += qname.len();

        for label in qname.split('.').filter(|l| !l.is_empty()) {
            max_label_len = max_label_len.max(label.len());
            label_len_sum += label.len();
            label_count += 1;
        }

        unique_qnames.insert(qname.clone());

        if let Some(rcode) = event.rcode {
            rcode_seen += 1;
            if rcode == 3 {
                nxdomain += 1;
            }
        }
        if event.qtype == 16 {
            txt += 1;
        }

        let variable = variable_part(&qname);
        entropy_sum += shannon(&variable);
        // Tunnels often split the payload across labels; one encoded label is
        // enough to mark the query.
        if variable.split('.').any(looks_encoded) {
            encoded += 1;
        }
        variables.insert(variable);
        times.push(event.ts);
    }

    Features {
        queries: n,
        qps: n as f64 / window,
        mean_qname_len: qname_len as f64 / n as f64,
        max_label_len,
        mean_label_len: label_len_sum as f64 / label_count.max(1) as f64,
        entropy: entropy_sum / n as f64,
        unique_ratio: unique_qnames.len() as f64 / n as f64,
        nxdomain_ratio: if rcode_seen > 0 {
            nxdomain as f64 / rcode_seen as f64
        } else {
            0.0
        },
        txt_ratio: txt as f64 / n as f64,
        encoding_ratio: encoded as f64 / n as f64,
        interval_cv: coefficient_of_variation(&mut times),
        fanout: variables.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_matches_known_values() {
        assert!((shannon("aaaa") - 0.0).abs() < 1e-9);
        assert!((shannon("ab") - 1.0).abs() < 1e-9);
        assert!((shannon("abcd") - 2.0).abs() < 1e-9);
        assert!((shannon("0123456789abcdef") - 4.0).abs() < 1e-9);
    }

    #[test]
    fn detects_encodings() {
        assert!(looks_encoded("d41d8cd98f00b204"));
        assert!(looks_encoded("MZXW6YTBONSWG3DF"));
        assert!(looks_encoded("SGVsbG8gV29ybGQhMTIz"));
        assert!(!looks_encoded("www"));
        assert!(!looks_encoded("api-v2"));
    }

    fn event(ts: f64, name: &str, qtype: u16, rcode: Option<u8>) -> DnsEvent {
        DnsEvent {
            ts,
            client: "10.0.0.5".into(),
            qname: name.into(),
            qtype,
            rcode,
            size: 60,
            label: None,
        }
    }

    #[test]
    fn beaconing_has_low_variation() {
        let events: Vec<_> = (0..10)
            .map(|i| event(i as f64 * 2.0, "a.example.com", 1, Some(0)))
            .collect();
        let f = compute(&events, 60.0);
        assert!(f.interval_cv < 0.01, "cv={}", f.interval_cv);
    }

    #[test]
    fn random_timing_has_high_variation() {
        let ts = [0.0, 1.0, 9.0, 10.5, 20.0, 31.0, 47.0];
        let events: Vec<_> = ts
            .iter()
            .map(|t| event(*t, "a.example.com", 1, Some(0)))
            .collect();
        let f = compute(&events, 60.0);
        assert!(f.interval_cv > 0.35, "cv={}", f.interval_cv);
    }

    #[test]
    fn ratios_are_computed() {
        let events = vec![
            event(0.0, "x.tunnel.net", 16, Some(3)),
            event(1.0, "y.tunnel.net", 1, Some(0)),
            event(2.0, "z.tunnel.net", 16, None),
        ];
        let f = compute(&events, 60.0);
        assert_eq!(f.queries, 3);
        assert!((f.txt_ratio - 2.0 / 3.0).abs() < 1e-9);
        assert!((f.nxdomain_ratio - 0.5).abs() < 1e-9);
    }
}
