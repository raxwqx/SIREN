//! Bucketing and analysis: from a flat event stream to ranked findings.

use std::collections::HashMap;

use crate::features;
use crate::model::{severity_for, DnsEvent, Finding};
use crate::score;

#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    pub window: f64,
    pub min_queries: usize,
    pub min_risk: u8,
    pub allowlist: Vec<String>,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            window: 60.0,
            min_queries: 3,
            min_risk: 12,
            allowlist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Bucket {
    pub client: String,
    pub domain: String,
    pub index: i64,
    pub events: Vec<DnsEvent>,
}

impl Bucket {
    pub fn start(&self, window: f64) -> f64 {
        self.index as f64 * window
    }

    pub fn end(&self, window: f64) -> f64 {
        (self.index + 1) as f64 * window
    }

    pub fn is_malicious(&self) -> bool {
        self.events.iter().any(|e| e.label == Some(1))
    }
}

/// Group events by (client, registrable domain, fixed time bucket).
/// Output order is deterministic so evaluation is reproducible.
pub fn bucketize(events: &[DnsEvent], window: f64) -> Vec<Bucket> {
    let mut groups: HashMap<(String, String, i64), Vec<DnsEvent>> = HashMap::new();
    for event in events {
        let bucket = (event.ts / window).floor() as i64;
        groups
            .entry((event.client.clone(), event.base_domain(), bucket))
            .or_default()
            .push(event.clone());
    }

    let mut buckets: Vec<Bucket> = groups
        .into_iter()
        .map(|((client, domain, index), events)| Bucket {
            client,
            domain,
            index,
            events,
        })
        .collect();
    buckets.sort_by(|a, b| {
        a.client
            .cmp(&b.client)
            .then_with(|| a.domain.cmp(&b.domain))
            .then_with(|| a.index.cmp(&b.index))
    });
    buckets
}

pub fn analyze(events: &[DnsEvent], config: &AnalyzerConfig) -> Vec<Finding> {
    let mut findings = Vec::new();

    for bucket in bucketize(events, config.window) {
        if bucket.events.len() < config.min_queries {
            continue;
        }
        if is_allowlisted(&bucket.domain, &config.allowlist) {
            continue;
        }

        let features = features::compute(&bucket.events, config.window);
        let (risk, signals, mitre) = score::score(&features);
        if risk < config.min_risk {
            continue;
        }

        findings.push(Finding {
            client: bucket.client.clone(),
            domain: bucket.domain.clone(),
            window_start: bucket.start(config.window),
            window_end: bucket.end(config.window),
            queries: features.queries,
            qps: features.qps,
            risk,
            severity: severity_for(risk),
            mitre,
            signals,
            features,
        });
    }

    findings.sort_by(|a, b| {
        b.risk
            .cmp(&a.risk)
            .then_with(|| b.queries.cmp(&a.queries))
            .then_with(|| a.client.cmp(&b.client))
            .then_with(|| a.domain.cmp(&b.domain))
    });
    findings
}

pub fn is_allowlisted(domain: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|entry| {
        let entry = entry.trim_end_matches('.');
        domain == entry || domain.ends_with(&format!(".{entry}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(ts: f64, client: &str, qname: &str) -> DnsEvent {
        DnsEvent {
            ts,
            client: client.into(),
            qname: qname.into(),
            qtype: 1,
            rcode: Some(0),
            size: 50,
            label: None,
        }
    }

    #[test]
    fn buckets_by_client_domain_and_time() {
        let events = vec![
            event(0.0, "10.0.0.1", "a.example.com"),
            event(30.0, "10.0.0.1", "b.example.com"),
            event(70.0, "10.0.0.1", "c.example.com"),
            event(10.0, "10.0.0.2", "a.example.com"),
        ];
        let buckets = bucketize(&events, 60.0);
        assert_eq!(buckets.len(), 3);
        assert_eq!(buckets[0].events.len(), 2);
        assert_eq!(buckets[0].domain, "example.com");
    }

    #[test]
    fn allowlist_matches_subdomains() {
        let list = vec!["github.com".to_string()];
        assert!(is_allowlisted("github.com", &list));
        assert!(is_allowlisted("api.github.com", &list));
        assert!(!is_allowlisted("notgithub.com", &list));
    }
}
