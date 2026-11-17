//! Capture-level summary: who talked, to which domains, and with what.
//!
//! This is deliberately independent from detection: it answers "what is in
//! this capture?" before (or after) asking "is anything malicious?".

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::model::DnsEvent;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Count {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub queries: usize,
    /// Queries with a correlated response (`rcode` known).
    pub responses: usize,
    pub clients: usize,
    pub domains: usize,
    pub unique_qnames: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_ts: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ts: Option<f64>,
    pub duration_seconds: f64,
    pub qtypes: Vec<Count>,
    pub rcodes: Vec<Count>,
    pub top_clients: Vec<Count>,
    pub top_domains: Vec<Count>,
}

fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        35 => "NAPTR".into(),
        43 => "DS".into(),
        46 => "RRSIG".into(),
        48 => "DNSKEY".into(),
        52 => "TLSA".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        99 => "SPF".into(),
        252 => "AXFR".into(),
        255 => "ANY".into(),
        257 => "CAA".into(),
        other => format!("TYPE{other}"),
    }
}

fn rcode_name(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        6 => "YXDOMAIN".into(),
        7 => "YXRRSET".into(),
        8 => "NXRRSET".into(),
        9 => "NOTAUTH".into(),
        10 => "NOTZONE".into(),
        16 => "BADVERS".into(),
        other => format!("RCODE{other}"),
    }
}

fn ranked(entries: HashMap<String, usize>, limit: usize) -> Vec<Count> {
    let mut rows: Vec<Count> = entries
        .into_iter()
        .map(|(name, count)| Count { name, count })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    rows.truncate(limit);
    rows
}

fn rank_mapped<K>(map: HashMap<K, usize>, limit: usize, name: fn(K) -> String) -> Vec<Count>
where
    K: Eq + std::hash::Hash + Copy,
{
    let mut named = HashMap::with_capacity(map.len());
    for (key, count) in map {
        named.insert(name(key), count);
    }
    ranked(named, limit)
}

/// Summarize a flat event stream. `top` is the maximum number of rows in each
/// endpoint list; qtype and rcode distributions are always complete.
pub fn summarize(events: &[DnsEvent], top: usize) -> Summary {
    let mut clients: HashMap<String, usize> = HashMap::new();
    let mut domains: HashMap<String, usize> = HashMap::new();
    let mut qtypes: HashMap<u16, usize> = HashMap::new();
    let mut rcodes: HashMap<u8, usize> = HashMap::new();
    let mut qnames: HashSet<String> = HashSet::new();
    let mut responses = 0usize;
    let mut first_ts: Option<f64> = None;
    let mut last_ts: Option<f64> = None;

    for event in events {
        *clients.entry(event.client.clone()).or_default() += 1;
        *domains.entry(event.base_domain()).or_default() += 1;
        *qtypes.entry(event.qtype).or_default() += 1;
        if let Some(rcode) = event.rcode {
            *rcodes.entry(rcode).or_default() += 1;
            responses += 1;
        }
        qnames.insert(event.qname.trim_end_matches('.').to_ascii_lowercase());
        if event.ts.is_finite() {
            first_ts = Some(first_ts.map_or(event.ts, |value| value.min(event.ts)));
            last_ts = Some(last_ts.map_or(event.ts, |value| value.max(event.ts)));
        }
    }

    let duration_seconds = match (first_ts, last_ts) {
        (Some(first), Some(last)) => (last - first).max(0.0),
        _ => 0.0,
    };

    Summary {
        queries: events.len(),
        responses,
        clients: clients.len(),
        domains: domains.len(),
        unique_qnames: qnames.len(),
        first_ts,
        last_ts,
        duration_seconds,
        qtypes: rank_mapped(qtypes, usize::MAX, qtype_name),
        rcodes: rank_mapped(rcodes, usize::MAX, rcode_name),
        top_clients: ranked(clients, top),
        top_domains: ranked(domains, top),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(ts: f64, client: &str, qname: &str, qtype: u16, rcode: Option<u8>) -> DnsEvent {
        DnsEvent {
            ts,
            client: client.into(),
            qname: qname.into(),
            qtype,
            rcode,
            size: 50,
            label: None,
        }
    }

    #[test]
    fn counts_endpoints_types_and_rcodes() {
        let events = vec![
            event(10.0, "10.0.0.2", "a.example.com", 1, Some(0)),
            event(20.0, "10.0.0.1", "b.example.com", 16, Some(3)),
            event(30.0, "10.0.0.1", "c.example.com", 16, None),
            event(40.0, "10.0.0.1", "d.tunnel.net", 28, Some(0)),
        ];
        let summary = summarize(&events, 10);

        assert_eq!(summary.queries, 4);
        assert_eq!(summary.responses, 3);
        assert_eq!(summary.clients, 2);
        assert_eq!(summary.domains, 2);
        assert_eq!(summary.unique_qnames, 4);
        assert_eq!(summary.first_ts, Some(10.0));
        assert_eq!(summary.last_ts, Some(40.0));
        assert_eq!(summary.duration_seconds, 30.0);
        assert_eq!(summary.top_clients[0].name, "10.0.0.1");
        assert_eq!(summary.top_clients[0].count, 3);
        assert_eq!(summary.top_domains[0].name, "example.com");
        assert_eq!(summary.top_domains[0].count, 3);
        assert_eq!(
            summary.qtypes[0],
            Count {
                name: "TXT".into(),
                count: 2
            }
        );
        assert_eq!(
            summary.rcodes.iter().find(|r| r.name == "NXDOMAIN"),
            Some(&Count {
                name: "NXDOMAIN".into(),
                count: 1
            })
        );
    }

    #[test]
    fn top_list_is_sorted_and_truncated() {
        let events: Vec<_> = (0..10)
            .map(|i| event(i as f64, &format!("10.0.0.{i}"), "example.com", 1, Some(0)))
            .collect();
        let summary = summarize(&events, 3);
        assert_eq!(summary.clients, 10);
        assert_eq!(summary.top_clients.len(), 3);
        assert_eq!(summary.top_clients[0].name, "10.0.0.0");
        assert_eq!(summary.top_domains.len(), 1);
    }

    #[test]
    fn empty_input_is_empty_not_a_panic() {
        let summary = summarize(&[], 5);
        assert_eq!(summary.queries, 0);
        assert_eq!(summary.responses, 0);
        assert_eq!(summary.clients, 0);
        assert!(summary.top_clients.is_empty());
        assert!(summary.qtypes.is_empty());
        assert_eq!(summary.first_ts, None);
        assert_eq!(summary.duration_seconds, 0.0);
    }
}
