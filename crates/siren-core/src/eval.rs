//! Detection-quality evaluation. This is the part that turns SIREN from a
//! heuristic script into a measured detector.

use crate::analyzer::{bucketize, AnalyzerConfig};
use crate::features;
use crate::score;

#[derive(Debug, Clone)]
pub struct ThresholdRow {
    pub threshold: u8,
    pub tp: usize,
    pub fp: usize,
    pub tn: usize,
    pub false_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub fpr: f64,
}

#[derive(Debug, Clone)]
pub struct EvalReport {
    pub rows: Vec<ThresholdRow>,
    pub best: usize,
    pub buckets: usize,
    pub positives: usize,
    pub negatives: usize,
}

impl EvalReport {
    pub fn best_row(&self) -> &ThresholdRow {
        &self.rows[self.best]
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

pub fn evaluate(events: &[crate::model::DnsEvent], config: &AnalyzerConfig) -> EvalReport {
    let scored: Vec<(u8, bool)> = bucketize(events, config.window)
        .into_iter()
        .filter(|bucket| bucket.events.len() >= config.min_queries)
        .map(|bucket| {
            let features = features::compute(&bucket.events, config.window);
            (score::score(&features).0, bucket.is_malicious())
        })
        .collect();

    let positives = scored.iter().filter(|(_, malicious)| *malicious).count();
    let negatives = scored.len() - positives;

    let mut rows = Vec::new();
    for threshold in (0..=100u8).step_by(5) {
        let mut tp = 0;
        let mut fp = 0;
        for (risk, malicious) in &scored {
            let flagged = *risk >= threshold;
            match (*malicious, flagged) {
                (true, true) => tp += 1,
                (false, true) => fp += 1,
                _ => {}
            }
        }
        let false_negatives = positives - tp;
        let tn = negatives - fp;
        let precision = ratio(tp, tp + fp);
        let recall = ratio(tp, tp + false_negatives);
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        rows.push(ThresholdRow {
            threshold,
            tp,
            fp,
            tn,
            false_negatives,
            precision,
            recall,
            f1,
            fpr: ratio(fp, fp + tn),
        });
    }

    let mut best = 0;
    for (index, row) in rows.iter().enumerate() {
        let better = row.f1 > rows[best].f1 + 1e-9
            || ((row.f1 - rows[best].f1).abs() <= 1e-9
                && (row.precision > rows[best].precision + 1e-9
                    || ((row.precision - rows[best].precision).abs() <= 1e-9
                        && row.threshold < rows[best].threshold)));
        if better {
            best = index;
        }
    }

    EvalReport {
        rows,
        best,
        buckets: scored.len(),
        positives,
        negatives,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DnsEvent;

    fn tunnel(client: &str) -> Vec<DnsEvent> {
        (0..80)
            .map(|i| DnsEvent {
                ts: 1_700_000_000.0 + i as f64,
                client: client.into(),
                qname: format!("{:032x}.tunnel.net", i * 2_654_435_761u64),
                qtype: 16,
                rcode: Some(3),
                size: 90,
                label: Some(1),
            })
            .collect()
    }

    fn benign(client: &str) -> Vec<DnsEvent> {
        ["www", "api", "mail", "cdn", "static"]
            .iter()
            .map(|sub| DnsEvent {
                ts: 1_700_000_000.0 + 7.0,
                client: client.into(),
                qname: format!("{sub}.example.com"),
                qtype: 1,
                rcode: Some(0),
                size: 50,
                label: Some(0),
            })
            .collect()
    }

    #[test]
    fn separates_a_tunnel_from_benign_traffic() {
        let mut events = tunnel("10.0.0.1");
        events.extend(benign("10.0.0.2"));
        let report = evaluate(&events, &AnalyzerConfig::default());
        // The tunnel spans 80 s of 1 s-apart queries, i.e. two 60 s buckets.
        assert_eq!(report.buckets, 3);
        assert_eq!(report.positives, 2);
        assert!(report.best_row().recall >= 0.99);
        assert!(report.best_row().fpr <= 0.01);
    }
}
