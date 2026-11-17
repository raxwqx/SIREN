//! Combines detector signals into a single 0..=100 risk score.

use crate::detect::DETECTORS;
use crate::model::{Features, Signal};

/// Weighted sum of fired signals. A single strong signal cannot reach a high
/// verdict on its own: corroboration is required by construction.
pub fn score(features: &Features) -> (u8, Vec<Signal>, Vec<&'static str>) {
    let mut total = 0.0;
    let mut signals = Vec::new();
    let mut mitre: Vec<&'static str> = Vec::new();

    for detector in DETECTORS {
        if let Some(signal) = (detector.run)(features) {
            total += detector.weight * signal.score;
            for technique in detector.mitre {
                if !mitre.contains(technique) {
                    mitre.push(technique);
                }
            }
            signals.push(signal);
        }
    }

    let risk = (total * 100.0).round().clamp(0.0, 100.0) as u8;
    (risk, signals, mitre)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel() -> Features {
        Features {
            queries: 80,
            qps: 1.33,
            mean_qname_len: 60.0,
            max_label_len: 52,
            mean_label_len: 40.0,
            entropy: 5.2,
            unique_ratio: 1.0,
            responses: 80,
            nxdomain_ratio: 0.6,
            txt_ratio: 0.7,
            encoding_ratio: 1.0,
            interval_cv: 0.1,
            fanout: 80,
        }
    }

    #[test]
    fn tunnel_scores_high() {
        let (risk, signals, mitre) = score(&tunnel());
        assert!(risk >= 55, "risk={risk}");
        assert!(signals.len() >= 5);
        assert!(mitre.contains(&"T1071.004"));
        assert!(mitre.contains(&"T1048"));
    }

    #[test]
    fn benign_scores_low() {
        let f = Features {
            queries: 12,
            qps: 0.2,
            mean_qname_len: 18.0,
            max_label_len: 7,
            mean_label_len: 6.0,
            entropy: 3.1,
            unique_ratio: 0.5,
            responses: 12,
            nxdomain_ratio: 0.0,
            txt_ratio: 0.0,
            encoding_ratio: 0.0,
            interval_cv: 0.7,
            fanout: 3,
        };
        let (risk, signals, _) = score(&f);
        assert!(risk < 12, "risk={risk}");
        assert!(signals.is_empty());
    }

    #[test]
    fn one_signal_alone_stays_low() {
        let f = Features {
            encoding_ratio: 1.0,
            ..Default::default()
        };
        let (risk, _, _) = score(&f);
        assert!(risk < 25, "a lone signal produced {risk}");
    }
}
