//! Machine-readable output: JSON and SARIF 2.1.0.

use serde_json::{json, Value};

use crate::detect::DETECTORS;
use crate::model::Finding;

pub fn to_json(findings: &[Finding], meta: Value) -> String {
    let payload = json!({
        "tool": "siren",
        "version": env!("CARGO_PKG_VERSION"),
        "meta": meta,
        "findings": findings,
    });
    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".into())
}

pub fn sarif_rules() -> Value {
    Value::Array(
        DETECTORS
            .iter()
            .map(|detector| {
                json!({
                    "id": detector.id,
                    "name": detector.name,
                    "shortDescription": { "text": detector.description },
                    "properties": {
                        "weight": detector.weight,
                        "mitre": detector.mitre,
                    }
                })
            })
            .collect(),
    )
}

pub fn to_sarif(findings: &[Finding]) -> String {
    let results: Vec<Value> = findings
        .iter()
        .map(|finding| {
            let level = match finding.severity {
                "critical" | "high" => "error",
                "medium" => "warning",
                _ => "note",
            };
            json!({
                "ruleId": "siren.dns-tunnel",
                "level": level,
                "message": {
                    "text": format!(
                        "{} possible DNS covert channel from {}: risk {} ({}), signals: {}",
                        finding.severity,
                        finding.client,
                        finding.risk,
                        finding.domain,
                        finding
                            .signals
                            .iter()
                            .map(|s| s.id)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": format!("dns://{}/{}", finding.client, finding.domain) }
                    }
                }],
                "properties": {
                    "client": finding.client,
                    "domain": finding.domain,
                    "risk": finding.risk,
                    "mitre": finding.mitre,
                    "signals": finding.signals.iter().map(|s| s.id).collect::<Vec<_>>(),
                }
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SIREN",
                    "informationUri": "https://github.com/raxwqx/SIREN",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": sarif_rules()
                }
            },
            "results": results
        }]
    });
    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".into())
}
