//! SIREN core: DNS parsing, feature extraction, detectors and scoring.
//!
//! The pipeline is intentionally split so every stage is testable in isolation:
//!
//! ```text
//! bytes  ->  dns::parse   ->  DnsEvent
//! events ->  analyzer     ->  Bucket (client, domain, time window)
//! bucket ->  features     ->  Features
//! feats  ->  score        ->  Finding (risk, signals, MITRE)
//! ```

pub mod analyzer;
pub mod detect;
pub mod dns;
pub mod eval;
pub mod features;
pub mod gen;
pub mod model;
pub mod pcap;
pub mod report;
pub mod score;
pub mod time;

pub use analyzer::{analyze, bucketize, AnalyzerConfig, Bucket};
pub use model::{severity_for, DnsEvent, Features, Finding, Signal};
