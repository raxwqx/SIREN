mod ui;

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::json;
use siren_core::analyzer::{analyze, bucketize, AnalyzerConfig};
use siren_core::model::DnsEvent;
use siren_core::{eval, gen, pcap, report, summary};
use ui::Ui;

#[derive(Parser)]
#[command(
    name = "siren",
    version,
    about = "SIREN — DNS covert-channel detection, measured.",
    long_about = "SIREN parses DNS traffic, extracts behavioural features, scores each \
                  (client, domain, time window) bucket with explainable signals, and \
                  reports the result as a table, JSON or SARIF."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a PCAP file or a JSONL DNS event log.
    Analyze {
        /// Input .pcap or .jsonl file.
        input: PathBuf,

        /// Time window in seconds.
        #[arg(long, default_value_t = 60.0)]
        window: f64,

        /// Ignore buckets with fewer queries than this.
        #[arg(long, default_value_t = 3)]
        min_queries: usize,

        /// Lowest risk score to report.
        #[arg(long, default_value_t = 12)]
        min_risk: u8,

        /// Output format.
        #[arg(long, value_parser = ["table", "json", "sarif"], default_value = "table")]
        format: String,

        /// File with one allowlisted domain per line.
        #[arg(long)]
        allowlist: Option<PathBuf>,

        /// Show per-signal evidence for every finding.
        #[arg(long)]
        explain: bool,

        /// Do not print the banner.
        #[arg(long)]
        no_banner: bool,

        /// Exit with code 2 if a finding at or above this severity exists.
        #[arg(long, value_parser = ["low", "medium", "high", "critical"])]
        fail_on: Option<String>,
    },

    /// Summarize clients, domains, query types and response codes.
    Summary {
        /// Input .pcap or .jsonl file.
        input: PathBuf,

        /// Rows per endpoint list (clients and domains).
        #[arg(long, default_value_t = 10)]
        top: usize,

        /// Output format.
        #[arg(long, value_parser = ["table", "json"], default_value = "table")]
        format: String,

        /// Do not print the banner.
        #[arg(long)]
        no_banner: bool,
    },

    /// Generate a labeled synthetic dataset for evaluation.
    Gen {
        /// Output JSONL path.
        #[arg(long, default_value = "data/eval.jsonl")]
        out: PathBuf,

        /// Deterministic seed.
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },

    /// Measure precision/recall on a labeled JSONL dataset.
    Eval {
        /// Labeled JSONL produced by `siren gen`.
        input: PathBuf,

        /// Time window in seconds.
        #[arg(long, default_value_t = 60.0)]
        window: f64,

        /// Ignore buckets with fewer queries than this.
        #[arg(long, default_value_t = 3)]
        min_queries: usize,

        /// Machine-readable output.
        #[arg(long)]
        json: bool,

        /// Do not print the banner.
        #[arg(long)]
        no_banner: bool,
    },

    /// List detectors, weights and MITRE mappings.
    Signals {
        /// Do not print the banner.
        #[arg(long)]
        no_banner: bool,
    },
}

fn main() -> ExitCode {
    // Let `siren ... | head` exit cleanly instead of panicking on EPIPE.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();
    let result = match cli.command {
        Command::Analyze {
            input,
            window,
            min_queries,
            min_risk,
            format,
            allowlist,
            explain,
            no_banner,
            fail_on,
        } => run_analyze(
            &input,
            window,
            min_queries,
            min_risk,
            &format,
            allowlist.as_deref(),
            explain,
            no_banner,
            fail_on.as_deref(),
        ),
        Command::Summary {
            input,
            top,
            format,
            no_banner,
        } => run_summary(&input, top, &format, no_banner),
        Command::Gen { out, seed } => run_gen(&out, seed),
        Command::Eval {
            input,
            window,
            min_queries,
            json,
            no_banner,
        } => run_eval(&input, window, min_queries, json, no_banner),
        Command::Signals { no_banner } => {
            run_signals(no_banner);
            Ok(ExitCode::SUCCESS)
        }
    };

    match result {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_analyze(
    input: &Path,
    window: f64,
    min_queries: usize,
    min_risk: u8,
    format: &str,
    allowlist: Option<&Path>,
    explain: bool,
    no_banner: bool,
    fail_on: Option<&str>,
) -> Result<ExitCode, String> {
    validate_window(window)?;
    if min_risk > 100 {
        return Err("--min-risk must be between 0 and 100".into());
    }
    let events = load_events(input)?;
    let allowlist = match allowlist {
        Some(path) => load_allowlist(path)?,
        None => Vec::new(),
    };
    let config = AnalyzerConfig {
        window,
        min_queries,
        min_risk,
        allowlist,
    };
    let findings = analyze(&events, &config);

    if format == "json" {
        let meta = json!({
            "input": input.display().to_string(),
            "window_seconds": window,
            "queries": events.len(),
            "findings": findings.len(),
        });
        println!("{}", report::to_json(&findings, meta));
    } else if format == "sarif" {
        println!("{}", report::to_sarif(&findings));
    } else {
        let ui = Ui::new();
        if !no_banner {
            ui.banner();
        }

        let domains: HashSet<String> = events.iter().map(|e| e.base_domain()).collect();
        let buckets = bucketize(&events, window).len();
        let critical = findings.iter().filter(|f| f.risk >= 60).count();
        let high = findings
            .iter()
            .filter(|f| (40..60).contains(&f.risk))
            .count();

        ui.panel(
            "capture",
            &[
                ("input", input.display().to_string()),
                ("queries", format_number(events.len())),
                ("domains", format_number(domains.len())),
                ("buckets", format_number(buckets)),
                ("window", format!("{window:.0}s")),
                ("suspects", format_number(findings.len())),
                ("critical / high", format!("{critical} / {high}")),
            ],
        );

        ui.section("findings");
        ui.findings_table(&findings);
        if explain {
            ui.section("evidence");
            ui.explain(&findings);
        }
        ui.footer(&findings);
        ui.hint("add --explain for signal-level evidence, --format json|sarif for automation");
        println!();
    }

    if let Some(threshold) = fail_on {
        let threshold_rank = ui::rank(threshold);
        let hit = findings
            .iter()
            .any(|f| ui::rank(f.severity) >= threshold_rank);
        if hit {
            return Ok(ExitCode::from(2));
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn run_summary(
    input: &Path,
    top: usize,
    format: &str,
    no_banner: bool,
) -> Result<ExitCode, String> {
    if !(1..=100).contains(&top) {
        return Err("--top must be between 1 and 100".into());
    }
    let events = load_events(input)?;
    let summary = summary::summarize(&events, top);

    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?
        );
        return Ok(ExitCode::SUCCESS);
    }

    let ui = Ui::new();
    if !no_banner {
        ui.banner();
    }
    ui.summary(&input.display().to_string(), &summary);
    Ok(ExitCode::SUCCESS)
}

fn run_gen(out: &Path, seed: u64) -> Result<ExitCode, String> {
    let events = gen::generate(seed);
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
    }
    let mut file = std::fs::File::create(out).map_err(|e| format!("{}: {e}", out.display()))?;
    for event in &events {
        let line = serde_json::to_string(event).map_err(|e| e.to_string())?;
        writeln!(file, "{line}").map_err(|e| e.to_string())?;
    }
    drop(file);

    let positives = events.iter().filter(|e| e.label == Some(1)).count();
    let ui = Ui::new();
    ui.panel(
        "generated",
        &[
            ("file", out.display().to_string()),
            ("seed", seed.to_string()),
            ("events", format_number(events.len())),
            ("benign", format_number(events.len() - positives)),
            ("malicious", format_number(positives)),
        ],
    );
    ui.hint("next: siren eval data/eval.jsonl");
    println!();
    Ok(ExitCode::SUCCESS)
}

fn run_eval(
    input: &Path,
    window: f64,
    min_queries: usize,
    json_output: bool,
    no_banner: bool,
) -> Result<ExitCode, String> {
    validate_window(window)?;
    let events = load_events(input)?;
    let config = AnalyzerConfig {
        window,
        min_queries,
        min_risk: 0,
        allowlist: Vec::new(),
    };
    let report = eval::evaluate(&events, &config);
    let best = report.best_row();

    if json_output {
        let payload = json!({
            "buckets": report.buckets,
            "positives": report.positives,
            "negatives": report.negatives,
            "best": {
                "threshold": best.threshold,
                "precision": best.precision,
                "recall": best.recall,
                "f1": best.f1,
                "fpr": best.fpr,
                "true_positives": best.tp,
                "false_positives": best.fp,
                "false_negatives": best.false_negatives,
            },
            "sweep": report.rows.iter().map(|row| json!({
                "threshold": row.threshold,
                "precision": row.precision,
                "recall": row.recall,
                "f1": row.f1,
                "fpr": row.fpr,
                "tp": row.tp,
                "fp": row.fp,
                "tn": row.tn,
                "fn": row.false_negatives,
            })).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        return Ok(ExitCode::SUCCESS);
    }

    let ui = Ui::new();
    if !no_banner {
        ui.banner();
    }
    ui.panel(
        "evaluation",
        &[
            ("dataset", input.display().to_string()),
            ("buckets", format_number(report.buckets)),
            ("positives", format_number(report.positives)),
            ("negatives", format_number(report.negatives)),
            ("best threshold", format!("≥ {}", best.threshold)),
            ("precision", format!("{:.3}", best.precision)),
            ("recall", format!("{:.3}", best.recall)),
            ("f1", format!("{:.3}", best.f1)),
            ("false pos. rate", format!("{:.3}", best.fpr)),
        ],
    );
    ui.section("threshold sweep");
    ui.eval_table(&report);
    ui.hint("buckets are (client, registrable domain, window) triples with a ground-truth label");
    println!();
    Ok(ExitCode::SUCCESS)
}

fn run_signals(no_banner: bool) {
    let ui = Ui::new();
    if !no_banner {
        ui.banner();
    }
    ui.section("detectors");
    ui.signals_table();
    ui.hint("risk = 100 × Σ(weight × signal score); one lone signal cannot reach a high verdict");
    println!();
}

fn load_events(path: &Path) -> Result<Vec<DnsEvent>, String> {
    if pcap::is_pcap(path) {
        let events = pcap::events(path)?;
        if events.is_empty() {
            return Err(format!("{}: no DNS events found", path.display()));
        }
        return Ok(events);
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut events = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let event: DnsEvent = serde_json::from_str(line)
            .map_err(|e| format!("{}:{}: {e}", path.display(), index + 1))?;
        events.push(event);
    }
    if events.is_empty() {
        return Err(format!("{}: no DNS events found", path.display()));
    }
    Ok(events)
}

fn load_allowlist(path: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.trim_end_matches('.').to_ascii_lowercase())
        .collect())
}

fn validate_window(window: f64) -> Result<(), String> {
    if !window.is_finite() || window <= 0.0 {
        return Err(format!(
            "--window must be a finite positive number of seconds, got {window}"
        ));
    }
    Ok(())
}

// `is_multiple_of` is newer than our MSRV (1.85), so keep the modulo form.
#[allow(clippy::manual_is_multiple_of)]
fn format_number(value: usize) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}
