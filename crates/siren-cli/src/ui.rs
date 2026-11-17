//! Terminal presentation. Everything degrades to plain text when stdout is
//! not a TTY, so pipes and CI logs stay clean.

use crossterm::style::{Color, Stylize};
use crossterm::terminal;
use siren_core::detect::DETECTORS;
use siren_core::eval::EvalReport;
use siren_core::model::Finding;
use siren_core::summary::{Count, Summary};
use siren_core::time::fmt_epoch;

const RED: Color = Color::Rgb {
    r: 255,
    g: 72,
    b: 102,
};
const BLUE: Color = Color::Rgb {
    r: 88,
    g: 166,
    b: 255,
};
const GREEN: Color = Color::Rgb {
    r: 96,
    g: 220,
    b: 156,
};
const YELLOW: Color = Color::Rgb {
    r: 245,
    g: 202,
    b: 84,
};
const ORANGE: Color = Color::Rgb {
    r: 255,
    g: 146,
    b: 72,
};
const MUTED: Color = Color::Rgb {
    r: 122,
    g: 132,
    b: 152,
};

const BANNER: [&str; 6] = [
    "███████╗██╗██████╗ ███████╗███╗   ██╗",
    "██╔════╝██║██╔══██╗██╔════╝████╗  ██║",
    "███████╗██║██████╔╝█████╗  ██╔██╗ ██║",
    "╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║",
    "███████║██║██║  ██║███████╗██║ ╚████║",
    "╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝",
];

pub struct Ui {
    color: bool,
}

impl Ui {
    pub fn new() -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        Self {
            color: std::io::IsTerminal::is_terminal(&std::io::stdout()) && !no_color,
        }
    }

    fn paint(&self, text: &str, color: Color) -> String {
        if self.color {
            format!("{}", text.with(color))
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: &str, color: Color) -> String {
        if self.color {
            format!("{}", text.with(color).bold())
        } else {
            text.to_string()
        }
    }

    fn dim(&self, text: &str) -> String {
        self.paint(text, MUTED)
    }

    fn width(&self) -> usize {
        terminal::size()
            .ok()
            .map(|(w, _)| w as usize)
            .filter(|w| *w >= 40)
            .unwrap_or(100)
    }

    pub fn banner(&self) {
        println!();
        for (index, line) in BANNER.iter().enumerate() {
            let t = index as f64 / (BANNER.len() - 1) as f64;
            let color = mix(RED, BLUE, t);
            println!("  {}", self.paint(line, color));
        }
        println!(
            "  {}",
            self.dim("DNS covert channels, measured.  ·  github.com/raxwqx/SIREN")
        );
        println!();
    }

    pub fn panel(&self, title: &str, rows: &[(&str, String)]) {
        let label = format!("─ {title} ");
        let pad = 60usize.saturating_sub(label.chars().count());
        println!(
            "{}{}{}",
            self.paint("╭", BLUE),
            self.paint(&format!("{label}{}", "─".repeat(pad)), BLUE),
            self.paint("╮", BLUE)
        );
        for (key, value) in rows {
            // Pad before colouring: ANSI escapes are zero-width, so a width
            // spec applied to an already-coloured string collapses the column.
            println!(
                "{} {} {} {}",
                self.paint("│", BLUE),
                self.dim(&cell(key, 17)),
                cell(value, 40),
                self.paint("│", BLUE)
            );
        }
        println!(
            "{}{}{}",
            self.paint("╰", BLUE),
            self.paint(&"─".repeat(60), BLUE),
            self.paint("╯", BLUE)
        );
        println!();
    }

    pub fn section(&self, title: &str) {
        println!();
        println!("  {}", self.bold(title, BLUE));
    }

    pub fn findings_table(&self, findings: &[Finding]) {
        if findings.is_empty() {
            println!(
                "  {}",
                self.paint("No covert channels above the threshold. Clean.", GREEN)
            );
            return;
        }

        let width = self.width();
        let show_client = width >= 84;
        let show_signals = width >= 108;

        let header = if show_signals {
            format!(
                "  {:>4} {:<8} {:<15} {:<24} {:>6} {:>6}  {}",
                "RISK", "SEVERITY", "CLIENT", "DOMAIN", "QPS", "ENT", "SIGNALS"
            )
        } else if show_client {
            format!(
                "  {:>4} {:<8} {:<15} {:<30} {:>6} {:>6}",
                "RISK", "SEVERITY", "CLIENT", "DOMAIN", "QPS", "ENT"
            )
        } else {
            format!(
                "  {:>4} {:<8} {:<34} {:>6} {:>6}",
                "RISK", "SEVERITY", "DOMAIN", "QPS", "ENT"
            )
        };
        println!("{}", self.dim(&header));

        for finding in findings {
            let risk = format!("{:>4}", finding.risk);
            let severity = format!("{:<8}", finding.severity);
            let color = severity_color(finding.severity);
            let signals = finding
                .signals
                .iter()
                .map(|s| s.id)
                .collect::<Vec<_>>()
                .join(",");

            let line = if show_signals {
                format!(
                    "  {} {} {:<15} {:<24} {:>6.2} {:>6.2}  {}",
                    self.bold(&risk, color),
                    self.paint(&severity, color),
                    truncate(&finding.client, 15),
                    truncate(&finding.domain, 24),
                    finding.qps,
                    finding.features.entropy,
                    self.paint(&signals, MUTED)
                )
            } else if show_client {
                format!(
                    "  {} {} {:<15} {:<30} {:>6.2} {:>6.2}",
                    self.bold(&risk, color),
                    self.paint(&severity, color),
                    truncate(&finding.client, 15),
                    truncate(&finding.domain, 30),
                    finding.qps,
                    finding.features.entropy
                )
            } else {
                format!(
                    "  {} {} {:<34} {:>6.2} {:>6.2}",
                    self.bold(&risk, color),
                    self.paint(&severity, color),
                    truncate(&finding.domain, 34),
                    finding.qps,
                    finding.features.entropy
                )
            };
            println!("{line}");
        }
    }

    pub fn explain(&self, findings: &[Finding]) {
        for finding in findings {
            println!();
            let head = format!(
                "{} · {} · risk {} ({})",
                finding.client, finding.domain, finding.risk, finding.severity
            );
            println!("  {}", self.bold(&head, severity_color(finding.severity)));
            println!(
                "  {}",
                self.dim(&format!(
                    "{} → {}   {} queries   {:.2} q/s   {} distinct labels",
                    fmt_epoch(finding.window_start),
                    fmt_epoch(finding.window_end),
                    finding.queries,
                    finding.qps,
                    finding.features.fanout
                ))
            );
            for signal in &finding.signals {
                println!(
                    "    {} {:<14} {:.2}  {}",
                    self.paint("▪", BLUE),
                    signal.id,
                    signal.score,
                    self.dim(&signal.detail)
                );
            }
            if !finding.mitre.is_empty() {
                println!(
                    "    {} {}",
                    self.dim("MITRE"),
                    self.paint(&finding.mitre.join(", "), YELLOW)
                );
            }
        }
        println!();
    }

    pub fn eval_table(&self, report: &EvalReport) {
        println!(
            "  {:<9} {:>9} {:>8} {:>7} {:>7} {:>6} {:>5}",
            "THRESH", "PRECISION", "RECALL", "F1", "FPR", "TP", "FP"
        );
        for (index, row) in report.rows.iter().enumerate() {
            let line = format!(
                "  {:<9} {:>9.3} {:>8.3} {:>7.3} {:>7.3} {:>6} {:>5}",
                format!("≥ {}", row.threshold),
                row.precision,
                row.recall,
                row.f1,
                row.fpr,
                row.tp,
                row.fp
            );
            if index == report.best {
                println!("{}", self.bold(&format!("{line}  ← best F1"), GREEN));
            } else {
                println!("{line}");
            }
        }
    }

    pub fn summary(&self, input: &str, summary: &Summary) {
        let first = summary
            .first_ts
            .map(fmt_epoch)
            .unwrap_or_else(|| "—".into());
        let last = summary.last_ts.map(fmt_epoch).unwrap_or_else(|| "—".into());
        self.panel(
            "capture summary",
            &[
                ("input", input.to_string()),
                ("queries", format_count(summary.queries)),
                ("responses", format_count(summary.responses)),
                ("clients", format_count(summary.clients)),
                ("domains", format_count(summary.domains)),
                ("qnames", format_count(summary.unique_qnames)),
                ("first seen", first),
                ("last seen", last),
                ("duration", format_duration(summary.duration_seconds)),
            ],
        );

        self.counts_section("top clients", "CLIENT", &summary.top_clients);
        self.counts_section("top domains", "DOMAIN", &summary.top_domains);
        self.counts_section("query types", "QTYPE", &summary.qtypes);
        self.counts_section("response codes", "RCODE", &summary.rcodes);
        self.hint("next: siren analyze <input> to score these buckets");
        println!();
    }

    fn counts_section(&self, title: &str, label: &str, rows: &[Count]) {
        self.section(title);
        if rows.is_empty() {
            println!("  {}", self.dim("none"));
            return;
        }
        println!("  {:>8}  {}", "COUNT", label);
        for row in rows {
            println!("  {:>8}  {}", row.count, row.name);
        }
    }

    pub fn signals_table(&self) {
        println!(
            "  {:<14} {:>6}  {:<18} WHAT IT LOOKS FOR",
            "SIGNAL", "WEIGHT", "MITRE"
        );
        for detector in DETECTORS {
            // Same rule as the panel: pad first, then colour.
            println!(
                "  {} {:>6.2}  {} {}",
                self.paint(&cell(detector.id, 14), BLUE),
                detector.weight,
                self.paint(&cell(&detector.mitre.join(","), 18), YELLOW),
                detector.description
            );
        }
    }

    pub fn footer(&self, findings: &[Finding]) {
        let mut techniques: Vec<&str> = findings
            .iter()
            .flat_map(|f| f.mitre.iter().copied())
            .collect();
        techniques.sort_unstable();
        techniques.dedup();
        if techniques.is_empty() {
            return;
        }
        println!();
        println!(
            "  {} {}",
            self.dim("MITRE ATT&CK covered:"),
            self.paint(&techniques.join("  "), YELLOW)
        );
    }

    pub fn hint(&self, text: &str) {
        println!("  {}", self.dim(text));
    }
}

pub fn severity_color(severity: &str) -> Color {
    match severity {
        "critical" => RED,
        "high" => ORANGE,
        "medium" => YELLOW,
        "low" => BLUE,
        _ => MUTED,
    }
}

pub fn rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn mix(a: Color, b: Color, t: f64) -> Color {
    let (
        Color::Rgb {
            r: ar,
            g: ag,
            b: ab,
        },
        Color::Rgb {
            r: br,
            g: bg,
            b: bb,
        },
    ) = (a, b)
    else {
        return a;
    };
    let lerp = |x: u8, y: u8| (x as f64 + (y as f64 - x as f64) * t).round() as u8;
    Color::Rgb {
        r: lerp(ar, br),
        g: lerp(ag, bg),
        b: lerp(ab, bb),
    }
}

// `is_multiple_of` is newer than our MSRV (1.85), so keep the modulo form.
#[allow(clippy::manual_is_multiple_of)]
fn format_count(value: usize) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn format_duration(seconds: f64) -> String {
    if seconds >= 3_600.0 {
        format!("{:.2}h", seconds / 3_600.0)
    } else if seconds >= 60.0 {
        format!("{:.2}m", seconds / 60.0)
    } else {
        format!("{seconds:.1}s")
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// A left-aligned cell of exactly `width` characters. Callers colour the
/// result *after* padding, never before: ANSI escapes are zero-width, so a
/// width spec applied to a coloured string silently collapses the column.
fn cell(text: &str, width: usize) -> String {
    format!("{:<width$}", truncate(text, width), width = width)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_are_exactly_the_requested_width() {
        assert_eq!(cell("input", 17).chars().count(), 17);
        assert_eq!(cell("", 5).chars().count(), 5);
        assert_eq!(cell("exactly-17-chars!", 17).chars().count(), 17);
        assert_eq!(cell("far-too-long-for-the-column", 17).chars().count(), 17);
        assert!(cell("far-too-long-for-the-column", 17).ends_with('…'));
    }

    #[test]
    fn severity_ranking_is_ordered() {
        assert!(rank("critical") > rank("high"));
        assert!(rank("high") > rank("medium"));
        assert!(rank("medium") > rank("low"));
        assert!(rank("low") > rank("info"));
        assert_eq!(rank("nonsense"), 0);
    }

    #[test]
    fn severity_colours_are_distinct() {
        let critical = severity_color("critical");
        let high = severity_color("high");
        let medium = severity_color("medium");
        let low = severity_color("low");
        assert_ne!(critical, high);
        assert_ne!(high, medium);
        assert_ne!(medium, low);
    }
}
