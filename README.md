<div align="center">

```text
███████╗██╗██████╗ ███████╗███╗   ██╗
██╔════╝██║██╔══██╗██╔════╝████╗  ██║
███████╗██║██████╔╝█████╗  ██╔██╗ ██║
╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║
███████║██║██║  ██║███████╗██║ ╚████║
╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
```

###  DNS covert channels, measured.

**SIREN reads DNS traffic, extracts behavioural features, and scores every
(client, domain, time window) bucket with eight explainable detectors — then
proves how well it does.**

[![CI](https://github.com/raxwqx/SIREN/actions/workflows/ci.yml/badge.svg)](https://github.com/raxwqx/SIREN/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-1.75%2B-dea584?logo=rust&logoColor=white)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-2b2f3a)
![License](https://img.shields.io/badge/license-MIT-3da639)
![Precision](https://img.shields.io/badge/precision-0.99-ff4866)
![Recall](https://img.shields.io/badge/recall-0.93-58a6ff)

🇬🇧 **English** · 🇹🇷 [Türkçe](README.tr.md) · 🇷🇺 [Русский](README.ru.md) · 🇸🇦 [العربية](README.ar.md)

</div>

---

## 🎯 Why SIREN exists

DNS is the one protocol almost every network lets out of the building, which is
exactly why it is used to tunnel data out. Most public "DNS exfiltration
detectors" are a single entropy check in a Python script: no tests, no ground
truth, no idea whether they work.

SIREN is built the other way around:

- 🔍 **Explainable by construction.** Every alert lists the signals that fired,
  with the measured value and the threshold it crossed.
- 🧩 **Corroboration, not vibes.** One strong signal alone cannot produce a high
  verdict; weights are designed so a verdict needs several independent signals.
- 📊 **Measured, not claimed.** A deterministic generator creates labeled traffic
  and `siren eval` reports precision, recall, F1 and FPR across thresholds.
  Every number in this README can be reproduced with two commands.
- 🪶 **No native dependencies.** The PCAP reader and DNS parser are pure Rust — no
  libpcap, no Npcap, no root. It runs the same on Linux, Windows and macOS.

> ⚠️ SIREN is a detection and analysis tool. It does not sit inline and it does not
> block traffic.

---

##  Demo

```console
$ siren analyze capture.pcap --window 300 --explain

  ███████╗██╗██████╗ ███████╗███╗   ██╗
  ██╔════╝██║██╔══██╗██╔════╝████╗  ██║
  ███████╗██║██████╔╝█████╗  ██╔██╗ ██║
  ╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║
  ███████║██║██║  ██║███████╗██║ ╚████║
  ╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
  DNS covert channels, measured.  ·  github.com/raxwqx/SIREN

╭─ capture ──────────────────────────────────────────────────╮
│ input             capture.pcap                             │
│ queries           17,719                                   │
│ domains           96                                       │
│ buckets           657                                      │
│ window            300s                                     │
│ suspects          184                                      │
│ critical / high   0 / 15                                   │
╰────────────────────────────────────────────────────────────╯

  findings
  RISK SEVERITY CLIENT           DOMAIN                     QPS    ENT   SIGNALS
    47 high     10.0.0.211       tunnel18.net              0.17   3.74   label-length,nxdomain,…
    45 high     10.0.0.198       tunnel6.net               0.27   3.73   label-length,qtype,…
    43 high     10.0.0.174       tunnel3.net               0.51   3.72   encoding,qtype,nxdomain,…

  evidence

  10.0.0.211 · tunnel18.net · risk 47 (high)
  2023-11-14 22:10:00 → 22:15:00   50 queries   0.17 q/s   50 distinct labels
    ▪ label-length   0.90  longest label 56 chars (normal <= 20)
    ▪ nxdomain       1.00  96% NXDOMAIN responses (normal < 25%)
    ▪ qtype          0.66  76% TXT queries (normal < 30%)
    ▪ encoding       1.00  100% of labels look encoded (hex/base32/base64)
    ▪ fanout         0.15  50 distinct labels under one domain
    MITRE T1071.004, T1568.002, T1001
```

---

## 📦 Install

###  Requirements

- 🦀 Rust **1.75+** (`rustup` recommended)
- 🪶 No libpcap, no Npcap, no root

### 🐧 Linux / macOS

```bash
git clone https://github.com/raxwqx/SIREN.git
cd SIREN
cargo build --release
./target/release/siren --help
```

Install globally:

```bash
sudo install -m 0755 target/release/siren /usr/local/bin/siren
```

###  Windows (PowerShell)

```powershell
git clone https://github.com/raxwqx/SIREN.git
cd SIREN
cargo build --release
.\target\release\siren.exe --help
```

Add it to your `PATH` for the current session:

```powershell
$env:Path += ";$PWD\target\release"
siren --version
```

> Windows Terminal (or any terminal with VT support) shows the coloured output.
> When stdout is redirected, SIREN automatically falls back to plain text.

### 📦 Build from crates.io (coming soon)

```bash
cargo install siren-cli
```

---

## ⚡ Quick start

```bash
# 1. analyze a capture
siren analyze capture.pcap

# 2. narrower or wider time window
siren analyze capture.pcap --window 300

# 3. show the evidence behind every finding
siren analyze capture.pcap --window 300 --explain

# 4. machine-readable output
siren analyze capture.pcap --format json  > findings.json
siren analyze capture.pcap --format sarif > siren.sarif

# 5. fail a CI job when something serious shows up
siren analyze capture.pcap --fail-on high

# 6. reproduce the evaluation in this README
siren gen --out data/eval.jsonl --seed 42
siren eval data/eval.jsonl --window 300
```

---

## 🧠 How it works

```text
   PCAP / PCAPNG*            JSONL logs
        │                       │
        └───────────┬───────────┘
                    ▼
            ┌───────────────┐
            │  DNS parser   │  Ethernet · VLAN · IPv4 · IPv6 · UDP/53
            └───────┬───────┘
                    ▼
            ┌───────────────┐
            │   bucketing   │  (client, registrable domain, window)
            └───────┬───────┘
                    ▼
            ┌───────────────┐
            │   features    │  entropy · label length · qps · NXDOMAIN
            └───────┬───────┘  TXT ratio · encoding · timing CV · fanout
                    ▼
            ┌───────────────┐
            │  8 detectors  │  each returns 0..1 + human evidence
            └───────┬───────┘
                    ▼
            ┌───────────────┐
            │    scoring    │  risk = 100 × Σ(weight × score)
            └───────┬───────┘
                    ▼
        table  ·  JSON  ·  SARIF
```

\* PCAPNG is detected and reported with a one-line conversion hint
(`editcap -F pcap`). Native PCAPNG is on the roadmap.

### 🚦 Detection signals

| 🔍 Signal | ⚖️ Weight | 🚦 Fires when | 🎯 MITRE ATT&CK |
|---|---:|---|---|
| `entropy` | 0.20 | mean label entropy **> 4.3 bits/char** | T1001 |
| `label-length` | 0.16 | any label **> 20 chars** | T1071.004 |
| `query-rate` | 0.18 | **> 0.3 q/s** to one domain | T1048 |
| `nxdomain` | 0.11 | **> 25%** of answers are NXDOMAIN | T1568.002 |
| `qtype` | 0.09 | **> 30%** of queries are TXT | T1071.004 |
| `encoding` | 0.15 | **> 20%** of labels look hex/base32/base64 | T1001 |
| `beaconing` | 0.07 | inter-arrival **CV < 0.35** with ≥ 6 queries | T1071.004 |
| `fanout` | 0.04 | **≥ 20** distinct labels under one domain | T1568.002 |

`risk = 100 × Σ(weight × signal_score)` — one lone signal cannot reach a high
verdict by design. Run `siren signals` to print this table from the binary.

---

## 📊 Evaluation

SIREN ships with a deterministic traffic generator: ordinary browsing, CDN
hard-negatives (long hex labels), high-rate telemetry, encoded tunnels (hex,
base32, base64), NXDOMAIN-heavy tunnels and deliberately slow tunnels.

```bash
siren gen --out data/eval.jsonl --seed 42
siren eval data/eval.jsonl --window 60 --json
siren eval data/eval.jsonl --window 300 --json
```

Dataset: **17,719 events**, **96 domains**, seed `42`, threshold chosen by best
F1 on the sweep.

| ⏱️ Window | 🗂️ Buckets | ✅ Positive | 🎯 Precision | 🔎 Recall | 🏅 F1 | ⚠️ FPR |
|---|---:|---:|---:|---:|---:|---:|
| 60 s | 1,717 | 157 | **1.000** | 0.790 | 0.883 | 0.000 |
| 300 s | 657 | 98 | **0.989** | **0.929** | **0.958** | 0.002 |

💡 **Read this honestly:** at 60 s the detector is precise but blind to
low-and-slow tunnels — a payload that sends two queries a minute never has
enough evidence inside a one-minute bucket. Widen the window and recall climbs,
at the cost of detection latency and one false positive. That trade-off is the
whole point of exposing a window parameter instead of hard-coding one.

Reproduce it yourself; the generator is seeded and the numbers are stable.

### ⚙️ Performance

| Workload | Events | Time | Throughput |
|---|---:|---:|---:|
| JSONL, release build | 17,719 | 61 ms | ~290k events/s |
| JSONL, 5× dataset | 88,595 | 296 ms | ~299k events/s |

Single core, no SIMD, no unsafe. PCAP parsing adds protocol parsing cost; the
bottleneck is JSON deserialization, which is on the list for v0.2.

---

## 🛠️ CLI reference

```text
siren analyze <INPUT> [OPTIONS]
siren gen     --out <PATH> [--seed N]
siren eval    <INPUT> [OPTIONS]
siren signals
```

### `siren analyze`

| Option | Default | Description |
|---|---|---|
| `--window <SECONDS>` | `60` | Bucket size for feature extraction |
| `--min-queries <N>` | `3` | Ignore buckets with fewer queries |
| `--min-risk <0-100>` | `12` | Lowest risk to report |
| `--format <table\|json\|sarif>` | `table` | Output format |
| `--allowlist <FILE>` | — | One allowlisted domain per line |
| `--explain` | off | Print signal-level evidence |
| `--fail-on <low\|medium\|high\|critical>` | off | Exit `2` when matched |
| `--no-banner` | off | Plain output |

### `siren eval`

| Option | Default | Description |
|---|---|---|
| `--window <SECONDS>` | `60` | Bucket size |
| `--min-queries <N>` | `3` | Ignore sparse buckets |
| `--json` | off | Machine-readable report |

---

## 📥 Input formats

### PCAP

Classic libpcap files (`0xa1b2c3d4`, microsecond or nanosecond).
Supported link types: Ethernet (with 802.1Q/QinQ), raw IP, Linux SLL/SLL2.
Ports 53/UDP only in v0.1.

### JSONL

One JSON object per line — useful when you already have DNS logs:

```json
{"ts":1700000000.0,"client":"10.0.0.5","qname":"a.example.com","qtype":1,"rcode":0,"size":55}
{"ts":1700000001.2,"client":"10.0.0.5","qname":"k3j4h5g6.tunnel.net","qtype":16,"rcode":3,"size":90}
```

Add `"label": 0|1` to events to run `siren eval` on your own ground truth.

---

## 📤 Output formats

| Format | Use case |
|---|---|
| `table` | Human triage in a terminal (colour when TTY) |
| `json` | Pipelines, notebooks, dashboards |
| `sarif` | GitHub code scanning / CI annotations |

SARIF findings carry the client, domain, risk, signal list and MITRE techniques
in `properties`.

---

## 🧩 Design decisions

1. **Windows first-class.** A pure-Rust parser means no Npcap install and no
   admin prompt. The same binary works on Windows, Linux and macOS.
2. **Explainability over black boxes.** No ML in the hot path. Every score can
   be recomputed by hand from the printed features.
3. **Corroboration.** A web page loading resources from a hex-labelled CDN looks
   suspicious to a naive entropy check. SIREN requires rate/type/timing
   agreement before it escalates.
4. **Reproducible research.** Seeded generator, fixed thresholds as constants,
   tests that assert the weights sum to 1.0.
5. **Boring where it matters.** No unsafe, no global state, no hidden I/O.

---

## 🗺️ Roadmap

- [ ] Streaming PCAP (constant memory for multi-GB captures)
- [ ] Native PCAPNG reader
- [ ] TCP/53 reassembly
- [ ] DoH / DoT detection and resolution-path analysis
- [ ] Full Public Suffix List
- [ ] Live capture behind an optional `live` feature
- [ ] Per-client behavioural baselines (EWMA) instead of fixed thresholds
- [ ] JA4/TLS correlation to link DNS and HTTPS sessions
- [ ] Sigma-style rule export
- [ ] Prebuilt binaries for Linux, Windows and macOS via GitHub Releases

---

## ❓ FAQ

**Is this an IDS?**
No. It is an offline analyser and detection engine. It reads traffic; it does not
sit inline and it does not block.

**Do I need root or Npcap?**
No. Point it at a file. Live capture (roadmap) will need capture privileges.

**Does it detect DNS over HTTPS?**
Not yet. DoH analysis is v0.2 work; in v0.1, DoH simply does not appear as DNS.

**Why Rust and not Python?**
One static binary, no interpreter, no dependency hell on Windows, and enough
headroom to process captures at hundreds of thousands of events per second.

**Can I plug my own labels?**
Yes: add `"label": 0|1` to JSONL events and run `siren eval`.

**Is the evaluation real?**
It is synthetic but labeled and deterministic. It measures the detector's
internal consistency, not real-world prevalence. Real captures with your own
labels are the next step — and the `eval` command exists precisely for that.

---

## ⚖️ Legal

Use SIREN only on traffic you own or are explicitly authorised to analyse.
Capturing other people's traffic without permission is illegal in most
jurisdictions. The author assumes no liability for misuse.

---

## 🤝 Contributing

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
```

PRs that add a detector must include a unit test and an entry in the signal
table. PRs that change scoring must include before/after `siren eval` numbers.

---

## 📄 License

MIT © 2026 StyxHQ — see [LICENSE](LICENSE).
