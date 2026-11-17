# Changelog

Notable changes to SIREN are documented here.

## 0.2.0 - Capture summary and parser hardening

### Added

- **`siren summary <INPUT>`** — a capture-level view before detection:
  query/response counts, unique clients, domains and qnames, first/last
  timestamps, duration, query-type distribution, response-code distribution,
  and top clients/domains. Supports `--top N` (1–100) and
  `--format table|json`.
- `responses` is now part of the extracted feature set, so NXDOMAIN scoring is
  explicit about how many answers it is based on.
- New parser tests for VLAN tags, malformed UDP lengths, zero IPv4 total
  lengths, reused transaction IDs, and unsupported PCAP link types.
- `SECURITY.md`, `CHANGELOG.md`, Dependabot configuration, and a summary smoke
  test in CI.

### Fixed

- **Numeric-only labels were treated as encoded.** `is_hex` and `is_base32`
  accepted strings such as `22222222`; both now require a letter.
- **NXDOMAIN could score 100% from a single response.** The detector now
  requires at least three correlated responses.
- **Legacy VLAN tags were ignored.** `0x9100` and `0x9200` are parsed in
  addition to `0x8100` and `0x88a8`.
- **Malformed UDP length fields were silently accepted.** A length below the
  eight-byte UDP header is rejected instead of clamping to the buffer.
- **IPv4 total length of zero** (segmentation offload) now falls back to the
  captured bytes instead of discarding the packet.
- **DNS responses could be attributed to the wrong query.** Correlation now
  keeps a queue per `(client, txid)` and prefers the response whose echoed
  question matches, instead of overwriting whichever query arrived last.
- **Unsupported PCAP link types silently produced "no findings".** They now
  fail with a clear error, and captures with no DNS events report it.
- **Invalid windows produced nonsensical scores.** `--window 0`, negative, NaN,
  and infinite values are rejected; `--min-risk` is bounded to 0–100.
- **Mixed-language PCAP errors** are now consistent English, matching the rest
  of the CLI.
- The documented Rust requirement was corrected from 1.75+ to **1.85+**, which
  is what the current dependency set (clap 4.6) actually requires.

## 0.1.0 - Initial release

- PCAP (classic libpcap) and JSONL input.
- Ethernet with 802.1Q/QinQ, raw IP, Linux SLL/SLL2.
- IPv4 and IPv6 DNS-over-UDP parsing.
- Eight explainable detectors with weighted scoring.
- Table, JSON, and SARIF output.
- Allowlist support and severity-based exit codes.
- Deterministic synthetic dataset and precision/recall/F1/FPR evaluation.
