# ShadowSecurityScanner

![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![Latest release](https://img.shields.io/github/v/release/safetylab/ShadowSecurityScanner)
![Stars](https://img.shields.io/github/stars/safetylab/ShadowSecurityScanner?style=social)

**ShadowSecurityScanner** is a free **penetration testing tool** and **network
vulnerability scanner**. It performs port scanning, service & OS fingerprinting, and
thousands of catalogued network and web checks, then ranks every finding by real-world
exploit probability — **EPSS** (FIRST.org) + **CISA KEV** — not just raw CVSS. A single
self-contained desktop app for **Windows, macOS and Linux**. No cloud, no agents, no telemetry.

- 🌐 **Website & docs:** https://shadowsecurityscanner.com/
- 📊 **vs Nessus & OpenVAS:** https://shadowsecurityscanner.com/compare/
- 📘 **Guides:** https://shadowsecurityscanner.com/guides/

> **Open-core.** The desktop app is free to use; its core exploit-aware components are
> open-source (MIT) and live in this repository — read, audit and reuse them below.

## Download

Get the latest build for your platform from the
[**Releases page**](https://github.com/safetylab/ShadowSecurityScanner/releases/latest):

| Platform | File |
|---|---|
| Windows (x64) | `ShadowSecurityScanner-windows-amd64.exe` |
| Windows (ARM64) | `ShadowSecurityScanner-windows-arm64.exe` |
| macOS (Apple Silicon) | `ShadowSecurityScanner-macos-arm64.dmg` |
| Linux (x64) | `ShadowSecurityScanner-linux-amd64` |
| Linux (ARM64) | `ShadowSecurityScanner-linux-arm64` |

No installer required. On Linux: `chmod +x` and run. On macOS: first launch, right-click → Open.

## Open-source components

This repository hosts the open-source, MIT-licensed parts of ShadowSecurityScanner as
reusable Go packages and CLIs.

### `epsskev` — EPSS + CISA KEV prioritisation

Fetch FIRST.org EPSS scores and CISA KEV status for any list of CVEs and sort them
fix-first (`KEV → EPSS → CVSS`).

```bash
go install github.com/safetylab/ShadowSecurityScanner/cmd/epss-kev@latest

epss-kev CVE-2021-44228 CVE-2017-0144 CVE-2024-6387
# RANK  CVE                 EPSS    KEV     PERCENTILE
# 1     CVE-2021-44228      1.00    KEV     100%
# ...
```

```go
import epsskev "github.com/safetylab/ShadowSecurityScanner/epsskev"

ranked, _ := epsskev.EnrichAndPrioritise(ctx, epsskev.NewClient(), findings)
```

### `sarif` — findings → SARIF 2.1.0

Convert vulnerability findings into a SARIF 2.1.0 document for GitHub code scanning,
with per-CVE rules, NVD `helpUri` and GitHub `security-severity`.

```bash
go install github.com/safetylab/ShadowSecurityScanner/cmd/vuln-sarif@latest
vuln-sarif < findings.json > results.sarif
```

```go
import sarif "github.com/safetylab/ShadowSecurityScanner/sarif"

out, _ := sarif.Marshal(findings, sarif.DefaultTool)
```

### `triage` — findings → enrich → SARIF (end to end)

Read vulnerability findings as JSON (see
[`findings/findings.schema.json`](findings/findings.schema.json)), enrich them with
EPSS + CISA KEV, sort fix-first, and print a ranked table or a SARIF report.

```bash
go install github.com/safetylab/ShadowSecurityScanner/cmd/triage@latest

triage < findings.json                  # ranked table
triage -format sarif < findings.json > results.sarif
```

```text
RANK  CVE                 SEVERITY   CVSS    KEV     EPSS
1     CVE-2021-44228      CRITICAL   10.0    KEV     1.00
2     CVE-2017-0144       HIGH       8.1     KEV     0.99
3     CVE-2099-0001       CRITICAL   9.8     -       0.00
```

### `nse2pack` — Nmap NSE → check-pack

Convert an Nmap NSE script into a **check-pack**: a JSON file the scanner reads at
startup and runs alongside its built-in checks. A pack is data, not code — it executes
nothing, so it needs no signature and no consent prompt.

```bash
cd tools/nse2pack

./nse2checkpack /usr/share/nmap/scripts/http-server-header.nse -o out
#   nse-version.json             pack-nse-version — 1 check (sweep: 1, own row: 0)
#   scripts read:   1
#   converted:      1
#   not converted:  0

./nse2checkpack --check -v out/nse-version.json
#   checks:   1 accepted, 0 dropped
#   http-server-header
#     when service http → GET / → 1 assertion(s) → detect nginx + version
```

Then add the folder under Settings → Sources (or drop the file into the scanner's
`probes` folder) and restart the app: your check runs with the rest.

Python 3.9+, standard library only. The converter translates what the format can
express — one exchange with the target and a match on the reply — and **refuses** what
it cannot: exploitation, brute force, DoS, anything that writes to the target, and Lua
patterns with no RE2 equivalent. Everything refused is listed in a report with the
reason, so coverage is never quietly smaller than it looks.

- [`docs/check-pack/format.md`](docs/check-pack/format.md) — the format specification
- [`docs/check-pack/README.md`](docs/check-pack/README.md) — where to start, with reference packs
- [`docs/check-pack/writing-a-converter.md`](docs/check-pack/writing-a-converter.md) — build a converter for another source (Nuclei, NASL, your own feed)
- [`tools/nse2pack/USAGE.md`](tools/nse2pack/USAGE.md) — the guide from a run to an installed pack

## Build the libraries

```bash
git clone https://github.com/safetylab/ShadowSecurityScanner.git
cd ShadowSecurityScanner
go test ./...
go build ./...
```

## Legal & ethical use

For **authorized security testing only** — scan systems you own or are explicitly
permitted to assess. Denial-of-service tests are intentionally excluded.

## License

[MIT](LICENSE) — © AndriiGordiienko.
