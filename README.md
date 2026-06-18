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

- 🌐 **Website & docs:** https://andriigordiienko.github.io/ShadowSecurityScanner-site/
- 📊 **vs Nessus & OpenVAS:** https://andriigordiienko.github.io/ShadowSecurityScanner-site/compare/
- 📘 **Guides:** https://andriigordiienko.github.io/ShadowSecurityScanner-site/guides/

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
