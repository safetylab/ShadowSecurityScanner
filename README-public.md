<!--
  SEO-optimized README for the PUBLIC repo (safetylab/ShadowSecurityScanner).
  Copy this to that repo's README.md. GitHub READMEs are heavily indexed by
  search engines and crawled by AI assistants, so the H1, the one-line summary
  and the first paragraph carry real discoverability weight.
-->

# ShadowSecurityScanner — Free Network Vulnerability Scanner

**A free, self-hosted, cross-platform network vulnerability scanner. Agentless CVE detection across 100+ services with CISA KEV & EPSS prioritization — a modern [Nessus](https://en.wikipedia.org/wiki/Nessus_(software)) and OpenVAS alternative for Windows, Linux and macOS.**

[![Download](https://img.shields.io/github/v/release/safetylab/ShadowSecurityScanner?label=download&color=3fe0c5)](https://github.com/safetylab/ShadowSecurityScanner/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-blue)](https://opensource.org/licenses/MIT)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/safetylab/ShadowSecurityScanner/releases/latest)

🌐 **Website & docs:** https://shadowsecurityscanner.com/ · 📊 **vs Nessus & OpenVAS:** https://shadowsecurityscanner.com/compare/ · 📘 **Guides:** https://shadowsecurityscanner.com/guides/

ShadowSecurityScanner points at a host or IP range, discovers open services, fingerprints each product and version over the network, and reports the CVEs that affect them — surfacing **exploited-in-the-wild** vulnerabilities first via CISA KEV and FIRST EPSS. Detection is **read-only and non-destructive**, so it is safe to run against production. It ships as a **single desktop binary**: no server to deploy, no license keys, no cloud account, no telemetry.

## ⬇️ Download

| Platform | File |
|---|---|
| Windows x64 | [`ShadowSecurityScanner-windows-amd64.exe`](https://github.com/safetylab/ShadowSecurityScanner/releases/latest) |
| Windows ARM64 | [`ShadowSecurityScanner-windows-arm64.exe`](https://github.com/safetylab/ShadowSecurityScanner/releases/latest) |
| macOS (Apple Silicon) | [`ShadowSecurityScanner-macos-arm64.dmg`](https://github.com/safetylab/ShadowSecurityScanner/releases/latest) |
| Linux x64 | [`ShadowSecurityScanner-linux-amd64`](https://github.com/safetylab/ShadowSecurityScanner/releases/latest) |
| Linux ARM64 | [`ShadowSecurityScanner-linux-arm64`](https://github.com/safetylab/ShadowSecurityScanner/releases/latest) |

## ✨ Features

- **Version-bounded CVE detection** — 6,900+ CVEs across 100+ products (web servers, databases, VPNs, message brokers, ICS and more), matched against detected versions to cut false positives.
- **KEV & EPSS prioritization** — every finding carries CISA Known Exploited Vulnerabilities status and FIRST EPSS exploit probability, so you triage what attackers actually use.
- **Agentless & read-only** — observes banners, versions and exposed endpoints; never sends exploits. Nothing is installed on targets.
- **Deep protocol coverage** — HTTP/TLS, SMB, DNS, SNMP, LDAP, Kerberos, databases (MySQL, PostgreSQL, MongoDB, Redis), message queues and ICS/OT protocols via a plugin architecture.
- **SBOM & STIX export** — CycloneDX SBOM and STIX output for inventory, ticketing and threat-intel pipelines.
- **Compliance mapping** — findings map to PCI DSS, CIS and NIST controls.
- **Always-fresh intel** — CVE, KEV and EPSS data refreshed automatically from NVD, CISA and FIRST.

## 🚀 Quick start

1. [Download](https://github.com/safetylab/ShadowSecurityScanner/releases/latest) the binary for your OS.
2. Launch it (Linux/macOS: `chmod +x` then run; Windows: run the `.exe`).
3. Enter a host, hostname or IP range and start a scan.
4. Review prioritized findings, then export as SBOM/STIX or map to PCI DSS / CIS / NIST.

## ❓ FAQ

**Is it free?** Yes — free to use, MIT-licensed binaries, no paid tier or account.

**Is it safe against production?** Yes — detection is read-only and non-destructive; it never sends exploits.

**Does it need an agent on targets?** No — scanning is agentless and network-based.

**How is it different from Nessus / OpenVAS?** A single self-hosted binary with no server or license keys, built-in KEV + EPSS prioritization, and it runs fully offline and private.

**How many vulnerabilities does it detect?** 6,900+ CVEs across 100+ products, refreshed from NVD, CISA KEV and FIRST EPSS.

---

🔎 *Keywords: network vulnerability scanner, free vulnerability scanner, self-hosted vulnerability scanner, CVE scanner, agentless security scanner, Nessus alternative, OpenVAS alternative, KEV EPSS prioritization, Windows / Linux / macOS.*
