# Security policy

## Reporting a vulnerability in ShadowSecurityScanner

Report it privately through the **Report a vulnerability** button on the
[Security tab](https://github.com/safetylab/ShadowSecurityScanner/security)
of this repository. That opens a private advisory visible only to the
maintainers.

Please do not open a public issue for a security problem in
ShadowSecurityScanner itself.

Include:

- what the problem is and what an attacker could do with it,
- the version you tested and how you built or installed it,
- the steps to reproduce, against a system you are authorised to test.

## What to expect

You will get an acknowledgement that the report was received, a decision
on whether it is in scope, and a note when a fix ships. If a report is
out of scope you will be told why.

## Scope

In scope — ShadowSecurityScanner itself:

- the scanner and its handling of responses from scanned systems,
- the open-source components in this repository: `epsskev` (EPSS and
  CISA KEV enrichment), `findings`, `sarif` (report generation),
- the reporting output, including SARIF consumed by other tools,
- handling of credentials, targets and scan data.

Out of scope:

- vulnerabilities in the systems you scan,
- findings produced by running the scanner against targets you do not
  control,
- reports from automated scanners with no demonstrated impact.

## Using this tool

ShadowSecurityScanner is for systems you own or are authorised to test.
Scanning infrastructure without the owner's written permission is
unlawful in most jurisdictions and is not supported here.
