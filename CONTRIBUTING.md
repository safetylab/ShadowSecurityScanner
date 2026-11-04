# Contributing to ShadowSecurityScanner

Thank you for considering a contribution. This is a security tool, so a
few rules exist that an ordinary project would not need.

## Ground rules

- Only ever test against systems you own or are explicitly authorised to
  test. Do not attach scan output from third-party infrastructure.
- Report a security problem in the scanner itself privately, through
  [SECURITY.md](SECURITY.md), not as a public issue.
- Do not add a check that is destructive by default, or one whose only
  purpose is evading detection.

## Getting started

This repository holds the open-source components: `epsskev`, `findings`
and `sarif`, plus the commands in `cmd/`.

```bash
git clone https://github.com/safetylab/ShadowSecurityScanner.git
cd ShadowSecurityScanner

go vet ./...
go test -race ./...
go build ./...
```

Run the suite before changing anything, so you know the baseline passes.

Try the commands end to end:

```bash
echo '[{"cve":"CVE-2021-44228","severity":"CRITICAL","cvss":10.0}]' \
  | go run ./cmd/triage
```

## What makes a change easy to accept

- A clear statement of the problem it solves.
- A test that fails without the change. The packages here are pure
  enough that most behaviour can be tested without network access —
  `epsskev.Enricher` exists so a test can supply a double.
- No unrelated reformatting in the same commit.
- Documentation updated in the same change where behaviour changed.
- `go vet ./...` and `go test -race ./...` both clean.

## Data from external sources

`epsskev` reads the FIRST.org EPSS API and the CISA KEV catalogue. Treat
both as untrusted input: bound what you read, check what you parse, and
fail loudly rather than defaulting a score to zero — a silently
mis-scored finding is worse than a visible error, because it sinks to
the bottom of a fix-first ranking.

## Reporting a bug

Use the bug report template. The most useful report says what you ran,
what you expected and what happened, with the version and platform.

## Questions

Open a discussion rather than an issue if you are not sure whether
something is a bug.
