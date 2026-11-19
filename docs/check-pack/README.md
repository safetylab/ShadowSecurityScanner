# Materials for writing a converter into the ShadowSecurityScanner format

Everything needed to write a converter — the first one being from the Nmap
Scripting Engine — into our check-pack format. Reading the scanner's source is
not required.

## Start here

**[format.md](format.md)** —
the full specification: the schema, every compiler refusal verbatim, the
limits, the routing rule, how NSE constructs map onto the format, and what the
format deliberately does not do.

Two conclusions from it worth accepting before you start:

1. The format describes **an exchange and a match on the reply**. There are no
   variables, branches or loops, so most of NSE does not convert. That is a
   boundary, not a gap.
2. The most valuable thing a converter can produce is not findings but
   **`detect`**: the check reports the product and version, and the scanner's
   database supplies the CVEs, EPSS scores, CISA KEV marks and end-of-life
   record.

## Examples

| File | Why it helps |
|---|---|
| `docs/check-pack/examples/nmap-acarsd-info.json` | **an NSE script already ported** — the closest reference for a converter |
| `docs/check-pack/examples/template.json` | a template of nine checks: every major shape in one file |
| `docs/check-pack/examples/every-shape.json` | header + `detect`, a `paths` list, a two-step check with `capture`/`{{tok}}`, a TCP banner, a missing header |
| `docs/check-pack/examples/demo-three-checks.json` | TCP banner → finding, URL → finding, version → `detect` → CVE |
| `docs/check-pack/examples/my-cheks-tcp.json`, `my-cheks-web.json` | small working packs: an own catalogue row against the shared web sweep |
| `docs/check-pack/examples/refusals.json` | **nine deliberately invalid checks** — a test set for a converter: each one triggers a different refusal |

Every pack except `refusals.json` compiles without a single dropped check.
`refusals.json` is rejected in full — that is the point of it.

## The NSE converter

[`tools/nse2pack/`](../../tools/nse2pack/) is a working converter in Python: it reads a
directory of `.nse` scripts and writes packs plus a report of what it could not
translate. No dependencies.

```bash
cd tools/nse2pack
./nse2checkpack /usr/share/nmap/scripts -o out --source nse
python3 -m unittest discover -s tests -t . -q      # 70 tests
```

What converts, what is refused and why, and the three decisions the whole thing
rests on are in [`tools/nse2pack/README.md`](../../tools/nse2pack/README.md). The workflow from
a run to an installed pack is in [`tools/nse2pack/USAGE.md`](../../tools/nse2pack/USAGE.md).

## Verifying the result

Any pack — generated or written by hand — can be inspected without the
application and without a key, network or running scanner:

```bash
tools/nse2pack/nse2checkpack --check <pack.json>             # what is accepted, what dropped and why
tools/nse2pack/nse2checkpack --check -v <pack.json>          # plus the plan of each check
tools/nse2pack/nse2checkpack --check --strict <pack.json>    # non-zero exit on any drop
```

It applies the refusal rules of §5 and the routing rule of §7. The desktop
application ships its own compiler, which remains the authority; a live run —
does the check fire where it should and stay silent elsewhere — is a scan of a
host you are allowed to scan.

`--strict` belongs in the converter's CI: then a regression in generation fails
immediately instead of turning up when a user loads the pack.

A useful testing habit: run the converter over inputs like `refusals.json` and
confirm that it refused them itself **before** generating, for the same reason.

## Where a finished pack goes

No signature is needed — a pack is data, it executes nothing.

1. **Your own folder:** Settings → Sources → Add source → "A folder of my own",
   with an absolute path. Every `*.json` directly in the folder is read;
   subdirectories are not walked.
2. **The scanner's data directory:** `<data>/probes/`. The path is shown in the
   same panel.

In both cases packs are read **once, at startup**.
