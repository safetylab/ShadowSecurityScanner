# nse2pack — a converter from Nmap NSE to check-packs

Reads a directory of `.nse` scripts and writes check-packs for
ShadowSecurityScanner plus a report of everything it could not translate.
Standard library Python 3.9+ only: no dependencies, no network.

The format specification is
[`docs/check-pack/format.md`](../../docs/check-pack/format.md).
[`USAGE.md`](USAGE.md) is the user guide: the run-to-install workflow, how to
read the report, and the common questions. This file covers how the converter
works and why it decides what it does.

## Running it

```bash
./nse2checkpack /usr/share/nmap/scripts -o out --source nse
```

```
  nse-discovery.json           pack-nse-discovery — 2 checks (sweep: 0, own row: 2)
  nse-version.json             pack-nse-version — 3 checks (sweep: 1, own row: 2)
  nse-vuln.json                pack-nse-vuln — 1 check (sweep: 1, own row: 0)

  scripts read:   11
  converted:      6
  not converted:  5 (exploitation: 2, routing: 1, untranslatable pattern: 1, weak assertions: 1)
```

`out/` then holds the packs, `report.md` and `report.json`. Inspect them with
the same tool — `--check` applies the compiler rules from §5 and the routing
rule from §7 to a finished file:

```bash
./nse2checkpack --check -v out/nse-version.json
./nse2checkpack --check --strict out/nse-vuln.json     # non-zero exit on any drop
```

The desktop application ships its own compiler and is the authority; `--check`
is a faithful reimplementation of the published rules, calibrated against the
reference packs so that it refuses exactly what they say it must.

### Options

| option | meaning |
|---|---|
| `-o`, `--out` | where packs and reports are written (default `out`) |
| `--source` | the `source` field: the name users see beside a finding and use to switch the whole set off |
| `--pack-version` | the pack's `version` stamp; a higher number replaces a lower one on update |
| `--single` | one pack instead of splitting by NSE category |
| `--products FILE` | JSON map `{"name in NSE": "canonical name in the scanner database"}` |
| `--min-marker N` | how long a lone piece of evidence must be (default 8) |
| `--strict` | exit non-zero if any generated check failed the compiler rules — for CI |
| `--check` | do not convert: inspect existing packs and report what the scanner will accept, drop and why |
| `-v`, `--verbose` | with `--check`, print the plan of each accepted check |

## What is translated

| NSE shape | result |
|---|---|
| `comm.get_banner` plus a match | a `tcp`/`udp` step with an empty `send_b64` |
| `comm.exchange` / `socket:send` with a literal payload | the same step with `send_b64` |
| one `http.get` / `http.head` with a literal path | an `http` step |
| `for _, p in ipairs({"/a", "/b"}) do http.get(…, p)` | `paths` — "any of them proves it" |
| two requests where the second uses a value from the first | two steps with `capture` and `{{name}}` |
| `port.version.product` / `port.version.version` | **`detect`** — the point of the whole exercise |
| `string.match` / `string.find` over body and headers | `expect.re`, `body_all`, `header`, `not` |
| `resp.status ~= 200 then return end` | `expect.status` |
| the `intrusive` category | `"intrusive": true` |

The title and description of a finding come from the script's `description`;
CVE and CWE identifiers are scraped from the whole text.

## What is not translated — by design

Every refusal reaches the report with a reason and a class; the classes are the
ones §11.2 of the specification asks for.

| class | when |
|---|---|
| `exploitation` | the `brute`, `exploit`, `dos`, `malware` or `fuzzer` category; `http.post`/`put`/`delete`; a method a declarative check may not use |
| `logic` | a computed path or payload, three or more requests, two unrelated requests, several `socket:send` calls |
| `state` | no `action`, no exchange with the target, a request to an arbitrary URL |
| `routing` | a `hostrule` with no `portrule`, an unrecognised `portrule` |
| `untranslatable pattern` | `%b`, `%f`, a position capture, a back-reference — none exist in RE2 |
| `weak assertions` | nothing could be asserted, or the only evidence is shorter than `--min-marker` with no product anchor |
| `generation error` | a defect in this converter: the check was built but failed the compiler rules. `--strict` turns it into a non-zero exit |

What the report marks as *candidate for a second-level script* is beyond this
format but within the scanner's script SDK, where real code runs in a
subprocess.

## Three decisions worth knowing

**The sense of a condition matters more than its shape.** In Lua
`if not string.match(body, "x") then return end` means `x` is **required**,
while `if string.match(body, "x") then return end` means it is **forbidden**.
Getting this wrong emits a check that asserts the opposite of the script it came
from — and it compiles and reports findings quite happily. The converter tells
an early return (`return` with no value) from a reporting branch
(`return <value>`), and the sign of every assertion follows from that. The tests
for it are in `tests/test_build.py::TestPolarity`.

**A Lua pattern is not a regular expression.** `%d` → `[0-9]`, `-` after an atom
→ `*?`, `.` → `(?s).` (in Lua the dot matches a newline), and `{`, `}`, `|`,
`\` are ordinary characters in Lua that RE2 needs escaped. Anything with no RE2
equivalent is a reason to drop the check, not to emit a broken regexp.

**`verified` is never claimed.** It asserts that vulnerable behaviour was
observed, not that a script printed something. The scanner derives it from how
specific the match was, which is what §8 recommends.

## Output quality

- evidence shorter than `--min-marker` is accepted only when something else
  narrows the check: a second piece of evidence, a product anchor
  (`require_ci`), a header test, a capture, a second step, or a byte exchange on
  a specific port;
- severity is not invented: `vuln` → `medium`, otherwise `info`;
- a check id is the script filename, so regenerating a pack **updates** it
  rather than duplicating it;
- output is deterministic: the same directory yields byte-identical packs;
- every check passes all the §5 refusal rules before it is written.

`detect.product` has to match the canonical spelling in the scanner's database.
The converter takes the string from NSE as it is, lowercased; reconcile it
against your database and feed the differences through `--products`:

```json
{"Apache httpd": "apache", "OpenSSH": "openssh"}
```

## Layout

| file | responsibility |
|---|---|
| `nse2pack/luapat.py` | translating Lua patterns into RE2 and refusing the untranslatable |
| `nse2pack/lua.py` | the Lua mini-parser: masking strings and comments, block boundaries, call arguments |
| `nse2pack/parser.py` | script fields: `description`, `categories`, `portrule`, the body of `action` |
| `nse2pack/build.py` | recognising exchange shapes, reading the sense of conditions, assembling a check |
| `nse2pack/validate.py` | every compiler refusal rule from §5 and the routing rule from §7 |
| `nse2pack/inspect.py` | `--check`: what the scanner will do with a finished pack |
| `nse2pack/report.py` | `report.md` and `report.json` |
| `nse2pack/cli.py` | splitting into packs by category, writing, the summary |

There is no full Lua interpreter here, and there cannot be: the format takes
only a few shapes anyway. The parser is built so that an unfamiliar construct
produces a refusal with a reason rather than a check made up on a guess.

## Tests

```bash
python3 -m unittest discover -s tests -t . -q
```

79 tests: pattern translation, Lua parsing, the sense of conditions, exchange
shapes, the refusal rules, pack inspection, and an end-to-end run over
`tests/fixtures/` — eleven synthetic scripts in the shape of real NSE, written
from scratch for this suite, six translatable and five not. The
validator is separately checked against the reference corpus in `docs/check-pack/examples/`:
it must refuse all nine checks in `refusals.json` and accept every other pack
without a single complaint.

## Implementation boundaries

- `bytes_at` is not generated: §4.3 of the specification shows it as an object
  while `docs/check-pack/examples/template.json` uses a list, and until that is settled it is
  safer not to emit it;
- `POST` is not generated, although the format allows it for an `intrusive`
  check: the specification documents no field for a request body;
- the exact `verified` rule was reconstructed from the reference packs rather
  than from the compiler source. It does not affect this converter's output,
  which never sets `verified`.
