# Writing a converter for another source

`nse2pack` converts Nmap NSE. The format has nothing to do with NSE, so the same
approach works for Nuclei templates, OpenVAS NASL, a vendor advisory feed, or the
YAML your team already keeps. This is how to build one — on your own or with a
coding agent such as Claude Code or Codex — and how to know it is correct.

Read [`format.md`](format.md) first. This document assumes it.

---

## What you are building

Two outputs, not one:

1. **Packs** — JSON files the scanner loads at startup. One pack is one catalogue
   row the operator switches on and off, so split the corpus the way an operator
   would want to switch it.
2. **A refusal report** — every input you did not translate, with the reason and a
   class. This is not a log. It is the only thing that distinguishes a converter
   that handled 300 of 300 rules from one that handled 40 and looks the same from
   outside.

A converter is judged by the share of the corpus it converts **correctly**, never
by the number of checks it emits.

---

## Before writing code: triage the corpus

The format expresses exactly one thing: *exchange something with the target and
look at the reply*. No variables, no branches, no loops, no arithmetic.

Go through twenty representative rules by hand and sort them:

| The rule… | Verdict |
|---|---|
| sends a request and matches the reply | converts |
| takes a banner and extracts a product and version | converts — and this is the valuable part |
| tries a list of paths, any of which proves it | converts (`paths`) |
| makes a second request using a value from the first | converts (`capture` + `{{name}}`, up to 8 steps) |
| computes a token, signs, encodes, loops, branches | does not convert |
| exploits, brute-forces, floods, writes to the target | does not convert, and should not |
| keeps state across runs or between rules | does not convert |

That ratio is your real coverage. Knowing it before you write code stops the two
classic failures: building machinery for shapes the format cannot hold, and
quietly emitting checks that assert less than the rule they came from.

---

## The five stages

Every converter ends up with the same pipeline. `nse2pack` names them in
[`../../tools/nse2pack/`](../../tools/nse2pack/); only the first and the fourth
are source-specific.

**1. Gate.** Refuse whole classes before parsing anything: attack categories,
rules that write to the target, rules with no assertion. Cheap, and it keeps the
rest of the pipeline honest.

**2. Route → `match`.** Where does the rule apply? Service name, ports, "at least
one of these ports open". A check with no precondition would be offered to every
host, and the compiler refuses it.

**3. Exchange → `steps`.** One transport per step: `http`, `tcp`, `udp`, `tls`.
A literal path or payload converts; a computed one does not — refuse it rather
than guessing a value.

**4. Assertions → `expect`.** The subtle stage. Three things to get right:

- **The sense of a condition.** Source languages express "this must be present"
  and "this must be absent" in ways that look alike. In Lua,
  `if not match(body, "x") then return end` *requires* `x`, while
  `if match(body, "x") then return end` *forbids* it. Get this backwards and you
  emit a check that asserts the opposite of its source — and it compiles, loads
  and reports findings quite happily. Whatever your source language, find its
  equivalent trap first and write tests for it before anything else.
- **Pattern dialects.** Lua patterns, PCRE, Go regexps and RE2 are different
  languages. RE2 has no backtracking, no lookaround, no back-references. Translate
  faithfully — including whether `.` matches a newline — and refuse what has no
  equivalent instead of emitting a regexp that will not compile.
- **Evidence strength.** A bare `"login"` on any 200 page is worse than no check
  at all. Require a second piece of evidence, a product anchor in `require_ci`, a
  header test, a capture, or a byte exchange on a known port — otherwise refuse.

**5. Report → `detect` / `finding`.** Prefer `detect`: the check says "nginx
1.24.0 is here" and the scanner supplies the CVEs, EPSS, KEV and end-of-life data
itself. A `finding` is for what you actually observed.

---

## Six invariants

1. **Refuse loudly, never guess.** An unconvertible rule must produce a refusal
   with a reason, not a check that approximates it.
2. **Validate before writing.** Apply every §5 rule to each generated check. A
   check dropped at load time shrinks coverage silently.
3. **Stable ids.** Derive `check.id` from something stable in the source (the file
   name, the rule id). Unstable ids turn every regeneration into a full
   replacement instead of an update.
4. **Never claim `verified`, never invent `severity`.** `verified` means the
   vulnerable behaviour was observed. Leave it out and the scanner derives
   confidence from how specific your match was.
5. **Prefer `detect` to `finding`.** One reliable version extraction beats twenty
   checks asserting that a page exists.
6. **Deterministic output.** The same corpus must produce byte-identical packs, so
   a diff between runs shows what actually changed.

---

## Reuse what is already here

`tools/nse2pack/nse2pack/validate.py` has no NSE in it — only `base64`, `binascii`
and `re` — so it validates checks built by any converter:

```python
from nse2pack.validate import validate_check, validate_pack, route_of

problems = validate_check(my_check)      # [] when the scanner will accept it
route, why = route_of(my_check)          # 'sweep' or 'own', and the reason
```

Also worth copying rather than rewriting:

- `inspect.py` — the `--check` report: accepted, dropped, why, and where each
  check will run.
- `report.py` — the shape of the refusal report, grouped by class.
- `luapat.py` — only if your source uses Lua patterns. For another dialect, write
  the equivalent translator with the same discipline: translate or refuse, never
  emit something that "probably works".

---

## How you know it is correct

**The reference corpus is an acceptance test you did not have to write.**

- [`examples/template.json`](examples/template.json) — nine checks, one per
  capability. Your validator must accept all of them.
- [`examples/refusals.json`](examples/refusals.json) — nine deliberately invalid
  checks, each triggering a different refusal. Your validator must refuse all
  nine, with the right reason for each.

Then, on your own output:

```bash
tools/nse2pack/nse2checkpack --check --strict out/*.json
```

It applies the published refusal and routing rules to finished packs regardless of
which converter wrote them. Put it in CI next to your own `--strict`.

Finally, run against a reference service you control. Compiling proves the pack is
well formed; only a live run shows that a check fires where it should and — the
half people forget — stays silent everywhere else.

---

## Working with a coding agent

A converter is a good fit for an agent: the rules are written down, the output is
machine-checkable, and the failure mode is visible. The risk is specific and worth
naming — **an agent asked to "make the corpus convert" will loosen assertions until
it does.** A check that matches everything compiles perfectly.

Put in its context, in this order:

1. `format.md` — the whole specification.
2. `examples/template.json` and `examples/refusals.json`.
3. `validate.py`, and the instruction to run it on every generated check.
4. Ten to twenty representative inputs from your corpus, including several you
   know must be refused.

Then work in this loop:

1. **Fixtures first.** Write the inputs you expect to convert *and* the ones you
   expect to be refused, with the expected class of each refusal. This is what
   stops the agent from declaring success by converting everything.
2. **Implement one stage at a time**, in the order above. Gate before parse,
   parse before assert.
3. **Validate and report** on every run. `--strict` in CI from the first commit.
4. **Review three things with suspicion**, because they look right when they are
   wrong: the sense of conditions, the pattern translation, and any check whose
   only evidence is a short literal.

Non-negotiables worth stating in the task brief verbatim:

```
- Never emit a check that asserts less than its source rule. If a construct
  cannot be expressed, refuse the rule with a reason and a class.
- Never set verified. Never invent severity.
- Never widen an assertion to make a rule convert.
- Validate every generated check against validate.py before writing it; a check
  that fails the rules is a bug in the converter, not an input to be skipped.
- Report every refusal: id, reason, class. Coverage must never look larger than
  it is.
```

Ask for the refusal report to be reviewed as carefully as the packs. It is where
an over-eager conversion shows up first: a corpus that converts at 95% usually
means assertions were dropped, not that the format grew.

---

## Where to start, by source family

| Source | Expect |
|---|---|
| **Nuclei templates** | The closest fit. `http` requests map to steps, `matchers` (word/regex/status/binary) map to `expect`, `extractors` to `capture`. Refuse `workflows`, DSL expressions, anything with `payloads`/fuzzing. |
| **OpenVAS / NASL** | Banner and version detection converts well and is worth doing for `detect` alone. Most of the rest is a script. |
| **Metasploit auxiliary** | Mostly refuse: these modules act on the target. A few version scanners convert. |
| **Your own YAML / CSV feed** | Usually a direct mapping, and the easiest place to start — you control the input shape. |

---

## Checklist before you publish a converter

- [ ] The refusal report names every input you did not convert, with a class.
- [ ] Every generated check passes `validate_check` before being written.
- [ ] `--check --strict` on the output is clean, in CI.
- [ ] Ids are stable: run twice, diff the packs, see nothing.
- [ ] No `verified`, no invented severity anywhere in the output.
- [ ] Spot-check ten converted checks against their source rules — do they assert
      the same thing, including the negative conditions?
- [ ] A live run against a reference service: fires where it should, silent where
      it should not.
- [ ] The licence of the source corpus is accounted for: a converted pack may be a
      derivative work of the rule it came from.
