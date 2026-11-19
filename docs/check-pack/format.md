# The check-pack format: a specification for converters

A self-contained document. To write a converter — from the Nmap Scripting
Engine into our format, say — you do not need to read the scanner's source:
the whole schema, every compiler rule verbatim, all the limits and the way to
verify the result are here.

Format version: **`api: 1`**. A pack that declares any other is rejected
whole, not read half way.

---

## 1. What the converter must produce

One JSON file (a "pack") per source. The scanner reads such files at startup,
compiles them and registers them as plugins. A pack is **data, not code**: it
executes nothing, so it is accepted without a signature and without an
operator consent prompt.

```
<data>/probes/<anything>.json        ← the scanner's data directory
<any folder>/*.json                  ← a folder the operator added as a source
```

The second path is the one that matters to a converter: the user does not have
to go looking for the data directory, they add their own folder under
Settings → Sources, and everything the converter put there is read at every
startup.

Both gzip (`.json.gz`) and plain JSON are accepted. Uncompressed size: up to
256 MB.

---

## 2. The one constraint: what converts at all

The format describes a check as **"exchange something with the target and look
at the reply"**. It has no variables, no branches, no loops, no arithmetic and
no function calls.

NSE is full Lua. So, an honest assessment before you start:

| Shape of NSE script | Converts |
|---|---|
| send a string/request, match the reply with a pattern, report | **yes** |
| take a banner, extract the version | **yes**, and this is the valuable part (see §8) |
| several dependent requests, where the second uses a value from the first | **yes**, up to 8 steps, through `capture` |
| a list of paths, any of which proves it | **yes**, `paths` |
| loops, conditionals, computing tokens, custom cryptography | **no** |
| brute force, exploitation, DoS | **no**, and no need: the format deliberately only observes |
| its own socket and state, sessions | **no** |

The converter **must** produce not only a pack but a report of what it could
not translate, with the reason. A check lost in silence is worse than one that
is missing: the pack looks complete while coverage is quietly smaller.

What does not translate is not a dead end: the scanner has a second SDK level,
a script subprocess in any language talking over JSON lines. That is a separate
format, not described here; it is enough for the converter to mark such cases
as "candidate for a script".

---

## 3. The pack schema

```jsonc
{
  "source":  "nse",            // required: the source name, travels with every finding
  "version": 1,                // monotonic stamp of the pack; newer replaces older
  "api":     1,                // format version
  "plugin": {                  // one catalogue entry per pack
    "id":            "pack-nse",          // ^[a-z0-9][a-z0-9._-]*$
    "name":          "NSE converted checks",  // required, non-empty
    "category":      "web",
    "protocols":     ["tcp"],              // optional
    "default_ports": [80, 443],            // optional, 1..65535
    "params_schema": { }                   // optional, a valid JSON Schema
  },
  "checks": [ /* see §4 */ ]
}
```

An unknown field at any level is **a parse error for the whole pack**
(`DisallowUnknownFields`). That is a safeguard: otherwise a typo in a key
silently loses a condition and turns the check into one that matches
everything.

---

## 4. A check (`check`)

```jsonc
{
  "id":    "nse-http-git",      // ^[A-Za-z0-9][A-Za-z0-9._-]*$, stable across converter runs
  "api":   1,                   // optional: overrides the format version for this check
  "match": { },                 // required, see §4.1
  "steps": [ ],                 // required, 1..8, see §4.2
  "detect":  { },               // optional, see §4.5
  "finding": { },               // optional, see §4.6
  "intrusive": false            // an active/noisy check; a passive scan skips it
}
```

A check must have **`detect` or `finding`** (both is fine). Without them it
reports nothing and is rejected.

The `id` must be **stable**: on a second run of the converter the same check
must get the same `id`, otherwise every regeneration breeds duplicates instead
of updating. For NSE the natural source is the script filename, plus a suffix
when one script yields several checks.

### 4.1 `match` — when the check applies

Decided without the network, from what is already known about the target.

| Field | Meaning |
|---|---|
| `service` | the protocol as routing understands it: `"http"`, `"ssh"`, `"smtp"`… Banner-oriented: a service on a non-standard port counts too |
| `ports` | candidate ports, for when the set of open ports is unknown |
| `any_port_open` | requires at least one of these ports to be known open |
| `os_any` | an OS constraint: substrings, case-insensitive |

**At least one of `service`, `ports`, `any_port_open` is required.** A check
with no precondition would be offered to every host.

Ports are 1..65535.

> NSE: `portrule = shortport.http` → `{"service": "http"}`;
> `portrule = shortport.port_or_service(21, "ftp")` → `{"service": "ftp", "ports": [21]}`;
> a `hostrule` with no ports usually means the check is not about a service —
> more often than not, that does not convert.

### 4.2 `steps` — the exchange

An ordered list, **1 to 8 entries**. More than that is logic, and logic belongs
in a script. A step sets exactly **one** transport field.

```jsonc
{ "http": { "method": "GET", "path": "/x", "headers": {"X-A": "b"}, "port": 8443, "tls": true } }
{ "http": { "paths": ["/a", "/b", "/c"] } }
{ "tcp":  { "send_b64": "UElORw==", "recv_max": 512, "recv_until": "\n", "port": 7788 } }
{ "udp":  { "send_b64": "UElORw==", "recv_max": 256, "port": 161 } }
{ "tls":  { "send_b64": "", "recv_until": "\n", "port": 443 } }
```

**HTTP:**
- `path` is required (or `paths`), and **must start with `/` or `?`** — a
  relative path would go to another host.
- `paths` — "any one of them proves it"; **single-step checks only**, up to
  256 entries. For dependent steps "any one of" makes no sense.
- `method` defaults to `GET`. Always allowed: **`GET`, `HEAD`, `OPTIONS`,
  `TRACE`**. Only with `"intrusive": true`: **`POST`**. `PUT`, `DELETE`,
  `PATCH`, `CONNECT` are **always rejected**.
- `tls`: `true` means https, `false` means http, absent lets the port's banner
  decide.
- `port`: 0 or absent means use the target's web ports.

**Byte transports:** `send_b64` is the payload in base64; **an empty string
means grab the banner** (open the port and read whatever it says).
`recv_max` is 0..1048576. `recv_until` reads up to a delimiter.
With `tls` the reply additionally carries certificate fields.

### 4.3 `expect` — what proves it

Required in every step. **An empty `expect` is rejected**: a check that asserts
nothing would fire on every host — the worst defect an imported pack can have.

| Field | Meaning |
|---|---|
| `status` | acceptable HTTP statuses. **Absent means 2xx only** |
| `body_any` | any one of these substrings (case-sensitive) |
| `body_all` | all of these substrings |
| `require_ci` | all of these substrings, **case-insensitively** — product anchors |
| `header` | a **list** of header tests (not an object!) |
| `bytes_at` | `{"offset": 0, "b64": "…"}` — bytes at an offset, for binary protocols |
| `re` | regular expressions over the body (RE2) |
| `not` | a nested assertion that must **not** hold; nesting up to 3 |

A header test:
```jsonc
{"name": "Server", "contains": "nginx"}   // present and contains
{"name": "Server", "equals": "nginx"}     // present and equal (case-insensitive)
{"name": "Server", "re": "nginx/([0-9.]+)"} // present and matches (case-sensitive)
{"name": "X-Frame-Options"}               // merely present
{"name": "X-Frame-Options", "absent": true} // absent
```
`absent` together with a value is an error.

**About the 2xx default.** This is the single most important rule against false
positives: an error page routinely carries the server version, footer text or
the requested path itself, and a weak marker matched against a 404 is the
classic false positive. If a check genuinely needs a 401 or a 403, write
`"status": [401]`.

**Regular expressions are RE2, without backtracking.** Back-references (`\1`)
and lookahead/lookbehind (`(?=`, `(?!`, `(?<=`) are **not supported**. The
converter must recognise them and drop the check rather than emit a pack that
will not compile.

### 4.4 `capture` and `{{name}}` — carrying a value into the next step

```jsonc
"capture": [{"as": "tok", "from": "body", "re": "value=\"([a-f0-9]+)\""}]
```
Then in the next step: `"path": "/api?csrf={{tok}}"`.

- `as` — `^[a-z0-9_]+$`, unique within the pack.
- `from` — `"body"` (the default) or `"header"` (which then needs `header`).
- `re` — exactly **one** capturing group.
- A placeholder may only refer to something an **earlier** step defined.
- If the capture did not match, the check stops rather than sending a request
  with a hole in it.

### 4.5 `detect` — product and version

```jsonc
"detect": {
  "product": "nginx",
  "version": {"from": "header", "header": "Server", "re": "nginx/([0-9.]+)"}
}
```

**This is worth more than a finding, and for an NSE converter it is the main
goal.** The check reports only what it saw; from there the scanner's own data
produces the identification, every known CVE for that version (with EPSS and
CISA KEV marks) and the end-of-life record. One reliable version extraction is
worth twenty checks asserting "vulnerable, because the page exists".

- `product` is required and must match the canonical spelling in the scanner's
  database (`nginx`, `openssh`, `apache`…).
- `version.from` — `"body"` (the default), `"header"`, `"capture"`.
  `"capture"` needs `name` and no regexp; the others need an `re` with
  **one** group.
- `version` may be omitted — then it is the observation "the product is here",
  which still goes into the inventory.

> NSE: anything that does `port.version.product` / `port.version.version` or
> `nmap.set_port_version` is a direct candidate for `detect`.

### 4.6 `finding` — what to report

```jsonc
"finding": {
  "title":       "…",            // required
  "severity":    "high",         // critical | high | medium | low | info
  "risk":        7,              // 0..9, legacy scale; fills severity when it is empty
  "cvss":        8.1,            // 0..10
  "cvss_vector": "CVSS:3.1/…",
  "cves":        ["CVE-2024-6387"],
  "cwes":        ["CWE-200"],
  "description": "…",
  "remediation": "…",
  "audit_id":    "chk-…",        // a reference to the catalogue entry, if there is one
  "fingerprint": "…",            // what to deduplicate by between scans
  "verified":    true            // see below
}
```

**`verified`** asserts that the vulnerable behaviour was **observed**, not
inferred from a version. Setting `true` on a check whose last step can only
find a bare substring is **a compile error**. This is not a formality:
distributions backport fixes without changing version numbers, so a version
match means "possibly affected", and a loose match must not pose as
confirmation. Leave the field empty and the scanner will derive the value
itself from how specific the match was.

**`fingerprint`** matters when the source being converted already produced
findings for users: set the same value as before and existing findings keep
matching instead of surfacing as duplicates after the migration.

---

## 5. Every compiler refusal

Worth checking all of these in the converter, so as not to emit a pack that
falls apart on load. The list is verbatim.

**Pack level**
```
checkpack: pack has no source
checkpack: unsupported api %d (this build understands 1)
checkpack: plugin id %q is not a valid id
checkpack: plugin %q has no name
checkpack: plugin %q default port %d out of range
checkpack: plugin %q has an invalid params schema
```

**Check level**
```
check api %d is not supported
check has no match precondition (service, ports or any_port_open)
match port %d out of range
check has no steps
check has %d steps, the limit is 8
check reports neither a finding nor a detection
```

**Steps and transport**
```
a step must set exactly one transport, found %d
an http step needs a path
path %q must start with / or ?
alternative paths are only valid on a single-step check
%d paths, the limit is 256
method %s is not available to a declarative check
method %s requires the check to declare itself intrusive
a request header has no name
port %d out of range
recv_max %d is out of range (0..1048576)
send_b64 is not valid base64: …
```

**Assertions**
```
an expectation that asserts nothing would match every reply
an empty marker matches every reply
an inverted expectation asserts nothing
inverted expectations nest deeper than 3
the final step asserts only a status, which cannot support a finding
status %d is not an http status
a header test has no name
header %q asserts absence and a value at once
header %q regexp %q: …
expect regexp %q: …
bytes_at has no bytes to compare
bytes_at offset %d is negative
bytes_at b64: …
```

**Captures and extraction**
```
capture name %q must match ^[a-z0-9_]+$
capture %q is defined twice in one step
capture %q is already defined by an earlier step
capture %q: from %q is not body or header
capture %q reads a header but names none
regexp %q has %d capturing groups, need exactly 1
%s references capture %q, which no earlier step defines
version from %q is not body, header or capture
version from %s needs a regexp
version reads a header but names none
version reads capture %q, which no step defines
detect: no product
```

**Finding**
```
finding has no title
finding severity %q is not a valid level
finding risk %d is outside the 0–9 scale
finding cvss %.1f is out of range
finding claims verified but the final step can only match a bare substring
```

A dropped check **does not fail the pack**: the rest still loads, and the
reason is printed to the startup log and shown by the `packcheck` tool.

---

## 6. Limits and allowed values — a summary

| What | Value |
|---|---|
| format version | `api: 1` |
| steps per check | 1..8 |
| alternative paths | up to 256, single-step only |
| `not` nesting depth | up to 3 |
| `recv_max` | 0..1 048 576 |
| ports | 1..65535 |
| `plugin.id` | `^[a-z0-9][a-z0-9._-]*$` |
| `check.id` | `^[A-Za-z0-9][A-Za-z0-9._-]*$` |
| capture name | `^[a-z0-9_]+$` |
| severity | `critical`, `high`, `medium`, `low`, `info` |
| risk | 0..9 |
| cvss | 0..10 |
| HTTP methods | `GET`/`HEAD`/`OPTIONS`/`TRACE`; `POST` only when `intrusive`; the rest forbidden |
| pack size | up to 256 MB uncompressed |
| regular expressions | RE2 — no backtracking, no lookaround, no back-references |

---

## 7. Where a check lands: the sweep or its own row

This affects how findings look in the interface, and a converter does well to
understand the rule.

**A single-step HTTP check using GET** goes into the shared web sweep: it
fetches each distinct path **once per endpoint** and compares that reply
against every check referring to it. This is cheap — a thousand checks on one
path cost one request — but they share a catalogue row (`cgi`), and the origin
badge on findings will read "built-in" rather than your source name. Checks
like that can be switched off through the sweep's `disabled_sources` setting,
by source name.

**Everything else** — a byte transport, several steps, a method other than GET
— gets **its own catalogue row** from your pack, with its own toggle, settings
and origin badge.

The reasons a check does not join the sweep are printed verbatim:
```
it has no step to run
it has several steps, which cannot share one fetched reply
it is not an HTTP check
the sweep issues GET only, and this check asks for <METHOD>
```

---

## 8. Mapping NSE onto the format

A guide, not an exhaustive table.

| NSE construct | Becomes |
|---|---|
| `portrule = shortport.http` | `match.service = "http"` |
| `shortport.port_or_service(N, "svc")` | `match.ports = [N]`, `match.service = "svc"` |
| `shortport.version_port_or_service(...)` | the same; the version comes through `detect` |
| `http.get(host, port, "/path")` | an `http` step with `path` |
| several `http.get` calls over a list of paths | `paths`, when the result is "any one proves it" |
| `socket:send(payload)` + `socket:receive()` | a `tcp` step with `send_b64` |
| open the port and read | `tcp` with an empty `send_b64` (banner grab) |
| `string.match(body, "pat")` | `expect.re` (translate the Lua pattern into RE2!) |
| `string.find(body, "lit", 1, true)` | `expect.body_any` |
| a check on a response header | `expect.header[...]` |
| `nmap.set_port_version` / `port.version.*` | **`detect`** |
| `stdnse.output_table` with a description | `finding` |
| the `safe`/`discovery`/`version` categories | usually convertible |
| the `intrusive`, `brute`, `exploit`, `dos`, `vuln` categories with exploitation | **drop them**; the format deliberately only observes |
| `nmap.registry`, global state between scripts | does not convert |
| loops, branches, computation | does not convert |

**Lua patterns ≠ regular expressions.** `%d`, `%s`, `%w`, `-` as a lazy
quantifier, classes like `%a` — all of it has to be translated into RE2 syntax
(`[0-9]`, `\s`, `\w`, `*?` and so on). What cannot be translated is a reason to
drop the check with a clear explanation, not to emit a broken regexp.

**Quality over quantity.** A translated check that looks for a bare substring
such as `"login"` on any 200 page is harmful: it will produce a stream of false
findings and undermine trust in the whole pack. Rules worth building into a
converter:
- if a marker is shorter than ~8 characters and not unique — add a product
  anchor in `require_ci`, or drop the check;
- never set `verified: true` automatically;
- do not invent a `severity` — if NSE has none, use `info` or derive it from
  the category.

---

## 9. How to verify the result

The scanner ships an author's tool that needs no key, no network and no
running scanner:

```bash
go run ./backend/cmd/packcheck <pack.json>            # does it compile, what was accepted and what dropped
go run ./backend/cmd/packcheck -v <pack.json>         # the plan of each check: when, what it sends, what it asserts
go run ./backend/cmd/packcheck -strict <pack.json>    # non-zero exit if anything was dropped
go run ./backend/cmd/packcheck -target 127.0.0.1 -ports 80,443 <pack.json>   # a live run
```

Typical output:
```
  source:   nse (version 1, api 1)
  plugin:   pack-nse — "NSE converted checks"
  checks:   412 accepted, 7 dropped
  runs as:  380 check(s) inside the CGI sweep (catalog row "cgi"), 32 under this pack's own row "pack-nse"
```

**`-strict` belongs in the converter's CI.** Then a regression in generation
fails immediately instead of turning up when a user loads the pack.

For anyone without that CLI, the NSE converter carries the same rules:
`nse2checkpack --check <pack.json>` reports what the scanner will accept, drop
and why, and `--check -v` prints the plan of each check. It is a
reimplementation of the rules published here, so the compiler shipped with the
application stays the authority.

A live run (`-target`) is the only way to see not just "it compiles" but "it
fires where it should and stays quiet where it should not". Stand up a
reference service and run against it.

---

## 10. Installing a finished pack

Two ways for the user, both without a signature, because a pack does not
execute:

1. **Your own folder.** Settings → Sources → Add source → "A folder of my own",
   then give an absolute path. Every `*.json` **directly** in that folder is
   read at every startup. Subdirectories are not walked.
2. **The scanner's data directory.** Put the file in `<data>/probes/`. The path
   is shown in the same sources panel.

In both cases **packs are read once, at startup**: a scanner already running
will not pick up a new file.

The source name inside the pack (`"source"`) is what the user sees on findings
and what lets them switch the whole set off at once. The folder only says
**where** to look; **whose** pack it is is said by the pack.

---

## 11. What the converter must produce besides the pack

1. **The pack** (or several: splitting by NSE category is sensible, so that a
   user can enable and disable groups — one pack is one catalogue row).
2. **A report of what was not translated**: the script identifier, the reason,
   and which class it falls into (logic / exploitation / state / untranslatable
   pattern). This is not a side detail: it is what shows the real coverage.
3. **Stable `id`s** between runs — otherwise every pack update looks like a
   wholesale replacement of the check set.
4. A monotonic pack `version`: a higher number replaces a lower one.

---

## 12. What the format does not do — deliberately

These are boundaries, not gaps:

- there is no field that writes to the target;
- there is no state-changing method unless the check declares itself
  `intrusive` (and even then it is only `POST`);
- an address other than the target being scanned cannot be reached;
- there is no code execution — a pack is data, which is why it is accepted
  without a signature.

If a check being converted needs any of the above, it should not become a pack.
Either it is a candidate for the second-level script SDK (code there, with a
signature and explicit operator consent), or it does not need porting at all.
