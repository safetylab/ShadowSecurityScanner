"""Building check-pack checks out of a parsed NSE script.

Only the shapes listed in §2 and §8 of the specification are translated: one
exchange with the target (or two, when the second depends on a value from the
first) and a match on the reply. Everything else is a boundary of the format,
not a gap in the converter, so a script is never "translated as best we can" —
it is refused, with the reason and class that go into the report (§11.2).

The subtlest part of the parse is **the sense of a condition**. In Lua the early
return ``if not string.match(body, "x") then return end`` means that ``x`` is
required, while ``if string.match(body, "x") then return end`` means it is
forbidden. Mixing the two emits a check asserting the exact opposite of the
script it came from — and it will compile and report findings quite happily.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

from .lua import call_args, mask, statement_start
from .luapat import Translated, Untranslatable, translate
from .parser import NseScript

__all__ = ["Skip", "Built", "convert", "KIND_LOGIC", "KIND_EXPLOIT", "KIND_STATE",
           "KIND_PATTERN", "KIND_ROUTING", "KIND_WEAK", "KIND_BUG", "DEFAULT_MIN_MARKER"]

KIND_LOGIC = "logic"
KIND_EXPLOIT = "exploitation"
KIND_STATE = "state"
KIND_PATTERN = "untranslatable pattern"
KIND_ROUTING = "routing"
KIND_WEAK = "weak assertions"
KIND_BUG = "generation error"

HOSTILE_CATEGORIES = {
    "brute": "brute category — credential guessing",
    "exploit": "exploit category — exploitation",
    "dos": "dos category — denial of service",
    "malware": "malware category — needs state and heuristics",
    "fuzzer": "fuzzer category — payload generation",
}

HTTP_SERVICES = {"http", "https", "http-alt", "https-alt", "http-proxy", "www"}

# Evidence shorter than this, without a second piece or a product anchor, gives a
# flood of false positives (§8: a short, non-unique marker — anchor it or drop it).
DEFAULT_MIN_MARKER = 8

RECEIVER = r"[A-Za-z_][A-Za-z_0-9.]*(?:\[[^\]\n]*\])*"
_CALL = re.compile(r"(?<![A-Za-z_0-9.])(" + RECEIVER + r")([.:])([A-Za-z_][A-Za-z_0-9]*)\s*\(")
_ID = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*$")
_HEADER_RECEIVER = re.compile(r"""^([A-Za-z_]\w*)\.header\s*\[\s*['"]([^'"]+)['"]\s*\]$""")
_RECV_MAX = 2048


@dataclass
class Skip:
    script: str
    reason: str
    kind: str
    script_candidate: bool = False

    def as_dict(self) -> dict:
        return {"script": self.script, "reason": self.reason, "kind": self.kind,
                "script_candidate": self.script_candidate}


@dataclass
class Built:
    checks: list[dict] = field(default_factory=list)
    skips: list[Skip] = field(default_factory=list)
    transports: set[str] = field(default_factory=set)


@dataclass
class _Match:
    service: str | None = None
    ports: list[int] = field(default_factory=list)
    proto: str = "tcp"
    is_http: bool = False


@dataclass
class _Exchange:
    kind: str                       # http | tcp | udp
    var: str | None = None
    path: str | None = None
    paths: list[str] = field(default_factory=list)
    method: str = "GET"
    payload: bytes = b""
    pos: int = 0
    capture: dict | None = None     # {"as", "from", "re"} — capture taken in this step
    path_span: tuple[int, int] | None = None   # where the path is written in the script


@dataclass
class _Assertion:
    target: str                     # body | header
    header: str | None = None
    pattern: str | None = None      # the translated RE2 expression
    literal: str | None = None      # a verbatim substring
    negated: bool = False
    strength: int = 0               # length of the longest verbatim run


# ------------------------------------------------------------------- helpers


def _calls(s: NseScript, lo: int | None = None, hi: int | None = None) -> list[tuple]:
    """(name, receiver, separator, method, start, args) over the body of action."""
    lo = s.action_lo if lo is None else lo
    hi = s.action_hi if hi is None else hi
    out = []
    for m in _CALL.finditer(s.masked, lo, hi):
        receiver = s.text[m.start(1):m.end(1)]      # original: the mask blanks strings
        sep, method = m.group(2), m.group(3)
        open_idx = m.end() - 1
        args, close = call_args(s.text, s.masked, open_idx)
        if close < 0:
            continue
        out.append((receiver + sep + method, receiver, sep, method, m.start(),
                    tuple(args), close))
    return out


def _literal_rhs(s: NseScript, offset: int) -> str | None:
    """A string literal starting right after ``offset`` (whitespace allowed)."""
    for lit in s.strings:
        if lit.start >= offset and s.text[offset:lit.start].strip() == "":
            return lit.value
    return None


def _resolve_string(s: NseScript, span: tuple[int, int]) -> str | None:
    """An argument's value: a literal, or a local variable that holds one."""
    literal = s.literal_at(*span)
    if literal is not None:
        return literal
    name = s.text[span[0]:span[1]].strip()
    if not _ID.match(name):
        return None
    pattern = re.compile(r"(?:local\s+)?" + re.escape(name) + r"\s*=\s*")
    for m in pattern.finditer(s.action_masked):
        value = _literal_rhs(s, s.action_lo + m.end())
        if value is not None:
            return value
    return None


def _assigned_names(s: NseScript, call_start: int) -> list[str]:
    head = s.text[statement_start(s.masked, call_start):call_start]
    m = re.search(r"(?:local\s+)?([A-Za-z_][\w,\s]*?)\s*=\s*$", head)
    return [n.strip() for n in m.group(1).split(",") if n.strip()] if m else []


def _response_var(s: NseScript, call_start: int, prefer_second: bool) -> str | None:
    names = _assigned_names(s, call_start)
    if not names:
        return None
    return names[1] if prefer_second and len(names) >= 2 else names[0]


def _is_guard(s: NseScript, close_idx: int) -> bool:
    """``if … then return end`` — the early return that inverts the sense.

    ``if … then return <value> end`` is not an early return: it is the branch that
    reports a result, and its condition reads straight.
    """
    line_end = s.masked.find("\n", close_idx)
    line_end = len(s.masked) if line_end < 0 else line_end
    m = re.search(r"\bthen\b", s.masked[close_idx:line_end])
    if not m:
        return False                      # not a condition at all: assignment, call
    after = s.masked[close_idx + m.end():close_idx + m.end() + 240]
    body = re.match(r"\s*(return|break|goto)\b(.*)", after, re.S)
    if not body:
        return False
    if body.group(1) in ("break", "goto"):
        return True
    rest = body.group(2).split("\n", 1)[0].strip()
    return rest == "" or rest.startswith("end") or bool(re.match(r"(nil|false)\b", rest))


def _negated(s: NseScript, name_start: int, close_idx: int) -> bool:
    """True when the assertion belongs inside ``not``."""
    head = s.text[statement_start(s.masked, name_start):name_start]
    has_not = bool(re.search(r"\bnot\s*\(?\s*$", head))
    tail = s.text[close_idx + 1:close_idx + 20]
    is_nil = bool(re.match(r"\s*\)?\s*==\s*nil", tail))
    negative_test = has_not or is_nil
    return negative_test != _is_guard(s, close_idx)      # XOR


def _literal_strength(pattern: str) -> int:
    """Length of the longest verbatim run — a measure of how specific it is."""
    runs = re.split(r"[\\\[\](){}.*+?|^$]|\(\?s\)", pattern)
    return max((len(r) for r in runs), default=0)


# --------------------------------------------------------------------- portrule


def _read_match(s: NseScript) -> _Match | Skip:
    if not s.has_portrule:
        if s.has_hostrule:
            return Skip(s.name, "hostrule with no portrule: the check is not tied "
                                "to a service", KIND_ROUTING)
        return Skip(s.name, "the script has no portrule", KIND_ROUTING)

    rule = s.portrule
    masked_rule, _ = mask(rule)
    out = _Match()

    if re.search(r"shortport\.(http|ssl)\b", masked_rule):
        out.service, out.is_http = "http", True
        return out

    call = re.search(r"shortport\.(port_or_service|version_port_or_service|portnumber|"
                     r"service)\s*\(", masked_rule)
    if call:
        open_idx = call.end() - 1
        args, close = call_args(rule, masked_rule, open_idx)
        base = s.text.find(rule)
        for lo, hi in args[:3]:
            chunk = rule[lo:hi]
            literals = [lit.value for lit in s.strings
                        if base >= 0 and base + lo <= lit.start and lit.end <= base + hi]
            if literals:
                for value in literals:
                    low = value.strip().lower()
                    if low in ("tcp", "udp"):
                        out.proto = low
                    elif not out.service:
                        out.service = low
            else:
                numbers = [int(n) for n in re.findall(r"\b\d{1,5}\b", chunk)]
                if numbers and not out.ports:
                    out.ports = sorted({n for n in numbers if 1 <= n <= 65535})
    else:
        numbers = [int(n) for n in re.findall(r"port\.number\s*==\s*(\d+)", masked_rule)]
        if numbers:
            out.ports = sorted(set(numbers))
        svc = re.search(r"port\.service\s*==\s*", masked_rule)
        if svc:
            base = s.text.find(rule)
            if base >= 0:
                value = _literal_rhs(s, base + svc.end())
                if value:
                    out.service = value.lower()
        if re.search(r'port\.protocol\s*==\s*"udp"', rule):
            out.proto = "udp"

    if not out.service and not out.ports:
        return Skip(s.name, "portrule not recognised: %s" % " ".join(rule.split())[:80],
                    KIND_ROUTING)
    out.is_http = bool(out.service and out.service in HTTP_SERVICES)
    return out


# -------------------------------------------------------------------- exchange


def _read_exchanges(s: NseScript, match: _Match) -> list[_Exchange] | Skip:
    calls = _calls(s)
    if not calls:
        return Skip(s.name, "action makes no exchange with the target", KIND_STATE,
                    script_candidate=True)

    for name, receiver, sep, method, pos, args, close in calls:
        if receiver == "http" and method in ("post", "put", "delete"):
            return Skip(s.name, "the script changes the target's state (http.%s)"
                        % method, KIND_EXPLOIT)
        if receiver == "http" and method == "get_url":
            return Skip(s.name, "http.get_url fetches an arbitrary URL; the format "
                                "addresses the target only", KIND_STATE)

    http_calls = [c for c in calls if c[1] == "http" and c[3] in ("get", "head", "generic_request")]
    banner_calls = [c for c in calls if c[1] == "comm" and c[3] == "get_banner"]
    exchange_calls = [c for c in calls if c[1] == "comm" and c[3] == "exchange"]
    send_calls = [c for c in calls if c[2] == ":" and c[3] == "send"]
    recv_calls = [c for c in calls if c[2] == ":" and c[3].startswith("receive")]

    if sum(bool(x) for x in (http_calls, banner_calls, exchange_calls, send_calls)) > 1:
        return Skip(s.name, "action makes several different exchanges — that is "
                            "logic, not one request",
                    KIND_LOGIC, script_candidate=True)

    if http_calls:
        return _read_http(s, http_calls)

    proto = "udp" if match.proto == "udp" else "tcp"

    if banner_calls:
        call = banner_calls[0]
        return [_Exchange(kind=proto, var=_response_var(s, call[4], True), pos=call[4])]

    if exchange_calls:
        call = exchange_calls[0]
        payload = _resolve_string(s, call[5][2]) if len(call[5]) >= 3 else None
        if payload is None:
            return Skip(s.name, "the comm.exchange payload is computed, not a literal",
                        KIND_LOGIC, script_candidate=True)
        return [_Exchange(kind=proto, var=_response_var(s, call[4], True),
                          payload=payload.encode("latin-1", "replace"), pos=call[4])]

    if send_calls:
        if len(send_calls) > 1:
            return Skip(s.name, "several socket:send calls — a dependent exchange, "
                                "beyond what the format can do",
                        KIND_LOGIC, script_candidate=True)
        call = send_calls[0]
        payload = _resolve_string(s, call[5][0]) if call[5] else ""
        if payload is None:
            return Skip(s.name, "the socket:send payload is computed, not a literal",
                        KIND_LOGIC, script_candidate=True)
        var = _response_var(s, recv_calls[0][4], True) if recv_calls else None
        return [_Exchange(kind=proto, var=var, payload=payload.encode("latin-1", "replace"),
                          pos=call[4])]

    if recv_calls:
        call = recv_calls[0]
        return [_Exchange(kind=proto, var=_response_var(s, call[4], True), pos=call[4])]

    return Skip(s.name, "action makes no exchange with the target", KIND_STATE,
                script_candidate=True)


def _http_method(s: NseScript, call) -> tuple[str, int] | Skip:
    method = {"get": "GET", "head": "HEAD"}.get(call[3])
    if method:
        return method, 2
    literal = _resolve_string(s, call[5][2]) if len(call[5]) >= 3 else None
    if literal is None:
        return Skip(s.name, "the http.generic_request method is computed", KIND_LOGIC)
    return literal.upper(), 3


def _read_http(s: NseScript, http_calls: list) -> list[_Exchange] | Skip:
    exchanges: list[_Exchange] = []
    for call in http_calls:
        method_info = _http_method(s, call)
        if isinstance(method_info, Skip):
            return method_info
        method, path_idx = method_info
        if method not in ("GET", "HEAD", "OPTIONS", "TRACE"):
            return Skip(s.name, "method %s is not available to a declarative check"
                        % method, KIND_EXPLOIT)
        if len(call[5]) <= path_idx:
            return Skip(s.name, "the http request's path could not be read", KIND_LOGIC)
        exchanges.append(_Exchange(kind="http", method=method, pos=call[4],
                                   var=_response_var(s, call[4], False)))
        exchanges[-1].path = _resolve_string(s, call[5][path_idx])
        exchanges[-1].paths = [] if exchanges[-1].path else _loop_paths(s, call[5][path_idx])
        exchanges[-1].path_span = call[5][path_idx]

    if len(exchanges) == 1:
        one = exchanges[0]
        if one.path is None and not one.paths:
            return Skip(s.name, "the request path is computed, not a literal string",
                        KIND_LOGIC, script_candidate=True)
        if one.path is not None and not one.path.startswith(("/", "?")):
            return Skip(s.name, "path %r does not start with / or ?" % one.path, KIND_LOGIC)
        return exchanges

    if len(exchanges) == 2:
        chained = _chain_two(s, exchanges)
        if chained is not None:
            return chained
        return Skip(s.name, "two http requests, but the second does not use a value "
                            "from the first: 'any of them proves it' and a dependent "
                            "exchange cannot be told apart",
                    KIND_LOGIC, script_candidate=True)

    return Skip(s.name, "%d http requests in action — that is logic" % len(exchanges),
                KIND_LOGIC, script_candidate=True)


def _loop_paths(s: NseScript, path_span: tuple[int, int]) -> list[str]:
    """A list of paths: ``for _, p in ipairs({"/a", "/b"}) do http.get(…, p)``."""
    var = s.text[path_span[0]:path_span[1]].strip()
    if not _ID.match(var):
        return []
    for m in re.finditer(r"for\s+([\w\s,]+?)\s+in\s+i?pairs\s*\(\s*\{", s.action_masked):
        if var not in [n.strip() for n in m.group(1).split(",")]:
            continue
        brace = s.action_lo + m.end() - 1
        depth, end = 0, brace
        for i in range(brace, s.action_hi):
            if s.masked[i] == "{":
                depth += 1
            elif s.masked[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        values = s.literals_in(brace, end + 1)
        good = [v for v in values if v.startswith(("/", "?"))]
        if good and len(good) == len(values):
            return good[:256]
    return []


def _chain_two(s: NseScript, exchanges: list[_Exchange]) -> list[_Exchange] | None:
    """The second request substitutes a value from the first — ``capture`` + ``{{name}}``."""
    first, second = exchanges
    if first.path is None or not first.path.startswith(("/", "?")):
        return None
    span = second.path_span
    if span is None:
        return None
    expr = s.text[span[0]:span[1]].strip()
    if ".." not in expr:
        return None

    parts: list[str] = []
    used: set[str] = set()
    offset = 0
    for raw in expr.split(".."):
        lo = span[0] + s.text[span[0]:span[1]].find(raw, offset)
        hi = lo + len(raw)
        offset += len(raw) + 2
        piece = raw.strip()
        literal = s.literal_at(lo, hi)
        if literal is not None:
            parts.append(literal)
            continue
        if not _ID.match(piece):
            return None
        capture = _capture_for(s, first, piece)
        if capture is None:
            return None
        used.add(capture["as"])
        first.capture = capture
        parts.append("{{%s}}" % capture["as"])

    path = "".join(parts)
    if not path.startswith(("/", "?")) or not used:
        return None
    second.path = path
    return [first, second]


def _capture_for(s: NseScript, first: _Exchange, var: str) -> dict | None:
    """``local tok = string.match(resp.body, "…(…)…")`` → the ``capture`` field."""
    if not first.var:
        return None
    aliases = _body_aliases(s, first.var)
    for name, receiver, sep, method, pos, args, close in _calls(s):
        if method not in ("match", "find"):
            continue
        if var not in _assigned_names(s, pos):
            continue
        if receiver == "string":
            if len(args) < 2:
                continue
            target, pat_span = s.text[args[0][0]:args[0][1]].strip(), args[1]
        elif sep == ":":
            target, pat_span = receiver, args[0] if args else None
        else:
            continue
        if pat_span is None:
            continue
        header = _HEADER_RECEIVER.match(target)
        if target not in aliases and not (header and header.group(1) == first.var):
            continue
        pattern = s.literal_at(*pat_span)
        if pattern is None:
            continue
        try:
            translated = translate(pattern)
        except Untranslatable:
            return None
        if translated.groups != 1:
            return None
        name_clean = re.sub(r"[^a-z0-9_]", "", var.lower()) or "tok"
        capture = {"as": name_clean, "re": translated.pattern}
        if header:
            capture["from"] = "header"
            capture["header"] = header.group(2).lower()
        return capture
    return None


# ----------------------------------------------------------------- assertions


def _body_aliases(s: NseScript, var: str) -> set[str]:
    names = {var, var + ".body", var + ".rawbody", var + ".raw"}
    for m in re.finditer(r"local\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_][\w.]*)", s.action_masked):
        if m.group(2) in names:
            names.add(m.group(1))
    return names


def _read_assertions(s: NseScript,
                     exchange: _Exchange) -> tuple[list[_Assertion], list[str]]:
    if not exchange.var:
        return [], []
    aliases = _body_aliases(s, exchange.var)
    found: list[_Assertion] = []
    rejected: list[str] = []

    for name, receiver, sep, method, pos, args, close in _calls(s):
        if method not in ("match", "find"):
            continue
        if receiver == "string":
            if len(args) < 2:
                continue
            target = s.text[args[0][0]:args[0][1]].strip()
            pat_span, rest = args[1], args[2:]
        elif sep == ":":
            if not args:
                continue
            target, pat_span, rest = receiver, args[0], args[1:]
        else:
            continue

        header_name = None
        header = _HEADER_RECEIVER.match(target)
        if header and header.group(1) == exchange.var:
            header_name = header.group(2).lower()
        elif target not in aliases:
            continue

        pattern = s.literal_at(*pat_span)
        if pattern is None:
            continue
        negated = _negated(s, pos, close)
        plain = any(s.text[a:b].strip() == "true" for a, b in rest)

        if plain:
            found.append(_Assertion(target="header" if header_name else "body",
                                    header=header_name, literal=pattern,
                                    negated=negated, strength=len(pattern)))
            continue
        try:
            translated: Translated = translate(pattern)
        except Untranslatable as exc:
            rejected.append("%s: %s" % (pattern, exc))
            continue
        found.append(_Assertion(target="header" if header_name else "body",
                                header=header_name, pattern=translated.pattern,
                                negated=negated,
                                strength=_literal_strength(translated.pattern)))
    return found, rejected


def _read_statuses(s: NseScript, exchange: _Exchange) -> list[int]:
    """``resp.status == 200`` and ``resp.status ~= 200 then return`` → status list."""
    if not exchange.var or exchange.kind != "http":
        return []
    statuses: set[int] = set()
    pattern = re.compile(re.escape(exchange.var) + r"\.status\s*(==|~=)\s*(\d{3})")
    for m in pattern.finditer(s.action_masked):
        op, code = m.group(1), int(m.group(2))
        guard = _is_guard(s, s.action_lo + m.end() - 1)
        # `status ~= 200 then return end` — the status is required;
        # `status == 200 then <report>`   — the status is required;
        # `status == 404 then return end` — forbidden, which the format cannot say.
        if (op == "~=" and guard) or (op == "==" and not guard):
            statuses.add(code)
    return sorted(statuses)


def _read_header_presence(s: NseScript, exchange: _Exchange) -> list[dict]:
    if not exchange.var or exchange.kind != "http":
        return []
    tests: list[dict] = []
    pattern = re.compile(re.escape(exchange.var) + r"\.header\s*\[")
    for m in pattern.finditer(s.action_masked):
        name = _literal_rhs(s, s.action_lo + m.end())
        if not name:
            continue
        start = s.action_lo + m.start()
        tail = s.text[s.action_lo + m.end():s.action_lo + m.end() + 200]
        if re.match(r"[^\n]*\]\s*[:.](match|find)\s*\(", tail):
            continue                       # the value is _read_assertions' business
        close = s.text.find("]", s.action_lo + m.end())
        test = {"name": name.lower()}
        if _negated(s, start, close):
            test["absent"] = True
        if test not in tests:
            tests.append(test)
    names_present = {t["name"] for t in tests if not t.get("absent")}
    return [t for t in tests if not (t.get("absent") and t["name"] in names_present)]


# ----------------------------------------------------------------------- detect


def _read_detect(s: NseScript, exchanges: list[_Exchange],
                 products: dict[str, str]) -> dict | None:
    product = None
    for field_name in ("product", "name"):
        m = re.search(r"port\.version\.%s\s*=\s*" % field_name, s.action_masked)
        if m:
            value = _literal_rhs(s, s.action_lo + m.end())
            if value:
                product = value.strip()
                break
    if not product:
        return None

    detect: dict = {"product": products.get(product.lower(), product.lower())}
    m = re.search(r"port\.version\.version\s*=\s*([^\n]+)", s.action_masked)
    if not m:
        return detect

    last = exchanges[-1]
    rhs_lo, rhs_hi = s.action_lo + m.start(1), s.action_lo + m.end(1)
    version = _version_from(s, last, s.text[rhs_lo:rhs_hi].strip(), rhs_lo, rhs_hi)
    if version:
        detect["version"] = version
    return detect


def _version_from(s: NseScript, exchange: _Exchange, rhs: str,
                  lo: int, hi: int) -> dict | None:
    found = _match_call_in(s, lo, hi)
    if found is None and _ID.match(rhs):
        assign = re.search(r"(?:local\s+)?" + re.escape(rhs) + r"\s*=\s*", s.action_masked)
        if assign:
            stmt_lo = s.action_lo + assign.end()
            nl = s.text.find("\n", stmt_lo)
            found = _match_call_in(s, stmt_lo, nl if nl > 0 else hi)
    if found is None:
        return None
    pattern, header_name = found
    try:
        translated = translate(pattern)
    except Untranslatable:
        return None
    if translated.groups != 1:
        return None
    if header_name:
        return {"from": "header", "header": header_name, "re": translated.pattern}
    return {"from": "body", "re": translated.pattern}


def _match_call_in(s: NseScript, lo: int, hi: int) -> tuple[str, str | None] | None:
    for name, receiver, sep, method, pos, args, close in _calls(s, lo, hi):
        if method not in ("match", "find"):
            continue
        if receiver == "string":
            if len(args) < 2:
                continue
            target, pat_span = s.text[args[0][0]:args[0][1]].strip(), args[1]
        elif sep == ":":
            target, pat_span = receiver, args[0] if args else None
        else:
            continue
        if pat_span is None:
            continue
        pattern = s.literal_at(*pat_span)
        if pattern is None:
            continue
        header = _HEADER_RECEIVER.match(target)
        return pattern, header.group(2).lower() if header else None
    return None


# --------------------------------------------------------------- check assembly


def _check_id(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", name).strip("-") or "check"
    return cleaned if re.match(r"^[A-Za-z0-9]", cleaned) else "nse-" + cleaned


def _first_sentence(text: str, limit: int = 120) -> str:
    text = " ".join(text.split())
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    head = (m.group(1) if m else text)[:limit]
    return head.rstrip(" .,;:")


def _title(s: NseScript) -> str:
    sentence = _first_sentence(s.description)
    if sentence:
        return sentence
    pretty = s.name.replace("-", " ").replace("_", " ").strip()
    return (pretty[:1].upper() + pretty[1:]) if pretty else s.name


def _description(s: NseScript, limit: int = 600) -> str:
    text = " ".join(s.description.split())
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0] + "…"
    tail = "Ported from the Nmap NSE script %s.nse." % s.name
    return (text + " " + tail).strip() if text else tail


def _dedup(items: list) -> list:
    out: list = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


def _expect_from(assertions: list[_Assertion], statuses: list[int],
                 header_tests: list[dict]) -> dict:
    expect: dict = {}
    body_all, res, headers = [], [], list(header_tests)
    neg_literals, neg_res = [], []

    for a in assertions:
        if a.header:
            if a.pattern:
                headers.append({"name": a.header, "re": a.pattern})
            elif a.literal:
                headers.append({"name": a.header, "contains": a.literal})
            continue
        if a.negated:
            (neg_literals if a.literal else neg_res).append(a.literal or a.pattern)
        elif a.literal:
            body_all.append(a.literal)
        elif a.pattern:
            res.append(a.pattern)

    if statuses:
        expect["status"] = statuses
    if body_all:
        expect["body_all"] = _dedup(body_all)
    if res:
        expect["re"] = _dedup(res)
    if headers:
        valued = {h["name"] for h in headers if set(h) - {"name"}}
        expect["header"] = _dedup([h for h in headers
                                   if set(h) - {"name"} or h["name"] not in valued])
    inverted: dict = {}
    if neg_literals:
        inverted["body_any"] = _dedup(neg_literals)
    if neg_res:
        inverted["re"] = _dedup(neg_res)
    if inverted:
        expect["not"] = inverted
    return expect


def _evidence_problem(expect: dict, assertions: list[_Assertion], anchor: str | None,
                      min_marker: int, structural: bool) -> str | None:
    """Is the assertion specific enough not to match every reply (§8)."""
    positive = [a for a in assertions if not a.negated]
    if structural or len(positive) >= 2:
        return None
    if any(a.strength >= min_marker for a in positive):
        return None
    if expect.get("header") or expect.get("bytes_at"):
        return None
    if anchor:
        expect["require_ci"] = [anchor]
        return None
    if not positive:
        return "no assertion about the reply body could be read from action"
    return ("the only evidence is shorter than %d characters and there is no product "
            "anchor — the check would match every reply" % min_marker)


def convert(s: NseScript, products: dict[str, str] | None = None,
            min_marker: int = DEFAULT_MIN_MARKER) -> Built:
    """A script becomes either one check or a refusal with a reason and a class."""
    products = products or {}
    built = Built()

    for category, why in HOSTILE_CATEGORIES.items():
        if category in s.categories:
            built.skips.append(Skip(s.name, why, KIND_EXPLOIT))
            return built

    if s.action_lo < 0:
        built.skips.append(Skip(s.name, "the script has no action", KIND_STATE))
        return built

    match = _read_match(s)
    if isinstance(match, Skip):
        built.skips.append(match)
        return built

    exchanges = _read_exchanges(s, match)
    if isinstance(exchanges, Skip):
        built.skips.append(exchanges)
        return built

    detect = _read_detect(s, exchanges, products)
    anchor = detect["product"] if detect else None

    steps: list[dict] = []
    rejected_patterns: list[str] = []
    all_assertions: list[_Assertion] = []

    for idx, exchange in enumerate(exchanges):
        capture = exchange.capture
        assertions, rejected = _read_assertions(s, exchange)
        rejected_patterns.extend(rejected)
        all_assertions.extend(assertions)
        statuses = _read_statuses(s, exchange)
        header_tests = _read_header_presence(s, exchange)
        expect = _expect_from(assertions, statuses, header_tests)

        if capture and not {k for k in expect if k != "status"}:
            # A step that only takes a value still has to assert something.
            expect["re"] = [capture["re"]]

        step: dict = {}
        if exchange.kind == "http":
            http: dict = {}
            if exchange.method != "GET":
                http["method"] = exchange.method
            if exchange.paths:
                http["paths"] = exchange.paths
            else:
                http["path"] = exchange.path
            step["http"] = http
        else:
            conn: dict = {"send_b64": base64.b64encode(exchange.payload).decode("ascii")
                          if exchange.payload else "", "recv_max": _RECV_MAX}
            step[exchange.kind] = conn
        step["expect"] = expect
        if capture:
            step["capture"] = [capture]
        steps.append(step)

    # Evidence counts as structural when the check is narrow even without a long
    # marker: several steps, a captured value, or a byte exchange on a specific
    # port (as opposed to a GET of an arbitrary path).
    structural = (len(steps) > 1
                  or any("capture" in step for step in steps)
                  or (exchanges[0].kind != "http" and bool(match.ports)))
    final_expect = steps[-1]["expect"]
    problem = _evidence_problem(final_expect, all_assertions, anchor, min_marker, structural)
    if problem:
        if rejected_patterns and not all_assertions:
            built.skips.append(Skip(s.name, "the Lua pattern has no RE2 equivalent: %s"
                                    % rejected_patterns[0], KIND_PATTERN))
        else:
            built.skips.append(Skip(s.name, problem, KIND_WEAK, script_candidate=True))
        return built

    check: dict = {"id": _check_id(s.name), "match": {}, "steps": steps}
    if match.service:
        check["match"]["service"] = match.service
    if match.ports:
        check["match"]["ports"] = match.ports
        if exchanges[0].kind != "http":
            check["match"]["any_port_open"] = match.ports
    if "intrusive" in s.categories:
        check["intrusive"] = True
    if detect:
        check["detect"] = detect
    if not detect or "vuln" in s.categories:
        finding: dict = {"title": _title(s), "severity": "medium" if "vuln" in s.categories
                         else "info", "description": _description(s)}
        if s.cves:
            finding["cves"] = s.cves
        if s.cwes:
            finding["cwes"] = s.cwes
        check["finding"] = finding
        # verified is never claimed (§8): confirmation cannot be inferred from the
        # fact that the script printed something.

    built.checks.append(check)
    built.transports.add("udp" if exchanges[0].kind == "udp" else "tcp")
    for pattern in rejected_patterns:
        built.skips.append(Skip(s.name, "pattern dropped, the check was emitted "
                                "without it: %s"
                                % pattern, KIND_PATTERN))
    return built
