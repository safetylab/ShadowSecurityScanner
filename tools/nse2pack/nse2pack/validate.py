"""The check-pack compiler rules, carried over from §5 of the specification.

The converter runs every generated check through them before writing a pack: a
check dropped at load time quietly shrinks coverage while the pack still looks
complete. The messages are the ones the scanner prints, word for word, so that
this tool's output and ``packcheck``'s output read the same way.
"""

from __future__ import annotations

import base64
import binascii
import re

__all__ = [
    "PACK_FIELDS", "validate_pack", "validate_check", "unknown_fields",
    "route_of", "ROUTE_SWEEP", "ROUTE_OWN",
]

PACK_FIELDS = {"source", "version", "api", "plugin", "checks"}
PLUGIN_FIELDS = {"id", "name", "category", "protocols", "default_ports", "params_schema"}
CHECK_FIELDS = {"id", "api", "match", "steps", "detect", "finding", "intrusive"}
MATCH_FIELDS = {"service", "ports", "any_port_open", "os_any"}
STEP_FIELDS = {"http", "tcp", "udp", "tls", "expect", "capture"}
HTTP_FIELDS = {"method", "path", "paths", "headers", "port", "tls"}
BYTES_FIELDS = {"send_b64", "recv_max", "recv_until", "port"}
EXPECT_FIELDS = {"status", "body_any", "body_all", "require_ci", "header", "bytes_at", "re", "not"}
HEADER_FIELDS = {"name", "contains", "equals", "re", "absent"}
CAPTURE_FIELDS = {"as", "from", "re", "header"}
DETECT_FIELDS = {"product", "version"}
VERSION_FIELDS = {"from", "header", "re", "name"}
FINDING_FIELDS = {"title", "severity", "risk", "cvss", "cvss_vector", "cves", "cwes",
                  "description", "remediation", "audit_id", "fingerprint", "verified"}

PLUGIN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
CHECK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
CAPTURE_NAME = re.compile(r"^[a-z0-9_]+$")
PLACEHOLDER = re.compile(r"\{\{([a-z0-9_]+)\}\}")

SEVERITIES = {"critical", "high", "medium", "low", "info"}
METHODS_FREE = {"GET", "HEAD", "OPTIONS", "TRACE"}
METHODS_INTRUSIVE = {"POST"}
METHODS_NEVER = {"PUT", "DELETE", "PATCH", "CONNECT"}

ROUTE_SWEEP = "sweep"
ROUTE_OWN = "own"


_PERL_ONLY = re.compile(r"\(\?[=!<]|\\[1-9]")


def _re2_error(pattern: str) -> str | None:
    """The Go engine's message when an expression uses what RE2 does not have."""
    m = _PERL_ONLY.search(pattern)
    if m:
        return ("error parsing regexp: invalid or unsupported Perl syntax: `%s`"
                % m.group(0)[:3])
    try:
        re.compile(pattern)
    except re.error as exc:
        return "error parsing regexp: %s" % exc
    return None


def _groups(pattern: str) -> int:
    return re.compile(pattern).groups


def unknown_fields(obj, allowed, path: str) -> list[str]:
    """``DisallowUnknownFields``: one typo in a key fails the whole pack."""
    if not isinstance(obj, dict):
        return []
    return ['json: unknown field "%s" in %s' % (k, path) for k in obj if k not in allowed]


# --------------------------------------------------------------------------- pack


def validate_pack(pack: dict) -> list[str]:
    errs = unknown_fields(pack, PACK_FIELDS, "pack")
    if not pack.get("source"):
        errs.append("checkpack: pack has no source")
    api = pack.get("api", 1)
    if api != 1:
        errs.append("checkpack: unsupported api %s (this build understands 1)" % api)
    plugin = pack.get("plugin") or {}
    errs += unknown_fields(plugin, PLUGIN_FIELDS, "plugin")
    pid = plugin.get("id", "")
    if not PLUGIN_ID.match(pid or ""):
        errs.append("checkpack: plugin id %r is not a valid id" % pid)
    if not plugin.get("name"):
        errs.append("checkpack: plugin %r has no name" % pid)
    for port in plugin.get("default_ports") or []:
        if not isinstance(port, int) or not 1 <= port <= 65535:
            errs.append("checkpack: plugin %r default port %s out of range" % (pid, port))
    schema = plugin.get("params_schema")
    if schema is not None and not isinstance(schema, dict):
        errs.append("checkpack: plugin %r has an invalid params schema" % pid)
    return errs


# -------------------------------------------------------------------------- check


def _validate_expect(expect, step_no: int, is_final: bool, has_finding: bool,
                     errs: list[str], depth: int = 0) -> None:
    if expect is None:
        errs.append("an expectation that asserts nothing would match every reply")
        return
    errs += unknown_fields(expect, EXPECT_FIELDS, "expect")

    meaningful = [k for k in expect if k != "not" and expect[k] not in (None, [], {})]
    nested = expect.get("not")
    if not meaningful and not nested:
        if depth:
            errs.append("an inverted expectation asserts nothing")
        else:
            errs.append("an expectation that asserts nothing would match every reply")
        return

    for key in ("body_any", "body_all", "require_ci"):
        for marker in expect.get(key) or []:
            if marker == "":
                errs.append("an empty marker matches every reply")

    for status in expect.get("status") or []:
        if not isinstance(status, int) or not 100 <= status <= 599:
            errs.append("status %s is not an http status" % status)

    for test in expect.get("header") or []:
        errs += unknown_fields(test, HEADER_FIELDS, "header test")
        name = test.get("name")
        if not name:
            errs.append("a header test has no name")
        if test.get("absent") and (set(test) - {"name", "absent"}):
            errs.append("header %r asserts absence and a value at once" % name)
        if test.get("re"):
            problem = _re2_error(test["re"])
            if problem:
                errs.append("header %r regexp %r: %s" % (name, test["re"], problem))

    for pattern in expect.get("re") or []:
        problem = _re2_error(pattern)
        if problem:
            errs.append("expect regexp %r: %s" % (pattern, problem))

    bytes_at = expect.get("bytes_at")
    if bytes_at is not None:
        for item in (bytes_at if isinstance(bytes_at, list) else [bytes_at]):
            if not item.get("b64"):
                errs.append("bytes_at has no bytes to compare")
            else:
                try:
                    base64.b64decode(item["b64"], validate=True)
                except (binascii.Error, ValueError) as exc:
                    errs.append("bytes_at b64: %s" % exc)
            if item.get("offset", 0) < 0:
                errs.append("bytes_at offset %s is negative" % item.get("offset"))

    if nested is not None:
        if depth + 1 > 3:
            errs.append("inverted expectations nest deeper than 3")
        else:
            _validate_expect(nested, step_no, False, has_finding, errs, depth + 1)

    if is_final and has_finding and set(meaningful) == {"status"} and not nested:
        errs.append("the final step asserts only a status, which cannot support a finding")


def _can_anchor(expect: dict) -> bool:
    """Whether the assertion can support ``verified: true``.

    The compiler's exact wording ("can only match a bare substring") cannot be
    recovered from the specification, so this rule is calibrated against the
    reference packs: only an assertion with nothing but ``body_any`` is refused —
    "any one of these markers", meaning the weakest of them may be what matched.
    ``body_all``, ``require_ci``, ``re``, ``bytes_at``, a header test with a value,
    ``not`` and an explicit ``status`` all count as support. The converter never
    sets ``verified`` itself (§8), so this rule only matters when validating
    someone else's pack.
    """
    if expect.get("re") or expect.get("bytes_at") or expect.get("not"):
        return True
    if expect.get("body_all") or expect.get("require_ci") or expect.get("status"):
        return True
    for test in expect.get("header") or []:
        if test.get("re") or test.get("equals") or test.get("contains"):
            return True
    return False


def validate_check(check: dict, pack_api: int = 1) -> list[str]:
    errs = unknown_fields(check, CHECK_FIELDS, "check")
    cid = check.get("id", "")
    if not CHECK_ID.match(cid or ""):
        errs.append("check id %r is not a valid id" % cid)

    api = check.get("api", pack_api)
    if api != 1:
        errs.append("check api %s is not supported" % api)

    match = check.get("match") or {}
    errs += unknown_fields(match, MATCH_FIELDS, "match")
    if not (match.get("service") or match.get("ports") or match.get("any_port_open")):
        errs.append("check has no match precondition (service, ports or any_port_open)")
    for port in list(match.get("ports") or []) + list(match.get("any_port_open") or []):
        if not isinstance(port, int) or not 1 <= port <= 65535:
            errs.append("match port %s out of range" % port)

    steps = check.get("steps") or []
    if not steps:
        errs.append("check has no steps")
    elif len(steps) > 8:
        errs.append("check has %d steps, the limit is 8" % len(steps))

    has_finding = check.get("finding") is not None
    has_detect = check.get("detect") is not None
    if not has_finding and not has_detect:
        errs.append("check reports neither a finding nor a detection")

    defined: set[str] = set()
    for idx, step in enumerate(steps):
        errs += unknown_fields(step, STEP_FIELDS, "step")
        transports = [t for t in ("http", "tcp", "udp", "tls") if t in step]
        if len(transports) != 1:
            errs.append("a step must set exactly one transport, found %d" % len(transports))

        for name in PLACEHOLDER.findall(_dump_step_requests(step)):
            if name not in defined:
                errs.append("step %d references capture %r, which no earlier step defines"
                            % (idx + 1, name))

        if "http" in step:
            http = step["http"] or {}
            errs += unknown_fields(http, HTTP_FIELDS, "http")
            paths = http.get("paths") or []
            path = http.get("path")
            if not path and not paths:
                errs.append("an http step needs a path")
            for p in ([path] if path else []) + list(paths):
                if not str(p).startswith(("/", "?")):
                    errs.append("path %r must start with / or ?" % p)
            if paths and len(steps) > 1:
                errs.append("alternative paths are only valid on a single-step check")
            if len(paths) > 256:
                errs.append("%d paths, the limit is 256" % len(paths))
            method = (http.get("method") or "GET").upper()
            if method in METHODS_NEVER:
                errs.append("method %s is not available to a declarative check" % method)
            elif method in METHODS_INTRUSIVE and not check.get("intrusive"):
                errs.append("method %s requires the check to declare itself intrusive" % method)
            elif method not in METHODS_FREE | METHODS_INTRUSIVE:
                errs.append("method %s is not available to a declarative check" % method)
            for header_name in (http.get("headers") or {}):
                if not header_name:
                    errs.append("a request header has no name")
            port = http.get("port")
            if port not in (None, 0) and not 1 <= port <= 65535:
                errs.append("port %s out of range" % port)

        for transport in ("tcp", "udp", "tls"):
            if transport in step:
                conn = step[transport] or {}
                errs += unknown_fields(conn, BYTES_FIELDS, transport)
                recv_max = conn.get("recv_max", 0)
                if not isinstance(recv_max, int) or not 0 <= recv_max <= 1048576:
                    errs.append("recv_max %s is out of range (0..1048576)" % recv_max)
                port = conn.get("port")
                if port not in (None, 0) and not 1 <= port <= 65535:
                    errs.append("port %s out of range" % port)
                payload = conn.get("send_b64")
                if payload:
                    try:
                        base64.b64decode(payload, validate=True)
                    except (binascii.Error, ValueError) as exc:
                        errs.append("send_b64 is not valid base64: %s" % exc)

        _validate_expect(step.get("expect"), idx + 1, idx == len(steps) - 1, has_finding, errs)

        seen_here: set[str] = set()
        for cap in step.get("capture") or []:
            errs += unknown_fields(cap, CAPTURE_FIELDS, "capture")
            name = cap.get("as", "")
            if not CAPTURE_NAME.match(name or ""):
                errs.append("capture name %r must match ^[a-z0-9_]+$" % name)
            if name in seen_here:
                errs.append("capture %r is defined twice in one step" % name)
            elif name in defined:
                errs.append("capture %r is already defined by an earlier step" % name)
            seen_here.add(name)
            source = cap.get("from", "body")
            if source not in ("body", "header"):
                errs.append("capture %r: from %r is not body or header" % (name, source))
            if source == "header" and not cap.get("header"):
                errs.append("capture %r reads a header but names none" % name)
            pattern = cap.get("re", "")
            problem = _re2_error(pattern)
            if problem:
                errs.append("expect regexp %r: %s" % (pattern, problem))
            else:
                count = _groups(pattern)
                if count != 1:
                    errs.append("regexp %r has %d capturing groups, need exactly 1"
                                % (pattern, count))
        defined |= seen_here

    detect = check.get("detect")
    if detect is not None:
        errs += unknown_fields(detect, DETECT_FIELDS, "detect")
        if not detect.get("product"):
            errs.append("detect: no product")
        version = detect.get("version")
        if version is not None:
            errs += unknown_fields(version, VERSION_FIELDS, "detect.version")
            source = version.get("from", "body")
            if source not in ("body", "header", "capture"):
                errs.append("version from %r is not body, header or capture" % source)
            elif source in ("body", "header"):
                if not version.get("re"):
                    errs.append("version from %s needs a regexp" % source)
                else:
                    problem = _re2_error(version["re"])
                    if problem:
                        errs.append("expect regexp %r: %s" % (version["re"], problem))
                    else:
                        count = _groups(version["re"])
                        if count != 1:
                            errs.append("regexp %r has %d capturing groups, need exactly 1"
                                        % (version["re"], count))
                if source == "header" and not version.get("header"):
                    errs.append("version reads a header but names none")
            elif source == "capture":
                name = version.get("name")
                if not name:
                    errs.append("version reads a header but names none")
                elif name not in defined:
                    errs.append("version reads capture %r, which no step defines" % name)

    finding = check.get("finding")
    if finding is not None:
        errs += unknown_fields(finding, FINDING_FIELDS, "finding")
        if not finding.get("title"):
            errs.append("finding has no title")
        severity = finding.get("severity")
        if severity is not None and severity not in SEVERITIES:
            errs.append("finding severity %r is not a valid level" % severity)
        risk = finding.get("risk")
        if risk is not None and (not isinstance(risk, int) or not 0 <= risk <= 9):
            errs.append("finding risk %s is outside the 0-9 scale" % risk)
        cvss = finding.get("cvss")
        if cvss is not None and not 0 <= cvss <= 10:
            errs.append("finding cvss %.1f is out of range" % cvss)
        if finding.get("verified") and steps:
            if not _can_anchor(steps[-1].get("expect") or {}):
                errs.append("finding claims verified but the final step "
                            "can only match a bare substring")

    return errs


def _dump_step_requests(step: dict) -> str:
    """A step's request text — where ``{{name}}`` placeholders may appear."""
    import json
    parts = []
    for transport in ("http", "tcp", "udp", "tls"):
        if transport in step:
            parts.append(json.dumps(step[transport], ensure_ascii=False))
    return " ".join(parts)


# -------------------------------------------------------------------------- route


def route_of(check: dict) -> tuple[str, str]:
    """Where a check will run (§7): the shared web sweep or its own catalogue row."""
    steps = check.get("steps") or []
    if not steps:
        return ROUTE_OWN, "it has no step to run"
    if len(steps) > 1:
        return ROUTE_OWN, "it has several steps, which cannot share one fetched reply"
    step = steps[0]
    if "http" not in step:
        return ROUTE_OWN, "it is not an HTTP check"
    method = (step["http"].get("method") or "GET").upper()
    if method != "GET":
        return ROUTE_OWN, "the sweep issues GET only, and this check asks for %s" % method
    return ROUTE_SWEEP, ""
