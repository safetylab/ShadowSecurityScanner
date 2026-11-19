"""Checking a finished pack: what the scanner will accept, drop and why.

The scanner ships its own compiler, but it is part of the desktop application,
so this is what a reader of the public repository has at hand. It applies the
same §5 rules the converter applies to its own output, plus the pack-level
checks a single check cannot see: duplicate ids, and the routing rule from §7.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from .validate import ROUTE_SWEEP, route_of, validate_check, validate_pack

__all__ = ["check_pack", "load_pack"]


def load_pack(path: Path) -> dict:
    """Reads a pack, gzipped or plain, as §1 of the specification allows."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return json.load(handle)
    return json.loads(path.read_text(encoding="utf-8"))


def _plan(check: dict) -> str:
    """One line describing what the check does, in the order it does it."""
    match = check.get("match") or {}
    when = []
    if match.get("service"):
        when.append("service %s" % match["service"])
    if match.get("ports"):
        when.append("ports %s" % ",".join(str(p) for p in match["ports"]))
    if match.get("any_port_open"):
        when.append("any of %s open" % ",".join(str(p) for p in match["any_port_open"]))
    if match.get("os_any"):
        when.append("os ~ %s" % "/".join(match["os_any"]))

    sends = []
    for step in check.get("steps") or []:
        if "http" in step:
            http = step["http"]
            target = http.get("path") or ("%d paths" % len(http.get("paths") or []))
            sends.append("%s %s" % (http.get("method", "GET"), target))
        for transport in ("tcp", "udp", "tls"):
            if transport in step:
                payload = step[transport].get("send_b64") or ""
                sends.append("%s %s" % (transport, "banner" if not payload else "payload"))

    asserts = 0
    for step in check.get("steps") or []:
        asserts += len([k for k in (step.get("expect") or {}) if k != "status"])

    reports = []
    if check.get("detect"):
        detect = check["detect"]
        reports.append("detect %s%s" % (detect.get("product", "?"),
                                        " + version" if detect.get("version") else ""))
    if check.get("finding"):
        reports.append("finding %s" % (check["finding"].get("severity") or "unrated"))

    return "when %s → %s → %d assertion(s) → %s" % (
        " and ".join(when) or "any host",
        " then ".join(sends) or "nothing",
        asserts,
        ", ".join(reports) or "nothing")


def check_pack(path: Path, verbose: bool = False, strict: bool = False) -> tuple[list[str], bool]:
    """Returns the lines to print and whether the run should be considered failed."""
    lines: list[str] = []
    failed = False

    try:
        pack = load_pack(path)
    except (OSError, ValueError) as exc:
        return ["%s: cannot be read as a pack: %s" % (path, exc)], True

    lines.append("%s" % path)
    errors = validate_pack(pack)
    if errors:
        for error in errors:
            lines.append("  %s" % error)
        lines.append("  the whole pack is refused")
        return lines, True

    lines.append("  source:   %s (version %s, api %s)"
                 % (pack.get("source"), pack.get("version"), pack.get("api", 1)))
    plugin = pack.get("plugin") or {}
    lines.append("  plugin:   %s — %r" % (plugin.get("id"), plugin.get("name")))

    accepted: list[dict] = []
    dropped: list[tuple[dict, list[str]]] = []
    seen: dict[str, int] = {}
    for check in pack.get("checks") or []:
        problems = validate_check(check, pack.get("api", 1))
        cid = check.get("id")
        seen[cid] = seen.get(cid, 0) + 1
        if seen[cid] > 1:
            problems = problems + ["check id %r appears %d times in this pack"
                                   % (cid, seen[cid])]
        (dropped if problems else accepted).append(
            (check, problems) if problems else check)

    sweep = sum(1 for check in accepted if route_of(check)[0] == ROUTE_SWEEP)
    own = len(accepted) - sweep
    lines.append("  checks:   %d accepted, %d dropped" % (len(accepted), len(dropped)))
    lines.append('  runs as:  %d check(s) inside the web sweep (catalog row "cgi"), '
                 '%d under this pack\'s own row %r' % (sweep, own, plugin.get("id")))

    for check, problems in dropped:
        lines.append("  dropped %s: %s" % (check.get("id", "<no id>"), problems[0]))
        for extra in problems[1:]:
            lines.append("            %s" % extra)

    if verbose:
        for check in accepted:
            lines.append("  %s" % check.get("id"))
            lines.append("    %s" % _plan(check))
            route, why = route_of(check)
            if route != ROUTE_SWEEP:
                lines.append("    own row: %s" % why)

    if dropped and strict:
        failed = True
    return lines, failed
